"""Connection-string evidence keeps detection, checked delivery, and privacy separate."""

import copy
import hashlib
import json
import subprocess
import sys
from collections import Counter
from dataclasses import replace

import pytest

from evaluation.connection_strings import run as evaluation
from guardtrellis import Rejected, Result


def corpus_bytes(cases):
    return "".join(json.dumps(case) + "\n" for case in cases).encode("utf-8")


def cases_by_id():
    return {case["id"]: case for case in evaluation.load_corpus()}


def test_versioned_corpus_has_independent_labels_and_original_character_spans():
    cases = evaluation.load_corpus()
    assert len(cases) == len({case["id"] for case in cases}) == 52
    assert {case["dataset_version"] for case in cases} == {"connection-strings-v1"}
    assert Counter(case["label"] for case in cases) == {
        "sensitive": 24,
        "benign": 10,
        "ambiguous": 12,
        "control": 2,
        "deferred": 4,
    }
    for case in cases:
        assert case["usage"] == "development"
        assert "synthetic" in case["source"] and "Codex assistance" in case["source"]
        assert case["label_basis"]
        for start, end in case["target_spans"] + case["credential_spans"]:
            assert 0 <= start < end <= len(case["text"])
        if case["expected_action"] == "block":
            for start, end in case["credential_spans"]:
                assert any(a <= start < end <= b for a, b in case["target_spans"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "unsafe|id"),
        ("dataset_version", "connection-strings-unreviewed"),
        ("usage", "held-out"),
        ("source", ""),
        ("label_basis", ""),
        ("label", "unknown"),
        ("expected_action", "redact"),
        ("text", None),
        ("text", "x" * 2_101),
        ("candidate_count", True),
        ("target_spans", [[0, 999_999]]),
        ("credential_spans", [[-1, 2]]),
        ("privacy_markers", []),
    ],
)
def test_loader_rejects_invalid_metadata_and_label_contract(field, value):
    case = copy.deepcopy(cases_by_id()["pg-userinfo"])
    case[field] = value
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([case]))


def test_loader_rejects_duplicates_empty_oversized_and_non_json_corpora():
    case = cases_by_id()["pg-userinfo"]
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([case, case]))
    duplicate_key = json.dumps(case)[:-1] + ', "id": "duplicate-key"}\n'
    for raw in (b"", b"not JSON", b" " * 1_000_001, duplicate_key.encode()):
        with pytest.raises(ValueError):
            evaluation.load_cases(raw)


@pytest.mark.parametrize(
    "text",
    [
        "A plain fabricated value",
        'quotes: "value"; slash: \\; newline: \n',
        "emoji: \U0001f512; accented: \u00e9; CJK: \u6f22",
        r"literal escape: \u0040",
    ],
)
def test_wire_representations_decode_to_the_same_string_once(text):
    plain = evaluation.wire_text(text)
    escaped = evaluation.wire_text(text, escaped=True)
    assert json.loads(plain) == json.loads(escaped) == {"value": text}
    assert evaluation.decode_value(plain) == evaluation.decode_value(escaped) == text
    if text:
        assert plain != escaped
    if "\U0001f512" in text:
        assert "\\ud83d\\udd12" in escaped.lower()


@pytest.mark.parametrize(
    "wire",
    [
        "not JSON",
        '{"value":"first","value":"second"}',
        '{"value":"text","extra":"not allowed"}',
        '{"value":"text"} trailing',
        '{"value": NaN}',
        '{"value": Infinity}',
        '{"value": -Infinity}',
        '{"value": null}',
        '{"value": true}',
        '{"value": 12}',
        '{"value": []}',
        '{"value": {"value":"nested"}}',
        '{"other":"wrong field"}',
        '"a top-level string"',
        "[]",
        "{}",
        '{"value":""}',
        '{"value":"\\ud800"}',
        '{"value":"\\udfff"}',
    ],
)
def test_decode_adapter_rejects_ambiguous_or_invalid_envelopes(wire):
    with pytest.raises(ValueError):
        evaluation.decode_value(wire)


def test_decode_adapter_bounds_wire_and_decoded_value_separately():
    assert evaluation.decode_value(evaluation.wire_text("x" * 2_100)) == "x" * 2_100
    with pytest.raises(ValueError):
        evaluation.decode_value(evaluation.wire_text("x" * 2_101))
    with pytest.raises(ValueError):
        evaluation.decode_value('{"value":"short"}' + " " * 14_000)


def test_once_decoded_backslash_escape_is_not_recursively_interpreted():
    original = r"postgresql://synthetic:marker\u0040host.invalid/db"
    assert evaluation.decode_value(evaluation.wire_text(original, escaped=True)) == original
    assert "@" not in evaluation.decode_value(evaluation.wire_text(original, escaped=True))


def test_incidental_email_redaction_is_not_secret_detection_or_complete_protection():
    case = cases_by_id()["pg-userinfo-and-query-password"]
    secret = evaluation.observe(case, "secret_only", "plain")
    ordered = evaluation.observe(case, "tool_return", "plain")
    assert secret["action"] == "allow"
    assert ordered["action"] == "redact"
    assert ordered["incidental_pii"]
    assert not secret["secret_signature_signal"] and not ordered["secret_signature_signal"]
    assert ordered["consumer_count"] == 1
    assert not ordered["comparisons"]["credential_coverage"]
    assert not ordered["comparisons"]["action"]
    assert not ordered["comparisons"]["delivery"]
    assert not ordered["comparisons"]["target_spans"]
    assert not ordered["privacy_failures"] and not ordered["harness_failures"]


def test_removing_a_userinfo_password_does_not_satisfy_required_block():
    case = cases_by_id()["pg-userinfo"]
    row = evaluation.observe(case, "tool_return", "plain")
    assert row["action"] == "redact" and row["accepted"]
    assert row["incidental_pii"] and not row["secret_signature_signal"]
    assert row["comparisons"]["credential_coverage"]
    assert not row["comparisons"]["target_spans"]
    assert not row["comparisons"]["action"] and not row["comparisons"]["delivery"]


@pytest.mark.parametrize("policy", ["secret_only", "tool_return"])
@pytest.mark.parametrize(
    "representation", ["plain", "json_plain", "decoded_plain", "decoded_escaped"]
)
def test_existing_github_positive_control_blocks_before_consumer(policy, representation):
    row = evaluation.observe(cases_by_id()["control-github-classic"], policy, representation)
    assert row["action"] == "block" and not row["accepted"]
    assert row["consumer_count"] == 0 and row["secret_signature_signal"]
    assert all(row["comparisons"].values())
    assert not row["privacy_failures"] and not row["harness_failures"]


def test_wire_escaped_positive_control_is_a_visible_miss_until_explicit_decoding():
    case = cases_by_id()["control-github-classic"]
    raw = evaluation.observe(case, "secret_only", "json_escaped")
    decoded = evaluation.observe(case, "secret_only", "decoded_escaped")
    assert raw["action"] == "allow" and raw["consumer_count"] == 1
    assert not raw["secret_signature_signal"]
    assert not raw["comparisons"]["action"] and not raw["comparisons"]["delivery"]
    assert decoded["action"] == "block" and decoded["consumer_count"] == 0
    assert decoded["secret_signature_signal"]


def test_ambiguous_labels_are_reported_without_invented_success_denominators():
    cases = [case for case in evaluation.load_corpus() if case["label"] == "ambiguous"]
    rows = evaluation.evaluate(cases)
    assert len(rows) == len(cases) * len(evaluation.POLICIES) * len(evaluation.REPRESENTATIONS)
    assert all(all(value is None for value in row["comparisons"].values()) for row in rows)
    summary = evaluation.summarize(rows)
    assert summary["scored"] == summary["exact_outcome_matches"] == 0
    assert summary["policy_dependent"] == len(rows)


def test_evaluation_keeps_authored_fixtures_unchanged_and_reports_no_payloads():
    cases = evaluation.load_corpus()
    preserved = copy.deepcopy(cases)
    rows = evaluation.evaluate(cases)
    assert cases == preserved
    assert len(rows) == len(cases) * len(evaluation.POLICIES) * len(evaluation.REPRESENTATIONS)
    serialized = json.dumps(rows)
    for case in cases:
        for marker in case["privacy_markers"]:
            assert marker not in serialized
    assert not any(
        key in row
        for row in rows
        for key in ("text", "delivered", "consumer_inputs", "diagnostics")
    )
    assert not any(row["privacy_failures"] or row["harness_failures"] for row in rows)


def test_short_benign_text_does_not_conflict_with_safe_action_metadata():
    fixture = copy.deepcopy(cases_by_id()["benign-public-text"])
    fixture["text"] = "allow"
    cases = evaluation.load_cases(corpus_bytes([fixture]))
    rows = evaluation.evaluate(cases)
    assert len(rows) == len(evaluation.POLICIES) * len(evaluation.REPRESENTATIONS)
    assert all(row["action"] == "allow" for row in rows)
    assert all(all(row["comparisons"].values()) for row in rows)
    assert not any(row["privacy_failures"] or row["harness_failures"] for row in rows)


def test_wrong_authored_span_stays_a_mismatch_even_when_the_control_blocks():
    fixture = copy.deepcopy(cases_by_id()["control-github-classic"])
    fixture["target_spans"][0][1] -= 1
    row = evaluation.observe(fixture, "secret_only", "plain")
    assert row["secret_signature_signal"] and row["action"] == "block"
    assert row["comparisons"]["action"] and row["comparisons"]["delivery"]
    assert not row["comparisons"]["target_spans"]


def test_wire_findings_use_serialized_offsets_after_astral_prefix():
    fixture = copy.deepcopy(cases_by_id()["control-github-classic"])
    prefix = "\U0001f512 "
    fixture["text"] = prefix + fixture["text"]
    for field in ("target_spans", "credential_spans"):
        fixture[field] = [[a + len(prefix), b + len(prefix)] for a, b in fixture[field]]
    rows = {
        representation: evaluation.observe(fixture, "secret_only", representation)
        for representation in ("plain", "json_plain", "decoded_plain", "decoded_escaped")
    }
    assert all(all(row["comparisons"].values()) for row in rows.values())
    plain_start = rows["plain"]["findings"][0]["start"]
    assert rows["decoded_plain"]["findings"][0]["start"] == plain_start
    assert rows["decoded_escaped"]["findings"][0]["start"] == plain_start
    assert rows["json_plain"]["findings"][0]["start"] > plain_start


@pytest.mark.parametrize("policy", ["secret_only", "tool_return"])
def test_expected_size_rejection_is_withholding_not_credential_detection(policy):
    cases = cases_by_id()
    within = evaluation.observe(cases["pg-candidate-2000-characters"], policy, "plain")
    over = evaluation.observe(cases["pg-candidate-2001-characters"], policy, "plain")
    assert within["accepted"] and within["consumer_count"] == 1
    assert not within["expected_limit_error"]
    assert over["action"] == "error" and not over["accepted"]
    assert over["consumer_count"] == 0 and over["expected_limit_error"]
    assert not over["secret_signature_signal"] and not over["unexpected_error"]
    assert not over["harness_failures"]
    assert not over["comparisons"]["action"] and over["comparisons"]["delivery"]


@pytest.mark.parametrize("case_id", ["pg-userinfo", "control-github-classic"])
def test_actual_consumer_history_catches_raw_fallback_after_redaction_or_rejection(
    monkeypatch, case_id
):
    fixture = cases_by_id()[case_id]
    original = evaluation.handoff.run_workflow

    def unsafe(name, arguments, authorize, execute, consume, *, result_guard):
        try:
            return original(
                name,
                arguments,
                authorize,
                execute,
                lambda _checked: consume(fixture["text"]),
                result_guard=result_guard,
            )
        except Rejected:
            consume(fixture["text"])
            raise

    monkeypatch.setattr(evaluation.handoff, "run_workflow", unsafe)
    row = evaluation.observe(fixture, "tool_return", "plain")
    expected = "checked_delivery" if case_id == "pg-userinfo" else "rejected_delivery"
    assert expected in row["harness_failures"]
    assert row["consumer_count"] == 1


def test_corrupted_redact_result_cannot_claim_credential_removal(monkeypatch):
    fixture = cases_by_id()["pg-userinfo"]
    original = evaluation.RecordingGuard.scan

    def restore_original(self, text, *, stage):
        result = original(self, text, stage=stage)
        if result.action.value == "redact":
            self.result = replace(result, text=text)
            return self.result
        return result

    monkeypatch.setattr(evaluation.RecordingGuard, "scan", restore_original)
    row = evaluation.observe(fixture, "tool_return", "plain")
    assert row["action"] == "redact" and row["consumer_count"] == 1
    assert not row["comparisons"]["credential_coverage"]
    assert "checked_transformation" in row["harness_failures"]
    serialized = json.dumps(evaluation.evaluate([fixture]))
    assert fixture["text"] not in serialized
    assert all(marker not in serialized for marker in fixture["privacy_markers"])


def test_corrupted_allow_result_cannot_claim_unchanged_checked_delivery(monkeypatch):
    fixture = cases_by_id()["benign-public-text"]
    original = evaluation.RecordingGuard.scan

    def change_allowed_text(self, text, *, stage):
        result = original(self, text, stage=stage)
        self.result = replace(result, text="Unrelated fabricated replacement")
        return self.result

    monkeypatch.setattr(evaluation.RecordingGuard, "scan", change_allowed_text)
    row = evaluation.observe(fixture, "secret_only", "plain")
    assert row["action"] == "allow" and row["consumer_count"] == 1
    assert not row["comparisons"]["delivery"]
    assert "checked_transformation" in row["harness_failures"]
    assert fixture["text"] not in json.dumps(row)


@pytest.mark.parametrize("surface", ["diagnostics", "repr", "rejection", "recipe_logs"])
def test_real_privacy_surface_leaks_fail_without_copying_payloads(
    tmp_path, monkeypatch, capsys, surface
):
    fixture = cases_by_id()["control-github-classic"]
    marker = fixture["privacy_markers"][0]
    if surface == "diagnostics":
        original = Result.diagnostics
        monkeypatch.setattr(Result, "diagnostics", lambda self: {**original(self), "leak": marker})
    elif surface == "repr":
        monkeypatch.setattr(Result, "__repr__", lambda self: marker)
    elif surface == "rejection":
        original = Result.require_text

        def unsafe_require(self):
            if not self.accepted:
                raise Rejected(marker)
            return original(self)

        monkeypatch.setattr(Result, "require_text", unsafe_require)
    else:
        original = evaluation.handoff.record_check

        def unsafe_log(request_id, result):
            evaluation.handoff.LOGGER.info(marker)
            original(request_id, result)

        monkeypatch.setattr(evaluation.handoff, "record_check", unsafe_log)

    observed = evaluation.observe(fixture, "secret_only", "plain")
    assert surface in observed["privacy_failures"]
    corpus = tmp_path / "synthetic.jsonl"
    corpus.write_bytes(corpus_bytes([fixture]))
    output = tmp_path / "evidence"
    assert evaluation.main(["--corpus", str(corpus), "--report-dir", str(output)]) == 1
    captured = capsys.readouterr()
    report = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert report["summary"]["privacy_failures"] > 0
    assert marker not in captured.out + captured.err
    assert marker not in json.dumps(report)
    assert marker not in (output / "REPORT.md").read_text(encoding="utf-8")


def test_observation_exception_is_recorded_without_exception_text(tmp_path, monkeypatch, capsys):
    marker = "synthetic-exception-private-value"

    def fail(*_args):
        raise RuntimeError(marker)

    monkeypatch.setattr(evaluation, "observe", fail)
    output = tmp_path / "evidence"
    assert evaluation.main(["--report-dir", str(output)]) == 1
    report = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert all(row["unexpected_error"] for row in report["rows"])
    assert all(row["harness_failures"] == ["observation_error"] for row in report["rows"])
    assert report["summary"]["exact_outcome_matches"] == 0
    assert marker not in json.dumps(report)
    captured = capsys.readouterr()
    assert marker not in captured.out + captured.err


def test_recipe_logger_is_restored_after_unexpected_callback_failure(monkeypatch):
    logger = evaluation.handoff.LOGGER
    before = logger.handlers[:], logger.level, logger.propagate, logger.disabled

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic callback failure")

    monkeypatch.setattr(evaluation.handoff, "run_workflow", fail)
    rows = evaluation.evaluate([cases_by_id()["benign-public-text"]])
    assert all(row["unexpected_error"] for row in rows)
    assert (logger.handlers, logger.level, logger.propagate, logger.disabled) == before


def test_reports_preserve_evidence_and_identify_current_sources(tmp_path):
    rows = evaluation.evaluate([cases_by_id()["pg-userinfo"]])
    output = tmp_path / "evidence"
    report = evaluation.write_report(output, rows)
    before = (output / "results.json").read_bytes()
    assert report["metadata"]["usage"] == "authored-development-only"
    assert report["metadata"]["sdk_sha256"]
    for name, digest in report["metadata"]["source_sha256"].items():
        assert "\\" not in name
        assert hashlib.sha256((evaluation.ROOT / name).read_bytes()).hexdigest() == digest
    imported = evaluation.Path(evaluation.guardtrellis.__file__).resolve().parent.parent
    for name, digest in report["metadata"]["sdk_sha256"].items():
        assert "\\" not in name and not name.startswith("/")
        assert hashlib.sha256((imported / name).read_bytes()).hexdigest() == digest
    with pytest.raises(FileExistsError):
        evaluation.write_report(output, rows)
    assert (output / "results.json").read_bytes() == before


def test_real_cli_completes_and_retains_known_detection_gaps(tmp_path):
    output = tmp_path / "evidence with spaces"
    result = subprocess.run(
        [sys.executable, str(evaluation.Path(evaluation.__file__)), "--report-dir", str(output)],
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    report = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert summary == report["summary"]
    assert summary["observations"] == 520
    assert summary["positive_cases_without_secret_signature"] > 0
    assert summary["incidental_pii_observations"] > 0
    assert summary["unexpected_errors"] == summary["privacy_failures"] == 0
    assert summary["harness_failures"] == 0
