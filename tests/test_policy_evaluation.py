"""Check evaluation accounting, payload boundaries and preservation of contrary evidence."""

import copy
import hashlib
import json
import subprocess
import sys

import pytest

from evaluation.policy_combinations import run as evaluation
from guardtrellis import Guard, Rejected, Result


def corpus_bytes(cases):
    return "".join(json.dumps(case) + "\n" for case in cases).encode()


def cases_by_id():
    return {case["id"]: case for case in evaluation.load_cases(evaluation.CORPUS.read_bytes())}


def test_corpus_is_attributable_development_evidence_and_pairs_have_same_meaning():
    cases = cases_by_id()
    assert len(cases) == 34
    assert {case["family"] for case in cases.values()} == set(evaluation.FAMILIES)
    for case in cases.values():
        assert case["dataset_version"] == "policy-delivery-v1"
        assert case["usage"] == "development"
        assert "synthetic" in case["source"]
        assert "Codex assistance" in case["source"]
        assert case["label_basis"]
    for plain, escaped in [
        ("json-email-redacted", "json-escaped-email-miss"),
        ("tool-redacted-dispatch", "tool-escaped-email-miss"),
    ]:
        assert cases[plain]["text"] != cases[escaped]["text"]
        assert json.loads(cases[plain]["text"]) == json.loads(cases[escaped]["text"])
        assert cases[plain]["expected"] == cases[escaped]["expected"]
    assert cases["delivery-plain-phone"]["text"] == cases["delivery-spaced-phone-miss"][
        "text"
    ].replace("+1 202 555 0123", "+12025550123")


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "invalid|id"),
        ("family", "unknown"),
        ("profile", "unknown"),
        ("expected_signal", 1),
        ("source", ""),
        ("usage", "held_out"),
        ("language", "not a language"),
        ("text", "x" * 10_001),
        ("text", None),
        ("response", []),
        ("tool", 3),
        ("privacy_markers", []),
        ("privacy_markers", ["tiny"]),
        ("expected", {}),
    ],
)
def test_malformed_or_oversized_fixtures_fail_before_execution(field, value):
    case = next(iter(cases_by_id().values()))
    case[field] = value
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([case]))


@pytest.mark.parametrize("field,value", [("action", []), ("accepted", 1), ("trace", {})])
def test_malformed_nested_expectations_fail(field, value):
    case = next(iter(cases_by_id().values()))
    case["expected"][field] = value
    with pytest.raises(ValueError, match="expectations"):
        evaluation.load_cases(corpus_bytes([case]))


def test_duplicates_mixed_versions_and_invalid_counts_are_rejected():
    cases = list(cases_by_id().values())[:2]
    with pytest.raises(ValueError, match="duplicate ID"):
        evaluation.load_cases(corpus_bytes([cases[0], cases[0]]))
    cases[1]["dataset_version"] = "policy-delivery-v2"
    with pytest.raises(ValueError, match="one dataset version"):
        evaluation.load_cases(corpus_bytes(cases))
    duplicate_key = json.dumps(cases[0])[:-1] + ', "expected_signal": false}\n'
    with pytest.raises(ValueError, match="Invalid JSON"):
        evaluation.load_cases(duplicate_key.encode())
    with pytest.raises(ValueError, match="between 1 and 200"):
        evaluation.load_cases(b"")
    with pytest.raises(ValueError, match="one megabyte"):
        evaluation.load_cases(b" " * 1_000_001)
    for index in range(201):
        cases.append({**cases[0], "id": f"case-{index}"})
    with pytest.raises(ValueError, match="between 1 and 200"):
        evaluation.load_cases(corpus_bytes(cases))


def test_callback_profiles_require_an_explicit_synthetic_response():
    case = cases_by_id()["delivery-benign-callback"]
    del case["response"]
    with pytest.raises(ValueError, match="Invalid label"):
        evaluation.load_cases(corpus_bytes([case]))


def test_wrong_scenario_expectations_remain_mismatches_not_silent_relabels():
    case = cases_by_id()["delivery-benign-callback"]
    original = copy.deepcopy(case)
    case["expected_signal"] = True
    case["expected"].update(action="block", accepted=False, callback_inputs=[], delivered=None)
    row = evaluation.evaluate_cases([case])[0]
    assert row["outcome"] == "fn"
    assert row["expected_action"] == "block"
    assert row["observed_action"] == "allow"
    assert set(row["mismatches"]) == {"action", "accepted", "callback_inputs", "delivered"}
    assert row["callback_count"] == 1
    assert case["expected"]["action"] == "block"
    assert case["text"] == original["text"]
    assert "text" not in row and "delivered" not in row and "callback_inputs" not in row


def test_ordering_revisions_and_real_delivery_are_compared():
    cases = cases_by_id()
    ids = [
        "order-two-redaction-revisions",
        "delivery-redact-both-stages",
        "delivery-input-block",
        "delivery-output-block",
        "tool-redacted-dispatch",
        "tool-redaction-schema-reject",
    ]
    rows = {row["id"]: row for row in evaluation.evaluate_cases([cases[key] for key in ids])}
    assert all(not row["mismatches"] for row in rows.values())
    assert rows["delivery-input-block"]["callback_count"] == 0
    assert rows["delivery-output-block"]["callback_count"] == 1
    assert not rows["delivery-output-block"]["delivered_available"]
    assert rows["tool-redacted-dispatch"]["dispatch_count"] == 1
    assert rows["tool-redaction-schema-reject"]["dispatch_count"] == 0
    assert rows["order-two-redaction-revisions"]["comparisons"]["findings"]
    # An incorrect revision expectation must be detected, even when final text agrees.
    cases["order-two-redaction-revisions"]["expected"]["findings"][1]["revision"] = 0
    wrong = evaluation.evaluate_cases([cases["order-two-redaction-revisions"]])[0]
    assert wrong["mismatches"] == ["findings"]


def test_warnings_remain_delivery_and_injected_errors_are_not_detections():
    cases = cases_by_id()
    rows = evaluation.evaluate_cases(
        [
            cases["secret-classic-warn"],
            cases["error-input-scanner"],
            cases["error-callback"],
            cases["error-tool-scanner"],
        ]
    )
    total = evaluation.summarize(rows)
    assert rows[0]["outcome"] == "tp" and rows[0]["accepted"]
    assert total["tp"] == 1 and total["expected_errors"] == total["error"] == 3
    assert total["unexpected_errors"] == total["harness_errors"] == 0
    assert total["privacy_failures"] == total["mismatched_cases"] == 0
    serialized = json.dumps(rows)
    assert "exception-sentinel" not in serialized


def test_report_does_not_serialize_payloads_or_extra_fields(tmp_path):
    case = cases_by_id()["delivery-benign-callback"]
    case["text"] = "private-input-sentinel"
    case["response"] = "private-response-sentinel"
    case["unexpected_extra"] = "private-extra-sentinel"
    case["expected"]["checked_text"] = "private-expectation-sentinel"
    case["privacy_markers"] = [case["text"], case["response"]]
    raw = corpus_bytes([case])
    loaded = evaluation.load_cases(raw)
    report = evaluation.build_report(loaded, raw, evaluation.evaluate_cases(loaded))
    assert "private-" not in json.dumps(report)
    assert "private-" not in evaluation.markdown(report)
    assert report["overall"]["mismatched_cases"] == 1


def test_payload_in_diagnostics_is_detected_and_suppressed(monkeypatch):
    case = cases_by_id()["delivery-benign-callback"]
    original = Result.diagnostics

    def leaking_diagnostics(self):
        return {**original(self), "payload": case["text"]}

    monkeypatch.setattr(Result, "diagnostics", leaking_diagnostics)
    row = evaluation.evaluate_cases([case])[0]
    assert row["diagnostics"] is None
    assert row["privacy_failures"] == ["diagnostics_safe"]
    assert evaluation.summarize([row])["privacy_failures"] == 1
    assert case["text"] not in json.dumps(row)


@pytest.mark.parametrize(
    "marker",
    ["multiline-payload\nsecond-line", "unicode-payload-é-漢字", r"backslash\payload\sentinel"],
)
@pytest.mark.parametrize("surface", ["diagnostic_key", "diagnostic_value", "repr", "rejection"])
def test_multiline_unicode_and_backslash_leaks_are_detected(monkeypatch, marker, surface):
    case = cases_by_id()["error-input-scanner"]
    case["privacy_markers"] = [marker]
    original = Result.diagnostics
    if surface == "diagnostic_key":
        monkeypatch.setattr(Result, "diagnostics", lambda self: {**original(self), marker: True})
    elif surface == "diagnostic_value":
        monkeypatch.setattr(
            Result, "diagnostics", lambda self: {**original(self), "nested": [{"payload": marker}]}
        )
    elif surface == "repr":
        monkeypatch.setattr(Result, "__repr__", lambda self: f"Payload({marker!r})")
    else:
        monkeypatch.setattr(Rejected, "__str__", lambda self: json.dumps(marker))
    row = evaluation.evaluate_cases([case])[0]
    expected_surface = "diagnostics_safe" if surface.startswith("diagnostic") else f"{surface}_safe"
    assert row["privacy_failures"] == [expected_surface]
    assert not evaluation.contains_marker(json.dumps(row), [marker])
    if surface.startswith("diagnostic"):
        assert row["diagnostics"] is None


def test_json_validity_is_explicit_and_uses_strict_validation(monkeypatch):
    cases = cases_by_id()
    rows = evaluation.evaluate_cases(
        [
            cases["json-email-redacted"],
            cases["json-duplicate-key"],
            cases["tool-redacted-dispatch"],
            cases["delivery-benign-callback"],
        ]
    )
    assert [row["checked_json_valid"] for row in rows] == [True, None, True, None]
    case = cases["json-email-redacted"]
    case["text"] = '{"message":"first","message":"second"}'
    monkeypatch.setattr(evaluation, "policy", lambda profile: Guard())
    row = evaluation.evaluate_cases([case])[0]
    assert row["accepted"] and row["checked_json_valid"] is False
    assert "checked_json_valid" in row["mismatches"]


def test_privacy_failure_returns_nonzero_without_copying_marker(tmp_path, monkeypatch):
    case = cases_by_id()["json-benign-valid"]
    original = Result.diagnostics
    monkeypatch.setattr(
        Result,
        "diagnostics",
        lambda self: {**original(self), "payload": case["privacy_markers"][0]},
    )
    corpus = tmp_path / "cases.jsonl"
    corpus.write_bytes(corpus_bytes([case]))
    output = tmp_path / "report"
    assert evaluation.main(["--corpus", str(corpus), "--report-dir", str(output)]) == 1
    recorded = (output / "results.json").read_text()
    assert case["privacy_markers"][0] not in recorded
    assert json.loads(recorded)["overall"]["privacy_failures"] == 1


def test_unexpected_error_and_harness_exception_are_retained_without_payload(monkeypatch):
    case = cases_by_id()["error-input-scanner"]
    case["expected"]["action"] = "allow"
    row = evaluation.evaluate_cases([case])[0]
    assert row["unexpected_error"]
    assert evaluation.summarize([row])["unexpected_errors"] == 1

    def fail(case):
        raise RuntimeError("private-harness-failure-sentinel")

    monkeypatch.setattr(evaluation, "observe", fail)
    row = evaluation.evaluate_cases([case])[0]
    assert row["harness_error"]
    assert evaluation.summarize([row])["harness_errors"] == 1
    assert "private-" not in json.dumps(row)


def test_cli_reports_evidence_and_refuses_to_overwrite_prior_reports(tmp_path):
    output = tmp_path / "report"
    process = subprocess.run(
        [sys.executable, str(evaluation.HERE / "run.py"), "--report-dir", str(output)],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    assert process.stderr == ""
    assert "does not imply all scenario expectations passed" in process.stdout
    recorded = (output / "results.json").read_bytes()
    data = json.loads(recorded)
    report = (output / "REPORT.md").read_text()
    assert (
        data["metadata"]["corpus_sha256"]
        == hashlib.sha256(evaluation.CORPUS.read_bytes()).hexdigest()
    )
    for key in ("source_sha256", "runner_sha256", "lockfile_sha256"):
        assert len(data["metadata"][key]) == 64
    assert data["metadata"]["independent_review"] == "none"
    assert sum(group["cases"] for group in data["families"].values()) == 34
    for group in data["families"].values():
        assert sum(group["actions"].values()) == group["cases"]
    for row in data["cases"]:
        if row["outcome"] in ("fp", "fn", "error") or row["mismatches"]:
            assert f"`{row['id']}`: **{row['outcome']}**" in report
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--report-dir", str(output)])
    assert error.value.code == 2
    assert (output / "results.json").read_bytes() == recorded


def test_unexpected_error_returns_nonzero_and_invalid_input_creates_no_report(tmp_path):
    case = cases_by_id()["error-input-scanner"]
    case["expected"]["action"] = "allow"
    corpus = tmp_path / "cases.jsonl"
    corpus.write_bytes(corpus_bytes([case]))
    output = tmp_path / "report"
    assert evaluation.main(["--corpus", str(corpus), "--report-dir", str(output)]) == 1
    assert json.loads((output / "results.json").read_bytes())["overall"]["unexpected_errors"] == 1
    corpus.write_bytes(b"private-invalid-corpus-sentinel")
    invalid_output = tmp_path / "invalid-report"
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--corpus", str(corpus), "--report-dir", str(invalid_output)])
    assert error.value.code == 2
    assert not invalid_output.exists()


def test_cli_requires_explicit_destination():
    with pytest.raises(SystemExit) as error:
        evaluation.main([])
    assert error.value.code == 2
