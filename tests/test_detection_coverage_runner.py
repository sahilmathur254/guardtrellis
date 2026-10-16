"""Keep new coverage evidence honest about decoding, complete edits and local timing."""

import copy
import hashlib
import json

import pytest

from evaluation.policy_combinations import run as evaluation
from guardtrellis import Rejected, Result

EMAIL = "casey@example.org"
SECRET = "ghp_" + "A" * 36


def query_case(profile="decoded_query_pii", *, escaped=False):
    query = "Contact " + EMAIL
    proposed = json.dumps({"query": query}, separators=(",", ":"))
    if escaped:
        proposed = proposed.replace("@", r"\u0040")
    return {
        "id": "query-email-escaped" if escaped else "query-email-plain",
        "family": "tool",
        "profile": profile,
        "dataset_version": "runner-test-v1",
        "source": "Original synthetic fixture authored with Codex assistance",
        "usage": "development",
        "language": "en",
        "format": "json-escaped" if escaped else "json-plain",
        "label_basis": "An authored contact should reach dispatch only as checked data",
        "expected_signal": True,
        "text": proposed,
        "tool": "search",
        "privacy_markers": [EMAIL],
        "pair_id": "query-email",
        "coverage_scope": "baseline",
        "expected": {
            "action": "allow" if profile == "decoded_query_pii" else "redact",
            "accepted": True,
            "checked_text": '{"query":"Contact [PII]"}',
            "callback_inputs": [],
            "delivered": {"query": "Contact [PII]"},
            "dispatches": [{"query": "Contact [PII]"}],
            "checked_json_valid": True,
        },
    }


def corpus_bytes(cases):
    return "".join(json.dumps(case) + "\n" for case in cases).encode()


def test_recipe_pairs_use_decoded_signal_without_claiming_serialized_findings():
    cases = [query_case(escaped=escaped) for escaped in (False, True)]
    expected_finding = {
        "code": "pii_email",
        "start": 8,
        "end": 25,
        "scanner": "pii",
        "scanner_index": 1,
        "revision": 0,
    }
    for case in cases:
        case["expected"].update(
            findings=[], decoded_action="redact", decoded_findings=[expected_finding]
        )
    rows = evaluation.evaluate_cases(evaluation.load_cases(corpus_bytes(cases)))
    assert [row["outcome"] for row in rows] == ["tp", "tp"]
    for row in rows:
        assert row["observed_action"] == "allow" and row["decoded_action"] == "redact"
        assert row["decoded_coordinate_space"] == "decoded-query-string"
        assert row["action_source"] == "handoff"
        assert row["dispatch_count"] == 1 and not row["mismatches"]
        assert row["diagnostics"]["handoff"]["findings"] == []
        assert row["diagnostics"]["decoded_query"]["findings"] == [expected_finding]
    assert EMAIL not in json.dumps(rows)


def test_raw_serialized_tool_miss_retains_desired_redaction_and_delivery():
    cases = [query_case("tool_query_pii", escaped=escaped) for escaped in (False, True)]
    before = copy.deepcopy(cases)
    plain, escaped = evaluation.evaluate_cases(cases)
    assert plain["outcome"] == "tp" and not plain["mismatches"]
    assert escaped["outcome"] == "fn" and escaped["observed_action"] == "allow"
    assert set(escaped["mismatches"]) == {"action", "checked_text", "delivered", "dispatches"}
    assert escaped["dispatch_count"] == 1
    assert cases == before
    assert "callback_inputs" not in escaped and "delivered" not in escaped


def test_partial_phone_redaction_is_not_counted_as_complete_protection():
    case = query_case()
    case.update(
        profile="run_pii",
        family="delivery",
        text="Call +12025550123-4567.",
        response="Offline result",
        privacy_markers=["+12025550123-4567"],
    )
    case["expected"] = {
        "action": "redact",
        "accepted": True,
        "checked_text": "Call [PII].",
        "callback_inputs": ["Call [PII]."],
        "delivered": "Offline result",
        "dispatches": [],
        "findings": [
            {
                "code": "pii_phone",
                "start": 5,
                "end": 22,
                "scanner": "pii",
                "scanner_index": 0,
                "revision": 0,
            }
        ],
    }
    row = evaluation.evaluate_cases([case])[0]
    assert row["outcome"] == "tp" and row["observed_action"] == "redact"
    assert set(row["mismatches"]) == {"checked_text", "callback_inputs", "findings"}


@pytest.mark.parametrize(
    "profile,action,callbacks", [("run_pii_warn", "warn", 1), ("run_pii_block", "block", 0)]
)
def test_phone_action_profiles_keep_warn_and_block_delivery_semantics(profile, action, callbacks):
    case = query_case()
    case.update(
        profile=profile,
        family="delivery",
        text="Call +12025550123.",
        response="Offline result",
        privacy_markers=["+12025550123"],
    )
    case["expected"] = {
        "action": action,
        "accepted": action == "warn",
        "checked_text": case["text"] if action == "warn" else None,
        "callback_inputs": [case["text"]] if action == "warn" else [],
        "delivered": "Offline result" if action == "warn" else None,
        "dispatches": [],
    }
    row = evaluation.evaluate_cases([case])[0]
    assert row["outcome"] == "tp" and row["callback_count"] == callbacks
    assert not row["mismatches"]


def test_decoded_block_records_real_decoded_policy_action_and_no_handoff():
    case = query_case()
    case.update(text=json.dumps({"query": SECRET}), privacy_markers=[SECRET])
    case["expected"] = {
        "action": "block",
        "accepted": False,
        "checked_text": None,
        "callback_inputs": [],
        "delivered": None,
        "dispatches": [],
        "findings": [],
        "decoded_action": "block",
    }
    row = evaluation.evaluate_cases([case])[0]
    assert row["outcome"] == "tp" and not row["mismatches"]
    assert row["action_source"] == "decoded-policy"
    assert row["dispatch_count"] == 0 and row["diagnostics"]["handoff"] is None
    assert SECRET not in json.dumps(row)


def test_strict_preflight_rejection_uses_real_result_without_decoding_or_dispatch():
    case = query_case()
    case["text"] = '{"query":"first","qu\\u0065ry":"second"}'
    case["expected"] = {
        "action": "block",
        "accepted": False,
        "checked_text": None,
        "callback_inputs": [],
        "delivered": None,
        "dispatches": [],
        "decoded_action": None,
    }
    row = evaluation.evaluate_cases([case])[0]
    assert row["observed_action"] == "block" and not row["mismatches"]
    assert row["action_source"] == "preflight" and row["dispatch_count"] == 0
    assert row["diagnostics"]["decoded_query"] is None


def test_recipe_owned_rejection_without_sdk_action_is_not_fabricated_as_detection():
    case = query_case()
    case["text"] = '{"query":"\\ud800"}'
    row = evaluation.evaluate_cases([case])[0]
    assert row["harness_error"] and row["unexpected_error"] and row["outcome"] == "error"
    assert "diagnostics" not in row


@pytest.mark.parametrize("surface", ["decoded_diagnostics", "repr", "rejection"])
def test_decoded_profile_suppresses_payloads_from_new_privacy_surfaces(monkeypatch, surface):
    case = query_case()
    if surface == "decoded_diagnostics":
        original = Result.diagnostics
        monkeypatch.setattr(
            Result, "diagnostics", lambda self: {**original(self), "unexpected_payload": EMAIL}
        )
        expected_failure = "diagnostics_safe"
    elif surface == "repr":
        monkeypatch.setattr(Result, "__repr__", lambda self: EMAIL)
        expected_failure = "repr_safe"
    else:
        case["text"] = json.dumps({"query": SECRET})
        monkeypatch.setattr(Rejected, "__str__", lambda self: EMAIL)
        expected_failure = "rejection_safe"
    row = evaluation.evaluate_cases([case])[0]
    assert row["privacy_failures"] == [expected_failure]
    assert EMAIL not in json.dumps(row)
    if surface == "decoded_diagnostics":
        assert row["diagnostics"] is None


@pytest.mark.parametrize("profile", ["tool_query_pii", "decoded_query_pii"])
@pytest.mark.parametrize("surface", ["diagnostics", "repr", "rejection"])
@pytest.mark.parametrize("representation", ["raw", "repr", "json"])
def test_original_escaped_json_is_a_privacy_marker_on_every_surface(
    monkeypatch, profile, surface, representation
):
    case = query_case(profile, escaped=True)
    # Authored decoded-value markers alone miss this noncanonical wire representation.
    assert not evaluation.contains_marker(case["text"], case["privacy_markers"])
    if surface == "rejection":
        case["tool"] = "not-allowed"
    marker = case["text"]
    payload = {"raw": marker, "repr": repr(marker), "json": json.dumps(marker)}[representation]
    if surface == "diagnostics":
        original = Result.diagnostics
        monkeypatch.setattr(
            Result, "diagnostics", lambda self: {**original(self), "unexpected_payload": payload}
        )
        expected_failure = "diagnostics_safe"
    elif surface == "repr":
        monkeypatch.setattr(Result, "__repr__", lambda self: payload)
        expected_failure = "repr_safe"
    else:
        monkeypatch.setattr(Rejected, "__str__", lambda self: payload)
        expected_failure = "rejection_safe"
    row = evaluation.evaluate_cases([case])[0]
    assert row["privacy_failures"] == [expected_failure]
    assert not evaluation.contains_marker(json.dumps(row), [marker])
    if surface == "diagnostics":
        assert row["diagnostics"] is None


def test_automatic_privacy_markers_include_bounded_responses_without_trivial_substrings():
    case = query_case()
    case["response"] = "Synthetic response sentinel"
    markers = evaluation.privacy_markers(case)
    assert case["text"] in markers and case["response"] in markers
    assert len(markers) == len(set(markers))
    case["text"] = "allow"
    case["response"] = ""
    assert "allow" not in evaluation.privacy_markers(case)
    case["text"] = "x" * 10_001
    assert case["text"] not in evaluation.privacy_markers(case)


@pytest.mark.parametrize(
    "field,value", [("pair_id", "unsafe|pair"), ("pair_id", []), ("coverage_scope", "unknown")]
)
def test_optional_pair_and_scope_metadata_are_validated(field, value):
    case = query_case()
    case[field] = value
    with pytest.raises(ValueError, match="pair or coverage scope"):
        evaluation.load_cases(corpus_bytes([case]))


def test_decoded_expectations_validate_types_and_cannot_be_attached_to_raw_profiles():
    case = query_case()
    case["expected"]["decoded_action"] = []
    with pytest.raises(ValueError, match="expectations"):
        evaluation.load_cases(corpus_bytes([case]))
    case["expected"]["decoded_action"] = "redact"
    case["profile"] = "tool_query_pii"
    with pytest.raises(ValueError, match="expectations"):
        evaluation.load_cases(corpus_bytes([case]))


def test_default_remains_one_execution_without_warmups_or_timing(monkeypatch):
    original = evaluation.observe
    calls = []

    def observe(case):
        calls.append(case["id"])
        return original(case)

    monkeypatch.setattr(evaluation, "observe", observe)
    row = evaluation.evaluate_cases([query_case()])[0]
    assert len(calls) == 1 and "latency_us" not in row
    assert "timed_observations" not in evaluation.summarize([row])


def test_timing_records_bounded_setup_inclusive_iterations_and_recipe_provenance(tmp_path):
    case = query_case()
    raw = corpus_bytes([case])
    corpus = tmp_path / "cases.jsonl"
    corpus.write_bytes(raw)
    output = tmp_path / "report"
    assert (
        evaluation.main(["--corpus", str(corpus), "--iterations", "2", "--report-dir", str(output)])
        == 0
    )
    report = json.loads((output / "results.json").read_text())
    metadata = report["metadata"]
    assert metadata["executions_per_case"] == 5
    assert metadata["warmups_per_case"] == 3 and metadata["timed_iterations_per_case"] == 2
    assert metadata["iteration_limit"] == 1000
    assert "Setup-inclusive" in metadata["timing_scope"]
    assert (
        metadata["recipe_sha256"] == hashlib.sha256(evaluation.RECIPE_PATH.read_bytes()).hexdigest()
    )
    assert report["cases"][0]["pair_id"] == case["pair_id"]
    assert len(report["cases"][0]["latency_us"]) == 2
    assert all(sample >= 0 for sample in report["cases"][0]["latency_us"])
    assert report["profiles"]["decoded_query_pii"]["timed_observations"] == 2
    assert report["formats"]["json-plain"]["cases"] == 1
    assert report["coverage_scopes"]["baseline"]["cases"] == 1
    assert EMAIL not in json.dumps(report)
    markdown = (output / "REPORT.md").read_text()
    assert "2 timed iterations" in markdown and "decoded query policy result" in markdown


def test_repeated_observation_disagreement_is_a_harness_error(monkeypatch):
    original = evaluation.observe
    count = 0

    def observe(case):
        nonlocal count
        count += 1
        observed = original(case)
        if count == 1:
            observed["dispatch_count"] = 0
        return observed

    monkeypatch.setattr(evaluation, "observe", observe)
    row = evaluation.evaluate_cases([query_case()], iterations=2)[0]
    assert count == 5
    assert row["harness_error"] and row["inconsistent_observations"]
    assert row["outcome"] == "error"


@pytest.mark.parametrize("iterations", [0, -1, 1001])
def test_timing_bounds_are_enforced_before_writing_reports(tmp_path, iterations):
    output = tmp_path / "report"
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--iterations", str(iterations), "--report-dir", str(output)])
    assert error.value.code == 2 and not output.exists()
    with pytest.raises(ValueError, match="iterations"):
        evaluation.evaluate_cases([query_case()], iterations)
