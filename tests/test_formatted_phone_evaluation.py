"""Independent labels, historical compatibility and safe opt-in comparison evidence."""

import copy
import json
import subprocess
import sys

import pytest

from evaluation.formatted_phone import resources
from evaluation.formatted_phone import run as evaluation


def test_historical_fixtures_are_reused_without_relabelling():
    fixtures = evaluation.load_cases()
    original = evaluation.load_corpus(evaluation.HISTORICAL)
    assert fixtures[:63] == original
    assert len(fixtures) == 93
    assert len({case["id"] for case in fixtures}) == 93
    assert {case["dataset_version"] for case in fixtures[63:]} == {"formatted-phone-grammar-v1"}
    assert sum(case["expected_signal"] for case in fixtures[63:]) == 9
    assert sum(not case["expected_signal"] for case in fixtures[63:]) == 21


def test_default_historical_outcomes_match_preserved_baseline():
    fixtures = evaluation.load_corpus(evaluation.HISTORICAL)
    baseline = json.loads(
        (evaluation.HISTORICAL.parent / "coverage_baseline_0.1.4/results.json").read_text()
    )["cases"]
    for case, archived in zip(fixtures, baseline, strict=True):
        observed = evaluation.observe(case, "default")
        assert case["id"] == archived["id"]
        for key in (
            "observed_action",
            "accepted",
            "signal",
            "callback_count",
            "dispatch_count",
            "comparisons",
            "diagnostics_safe",
            "repr_safe",
            "rejection_safe",
        ):
            assert observed[key] == archived[key], (case["id"], key)


def test_opt_in_improves_complete_phone_protection_and_retains_visible_limits():
    fixtures = evaluation.load_cases()
    preserved = copy.deepcopy(fixtures)
    rows = evaluation.evaluate(fixtures)
    assert fixtures == preserved
    assert len(rows) == 186
    default = [row for row in rows if row["phone_mode"] == "default"]
    formatted = [row for row in rows if row["phone_mode"] == "formatted"]
    assert evaluation.summarize(default)["exact_outcome_matches"] == 50
    assert evaluation.summarize(formatted)["exact_outcome_matches"] == 81
    direct = [row for row in formatted if row["id"].startswith("phone-")]
    for scope, total, matches in (
        ("baseline", 6, 6),
        ("proposed", 11, 11),
        ("benign", 16, 15),
        ("deferred", 6, 0),
    ):
        selected = [row for row in direct if row["coverage_scope"] == scope]
        assert len(selected) == total
        assert sum(not row["mismatches"] for row in selected) == matches
    assert all(not row["mismatches"] for row in formatted if row["id"].startswith("grammar-"))
    failures = [row for row in formatted if row["mismatches"]]
    assert len(failures) == 12
    assert all(row["known_limit"] or row["id"].endswith("raw-escaped") for row in failures)
    assert not any(row["unexpected_error"] or row["privacy_failures"] for row in rows)
    assert "+12025550123" not in json.dumps(rows)
    assert not any("text" in row or "delivered" in row or "diagnostics" in row for row in rows)


def test_decoded_pairs_share_exact_expected_delivery_but_raw_escapes_remain_misses():
    rows = evaluation.evaluate(evaluation.load_cases()[:63])
    selected = [row for row in rows if row["phone_mode"] == "formatted"]
    decoded = [row for row in selected if row["profile"] == "decoded_query_pii"]
    assert len(decoded) == 12
    assert all(not row["mismatches"] for row in decoded)
    # Both representations have independently stored identical desired dictionaries.
    pairs = {}
    for case in evaluation.load_cases()[:63]:
        if case["profile"] == "decoded_query_pii":
            pairs.setdefault(case["pair_id"], []).append(case["expected"]["delivered"])
    assert len(pairs) == 6
    assert all(len(values) == 2 and values[0] == values[1] for values in pairs.values())
    phone = [row for row in decoded if "formatted-phone" in row["id"]]
    assert all(
        row["decoded_action"] == "redact" and row["observed_action"] == "allow" for row in phone
    )
    assert all(row["dispatch_count"] == 1 for row in phone)
    blocked = [row for row in decoded if "secret" in row["id"]]
    assert all(row["dispatch_count"] == 0 and not row["accepted"] for row in blocked)


def test_wrong_authored_span_is_a_failure_even_when_detection_fires():
    fixture = copy.deepcopy(evaluation.load_cases()[6])
    fixture["expected"]["findings"][0]["end"] -= 1
    observed = evaluation.observe(fixture, "formatted")
    assert observed["signal"]
    assert not observed["comparisons"]["findings"]
    assert observed["comparisons"]["callback_inputs"]


@pytest.mark.parametrize("failure", ["duplicate", "version", "profile", "size"])
def test_comparison_loader_rejects_invalid_inputs(tmp_path, monkeypatch, failure):
    cases = evaluation.load_corpus(evaluation.CORPUS)
    if failure == "duplicate":
        cases[1]["id"] = cases[0]["id"]
    elif failure == "version":
        for case in cases:
            case["dataset_version"] = "unreviewed-version"
    elif failure == "profile":
        cases[0]["profile"] = "run_callback_error"
    path = tmp_path / "grammar.jsonl"
    path.write_bytes(
        b" " * 1_000_001
        if failure == "size"
        else "".join(json.dumps(case) + "\n" for case in cases).encode()
    )
    monkeypatch.setattr(evaluation, "CORPUS", path)
    with pytest.raises(ValueError):
        evaluation.load_cases()


@pytest.mark.parametrize("surface", ["diagnostics", "repr", "rejection"])
def test_privacy_failure_changes_exit_without_copying_payload(tmp_path, monkeypatch, surface):
    private = "+1 202 555 0123"
    original = evaluation.observe

    def unsafe(case, mode):
        result = original(case, mode)
        result[f"{surface}_safe"] = False
        result["diagnostics"] = {"private": private}
        return result

    monkeypatch.setattr(evaluation, "observe", unsafe)
    output = tmp_path / "evidence"
    assert evaluation.main(["--report-dir", str(output)]) == 1
    raw = (output / "results.json").read_text()
    assert private not in raw
    assert all(row["privacy_failures"] for row in json.loads(raw)["rows"])


def test_canary_checks_real_formatted_diagnostic_surface(monkeypatch):
    from guardtrellis import RunResult

    fixture = evaluation.load_cases()[6]
    monkeypatch.setattr(RunResult, "diagnostics", lambda self: {"leak": fixture["text"]})
    observed = evaluation.observe(fixture, "formatted")
    assert not observed["diagnostics_safe"]


def test_exception_is_failure_with_no_payload_or_traceback_in_report(tmp_path, monkeypatch):
    private = "private callback fixture should never be printed"

    def fail(*args):
        raise RuntimeError(private)

    monkeypatch.setattr(evaluation, "observe", fail)
    output = tmp_path / "evidence"
    assert evaluation.main(["--report-dir", str(output)]) == 1
    report = json.loads((output / "results.json").read_text())
    assert private not in json.dumps(report)
    assert all(row["unexpected_error"] for row in report["rows"])
    assert report["summary"]["default"]["exact_outcome_matches"] == 0


def test_actual_cli_resource_deadlines_source_hashes_and_report_preservation(tmp_path):
    output = tmp_path / "evidence"
    command = [
        sys.executable,
        str(evaluation.Path(evaluation.__file__)),
        "--resources",
        "--report-dir",
        str(output),
    ]
    first = subprocess.run(command, text=True, capture_output=True, check=False, timeout=30)
    assert first.returncode == 0, first.stderr
    before = (output / "results.json").read_bytes()
    report = json.loads(before)
    assert report["metadata"]["usage"] == "authored-development-only"
    assert "evaluation/formatted_phone/resources.py" in report["metadata"]["sha256"]
    assert (
        "evaluation/policy_combinations/detection_coverage_v1.jsonl" in report["metadata"]["sha256"]
    )
    assert all("\\" not in key for key in report["metadata"]["sha256"])
    for probe in report["resource_probes"]:
        assert probe["wall_budget_seconds"] == 10
        assert probe["contract_matches"] and probe["child_reaped"]
        assert probe["status"] == "completed"
        assert not probe["stderr_bytes"]
        assert len(probe["rows"]) == 8
        assert {row["scenario"] for row in probe["rows"]} == {
            item[0] for item in resources.scenarios()
        }
    second = subprocess.run(command, text=True, capture_output=True, check=False, timeout=30)
    assert second.returncode == 2
    assert "already exists" in second.stderr
    assert (output / "results.json").read_bytes() == before


def stub_resource_process(monkeypatch, payload, *, times_out=False):
    """Inject a child that exits successfully just after the supervisor's deadline."""

    class Process:
        returncode = 0
        wait_count = 0

        def __init__(self, args, **kwargs):
            kwargs["stdout"].write(json.dumps(payload).encode())
            kwargs["stdout"].flush()

        def wait(self, timeout):
            self.wait_count += 1
            if times_out and self.wait_count == 1:
                raise subprocess.TimeoutExpired("fixed worker", timeout)
            return self.returncode

        def poll(self):
            return self.returncode

    monkeypatch.setattr(resources.subprocess, "Popen", Process)


def valid_resource_payload():
    return {
        "limits": {
            "cpu_seconds": None,
            "address_space_bytes": None,
            "core_bytes": None,
            "output_file_bytes": None,
        },
        "resources": {"process_cpu_ms": 1.0, "peak_rss_bytes": None},
        "rows": [
            {
                "scenario": name,
                "input_chars": len(text),
                "operation_ms": 0.1,
                "action": default,
                "expected_action": default,
                "accepted": default != "error",
                "has_deliverable_text": default != "error",
                "finding_count": int(default == "error"),
                "finding_codes": ["text_limit_exceeded"] if default == "error" else [],
            }
            for name, text, default, _ in resources.scenarios()
        ],
    }


def test_late_valid_worker_output_cannot_overwrite_parent_timeout(monkeypatch):
    payload = valid_resource_payload()
    stub_resource_process(monkeypatch, payload)
    assert resources.measure("default")["contract_matches"]
    stub_resource_process(monkeypatch, payload, times_out=True)
    observed = resources.measure("default")
    assert observed["status"] == "wall_timeout"
    assert not observed["contract_matches"]
    assert observed["child_reaped"]
    assert observed["returncode"] == 0
    assert "rows" not in observed


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {"rows": None},
        {"limits": {}, "resources": {}, "rows": [None] * 8},
        {"limits": {}, "resources": {}, "rows": [{}] * 8},
        {"limits": {}, "resources": {}, "rows": "abcdefgh"},
    ],
)
def test_invalid_worker_payload_is_a_fixed_protocol_failure(monkeypatch, payload):
    stub_resource_process(monkeypatch, payload)
    observed = resources.measure("default")
    assert observed["status"] == "protocol_error"
    assert not observed["contract_matches"]
    assert observed["child_reaped"]
    assert "rows" not in observed


@pytest.mark.parametrize(
    "failure",
    [
        "duplicate",
        "missing",
        "wrong-id",
        "wrong-expectation",
        "input-type",
        "finding-type",
        "time-type",
        "time-nonfinite",
        "time-overflow",
        "resource-type",
        "boolean-type",
    ],
)
def test_worker_protocol_cannot_substitute_scenarios_or_metadata(monkeypatch, failure):
    payload = valid_resource_payload()
    first = payload["rows"][0]
    if failure == "duplicate":
        payload["rows"] = [first] * 8
    elif failure == "missing":
        payload["rows"].pop()
    elif failure == "wrong-id":
        first["scenario"] = "unreviewed-scenario"
    elif failure == "wrong-expectation":
        first["expected_action"] = "warn"
    elif failure == "input-type":
        first["input_chars"] = True
    elif failure == "finding-type":
        first["finding_count"] = "0"
    elif failure == "time-type":
        first["operation_ms"] = "fast"
    elif failure == "time-nonfinite":
        first["operation_ms"] = float("nan")
    elif failure == "time-overflow":
        first["operation_ms"] = 10**1000
    elif failure == "resource-type":
        payload["resources"]["peak_rss_bytes"] = "unknown"
    else:
        first["accepted"] = 1
    stub_resource_process(monkeypatch, payload)
    observed = resources.measure("default")
    assert observed["status"] == "protocol_error"
    assert not observed["contract_matches"]
    assert observed["child_reaped"]
    assert "rows" not in observed


def test_worker_action_is_compared_with_parent_expectation(monkeypatch):
    payload = valid_resource_payload()
    payload["rows"][0]["action"] = "warn"
    stub_resource_process(monkeypatch, payload)
    observed = resources.measure("default")
    assert observed["status"] == "completed"
    assert not observed["contract_matches"]
    assert observed["child_reaped"]
