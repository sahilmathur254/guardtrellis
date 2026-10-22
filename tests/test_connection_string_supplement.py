"""Proposed URI decisions remain separate from the unchanged SDK's observations."""

import copy
import hashlib
import json
import subprocess
import sys
from collections import Counter

import pytest

from evaluation.connection_strings import run_supplement as evaluation


def corpus_bytes(cases):
    return "".join(json.dumps(case) + "\n" for case in cases).encode("utf-8")


def cases_by_id():
    return {case["id"]: case for case in evaluation.load_corpus()}


def test_supplement_retains_new_provenance_and_all_twelve_original_ambiguous_inputs():
    assert hashlib.sha256(evaluation.CORPUS.read_bytes()).hexdigest() == (
        "586d3e9d6a0bff898dd6d593f7927a95039c3d6b607fe14e1a1b371a0563a13c"
    )
    cases = evaluation.load_corpus()
    assert len(cases) == len({case["id"] for case in cases}) == 60
    assert {case["dataset_version"] for case in cases} == {"connection-strings-contract-v1"}
    assert Counter(case["contract_status"] for case in cases) == {
        "selected": 52,
        "excluded": 6,
        "resource_pending": 2,
    }
    origins = {
        case["id"]: case for case in evaluation.base.load_corpus() if case["label"] == "ambiguous"
    }
    mapped = [case for case in cases if case["origin_case_id"] is not None]
    assert len(mapped) == len(origins) == 12
    assert {case["origin_case_id"] for case in mapped} == set(origins)
    for case in mapped:
        assert case["text"] == origins[case["origin_case_id"]]["text"]
    for case in cases:
        assert case["case_group"] and case["label_basis"] and case["source"]
        assert case["usage"] == "development"
        if case["contract_status"] == "selected":
            assert case["expected_action"] in ("allow", "block")
        else:
            assert case["label"] == "ambiguous" and case["expected_action"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("dataset_version", "connection-strings-v1"),
        ("case_group", "unknown|unsafe"),
        ("case_group", ""),
        ("case_group", None),
        ("origin_case_id", "unknown-origin"),
        ("origin_case_id", 1),
        ("contract_status", "passed"),
        ("contract_status", "excluded"),
        ("contract_status", "resource_pending"),
        ("expected_action", None),
        ("expected_action", "redact"),
        ("expected_action", "error"),
        ("usage", "held-out"),
        ("target_spans", [[0, 100_000]]),
        ("text", None),
        ("candidate_count", True),
        ("unexpected_field", "untrusted data"),
    ],
)
def test_loader_rejects_invalid_supplement_contracts(field, value):
    case = copy.deepcopy(cases_by_id()["contract-origin-mask"])
    case[field] = value
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([case]))


@pytest.mark.parametrize("field", ["case_group", "origin_case_id", "contract_status"])
def test_loader_requires_each_new_provenance_field(field):
    case = copy.deepcopy(cases_by_id()["contract-origin-mask"])
    del case[field]
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([case]))


def test_loader_preserves_origin_text_rejects_duplicate_origins_and_allows_subsets():
    case = cases_by_id()["contract-origin-mask"]
    original = copy.deepcopy(case)
    assert evaluation.load_cases(corpus_bytes([case])) == [case]
    assert case == original
    modified = {**case, "text": case["text"] + "changed"}
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([modified]))
    duplicate_origin = {**case, "id": "new-id-same-origin"}
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([case, duplicate_origin]))


def test_loader_rejects_duplicate_keys_ids_empty_oversized_and_invalid_utf8():
    case = cases_by_id()["contract-upper-pg"]
    duplicate_key = json.dumps(case)[:-1] + ', "contract_status": "selected"}\n'
    for raw in (
        b"",
        b"\xff",
        b"not JSON",
        b" " * (evaluation.base.MAX_CORPUS_BYTES + 1),
        corpus_bytes([case, case]),
        duplicate_key.encode("utf-8"),
    ):
        with pytest.raises(ValueError):
            evaluation.load_cases(raw)


def test_current_observations_equal_frozen_harness_without_simulating_the_new_scanner():
    cases = evaluation.load_corpus()
    preserved = copy.deepcopy(cases)
    rows = evaluation.evaluate(cases)
    existing = evaluation.base.evaluate(cases)
    assert cases == preserved
    assert len(rows) == len(existing) == 600
    assert [
        {key: value for key, value in row.items() if key not in evaluation.EXTRA_FIELDS}
        for row in rows
    ] == existing
    assert {row["policy"] for row in rows} == {"secret_only", "tool_return"}
    assert not any(row["unexpected_error"] or row["harness_failures"] for row in rows)
    assert not any(row["privacy_failures"] for row in rows)
    for row in rows:
        if row["contract_status"] != "selected":
            assert all(value is None for value in row["comparisons"].values())


def test_resource_pending_rows_do_not_turn_input_errors_into_passed_production_limits(tmp_path):
    cases = [
        case for case in evaluation.load_corpus() if case["contract_status"] == "resource_pending"
    ]
    report = evaluation.write_report(tmp_path / "pending-evidence", evaluation.evaluate(cases))
    summary = report["by_contract_status"]["resource_pending"]
    assert summary["observations"] == 20
    assert summary["scored"] == summary["exact_outcome_matches"] == 0
    assert summary["policy_dependent"] == 20
    assert summary["expected_limit_errors"] > 0
    assert summary["unexpected_errors"] == 0
    assert report["metadata"]["opt_in_status"] == "not_implemented"
    prose = (tmp_path / "pending-evidence" / "REPORT.md").read_text(encoding="utf-8")
    assert "No resource-limit experiment is performed here" in prose


def test_current_token_control_block_does_not_claim_whole_uri_detection():
    rows = evaluation.evaluate([cases_by_id()["contract-existing-token-overlap"]])
    plain = next(
        row for row in rows if row["policy"] == "secret_only" and row["representation"] == "plain"
    )
    assert plain["action"] == "block" and plain["secret_signature_signal"]
    assert plain["consumer_count"] == 0
    assert plain["comparisons"]["action"] and plain["comparisons"]["delivery"]
    assert not plain["comparisons"]["target_spans"]


def test_short_public_input_does_not_match_metadata_field_names():
    case = copy.deepcopy(cases_by_id()["contract-benign-credential-free"])
    case["text"] = "status"
    case["candidate_count"] = 0
    rows = evaluation.evaluate(evaluation.load_cases(corpus_bytes([case])))
    assert all(row["action"] == "allow" for row in rows)
    assert not any(row["privacy_failures"] or row["harness_failures"] for row in rows)


@pytest.mark.parametrize("field", ["case_group", "id"])
def test_new_metadata_cannot_echo_a_credential_canary(field, tmp_path, capsys):
    case = copy.deepcopy(cases_by_id()["contract-upper-pg"])
    private = "synthetic-private-metadata-canary"
    case[field] = private
    case["privacy_markers"].append(private)
    corpus = tmp_path / "unsafe-metadata.jsonl"
    corpus.write_bytes(corpus_bytes([case]))
    output = tmp_path / "evidence"
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--corpus", str(corpus), "--report-dir", str(output)])
    assert error.value.code == 2
    assert not output.exists()
    captured = capsys.readouterr()
    assert private not in captured.out + captured.err


def test_payload_bearing_observation_error_is_sanitized_by_reused_harness(
    tmp_path, monkeypatch, capsys
):
    private = "synthetic-private-exception-canary"

    def fail(*_args):
        raise RuntimeError(private)

    monkeypatch.setattr(evaluation.base, "observe", fail)
    corpus = tmp_path / "single-case.jsonl"
    corpus.write_bytes(corpus_bytes([cases_by_id()["contract-upper-pg"]]))
    output = tmp_path / "evidence"
    assert evaluation.main(["--corpus", str(corpus), "--report-dir", str(output)]) == 1
    report = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert report["summary"]["unexpected_errors"] == 10
    assert report["summary"]["harness_failures"] == 10
    assert report["summary"]["exact_outcome_matches"] == 0
    assert report["metadata"]["opt_in_status"] == "not_implemented"
    captured = capsys.readouterr()
    assert private not in captured.out + captured.err
    assert private not in json.dumps(report)
    assert private not in (output / "REPORT.md").read_text(encoding="utf-8")


def test_report_is_immutable_identifies_both_runners_and_preserves_frozen_inputs(tmp_path):
    frozen = [
        evaluation.HERE / "run.py",
        evaluation.HERE / "corpus_v1.jsonl",
        evaluation.HERE / "baseline_0.1.7" / "results.json",
        evaluation.HERE / "baseline_0.1.7" / "REPORT.md",
        *sorted((evaluation.base.ROOT / "src" / "guardtrellis").glob("*.py")),
    ]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in frozen}
    cases = evaluation.load_corpus()
    rows = evaluation.evaluate(cases)
    output = tmp_path / "evidence"
    report = evaluation.write_report(output, rows)
    assert report["metadata"]["evaluation_version"] == "connection-strings-contract-v1"
    assert report["metadata"]["opt_in_status"] == "not_implemented"
    assert report["metadata"]["usage"] == "authored-development-only"
    hashes = report["metadata"]["source_sha256"]
    for name in (
        "evaluation/connection_strings/run_supplement.py",
        "evaluation/connection_strings/run.py",
        "evaluation/connection_strings/contract_supplement_v1.jsonl",
        "evaluation/connection_strings/corpus_v1.jsonl",
        "evaluation/connection_strings/PROPOSAL.md",
    ):
        assert name in hashes
    for name, digest in hashes.items():
        assert "\\" not in name
        assert hashlib.sha256((evaluation.base.ROOT / name).read_bytes()).hexdigest() == digest
    payload = (output / "results.json").read_bytes()
    prose = (output / "REPORT.md").read_bytes()
    with pytest.raises(FileExistsError):
        evaluation.write_report(output, rows)
    assert (output / "results.json").read_bytes() == payload
    assert (output / "REPORT.md").read_bytes() == prose
    for case in cases:
        assert case["text"] not in payload.decode("utf-8")
        assert all(marker not in payload.decode("utf-8") for marker in case["privacy_markers"])
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in frozen}


def test_actual_cli_reports_current_sdk_and_pending_contract_separately(tmp_path):
    output = tmp_path / "evidence with spaces"
    completed = subprocess.run(
        [sys.executable, str(evaluation.Path(evaluation.__file__)), "--report-dir", str(output)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert json.loads(completed.stdout) == report["summary"]
    assert report["summary"]["observations"] == 600
    assert report["summary"]["scored"] == 520
    assert report["summary"]["policy_dependent"] == 80
    assert report["summary"]["positive_cases_without_secret_signature"] > 0
    assert report["summary"]["harness_failures"] == report["summary"]["privacy_failures"] == 0
    assert report["metadata"]["opt_in_status"] == "not_implemented"
