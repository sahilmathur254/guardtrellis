"""Protect independent URI acceptance, historical comparisons and safe reporting."""

import copy
import hashlib
import json
import subprocess
import sys

import pytest

from evaluation.connection_strings import opt_in


@pytest.fixture(scope="module")
def rows():
    return opt_in.evaluate()


def find(rows, case_id, representation="plain", policy="secret_only", mode="connection_strings"):
    return next(
        row
        for row in rows
        if (row["id"], row["representation"], row["policy"], row["mode"])
        == (case_id, representation, policy, mode)
    )


def test_frozen_acceptance_and_narrow_documented_correction(tmp_path):
    original = json.loads(opt_in.ACCEPTANCE.read_text())
    assert len(original["rows"]) == 640
    assert sum(row["eligible"] for row in original["rows"]) == 402
    raw_overlap = next(
        row
        for row in original["rows"]
        if row["id"] == "contract-existing-token-overlap" and row["representation"] == "plain"
    )
    assert raw_overlap["uri_spans"] == []  # Preserve the original projection mistake.
    corrected = opt_in.load_acceptance()
    assert corrected["contract-existing-token-overlap", "plain"]["uri_spans"] == [[0, 81]]
    assert corrected["contract-existing-token-overlap", "json_plain"]["uri_spans"] == [[10, 91]]
    changed = tmp_path / "changed.json"
    changed.write_bytes(opt_in.ACCEPTANCE.read_bytes() + b" ")
    with pytest.raises(ValueError, match="Acceptance decisions changed"):
        opt_in.load_acceptance(changed)


def test_representation_eligibility_does_not_follow_detector_matches():
    decisions = opt_in.load_acceptance()
    for representation in ("plain", "decoded_plain", "decoded_escaped"):
        assert decisions["contract-double-quote-wrapper", representation]["eligible"]
    for representation in ("json_plain", "json_escaped"):
        assert not decisions["contract-double-quote-wrapper", representation]["eligible"]
    assert decisions["pg-userinfo", "json_plain"]["uri_spans"] == [[10, 62]]
    assert not decisions["contract-origin-mongo-query", "plain"]["eligible"]


def test_comparison_preserves_defaults_and_passes_only_eligible_contracts(rows):
    summary = opt_in.summarize(rows)
    assert summary["observations"] == 2560
    assert summary["eligible_opt_in_observations"] == 794
    for field in (
        "default_compatibility_failures",
        "contract_failures",
        "unexpected_errors",
        "privacy_failures",
        "harness_failures",
    ):
        assert summary[field] == 0
    raw = find(rows, "pg-userinfo", "json_escaped")
    assert not raw["contract_eligible"] and raw["contract_pass"] is None
    assert raw["comparisons"]["action"] is False
    decoded = find(rows, "pg-userinfo", "decoded_escaped")
    assert decoded["contract_pass"] and decoded["action"] == "block"
    assert decoded["uri_findings"] and not decoded["secret_signature_signal"]
    over_limit = find(rows, "pg-candidate-2001-characters")
    assert not over_limit["contract_eligible"] and over_limit["expected_limit_error"]
    assert over_limit["acceptance_reason"] == "fixed_return_input_limit"


def test_overlapping_token_and_uri_have_separate_acceptance(rows):
    row = find(rows, "contract-existing-token-overlap")
    assert row["contract_pass"]
    assert [(item["code"], item["start"], item["end"]) for item in row["uri_findings"]] == [
        ("secret_postgresql_uri", 0, 81)
    ]
    assert [item["code"] for item in row["existing_token_findings"]] == ["secret_github_classic"]
    assert row["acceptance_checks"]["existing_tokens"]
    # Broader desired comparisons retain the extra overlapping token as a mismatch.
    assert row["comparisons"]["target_spans"] is False


def test_acceptance_catches_missing_extra_and_lost_overlap_findings(rows):
    decisions = opt_in.load_acceptance()
    case_id = "contract-existing-token-overlap"
    observed = find(rows, case_id)
    default = find(rows, case_id, mode="default")
    decision = decisions[case_id, "plain"]
    missing = copy.deepcopy(observed)
    missing["findings"] = missing["existing_token_findings"]
    assert opt_in.acceptance_checks(missing, default, decision)["contract_pass"] is False
    lost_token = copy.deepcopy(observed)
    lost_token["findings"] = lost_token["uri_findings"]
    checked = opt_in.acceptance_checks(lost_token, default, decision)
    assert checked["acceptance_checks"]["existing_tokens"] is False
    negative_id = "benign-public-text"
    negative = copy.deepcopy(find(rows, negative_id))
    negative["findings"] = observed["uri_findings"]
    assert not opt_in.acceptance_checks(
        negative, find(rows, negative_id, mode="default"), decisions[negative_id, "plain"]
    )["contract_pass"]


def test_report_preserves_history_and_omits_payloads(rows, tmp_path):
    frozen = [opt_in.HERE / name for name in opt_in.CORPORA]
    frozen.extend(opt_in.HERE / name / "results.json" for name in opt_in.BASELINES)
    frozen.extend((opt_in.ACCEPTANCE, opt_in.CORRECTIONS))
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in frozen}
    destination = tmp_path / "safe comparison"
    report = opt_in.write_report(destination, rows)
    assert report["metadata"]["acceptance_sha256"] == opt_in.ACCEPTANCE_SHA256
    assert report["metadata"]["acceptance_corrections_sha256"] == opt_in.CORRECTIONS_SHA256
    assert "guardtrellis/_connection_strings.py" in report["metadata"]["sdk_sha256"]
    payload = (destination / "results.json").read_text()
    for case in opt_in.load_cases():
        for marker in (case["text"], *case["privacy_markers"]):
            assert marker not in payload
    with pytest.raises(FileExistsError):
        opt_in.write_report(destination, rows)
    assert (destination / "results.json").read_text() == payload
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in frozen}


def test_cli_writes_a_fresh_report_to_a_path_with_spaces(tmp_path):
    destination = tmp_path / "comparison results"
    completed = subprocess.run(
        [sys.executable, str(opt_in.Path(opt_in.__file__)), "--report-dir", str(destination)],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((destination / "results.json").read_text())
    assert json.loads(completed.stdout) == report["summary"]
    assert report["summary"]["contract_failures"] == 0
