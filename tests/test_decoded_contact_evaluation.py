"""Independent labels, privacy failures and report preservation for contact evidence."""

import copy
import json
import subprocess
import sys

import pytest

from evaluation.decoded_contact import run as evaluation


def cases():
    return evaluation.load_cases(evaluation.CORPUS.read_bytes())


def encoded(rows):
    return "".join(json.dumps(row) + "\n" for row in rows).encode()


def test_authored_pairs_and_rejections_are_not_detector_generated_labels():
    fixtures = cases()
    assert len(fixtures) == 24
    assert sum(case["representation"] == "invalid" for case in fixtures) == 8
    assert {case["usage"] for case in fixtures} == {"development"}
    assert len({case["pair_id"] for case in fixtures if case["representation"] != "invalid"}) == 8
    for case in fixtures:
        if case["pair_id"] == "formatted-phone":
            assert case["expected"] == {
                "accepted": True,
                "arguments": {"email": "contact fixture", "phone": "[PII]"},
                "action": "redact",
            }
            assert case["known_limit"]
        if case["pair_id"] == "literal-backslash":
            assert case["expected"]["arguments"]["email"] == r"casey\u0040example.org"


@pytest.mark.parametrize("failure", ["duplicate", "unknown", "label", "pair", "representation"])
def test_loader_rejects_ambiguous_or_malformed_corpus(failure):
    fixtures = cases()
    if failure == "duplicate":
        raw = encoded(fixtures).replace(b'"usage":', b'"usage":"development","usage":', 1)
    else:
        if failure == "unknown":
            fixtures[0]["unreviewed_metadata"] = "unexpected"
        elif failure == "label":
            fixtures[0]["expected"]["arguments"] = None
        elif failure == "pair":
            fixtures[1]["expected"]["arguments"]["email"] = "different fixture"
        else:
            fixtures[1]["representation"] = "plain"
        raw = encoded(fixtures)
    with pytest.raises(ValueError):
        evaluation.load_cases(raw)


def test_comparison_retains_raw_gaps_and_known_phone_misses_without_mutating_labels():
    fixtures = cases()
    before = copy.deepcopy(fixtures)
    rows = evaluation.evaluate(fixtures)
    assert len(rows) == 72
    assert fixtures == before
    for profile, mismatches in zip(evaluation.PROFILES, (9, 2, 2), strict=True):
        selected = [row for row in rows if row["profile"] == profile]
        assert sum(bool(row["mismatches"]) for row in selected) == mismatches
        assert not any(row["privacy_failures"] or row["unexpected_error"] for row in selected)
        if profile != "raw_serialized":
            assert all(row["known_limit"] for row in selected if row["mismatches"])
            assert all(row["paired_delivery_equal"] is not False for row in selected)
    assert "casey@example.org" not in json.dumps(rows)
    assert "+12025550123" not in json.dumps(rows)
    for row in rows:
        assert "arguments" not in row and "arguments_json" not in row
        if row["profile"] == "contact_helper" and row["pair_id"] == "email":
            assert row["protection_action"] == "redact"
            assert row["final_validation_action"] == "allow"
            assert row["finding_count"] == row["checked_call_count"] == 1
        if row["profile"] == "contact_helper" and row["pair_id"].startswith("secret-"):
            assert row["rejected"] and not row["accepted"]
            assert row["checked_call_count"] == 0
            assert row["protection_action"] is None


@pytest.mark.parametrize("surface", ["diagnostics", "repr", "rejection", "rejection-repr"])
@pytest.mark.parametrize("spelling", ["decoded", "wire-fragment", "whole-wire"])
def test_privacy_canaries_cover_decoded_and_exact_escaped_wire_surfaces(
    monkeypatch, surface, spelling, tmp_path
):
    fixtures = cases()[:2]
    escaped = fixtures[1]
    private = {
        "decoded": "casey@example.org",
        "wire-fragment": escaped["arguments_json"].split(":", 1)[1].split(",", 1)[0][1:-1],
        "whole-wire": escaped["arguments_json"],
    }[spelling]
    if surface == "diagnostics":
        monkeypatch.setattr(
            evaluation.decoded_contact.ContactResult, "diagnostics", lambda self: {"leak": private}
        )
    elif surface == "repr":
        monkeypatch.setattr(
            evaluation.decoded_contact.ContactResult, "__repr__", lambda self: private
        )
    else:

        def reject(*args):
            raise evaluation.Rejected("fixed rejection")

        monkeypatch.setattr(evaluation.decoded_contact, "check_contact", reject)
        monkeypatch.setattr(
            evaluation.Rejected,
            "__str__" if surface == "rejection" else "__repr__",
            lambda self: private,
        )
    rows = evaluation.evaluate(fixtures)
    assert any(row["privacy_failures"] for row in rows)
    report = evaluation.write_report(tmp_path / "fresh", {}, rows)
    assert private not in json.dumps(report)
    assert private not in (tmp_path / "fresh" / "results.json").read_text()


def test_unexpected_exception_is_reported_without_its_payload(monkeypatch):
    fixtures = cases()[:2]
    private = fixtures[0]["arguments_json"]

    def fail(*args):
        raise RuntimeError(private)

    monkeypatch.setattr(evaluation.decoded_contact, "check_contact", fail)
    rows = evaluation.evaluate(fixtures)
    assert sum(row["unexpected_error"] for row in rows) == 2
    assert private not in json.dumps(rows)


@pytest.mark.parametrize("failure", ["exception", "privacy"])
def test_cli_exit_fails_on_privacy_or_harness_error_and_keeps_safe_evidence(
    monkeypatch, tmp_path, failure
):
    def fail(*args):
        raise RuntimeError("private fixture from unsafe callback")

    if failure == "exception":
        monkeypatch.setattr(evaluation.decoded_contact, "check_contact", fail)
    else:
        monkeypatch.setattr(
            evaluation.decoded_contact.ContactResult,
            "diagnostics",
            lambda self: {"leak": "casey@example.org"},
        )
    assert evaluation.main(["--report-dir", str(tmp_path / "error")]) == 1
    output = (tmp_path / "error" / "results.json").read_text()
    assert "private fixture from unsafe callback" not in output
    summary = json.loads(output)["summary"]["contact_helper"]
    if failure == "exception":
        assert summary["unexpected_errors"] == 24
    else:
        assert summary["privacy_failures"] > 0
        assert "casey@example.org" not in output


def test_actual_cli_reports_source_hashes_and_refuses_existing_output(tmp_path):
    report_dir = tmp_path / "evidence"
    command = [
        sys.executable,
        str(evaluation.Path(evaluation.__file__)),
        "--report-dir",
        str(report_dir),
    ]
    first = subprocess.run(command, text=True, capture_output=True, check=False)
    assert first.returncode == 0, first.stderr
    report = report_dir / "results.json"
    before = report.read_bytes()
    evidence = json.loads(before)
    assert evidence["metadata"]["usage"] == "authored-development-only"
    assert "examples/decoded_contact.py" in evidence["metadata"]["sha256"]
    assert evidence["summary"]["contact_helper"]["known_limit_mismatches"] == 2
    second = subprocess.run(command, text=True, capture_output=True, check=False)
    assert second.returncode == 2
    assert "already exists" in second.stderr
    assert report.read_bytes() == before
