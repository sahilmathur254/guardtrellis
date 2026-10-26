"""Freeze boundary decisions separately from observations of the unchanged SDK."""

import copy
import hashlib
import json
import subprocess
import sys

import pytest

from evaluation.connection_strings import run_supplement as evaluation

CORPUS = evaluation.HERE / "boundaries_v1.jsonl"
PASSWORDS = {
    "boundary-pg-extra-colon": "BoundaryPgColon61:tail",
    "boundary-mongo-extra-colon": "BoundaryMgColon62:tail",
    "boundary-pg-multiple-at": "BoundaryPgFirst71@route.example.invalid",
    "boundary-mongo-multiple-at": "BoundaryMgFirst73@route.example.invalid",
    "boundary-pg-first-gap-empty": "@BoundaryPgInner72",
    "boundary-mongo-first-gap-empty": "@BoundaryMgInner74",
    "boundary-pg-encoded-password-separators": "BoundaryEncodedPg81%3Atail%40route",
    "boundary-mongo-encoded-password-separators": "BoundaryEncodedMg82%3Atail%40route",
    "boundary-pg-malformed-query-before": "BoundaryQueryBefore91",
    "boundary-pg-malformed-query-after": "BoundaryQueryAfter92",
}


def corpus_bytes(cases):
    return "".join(json.dumps(case) + "\n" for case in cases).encode("utf-8")


def test_boundary_decisions_and_original_character_spans_are_frozen_before_observations():
    assert hashlib.sha256(CORPUS.read_bytes()).hexdigest() == (
        "a54ede2cdfb221e63e3af03d7e94eb86f7bd9cbadd927884b4a7646e5ab6d7b6"
    )
    cases = evaluation.load_corpus(CORPUS)
    assert len(cases) == len({case["id"] for case in cases}) == 16
    assert {case["dataset_version"] for case in cases} == {evaluation.BOUNDARY_VERSION}
    assert {case["id"] for case in cases if case["expected_action"] == "block"} == set(PASSWORDS)
    for case in cases:
        assert case["origin_case_id"] is None
        assert case["contract_status"] == "selected"
        assert case["usage"] == "development"
        assert "2026-10-22" in case["source"]
        assert case["label_basis"] and case["case_group"]
        if case["id"] in PASSWORDS:
            assert case["label"] == "sensitive"
            assert case["target_spans"] == [[0, len(case["text"])]]
            assert [case["text"][a:b] for a, b in case["credential_spans"]] == [
                PASSWORDS[case["id"]]
            ]
        else:
            assert case["label"] == "benign" and case["expected_action"] == "allow"
            assert case["target_spans"] == case["credential_spans"] == []


def test_boundary_loader_rejects_mixed_versions_without_mutating_cases():
    boundary = evaluation.load_corpus(CORPUS)[0]
    contract = evaluation.load_corpus()[0]
    cases = [boundary, contract]
    original = copy.deepcopy(cases)
    for mixed in (cases, list(reversed(cases))):
        with pytest.raises(ValueError):
            evaluation.load_cases(corpus_bytes(mixed))
    assert cases == original


def test_new_boundary_rows_cannot_claim_an_original_ambiguous_case():
    origin = next(case for case in evaluation.load_corpus() if case["origin_case_id"])
    origin["dataset_version"] = evaluation.BOUNDARY_VERSION
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([origin]))


def test_single_boundary_case_is_valid_without_relabelling_the_default_corpus():
    case = evaluation.load_corpus(CORPUS)[0]
    assert evaluation.load_cases(corpus_bytes([case])) == [case]
    assert evaluation.CORPUS.name == "contract_supplement_v1.jsonl"
    assert len(evaluation.load_corpus()) == 60
    assert {item["dataset_version"] for item in evaluation.load_corpus()} == {evaluation.VERSION}


def test_boundary_observations_reuse_existing_policies_without_a_simulated_detector():
    cases = evaluation.load_corpus(CORPUS)
    original = copy.deepcopy(cases)
    rows = evaluation.evaluate(cases)
    assert cases == original
    assert len(rows) == 160
    assert [
        {key: value for key, value in row.items() if key not in evaluation.EXTRA_FIELDS}
        for row in rows
    ] == evaluation.base.evaluate(cases)
    assert {row["policy"] for row in rows} == {"secret_only", "tool_return"}
    assert not any(
        row["unexpected_error"] or row["privacy_failures"] or row["harness_failures"]
        for row in rows
    )


def test_boundary_report_identifies_its_source_and_preserves_frozen_evidence(tmp_path):
    frozen = [
        evaluation.HERE / "run.py",
        evaluation.HERE / "corpus_v1.jsonl",
        evaluation.CORPUS,
        *sorted((evaluation.HERE / "baseline_0.1.7").glob("*")),
        *sorted((evaluation.HERE / "contract_baseline_0.1.7").glob("*")),
        *sorted((evaluation.base.ROOT / "src" / "guardtrellis").rglob("*.py")),
    ]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in frozen}
    cases = evaluation.load_corpus(CORPUS)
    rows = evaluation.evaluate(cases)
    output = tmp_path / "boundary evidence"
    report = evaluation.write_report(output, rows, CORPUS)
    assert report["metadata"]["evaluation_version"] == evaluation.BOUNDARY_VERSION
    assert report["metadata"]["opt_in_status"] == "not_implemented"
    key = CORPUS.relative_to(evaluation.base.ROOT).as_posix()
    assert (
        report["metadata"]["source_sha256"][key] == hashlib.sha256(CORPUS.read_bytes()).hexdigest()
    )
    assert report["summary"]["observations"] == 160
    payload = (output / "results.json").read_text(encoding="utf-8")
    prose = (output / "REPORT.md").read_text(encoding="utf-8")
    for case in cases:
        for marker in (case["text"], *case["privacy_markers"]):
            assert marker not in payload
            assert marker not in prose
    with pytest.raises(FileExistsError):
        evaluation.write_report(output, rows, CORPUS)
    assert (output / "results.json").read_text(encoding="utf-8") == payload
    assert (output / "REPORT.md").read_text(encoding="utf-8") == prose
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in frozen}


def test_boundary_cli_accepts_explicit_corpus_and_paths_with_spaces(tmp_path):
    copied = tmp_path / "boundary corpus.jsonl"
    copied.write_bytes(CORPUS.read_bytes())
    output = tmp_path / "new boundary evidence"
    completed = subprocess.run(
        [
            sys.executable,
            str(evaluation.Path(evaluation.__file__)),
            "--corpus",
            str(copied),
            "--report-dir",
            str(output),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert json.loads(completed.stdout) == report["summary"]
    assert report["summary"]["observations"] == 160
    assert report["metadata"]["evaluation_version"] == evaluation.BOUNDARY_VERSION
    assert (
        report["metadata"]["source_sha256"]["external-corpus"]
        == hashlib.sha256(copied.read_bytes()).hexdigest()
    )
    assert report["metadata"]["opt_in_status"] == "not_implemented"
    assert report["summary"]["unexpected_errors"] == 0
    assert report["summary"]["privacy_failures"] == report["summary"]["harness_failures"] == 0
