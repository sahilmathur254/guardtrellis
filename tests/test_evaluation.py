"""Evaluation accounting must preserve misses, warnings, provenance, and prior reports."""

import hashlib
import json
import subprocess
import sys
from collections import defaultdict

import pytest

from evaluation import run as evaluation
from guardtrellis import Action, Finding, Guard, JSONScanner, Result, Stage

CORPUS = evaluation.HERE / "challenges/unicode_pii_v1.jsonl"


def corpus_bytes(cases):
    return "".join(json.dumps(case) + "\n" for case in cases).encode()


def test_fixture_provenance_and_json_pairs_are_explicit_and_consistent():
    cases = evaluation.load_cases(CORPUS.read_bytes())
    assert len(cases) == 40
    assert {case["dataset_version"] for case in cases} == {"unicode-pii-v1"}
    assert {case["usage"] for case in cases} == {"development"}
    assert {case["family"] for case in cases} == {"pii", "invisible"}
    pairs = defaultdict(list)
    for case in cases:
        assert "synthetic" in case["source"]
        assert "Codex assistance" in case["source"]
        assert case["label_basis"]
        if "pair_id" in case:
            pairs[case["pair_id"]].append(case)
    assert len(pairs) == 3
    json_guard = Guard(input_scanners=[JSONScanner()])
    for pair in pairs.values():
        assert len(pair) == 2
        assert {case["format"] for case in pair} == {"json-plain", "json-escaped"}
        assert (
            len({(case["family"], case["language"], case["expected_signal"]) for case in pair}) == 1
        )
        # Use strict validation first so duplicate keys cannot fake equivalence.
        assert all(json_guard.scan(case["text"]).accepted for case in pair)
        assert pair[0]["text"] != pair[1]["text"]
        assert json.loads(pair[0]["text"]) == json.loads(pair[1]["text"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", ""),
        ("family", "unknown"),
        ("expected_signal", "false"),
        ("expected_signal", 1),
        ("text", None),
        ("language", "not a language"),
        ("source", ""),
        ("dataset_version", ""),
        ("usage", "independent"),
        ("label_basis", None),
        ("format", ""),
        ("pair_id", "unsafe|table"),
    ],
)
def test_malformed_labels_or_missing_provenance_are_rejected(field, value):
    case = evaluation.load_cases(CORPUS.read_bytes())[0]
    case[field] = value
    with pytest.raises(ValueError):
        evaluation.load_cases(corpus_bytes([case]))


def test_duplicate_ids_and_mixed_versions_are_rejected():
    cases = evaluation.load_cases(CORPUS.read_bytes())[:2]
    with pytest.raises(ValueError, match="duplicate ID"):
        evaluation.load_cases(corpus_bytes([cases[0], cases[0]]))
    cases[1]["dataset_version"] = "unicode-pii-v2"
    with pytest.raises(ValueError, match="one dataset version"):
        evaluation.load_cases(corpus_bytes(cases))


def test_duplicate_metadata_keys_cannot_silently_replace_a_label():
    case = evaluation.load_cases(CORPUS.read_bytes())[0]
    duplicated = json.dumps(case)[:-1] + ', "expected_signal": false}\n'
    with pytest.raises(ValueError, match="Invalid JSON"):
        evaluation.load_cases(duplicated.encode())


def test_new_corpus_revision_agrees_with_its_recorded_digest():
    recorded = json.loads(
        (evaluation.HERE / "challenges/unicode_pii_v1/results.json").read_text(encoding="utf-8")
    )
    assert recorded["metadata"]["dataset_version"] == "unicode-pii-v1"
    assert recorded["metadata"]["corpus_sha256"] == hashlib.sha256(CORPUS.read_bytes()).hexdigest()


def test_legacy_labels_are_only_accepted_without_provenance_when_bytes_match():
    original = (evaluation.HERE / "corpus.jsonl").read_bytes()
    cases = evaluation.load_cases(original)
    assert len(cases) == 72
    assert {case["dataset_version"] for case in cases} == {"smoke-v1"}
    changed = [json.loads(line) for line in original.splitlines()]
    changed[0]["expected_signal"] = not changed[0]["expected_signal"]
    with pytest.raises(ValueError, match="provenance"):
        evaluation.load_cases(corpus_bytes(changed))


def test_warning_detection_is_not_blocking_and_errors_are_not_true_positives():
    cases = evaluation.load_cases(CORPUS.read_bytes())[:5]
    actions = [Action.WARN, Action.REDACT, Action.BLOCK, Action.ERROR, Action.ALLOW]
    positive = [False, True, True, True, True]
    answers = {}
    for case, action, expected in zip(cases, actions, positive, strict=True):
        case["expected_signal"] = expected
        case["text"] = "private-input-sentinel"
        case["unexpected_payload"] = "private-extra-sentinel"
        findings = () if action == Action.ALLOW else (Finding("static_code"),)
        answers[case["id"]] = Result(
            action,
            Stage.INPUT,
            None if action in (Action.BLOCK, Action.ERROR) else "private-output-sentinel",
            findings,
        )
    rows = evaluation.evaluate_cases(cases, lambda case: answers[case["id"]], 1)
    data = evaluation.summarize(rows)
    assert [row["outcome"] for row in rows] == ["fp", "tp", "tp", "error", "fn"]
    assert [row["accepted"] for row in rows] == [True, True, False, False, True]
    assert data["actions"] == {action.value: 1 for action in Action}
    assert data["precision"] == pytest.approx(2 / 3)
    assert data["recall"] == pytest.approx(2 / 3)
    assert data["false_positive_rate"] == 1
    assert "private-" not in json.dumps(rows)


def test_undefined_metric_denominators_are_null():
    data = evaluation.summarize(
        [
            {
                "outcome": "error",
                "observed_action": "error",
                "expected_signal": True,
                "latency_us": [1.0],
            }
        ]
    )
    assert data["precision"] is data["recall"] is data["false_positive_rate"] is None
    assert data["error"] == 1


def test_full_report_retains_language_counts_actions_and_provenance(tmp_path):
    output = tmp_path / "new-report"
    process = subprocess.run(
        [
            sys.executable,
            str(evaluation.HERE / "run.py"),
            "--corpus",
            str(CORPUS),
            "--iterations",
            "1",
            "--report-dir",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    assert process.stderr == ""
    data = json.loads((output / "results.json").read_text(encoding="utf-8"))
    report = (output / "REPORT.md").read_text(encoding="utf-8")
    assert data["metadata"]["dataset_version"] == "unicode-pii-v1"
    assert data["metadata"]["corpus_sha256"] == hashlib.sha256(CORPUS.read_bytes()).hexdigest()
    for name in ("source_sha256", "runner_sha256", "lockfile_sha256"):
        assert len(data["metadata"][name]) == 64
    assert data["metadata"]["unicode_database"]
    assert sum(family["cases"] for family in data["families"].values()) == 40
    for family, group in data["family_languages"].items():
        assert (
            sum(values["cases"] for values in group.values()) == data["families"][family]["cases"]
        )
        assert (
            sum(data["families"][family]["actions"].values()) == data["families"][family]["cases"]
        )
    assert "WARN permits delivery" in report
    assert "## Paired representations" in report
    for row in data["cases"]:
        assert "text" not in row
        if row["outcome"] in ("fp", "fn", "error"):
            assert f"`{row['id']}`: **{row['outcome']}**" in report
    original = (output / "results.json").read_bytes()
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--corpus", str(CORPUS), "--report-dir", str(output)])
    assert error.value.code == 2
    assert (output / "results.json").read_bytes() == original


@pytest.mark.parametrize("iterations", ["0", "-1", "1001"])
def test_cli_rejects_invalid_iteration_counts(tmp_path, iterations):
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--iterations", iterations, "--report-dir", str(tmp_path / "report")])
    assert error.value.code == 2


def test_cli_requires_an_explicit_destination():
    with pytest.raises(SystemExit) as error:
        evaluation.main([])
    assert error.value.code == 2


def test_errors_remain_in_report_and_return_nonzero(tmp_path):
    case = evaluation.load_cases(CORPUS.read_bytes())[0]
    case["text"] = "x" * 100_001
    file = tmp_path / "corpus.jsonl"
    file.write_bytes(corpus_bytes([case]))
    output = tmp_path / "report"
    assert (
        evaluation.main(["--corpus", str(file), "--iterations", "1", "--report-dir", str(output)])
        == 1
    )
    data = json.loads((output / "results.json").read_text(encoding="utf-8"))
    assert data["overall"]["error"] == 1
    assert data["cases"][0]["finding_codes"] == ["text_limit_exceeded"]
    assert data["cases"][0]["outcome"] == "error"


def test_default_smoke_keeps_every_historical_label(tmp_path):
    output = tmp_path / "smoke"
    assert evaluation.main(["--iterations", "1", "--report-dir", str(output)]) == 0
    old = json.loads((evaluation.HERE / "results.json").read_text(encoding="utf-8"))
    new = json.loads((output / "results.json").read_text(encoding="utf-8"))
    fields = ("id", "family", "expected_signal")
    assert [tuple(row[key] for key in fields) for row in new["cases"]] == [
        tuple(row[key] for key in fields) for row in old["cases"]
    ]
