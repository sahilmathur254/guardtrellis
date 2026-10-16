"""Validate the versioned corpus's provenance and semantic comparison pairs."""

import json
from collections import defaultdict

from evaluation.policy_combinations import run as evaluation

CORPUS = evaluation.HERE / "detection_coverage_v1.jsonl"


def test_coverage_corpus_preserves_authored_scope_and_provenance():
    cases = evaluation.load_cases(CORPUS.read_bytes())
    assert len(cases) == 63
    assert {case["dataset_version"] for case in cases} == {"detection-coverage-v1"}
    assert {case["usage"] for case in cases} == {"development"}
    assert {case["coverage_scope"] for case in cases} == {
        "baseline",
        "proposed",
        "benign",
        "deferred",
    }
    for case in cases:
        assert "synthetic" in case["source"] and "Codex assistance" in case["source"]
        assert case["label_basis"]
        assert all(len(marker) >= 8 for marker in case["privacy_markers"])


def test_json_pairs_have_same_meaning_and_desired_checked_delivery():
    groups = defaultdict(list)
    for case in evaluation.load_cases(CORPUS.read_bytes()):
        if case["profile"] in ("tool_query_pii", "decoded_query_pii"):
            groups[case["pair_id"]].append(case)
    assert len(groups) == 6
    for group in groups.values():
        assert len(group) == 4
        assert {(case["profile"], case["format"]) for case in group} == {
            (profile, format_name)
            for profile in ("tool_query_pii", "decoded_query_pii")
            for format_name in ("json-plain", "json-escaped")
        }
        first = group[0]
        for case in group:
            assert json.loads(case["text"]) == json.loads(first["text"])
            assert case["expected_signal"] == first["expected_signal"]
            for field in ("accepted", "delivered", "dispatches", "checked_json_valid"):
                assert case["expected"][field] == first["expected"][field]
            # A structural preflight accepts the fixture even when its policy blocks.
            assert evaluation.decoded_query.TOOLS.validate("search", case["text"]).accepted
