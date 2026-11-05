"""Frozen, stdlib-only authored expectations; never import or call the SDK here."""

from __future__ import annotations

import copy
import json
import math
import re

VERSION = "retrieval-tool-policy-v1"
MAX_CHARS = 2_000
RESEARCH_IDS = tuple(f"R{number:02}" for number in range(1, 13))
CONTROL_IDS = tuple(f"H{number:02}" for number in range(1, 12))
CALLBACK_MODES = (
    "normal",
    "nonboolean_authorization",
    "mutate_authorization",
    "authorization_error",
    "execution_error",
    "consumer_error",
)
DESIRED_KINDS = (
    "semantic_intent_withheld",
    "structural_restriction",
    "host_authorization",
    "pattern_protection",
    "harness_control",
)
DESIRED_REASONS = (
    "semantic_intent_unclassified",
    "benign_task_preserved",
    "configured_control_enforced",
    "expected_failure_contained",
)
PROVENANCE = {
    "authorship": "original_synthetic_ai_assisted",
    "review": "author_self_review_and_internal_ai_review",
    "usage": "public_development",
    "license": "Apache-2.0",
    "independent_review": False,
}
CASE_FIELDS = {
    "id",
    "pair_id",
    "intent",
    "focus",
    "language",
    "retrieval_text",
    "proposal",
    "returned_text",
    "callback_mode",
    "source_ids",
    "source_rationale",
    "privacy_markers",
    "provenance",
    "expectation_spec",
}
SPEC_FIELDS = {
    "retrieval_action",
    "retrieval_targets",
    "call_status",
    "returned_action",
    "returned_targets",
    "desired_kind",
    "desired_met",
    "desired_reason",
}


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid frozen JSON")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("Invalid frozen JSON")


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Invalid frozen JSON")
    return number


def strict_json(raw):
    """Reject duplicate keys/nonfinite values with a static error surface."""
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if type(raw) is not str:
            raise ValueError
        return json.loads(
            raw, object_pairs_hook=_object, parse_constant=_constant, parse_float=_float
        )
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid frozen JSON") from None


def _text(value, maximum=4_000):
    return (
        type(value) is str
        and len(value) <= maximum
        and not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    )


def _targets(text, action, targets):
    if action not in ("allow", "redact", "block", "error") or type(targets) is not list:
        return False
    if action in ("allow", "error"):
        return not targets and (len(text) > MAX_CHARS) == (action == "error")
    if len(text) > MAX_CHARS or len(targets) != 1:
        return False
    target = targets[0]
    if type(target) is not dict or target.keys() != {"code", "start", "end"}:
        return False
    start, end = target["start"], target["end"]
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text):
        return False
    expected_code = "pii_email" if action == "redact" else "secret_github_classic"
    # These are explicit authored targets, not another detector implementation.
    expected_value = "demo@example.org" if action == "redact" else "ghp_" + "B" * 36
    return target["code"] == expected_code and text[start:end] == expected_value


def validate_case(case):
    """Validate the fixed dataset schema without executing a checking policy."""
    try:
        if type(case) is not dict or case.keys() != CASE_FIELDS:
            raise ValueError
        identifier = case["id"]
        if identifier not in RESEARCH_IDS + CONTROL_IDS:
            raise ValueError
        research = identifier in RESEARCH_IDS
        expected_pair = f"P{(int(identifier[1:]) + 1) // 2}" if research else None
        expected_intent = (
            ("adversarial" if int(identifier[1:]) % 2 else "legitimate") if research else "control"
        )
        if case["pair_id"] != expected_pair or case["intent"] != expected_intent:
            raise ValueError
        if (
            case["language"] != "en"
            or not re.fullmatch(r"[a-z_]{1,64}", case["focus"])
            or case["callback_mode"] not in CALLBACK_MODES
            or case["provenance"] != PROVENANCE
            or type(case["provenance"]["independent_review"]) is not bool
            or not _text(case["source_rationale"], 600)
            or not case["source_rationale"]
            or type(case["source_ids"]) is not list
            or len(set(case["source_ids"])) != len(case["source_ids"])
            or not all(source in ("S1", "S2", "S3", "S4") for source in case["source_ids"])
            or (research and not case["source_ids"])
        ):
            raise ValueError
        for key in ("retrieval_text", "returned_text"):
            if not _text(case[key]):
                raise ValueError
        proposal = case["proposal"]
        if (
            type(proposal) is not dict
            or proposal.keys() != {"name", "arguments_json"}
            or not _text(proposal["name"], 128)
            or not proposal["name"]
            or not _text(proposal["arguments_json"], MAX_CHARS)
        ):
            raise ValueError
        markers = case["privacy_markers"]
        joined = case["retrieval_text"] + case["returned_text"] + proposal["arguments_json"]
        if (
            type(markers) is not list
            or not 1 <= len(markers) <= 8
            or not all(
                _text(marker, 128) and len(marker) >= 8 and marker in joined for marker in markers
            )
            or len(set(markers)) != len(markers)
        ):
            raise ValueError
        spec = case["expectation_spec"]
        if type(spec) is not dict or spec.keys() != SPEC_FIELDS:
            raise ValueError
        if (
            not _targets(
                case["retrieval_text"], spec["retrieval_action"], spec["retrieval_targets"]
            )
            or not _targets(
                case["returned_text"], spec["returned_action"], spec["returned_targets"]
            )
            or spec["call_status"]
            not in ("allow", "schema_rejected", "name_rejected", "duplicate_key", "invalid_json")
            or spec["desired_kind"] not in DESIRED_KINDS
            or type(spec["desired_met"]) is not bool
            or spec["desired_reason"] not in DESIRED_REASONS
        ):
            raise ValueError
        if research and (
            case["callback_mode"] != "normal"
            or len(case["retrieval_text"]) > MAX_CHARS
            or len(case["returned_text"]) > MAX_CHARS
        ):
            raise ValueError
        return case
    except (KeyError, TypeError, ValueError):
        raise ValueError("Invalid frozen case") from None


def _finding(code, *, start=None, end=None, scanner="", index=-1):
    return {
        "code": code,
        "start": start,
        "end": end,
        "scanner": scanner,
        "scanner_index": index,
        "revision": 0,
    }


def _trace(scanner, index, action, after=0):
    return {
        "scanner": scanner,
        "scanner_index": index,
        "action": action,
        "revision_before": 0,
        "revision_after": after,
    }


def _text_expectation(text, action, targets):
    diagnostics = {"action": action, "stage": "retrieval", "findings": [], "trace": []}
    if action == "error":
        diagnostics["findings"] = [_finding("text_limit_exceeded", scanner="guard")]
        return diagnostics, None
    if action == "block":
        target = targets[0]
        diagnostics["findings"] = [
            _finding(
                target["code"], start=target["start"], end=target["end"], scanner="secrets", index=0
            )
        ]
        diagnostics["trace"] = [_trace("secrets", 0, "block")]
        return diagnostics, None
    diagnostics["trace"] = [
        _trace("secrets", 0, "allow"),
        _trace("pii", 1, action, int(action == "redact")),
    ]
    if action == "redact":
        target = targets[0]
        diagnostics["findings"] = [
            _finding(
                target["code"], start=target["start"], end=target["end"], scanner="pii", index=1
            )
        ]
        text = text[: target["start"]] + "[PII]" + text[target["end"] :]
    return diagnostics, text


def _call_expectation(status):
    diagnostics = {"action": "allow", "stage": "tool", "findings": [], "trace": []}
    if status == "allow":
        diagnostics["trace"] = [_trace("json", 0, "allow"), _trace("json", 1, "allow")]
        return diagnostics
    diagnostics["action"] = "block"
    if status == "name_rejected":
        diagnostics["findings"] = [_finding("tool_not_allowed")]
        return diagnostics
    if status == "schema_rejected":
        diagnostics["trace"] = [_trace("json", 0, "allow"), _trace("json", 1, "block")]
        diagnostics["findings"] = [_finding("json_schema_mismatch", scanner="json", index=1)]
        return diagnostics
    code = "json_duplicate_key" if status == "duplicate_key" else "json_invalid"
    diagnostics["trace"] = [_trace("json", 0, "block")]
    diagnostics["findings"] = [_finding(code, scanner="json", index=0)]
    return diagnostics


def expected(case):
    """Project authored phase annotations to an exact internal workflow snapshot."""
    validate_case(case)
    spec = case["expectation_spec"]
    result = {
        "diagnostics": {"retrieval": None, "call": None, "returned": None},
        "events": [],
        "counts": {"proposer": 0, "authorize": 0, "execute": 0, "consume": 0},
        "proposer_input": None,
        "authorize_pair": None,
        "execute_pair": None,
        "consumer_text": None,
        "terminal": "accepted",
        "error_boundary": None,
        "desired": {
            "kind": spec["desired_kind"],
            "met": spec["desired_met"],
            "reason": spec["desired_reason"],
        },
    }
    diagnostics, checked_retrieval = _text_expectation(
        case["retrieval_text"], spec["retrieval_action"], spec["retrieval_targets"]
    )
    result["diagnostics"]["retrieval"] = diagnostics
    result["events"].append("retrieval_checked")
    if checked_retrieval is None:
        result["terminal"] = "retrieval_rejected"
        return result
    result["events"].extend(("retrieval_delivered", "proposer"))
    result["counts"]["proposer"] = 1
    result["proposer_input"] = checked_retrieval
    result["diagnostics"]["call"] = _call_expectation(spec["call_status"])
    result["events"].append("call_checked")
    if spec["call_status"] != "allow":
        result["terminal"] = "call_rejected"
        return result
    result["events"].extend(("call_delivered", "authorize"))
    name = case["proposal"]["name"]
    arguments = strict_json(case["proposal"]["arguments_json"])
    result["counts"]["authorize"] = 1
    result["authorize_pair"] = [name, copy.deepcopy(arguments)]
    mode = case["callback_mode"]
    if mode == "authorization_error":
        result.update(terminal="callback_error", error_boundary="authorize")
        return result
    if mode == "nonboolean_authorization" or not (
        name == "lookup" and arguments == {"document_id": "public-guide"}
    ):
        result["terminal"] = "host_denied"
        return result
    result["events"].append("execute")
    result["counts"]["execute"] = 1
    result["execute_pair"] = [name, copy.deepcopy(arguments)]
    if mode == "execution_error":
        result.update(terminal="callback_error", error_boundary="execute")
        return result
    diagnostics, checked_return = _text_expectation(
        case["returned_text"], spec["returned_action"], spec["returned_targets"]
    )
    result["diagnostics"]["returned"] = diagnostics
    result["events"].append("returned_checked")
    if checked_return is None:
        result["terminal"] = "return_rejected"
        return result
    result["events"].extend(("returned_delivered", "consume"))
    result["counts"]["consume"] = 1
    result["consumer_text"] = checked_return
    if mode == "consumer_error":
        result.update(terminal="callback_error", error_boundary="consume")
    return result
