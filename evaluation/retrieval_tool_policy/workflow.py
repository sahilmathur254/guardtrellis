"""One fixed offline workflow and payload-free observation oracle for issue #35.

The worker executes these functions only after its caller verifies the frozen assets and
external receipt. Scenario proposals are scripted fixture data, never model responses.
"""

from __future__ import annotations

import copy
import json

from guardtrellis import Guard, PIIScanner, Rejected, SecretScanner, Stage, ToolGuard

from . import contract

MUTATIONS = frozenset(
    {
        "raw_retrieval",
        "raw_return",
        "alter_call",
        "early_consume",
        "raw_fallback",
        "payload_approval",
        "truthy_auth",
    }
)
MAX_ROW_BYTES = 48 * 1024
DIAGNOSTIC_CODES = frozenset(
    {
        "secret_github_classic",
        "pii_email",
        "text_limit_exceeded",
        "tool_not_allowed",
        "json_schema_mismatch",
        "json_duplicate_key",
        "json_invalid",
        "json_object_required",
        "json_too_deep",
        "json_non_finite",
        "json_schema_work_limit",
        "scanner_error",
        "finding_limit_exceeded",
        "invalid_text_type",
    }
)
SCANNERS = frozenset({"secrets", "pii", "json", "guard"})
ACTIONS = frozenset({"allow", "warn", "redact", "block", "error"})
STAGES = frozenset({"retrieval", "tool"})
DESIRED_KINDS = frozenset(
    {
        "semantic_intent_withheld",
        "structural_restriction",
        "host_authorization",
        "pattern_protection",
        "harness_control",
    }
)
DESIRED_REASONS = frozenset(
    {
        "semantic_intent_unclassified",
        "benign_task_preserved",
        "configured_control_enforced",
        "expected_failure_contained",
    }
)


class _Stop(Exception):
    """Internal, message-free workflow termination."""


def _tools():
    return ToolGuard(
        {
            "lookup": {
                "type": "object",
                "properties": {"document_id": {"type": "string", "minLength": 1, "maxLength": 64}},
                "required": ["document_id"],
                "additionalProperties": False,
            }
        },
        max_chars=contract.MAX_CHARS,
        max_depth=2,
    )


def _initial_state():
    return {
        "diagnostics": {"retrieval": None, "call": None, "returned": None},
        "events": [],
        "counts": {"proposer": 0, "authorize": 0, "execute": 0, "consume": 0},
        "proposer_input": None,
        "authorize_pair": None,
        "execute_pair": None,
        "consumer_text": None,
        "terminal": "accepted",
        "error_boundary": None,
    }


def _observe_state(case, mutation):
    state = _initial_state()
    policy = Guard(retrieval_scanners=[SecretScanner(), PIIScanner()], max_chars=contract.MAX_CHARS)
    tools = _tools()
    mode = case["callback_mode"]

    def stop(terminal):
        state["terminal"] = terminal
        raise _Stop

    def called(name):
        state["events"].append(name)
        state["counts"][name] += 1

    def callback_failure(boundary):
        state["error_boundary"] = boundary
        stop("callback_error")

    def consume(text):
        called("consume")
        state["consumer_text"] = text
        if mode == "consumer_error":
            # The exception deliberately carries fixture content; nothing catches or
            # serializes its message into an observation or a public diagnostic.
            raise RuntimeError(case["privacy_markers"][0])

    def propose(text):
        # No model or parsing: the proposal is independent of the supplied text.
        called("proposer")
        state["proposer_input"] = text
        return case["proposal"]["name"], case["proposal"]["arguments_json"]

    def authorize(name, arguments):
        called("authorize")
        state["authorize_pair"] = [name, copy.deepcopy(arguments)]
        if mode == "authorization_error":
            raise RuntimeError(case["privacy_markers"][0])
        if mode == "nonboolean_authorization":
            return 1
        if mode == "mutate_authorization":
            arguments["document_id"] = "private-guide"
            return True
        return name == "lookup" and arguments["document_id"] == "public-guide"

    def execute(name, arguments):
        called("execute")
        state["execute_pair"] = [name, copy.deepcopy(arguments)]
        if mode == "execution_error":
            raise RuntimeError(case["privacy_markers"][0])
        # This local fixture tool has no network, filesystem or other capability.
        return case["returned_text"]

    try:
        if mutation == "early_consume":
            consume(case["returned_text"])

        retrieved = policy.scan(case["retrieval_text"], stage=Stage.RETRIEVAL)
        state["diagnostics"]["retrieval"] = retrieved.diagnostics()
        state["events"].append("retrieval_checked")
        try:
            checked_retrieval = retrieved.require_text()
        except Rejected:
            stop("retrieval_rejected")
        state["events"].append("retrieval_delivered")

        proposer_input = (
            case["retrieval_text"] if mutation == "raw_retrieval" else checked_retrieval
        )
        proposed_name, arguments_json = propose(proposer_input)
        validated = tools.validate(proposed_name, arguments_json)
        state["diagnostics"]["call"] = validated.diagnostics()
        state["events"].append("call_checked")
        try:
            checked_name, checked_arguments = validated.require_call()
        except Rejected:
            stop("call_rejected")
        state["events"].append("call_delivered")

        authorized_arguments = checked_arguments.copy()
        try:
            permitted = authorize(checked_name, authorized_arguments)
        except Exception:
            callback_failure("authorize")
        if mutation == "payload_approval":
            permitted = True
        permission = bool(permitted) if mutation == "truthy_auth" else permitted is True
        if not permission:
            stop("host_denied")

        dispatch_arguments = checked_arguments.copy()
        if mutation == "alter_call":
            dispatch_arguments["document_id"] = "private-guide"
        try:
            raw_return = execute(checked_name, dispatch_arguments)
        except Exception as exc:
            if mutation == "raw_fallback":
                consume(str(exc))
            callback_failure("execute")

        returned = policy.scan(raw_return, stage=Stage.RETRIEVAL)
        state["diagnostics"]["returned"] = returned.diagnostics()
        state["events"].append("returned_checked")
        try:
            checked_return = returned.require_text()
        except Rejected:
            stop("return_rejected")
        state["events"].append("returned_delivered")
        try:
            consume(raw_return if mutation == "raw_return" else checked_return)
        except Exception:
            callback_failure("consume")
    except _Stop:
        pass
    except Exception:
        # Unexpected application/SDK errors remain failures without retaining the
        # exception object, its message, traceback, payload, path or environment.
        state["terminal"] = "unexpected_error"
    return state


def _bounded_int(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _valid_diagnostics(value):
    if value is None:
        return True
    if type(value) is not dict or value.keys() != {"action", "stage", "findings", "trace"}:
        return False
    if value["action"] not in ACTIONS or value["stage"] not in STAGES:
        return False
    findings, trace = value["findings"], value["trace"]
    if type(findings) is not list or len(findings) > 256:
        return False
    if type(trace) is not list or len(trace) > 3:
        return False
    for item in findings:
        if type(item) is not dict or item.keys() != {
            "code",
            "start",
            "end",
            "scanner",
            "scanner_index",
            "revision",
        }:
            return False
        if item["code"] not in DIAGNOSTIC_CODES or item["scanner"] not in SCANNERS | {""}:
            return False
        if not _bounded_int(item["scanner_index"], -1, 2):
            return False
        if not _bounded_int(item["revision"], 0, 2):
            return False
        if item["start"] is None and item["end"] is None:
            continue
        if (
            not _bounded_int(item["start"], 0, contract.MAX_CHARS)
            or not _bounded_int(item["end"], 1, contract.MAX_CHARS)
            or item["start"] >= item["end"]
        ):
            return False
    for item in trace:
        if type(item) is not dict or item.keys() != {
            "scanner",
            "scanner_index",
            "action",
            "revision_before",
            "revision_after",
        }:
            return False
        if item["scanner"] not in SCANNERS or item["action"] not in ACTIONS:
            return False
        if not _bounded_int(item["scanner_index"], 0, 2):
            return False
        if not all(_bounded_int(item[key], 0, 2) for key in ("revision_before", "revision_after")):
            return False
    return True


def _private_diagnostics(diagnostics, case):
    if not all(_valid_diagnostics(value) for value in diagnostics.values()):
        return False
    encoded = json.dumps(diagnostics, sort_keys=True, ensure_ascii=False, allow_nan=False)
    markers = [
        *case["privacy_markers"],
        case["retrieval_text"],
        case["returned_text"],
        case["proposal"]["arguments_json"],
    ]
    return not any(len(marker) >= 8 and marker in encoded for marker in markers)


def unexpected_error(state, expectation):
    """Separate authored ERROR controls from unexpected SDK/callback failures."""
    if state["terminal"] == "unexpected_error":
        return True
    if state["terminal"] == "callback_error" and (
        expectation["terminal"] != "callback_error"
        or state["error_boundary"] != expectation["error_boundary"]
    ):
        return True
    return any(
        diagnostic is not None
        and diagnostic["action"] == "error"
        and diagnostic != expectation["diagnostics"][boundary]
        for boundary, diagnostic in state["diagnostics"].items()
    )


def observe(case, expectation, *, mutation=None):
    """Compare one observation with its frozen oracle without returning payload values.

    ``mutation`` injects a deliberately broken harness path for regression checks only;
    mutated rows are never pooled into the twelve research-scenario results.
    """
    contract.validate_case(case)
    if mutation is not None and mutation not in MUTATIONS:
        raise ValueError("Invalid workflow mutation")
    desired = expectation["desired"]
    if (
        type(desired) is not dict
        or desired.keys() != {"kind", "met", "reason"}
        or desired["kind"] not in DESIRED_KINDS
        or type(desired["met"]) is not bool
        or desired["reason"] not in DESIRED_REASONS
    ):
        raise ValueError("Invalid frozen expectation")
    actual = _observe_state(case, mutation)
    comparisons = {key: actual[key] == expectation[key] for key in actual}
    diagnostics_private = _private_diagnostics(actual["diagnostics"], case)
    contract_matches = all(comparisons.values()) and diagnostics_private
    integrity_fields = (
        "events",
        "counts",
        "proposer_input",
        "authorize_pair",
        "execute_pair",
        "consumer_text",
        "terminal",
        "error_boundary",
    )
    row = {
        "id": case["id"],
        "intent": case["intent"],
        "focus": case["focus"],
        "terminal": actual["terminal"],
        "error_boundary": actual["error_boundary"],
        "diagnostics": actual["diagnostics"]
        if diagnostics_private
        else {"retrieval": None, "call": None, "returned": None},
        "events": actual["events"],
        "counts": actual["counts"],
        "eligible": {key: value is not None for key, value in actual["diagnostics"].items()},
        "comparisons": comparisons,
        "contract_matches": contract_matches,
        "delivery_integrity": all(comparisons[key] for key in integrity_fields),
        "diagnostics_private": diagnostics_private,
        "unexpected_error": unexpected_error(actual, expectation),
        "desired": {**desired, "met": desired["met"] and contract_matches},
    }
    if (
        len(json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False).encode())
        > MAX_ROW_BYTES
    ):
        row["diagnostics"] = {"retrieval": None, "call": None, "returned": None}
        row["contract_matches"] = False
        row["diagnostics_private"] = False
        row["desired"]["met"] = False
    return row
