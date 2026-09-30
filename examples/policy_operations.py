"""Run: python examples/policy_operations.py. Fabricated data; no network or credentials."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any, NoReturn
from uuid import uuid4

from guardtrellis import (
    Action,
    Guard,
    InvisibleScanner,
    LiteralScanner,
    PIIScanner,
    Rejected,
    Result,
    SecretScanner,
    Stage,
    ToolGuard,
    ToolResult,
)

LOGGER = logging.getLogger("guardtrellis.policy_operations")
POLICIES = Guard(
    input_scanners=[
        SecretScanner(),
        PIIScanner(formats=["email"]),
        InvisibleScanner(action=Action.WARN),
    ],
    retrieval_scanners=[
        SecretScanner(),
        # An application-owned document classification marker, not an injection detector.
        LiteralScanner(["internal-only"], action=Action.BLOCK),
        PIIScanner(formats=["email"]),
    ],
    output_scanners=[
        SecretScanner(),
        # This example's delivery policy rejects residual supported PII formats.
        PIIScanner(action=Action.BLOCK),
    ],
    max_chars=2_000,
)
TOOLS = ToolGuard(
    {
        "lookup": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string", "minLength": 1, "maxLength": 64},
                "query": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            "required": ["document_id", "query"],
            "additionalProperties": False,
        }
    },
    argument_scanners=[SecretScanner(), PIIScanner(formats=["email"])],
    max_chars=2_000,
)


class WorkflowError(RuntimeError):
    """A callback failed; the public message deliberately excludes the original error."""


def record_check(request_id: str, result: Result | ToolResult) -> None:
    """Only generated IDs and trusted scanner metadata belong in this log."""
    LOGGER.info(
        json.dumps(
            {
                "request_id": request_id,
                "event": "boundary_checked",
                "diagnostics": result.diagnostics(),
            },
            sort_keys=True,
        )
    )


def callback_failed(request_id: str, boundary: str) -> NoReturn:
    """Call with a static boundary label; do not log the exception or its traceback."""
    LOGGER.error(
        json.dumps(
            {
                "request_id": request_id,
                "event": "callback_failed",
                "boundary": boundary,
                "action": "error",
                "code": "callback_error",
            },
            sort_keys=True,
        )
    )
    raise WorkflowError("Workflow callback failed") from None


def run_workflow(
    user_text: str,
    retrieve: Callable[[str], str],
    propose: Callable[[str], tuple[str, str]],
    execute: Callable[[str, dict[str, Any]], str],
    deliver: Callable[[str], None],
) -> str:
    """Application-owned boundaries, using only checked values in downstream calls.

    BLOCK and ERROR raise Rejected; callback failures raise WorkflowError. Nothing
    rolls back callback side effects. The host still owns authorization and resources.
    """
    # Generate locally: never use a prompt, email, or unchecked request header as the ID.
    request_id = uuid4().hex
    input_result = POLICIES.scan(user_text, stage=Stage.INPUT)
    record_check(request_id, input_result)
    checked_input = input_result.require_text()
    try:
        retrieved_text = retrieve(checked_input)
    except Exception:
        callback_failed(request_id, "retrieval")

    retrieval_result = POLICIES.scan(retrieved_text, stage=Stage.RETRIEVAL)
    record_check(request_id, retrieval_result)
    prompt = checked_input + "\nReference: " + retrieval_result.require_text()
    try:
        proposed_name, arguments_json = propose(prompt)
    except Exception:
        callback_failed(request_id, "proposal")

    tool_result = TOOLS.validate(proposed_name, arguments_json)
    record_check(request_id, tool_result)
    name, arguments = tool_result.require_call()
    try:
        # The original proposed arguments are never dispatched.
        output = execute(name, arguments)
    except Exception:
        callback_failed(request_id, "execution")

    output_result = POLICIES.scan(output, stage=Stage.OUTPUT)
    record_check(request_id, output_result)
    checked_output = output_result.require_text()
    try:
        deliver(checked_output)
    except Exception:
        callback_failed(request_id, "delivery")
    return checked_output


def demo_execute(name: str, arguments: dict[str, Any]) -> str:
    """A separate host authorization decision before reading one in-memory document."""
    if name != "lookup" or arguments["document_id"] != "public-guide":
        raise PermissionError("Tool request is not authorized")
    return f"Public guide found. Query: {arguments['query']}"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    delivered: list[str] = []

    def retrieve(query: str) -> str:
        assert "demo@example.org" not in query
        return "Public guide maintained by reference@example.org"

    def propose(prompt: str) -> tuple[str, str]:
        assert "reference@example.org" not in prompt
        return "lookup", json.dumps({"document_id": "public-guide", "query": "other@example.net"})

    result = run_workflow(
        "Contact demo@example.org", retrieve, propose, demo_execute, delivered.append
    )
    assert result == "Public guide found. Query: [PII]"
    print("Checked callbacks received [PII] for matched emails; one result was delivered.")

    # WARN remains deliverable; this demonstration intentionally preserves the character.
    run_workflow("Public\u200b query", retrieve, propose, demo_execute, delivered.append)

    for text in ("ghp_" + "A" * 36, "x" * 2_001):
        try:
            run_workflow(text, retrieve, propose, demo_execute, delivered.append)
        except Rejected:
            pass
        else:
            raise AssertionError("Expected rejection")
    assert len(delivered) == 2
    print("WARN continued; BLOCK and ERROR stopped before retrieval or delivery.")


if __name__ == "__main__":
    main()
