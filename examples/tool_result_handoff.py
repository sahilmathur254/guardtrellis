"""Run: python examples/tool_result_handoff.py. Fabricated data; no network or credentials."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any, NoReturn
from uuid import uuid4

from guardtrellis import (
    Action,
    Guard,
    LiteralScanner,
    PIIScanner,
    Rejected,
    Result,
    SecretScanner,
    Stage,
    ToolGuard,
    ToolResult,
)

LOGGER = logging.getLogger("guardtrellis.tool_result_handoff")
MAX_RETURN_CHARS = 2_000
TOOLS = ToolGuard(
    {
        "lookup": {
            "type": "object",
            "properties": {
                "document_id": {"type": "string", "minLength": 1, "maxLength": 64},
            },
            "required": ["document_id"],
            "additionalProperties": False,
        }
    },
    max_chars=2_000,
    max_depth=2,
)
RETURN_POLICY = Guard(
    retrieval_scanners=[
        SecretScanner(),
        # A fixed application classification rule, not semantic injection detection.
        LiteralScanner(["internal-only"], action=Action.BLOCK),
        PIIScanner(),
    ],
    max_chars=MAX_RETURN_CHARS,
)


class WorkflowError(RuntimeError):
    """Callback failure whose public message excludes the original exception."""


def record_check(request_id: str, result: Result | ToolResult) -> None:
    """Log generated IDs and trusted scanner metadata, never complete result objects."""
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
    """Use a static boundary label; exclude exception messages and traceback locals."""
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
    name: str,
    arguments_json: str,
    authorize: Callable[[str, dict[str, Any]], bool],
    execute: Callable[[str, dict[str, Any]], str],
    consume: Callable[[str], None],
    *,
    result_guard: Guard = RETURN_POLICY,
) -> str:
    """Check returned context before the next model/state consumer receives it.

    The trusted result guard must configure RETRIEVAL scanners and suitable limits.
    This synchronous recipe has no deadline and cannot undo callback side effects.
    """
    request_id = uuid4().hex
    proposed_call = TOOLS.validate(name, arguments_json)
    record_check(request_id, proposed_call)
    checked_name, arguments = proposed_call.require_call()
    try:
        # This schema is flat; the authorizer cannot mutate the dispatched dictionary.
        permitted = authorize(checked_name, arguments.copy())
    except Exception:
        callback_failed(request_id, "authorization")
    if permitted is not True:
        raise PermissionError("Tool request is not authorized")

    try:
        raw_return = execute(checked_name, arguments)
    except Exception:
        callback_failed(request_id, "execution")

    # Keep the raw return out of prompts, model callbacks and agent state until this check.
    returned = result_guard.scan(raw_return, stage=Stage.RETRIEVAL)
    record_check(request_id, returned)
    checked_text = returned.require_text()
    try:
        # Passing raw_return here would silently discard redactions. Never fall back to it.
        consume(checked_text)
    except Exception:
        callback_failed(request_id, "consumption")
    return checked_text


def demo_authorize(name: str, arguments: dict[str, Any]) -> bool:
    """Host authorization for one fixed public document, separate from schema validity."""
    return name == "lookup" and arguments["document_id"] == "public-guide"


def demo_execute(name: str, arguments: dict[str, Any]) -> str:
    """A local text-returning tool; no external operation or persistent side effect."""
    if not demo_authorize(name, arguments):
        raise PermissionError("Tool request is not authorized")
    return "Public guide: contact demo@example.org"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    state: list[str] = []
    arguments_json = json.dumps({"document_id": "public-guide"})
    checked_text = run_workflow(
        "lookup", arguments_json, demo_authorize, demo_execute, state.append
    )
    assert checked_text == "Public guide: contact [PII]"
    assert state == [checked_text]
    print("The next state consumer received only the checked return containing [PII].")

    # Fabricated secret signature, classification marker, and oversized tool return.
    for raw_return in ("ghp_" + "A" * 36, "internal-only@example.org", "x" * 2_001):

        def execute_return(name: str, arguments: dict[str, Any], text: str = raw_return) -> str:
            return text

        try:
            run_workflow(
                "lookup",
                arguments_json,
                demo_authorize,
                execute_return,
                state.append,
            )
        except Rejected:
            pass
        else:
            raise AssertionError("Expected returned-text rejection")
    assert state == [checked_text]

    try:
        run_workflow(
            "lookup",
            json.dumps({"document_id": "private-guide"}),
            demo_authorize,
            demo_execute,
            state.append,
        )
    except PermissionError:
        pass
    else:
        raise AssertionError("Expected authorization denial")
    assert state == [checked_text]
    print("Rejected tool returns and authorization denial added nothing to the next state.")


if __name__ == "__main__":
    main()
