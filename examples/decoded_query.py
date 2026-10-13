"""Run: python examples/decoded_query.py. Fabricated data; no credentials or network."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from guardtrellis import Guard, PIIScanner, Rejected, SecretScanner, Stage, ToolGuard, ToolResult

MAX_JSON_CHARS = 4_096
MAX_OUTPUT_CHARS = 4_096
MAX_QUERY_CHARS = 200
MAX_DEPTH = 2

TOOLS = ToolGuard(
    {
        "search": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": MAX_QUERY_CHARS},
            },
            "required": ["query"],
            "additionalProperties": False,
        }
    },
    # No serialized-text policies: this preflight preserves strict JSON/schema checks.
    max_chars=MAX_JSON_CHARS,
    max_depth=MAX_DEPTH,
)
QUERY_POLICY = Guard(
    tool_scanners=[SecretScanner(), PIIScanner(formats=["email"])],
    max_chars=MAX_QUERY_CHARS,
)


class WorkflowError(RuntimeError):
    """Callback failure with a fixed public message, excluding the original exception."""


def has_surrogate(text: str) -> bool:
    """JSON's decoder may accept unpaired UTF-16 surrogates; reject them explicitly."""
    return any("\ud800" <= char <= "\udfff" for char in text)


def check_query(name: str, arguments_json: str, *, query_guard: Guard = QUERY_POLICY) -> ToolResult:
    """Application recipe for exactly one field, using only public SDK APIs.

    Rejection raises before any normal return. The returned result describes the final
    serialized JSON validation; decoded findings are never mixed with wire-text offsets.
    The trusted query guard must configure TOOL scanners. Synchronous work has no deadline.
    """
    preflight = TOOLS.validate(name, arguments_json)
    checked_name, original_arguments = preflight.require_call()
    query = original_arguments["query"]
    if has_surrogate(query):
        raise Rejected("Decoded query rejected: query_unicode_invalid")

    query_result = query_guard.scan(query, stage=Stage.TOOL)
    checked_query = query_result.require_text()
    if has_surrogate(checked_query):
        raise Rejected("Decoded query rejected: replacement_unicode_invalid")
    if len(checked_query) > MAX_QUERY_CHARS:
        raise Rejected("Decoded query rejected: query_limit_exceeded")

    # Never edit or dispatch the preflight dictionary. Construct one bounded fresh object.
    try:
        serialized = json.dumps(
            {"query": checked_query}, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
    except Exception:
        raise Rejected("Decoded query rejected: serialization_error") from None
    if len(serialized) > MAX_OUTPUT_CHARS:
        raise Rejected("Decoded query rejected: output_limit_exceeded")

    final = TOOLS.validate(checked_name, serialized)
    # Recheck the schema after edits; an empty or oversized replacement is not a repair.
    final.require_call()
    return final


def run_workflow(
    name: str,
    arguments_json: str,
    authorize: Callable[[str, dict[str, Any]], bool],
    execute: Callable[[str, dict[str, Any]], str],
    *,
    query_guard: Guard = QUERY_POLICY,
) -> str:
    """Authorize the final checked pair, then execute it through the host callback.

    The authorizer receives a copy so it cannot mutate the dispatched arguments. Both
    callbacks are trusted synchronous host code. Errors stop execution/delivery, but
    cannot roll back side effects; identity, resource limits, and output checks are host-owned.
    """
    final = check_query(name, arguments_json, query_guard=query_guard)
    checked_name, arguments = final.require_call()
    try:
        authorized = authorize(checked_name, dict(arguments))
    except Exception:
        raise WorkflowError("Workflow callback failed") from None
    if authorized is not True:
        raise PermissionError("Tool request is not authorized")
    try:
        return execute(checked_name, arguments)
    except Exception:
        raise WorkflowError("Workflow callback failed") from None


def main() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def authorize(name: str, arguments: dict[str, Any]) -> bool:
        # A local demo grant only. Real hosts must use the caller's identity/permissions.
        return name == "search"

    def execute(name: str, arguments: dict[str, Any]) -> str:
        calls.append((name, arguments))
        return f"Local search query: {arguments['query']}"

    plain = '{"query":"Contact demo@example.org"}'
    escaped = r'{"query":"Contact demo\u0040example.org"}'
    for proposed in (plain, escaped):
        print(run_workflow("search", proposed, authorize, execute))
    assert calls == [("search", {"query": "Contact [PII]"})] * 2
    print("Equivalent plain and escaped queries reached the same checked local callback.")

    # Artificial signature only; the default policy blocks it before any dispatch.
    for name, proposed in (
        ("delete", "{}"),
        ("search", json.dumps({"query": "ghp_" + "A" * 36})),
        ("search", '{"query":"first","query":"second"}'),
    ):
        try:
            run_workflow(name, proposed, authorize, execute)
        except Rejected:
            pass
        else:
            raise AssertionError("Expected query rejection")
    assert len(calls) == 2

    try:
        run_workflow("search", plain, lambda name, arguments: False, execute)
    except PermissionError:
        pass
    else:
        raise AssertionError("Expected authorization denial")
    assert len(calls) == 2
    print("Rejected queries and authorization denial skipped execution.")


if __name__ == "__main__":
    main()
