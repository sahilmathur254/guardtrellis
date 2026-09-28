"""Run: python examples/retrieval_tools.py. Fabricated data; no credentials or network."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from guardtrellis import Guard, PIIScanner, Rejected, SecretScanner, Stage, ToolGuard

RETRIEVAL = Guard(retrieval_scanners=[SecretScanner(), PIIScanner()], max_chars=2_000)
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
    argument_scanners=[SecretScanner(), PIIScanner()],
    max_chars=2_000,
)


def run_workflow(
    retrieved_text: str,
    propose: Callable[[str], tuple[str, str]],
    execute: Callable[[str, dict[str, Any]], str],
) -> str:
    """Check each boundary; rejection raises before the next callback is invoked.

    The model adapter returns a proposed name and the original JSON argument text.
    The host owns callback failures, authorization, execution limits, and any output checks.
    """
    retrieval = RETRIEVAL.scan(retrieved_text, stage=Stage.RETRIEVAL)
    prompt = "Use this public reference: " + retrieval.require_text()
    proposed_name, arguments_json = propose(prompt)
    call = TOOLS.validate(proposed_name, arguments_json)
    name, arguments = call.require_call()
    # Consume only this checked pair. Reusing the proposal would discard redactions.
    return execute(name, arguments)


def demo_model(prompt: str) -> tuple[str, str]:
    """Deterministic local proposal in the shape a model adapter could return."""
    return "lookup", json.dumps({"document_id": "public-guide", "query": prompt})


def demo_execute(name: str, arguments: dict[str, Any]) -> str:
    """Host permission check: this demo may read only one fixed public reference."""
    if name != "lookup" or arguments["document_id"] != "public-guide":
        raise PermissionError("Tool request is not authorized")
    # No arbitrary dispatch, file access, network, or persistent side effects.
    # Real hosts must also enforce identity, deadlines, and execution/concurrency budgets.
    return f"Public guide found. Query: {arguments['query']}"


def main() -> None:
    calls = {"model": 0, "tool": 0}

    def propose(prompt: str) -> tuple[str, str]:
        calls["model"] += 1
        return demo_model(prompt)

    def execute(name: str, arguments: dict[str, Any]) -> str:
        calls["tool"] += 1
        return demo_execute(name, arguments)

    print(run_workflow("Public guide: contact demo@example.org", propose, execute))
    assert calls == {"model": 1, "tool": 1}

    # Artificial signature only, not a credential. Rejection skips both callbacks.
    try:
        run_workflow("ghp_" + "A" * 36, propose, execute)
    except Rejected:
        assert calls == {"model": 1, "tool": 1}
        print("Rejected retrieval; model and tool callbacks skipped.")
    else:
        raise AssertionError("Expected retrieval rejection")

    def disallowed_proposal(prompt: str) -> tuple[str, str]:
        calls["model"] += 1
        return "delete", "{}"

    try:
        run_workflow("Public reference", disallowed_proposal, execute)
    except Rejected:
        assert calls == {"model": 2, "tool": 1}
        print("Rejected tool proposal; tool callback skipped.")
    else:
        raise AssertionError("Expected tool rejection")


if __name__ == "__main__":
    main()
