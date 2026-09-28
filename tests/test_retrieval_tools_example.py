"""Checked values must cross boundaries, and rejection must stop the next callback."""

import json

import pytest

from examples import retrieval_tools as demo
from guardtrellis import Rejected


def test_checked_retrieval_and_transformed_arguments_reach_only_the_next_callback():
    prompts = []
    calls = []
    proposal = json.dumps({"document_id": "public-guide", "query": "Contact other@example.net"})

    def propose(prompt):
        prompts.append(prompt)
        return "lookup", proposal

    def execute(name, arguments):
        calls.append((name, arguments))
        return demo.demo_execute(name, arguments)

    result = demo.run_workflow("Public guide: demo@example.org", propose, execute)
    assert prompts == ["Use this public reference: Public guide: [PII]"]
    assert calls == [("lookup", {"document_id": "public-guide", "query": "Contact [PII]"})]
    assert result == "Public guide found. Query: Contact [PII]"
    # The original proposal remains unchanged; it must never be used for execution.
    assert "other@example.net" in proposal


@pytest.mark.parametrize("retrieved", ["ghp_" + "A" * 36, "x" * 2_001])
def test_rejected_retrieval_skips_both_callbacks(retrieved):
    calls = []

    def propose(prompt):
        calls.append("model")
        return demo.demo_model(prompt)

    def execute(name, arguments):
        calls.append("tool")
        return "Unexpected execution"

    with pytest.raises(Rejected):
        demo.run_workflow(retrieved, propose, execute)
    assert calls == []


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("delete", "{}"),
        ("lookup", "not JSON"),
        ("lookup", '{"document_id":"public-guide","query":"first","query":"second"}'),
        ("lookup", '{"document_id":"public-guide","query":42}'),
        ("lookup", '{"document_id":"public-guide","query":"ok","extra":true}'),
        ("lookup", json.dumps({"document_id": "public-guide", "query": "ghp_" + "A" * 36})),
        ("lookup", " " * 2_001),
    ],
)
def test_rejected_tool_proposals_never_reach_execution(name, arguments):
    calls = []

    def propose(prompt):
        calls.append("model")
        return name, arguments

    def execute(name, arguments):
        calls.append("tool")
        return "Unexpected execution"

    with pytest.raises(Rejected):
        demo.run_workflow("Public reference", propose, execute)
    assert calls == ["model"]


def test_host_authorization_can_deny_a_structurally_valid_call():
    arguments = json.dumps({"document_id": "private-guide", "query": "Public reference"})
    assert demo.TOOLS.validate("lookup", arguments).accepted
    with pytest.raises(PermissionError, match="not authorized"):
        demo.run_workflow(
            "Public reference", lambda prompt: ("lookup", arguments), demo.demo_execute
        )


def test_model_failure_stops_tool_execution():
    calls = []

    def propose(prompt):
        raise RuntimeError("Fabricated model failure")

    def execute(name, arguments):
        calls.append("tool")
        return "Unexpected execution"

    with pytest.raises(RuntimeError, match="Fabricated model failure"):
        demo.run_workflow("Public reference", propose, execute)
    assert calls == []
