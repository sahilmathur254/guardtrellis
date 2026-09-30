"""Policies stop delivery at the failing boundary and operations logs exclude payloads."""

import json
import logging
import re
import traceback

import pytest

from examples import policy_operations as demo
from guardtrellis import Action, Guard, Rejected


def callbacks(events, *, retrieval="Public guide", tool_name="lookup", arguments=None, output=None):
    if arguments is None:
        arguments = json.dumps({"document_id": "public-guide", "query": "Public query"})

    def retrieve(query):
        events.append(("retrieval", query))
        return retrieval

    def propose(prompt):
        events.append(("proposal", prompt))
        return tool_name, arguments

    def execute(name, values):
        events.append(("execution", name, values))
        return demo.demo_execute(name, values) if output is None else output

    def deliver(text):
        events.append(("delivery", text))

    return retrieve, propose, execute, deliver


def records(caplog):
    return [
        json.loads(record.message) for record in caplog.records if record.name == demo.LOGGER.name
    ]


def test_only_checked_values_cross_each_boundary(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events = []
    arguments = json.dumps({"document_id": "public-guide", "query": "tool@example.org"})
    result = demo.run_workflow(
        "Contact input@example.org",
        *callbacks(events, retrieval="See retrieval@example.org", arguments=arguments),
    )
    assert events == [
        ("retrieval", "Contact [PII]"),
        ("proposal", "Contact [PII]\nReference: See [PII]"),
        ("execution", "lookup", {"document_id": "public-guide", "query": "[PII]"}),
        ("delivery", "Public guide found. Query: [PII]"),
    ]
    assert result == events[-1][1]
    assert "tool@example.org" in arguments  # Original proposals are not transformed in place.
    logged = records(caplog)
    assert [item["diagnostics"]["stage"] for item in logged] == [
        "input",
        "retrieval",
        "tool",
        "output",
    ]
    assert [item["diagnostics"]["action"] for item in logged] == [
        "redact",
        "redact",
        "redact",
        "allow",
    ]
    ids = {item["request_id"] for item in logged}
    assert len(ids) == 1 and re.fullmatch(r"[a-f0-9]{32}", ids.pop())
    assert "@example.org" not in caplog.text
    assert "Public guide found" not in caplog.text
    assert '"arguments"' not in caplog.text and '"text"' not in caplog.text


def test_warn_is_advisory_and_preserves_input(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events = []
    demo.run_workflow("Public\u200b query", *callbacks(events))
    assert events[0] == ("retrieval", "Public\u200b query")
    assert events[-1][0] == "delivery"
    assert records(caplog)[0]["diagnostics"]["action"] == "warn"
    assert "Public" not in caplog.text and "\u200b" not in caplog.text


@pytest.mark.parametrize(
    "user_text,options,expected_callbacks,stage,action",
    [
        ("ghp_" + "A" * 36, {}, [], "input", "block"),
        ("x" * 2_001, {}, [], "input", "error"),
        # The blocking marker overlaps an email that the following redactor could erase.
        (
            "Public query",
            {"retrieval": "internal-only@example.org"},
            ["retrieval"],
            "retrieval",
            "block",
        ),
        ("Public query", {"retrieval": "x" * 2_001}, ["retrieval"], "retrieval", "error"),
        ("Public query", {"tool_name": "delete"}, ["retrieval", "proposal"], "tool", "block"),
        ("Public query", {"arguments": "x" * 2_001}, ["retrieval", "proposal"], "tool", "error"),
        (
            "Public query",
            {"output": "leaked@example.org"},
            ["retrieval", "proposal", "execution"],
            "output",
            "block",
        ),
        (
            "Public query",
            {"output": "x" * 2_001},
            ["retrieval", "proposal", "execution"],
            "output",
            "error",
        ),
    ],
)
def test_rejected_boundary_stops_the_next_callback(
    caplog, user_text, options, expected_callbacks, stage, action
):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events = []
    with pytest.raises(Rejected, match=action):
        demo.run_workflow(user_text, *callbacks(events, **options))
    assert [event[0] for event in events] == expected_callbacks
    final = records(caplog)[-1]["diagnostics"]
    assert final["stage"] == stage and final["action"] == action
    assert "@example.org" not in caplog.text and "ghp_" not in caplog.text


def test_output_scanner_failure_has_no_deliverable_or_raw_error(monkeypatch, caplog):
    class BrokenScanner:
        name = "broken"

        def scan(self, text, *, stage):
            raise RuntimeError("Fabricated sensitive exception: private@example.org")

    monkeypatch.setattr(demo, "POLICIES", Guard(output_scanners=[BrokenScanner()]))
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events = []
    with pytest.raises(Rejected, match=Action.ERROR.value):
        demo.run_workflow("Public query", *callbacks(events))
    assert [event[0] for event in events] == ["retrieval", "proposal", "execution"]
    final = records(caplog)[-1]["diagnostics"]
    assert final["action"] == "error" and final["stage"] == "output"
    assert final["findings"][0]["code"] == "scanner_error"
    assert "private@example.org" not in caplog.text


@pytest.mark.parametrize("failing_index", range(4))
def test_callback_failures_log_static_metadata_only(failing_index, caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events = []
    work = list(callbacks(events))

    def fail(*args):
        raise RuntimeError("Fabricated sensitive exception: callback@example.org")

    work[failing_index] = fail
    with pytest.raises(demo.WorkflowError, match="^Workflow callback failed$") as caught:
        demo.run_workflow("Public query", *work)
    assert len(events) == failing_index
    final = records(caplog)[-1]
    assert final["event"] == "callback_failed" and final["action"] == "error"
    assert final["boundary"] == ["retrieval", "proposal", "execution", "delivery"][failing_index]
    assert "callback@example.org" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    # Standard traceback formatting suppresses original context; avoid traceback locals in hosts.
    assert "callback@example.org" not in "".join(traceback.format_exception(caught.value))


def test_host_denies_schema_valid_but_unauthorized_document(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events = []
    arguments = json.dumps({"document_id": "private-guide", "query": "Public query"})
    assert demo.TOOLS.validate("lookup", arguments).accepted
    with pytest.raises(demo.WorkflowError):
        demo.run_workflow("Public query", *callbacks(events, arguments=arguments))
    assert [event[0] for event in events] == ["retrieval", "proposal", "execution"]
    assert records(caplog)[-1]["boundary"] == "execution"
    assert "private-guide" not in caplog.text
