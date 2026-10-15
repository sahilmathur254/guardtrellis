"""Only checked tool-return text reaches the next model or application state."""

import json
import logging
import re
import traceback

import pytest

from examples import tool_result_handoff as demo
from guardtrellis import Action, Check, Finding, Guard, PIIScanner, Rejected, SecretScanner, Stage

ARGUMENTS = '{"document_id":"public-guide"}'
EMAIL = "casey@example.org"
SECRET = "ghp_" + "A" * 36


def callbacks(events, state, *, returned="Public guide"):
    def authorize(name, arguments):
        events.append(("authorize", name, arguments.copy()))
        return True

    def execute(name, arguments):
        events.append(("execute", name, arguments.copy()))
        return returned

    def consume(text):
        events.append(("consume", text))
        state.append(text)

    return authorize, execute, consume


def records(caplog):
    return [
        json.loads(record.message) for record in caplog.records if record.name == demo.LOGGER.name
    ]


def test_allow_handoff_uses_the_checked_call_and_return_text(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events, state = [], []
    result = demo.run_workflow("lookup", ARGUMENTS, *callbacks(events, state))

    assert result == "Public guide"
    assert events == [
        ("authorize", "lookup", {"document_id": "public-guide"}),
        ("execute", "lookup", {"document_id": "public-guide"}),
        ("consume", "Public guide"),
    ]
    assert state == [result]
    logged = records(caplog)
    assert [entry["diagnostics"]["stage"] for entry in logged] == ["tool", "retrieval"]
    assert [entry["diagnostics"]["action"] for entry in logged] == ["allow", "allow"]
    ids = {entry["request_id"] for entry in logged}
    assert len(ids) == 1 and re.fullmatch(r"[a-f0-9]{32}", ids.pop())


def test_every_supported_default_pii_format_is_redacted_before_state_insertion(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    original = f"Contact {EMAIL}, +14155552671, or 123-45-6789."
    checked = "Contact [PII], [PII], or [PII]."
    events, state = [], ["Earlier checked result"]

    result = demo.run_workflow("lookup", ARGUMENTS, *callbacks(events, state, returned=original))

    # Comparing the entire consumer history catches accidental original-result reuse.
    assert [event for event in events if event[0] == "consume"] == [("consume", checked)]
    assert state == ["Earlier checked result", checked]
    assert result == checked and original != checked
    diagnostic = records(caplog)[-1]["diagnostics"]
    assert diagnostic["action"] == "redact"
    assert {finding["code"] for finding in diagnostic["findings"]} == {
        "pii_email",
        "pii_phone",
        "pii_ssn",
    }
    assert all(value not in caplog.text for value in [EMAIL, "+14155552671", "123-45-6789"])


@pytest.mark.parametrize(
    "returned,action,code",
    [
        (SECRET + " " + EMAIL, "block", "secret_github_classic"),
        ("internal-only@example.org", "block", "literal_match"),
        ("x" * 2_001, "error", "text_limit_exceeded"),
        (None, "error", "invalid_text_type"),
        (b"Public guide", "error", "invalid_text_type"),
        ({"text": "Public guide"}, "error", "invalid_text_type"),
    ],
)
def test_rejected_tool_return_never_reaches_consumer_or_state(returned, action, code, caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events, state = [], ["Earlier checked result"]

    with pytest.raises(Rejected, match=action):
        demo.run_workflow("lookup", ARGUMENTS, *callbacks(events, state, returned=returned))

    # Execution has already happened; rejection stops the subsequent handoff.
    assert [event[0] for event in events] == ["authorize", "execute"]
    assert state == ["Earlier checked result"]
    diagnostic = records(caplog)[-1]["diagnostics"]
    assert diagnostic["stage"] == "retrieval" and diagnostic["action"] == action
    assert diagnostic["findings"][0]["code"] == code
    assert EMAIL not in caplog.text and SECRET not in caplog.text


def test_blocking_marker_cannot_be_erased_by_later_pii_redaction(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events, state = [], []
    with pytest.raises(Rejected, match="block"):
        demo.run_workflow(
            "lookup",
            ARGUMENTS,
            *callbacks(events, state, returned="internal-only@example.org"),
        )

    diagnostic = records(caplog)[-1]["diagnostics"]
    assert [item["scanner"] for item in diagnostic["trace"]] == ["secrets", "literal"]
    assert state == []


def test_alternate_redacting_secret_policy_hands_off_only_transformed_text():
    policy = Guard(
        retrieval_scanners=[SecretScanner(action=Action.REDACT), PIIScanner()],
        max_chars=demo.MAX_RETURN_CHARS,
    )
    events, state = [], []
    result = demo.run_workflow(
        "lookup",
        ARGUMENTS,
        *callbacks(events, state, returned=SECRET + " " + EMAIL),
        result_guard=policy,
    )

    assert result == "[SECRET] [PII]"
    assert events[-1] == ("consume", "[SECRET] [PII]")
    assert state == ["[SECRET] [PII]"]


def test_trusted_custom_policy_receives_retrieval_stage_and_warning_is_deliverable(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    scans = []

    class Observe:
        name = "observe"

        def scan(self, text, *, stage):
            scans.append((text, stage))
            return Check(Action.WARN, (Finding("notice"),))

    events, state = [], []
    result = demo.run_workflow(
        "lookup",
        ARGUMENTS,
        *callbacks(events, state),
        result_guard=Guard(retrieval_scanners=[Observe()]),
    )

    assert scans == [("Public guide", Stage.RETRIEVAL)]
    assert state == [result] == ["Public guide"]
    assert records(caplog)[-1]["diagnostics"]["action"] == "warn"


@pytest.mark.parametrize("size", [1_999, 2_000])
def test_return_text_at_the_configured_limit_is_deliverable(size):
    events, state = [], []
    result = demo.run_workflow("lookup", ARGUMENTS, *callbacks(events, state, returned="x" * size))
    assert state == [result] == ["x" * size]


@pytest.mark.parametrize(
    "name,arguments",
    [
        ("LOOKUP", ARGUMENTS),
        ("lookup ", ARGUMENTS),
        ("delete", ARGUMENTS),
        (None, ARGUMENTS),
        ("lookup", "not JSON"),
        ("lookup", "{} trailing"),
        ("lookup", "[]"),
        ("lookup", "{}"),
        ("lookup", '{"document_id":42}'),
        ("lookup", '{"document_id":""}'),
        ("lookup", '{"document_id":"public-guide","extra":true}'),
        ("lookup", '{"document_id":"one","document_id":"two"}'),
        ("lookup", '{"document_id":"' + "x" * 65 + '"}'),
        ("lookup", '{"document_id":[[]]}'),
        ("lookup", None),
        ("lookup", b'{"document_id":"public-guide"}'),
    ],
)
def test_invalid_proposals_stop_before_authorization_execution_or_result_scanning(name, arguments):
    scans = []

    class Observe:
        name = "observe"

        def scan(self, text, *, stage):
            scans.append((text, stage))
            return Check()

    events, state = [], []
    with pytest.raises(Rejected):
        demo.run_workflow(
            name,
            arguments,
            *callbacks(events, state),
            result_guard=Guard(retrieval_scanners=[Observe()]),
        )
    assert events == scans == state == []


@pytest.mark.parametrize("size,accepted", [(2_000, True), (2_001, False)])
def test_serialized_proposal_limit_is_checked_before_host_callbacks(size, accepted):
    arguments = ARGUMENTS + " " * (size - len(ARGUMENTS))
    events, state = [], []
    if accepted:
        demo.run_workflow("lookup", arguments, *callbacks(events, state))
        assert state == ["Public guide"]
    else:
        with pytest.raises(Rejected, match="error"):
            demo.run_workflow("lookup", arguments, *callbacks(events, state))
        assert events == state == []


def test_schema_valid_unauthorized_document_stops_before_execution(caplog):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events, state = [], []
    arguments = '{"document_id":"private-guide"}'
    assert demo.TOOLS.validate("lookup", arguments).accepted
    _, execute, consume = callbacks(events, state)

    with pytest.raises(PermissionError, match="^Tool request is not authorized$"):
        demo.run_workflow("lookup", arguments, demo.demo_authorize, execute, consume)
    assert events == state == []
    assert "private-guide" not in caplog.text


@pytest.mark.parametrize("decision", [False, None, 1, "yes"])
def test_authorization_requires_an_explicit_boolean_true(decision):
    events, state = [], []
    _, execute, consume = callbacks(events, state)
    with pytest.raises(PermissionError, match="^Tool request is not authorized$"):
        demo.run_workflow("lookup", ARGUMENTS, lambda *_: decision, execute, consume)
    assert events == state == []


def test_authorizer_mutation_cannot_change_the_executed_checked_call():
    events, state = [], []
    _, execute, consume = callbacks(events, state)

    def authorize(name, arguments):
        assert name == "lookup" and arguments == {"document_id": "public-guide"}
        arguments["document_id"] = "private-guide"
        arguments["extra"] = "injected"
        return True

    demo.run_workflow("lookup", ARGUMENTS, authorize, execute, consume)
    assert events == [
        ("execute", "lookup", {"document_id": "public-guide"}),
        ("consume", "Public guide"),
    ]
    assert state == ["Public guide"]


def test_scanner_failure_rejects_without_payload_diagnostics_or_state(caplog, capsys, monkeypatch):
    class Broken:
        name = "broken"

        def scan(self, text, *, stage):
            raise RuntimeError(text)

    captured = []
    record_check = demo.record_check

    def capture(request_id, result):
        captured.append(result)
        record_check(request_id, result)

    monkeypatch.setattr(demo, "record_check", capture)
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events, state = [], []
    with pytest.raises(Rejected, match="error") as caught:
        demo.run_workflow(
            "lookup",
            ARGUMENTS,
            *callbacks(events, state, returned=EMAIL),
            result_guard=Guard(retrieval_scanners=[Broken()]),
        )

    displayed = str(caught.value) + repr(caught.value)
    displayed += "".join(traceback.format_exception(caught.value))
    displayed += "".join(repr(result) + json.dumps(result.diagnostics()) for result in captured)
    assert EMAIL not in displayed + caplog.text
    assert [event[0] for event in events] == ["authorize", "execute"]
    assert state == []
    assert records(caplog)[-1]["diagnostics"]["findings"][0]["code"] == "scanner_error"
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("failing_boundary", ["authorization", "execution", "consumption"])
def test_callback_failures_sanitize_exceptions_and_logs(failing_boundary, caplog, capsys):
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events, state = [], []

    def fail_if_selected(boundary):
        events.append(boundary)
        if boundary == failing_boundary:
            raise RuntimeError("Fabricated private callback value: " + EMAIL)

    def authorize(name, arguments):
        fail_if_selected("authorization")
        return True

    def execute(name, arguments):
        fail_if_selected("execution")
        return "Contact " + EMAIL

    def consume(text):
        assert text == "Contact [PII]"
        fail_if_selected("consumption")
        state.append(text)

    with pytest.raises(demo.WorkflowError, match="^Workflow callback failed$") as caught:
        demo.run_workflow("lookup", ARGUMENTS, authorize, execute, consume)

    expected = ["authorization", "execution", "consumption"]
    assert events == expected[: expected.index(failing_boundary) + 1]
    assert state == []
    displayed = str(caught.value) + repr(caught.value)
    displayed += "".join(traceback.format_exception(caught.value))
    assert EMAIL not in displayed + caplog.text
    final = records(caplog)[-1]
    assert final["event"] == "callback_failed" and final["action"] == "error"
    assert final["boundary"] == failing_boundary
    assert all(record.exc_info is None for record in caplog.records)
    assert capsys.readouterr() == ("", "")


def test_accepted_diagnostics_and_reprs_exclude_raw_return_and_argument_values(caplog, monkeypatch):
    captured = []
    record_check = demo.record_check

    def capture(request_id, result):
        captured.append(result)
        record_check(request_id, result)

    monkeypatch.setattr(demo, "record_check", capture)
    caplog.set_level(logging.INFO, logger=demo.LOGGER.name)
    events, state = [], []
    demo.run_workflow(
        "lookup",
        '{"document_id":"canary-document"}',
        *callbacks(events, state, returned="Fabricated return " + EMAIL),
    )
    displayed = caplog.text + "".join(
        repr(result) + json.dumps(result.diagnostics()) for result in captured
    )
    assert all(value not in displayed for value in ["canary-document", "Fabricated return", EMAIL])
    assert '"arguments"' not in caplog.text and '"text"' not in caplog.text
    assert state == ["Fabricated return [PII]"]
