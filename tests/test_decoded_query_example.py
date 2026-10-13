"""Synthetic fixed-field checks and host handoff; no credentials or network."""

import json
import traceback
from dataclasses import dataclass

import pytest

from examples import decoded_query as demo
from guardtrellis import (
    Action,
    Check,
    Edit,
    Finding,
    Guard,
    PIIScanner,
    Rejected,
    SecretScanner,
    Stage,
)

EMAIL = "casey@example.org"
SECRET = "ghp_" + "A" * 36


@pytest.fixture
def callbacks():
    events = []

    def authorize(name, arguments):
        events.append(("authorize", name, arguments.copy()))
        return True

    def execute(name, arguments):
        events.append(("execute", name, arguments.copy()))
        return "Offline result"

    return events, authorize, execute


@dataclass
class Returns:
    value: object
    name: str = "custom"

    def scan(self, text, *, stage):
        return self.value


@dataclass
class Replaces:
    replacement: str
    name: str = "replacement"

    def scan(self, text, *, stage):
        return Check(
            Action.REDACT,
            (Finding("replacement", 0, len(text)),),
            (Edit(0, len(text), self.replacement),),
        )


def test_plain_and_escaped_email_reach_both_callbacks_as_checked_values(callbacks):
    events, authorize, execute = callbacks
    proposals = [
        '{"query":"Contact casey@example.org"}',
        '{"query":"Contact casey\\u0040example.org"}',
    ]
    for arguments_json in proposals:
        assert demo.run_workflow("search", arguments_json, authorize, execute) == "Offline result"

    assert events == [
        (event, "search", {"query": "Contact [PII]"})
        for _ in proposals
        for event in ("authorize", "execute")
    ]
    # Checking does not rewrite the caller's original wire text.
    assert EMAIL in proposals[0]
    assert "\\u0040" in proposals[1]


@pytest.mark.parametrize("escape", [False, True])
def test_equivalent_secrets_block_before_authorization_or_dispatch(escape, callbacks):
    events, authorize, execute = callbacks
    proposal = json.dumps({"query": EMAIL + " " + SECRET})
    if escape:
        proposal = proposal.replace("ghp_", "ghp\\u005f")
    with pytest.raises(Rejected):
        demo.run_workflow("search", proposal, authorize, execute)
    assert events == []


def test_alternate_redacting_secret_policy_has_equivalent_checked_calls():
    policy = Guard(
        tool_scanners=[SecretScanner(action=Action.REDACT), PIIScanner(formats=["email"])],
        max_chars=demo.MAX_QUERY_CHARS,
    )
    plain = json.dumps({"query": EMAIL + " " + SECRET})
    escaped = plain.replace("@", "\\u0040").replace("ghp_", "ghp\\u005f")
    for proposal in (plain, escaped):
        result = demo.check_query("search", proposal, query_guard=policy)
        assert result.require_call() == ("search", {"query": "[PII] [SECRET]"})
        # This is the final wire ToolGuard result, with no decoded-field offsets merged in.
        assert result.action == Action.ALLOW
        assert result.diagnostics()["findings"] == []


@pytest.mark.parametrize(
    "name,proposal",
    [
        ("SEARCH", '{"query":"safe"}'),
        (" search", '{"query":"safe"}'),
        ("search ", '{"query":"safe"}'),
        ("delete", '{"query":"safe"}'),
        (None, '{"query":"safe"}'),
        ("search", None),
        ("search", b'{"query":"safe"}'),
        ("search", 123),
        ("search", "not JSON"),
        ("search", "{} trailing"),
        ("search", "[]"),
        ("search", "null"),
        ("search", "{}"),
        ("search", '{"query":42}'),
        ("search", '{"query":true}'),
        ("search", '{"query":"safe","extra":true}'),
        ("search", '{"query":"first","query":"second"}'),
        ("search", '{"query":"first","\\u0071uery":"second"}'),
        ("search", '{"query":NaN}'),
        ("search", '{"query":Infinity}'),
        ("search", '{"query":-Infinity}'),
        ("search", '{"query":1e9999}'),
    ],
)
def test_preflight_rejects_before_decoded_scanning_and_callbacks(name, proposal, callbacks):
    scans = []

    class Spy:
        name = "spy"

        def scan(self, text, *, stage):
            scans.append((text, stage))
            return Check()

    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow(
            name, proposal, authorize, execute, query_guard=Guard(tool_scanners=[Spy()])
        )
    assert scans == events == []


@pytest.mark.parametrize(
    "size,accepted", [(0, False), (1, True), (2, True), (199, True), (200, True), (201, False)]
)
def test_decoded_query_length_bound(size, accepted, callbacks):
    events, authorize, execute = callbacks
    proposal = json.dumps({"query": "x" * size})
    if accepted:
        demo.run_workflow("search", proposal, authorize, execute)
        assert events[-1] == ("execute", "search", {"query": "x" * size})
    else:
        with pytest.raises(Rejected):
            demo.run_workflow("search", proposal, authorize, execute)
        assert events == []


@pytest.mark.parametrize("size,accepted", [(4095, True), (4096, True), (4097, False)])
def test_serialized_input_length_bound(size, accepted, callbacks):
    events, authorize, execute = callbacks
    proposal = '{"query":"safe"}'
    proposal += " " * (size - len(proposal))
    assert len(proposal) == size
    if accepted:
        demo.run_workflow("search", proposal, authorize, execute)
        assert events[-1] == ("execute", "search", {"query": "safe"})
    else:
        with pytest.raises(Rejected):
            demo.run_workflow("search", proposal, authorize, execute)
        assert events == []


@pytest.mark.parametrize(
    "proposal,code",
    [
        ('{"query":"safe"}', None),  # One container, below the depth ceiling.
        ('{"query":[]}', "json_schema_mismatch"),  # Two containers, at the ceiling.
        ('{"query":[[]]}', "json_too_deep"),  # Three containers, above the ceiling.
    ],
)
def test_parser_depth_bound_precedes_schema_for_excessive_nesting(proposal, code, callbacks):
    assert demo.MAX_DEPTH == 2
    preflight = demo.TOOLS.validate("search", proposal)
    events, authorize, execute = callbacks
    if code is None:
        demo.run_workflow("search", proposal, authorize, execute)
        assert events[-1][0] == "execute"
    else:
        assert preflight.validation.findings[0].code == code
        with pytest.raises(Rejected):
            demo.run_workflow("search", proposal, authorize, execute)
        assert events == []


@pytest.mark.parametrize(
    "proposal",
    [
        '{"query":"\\ud800"}',
        '{"query":"\\udfff"}',
        json.dumps({"query": "\ud800"}, ensure_ascii=False),
    ],
)
def test_unpaired_decoded_surrogates_stop_before_scanners_and_callbacks(proposal, callbacks):
    scans = []

    class Spy:
        name = "spy"

        def scan(self, text, *, stage):
            scans.append(text)
            return Check()

    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow(
            "search", proposal, authorize, execute, query_guard=Guard(tool_scanners=[Spy()])
        )
    assert scans == events == []


def test_valid_surrogate_pair_and_literal_escape_decode_only_once():
    assert demo.check_query("search", '{"query":"\\ud83d\\ude00"}').require_call() == (
        "search",
        {"query": "😀"},
    )
    literal = r"casey\u0040example.org"
    assert demo.check_query("search", json.dumps({"query": literal})).require_call() == (
        "search",
        {"query": literal},
    )


def test_default_policy_is_email_only_for_pii():
    query = "Contact +14155552671"
    assert demo.check_query("search", json.dumps({"query": query})).require_call() == (
        "search",
        {"query": query},
    )


def test_decoded_policy_stage_order_and_warning_handoff():
    scans = []

    class Observe:
        name = "observe"

        def scan(self, text, *, stage):
            scans.append((text, stage))
            return Check(Action.WARN, (Finding("notice"),))

    policy = Guard(tool_scanners=[PIIScanner(formats=["email"]), Observe()])
    result = demo.check_query("search", json.dumps({"query": EMAIL}), query_guard=policy)
    assert scans == [("[PII]", Stage.TOOL)]
    assert result.require_call() == ("search", {"query": "[PII]"})
    assert result.diagnostics()["findings"] == []


@pytest.mark.parametrize(
    "decision",
    [
        None,
        Check("allow"),
        Check(Action.ALLOW, (Finding("unexpected"),)),
        Check(Action.BLOCK),
        Check(Action.REDACT, (Finding("missing_edits"),)),
        Check(Action.WARN, (Finding("bad_span", -1, 2),)),
        Check(Action.WARN, (Finding("private canary"),)),
        Check(Action.REDACT, (Finding("bad_replacement"),), (Edit(0, 1, None),)),
        Check(Action.REDACT, (Finding("overlap"),), (Edit(0, 3), Edit(2, 4))),
    ],
)
def test_malformed_scanner_checks_never_reach_authorization_or_dispatch(decision, callbacks):
    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow(
            "search",
            '{"query":"safe"}',
            authorize,
            execute,
            query_guard=Guard(tool_scanners=[Returns(decision)]),
        )
    assert events == []


@pytest.mark.parametrize("replacement", ["", "\ud800", "\udfff", "x" * 201])
def test_invalid_transformed_field_rejects_even_with_a_wider_policy(replacement, callbacks):
    events, authorize, execute = callbacks
    # The recipe's schema/Unicode bound remains in force with a caller-supplied policy.
    policy = Guard(tool_scanners=[Replaces(replacement)], max_chars=1000)
    with pytest.raises(Rejected):
        demo.run_workflow("search", '{"query":"safe"}', authorize, execute, query_guard=policy)
    assert events == []


@pytest.mark.parametrize("size", [1, 199, 200])
def test_valid_transformed_field_lengths(size):
    policy = Guard(tool_scanners=[Replaces("x" * size)], max_chars=1000)
    assert demo.check_query("search", '{"query":"safe"}', query_guard=policy).require_call() == (
        "search",
        {"query": "x" * size},
    )


@pytest.mark.parametrize("delta,accepted", [(-1, False), (0, True), (1, True)])
def test_serialized_output_cap_is_rechecked_after_a_replacement(monkeypatch, delta, accepted):
    # The default query cap makes a 4096-char output unreachable. Lower only this cap
    # to independently exercise its boundary with an otherwise permitted replacement.
    query = "\n" * 200
    serialized = json.dumps({"query": query}, ensure_ascii=False, separators=(",", ":"))
    monkeypatch.setattr(demo, "MAX_OUTPUT_CHARS", len(serialized) + delta)
    policy = Guard(tool_scanners=[Replaces(query)], max_chars=200)
    if accepted:
        assert demo.check_query(
            "search", '{"query":"safe"}', query_guard=policy
        ).require_call() == ("search", {"query": query})
    else:
        with pytest.raises(Rejected):
            demo.check_query("search", '{"query":"safe"}', query_guard=policy)


def test_accepted_result_and_rejection_outputs_are_payload_free(caplog, capsys, callbacks):
    result = demo.check_query("search", json.dumps({"query": EMAIL}))
    assert EMAIL not in repr(result) + json.dumps(result.diagnostics())

    class Failing:
        name = "failing"

        def scan(self, text, *, stage):
            raise RuntimeError(text)

    events, authorize, execute = callbacks
    with pytest.raises(Rejected) as error:
        demo.run_workflow(
            "search",
            json.dumps({"query": EMAIL}),
            authorize,
            execute,
            query_guard=Guard(tool_scanners=[Failing()]),
        )
    displayed = (
        str(error.value) + repr(error.value) + "".join(traceback.format_exception(error.value))
    )
    assert EMAIL not in displayed
    assert events == []
    assert caplog.text == ""
    assert capsys.readouterr() == ("", "")


def test_host_authorization_denial_stops_dispatch(callbacks):
    events, _, execute = callbacks

    def deny(name, arguments):
        events.append(("authorize", name, arguments.copy()))
        return False

    with pytest.raises(PermissionError, match="not authorized"):
        demo.run_workflow("search", json.dumps({"query": EMAIL}), deny, execute)
    assert events == [("authorize", "search", {"query": "[PII]"})]


def test_authorizer_mutation_cannot_change_the_executed_checked_pair(callbacks):
    events, _, execute = callbacks

    def authorize(name, arguments):
        assert name == "search"
        assert arguments == {"query": "[PII]"}
        arguments["query"] = EMAIL
        arguments["extra"] = "injected"
        return True

    demo.run_workflow("search", json.dumps({"query": EMAIL}), authorize, execute)
    assert events == [("execute", "search", {"query": "[PII]"})]


@pytest.mark.parametrize("decision", [None, False, 1, "yes"])
def test_authorization_requires_an_explicit_boolean_true(decision, callbacks):
    events, _, execute = callbacks
    with pytest.raises(PermissionError, match="^Tool request is not authorized$"):
        demo.run_workflow("search", '{"query":"safe"}', lambda *_: decision, execute)
    assert events == []


@pytest.mark.parametrize("failure_stage", ["authorize", "execute"])
def test_callback_errors_are_sanitized_and_stop_later_work(failure_stage, caplog, capsys):
    events = []

    def authorize(name, arguments):
        events.append("authorize")
        if failure_stage == "authorize":
            raise RuntimeError(EMAIL)
        return True

    def execute(name, arguments):
        events.append("execute")
        raise RuntimeError(EMAIL)

    with pytest.raises(demo.WorkflowError, match="^Workflow callback failed$") as error:
        demo.run_workflow("search", '{"query":"safe"}', authorize, execute)
    displayed = (
        str(error.value) + repr(error.value) + "".join(traceback.format_exception(error.value))
    )
    assert EMAIL not in displayed
    assert events == (["authorize"] if failure_stage == "authorize" else ["authorize", "execute"])
    assert caplog.text == ""
    assert capsys.readouterr() == ("", "")
