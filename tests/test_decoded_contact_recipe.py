"""Synthetic fixed-policy contact checks and host handoff; no credentials or network."""

import inspect
import json
import traceback
from dataclasses import dataclass

import pytest

from examples import decoded_contact as demo
from guardtrellis import Action, Check, Edit, Finding, Guard, Rejected, Stage, ToolGuard

EMAIL = "casey@example.org"
PHONE = "+14155552671"
SECRET = "ghp_" + "A" * 36


def proposal(email="safe", phone="safe"):
    return json.dumps({"email": email, "phone": phone})


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


def install_policy(monkeypatch, scanner, *, pass_name="PII_POLICY"):
    monkeypatch.setattr(demo, pass_name, Guard(tool_scanners=[scanner], max_chars=1000))


def test_plain_and_escaped_contact_deliver_the_same_checked_values(callbacks):
    events, authorize, execute = callbacks
    plain = proposal(EMAIL, PHONE)
    escaped = plain.replace("@", r"\u0040").replace("+", r"\u002b")
    for wire in (plain, escaped):
        result = demo.check_contact("contact", wire)
        assert result.action == Action.REDACT
        assert result.final.action == Action.ALLOW
        assert result.require_call() == ("contact", {"email": "[PII]", "phone": "[PII]"})
        assert demo.run_workflow("contact", wire, authorize, execute) == "Offline result"
    assert events == [
        (event, "contact", {"email": "[PII]", "phone": "[PII]"})
        for _ in range(2)
        for event in ("authorize", "execute")
    ]


@pytest.mark.parametrize("field", ["email", "phone"])
@pytest.mark.parametrize("escaped", [False, True])
def test_secret_in_either_field_blocks_before_any_pii_or_host_callback(
    field, escaped, monkeypatch, callbacks
):
    scans = []

    class PiiSpy:
        name = "pii_spy"

        def scan(self, text, *, stage):
            scans.append((text, stage))
            return Check()

    install_policy(monkeypatch, PiiSpy())
    values = {"email": EMAIL, "phone": PHONE, field: SECRET}
    wire = json.dumps(values)
    if escaped:
        wire = wire.replace("ghp_", r"ghp\u005f")
    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow("contact", wire, authorize, execute)
    assert scans == events == []


@pytest.mark.parametrize(
    "name,wire",
    [
        ("CONTACT", proposal()),
        (" contact", proposal()),
        ("contact ", proposal()),
        ("delete", proposal()),
        (None, proposal()),
        ("contact", None),
        ("contact", b"{}"),
        ("contact", 1),
        ("contact", "not JSON"),
        ("contact", proposal() + " trailing"),
        ("contact", "[]"),
        ("contact", "null"),
        ("contact", "{}"),
        ("contact", '{"email":"safe"}'),
        ("contact", '{"phone":"safe"}'),
        ("contact", '{"email":42,"phone":"safe"}'),
        ("contact", '{"email":"safe","phone":true}'),
        ("contact", '{"email":"safe","phone":"safe","extra":true}'),
        ("contact", '{"email":"first","email":"second","phone":"safe"}'),
        ("contact", '{"email":"first","\\u0065mail":"second","phone":"safe"}'),
        ("contact", '{"email":"safe","phone":"first","\\u0070hone":"second"}'),
        ("contact", '{"email":NaN,"phone":"safe"}'),
        ("contact", '{"email":"safe","phone":Infinity}'),
        ("contact", '{"email":"safe","phone":-Infinity}'),
        ("contact", '{"email":"safe","phone":1e9999}'),
    ],
)
def test_strict_preflight_failure_never_scans_decoded_fields(name, wire, monkeypatch, callbacks):
    scans = []

    class Spy:
        name = "spy"

        def scan(self, text, *, stage):
            scans.append(text)
            return Check()

    install_policy(monkeypatch, Spy(), pass_name="SECRET_POLICY")
    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow(name, wire, authorize, execute)
    assert scans == events == []


@pytest.mark.parametrize("field,limit", [("email", 254), ("phone", 64)])
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_decoded_field_limits(field, limit, delta, callbacks):
    events, authorize, execute = callbacks
    values = {"email": "safe", "phone": "safe", field: "x" * (limit + delta)}
    if delta <= 0:
        demo.run_workflow("contact", json.dumps(values), authorize, execute)
        assert events[-1] == ("execute", "contact", values)
    else:
        with pytest.raises(Rejected):
            demo.run_workflow("contact", json.dumps(values), authorize, execute)
        assert events == []


@pytest.mark.parametrize("field", ["email", "phone"])
def test_empty_fields_reject(field, callbacks):
    values = {"email": "safe", "phone": "safe", field: ""}
    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow("contact", json.dumps(values), authorize, execute)
    assert events == []


@pytest.mark.parametrize("size,accepted", [(4095, True), (4096, True), (4097, False)])
def test_wire_input_boundary(size, accepted):
    wire = proposal()
    wire += " " * (size - len(wire))
    assert len(wire) == size
    if accepted:
        assert demo.check_contact("contact", wire).action == Action.ALLOW
    else:
        with pytest.raises(Rejected):
            demo.check_contact("contact", wire)


@pytest.mark.parametrize(
    "wire,code",
    [
        (proposal(), None),
        ('{"email":[],"phone":"safe"}', "json_schema_mismatch"),
        ('{"email":[[]],"phone":"safe"}', "json_too_deep"),
    ],
)
def test_json_depth_bound(wire, code):
    assert demo.MAX_DEPTH == 2
    preflight = demo.TOOLS.validate("contact", wire)
    if code:
        assert preflight.validation.findings[0].code == code
        with pytest.raises(Rejected):
            demo.check_contact("contact", wire)
    else:
        assert demo.check_contact("contact", wire).action == Action.ALLOW


@pytest.mark.parametrize("field", ["email", "phone"])
@pytest.mark.parametrize("value", ["\ud800", "\udfff", "\ud800\ud800"])
def test_surrogates_reject_before_any_decoded_scanning(field, value, monkeypatch, callbacks):
    scans = []

    class Spy:
        name = "spy"

        def scan(self, text, *, stage):
            scans.append(text)
            return Check()

    install_policy(monkeypatch, Spy(), pass_name="SECRET_POLICY")
    values = {"email": "safe", "phone": "safe", field: value}
    events, authorize, execute = callbacks
    with pytest.raises(Rejected, match="unicode_invalid"):
        demo.run_workflow("contact", json.dumps(values), authorize, execute)
    assert scans == events == []


def test_valid_surrogate_pair_and_literal_backslashes_decode_once():
    wire = r'{"email":"\ud83d\ude00","phone":"casey\\u0040example.org"}'
    assert demo.check_contact("contact", wire).require_call() == (
        "contact",
        {"email": "😀", "phone": r"casey\u0040example.org"},
    )


def test_escaped_schema_keys_are_validated_but_never_scanned(monkeypatch):
    scans = []

    class Spy:
        name = "spy"

        def scan(self, text, *, stage):
            scans.append((text, stage))
            return Check()

    install_policy(monkeypatch, Spy(), pass_name="SECRET_POLICY")
    install_policy(monkeypatch, Spy())
    wire = r'{"\u0065mail":"first","\u0070hone":"second"}'
    assert demo.check_contact("contact", wire).require_call() == (
        "contact",
        {"email": "first", "phone": "second"},
    )
    assert scans == [(text, Stage.TOOL) for text in ("first", "second", "first", "second")]


def test_both_pii_formats_are_checked_in_both_fields():
    result = demo.check_contact("contact", proposal(PHONE, EMAIL))
    assert result.require_call()[1] == {"email": "[PII]", "phone": "[PII]"}
    assert [item.code for item in result.findings] == ["pii_phone", "pii_email"]


def test_known_formatted_phone_miss_is_retained():
    formatted = "+1 (415) 555-2671"
    assert demo.check_contact("contact", proposal("safe", formatted)).require_call()[1] == {
        "email": "safe",
        "phone": formatted,
    }


def test_metadata_has_opaque_field_ids_and_separate_decoded_coordinates():
    result = demo.check_contact("contact", proposal("😀 " + EMAIL, PHONE))
    assert result.action == Action.REDACT
    assert result.final.action == Action.ALLOW
    assert [(item.field_id, item.pass_index, item.revision) for item in result.findings] == [
        ("field-0", 1, 0),
        ("field-1", 1, 0),
    ]
    assert [(item.start, item.end) for item in result.findings] == [
        (2, 2 + len(EMAIL)),
        (0, len(PHONE)),
    ]
    assert all(item.scanner == "pii" and item.scanner_index == 0 for item in result.findings)
    diagnostics = result.diagnostics()
    assert diagnostics["final_validation"]["findings"] == []
    assert diagnostics["action"] == "redact"
    assert diagnostics["scanner_invocations"] == 4
    assert diagnostics["scanned_chars"] == 2 * (2 + len(EMAIL) + len(PHONE))
    encoded = json.dumps(diagnostics) + repr(result)
    assert EMAIL not in encoded and PHONE not in encoded and "😀" not in encoded
    assert "field-0" in encoded and "field-1" in encoded


def test_pass_provenance_and_revision_track_prior_redaction(monkeypatch):
    install_policy(monkeypatch, Replaces("prefix " + EMAIL), pass_name="SECRET_POLICY")
    result = demo.check_contact("contact", proposal())
    assert [(item.pass_index, item.revision, item.scanner) for item in result.findings] == [
        (0, 0, "replacement"),
        (0, 0, "replacement"),
        (1, 1, "pii"),
        (1, 1, "pii"),
    ]
    assert result.require_call()[1] == {"email": "prefix [PII]", "phone": "prefix [PII]"}
    assert result.action == Action.REDACT


def test_warning_is_preserved_separately_from_final_allow(monkeypatch):
    install_policy(monkeypatch, Returns(Check(Action.WARN, (Finding("notice"),))))
    result = demo.check_contact("contact", proposal())
    assert result.action == Action.WARN
    assert result.final.action == Action.ALLOW
    assert result.require_call()[1] == {"email": "safe", "phone": "safe"}


@pytest.mark.parametrize("limit,accepted", [(3, False), (4, True)])
def test_scanner_invocation_budget(monkeypatch, limit, accepted, callbacks):
    monkeypatch.setattr(demo, "MAX_SCANNER_INVOCATIONS", limit)
    events, authorize, execute = callbacks
    if accepted:
        result = demo.check_contact("contact", proposal())
        assert result.scanner_invocations == 4
    else:
        with pytest.raises(Rejected, match="scanner_limit_exceeded"):
            demo.run_workflow("contact", proposal(), authorize, execute)
        assert events == []


@pytest.mark.parametrize("limit,accepted", [(15, False), (16, True)])
def test_cumulative_scanned_character_budget(monkeypatch, limit, accepted, callbacks):
    monkeypatch.setattr(demo, "MAX_SCANNED_CHARS", limit)
    events, authorize, execute = callbacks
    if accepted:
        assert demo.check_contact("contact", proposal()).scanned_chars == 16
    else:
        with pytest.raises(Rejected, match="scanned_limit_exceeded"):
            demo.run_workflow("contact", proposal(), authorize, execute)
        assert events == []


def test_original_decoded_aggregate_cap(monkeypatch, callbacks):
    monkeypatch.setattr(demo, "MAX_DECODED_CHARS", 7)
    events, authorize, execute = callbacks
    with pytest.raises(Rejected, match="decoded_limit_exceeded"):
        demo.run_workflow("contact", proposal(), authorize, execute)
    assert events == []


def test_full_allowed_field_lengths_fit_default_document_budgets():
    result = demo.check_contact("contact", proposal("x" * 254, "x" * 64))
    assert result.action == Action.ALLOW
    assert result.scanner_invocations == 4
    assert result.scanned_chars == 636 <= demo.MAX_SCANNED_CHARS
    assert result.findings == ()


def test_transformed_aggregate_cap(monkeypatch, callbacks):
    monkeypatch.setattr(demo, "MAX_DECODED_CHARS", 8)
    install_policy(monkeypatch, Replaces("longer"))
    events, authorize, execute = callbacks
    with pytest.raises(Rejected, match="decoded_limit_exceeded"):
        demo.run_workflow("contact", proposal(), authorize, execute)
    assert events == []


@pytest.mark.parametrize("count,accepted", [(16, True), (17, False)])
def test_document_finding_cap_with_real_detector(count, accepted, callbacks):
    email = " ".join(["a@b.co"] * count)
    events, authorize, execute = callbacks
    if accepted:
        result = demo.check_contact("contact", proposal(email))
        assert len(result.findings) == count
    else:
        with pytest.raises(Rejected, match="finding_limit_exceeded"):
            demo.run_workflow("contact", proposal(email), authorize, execute)
        assert events == []


def test_finding_budget_aggregates_fields_and_passes(monkeypatch, callbacks):
    nine = tuple(Finding("notice", index, index + 1) for index in range(9))
    install_policy(monkeypatch, Returns(Check(Action.WARN, nine)), pass_name="SECRET_POLICY")
    events, authorize, execute = callbacks
    with pytest.raises(Rejected, match="finding_limit_exceeded"):
        demo.run_workflow("contact", proposal("x" * 9, "x" * 9), authorize, execute)
    assert events == []


def test_finding_budget_includes_previous_passes(monkeypatch, callbacks):
    eight = tuple(Finding("notice", index, index + 1) for index in range(8))
    install_policy(monkeypatch, Returns(Check(Action.WARN, eight)), pass_name="SECRET_POLICY")
    events, authorize, execute = callbacks
    with pytest.raises(Rejected, match="finding_limit_exceeded"):
        demo.run_workflow("contact", proposal(EMAIL, "x" * 8), authorize, execute)
    assert events == []


@pytest.mark.parametrize("replacement", ["", "\ud800", "\udfff", "x" * 65, "x" * 255])
def test_invalid_transformed_field_has_no_partial_delivery(replacement, monkeypatch, callbacks):
    install_policy(monkeypatch, Replaces(replacement))
    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow("contact", proposal(), authorize, execute)
    assert events == []


@pytest.mark.parametrize("delta,accepted", [(-1, False), (0, True), (1, True)])
def test_output_serialized_boundary_after_replacement(monkeypatch, delta, accepted, callbacks):
    replacement = "\n" * 64
    output = json.dumps(
        {"email": replacement, "phone": replacement}, ensure_ascii=False, separators=(",", ":")
    )
    monkeypatch.setattr(demo, "MAX_OUTPUT_CHARS", len(output) + delta)
    install_policy(monkeypatch, Replaces(replacement))
    events, authorize, execute = callbacks
    if accepted:
        assert demo.check_contact("contact", proposal()).require_call()[1] == {
            "email": replacement,
            "phone": replacement,
        }
    else:
        with pytest.raises(Rejected, match="output_limit_exceeded"):
            demo.run_workflow("contact", proposal(), authorize, execute)
        assert events == []


def test_fresh_serialized_object_is_schema_rechecked_before_return(monkeypatch, callbacks):
    original = demo.TOOLS
    calls = []
    final_only = ToolGuard(
        {"contact": {"type": "object", "required": ["impossible"]}}, max_chars=4096
    )

    class SecondValidationRejects:
        def validate(self, name, wire):
            calls.append((name, wire))
            return (original if len(calls) == 1 else final_only).validate(name, wire)

    monkeypatch.setattr(demo, "TOOLS", SecondValidationRejects())
    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow("contact", proposal(EMAIL, PHONE), authorize, execute)
    assert len(calls) == 2
    assert json.loads(calls[1][1]) == {"email": "[PII]", "phone": "[PII]"}
    assert events == []


def test_serialization_failure_is_payload_free_and_stops_host_work(monkeypatch, callbacks):
    wire = proposal(EMAIL, PHONE)

    def fail(*args, **kwargs):
        raise RuntimeError(EMAIL)

    monkeypatch.setattr(demo.json, "dumps", fail)
    events, authorize, execute = callbacks
    with pytest.raises(Rejected, match="serialization_error") as error:
        demo.run_workflow("contact", wire, authorize, execute)
    displayed = repr(error.value) + "".join(traceback.format_exception(error.value))
    assert EMAIL not in displayed and PHONE not in displayed
    assert events == []


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
def test_malformed_scanner_result_prevents_host_work(decision, monkeypatch, callbacks):
    install_policy(monkeypatch, Returns(decision))
    events, authorize, execute = callbacks
    with pytest.raises(Rejected):
        demo.run_workflow("contact", proposal(), authorize, execute)
    assert events == []


def test_scanner_exception_diagnostics_and_traceback_are_payload_free(
    monkeypatch, callbacks, capsys
):
    class Failing:
        name = "failing"

        def scan(self, text, *, stage):
            raise RuntimeError(text)

    install_policy(monkeypatch, Failing())
    events, authorize, execute = callbacks
    with pytest.raises(Rejected) as error:
        demo.run_workflow("contact", proposal(EMAIL, PHONE), authorize, execute)
    displayed = repr(error.value) + "".join(traceback.format_exception(error.value))
    assert EMAIL not in displayed and PHONE not in displayed
    assert events == []
    assert capsys.readouterr() == ("", "")


def test_result_require_call_returns_a_copy():
    result = demo.check_contact("contact", proposal(EMAIL, PHONE))
    _, arguments = result.require_call()
    arguments["email"] = EMAIL
    assert result.require_call()[1] == {"email": "[PII]", "phone": "[PII]"}


def test_authorizer_only_sees_checked_pair_and_cannot_mutate_execution(callbacks):
    events, _, execute = callbacks

    def authorize(name, arguments):
        assert (name, arguments) == ("contact", {"email": "[PII]", "phone": "[PII]"})
        arguments["email"] = EMAIL
        arguments["extra"] = "injected"
        return True

    demo.run_workflow("contact", proposal(EMAIL, PHONE), authorize, execute)
    assert events == [("execute", "contact", {"email": "[PII]", "phone": "[PII]"})]


@pytest.mark.parametrize("decision", [None, False, 1, "yes"])
def test_only_literal_true_authorizes_execution(decision, callbacks):
    events, _, execute = callbacks
    with pytest.raises(PermissionError, match="^Tool request is not authorized$"):
        demo.run_workflow("contact", proposal(), lambda *_: decision, execute)
    assert events == []


@pytest.mark.parametrize("failure_stage", ["authorize", "execute"])
def test_callback_errors_are_sanitized(failure_stage, caplog, capsys):
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
        demo.run_workflow("contact", proposal(), authorize, execute)
    displayed = repr(error.value) + "".join(traceback.format_exception(error.value))
    assert EMAIL not in displayed
    assert events == (["authorize"] if failure_stage == "authorize" else ["authorize", "execute"])
    assert caplog.text == ""
    assert capsys.readouterr() == ("", "")


def test_public_recipe_is_fixed_policy_and_smoke_is_offline(capsys):
    assert list(inspect.signature(demo.check_contact).parameters) == ["name", "arguments_json"]
    assert list(inspect.signature(demo.run_workflow).parameters) == [
        "name",
        "arguments_json",
        "authorize",
        "execute",
    ]
    demo.main()
    assert "Equivalent plain and escaped contacts" in capsys.readouterr().out
