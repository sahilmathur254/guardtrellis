"""Authored synthetic regressions for explicit formatted-phone detection; no network."""

import json

import pytest

from examples import decoded_query
from guardtrellis import Action, Guard, LiteralScanner, PIIScanner, Rejected, Stage

PHONE = "+1 (202) 555-0123"


def formatted_guard(*, action=Action.REDACT, **kwargs):
    return Guard(
        input_scanners=[PIIScanner(formats=["phone"], phone_mode="formatted", action=action)],
        **kwargs,
    )


@pytest.mark.parametrize(
    "phone",
    [
        "+12345678",
        "+123456789012345",
        "+1 234 5678",
        "+12-345-678",
        "+1 202 555 0123",
        "+1-202-555-0123",
        PHONE,
        "+1-(202)-555-0123",
        "+44 20-7946 0123",
        "+1234567 (8)",
        "+1 (2345678)",
        "+123 456 (789) 012345",
        "+12025550123-4567",
    ],
)
def test_supported_shapes_cover_the_entire_original_span(phone):
    text = f"😀 contact: {phone}!"
    result = formatted_guard().scan(text)
    assert result.action == Action.REDACT
    assert result.require_text() == "😀 contact: [PII]!"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.code == "pii_phone"
    assert (finding.start, finding.end) == (11, 11 + len(phone))
    assert text[finding.start : finding.end] == phone


@pytest.mark.parametrize(
    "text",
    [
        "+1234567",  # Seven digits is below the minimum.
        "+1234567890123456",  # Sixteen contiguous digits.
        "+1 234 567 890 123 456",  # Sixteen formatted digits.
        "+12025550123-45678",  # A valid prefix must not survive overflow.
        "+12025550123 45678",
        "+12025550123--4567",
        "+12025550123  4567",
        "+12025550123 -4567",
        "+12025550123.4567",
        "+12025550123 ٤٥٦٧",
        "+12025550123  ٤٥٦٧",
        "+12025550123 ４５６７",
        "+12025550123  ４５６７",
        "+12025550123(4567)",
        "+12025550123 (4567) 8",
        "+12025550123 (4567",
        "+12025550123 ()",
        "+12025550123 ((4))",
        "+12025550123 (4-5)",
        "+1 (202) (555) 0123",
        "+1(202)5550123",
        "+1 (202)5550123",
        "+1 (202 555-0123",
        "+1 202) 555-0123",
        "+02025550123",
        "+0 202 555 0123",
        "x+12025550123",
        "_+12025550123",
        "é+12025550123",
        "+12025550123x",
        "+12025550123_",
        "+12025550123é",
        "++12025550123",
        "+1\t202\t555\t0123",
        "+1\n202\n555\n0123",
        "+1\u00a0202\u00a0555\u00a00123",
        "+1\u200b2025550123",
        "+١٢٠٢٥٥٥٠١٢٣",
        "+1 ２０２ 555 0123",
        "+1.202.555.0123",
        "202-555-0123",
    ],
)
def test_unsupported_shapes_do_not_fall_back_to_contiguous_prefixes(text):
    result = formatted_guard().scan(text)
    assert result.action == Action.ALLOW
    assert result.require_text() == text
    assert result.findings == ()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"({PHONE}).", "([PII])."),
        ("(+12025550123).", "([PII])."),
        (f"[{PHONE}]", "[[PII]]"),
        (f'"{PHONE}"', '"[PII]"'),
        (f"{PHONE}, next", "[PII], next"),
        (f"{PHONE}: next", "[PII]: next"),
        (f"{PHONE}; next", "[PII]; next"),
        (f"{PHONE} today", "[PII] today"),
        (f"{PHONE}\n+44 20 7946 0123", "[PII]\n[PII]"),
        (f"{PHONE}\t+44 20 7946 0123", "[PII]\t[PII]"),
        ("+12025550123 7 items", "[PII] items"),
    ],
)
def test_boundaries_preserve_punctuation_and_do_not_join_lines(text, expected):
    assert formatted_guard().scan(text).require_text() == expected


@pytest.mark.parametrize("mode", ["", "FORMATTED", "unknown", None, True, 1, [], {}])
def test_invalid_mode_values_are_rejected(mode):
    with pytest.raises(ValueError):
        PIIScanner(phone_mode=mode)


@pytest.mark.parametrize(
    ("text", "checked"),
    [
        (PHONE, PHONE),
        ("+12025550123-4567", "[PII]-4567"),
        ("+12025550123.4567", "[PII].4567"),
        ("+12025550123 ٤٥٦٧", "[PII] ٤٥٦٧"),
        ("+12025550123  ٤٥٦٧", "[PII]  ٤٥٦٧"),
        ("+12025550123 ４５６７", "[PII] ４５６７"),
        ("+12025550123  ４５６７", "[PII]  ４５６７"),
        ("+1234567890123456", "+1234567890123456"),
        ("(+12025550123).", "([PII])."),
    ],
)
def test_default_and_explicit_contiguous_mode_preserve_legacy_behavior(text, checked):
    default = Guard(input_scanners=[PIIScanner(formats=["phone"])]).scan(text)
    explicit = Guard(input_scanners=[PIIScanner(formats=["phone"], phone_mode="contiguous")]).scan(
        text
    )
    assert default == explicit
    assert default.require_text() == checked


def test_formats_gate_and_duplicate_selection_do_not_add_phone_matches():
    text = f"alpha@example.org {PHONE}"
    email_only = Guard(input_scanners=[PIIScanner(formats=["email"], phone_mode="formatted")]).scan(
        text
    )
    assert email_only.require_text() == f"[PII] {PHONE}"
    assert [finding.code for finding in email_only.findings] == ["pii_email"]
    repeated = Guard(
        input_scanners=[PIIScanner(formats=["phone", "phone"], phone_mode="formatted")]
    ).scan(text)
    assert repeated.require_text() == "alpha@example.org [PII]"
    assert len(repeated.findings) == 1


@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize("action", [Action.WARN, Action.REDACT, Action.BLOCK])
def test_all_stage_policies_preserve_action_and_metadata_contract(stage, action):
    guard = Guard(
        **{
            f"{stage.value}_scanners": [
                PIIScanner(formats=["phone"], phone_mode="formatted", action=action)
            ]
        }
    )
    result = guard.scan(PHONE, stage=stage)
    assert result.stage == stage
    assert result.action == action
    finding = result.findings[0]
    assert (finding.code, finding.start, finding.end) == ("pii_phone", 0, len(PHONE))
    assert (finding.revision, finding.scanner_index, finding.scanner) == (0, 0, "pii")
    assert PHONE not in repr(result) + json.dumps(result.diagnostics())
    if action == Action.BLOCK:
        assert result.text is None
        with pytest.raises(Rejected):
            result.require_text()
    else:
        assert result.require_text() == (PHONE if action == Action.WARN else "[PII]")
    for other_stage in Stage:
        if other_stage != stage:
            assert guard.scan(PHONE, stage=other_stage).action == Action.ALLOW


@pytest.mark.parametrize("action", [Action.WARN, Action.REDACT, Action.BLOCK])
def test_sync_delivery_uses_checked_input_and_output(action):
    calls = []

    def model(text):
        calls.append(text)
        return f"Reply {PHONE}"

    scanner = PIIScanner(formats=["phone"], phone_mode="formatted", action=action)
    result = Guard(input_scanners=[scanner], output_scanners=[scanner]).run(PHONE, model)
    assert result.action == action
    if action == Action.BLOCK:
        assert calls == []
        assert result.output_result is None
        with pytest.raises(Rejected):
            result.require_text()
    else:
        checked = PHONE if action == Action.WARN else "[PII]"
        assert calls == [checked]
        assert result.require_text() == f"Reply {checked}"
    assert PHONE not in repr(result) + json.dumps(result.diagnostics())


@pytest.mark.parametrize("action", [Action.WARN, Action.REDACT, Action.BLOCK])
async def test_async_delivery_uses_checked_input_and_output(action):
    calls = []

    async def model(text):
        calls.append(text)
        return f"Reply {PHONE}"

    scanner = PIIScanner(formats=["phone"], phone_mode="formatted", action=action)
    result = await Guard(input_scanners=[scanner], output_scanners=[scanner]).arun(PHONE, model)
    assert result.action == action
    if action == Action.BLOCK:
        assert calls == []
        assert result.output_result is None
        with pytest.raises(Rejected):
            result.require_text()
    else:
        checked = PHONE if action == Action.WARN else "[PII]"
        assert calls == [checked]
        assert result.require_text() == f"Reply {checked}"
    assert PHONE not in repr(result) + json.dumps(result.diagnostics())


def test_output_only_block_prevents_delivery_after_callback():
    result = Guard(output_scanners=[PIIScanner(phone_mode="formatted", action=Action.BLOCK)]).run(
        "Return synthetic contact", lambda _: PHONE
    )
    assert result.input_result.accepted
    assert result.action == Action.BLOCK
    assert result.text is None
    with pytest.raises(Rejected):
        result.require_text()


@pytest.mark.parametrize("action", [Action.WARN, Action.REDACT, Action.BLOCK])
def test_decoded_query_plain_and_escaped_share_checked_handoff(action):
    policy = Guard(
        tool_scanners=[PIIScanner(formats=["phone"], phone_mode="formatted", action=action)]
    )
    plain = json.dumps({"query": f"😀 Call {PHONE}"}, ensure_ascii=False)
    escaped = plain.translate(str.maketrans({"+": r"\u002b", "(": r"\u0028", "2": r"\u0032"}))
    assert json.loads(plain) == json.loads(escaped)
    events = []

    def authorize(name, arguments):
        events.append(("authorize", name, arguments.copy()))
        arguments["query"] = "authorizer must not replace checked dispatch"
        return True

    def execute(name, arguments):
        events.append(("execute", name, arguments.copy()))
        return "Offline receipt"

    for proposal in (plain, escaped):
        if action == Action.BLOCK:
            with pytest.raises(Rejected):
                decoded_query.run_workflow(
                    "search", proposal, authorize, execute, query_guard=policy
                )
        else:
            final = decoded_query.check_query("search", proposal, query_guard=policy)
            assert final.action == Action.ALLOW
            assert final.diagnostics()["findings"] == []
            checked = f"😀 Call {PHONE}" if action == Action.WARN else "😀 Call [PII]"
            assert final.require_call() == ("search", {"query": checked})
            assert (
                decoded_query.run_workflow(
                    "search", proposal, authorize, execute, query_guard=policy
                )
                == "Offline receipt"
            )
    if action == Action.BLOCK:
        assert events == []
    else:
        assert events == [
            (event, "search", {"query": checked})
            for _ in (plain, escaped)
            for event in ("authorize", "execute")
        ]


def test_phone_offsets_follow_the_input_revision_after_an_earlier_edit():
    result = Guard(
        input_scanners=[
            LiteralScanner(["prefix"], action=Action.REDACT),
            PIIScanner(formats=["phone"], phone_mode="formatted"),
        ]
    ).scan(f"prefix 😀 {PHONE} tail")
    assert result.require_text() == "[REDACTED] 😀 [PII] tail"
    first, phone = result.findings
    assert (first.start, first.end, first.revision, first.scanner_index) == (0, 6, 0, 0)
    assert (phone.start, phone.end, phone.revision, phone.scanner_index) == (
        13,
        13 + len(PHONE),
        1,
        1,
    )
    assert result.trace[-1].revision_after == 2


@pytest.mark.parametrize(
    ("text", "codes"),
    [
        ("+1 321-54-9876", {"pii_phone", "pii_ssn"}),
        ("+12025550123@example.org", {"pii_phone", "pii_email"}),
        ("321-54-9876@example.org", {"pii_email", "pii_ssn"}),
    ],
)
def test_overlapping_formats_keep_all_findings_and_redact_the_union(text, codes):
    result = Guard(input_scanners=[PIIScanner(phone_mode="formatted")]).scan(text)
    assert result.require_text() == "[PII]"
    assert {finding.code for finding in result.findings} == codes


def test_multiple_phone_matches_keep_original_unicode_offsets():
    other = "+44 20 7946 0123"
    text = f"😀 {PHONE}; 🌱 {other}."
    result = formatted_guard().scan(text)
    assert result.require_text() == "😀 [PII]; 🌱 [PII]."
    assert [(finding.start, finding.end) for finding in result.findings] == [
        (2, 2 + len(PHONE)),
        (text.index(other), text.index(other) + len(other)),
    ]


def test_invalid_candidate_does_not_hide_a_later_independent_plus_start():
    text = "+12025550123-+442079460123"
    result = formatted_guard().scan(text)
    assert result.require_text() == "+12025550123-[PII]"
    assert [(finding.start, finding.end) for finding in result.findings] == [(13, 26)]


@pytest.mark.parametrize("count", [256, 257])
def test_existing_finding_limit_is_enforced_without_partial_delivery(count):
    result = formatted_guard().scan("\n".join([PHONE] * count))
    if count == 256:
        assert result.require_text() == "\n".join(["[PII]"] * count)
        assert len(result.findings) == count
    else:
        assert result.action == Action.ERROR
        assert result.text is None
        assert [finding.code for finding in result.findings] == ["finding_limit_exceeded"]


def test_maximum_input_and_oversize_fail_before_any_scanning():
    text = "x" * (100_000 - len(PHONE) - 1) + " " + PHONE
    guard = formatted_guard()
    result = guard.scan(text)
    assert result.action == Action.REDACT
    assert result.require_text().endswith(" [PII]")
    assert (result.findings[0].start, result.findings[0].end) == (
        100_000 - len(PHONE),
        100_000,
    )
    oversize = guard.scan(text + "x")
    assert oversize.action == Action.ERROR
    assert oversize.trace == ()
    assert [finding.code for finding in oversize.findings] == ["text_limit_exceeded"]


@pytest.mark.parametrize(
    "text",
    [
        "+" + "1" * 99_999,
        "+12025550123 (" + "1" * (100_000 - len("+12025550123 (")),
        "+1 " * 33_333,
    ],
    ids=["overlong-digit-run", "unclosed-long-group", "many-short-candidates"],
)
def test_long_malformed_runs_finish_without_prefix_redaction(text):
    result = formatted_guard().scan(text)
    assert result.action == Action.ALLOW
    assert result.require_text() == text
    assert result.findings == ()
