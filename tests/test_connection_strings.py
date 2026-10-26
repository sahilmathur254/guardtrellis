"""Authored connection-URI disclosure and checked-delivery regressions; no network."""

import json
import logging
from pathlib import Path
from unittest.mock import Mock

import pytest

from examples import tool_result_handoff as handoff
from guardtrellis import Action, Guard, PIIScanner, Rejected, SecretScanner, Stage, ToolGuard

PASSWORD = "SyntheticRegressionPassword41"
URI = f"postgresql://app:{PASSWORD}@db.example.invalid/demo"
URI_CODES = {"secret_postgresql_uri", "secret_mongodb_uri"}
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = {
    "type": "object",
    "properties": {"query": {"type": "string"}},
    "required": ["query"],
    "additionalProperties": False,
}


def selected_cases():
    """Use authored plaintext decisions, not outcomes or raw-JSON span guesses."""
    cases = []
    for filename in (
        "corpus_v1.jsonl",
        "contract_supplement_v1.jsonl",
        "boundaries_v1.jsonl",
    ):
        for line in (
            (ROOT / "evaluation" / "connection_strings" / filename)
            .read_text(encoding="utf-8")
            .splitlines()
        ):
            case = json.loads(line)
            if (
                case.get("contract_status") == "selected"
                or "contract_status" not in case
                and case["label"] in {"sensitive", "benign"}
            ):
                cases.append(case)
    return cases


def uri_findings(check):
    return [(item.code, item.start, item.end) for item in check.findings if item.code in URI_CODES]


def assert_static_error(check, code):
    assert check.action == Action.ERROR
    assert [(item.code, item.start, item.end) for item in check.findings] == [(code, None, None)]
    assert check.edits == ()


@pytest.mark.parametrize("case", selected_cases(), ids=lambda case: case["id"])
def test_selected_plain_and_explicitly_decoded_cases_have_exact_authored_spans(case):
    scanner = SecretScanner(connection_strings=True)
    text = case["text"]
    # Decoding is performed by the application before the scanner receives its text.
    decoded = json.loads(json.dumps({"value": text}, ensure_ascii=True))["value"]
    assert decoded == text
    expected = []
    for start, end in case["target_spans"]:
        family = "mongodb" if text[start:end].lower().startswith("mongo") else "postgresql"
        expected.append((f"secret_{family}_uri", start, end))
    for scanned in (text, decoded):
        check = scanner.scan(scanned, stage=Stage.RETRIEVAL)
        assert check.action.value == case["expected_action"]
        assert uri_findings(check) == expected
        assert check.edits == ()


@pytest.mark.parametrize("value", [None, 0, 1, "true", "false", [], {}, object()])
def test_opt_in_requires_an_actual_boolean(value):
    with pytest.raises(ValueError):
        SecretScanner(connection_strings=value)


@pytest.mark.parametrize(
    "action", [Action.WARN, Action.REDACT, Action.ALLOW, Action.ERROR, "block"]
)
def test_opt_in_rejects_non_block_actions_at_construction(action):
    with pytest.raises(ValueError):
        SecretScanner(connection_strings=True, action=action)


@pytest.mark.parametrize(
    "action", [Action.WARN, Action.REDACT, Action.ALLOW, Action.ERROR, "block"]
)
def test_mutated_opt_in_action_fails_closed_even_without_a_matching_uri(action):
    scanner = SecretScanner(connection_strings=True)
    scanner.action = action
    for text in (URI, "Public opening hours"):
        assert_static_error(
            scanner.scan(text, stage=Stage.INPUT), "connection_string_configuration_error"
        )
        result = Guard(input_scanners=[scanner]).scan(text)
        assert result.text is None and not result.accepted
        with pytest.raises(Rejected):
            result.require_text()


@pytest.mark.parametrize("action", [Action.WARN, Action.REDACT, Action.BLOCK])
def test_disabled_mode_preserves_existing_actions_and_public_action_mutation(action):
    token = "ghp_" + "B" * 36
    implicit, explicit = SecretScanner(), SecretScanner(connection_strings=False)
    for scanner in (implicit, explicit):
        scanner.action = action
        check = scanner.scan(f"{URI} {token}", stage=Stage.INPUT)
        assert check.action == action
        assert [item.code for item in check.findings] == ["secret_github_classic"]
        assert bool(check.edits) == (action == Action.REDACT)
        assert scanner.scan(URI, stage=Stage.INPUT).action == Action.ALLOW
    assert implicit.scan(token, stage=Stage.INPUT) == explicit.scan(token, stage=Stage.INPUT)


@pytest.mark.parametrize("scheme", ["postgresql", "postgres", "mongodb", "mongodb+srv"])
@pytest.mark.parametrize("prefix", ["x", "0", "_", "+", ".", "-"])
def test_scheme_like_ascii_prefixes_do_not_create_a_supported_candidate(scheme, prefix):
    text = f"{prefix}{scheme}://app:{PASSWORD}@db.example.invalid/demo"
    assert (
        SecretScanner(connection_strings=True).scan(text, stage=Stage.TOOL).action == Action.ALLOW
    )


@pytest.mark.parametrize("prefix", ["🧪 ", "é", "演示:", "("])
def test_non_ascii_or_prose_boundaries_preserve_original_offsets(prefix):
    text = prefix + URI
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert uri_findings(check) == [("secret_postgresql_uri", len(prefix), len(text))]


@pytest.mark.parametrize(
    "text",
    [
        "poſtgresql://app:synthetic@db.example.invalid/demo",
        "postgreſql://app:synthetic@db.example.invalid/demo",
        "postgresql://db.example.invalid/demo?paſſword=synthetic",
        "postgresql://db.example.invalid/demo?password%00=synthetic",
        "postgresql://db.example.invalid/demo?passwordx=synthetic",
        "postgresql://db.example.invalid/demo?pass+word=synthetic",
        "postgresql://db.example.invalid/demo?%2570assword=synthetic",
        "postgresql://db.example.invalid/demo?password",
        "postgresql://db.example.invalid/demo?password=",
        "postgresql://db.example.invalid/demo#password=synthetic",
        "mongodb://db.example.invalid/demo?password=synthetic",
    ],
)
def test_unsupported_keys_and_spellings_do_not_become_uri_findings(text):
    assert (
        SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT).action == Action.ALLOW
    )


@pytest.mark.parametrize(
    "key",
    ["password", "PASSWORD", "%70assword", "%50%61%73%73%77%6f%72%64", "p%61ssw%6Frd"],
)
def test_each_nonempty_query_password_is_considered_after_bad_pairs_and_empty_duplicates(key):
    text = f"postgresql://db.example.invalid/demo?pass%GGword=ignored&password=&{key}=x&password="
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.BLOCK
    assert uri_findings(check) == [("secret_postgresql_uri", 0, len(text))]


@pytest.mark.parametrize("value", ["#", "+", "%", "%GG", "*", "${VALUE}", "<value>"])
def test_nonempty_query_password_spelling_is_opaque_and_never_treated_as_a_template_exemption(
    value,
):
    text = f"postgresql://db.example.invalid/demo?password={value}"
    assert uri_findings(SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)) == [
        ("secret_postgresql_uri", 0, len(text))
    ]


@pytest.mark.parametrize("wrapper", [('"', '"'), ("`", "`"), ("<", ">")])
def test_outer_wrappers_exclude_only_the_wrapper_and_keep_inner_angle_placeholders(wrapper):
    candidate = "mongodb://<user>:<synthetic>@db.example.invalid/demo"
    before, after = wrapper
    text = f"🧪 {before}{candidate}{after}; next"
    start = len(f"🧪 {before}")
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.RETRIEVAL)
    assert uri_findings(check) == [("secret_mongodb_uri", start, start + len(candidate))]


@pytest.mark.parametrize("opening,inside", [('"', "`"), ("`", '"')])
def test_only_the_active_outer_wrapper_ends_an_opaque_password_candidate(opening, inside):
    candidate = f"postgresql://app:Synthetic{inside}Password41@db.example.invalid/demo"
    text = opening + candidate + opening
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.BLOCK
    assert uri_findings(check) == [("secret_postgresql_uri", 1, 1 + len(candidate))]


@pytest.mark.parametrize("punctuation", ['"', "`"])
@pytest.mark.parametrize("location", ["userinfo", "query"])
def test_unwrapped_password_quotes_are_preserved_as_opaque_content(punctuation, location):
    password = f"Synthetic{punctuation}Password41"
    text = (
        f"postgresql://app:{password}@db.example.invalid/demo"
        if location == "userinfo"
        else f"postgresql://db.example.invalid/demo?password={password}"
    )
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.BLOCK
    assert uri_findings(check) == [("secret_postgresql_uri", 0, len(text))]


@pytest.mark.parametrize(
    "prefix,suffix",
    [
        ('"Returned URI: ', '"'),
        ("`Returned URI: ", "`"),
        ('{"value":"Returned URI: ', '"}'),
    ],
)
def test_outer_quote_context_can_start_before_a_prose_prefix(prefix, suffix):
    text = prefix + URI + suffix
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.BLOCK
    assert uri_findings(check) == [("secret_postgresql_uri", len(prefix), len(prefix) + len(URI))]


@pytest.mark.parametrize(
    "prefix",
    [
        "postgresql://public.example.invalid/demo,",
        "postgresql://public.example.invalid/demo?next=",
        "mongodb://public.example.invalid/demo/",
    ],
)
def test_nested_or_undelimited_uri_inside_an_earlier_candidate_remains_a_documented_gap(prefix):
    # The candidate walk does not restart inside a path or query value. This is
    # a retained scope limitation, not an assertion that the nested value is safe.
    text = prefix + f"mongodb://app:{PASSWORD}@db.example.invalid/demo"
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert check.action == Action.ALLOW
    assert uri_findings(check) == []


def test_apostrophes_and_adjacent_punctuation_are_not_trimmed_from_the_candidate():
    candidate = "postgresql://app:Synthetic'Opaque@db.example.invalid/demo),;"
    check = SecretScanner(connection_strings=True).scan(candidate, stage=Stage.INPUT)
    assert uri_findings(check) == [("secret_postgresql_uri", 0, len(candidate))]


def test_raw_unicode_escaped_json_is_not_implicitly_decoded():
    wire = '{"value":"' + "".join(f"\\u{ord(char):04x}" for char in URI) + '"}'
    scanner = SecretScanner(connection_strings=True)
    assert scanner.scan(wire, stage=Stage.TOOL).action == Action.ALLOW
    decoded = json.loads(wire)["value"]
    check = scanner.scan(decoded, stage=Stage.TOOL)
    assert uri_findings(check) == [("secret_postgresql_uri", 0, len(URI))]


def test_existing_signatures_are_retained_inside_uri_spans_in_deterministic_order():
    token = "ghp_" + "C" * 36
    candidate = f"postgresql://app:{token}@db.example.invalid/demo"
    text = f"{token} {candidate}"
    start = len(token) + 1
    embedded = start + len("postgresql://app:")
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert [(item.code, item.start, item.end) for item in check.findings] == [
        ("secret_github_classic", 0, len(token)),
        ("secret_postgresql_uri", start, len(text)),
        ("secret_github_classic", embedded, embedded + len(token)),
    ]


@pytest.mark.parametrize("count,action", [(128, Action.BLOCK), (129, Action.ERROR)])
def test_uri_and_existing_signature_findings_share_one_combined_ceiling(count, action):
    token = "ghp_" + "D" * 36
    text = "\n".join([f"postgresql://app:{token}@db.example.invalid/demo"] * count)
    check = SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT)
    assert check.action == action
    if action == Action.ERROR:
        assert_static_error(check, "finding_limit_exceeded")
    else:
        assert len(check.findings) == 256


@pytest.mark.parametrize(
    "candidate", ["postgresql://db.example.invalid/demo", "postgresql://app:cut"]
)
def test_candidate_attempt_limit_counts_credential_free_and_malformed_candidates(candidate):
    from guardtrellis import _connection_strings as limits

    scanner = SecretScanner(connection_strings=True)
    allowed = "\n".join([candidate] * limits.MAX_CANDIDATES)
    assert scanner.scan(allowed, stage=Stage.INPUT).action == Action.ALLOW
    assert_static_error(
        scanner.scan(allowed + "\n" + candidate, stage=Stage.INPUT),
        "connection_string_limit_exceeded",
    )


@pytest.mark.parametrize("sensitive", [False, True])
def test_candidate_length_limit_is_checked_without_returning_a_partial_match(sensitive):
    from guardtrellis import _connection_strings as limits

    prefix = URI if sensitive else "postgresql://db.example.invalid/demo"
    text = prefix + "x" * (limits.MAX_CANDIDATE_CHARS - len(prefix))
    scanner = SecretScanner(connection_strings=True)
    check = scanner.scan(text, stage=Stage.INPUT)
    assert check.action == (Action.BLOCK if sensitive else Action.ALLOW)
    if sensitive:
        assert uri_findings(check) == [("secret_postgresql_uri", 0, len(text))]
    assert_static_error(
        scanner.scan(text + "x", stage=Stage.INPUT), "connection_string_limit_exceeded"
    )


def test_direct_input_budget_is_independent_of_guard_max_chars_and_disabled_mode():
    from guardtrellis import _connection_strings as limits

    scanner = SecretScanner(connection_strings=True)
    assert scanner.scan("x" * limits.MAX_TEXT_CHARS, stage=Stage.INPUT).action == Action.ALLOW
    text = "x" * (limits.MAX_TEXT_CHARS + 1)
    assert_static_error(scanner.scan(text, stage=Stage.INPUT), "connection_string_limit_exceeded")
    assert SecretScanner().scan(text, stage=Stage.INPUT).action == Action.ALLOW
    result = Guard(input_scanners=[scanner], max_chars=len(text)).scan(text)
    assert result.action == Action.ERROR and result.text is None
    assert [(item.code, item.start, item.end) for item in result.findings] == [
        ("connection_string_limit_exceeded", None, None)
    ]


def test_overflow_after_a_sensitive_candidate_discards_partial_findings():
    from guardtrellis import _connection_strings as limits

    text = URI + "\n" + "\n".join(["mongodb://public.example.invalid/demo"] * limits.MAX_CANDIDATES)
    assert_static_error(
        SecretScanner(connection_strings=True).scan(text, stage=Stage.INPUT),
        "connection_string_limit_exceeded",
    )


def test_direct_unexpected_failure_has_static_metadata_and_no_exception_payload(
    monkeypatch, caplog
):
    scanner = SecretScanner(connection_strings=True)

    def fail(_text):
        raise RuntimeError(PASSWORD)

    monkeypatch.setattr(scanner, "_find", fail)
    check = scanner.scan(URI, stage=Stage.INPUT)
    assert_static_error(check, "scanner_error")
    assert PASSWORD not in repr(check) + caplog.text


@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize("fault", [False, True], ids=["block", "configuration-error"])
async def test_every_stage_withholds_sync_and_async_output_and_metadata_is_safe(stage, fault):
    scanner = SecretScanner(connection_strings=True)
    if fault:
        scanner.action = Action.WARN
    policy = Guard(**{f"{stage.value}_scanners": [scanner, PIIScanner()]})
    original = f"{URI} contact demo@example.org"
    for result in (policy.scan(original, stage=stage), await policy.ascan(original, stage=stage)):
        assert result.action == (Action.ERROR if fault else Action.BLOCK)
        assert result.stage == stage and result.text is None and not result.accepted
        assert [trace.scanner for trace in result.trace] == ["secrets"]
        consumer = Mock()
        with pytest.raises(Rejected) as error:
            consumer(result.require_text())
        consumer.assert_not_called()
        surface = repr(result) + json.dumps(result.diagnostics()) + str(error.value)
        assert all(marker not in surface for marker in (PASSWORD, URI, "demo@example.org"))


@pytest.mark.parametrize("fault", [False, True], ids=["block", "configuration-error"])
async def test_input_rejection_prevents_sync_and_async_model_calls(fault):
    scanner = SecretScanner(connection_strings=True)
    if fault:
        scanner.action = Action.REDACT
    policy = Guard(input_scanners=[scanner])
    model = Mock(return_value="Public answer")
    for result in (policy.run(URI, model), await policy.arun(URI, model)):
        assert result.action == (Action.ERROR if fault else Action.BLOCK)
        assert result.output_result is result.text is None
        with pytest.raises(Rejected):
            result.require_text()
    model.assert_not_called()


async def test_model_output_rejection_prevents_downstream_state_insertion():
    policy = Guard(output_scanners=[SecretScanner(connection_strings=True)])
    state = ["Earlier checked answer"]
    for result in (
        policy.run("Public question", lambda _: URI),
        await policy.arun("Public question", lambda _: URI),
    ):
        assert result.action == Action.BLOCK
        assert result.output_result.text is result.text is None
        with pytest.raises(Rejected):
            state.append(result.require_text())
    assert state == ["Earlier checked answer"]


@pytest.mark.parametrize("fault", [False, True], ids=["block", "configuration-error"])
def test_tool_return_policy_stops_the_consumer_and_state_after_execution(fault, caplog):
    caplog.set_level(logging.INFO, logger=handoff.LOGGER.name)
    scanner = SecretScanner(connection_strings=True)
    if fault:
        scanner.action = Action.WARN
    policy = Guard(retrieval_scanners=[scanner, PIIScanner()])
    state, events = ["Earlier checked result"], []

    def execute(name, arguments):
        events.append((name, arguments))
        return URI + " Contact demo@example.org"

    with pytest.raises(Rejected):
        handoff.run_workflow(
            "lookup",
            '{"document_id":"public-guide"}',
            handoff.demo_authorize,
            execute,
            state.append,
            result_guard=policy,
        )
    assert events == [("lookup", {"document_id": "public-guide"})]
    assert state == ["Earlier checked result"]
    assert all(marker not in caplog.text for marker in (PASSWORD, URI, "demo@example.org"))


@pytest.mark.parametrize("fault", [False, True], ids=["block", "configuration-error"])
async def test_tool_arguments_withhold_the_name_arguments_and_dispatch(fault):
    scanner = SecretScanner(connection_strings=True)
    if fault:
        scanner.action = Action.REDACT
    tools = ToolGuard({"search": SCHEMA}, argument_scanners=[scanner, PIIScanner()])
    arguments = json.dumps({"query": URI})
    for result in (
        tools.validate("search", arguments),
        await tools.avalidate("search", arguments),
    ):
        assert result.action == (Action.ERROR if fault else Action.BLOCK)
        assert result.name is result.arguments is result.validation.text is None
        dispatch = Mock()
        with pytest.raises(Rejected):
            dispatch(*result.require_call())
        dispatch.assert_not_called()
        assert PASSWORD not in repr(result) + json.dumps(result.diagnostics())


async def test_benign_tool_call_and_following_redaction_deliver_only_checked_data():
    policy = Guard(
        retrieval_scanners=[SecretScanner(connection_strings=True), PIIScanner()],
    )
    original = "postgresql://public.example.invalid/demo Contact demo@example.org"
    expected = "postgresql://public.example.invalid/demo Contact [PII]"
    for result in (
        policy.scan(original, stage=Stage.RETRIEVAL),
        await policy.ascan(original, stage=Stage.RETRIEVAL),
    ):
        assert result.action == Action.REDACT
        assert result.require_text() == expected
        assert [trace.scanner for trace in result.trace] == ["secrets", "pii"]
    tools = ToolGuard(
        {"search": SCHEMA}, argument_scanners=[SecretScanner(connection_strings=True)]
    )
    arguments = {"query": "Opening hours: 9am to 5pm."}
    assert (await tools.avalidate("search", json.dumps(arguments))).require_call() == (
        "search",
        arguments,
    )


def test_finding_offsets_follow_the_current_input_revision_after_an_earlier_edit():
    policy = Guard(
        input_scanners=[PIIScanner(formats=["phone"]), SecretScanner(connection_strings=True)]
    )
    text = "+14155550123 " + URI
    result = policy.scan(text)
    finding = next(item for item in result.findings if item.code in URI_CODES)
    assert (finding.start, finding.end, finding.revision, finding.scanner_index) == (
        len("[PII] "),
        len("[PII] ") + len(URI),
        1,
        1,
    )
    assert result.action == Action.BLOCK and result.text is None
