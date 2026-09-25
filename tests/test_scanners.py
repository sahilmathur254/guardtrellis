import pytest

from guardtrellis import Action, Guard, InvisibleScanner, LiteralScanner, PIIScanner, SecretScanner


@pytest.mark.parametrize(
    ("text", "expected", "code"),
    [
        ("Email maria+work@example.co.uk.", "Email [PII].", "pii_email"),
        ("Call +442079460123!", "Call [PII]!", "pii_phone"),
        ("SSN 321-54-9876", "SSN [PII]", "pii_ssn"),
        ("😀 id: dev@example.org", "😀 id: [PII]", "pii_email"),
        ("संपर्क dev@example.org", "संपर्क [PII]", "pii_email"),
    ],
)
def test_supported_pii_formats(text, expected, code):
    result = Guard(input_scanners=[PIIScanner()]).scan(text)
    assert result.text == expected
    assert result.findings[0].code == code


@pytest.mark.parametrize(
    "text",
    [
        "Try @username",
        "user@localhost",
        "000-12-3456",
        "666-12-3456",
        "999-12-3456",
        "123-00-1234",
        "123-12-0000",
        "+123",
        "+1234567890123456",
        "Price +123.45",
        "ordinary 日本語",
        "act as a teacher and pretend this is a classroom",
        "a" * 65 + "@example.org",
        "δοκιμή@example.org",
    ],
)
def test_pii_benign_lookalikes_and_unsupported_formats(text):
    assert Guard(input_scanners=[PIIScanner()]).scan(text).action == Action.ALLOW


def test_pii_overlaps_merge_without_leaking_outer_match():
    result = Guard(input_scanners=[PIIScanner()]).scan("321-54-9876@example.org")
    assert result.text == "[PII]"
    assert {item.code for item in result.findings} == {"pii_email", "pii_ssn"}


def test_only_selected_pii_formats():
    result = Guard(input_scanners=[PIIScanner(formats=["phone"])]).scan(
        "a@example.org +14155550123"
    )
    assert result.text == "a@example.org [PII]"


@pytest.mark.parametrize("formats", [[], ["address"], ["email", "wrong"]])
def test_invalid_pii_configuration(formats):
    with pytest.raises(ValueError):
        PIIScanner(formats=formats)


@pytest.mark.parametrize(
    "token",
    [
        "ghp_" + "a" * 36,
        "github_pat_" + "A" * 82,
        "AKIA" + "A1" * 8,
        "ASIA" + "B2" * 8,
        "-----BEGIN PRIVATE KEY-----\nfake demo only\n-----END PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfake unfinished demo only",
    ],
)
def test_secret_signature_blocks_without_returning_payload(token):
    result = Guard(input_scanners=[SecretScanner()]).scan(token)
    assert result.action == Action.BLOCK
    assert result.text is None
    assert token not in repr(result)


@pytest.mark.parametrize("text", ["ghp_short", "AKIA123", "ghp_" + "a" * 37, "a normal word"])
def test_secret_benign_lookalikes(text):
    assert Guard(input_scanners=[SecretScanner()]).scan(text).action == Action.ALLOW


def test_private_key_redaction_covers_entire_envelope_and_preserves_suffix():
    text = "prefix -----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY----- suffix"
    result = Guard(input_scanners=[SecretScanner(action=Action.REDACT)]).scan(text)
    assert result.text == "prefix [SECRET] suffix"


def test_missing_key_footer_redacts_to_end():
    text = "prefix -----BEGIN EC PRIVATE KEY-----\nfake\ntrailing content"
    assert Guard(input_scanners=[SecretScanner(action=Action.REDACT)]).scan(text).text == (
        "prefix [SECRET]"
    )


def test_invisible_warn_preserves_legitimate_joiner():
    text = "👩\u200d💻 and दे\u200dव"
    result = Guard(input_scanners=[InvisibleScanner()]).scan(text)
    assert result.action == Action.WARN
    assert result.text == text
    assert [item.start for item in result.findings] == [1, 10]


def test_controls_removal_is_explicit():
    result = Guard(input_scanners=[InvisibleScanner(action=Action.REDACT)]).scan(
        "a\u200bb\x00c\u202ed\ufeff\n\t\r"
    )
    assert result.text == "abcd\n\t\r"


def test_ordinary_unicode_and_whitespace_unchanged():
    text = "é café नमस्ते 日本語 ☀️\n\t\r"
    assert Guard(input_scanners=[InvisibleScanner()]).scan(text).action == Action.ALLOW


def test_literal_regex_metacharacters_are_literal():
    guard = Guard(input_scanners=[LiteralScanner(["a.*b"])])
    assert guard.scan("axxxb").action == Action.ALLOW
    assert guard.scan("a.*b").action == Action.BLOCK


def test_overlapping_literals_redact_union():
    guard = Guard(input_scanners=[LiteralScanner(["aba", "bab"], action=Action.REDACT)])
    result = guard.scan("x ababa y")
    assert result.text == "x [REDACTED] y"
    assert len(result.findings) == 3


def test_ascii_case_matching_preserves_unicode_offsets():
    guard = Guard(input_scanners=[LiteralScanner(["SECRET"], case_sensitive=False)])
    result = guard.scan("ß secret")
    assert (result.findings[0].start, result.findings[0].end) == (2, 8)
    assert Guard(input_scanners=[LiteralScanner(["i"], case_sensitive=False)]).scan("İı").accepted


@pytest.mark.parametrize("literals", [[], [""], "a", ["x"] * 129, ["x" * 1025]])
def test_invalid_literal_config(literals):
    with pytest.raises(ValueError):
        LiteralScanner(literals)


@pytest.mark.parametrize("constructor", [PIIScanner, SecretScanner, InvisibleScanner])
@pytest.mark.parametrize("action", [Action.ALLOW, Action.ERROR, "redact"])
def test_invalid_detector_action(constructor, action):
    with pytest.raises(ValueError):
        constructor(action=action)


def test_finding_flood_is_explicit_error():
    result = Guard(input_scanners=[InvisibleScanner()]).scan("\x00" * 257)
    assert result.action == Action.ERROR
    assert result.findings[0].code == "finding_limit_exceeded"
