"""Small, deterministic format detectors. These are not semantic safety classifiers."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence

from .guard import MAX_FINDINGS
from .models import Action, Check, Edit, Finding, Stage


def _validate_action(action: Action) -> None:
    if not isinstance(action, Action) or action not in (Action.WARN, Action.REDACT, Action.BLOCK):
        raise ValueError("Detector action must be WARN, REDACT, or BLOCK")


def _decision(findings: Iterable[Finding], action: Action, replacement: str) -> Check:
    collected = []
    for finding in findings:
        collected.append(finding)
        if len(collected) > MAX_FINDINGS:
            return Check(Action.ERROR, (Finding("finding_limit_exceeded"),))
    if not collected:
        return Check()
    ordered = tuple(sorted(collected, key=lambda item: (item.start or 0, item.end or 0, item.code)))
    edits: list[Edit] = []
    if action == Action.REDACT:
        for item in ordered:
            assert item.start is not None and item.end is not None
            if edits and item.start < edits[-1].end:
                previous = edits.pop()
                edits.append(Edit(previous.start, max(previous.end, item.end), replacement))
            else:
                edits.append(Edit(item.start, item.end, replacement))
    return Check(action, ordered, tuple(edits))


class PIIScanner:
    """ASCII email, contiguous international +phone (8-15 digits), US SSN shapes.

    This does not identify people, validate issuance, or cover all PII formats.
    """

    name = "pii"
    _patterns = {
        "email": re.compile(
            r"(?<![\w.!#$%&'*+/=?^`{|}~@-])"
            r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{0,63}"
            r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}"
            r"[A-Za-z]{2,63}(?![\w@-])"
        ),
        "phone": re.compile(r"(?<![\w+])\+[1-9][0-9]{7,14}(?!\w)"),
        "ssn": re.compile(
            r"(?<!\w)(?!000|666|9[0-9]{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?!\w)"
        ),
    }

    def __init__(
        self,
        *,
        formats: Sequence[str] = ("email", "phone", "ssn"),
        action: Action = Action.REDACT,
    ):
        _validate_action(action)
        if not formats or any(name not in self._patterns for name in formats):
            raise ValueError("Unsupported or empty PII format selection")
        self._formats = tuple(dict.fromkeys(formats))
        self.action = action

    def scan(self, text: str, *, stage: Stage) -> Check:
        findings = (
            Finding(f"pii_{name}", match.start(), match.end())
            for name in self._formats
            for match in self._patterns[name].finditer(text)
        )
        return _decision(findings, self.action, "[PII]")


class SecretScanner:
    """Selected token signatures and private-key envelopes, not credential verification."""

    name = "secrets"
    _patterns = {
        "github_classic": re.compile(r"(?<!\w)gh[pousr]_[A-Za-z0-9]{36}(?!\w)"),
        "github_fine_grained": re.compile(r"(?<!\w)github_pat_[A-Za-z0-9_]{82}(?!\w)"),
        "aws_access_key_id": re.compile(r"(?<!\w)(?:AKIA|ASIA)[A-Z0-9]{16}(?!\w)"),
    }
    _pem = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----")

    def __init__(self, *, action: Action = Action.BLOCK):
        _validate_action(action)
        self.action = action

    def _find(self, text: str) -> Iterable[Finding]:
        for name, pattern in self._patterns.items():
            for match in pattern.finditer(text):
                yield Finding(f"secret_{name}", match.start(), match.end())
        for match in self._pem.finditer(text):
            footer = f"-----END {match.group(1)}-----"
            end = text.find(footer, match.end())
            # An incomplete envelope is conservatively covered through end of input.
            yield Finding(
                "secret_private_key", match.start(), len(text) if end < 0 else end + len(footer)
            )

    def scan(self, text: str, *, stage: Stage) -> Check:
        return _decision(self._find(text), self.action, "[SECRET]")


class InvisibleScanner:
    """Flag Unicode Cc/Cf except tab, CR, and LF; warning is the non-destructive default."""

    name = "invisible"

    def __init__(self, *, action: Action = Action.WARN):
        _validate_action(action)
        self.action = action

    def scan(self, text: str, *, stage: Stage) -> Check:
        findings = (
            Finding("invisible_control", index, index + 1)
            for index, char in enumerate(text)
            if char not in "\t\r\n" and unicodedata.category(char) in ("Cc", "Cf")
        )
        return _decision(findings, self.action, "")


class LiteralScanner:
    """Substring policies with exact or ASCII-insensitive matching; no arbitrary regex."""

    name = "literal"
    _lower = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

    def __init__(
        self,
        literals: Sequence[str],
        *,
        action: Action = Action.BLOCK,
        case_sensitive: bool = True,
    ):
        _validate_action(action)
        if isinstance(literals, str) or not 1 <= len(literals) <= 128:
            raise ValueError("Supply between 1 and 128 literal strings")
        if any(not isinstance(item, str) or not 1 <= len(item) <= 1024 for item in literals):
            raise ValueError("Each literal must contain between 1 and 1024 characters")
        self._literals = tuple(dict.fromkeys(literals))
        self.action = action
        self.case_sensitive = case_sensitive

    def _find(self, text: str) -> Iterable[Finding]:
        haystack = text if self.case_sensitive else text.translate(self._lower)
        for literal in self._literals:
            needle = literal if self.case_sensitive else literal.translate(self._lower)
            start = haystack.find(needle)
            while start >= 0:
                yield Finding("literal_match", start, start + len(literal))
                start = haystack.find(needle, start + 1)

    def scan(self, text: str, *, stage: Stage) -> Check:
        return _decision(self._find(text), self.action, "[REDACTED]")
