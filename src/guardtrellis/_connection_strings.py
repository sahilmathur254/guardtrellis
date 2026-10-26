"""Bounded disclosure detection for selected connection URIs, without URL decoding."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .models import Finding

# Private processing budgets, independent of a caller's Guard configuration.
MAX_TEXT_CHARS = 100_000
MAX_CANDIDATE_CHARS = 8_192
MAX_CANDIDATES = 256

_START = re.compile(
    r"(?<![A-Za-z0-9_+.\-])(?:postgresql|postgres|mongodb(?:\+srv)?)://",
    re.IGNORECASE | re.ASCII,
)
_HEX = frozenset("0123456789abcdefABCDEF")


class ConnectionStringLimitError(Exception):
    """Internal control flow; never includes input or component text."""


def _candidate_end(text: str, start: int, cursor: int, wrapper: str | None) -> int:
    outer_angle = start > 0 and text[start - 1] == "<"
    inner_angles = 0
    while cursor < len(text):
        char = text[cursor]
        if char.isspace() or char == wrapper:
            break
        if char == ">" and outer_angle and inner_angles == 0:
            break
        if cursor - start >= MAX_CANDIDATE_CHARS:
            raise ConnectionStringLimitError
        if char == "<":
            inner_angles += 1
        elif char == ">" and inner_angles:
            inner_angles -= 1
        cursor += 1
    return cursor


def _password_key(text: str, start: int, end: int) -> bool:
    # Only eight ASCII characters can match; no value or whole-URI decoding.
    for expected in "password":
        if start >= end:
            return False
        char = text[start]
        if char == "%":
            if start + 2 >= end or any(c not in _HEX for c in text[start + 1 : start + 3]):
                return False
            char = chr(int(text[start + 1 : start + 3], 16))
            start += 3
        else:
            start += 1
        if char not in (expected, expected.upper()):
            return False
    return start == end


def _has_password(text: str, start: int, end: int, *, postgresql: bool) -> bool:
    authority_end = end
    for separator in ("/", "?"):
        position = text.find(separator, start, end)
        if position != -1:
            authority_end = min(authority_end, position)
    colon = text.find(":", start, authority_end)
    at = text.rfind("@", start, authority_end)
    if colon != -1 and colon + 1 < at:
        return True
    if not postgresql:
        return False
    query = text.find("?", start, end)
    if query == -1:
        return False
    cursor = query + 1
    while cursor < end:
        pair_end = text.find("&", cursor, end)
        if pair_end == -1:
            pair_end = end
        equals = text.find("=", cursor, pair_end)
        if equals != -1 and equals + 1 < pair_end and _password_key(text, cursor, equals):
            return True
        cursor = pair_end + 1
    return False


def find_connection_strings(text: str) -> Iterator[Finding]:
    if len(text) > MAX_TEXT_CHARS:
        raise ConnectionStringLimitError
    cursor, attempts = 0, 0
    wrapper = None
    while match := _START.search(text, cursor):
        attempts += 1
        if attempts > MAX_CANDIDATES:
            raise ConnectionStringLimitError
        start = match.start()
        # Track lexical prose/string wrappers, without interpreting escapes or JSON.
        # Only the matching outer quote ends the candidate; other quotes are opaque.
        for position in range(cursor, start):
            char = text[position]
            if char == wrapper:
                wrapper = None
            elif wrapper is None and char in '"`':
                wrapper = char
        # An immediately enclosing wrapper can sit inside a larger quoted string.
        candidate_wrapper = text[start - 1] if start and text[start - 1] in '"`' else wrapper
        end = _candidate_end(text, start, match.end(), candidate_wrapper)
        postgresql = text[start] in "pP"
        if _has_password(text, match.end(), end, postgresql=postgresql):
            code = "secret_postgresql_uri" if postgresql else "secret_mongodb_uri"
            yield Finding(code, start, end)
        # Never search a candidate's suffix again, including nested scheme spellings.
        cursor = end
