"""Frozen fixture projections and desired outcomes; stdlib only, no SDK imports/scans."""

from __future__ import annotations

import json

VERSION = "detector-delivery-v1"
FAMILIES = ("email", "phone", "connection_uri")
PROFILES = ("default", "opt_in")
REPRESENTATIONS = ("plain", "json_literal", "json_escaped", "decoded")
MAX_INPUT_CHARS = 2_000
PRIMARY_CODES = {
    "email": {"pii_email"},
    "phone": {"pii_phone"},
    "connection_uri": {"secret_postgresql_uri", "secret_mongodb_uri"},
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("Non-finite value")


def strict_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def valid_text(value):
    return (
        type(value) is str
        and 0 < len(value) <= MAX_INPUT_CHARS
        and not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    )


def escaped_character(char):
    encoded = char.encode("utf-16-be")
    return "".join(r"\u" + encoded[index : index + 2].hex() for index in range(0, len(encoded), 2))


def wire(text, escaped=False):
    content = (
        "".join(map(escaped_character, text))
        if escaped
        else json.dumps(text, ensure_ascii=True)[1:-1]
    )
    return '{"value":"' + content + '"}'


def decode_value(serialized):
    if not valid_text(serialized):
        raise ValueError("Invalid fixed-field input")
    value = strict_json(serialized)
    if type(value) is not dict or value.keys() != {"value"} or not valid_text(value["value"]):
        raise ValueError("Invalid fixed-field value")
    return value["value"]


def represented(case, representation, spans):
    if representation not in REPRESENTATIONS:
        raise ValueError("Invalid representation")
    text = case["text"]
    if representation in ("plain", "decoded"):
        if representation == "decoded":
            # Both encodings must decode identically; only one SDK observation is counted.
            left, right = decode_value(wire(text)), decode_value(wire(text, True))
            if left != right or left != text:
                raise ValueError("Unequal decoded values")
            text = left
        return text, spans
    escaped = representation == "json_escaped"
    offsets = [len('{"value":"')]
    for char in text:
        offsets.append(
            offsets[-1]
            + len(escaped_character(char) if escaped else json.dumps(char, ensure_ascii=True)[1:-1])
        )
    return wire(text, escaped), [[offsets[a], offsets[b]] for a, b in spans]


def desired(case, representation):
    text, spans = represented(case, representation, case["targets"])
    if case["label"] == "benign":
        return {"action": "allow", "text": text, "spans": []}
    if case["family"] == "connection_uri":
        return {"action": "block", "text": None, "spans": spans}
    for start, end in reversed(spans):
        text = text[:start] + "[PII]" + text[end:]
    return {"action": "redact", "text": text, "spans": spans}


def expectation(case, profile, representation):
    if profile not in PROFILES:
        raise ValueError("Invalid profile")
    contract = case["contracts"][profile]
    if representation == "json_escaped":
        scope, spans, action = "raw_escaped_control", [], "allow"
        codes = []
    else:
        scope, action = contract["scope"], contract["action"]
        codes = contract["codes"]
        spans = (
            None
            if contract["spans"] is None
            else represented(case, representation, contract["spans"])[1]
        )
    return {
        "id": case["id"],
        "profile": profile,
        "representation": representation,
        "desired": desired(case, representation),
        "contract": {
            "scope": scope,
            "spans": spans,
            "action": action,
            "codes": codes,
            "eligible": spans is not None,
        },
    }
