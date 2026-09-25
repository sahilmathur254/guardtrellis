import json
import socket

import pytest

from guardtrellis import (
    Action,
    Guard,
    JSONScanner,
    LiteralScanner,
    PIIScanner,
    Rejected,
    Stage,
    ToolGuard,
)


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ('{"a":1,"a":2}', "json_duplicate_key"),
        ('{"a":1,"\\u0061":2}', "json_duplicate_key"),
        ('{"nested":{"a":1,"a":2}}', "json_duplicate_key"),
        ('{"value":NaN}', "json_non_finite"),
        ('{"value":Infinity}', "json_non_finite"),
        ("-Infinity", "json_non_finite"),
        ("1e9999", "json_non_finite"),
        ("{not json}", "json_invalid"),
        ('{"x":1,}', "json_invalid"),
        ("{} trailing", "json_invalid"),
        ("01", "json_invalid"),
        ('{"x":"\x00"}', "json_invalid"),
        ("[" * 33 + "0" + "]" * 33, "json_too_deep"),
    ],
)
def test_strict_json_rejections(text, code):
    result = Guard(input_scanners=[JSONScanner()]).scan(text)
    assert result.action == Action.BLOCK
    assert result.findings[0].code == code
    assert result.text is None


@pytest.mark.parametrize("value", [None, True, 12, 1.5, "hello", [], {}, {"brackets": "[{}]"}])
def test_all_json_top_level_values_supported_by_default(value):
    text = json.dumps(value)
    assert Guard(input_scanners=[JSONScanner()]).scan(text).require_text() == text


def test_depth_counts_containers_not_escaped_quotes_and_brackets():
    text = json.dumps({"quoted": '\\"[[[{{{'})
    assert Guard(input_scanners=[JSONScanner(max_depth=1)]).scan(text).accepted
    assert Guard(input_scanners=[JSONScanner(max_depth=1)]).scan('{"x":[]}').action == Action.BLOCK


SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "$defs": {"count": {"type": "integer", "minimum": 1, "maximum": 5}},
    "properties": {
        "count": {"$ref": "#/$defs/count"},
        "kind": {"enum": ["short", "long"]},
        "tags": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
    },
    "required": ["count", "kind"],
    "additionalProperties": False,
}


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"count": 0, "kind": "short"},
        {"count": True, "kind": "short"},
        {"count": 6, "kind": "short"},
        {"count": 1, "kind": "other"},
        {"count": 1, "kind": "short", "extra": 2},
        {"count": 1, "kind": "long", "tags": ["x", "x"]},
    ],
)
def test_schema_constraints(value):
    result = Guard(output_scanners=[JSONScanner(SCHEMA)]).scan(
        json.dumps(value), stage=Stage.OUTPUT
    )
    assert result.action == Action.BLOCK
    assert result.findings[0].code == "json_schema_mismatch"


def test_local_references_work_without_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Network resolution must not run")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    assert Guard(input_scanners=[JSONScanner(SCHEMA)]).scan('{"count":2,"kind":"short"}').accepted


@pytest.mark.parametrize(
    "schema",
    [
        {"$ref": "https://example.org/schema"},
        {"$ref": "file:///etc/passwd"},
        {"$dynamicRef": "other.json#anchor"},
        {"$defs": {"unused": {"$ref": "https://example.org"}}},
        {"properties": {"x": {"$schema": "http://json-schema.org/draft-07/schema#"}}},
        {"$schema": "http://json-schema.org/draft-07/schema#"},
        {"type": "invalid"},
        {"pattern": "(a+)+$"},
        {"patternProperties": {"a": {"type": "string"}}},
        {"properties": {"x": {"pattern": "safe"}}},
        {"maximum": float("inf")},
    ],
)
def test_invalid_or_unsafe_schema_configuration_is_rejected(schema):
    with pytest.raises(ValueError, match="bounded Draft"):
        JSONScanner(schema)


def test_const_data_is_not_mistaken_for_schema_keywords():
    schema = {"const": {"$ref": "https://example.org", "pattern": "literal data"}}
    assert Guard(input_scanners=[JSONScanner(schema)]).scan(json.dumps(schema["const"])).accepted


@pytest.mark.parametrize(
    "target",
    [{"pattern": "(a+)+$"}, {"$ref": "https://example.org/schema"}],
)
def test_reference_cannot_hide_restricted_schema_in_extension_data(target):
    with pytest.raises(ValueError):
        JSONScanner({"$ref": "#/extension", "extension": target})
    with pytest.raises(ValueError):
        JSONScanner({"$ref": "#/const", "const": target})


def test_reference_to_safe_extension_schema():
    scanner = JSONScanner({"$ref": "#/extension", "extension": {"type": "integer"}})
    guard = Guard(input_scanners=[scanner])
    assert guard.scan("1").accepted
    assert guard.scan('"text"').action == Action.BLOCK


def test_local_anchor_and_root_identifier():
    scanner = JSONScanner(
        {
            "$id": "https://example.org/local-root",
            "$defs": {"thing": {"$anchor": "item", "type": "integer"}},
            "$ref": "#item",
        }
    )
    assert Guard(input_scanners=[scanner]).scan("1").accepted


def test_unresolved_reference_is_error_not_validation_success():
    result = Guard(input_scanners=[JSONScanner({"$ref": "#/$defs/missing"})]).scan("1")
    assert result.action == Action.ERROR
    assert result.text is None


def test_recursive_schema_failure_is_explicit():
    result = Guard(input_scanners=[JSONScanner({"$ref": "#"})]).scan("1")
    assert result.action == Action.ERROR


def test_schema_is_snapshotted():
    schema = {"type": "integer", "minimum": 3}
    scanner = JSONScanner(schema)
    schema["minimum"] = 0
    assert Guard(input_scanners=[scanner]).scan("1").action == Action.BLOCK


def test_format_is_an_annotation_not_an_enforced_validator():
    result = Guard(input_scanners=[JSONScanner({"type": "string", "format": "email"})]).scan(
        '"not an email"'
    )
    assert result.accepted


@pytest.mark.parametrize("schema,action", [(True, Action.ALLOW), (False, Action.BLOCK)])
def test_boolean_schema(schema, action):
    assert Guard(input_scanners=[JSONScanner(schema)]).scan("1").action == action


def test_draft_202012_features():
    schema = {
        "type": "array",
        "prefixItems": [{"type": "integer"}, {"const": "x"}],
        "items": False,
        "minItems": 2,
    }
    guard = Guard(input_scanners=[JSONScanner(schema)])
    assert guard.scan('[1,"x"]').accepted
    assert not guard.scan('[1,"x",3]').accepted


TOOL_SCHEMA = {
    "type": "object",
    "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 80}},
    "required": ["query"],
    "additionalProperties": False,
}


def test_tool_exact_allowlist_and_schema():
    guard = ToolGuard({"search": TOOL_SCHEMA})
    result = guard.validate("search", '{"query":"safe"}')
    assert result.require_call() == ("search", {"query": "safe"})
    for name in ["SEARCH", "delete", " search", "search ", ""]:
        result = guard.validate(name, '{"query":"safe"}')
        assert result.action == Action.BLOCK
        assert result.name is result.arguments is None
        with pytest.raises(Rejected):
            result.require_call()


@pytest.mark.parametrize("arguments", ["[]", "null", "{}", '{"query": 2}', '{"query":"a","x":1}'])
def test_tool_rejects_invalid_arguments(arguments):
    result = ToolGuard({"search": TOOL_SCHEMA}).validate("search", arguments)
    assert result.action == Action.BLOCK
    assert result.arguments is None


def test_tool_redacts_then_checks_final_schema():
    guard = ToolGuard({"search": TOOL_SCHEMA}, argument_scanners=[PIIScanner()])
    result = guard.validate("search", '{"query":"person@example.org"}')
    assert result.require_call() == ("search", {"query": "[PII]"})
    assert "person@example.org" not in repr(result) + json.dumps(result.diagnostics())
    assert result.action == Action.REDACT


def test_tool_redaction_cannot_bypass_schema():
    # A policy redacts the only allowed property name; final validation must catch it.
    guard = ToolGuard(
        {"search": TOOL_SCHEMA},
        argument_scanners=[LiteralScanner(["query"], action=Action.REDACT)],
    )
    assert guard.validate("search", '{"query":"hello"}').action == Action.BLOCK


def test_tool_duplicate_key_is_checked_before_redaction():
    guard = ToolGuard({"search": TOOL_SCHEMA}, argument_scanners=[PIIScanner()])
    result = guard.validate("search", '{"query":"one","query":"two"}')
    assert result.validation.findings[0].code == "json_duplicate_key"


async def test_async_tool_validation():
    guard = ToolGuard({"search": TOOL_SCHEMA})
    assert (await guard.avalidate("search", '{"query":"safe"}')).accepted
    assert (await guard.avalidate("other", "{}")).action == Action.BLOCK
