"""Strict JSON and local Draft 2020-12 validation with bounded structural depth."""

from __future__ import annotations

import json
import math
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT202012

from .models import Action, Check, Finding, Stage

Schema = dict[str, Any] | bool
_DIALECT = "https://json-schema.org/draft/2020-12/schema"


class _JSONProblem(ValueError):
    pass


def _constant(_: str) -> Any:
    raise _JSONProblem("json_non_finite")


def _float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise _JSONProblem("json_non_finite")
    return number


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _JSONProblem("json_duplicate_key")
        result[key] = value
    return result


def _check_depth(text: str, limit: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                raise _JSONProblem("json_too_deep")
        elif char in "]}":
            depth -= 1


def strict_loads(text: str, *, max_depth: int = 32) -> Any:
    _check_depth(text, max_depth)
    try:
        return json.loads(
            text, object_pairs_hook=_object, parse_constant=_constant, parse_float=_float
        )
    except _JSONProblem:
        raise
    except (ValueError, RecursionError):
        raise _JSONProblem("json_invalid") from None


def _check_schema_policy(schema: Schema) -> None:
    """Check schema positions AND referenced extension data, without inspecting const data.

    JSON pointers can turn arbitrary extension fields into active schemas. Following
    them prevents hiding a regex/remote reference outside normal schema positions.
    """
    root = DRAFT202012.create_resource(schema)
    registry = Registry().with_resource("urn:guardtrellis:root", root)
    resolver = registry.resolver("urn:guardtrellis:root").in_subresource(root)
    pending: list[tuple[Resource[Any], Any]] = [(root, resolver)]
    visited: set[int] = set()
    while pending:
        resource, current_resolver = pending.pop()
        node = resource.contents
        if id(node) in visited or isinstance(node, bool):
            continue
        visited.add(id(node))
        Draft202012Validator.check_schema(node)
        if node.get("$schema", _DIALECT).rstrip("#") != _DIALECT:
            raise ValueError
        if "pattern" in node or "patternProperties" in node:
            raise ValueError
        for keyword in ("$ref", "$dynamicRef"):
            if keyword not in node:
                continue
            if not node[keyword].startswith("#"):
                raise ValueError
            try:
                resolved = current_resolver.lookup(node[keyword])
            except Unresolvable:
                # A missing target is an explicit runtime ERROR if the branch is used.
                continue
            pending.append((DRAFT202012.create_resource(resolved.contents), resolved.resolver))
        for child in resource.subresources():
            pending.append((child, current_resolver.in_subresource(child)))


class JSONScanner:
    """Validate JSON and an optional, trusted Draft 2020-12 schema.

    References must be document-local fragments. Regex schema keywords are
    rejected to avoid exposing Python's backtracking regex engine to instances.
    Formats remain annotations, per JSON Schema's default behavior.
    """

    name = "json"

    def __init__(
        self,
        schema: Schema | None = None,
        *,
        max_depth: int = 32,
        require_object: bool = False,
    ):
        if type(max_depth) is not int or not 1 <= max_depth <= 64:
            raise ValueError("max_depth must be an integer from 1 to 64")
        self.max_depth = max_depth
        self.require_object = require_object
        self._validator: Draft202012Validator | None = None
        if schema is not None:
            try:
                # Snapshot config so mutation of the caller's schema cannot change a policy.
                if not isinstance(schema, (dict, bool)):
                    raise ValueError
                serialized = json.dumps(schema, allow_nan=False)
                if len(serialized) > 100_000:
                    raise ValueError
                copied = strict_loads(serialized, max_depth=64)
                Draft202012Validator.check_schema(copied)
                _check_schema_policy(copied)
                # Supplying a Registry explicitly prevents legacy automatic URL retrieval.
                self._validator = Draft202012Validator(copied, registry=Registry())
            except (ValueError, TypeError, RecursionError, SchemaError):
                raise ValueError(
                    "Schema must be bounded Draft 2020-12 with local references "
                    "and no regex keywords"
                ) from None

    def scan(self, text: str, *, stage: Stage) -> Check:
        try:
            instance = strict_loads(text, max_depth=self.max_depth)
        except _JSONProblem as problem:
            return Check(Action.BLOCK, (Finding(str(problem)),))
        if self.require_object and not isinstance(instance, dict):
            return Check(Action.BLOCK, (Finding("json_object_required"),))
        if self._validator is not None:
            # Consume one error only; do not retain ValidationError (it holds the instance).
            # Resolution/runtime errors propagate into Guard's explicit ERROR result.
            error = next(self._validator.iter_errors(instance), None)
            if error is not None:
                return Check(Action.BLOCK, (Finding("json_schema_mismatch"),))
        return Check()
