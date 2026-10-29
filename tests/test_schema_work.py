"""Schema traversal must terminate inside the scanner, including annotation walks."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest

from guardtrellis import Action, Guard, JSONScanner, Stage, ToolGuard, json_check


def fanout(levels=20, *, keyword="$ref", dialect=False, leaf=None):
    definitions = {"n0": {"type": "integer"} if leaf is None else leaf}
    for i in range(1, levels + 1):
        definitions[f"n{i}"] = {
            "allOf": [{keyword: f"#/$defs/n{i - 1}"} for _ in range(2)],
        }
        if dialect:
            definitions[f"n{i}"]["$schema"] = json_check._DIALECT
    return {"$defs": definitions, keyword: f"#/$defs/n{levels}"}


@pytest.mark.parametrize("keyword", ["$ref", "$dynamicRef"])
@pytest.mark.parametrize("dialect", [False, True])
def test_reference_fanout_stops_at_work_budget(monkeypatch, keyword, dialect):
    scanner = JSONScanner(fanout(keyword=keyword, dialect=dialect))
    calls = 0
    charge = json_check._charge_schema_work

    def counted():
        nonlocal calls
        calls += 1
        charge()

    monkeypatch.setattr(json_check, "_charge_schema_work", counted)
    result = Guard(input_scanners=[scanner]).scan("0")
    assert result.action == Action.ERROR
    assert result.text is None
    assert result.findings[0].code == "json_schema_work_limit"
    assert calls == json_check._SCHEMA_WORK_LIMIT + 1
    assert json_check._schema_work.get() is None


def test_unevaluated_properties_reference_walk_is_budgeted():
    definitions = {"n0": {}}
    for i in range(1, 21):
        definitions[f"n{i}"] = {
            "dependentSchemas": {name: {"$ref": f"#/$defs/n{i - 1}"} for name in ("a", "b")}
        }
    # This keyword runs its annotation helper before normal reference validation.
    schema = {"unevaluatedProperties": False, "$ref": "#/$defs/n20", "$defs": definitions}
    result = Guard(input_scanners=[JSONScanner(schema)]).scan('{"a":0,"b":0}')
    assert result.action == Action.ERROR
    assert result.findings[0].code == "json_schema_work_limit"
    assert result.text is None


def test_unevaluated_items_reference_walk_is_budgeted():
    graph = fanout(keyword="$dynamicRef", leaf={})
    schema = {"unevaluatedItems": False, **graph}
    result = Guard(input_scanners=[JSONScanner(schema)]).scan("[0]")
    assert result.action == Action.ERROR
    assert result.findings[0].code == "json_schema_work_limit"


def test_budget_resets_after_exhaustion_and_preserves_local_reference_semantics():
    schema = {"if": {"type": "integer"}, "then": fanout(), "else": {"type": "string"}}
    guard = Guard(input_scanners=[JSONScanner(schema)])
    assert guard.scan("0").action == Action.ERROR
    assert guard.scan('"ok"').accepted
    assert guard.scan("null").action == Action.BLOCK
    ordinary = Guard(input_scanners=[JSONScanner(fanout(3, dialect=True))])
    assert ordinary.scan("0").accepted
    assert ordinary.scan('"wrong"').action == Action.BLOCK


def test_budget_is_independent_for_concurrent_calls_to_same_scanner():
    scanner = JSONScanner(fanout(10, dialect=True))
    barrier = Barrier(4)

    def run(_):
        barrier.wait(timeout=10)
        return scanner.scan("0", stage=Stage.INPUT).action

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(run, range(4))) == [Action.ALLOW] * 4


@pytest.mark.asyncio
async def test_async_budget_exhaustion_finishes_worker_before_returning(monkeypatch):
    scanner = JSONScanner(fanout())
    finished = Event()
    original = scanner.scan

    def tracked(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(scanner, "scan", tracked)
    guard = Guard(input_scanners=[scanner], timeout_seconds=10)
    result = await asyncio.wait_for(guard.ascan("0"), timeout=15)
    assert result.action == Action.ERROR
    assert result.findings[0].code == "json_schema_work_limit"
    assert finished.is_set()


@pytest.mark.asyncio
async def test_tool_paths_withhold_arguments_on_budget_exhaustion():
    tools = ToolGuard({"lookup": fanout(leaf={"type": "object"})}, timeout_seconds=10)
    for result in (tools.validate("lookup", "{}"), await tools.avalidate("lookup", "{}")):
        assert result.action == Action.ERROR
        assert result.name is None
        assert result.arguments is None
        assert result.validation.findings[0].code == "json_schema_work_limit"
        assert "{}" not in json.dumps(result.diagnostics())
