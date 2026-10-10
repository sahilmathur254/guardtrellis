import asyncio
import json
import threading
from unittest.mock import Mock

import pytest

from guardtrellis import (
    Action,
    Check,
    Finding,
    LiteralScanner,
    PIIScanner,
    Rejected,
    Stage,
    ToolGuard,
)

SCHEMA = {
    "type": "object",
    "properties": {"query": {"type": "string", "minLength": 1}},
    "required": ["query"],
    "additionalProperties": False,
}
CANARY = "async.canary@example.org"
ARGUMENTS = json.dumps({"query": CANARY})


def assert_private(result):
    assert CANARY not in repr(result) + repr(result.validation)
    assert CANARY not in json.dumps(result.diagnostics())


def assert_withheld(result, action, code):
    assert result.action == action
    assert not result.accepted
    assert result.validation.stage == Stage.TOOL
    assert result.validation.text is result.name is result.arguments is None
    assert code in {finding.code for finding in result.validation.findings}
    dispatch = Mock()
    with pytest.raises(Rejected) as error:
        dispatch(*result.require_call())
    dispatch.assert_not_called()
    assert CANARY not in str(error.value)
    assert_private(result)


async def test_async_tool_dispatch_uses_checked_redacted_pair():
    guard = ToolGuard({"search": SCHEMA}, argument_scanners=[PIIScanner()])
    result = await guard.avalidate("search", ARGUMENTS)
    dispatch = Mock()
    dispatch(*result.require_call())
    dispatch.assert_called_once_with("search", {"query": "[PII]"})
    assert result.action == Action.REDACT
    assert result.validation.stage == Stage.TOOL
    assert_private(result)


async def test_async_tool_rechecks_schema_after_redaction():
    guard = ToolGuard(
        {"search": SCHEMA},
        argument_scanners=[LiteralScanner(["query"], action=Action.REDACT)],
    )
    result = await guard.avalidate("search", ARGUMENTS)
    assert_withheld(result, Action.BLOCK, "json_schema_mismatch")


async def test_async_tool_policy_rejection_withholds_call():
    guard = ToolGuard({"search": SCHEMA}, argument_scanners=[LiteralScanner([CANARY])])
    result = await guard.avalidate("search", ARGUMENTS)
    assert_withheld(result, Action.BLOCK, "literal_match")


@pytest.mark.parametrize(
    "decision",
    [
        None,
        Check("allow"),
        Check(Action.ALLOW, (Finding("unexpected_finding"),)),
        Check(Action.REDACT, (Finding("missing_edit"),)),
        Check(Action.WARN, (Finding(CANARY),)),
    ],
)
async def test_async_tool_malformed_check_withholds_call(decision):
    class Malformed:
        name = "malformed"

        async def scan(self, text, *, stage):
            assert stage == Stage.TOOL
            return decision

    result = await ToolGuard({"search": SCHEMA}, argument_scanners=[Malformed()]).avalidate(
        "search", ARGUMENTS
    )
    assert_withheld(result, Action.ERROR, "scanner_error")


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_async_tool_scanner_exception_withholds_call(kind, caplog, capsys):
    class Failing:
        name = "failing"

        def scan(self, text, *, stage):
            raise RuntimeError(text)

    class AsyncFailing:
        name = "async_failing"

        async def scan(self, text, *, stage):
            raise RuntimeError(text)

    scanner = Failing() if kind == "sync" else AsyncFailing()
    result = await ToolGuard({"search": SCHEMA}, argument_scanners=[scanner]).avalidate(
        "search", ARGUMENTS
    )
    assert_withheld(result, Action.ERROR, "scanner_error")
    assert caplog.text == ""
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def controlled_scanner(kind):
    """Let a worker return ALLOW after its caller has stopped waiting."""
    loop = asyncio.get_running_loop()
    started = asyncio.Event()
    finished = asyncio.Event()
    release = threading.Event() if kind == "sync" else asyncio.Event()

    class Worker:
        name = "worker"

        def scan(self, text, *, stage):
            assert stage == Stage.TOOL
            loop.call_soon_threadsafe(started.set)
            try:
                assert release.wait(5), "Worker was not released during cleanup"
                return Check()
            finally:
                loop.call_soon_threadsafe(finished.set)

    class AsyncWorker:
        name = "async_worker"

        async def scan(self, text, *, stage):
            assert stage == Stage.TOOL
            started.set()
            try:
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    # Deliberately suppress cancellation to exercise late success.
                    await release.wait()
                return Check()
            finally:
                finished.set()

    return (Worker() if kind == "sync" else AsyncWorker()), started, release, finished


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_async_tool_timeout_cannot_release_late_call(kind, monkeypatch):
    scanner, started, release, finished = controlled_scanner(kind)
    wait = asyncio.wait
    waits = 0

    async def expire_argument_scanner(tasks, *, timeout):  # noqa: ASYNC109
        nonlocal waits
        waits += 1
        # Syntax validation is first; force only the argument scanner's deadline.
        if waits == 2:
            await asyncio.wait_for(started.wait(), 5)
            return await wait(tasks, timeout=0)
        return await wait(tasks, timeout=timeout)

    monkeypatch.setattr(asyncio, "wait", expire_argument_scanner)
    guard = ToolGuard({"search": SCHEMA}, argument_scanners=[scanner])
    try:
        result = await guard.avalidate("search", ARGUMENTS)
        assert_withheld(result, Action.ERROR, "scanner_timeout")
        assert not finished.is_set()
    finally:
        release.set()
        await asyncio.wait_for(finished.wait(), 5)
    # Finishing with ALLOW cannot revise the already rejected result or dispatch.
    assert_withheld(result, Action.ERROR, "scanner_timeout")
    assert waits == 2


@pytest.mark.parametrize("kind", ["sync", "async"])
async def test_async_tool_caller_cancellation_prevents_dispatch(kind):
    scanner, started, release, finished = controlled_scanner(kind)
    guard = ToolGuard({"search": SCHEMA}, argument_scanners=[scanner])
    dispatch = Mock()

    async def validate_and_dispatch():
        result = await guard.avalidate("search", ARGUMENTS)
        dispatch(*result.require_call())

    task = asyncio.create_task(validate_and_dispatch())
    try:
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled()
        dispatch.assert_not_called()
        assert not finished.is_set()
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.wait_for(finished.wait(), 5)
    dispatch.assert_not_called()
