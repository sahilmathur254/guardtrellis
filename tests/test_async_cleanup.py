import asyncio
import gc
import threading

import pytest

import guardtrellis.guard as guard_module
from guardtrellis import Action, Guard, Stage


@pytest.mark.parametrize("entrypoint", ["scanner", "callback"])
async def test_completed_failure_is_drained_on_caller_cancellation(monkeypatch, entrypoint):
    loop = asyncio.get_running_loop()
    diagnostics = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: diagnostics.append(context))
    original_wait = asyncio.wait

    async def cancel_after_completion(tasks, *, timeout):  # noqa: ASYNC109
        done, pending = await original_wait(tasks, timeout=timeout)
        assert done and not pending
        # Reproduce cancellation before _bounded can retrieve the completed result.
        asyncio.current_task().cancel()
        await asyncio.sleep(0)
        return done, pending

    monkeypatch.setattr(asyncio, "wait", cancel_after_completion)

    class FailingScanner:
        name = "failing"

        async def scan(self, text, *, stage):
            raise RuntimeError(text)

    async def failing_callback(text):
        raise RuntimeError(text)

    async def run():
        if entrypoint == "scanner":
            await Guard(input_scanners=[FailingScanner()]).ascan("synthetic-canary")
        else:
            await Guard().arun("synthetic-canary", failing_callback)

    try:
        task = asyncio.create_task(run())
        with pytest.raises(asyncio.CancelledError):
            await task
        del task
        # Run cleanup callbacks and release the failed child and its traceback.
        await asyncio.sleep(0)
        gc.collect()
        assert diagnostics == []
    finally:
        loop.set_exception_handler(previous_handler)


@pytest.mark.parametrize("kind", ["failed_future", "cancellation_resistant_task"])
async def test_late_worker_future_is_drained_after_timeout(monkeypatch, kind):
    loop = asyncio.get_running_loop()
    diagnostics = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: diagnostics.append(context))
    started = asyncio.Event()
    release = threading.Event()
    disposed = asyncio.Event()
    retrieved = asyncio.Event()
    original_discard = guard_module._discard_worker_result

    class ObservedFuture(asyncio.Future):
        def exception(self):
            retrieved.set()
            return super().exception()

    async def late_failure():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise RuntimeError("synthetic-canary") from None

    if kind == "failed_future":
        nested = ObservedFuture()
        nested.set_exception(RuntimeError("synthetic-canary"))
    else:
        nested = asyncio.create_task(late_failure())
        await asyncio.sleep(0)

    def factory(_):
        loop.call_soon_threadsafe(started.set)
        assert release.wait(5), "Worker was not released"
        return nested

    def record_disposal(future):
        original_discard(future)
        disposed.set()

    original_wait = asyncio.wait

    async def expire_after_start(tasks, *, timeout):  # noqa: ASYNC109
        await asyncio.wait_for(started.wait(), 5)
        return await original_wait(tasks, timeout=0)

    monkeypatch.setattr(guard_module, "_discard_worker_result", record_disposal)
    monkeypatch.setattr(asyncio, "wait", expire_after_start)
    try:
        result = await Guard(timeout_seconds=0.03).arun("synthetic-canary", factory)
        assert result.action == Action.ERROR
        assert result.output_result.findings[0].code == "callback_timeout"
        assert "synthetic-canary" not in repr(result)
        release.set()
        await asyncio.wait_for(disposed.wait(), 5)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        if kind == "failed_future":
            assert retrieved.is_set()
        nested = None
        gc.collect()
        assert diagnostics == []
    finally:
        release.set()
        loop.set_exception_handler(previous_handler)


@pytest.mark.parametrize("failed", [False, True], ids=["successful", "failed"])
async def test_late_completed_future_from_closed_loop_is_drained(monkeypatch, failed):
    loop = asyncio.get_running_loop()
    diagnostics = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _, context: diagnostics.append(context))
    foreign = asyncio.new_event_loop()
    nested = foreign.create_future()
    if failed:
        nested.set_exception(RuntimeError("synthetic-canary"))
    else:
        nested.set_result("synthetic-canary")
    foreign.close()
    started = asyncio.Event()
    release = threading.Event()
    disposed = asyncio.Event()
    original_discard = guard_module._discard_worker_result

    def observe_disposal(future):
        try:
            original_discard(future)
        finally:
            disposed.set()

    monkeypatch.setattr(guard_module, "_discard_worker_result", observe_disposal)

    def factory(_):
        loop.call_soon_threadsafe(started.set)
        assert release.wait(5), "Worker was not released"
        return nested

    try:
        pending = asyncio.create_task(Guard(timeout_seconds=0.05).arun("input", factory))
        await asyncio.wait_for(started.wait(), 5)
        result = await pending
        assert result.action == Action.ERROR
        assert result.output_result.findings[0].code == "callback_timeout"
        release.set()
        await asyncio.wait_for(disposed.wait(), 5)
        await asyncio.sleep(0)
        assert diagnostics == []
        if failed:
            # A drained failure no longer has an unretrieved exception to report.
            assert not nested._log_traceback
    finally:
        release.set()
        loop.set_exception_handler(previous_handler)


async def test_completed_foreign_loop_future_is_still_delivered():
    foreign = asyncio.new_event_loop()
    future = foreign.create_future()
    future.set_result("checked output")
    foreign.close()
    result = await Guard().arun("input", lambda _: future)
    assert result.require_text() == "checked output"


async def test_ordinary_async_failures_remain_sanitized():
    class FailingScanner:
        name = "failing"

        async def scan(self, text, *, stage):
            raise RuntimeError(text)

    scanner_result = await Guard(tool_scanners=[FailingScanner()]).ascan(
        "synthetic-canary", stage=Stage.TOOL
    )
    assert scanner_result.findings[0].code == "scanner_error"

    async def callback(text):
        raise RuntimeError(text)

    result = await Guard().arun("synthetic-canary", callback)
    assert result.output_result.findings[0].code == "callback_error"
    assert "synthetic-canary" not in repr(result) + repr(scanner_result)


async def test_sync_factory_future_result_is_still_delivered():
    future = asyncio.get_running_loop().create_future()
    future.set_result("checked output")
    result = await Guard().arun("input", lambda _: future)
    assert result.require_text() == "checked output"
