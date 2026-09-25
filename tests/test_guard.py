import asyncio
import gc
import json
import threading
from dataclasses import dataclass

import pytest

from guardtrellis import (
    Action,
    Check,
    Edit,
    Finding,
    Guard,
    LiteralScanner,
    PIIScanner,
    Rejected,
    Stage,
)


def test_redaction_precedes_provider_and_output_validation():
    seen = []

    def model(text):
        seen.append(text)
        return "Reply to agent@example.org"

    result = Guard(input_scanners=[PIIScanner()], output_scanners=[PIIScanner()]).run(
        "Ask person@example.net", model
    )
    assert seen == ["Ask [PII]"]
    assert result.require_text() == "Reply to [PII]"
    assert result.action == Action.REDACT
    assert "person@example.net" not in repr(result)
    assert "agent@example.org" not in json.dumps(result.diagnostics())


def test_blocked_input_never_calls_provider():
    def forbidden(_):
        pytest.fail("Provider must not run")

    result = Guard(input_scanners=[LiteralScanner(["private"])]).run("private data", forbidden)
    assert result.action == Action.BLOCK
    assert result.output_result is None
    assert result.input_result.text is result.text is None
    with pytest.raises(Rejected, match="block"):
        result.require_text()


def test_output_block_hides_content():
    result = Guard(output_scanners=[LiteralScanner(["hidden"])]).run("question", lambda _: "hidden")
    assert not result.accepted
    assert result.text is None
    assert "hidden" not in repr(result)


def test_order_and_offsets_reference_intermediate_revision():
    guard = Guard(input_scanners=[PIIScanner(), LiteralScanner(["tail"], action=Action.REDACT)])
    result = guard.scan("long.address@example.org tail")
    assert result.text == "[PII] [REDACTED]"
    first, second = result.findings
    assert (first.start, first.end, first.revision, first.scanner_index) == (0, 24, 0, 0)
    assert (second.start, second.end, second.revision, second.scanner_index) == (6, 10, 1, 1)
    assert result.trace[-1].revision_after == 2


def test_later_scanner_receives_transformed_text():
    result = Guard(input_scanners=[PIIScanner(), LiteralScanner(["@"])]).scan("a@example.org")
    assert result.action == Action.REDACT


def test_warning_allows_delivery_and_is_preserved():
    result = Guard(input_scanners=[LiteralScanner(["note"], action=Action.WARN)]).run(
        "note", lambda text: text
    )
    assert result.action == Action.WARN
    assert result.require_text() == "note"


class Failing:
    name = "failing"

    def scan(self, text, *, stage):
        raise RuntimeError(text)


def test_scanner_error_is_explicit_and_does_not_log_payload(caplog, capsys):
    result = Guard(input_scanners=[Failing()]).scan("sensitive-marker")
    assert result.action == Action.ERROR
    assert result.text is None
    assert result.findings[0].code == "scanner_error"
    assert "sensitive-marker" not in repr(result) + json.dumps(result.diagnostics())
    assert caplog.text == ""
    assert capsys.readouterr().out == ""


def test_callback_exception_is_sanitized():
    def failing(text):
        raise RuntimeError(text)

    result = Guard().run("sensitive-marker", failing)
    assert result.action == Action.ERROR
    assert result.output_result.findings[0].code == "callback_error"
    assert "sensitive-marker" not in repr(result)


@dataclass
class Returns:
    value: object
    name: str = "custom"

    def scan(self, text, *, stage):
        return self.value


@pytest.mark.parametrize(
    "value",
    [
        None,
        Check("allow"),
        Check(Action.ALLOW, (Finding("ignored"),)),
        Check(Action.BLOCK),
        Check(Action.REDACT, (Finding("missing_edits"),)),
        Check(Action.WARN, (Finding("bad_span", -1, 2),)),
        Check(Action.WARN, (Finding("partial_span", 0),)),
        Check(Action.WARN, (Finding("raw text is not metadata"),)),
        Check(Action.REDACT, (Finding("overlap"),), (Edit(0, 3), Edit(2, 4))),
        Check(Action.REDACT, (Finding("bad_edit"),), (Edit(0, 99),)),
        Check(Action.WARN, (Finding("bad_edit"),), (Edit(0, 1),)),
        Check(Action.WARN, (Finding("flood"),) * 257),
    ],
)
def test_invalid_scanner_outputs_fail_closed(value):
    result = Guard(input_scanners=[Returns(value)]).scan("test")
    assert result.action == Action.ERROR
    assert result.text is None


def test_transformation_size_limit():
    scanner = Returns(Check(Action.REDACT, (Finding("growth"),), (Edit(0, 1, "x" * 100),)))
    assert Guard(input_scanners=[scanner], max_chars=10).scan("a").action == Action.ERROR


@pytest.mark.parametrize("text", ["x" * 11, None, 123, b"text"])
def test_invalid_or_oversized_input_never_calls_scanner(text):
    result = Guard(input_scanners=[Failing()], max_chars=10).scan(text)
    assert result.action == Action.ERROR
    assert not result.trace


@pytest.mark.parametrize("output", [None, 1, b"bytes", ["stream"], "x" * 11])
def test_invalid_provider_output_is_error(output):
    result = Guard(max_chars=10).run("ok", lambda _: output)
    assert result.action == Action.ERROR
    assert result.text is None


def test_stage_isolation_and_empty_input():
    guard = Guard(retrieval_scanners=[LiteralScanner(["source"])])
    assert guard.scan("source", stage=Stage.INPUT).accepted
    assert guard.scan("source", stage=Stage.OUTPUT).accepted
    assert guard.scan("source", stage=Stage.TOOL).accepted
    assert guard.scan("source", stage=Stage.RETRIEVAL).action == Action.BLOCK
    assert guard.scan("").require_text() == ""
    with pytest.raises(ValueError):
        guard.scan("source", stage="input")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_chars": 0},
        {"max_chars": True},
        {"max_chars": 1.5},
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        {"timeout_seconds": float("inf")},
        {"timeout_seconds": float("nan")},
    ],
)
def test_invalid_guard_configuration(kwargs):
    with pytest.raises(ValueError):
        Guard(**kwargs)


class AsyncScanner:
    name = "async_scanner"

    async def scan(self, text, *, stage):
        await asyncio.sleep(0)
        return Check(Action.WARN, (Finding("async_notice"),))


async def test_mixed_async_and_sync_scanners_and_callbacks():
    guard = Guard(input_scanners=[AsyncScanner(), PIIScanner()])

    async def model(text):
        return text.upper()

    result = await guard.arun("email test@example.net", model)
    assert result.require_text() == "EMAIL [PII]"
    assert result.action == Action.REDACT
    sync_result = await guard.arun("hello", lambda text: text)
    assert sync_result.require_text() == "hello"


def test_sync_rejects_async_scanner_without_unawaited_coroutine():
    assert Guard(input_scanners=[AsyncScanner()]).scan("x").action == Action.ERROR


def test_sync_rejects_async_provider():
    async def model(text):
        return text

    assert Guard().run("x", model).action == Action.ERROR


async def test_async_timeout_is_fail_closed():
    class Slow:
        name = "slow"

        async def scan(self, text, *, stage):
            await asyncio.sleep(10)
            return Check()

    result = await Guard(input_scanners=[Slow()], timeout_seconds=0.03).ascan("x")
    assert result.action == Action.ERROR
    assert result.findings[0].code == "scanner_timeout"
    assert result.text is None


async def test_callback_cannot_suppress_cancellation_to_turn_timeout_into_success():
    done = asyncio.Event()

    async def model(_):
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            done.set()
            return "late content"

    result = await Guard(timeout_seconds=0.03).arun("x", model)
    assert result.action == Action.ERROR
    assert result.output_result.findings[0].code == "callback_timeout"
    assert result.text is None
    await asyncio.wait_for(done.wait(), 1)


async def test_timeout_does_not_claim_to_stop_worker_thread():
    started = threading.Event()
    release = threading.Event()
    ended = threading.Event()

    def model(_):
        started.set()
        release.wait(timeout=2)
        ended.set()
        return "late"

    try:
        result = await Guard(timeout_seconds=0.05).arun("x", model)
        assert started.is_set()
        assert result.action == Action.ERROR
        assert not ended.is_set()
    finally:
        release.set()
        await asyncio.to_thread(ended.wait, 2)


async def test_caller_cancellation_propagates():
    started = asyncio.Event()

    async def model(_):
        started.set()
        await asyncio.sleep(10)
        return "late"

    task = asyncio.create_task(Guard().arun("x", model))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_late_coroutine_from_sync_factory_is_closed(recwarn):
    release = threading.Event()
    finished = threading.Event()

    async def late_result():
        pytest.fail("Timed-out work must not start its returned coroutine")

    def factory(_):
        release.wait(timeout=2)
        coroutine = late_result()
        finished.set()
        return coroutine

    try:
        result = await Guard(timeout_seconds=0.03).arun("x", factory)
        assert result.action == Action.ERROR
    finally:
        release.set()
        await asyncio.to_thread(finished.wait, 2)
        # Let the executor completion callback and disposal callback run.
        await asyncio.sleep(0.02)
        gc.collect()
    assert not [warning for warning in recwarn if "never awaited" in str(warning.message)]


async def test_concurrent_requests_do_not_share_state():
    guard = Guard(input_scanners=[PIIScanner()])
    results = await asyncio.gather(
        *(guard.arun(f"{i}@example.org", lambda x: x) for i in range(20))
    )
    assert all(result.require_text() == "[PII]" for result in results)
    assert all(result.input_result.findings[0].revision == 0 for result in results)


async def test_async_stages_and_input_gate():
    guard = Guard(
        input_scanners=[LiteralScanner(["blocked"])],
        output_scanners=[PIIScanner()],
        retrieval_scanners=[LiteralScanner(["blocked"])],
        tool_scanners=[LiteralScanner(["blocked"])],
    )

    def forbidden(_):
        pytest.fail("Provider must not run")

    assert (await guard.arun("blocked", forbidden)).output_result is None
    assert (await guard.ascan("x@example.org", stage=Stage.OUTPUT)).text == "[PII]"
    assert (await guard.ascan("blocked", stage=Stage.RETRIEVAL)).action == Action.BLOCK
    assert (await guard.ascan("blocked", stage=Stage.TOOL)).stage == Stage.TOOL
