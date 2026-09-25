"""Ordered checks and provider-independent, complete-response callback integration."""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import math
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import replace
from functools import partial
from typing import Protocol, TypeVar, cast

from .models import Action, Check, Finding, Result, RunResult, Stage, Trace, combine_actions

T = TypeVar("T")
_IDENTIFIER = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{0,63}\Z")
MAX_FINDINGS = 256


class Scanner(Protocol):
    """Custom scanners are trusted code; never put content in names or finding codes."""

    @property
    def name(self) -> str: ...

    def scan(self, text: str, *, stage: Stage) -> Check | Awaitable[Check]: ...


def _consume_task(task: asyncio.Task[T]) -> None:
    if not task.cancelled():
        task.exception()


def _discard_worker_result(future: asyncio.Future[T | Awaitable[T]]) -> None:
    if future.cancelled() or future.exception() is not None:
        return
    value = future.result()
    if inspect.iscoroutine(value):
        value.close()
    elif isinstance(value, asyncio.Future):
        value.cancel()


async def _invoke(function: Callable[[], T | Awaitable[T]]) -> T:
    if inspect.iscoroutinefunction(function):
        return await cast(Awaitable[T], function())
    # Copy context like to_thread, but retain the future to dispose of late awaitables.
    # Cancelling a thread's await cannot stop that thread from returning a coroutine.
    worker = asyncio.get_running_loop().run_in_executor(
        None, contextvars.copy_context().run, function
    )
    try:
        value = await asyncio.shield(worker)
    except asyncio.CancelledError:
        worker.add_done_callback(_discard_worker_result)
        raise
    if inspect.isawaitable(value):
        return await value
    return value


async def _bounded(function: Callable[[], T | Awaitable[T]], wait_seconds: float) -> T:
    task = asyncio.create_task(_invoke(function))
    try:
        # wait_for/timeout can accept late results if user code suppresses cancellation.
        done, _ = await asyncio.wait({task}, timeout=wait_seconds)
        if not done:
            raise TimeoutError
        return task.result()
    finally:
        if not task.done():
            task.cancel()
            task.add_done_callback(_consume_task)


def _sync_value(value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        if inspect.iscoroutine(value):
            value.close()
        raise TypeError("Use the asynchronous entry point for awaitable work")
    return value


def _error(stage: Stage, code: str) -> Result:
    return Result(Action.ERROR, stage, None, (Finding(code, scanner="guard"),))


class _Pipeline:
    def __init__(self, text: str, stage: Stage, max_chars: int):
        self.text = text
        self.stage = stage
        self.max_chars = max_chars
        self.action = Action.ALLOW
        self.revision = 0
        self.findings: list[Finding] = []
        self.trace: list[Trace] = []

    def apply(self, check: Check, name: str, index: int) -> None:
        # Validate a custom scanner's entire response before changing state.
        if not isinstance(check, Check) or not isinstance(check.action, Action):
            raise ValueError("Invalid scanner decision")
        if len(check.findings) > MAX_FINDINGS or len(check.edits) > MAX_FINDINGS:
            raise ValueError("Scanner result limit exceeded")
        if check.action == Action.ALLOW and (check.findings or check.edits):
            raise ValueError("Allow cannot contain findings or edits")
        if check.action != Action.ALLOW and not check.findings:
            raise ValueError("Non-allow decisions require a reason")
        if bool(check.edits) != (check.action == Action.REDACT):
            raise ValueError("Only redact decisions may contain edits")
        for finding in check.findings:
            if not isinstance(finding, Finding) or not _IDENTIFIER.fullmatch(finding.code):
                raise ValueError("Invalid finding")
            if finding.start is None and finding.end is None:
                continue
            if (
                type(finding.start) is not int
                or type(finding.end) is not int
                or not 0 <= finding.start < finding.end <= len(self.text)
            ):
                raise ValueError("Invalid finding span")
        previous = 0
        for edit in sorted(check.edits, key=lambda item: item.start):
            if (
                type(edit.start) is not int
                or type(edit.end) is not int
                or not previous <= edit.start < edit.end <= len(self.text)
                or not isinstance(edit.replacement, str)
            ):
                raise ValueError("Invalid edit")
            previous = edit.end
        updated = self.text
        for edit in sorted(check.edits, key=lambda item: item.start, reverse=True):
            updated = updated[: edit.start] + edit.replacement + updated[edit.end :]
            if len(updated) > self.max_chars:
                raise ValueError("Transformed text exceeds limit")
        before = self.revision
        if check.action == Action.REDACT:
            self.revision += 1
        self.findings.extend(
            replace(item, scanner=name, scanner_index=index, revision=before)
            for item in check.findings
        )
        self.trace.append(Trace(name, index, check.action, before, self.revision))
        self.text = updated
        self.action = combine_actions(self.action, check.action)

    def fail(self, name: str, index: int, code: str) -> None:
        self.apply(Check(Action.ERROR, (Finding(code),)), name, index)

    @property
    def stopped(self) -> bool:
        return self.action in (Action.BLOCK, Action.ERROR)

    def result(self) -> Result:
        return Result(
            self.action,
            self.stage,
            None if self.stopped else self.text,
            tuple(self.findings),
            tuple(self.trace),
        )


class Guard:
    """Explicit, ordered stage policies. An unconfigured stage allows bounded text.

    Async timeout is per scanner/callback, not for the complete run. Cancellation
    cannot terminate a worker thread or preempt an event-loop-blocking coroutine.
    Synchronous entry points have no execution deadline.
    """

    def __init__(
        self,
        *,
        input_scanners: Sequence[Scanner] = (),
        output_scanners: Sequence[Scanner] = (),
        retrieval_scanners: Sequence[Scanner] = (),
        tool_scanners: Sequence[Scanner] = (),
        max_chars: int = 100_000,
        timeout_seconds: float = 5.0,
    ):
        if type(max_chars) is not int or max_chars < 1:
            raise ValueError("max_chars must be a positive integer")
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive and finite")
        self.max_chars = max_chars
        self.timeout_seconds = timeout_seconds
        self._scanners = {
            Stage.INPUT: tuple(input_scanners),
            Stage.OUTPUT: tuple(output_scanners),
            Stage.RETRIEVAL: tuple(retrieval_scanners),
            Stage.TOOL: tuple(tool_scanners),
        }
        for scanners in self._scanners.values():
            for scanner in scanners:
                if not _IDENTIFIER.fullmatch(scanner.name) or not callable(scanner.scan):
                    raise ValueError("Scanners require a static identifier name and scan method")

    def _prepare(self, text: str, stage: Stage) -> _Pipeline | Result:
        if not isinstance(stage, Stage):
            raise ValueError("stage must be a Stage enum")
        if not isinstance(text, str):
            return _error(stage, "invalid_text_type")
        if len(text) > self.max_chars:
            return _error(stage, "text_limit_exceeded")
        return _Pipeline(text, stage, self.max_chars)

    def scan(self, text: str, *, stage: Stage = Stage.INPUT) -> Result:
        pipeline = self._prepare(text, stage)
        if isinstance(pipeline, Result):
            return pipeline
        for index, scanner in enumerate(self._scanners[stage]):
            try:
                check = _sync_value(scanner.scan(pipeline.text, stage=stage))
                pipeline.apply(check, scanner.name, index)
            except Exception:
                pipeline.fail(scanner.name, index, "scanner_error")
            if pipeline.stopped:
                break
        return pipeline.result()

    async def ascan(self, text: str, *, stage: Stage = Stage.INPUT) -> Result:
        pipeline = self._prepare(text, stage)
        if isinstance(pipeline, Result):
            return pipeline
        for index, scanner in enumerate(self._scanners[stage]):
            try:
                check = await _bounded(
                    partial(scanner.scan, pipeline.text, stage=stage), self.timeout_seconds
                )
                pipeline.apply(check, scanner.name, index)
            except TimeoutError:
                pipeline.fail(scanner.name, index, "scanner_timeout")
            except Exception:
                pipeline.fail(scanner.name, index, "scanner_error")
            if pipeline.stopped:
                break
        return pipeline.result()

    def run(self, text: str, model: Callable[[str], str]) -> RunResult:
        checked_input = self.scan(text, stage=Stage.INPUT)
        if not checked_input.accepted:
            return RunResult(checked_input.action, checked_input, None)
        try:
            output = _sync_value(model(checked_input.require_text()))
        except Exception:
            checked_output = _error(Stage.OUTPUT, "callback_error")
        else:
            checked_output = self.scan(output, stage=Stage.OUTPUT)
        return RunResult(
            combine_actions(checked_input.action, checked_output.action),
            checked_input,
            checked_output,
        )

    async def arun(self, text: str, model: Callable[[str], str | Awaitable[str]]) -> RunResult:
        checked_input = await self.ascan(text, stage=Stage.INPUT)
        if not checked_input.accepted:
            return RunResult(checked_input.action, checked_input, None)
        try:
            output = await _bounded(
                lambda: model(checked_input.require_text()), self.timeout_seconds
            )
        except TimeoutError:
            checked_output = _error(Stage.OUTPUT, "callback_timeout")
        except Exception:
            checked_output = _error(Stage.OUTPUT, "callback_error")
        else:
            checked_output = await self.ascan(output, stage=Stage.OUTPUT)
        return RunResult(
            combine_actions(checked_input.action, checked_output.action),
            checked_input,
            checked_output,
        )
