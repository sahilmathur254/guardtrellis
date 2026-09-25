"""Public, payload-safe result types. Explicit serialization may still expose text."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Action(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"
    ERROR = "error"


class Stage(StrEnum):
    INPUT = "input"
    OUTPUT = "output"
    RETRIEVAL = "retrieval"
    TOOL = "tool"


@dataclass(frozen=True)
class Finding:
    """Offsets are half-open Python character indices in the indicated text revision.

    Codes and scanner names must be static metadata, never matched text.
    The orchestrator supplies revision, scanner, and scanner_index.
    """

    code: str
    start: int | None = None
    end: int | None = None
    scanner: str = ""
    scanner_index: int = -1
    revision: int = 0


@dataclass(frozen=True)
class Edit:
    """A replacement in the current scanner's input, never a rehydration map."""

    start: int
    end: int
    replacement: str = field(default="[REDACTED]", repr=False)


@dataclass(frozen=True)
class Check:
    """A scanner decision; REDACT requires non-overlapping edits and findings."""

    action: Action = Action.ALLOW
    findings: tuple[Finding, ...] = ()
    edits: tuple[Edit, ...] = field(default=(), repr=False)


@dataclass(frozen=True)
class Trace:
    scanner: str
    scanner_index: int
    action: Action
    revision_before: int
    revision_after: int


class Rejected(RuntimeError):
    """Raised by require_text when a result has no deliverable content."""


@dataclass(frozen=True)
class Result:
    action: Action
    stage: Stage
    text: str | None = field(repr=False)
    findings: tuple[Finding, ...] = ()
    trace: tuple[Trace, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.action in (Action.ALLOW, Action.WARN, Action.REDACT)

    def require_text(self) -> str:
        if not self.accepted or self.text is None:
            raise Rejected(f"GuardTrellis rejected content: {self.action.value}")
        return self.text

    def diagnostics(self) -> dict[str, Any]:
        """The supported metadata-only logging interface (unlike dataclasses.asdict)."""
        return {
            "action": self.action.value,
            "stage": self.stage.value,
            "findings": [
                {
                    "code": item.code,
                    "start": item.start,
                    "end": item.end,
                    "scanner": item.scanner,
                    "scanner_index": item.scanner_index,
                    "revision": item.revision,
                }
                for item in self.findings
            ],
            "trace": [
                {
                    "scanner": item.scanner,
                    "scanner_index": item.scanner_index,
                    "action": item.action.value,
                    "revision_before": item.revision_before,
                    "revision_after": item.revision_after,
                }
                for item in self.trace
            ],
        }


@dataclass(frozen=True)
class RunResult:
    action: Action
    input_result: Result
    output_result: Result | None

    @property
    def text(self) -> str | None:
        if self.output_result is None:
            return None
        return self.output_result.text

    @property
    def accepted(self) -> bool:
        return self.output_result is not None and self.output_result.accepted

    def require_text(self) -> str:
        if not self.accepted or self.text is None:
            raise Rejected(f"GuardTrellis rejected call: {self.action.value}")
        return self.text

    def diagnostics(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "input": self.input_result.diagnostics(),
            "output": self.output_result.diagnostics() if self.output_result else None,
        }


def combine_actions(*actions: Action) -> Action:
    priority = (Action.ALLOW, Action.WARN, Action.REDACT, Action.BLOCK, Action.ERROR)
    return max(actions, key=priority.index)
