"""Tool validation returns data, and never dispatches or authorizes execution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .guard import Guard, Scanner
from .json_check import JSONScanner, Schema, strict_loads
from .models import Action, Finding, Rejected, Result, Stage


@dataclass(frozen=True)
class ToolResult:
    validation: Result
    name: str | None = field(default=None, repr=False)
    arguments: dict[str, Any] | None = field(default=None, repr=False)

    @property
    def action(self) -> Action:
        return self.validation.action

    @property
    def accepted(self) -> bool:
        return self.validation.accepted

    def require_call(self) -> tuple[str, dict[str, Any]]:
        if not self.accepted or self.name is None or self.arguments is None:
            raise Rejected(f"GuardTrellis rejected tool call: {self.action.value}")
        return self.name, self.arguments

    def diagnostics(self) -> dict[str, Any]:
        return self.validation.diagnostics()


class ToolGuard:
    """Exact name allowlist with a separate argument schema for each tool.

    Arguments must arrive as JSON text, enabling duplicate-key detection. A
    syntax check precedes text policies, and the schema is checked after edits.
    """

    def __init__(
        self,
        tools: Mapping[str, Schema],
        *,
        argument_scanners: Sequence[Scanner] = (),
        max_chars: int = 100_000,
        timeout_seconds: float = 5.0,
        max_depth: int = 32,
    ):
        if any(not isinstance(name, str) or not 1 <= len(name) <= 128 for name in tools):
            raise ValueError("Tool names must have between 1 and 128 characters")
        self._guards = {
            name: Guard(
                tool_scanners=(
                    JSONScanner(max_depth=max_depth, require_object=True),
                    *argument_scanners,
                    JSONScanner(schema, max_depth=max_depth, require_object=True),
                ),
                max_chars=max_chars,
                timeout_seconds=timeout_seconds,
            )
            for name, schema in tools.items()
        }
        self._max_depth = max_depth

    def _unknown(self) -> ToolResult:
        return ToolResult(Result(Action.BLOCK, Stage.TOOL, None, (Finding("tool_not_allowed"),)))

    def _result(self, name: str, validation: Result) -> ToolResult:
        if not validation.accepted:
            return ToolResult(validation)
        return ToolResult(
            validation, name, strict_loads(validation.require_text(), max_depth=self._max_depth)
        )

    def validate(self, name: str, arguments_json: str) -> ToolResult:
        if not isinstance(name, str) or name not in self._guards:
            return self._unknown()
        return self._result(name, self._guards[name].scan(arguments_json, stage=Stage.TOOL))

    async def avalidate(self, name: str, arguments_json: str) -> ToolResult:
        if not isinstance(name, str) or name not in self._guards:
            return self._unknown()
        return self._result(name, await self._guards[name].ascan(arguments_json, stage=Stage.TOOL))
