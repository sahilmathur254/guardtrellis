"""Run: python examples/decoded_contact.py. Fabricated data; no credentials or network."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from guardtrellis import (
    Action,
    Finding,
    Guard,
    PIIScanner,
    Rejected,
    SecretScanner,
    Stage,
    ToolGuard,
    ToolResult,
)

MAX_JSON_CHARS = 4_096
MAX_OUTPUT_CHARS = 4_096
MAX_DEPTH = 2
MAX_EMAIL_CHARS = 254
MAX_PHONE_CHARS = 64
MAX_DECODED_CHARS = MAX_EMAIL_CHARS + MAX_PHONE_CHARS
MAX_SCANNER_INVOCATIONS = 4
MAX_SCANNED_CHARS = 1_024
MAX_FINDINGS = 16

# These are trusted schema identifiers. No input-derived path or key enters diagnostics.
_FIELDS = (("email", "field-0", MAX_EMAIL_CHARS), ("phone", "field-1", MAX_PHONE_CHARS))
TOOLS = ToolGuard(
    {
        "contact": {
            "type": "object",
            "properties": {
                "email": {"type": "string", "minLength": 1, "maxLength": MAX_EMAIL_CHARS},
                "phone": {"type": "string", "minLength": 1, "maxLength": MAX_PHONE_CHARS},
            },
            "required": ["email", "phone"],
            "additionalProperties": False,
        }
    },
    max_chars=MAX_JSON_CHARS,
    max_depth=MAX_DEPTH,
)
# A fixed application policy, not a configurable SDK traversal/scanner-list API.
SECRET_POLICY = Guard(tool_scanners=[SecretScanner()], max_chars=MAX_EMAIL_CHARS)
PII_POLICY = Guard(
    tool_scanners=[PIIScanner(formats=["email", "phone"])], max_chars=MAX_EMAIL_CHARS
)


@dataclass(frozen=True)
class ContactFinding:
    """Metadata in one decoded field revision, never serialized JSON coordinates."""

    field_id: str
    pass_index: int
    revision: int
    code: str
    start: int | None
    end: int | None
    scanner: str
    scanner_index: int

    def diagnostics(self) -> dict[str, Any]:
        return {
            "field_id": self.field_id,
            "pass_index": self.pass_index,
            "revision": self.revision,
            "code": self.code,
            "start": self.start,
            "end": self.end,
            "scanner": self.scanner,
            "scanner_index": self.scanner_index,
        }


@dataclass(frozen=True)
class ContactResult:
    """Application result preserving decoded outcomes separately from wire validation.

    Only diagnostics()/repr are metadata-only. require_call() explicitly exposes the
    checked payload, and the final ToolResult also contains it; do not log either.
    """

    action: Action
    findings: tuple[ContactFinding, ...]
    final: ToolResult = field(repr=False)
    scanner_invocations: int
    scanned_chars: int

    def require_call(self) -> tuple[str, dict[str, Any]]:
        name, arguments = self.final.require_call()
        return name, dict(arguments)

    def diagnostics(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "decoded_findings": [finding.diagnostics() for finding in self.findings],
            "final_validation": self.final.diagnostics(),
            "scanner_invocations": self.scanner_invocations,
            "scanned_chars": self.scanned_chars,
        }


class WorkflowError(RuntimeError):
    """Callback failure with a fixed public message, excluding the original exception."""


def _reject(code: str) -> None:
    raise Rejected(f"Decoded contact rejected: {code}")


def _check_values(values: dict[str, Any]) -> None:
    for key, _, limit in _FIELDS:
        text = values[key]
        if not isinstance(text, str) or not 1 <= len(text) <= limit:
            _reject("field_limit_exceeded")
        if any("\ud800" <= char <= "\udfff" for char in text):
            _reject("unicode_invalid")
    if sum(len(values[key]) for key, _, _ in _FIELDS) > MAX_DECODED_CHARS:
        _reject("decoded_limit_exceeded")


def _envelope(finding: Finding, field_id: str, pass_index: int, revision: int) -> ContactFinding:
    return ContactFinding(
        field_id,
        pass_index,
        revision + finding.revision,
        finding.code,
        finding.start,
        finding.end,
        finding.scanner,
        finding.scanner_index,
    )


def check_contact(name: str, arguments_json: str) -> ContactResult:
    """Check exactly two decoded fields with a fixed policy using public SDK APIs.

    All secret checks precede every PII check. Each field is decoded once, and keys
    are neither scanned nor edited. BLOCK/ERROR or any failed bound raises without
    returning partial output. The fixed synchronous policy has no execution deadline.
    """
    checked_name, original = TOOLS.validate(name, arguments_json).require_call()
    values = {key: original[key] for key, _, _ in _FIELDS}
    _check_values(values)
    findings: list[ContactFinding] = []
    revisions = {key: 0 for key, _, _ in _FIELDS}
    action = Action.ALLOW
    invocations = scanned_chars = 0

    for pass_index, policy in enumerate((SECRET_POLICY, PII_POLICY)):
        for key, field_id, _ in _FIELDS:
            text = values[key]
            if invocations >= MAX_SCANNER_INVOCATIONS:
                _reject("scanner_limit_exceeded")
            if scanned_chars + len(text) > MAX_SCANNED_CHARS:
                _reject("scanned_limit_exceeded")
            invocations += 1
            scanned_chars += len(text)
            result = policy.scan(text, stage=Stage.TOOL)
            if len(findings) + len(result.findings) > MAX_FINDINGS:
                _reject("finding_limit_exceeded")
            findings.extend(
                _envelope(finding, field_id, pass_index, revisions[key])
                for finding in result.findings
            )
            # Guard converts scanner exceptions/malformed checks to payload-free ERROR.
            values[key] = result.require_text()
            _check_values(values)
            if result.action == Action.REDACT:
                revisions[key] += 1
                action = Action.REDACT
            elif result.action == Action.WARN and action == Action.ALLOW:
                action = Action.WARN

    try:
        serialized = json.dumps(
            {key: values[key] for key, _, _ in _FIELDS},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except Exception:
        raise Rejected("Decoded contact rejected: serialization_error") from None
    if len(serialized) > MAX_OUTPUT_CHARS:
        _reject("output_limit_exceeded")
    final = TOOLS.validate(checked_name, serialized)
    final.require_call()
    return ContactResult(action, tuple(findings), final, invocations, scanned_chars)


def run_workflow(
    name: str,
    arguments_json: str,
    authorize: Callable[[str, dict[str, Any]], bool],
    execute: Callable[[str, dict[str, Any]], str],
) -> str:
    """Authorize only the final checked pair, then execute through trusted host code.

    Authorization gets a copy, and only literal True permits dispatch. Callback errors
    prevent delivery but cannot undo host side effects. Identity, permissions, external
    resource limits and output checking remain host responsibilities.
    """
    checked_name, arguments = check_contact(name, arguments_json).require_call()
    try:
        authorized = authorize(checked_name, dict(arguments))
    except Exception:
        raise WorkflowError("Workflow callback failed") from None
    if authorized is not True:
        raise PermissionError("Tool request is not authorized")
    try:
        return execute(checked_name, arguments)
    except Exception:
        raise WorkflowError("Workflow callback failed") from None


def main() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def authorize(name: str, arguments: dict[str, Any]) -> bool:
        # Local demo grant; production hosts must use the caller's identity/permissions.
        return name == "contact"

    def execute(name: str, arguments: dict[str, Any]) -> str:
        calls.append((name, arguments))
        return f"Local checked contact: {arguments['email']} / {arguments['phone']}"

    plain = '{"email":"casey@example.org","phone":"+14155552671"}'
    escaped = r'{"email":"casey\u0040example.org","phone":"\u002b14155552671"}'
    for proposed in (plain, escaped):
        result = check_contact("contact", proposed)
        assert result.action == Action.REDACT and result.final.action == Action.ALLOW
        print(run_workflow("contact", proposed, authorize, execute))
    assert calls == [("contact", {"email": "[PII]", "phone": "[PII]"})] * 2
    print("Equivalent plain and escaped contacts reached the same checked local callback.")

    for name, proposed in (
        ("delete", "{}"),
        ("contact", json.dumps({"email": "casey@example.org", "phone": "ghp_" + "A" * 36})),
        ("contact", '{"email":"first","\\u0065mail":"second","phone":"safe"}'),
    ):
        try:
            run_workflow(name, proposed, authorize, execute)
        except Rejected:
            pass
        else:
            raise AssertionError("Expected contact rejection")
    assert len(calls) == 2
    print("Rejected contacts skipped authorization and execution.")


if __name__ == "__main__":
    main()
