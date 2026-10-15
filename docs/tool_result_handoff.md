# Checking a tool result before the next consumer

Validating a tool call's name and arguments does not check the data returned by that tool.
Treat a tool result as untrusted retrieval text: check it **before** inserting it into an
agent's state, composing the next prompt, calling another model, or handing it to another
consumer. The [offline recipe](../examples/tool_result_handoff.py) makes that ordering explicit
with the existing public APIs available in GuardTrellis 0.1.3. It adds no SDK method,
`Stage` member, automatic interception, or provider dependency.

Run it with core dependencies:

```sh
uv sync --frozen --group dev
uv run --frozen python examples/tool_result_handoff.py
```

The callbacks use a fabricated in-memory public document and an agent-state list. The
example makes no network calls and needs no provider, framework, or credentials.
Runnable-example tests and distribution smokes execute it against both installed package
formats, including core-only environments.

## Follow the checked result through the handoff

`run_workflow(name, arguments_json, authorize, execute, consume, *, result_guard=RETURN_POLICY)`
follows this sequence:

1. Validate the proposed call with `ToolGuard`. The exact name is `lookup`; the object
   contains only a required `document_id` string of 1–64 Python characters. Consume the
   `require_call()` pair. Strict JSON, duplicate-key rejection, size/depth limits, and the
   schema apply before any callback runs. This schema does not establish permission.
2. Ask the host's `authorize(name, arguments)` callback for permission with a copy of the
   checked dictionary. It must return the boolean `True`; other values raise
   `PermissionError("Tool request is not authorized")` before execution. The schema permits
   only a flat string field, so a shallow copy isolates authorization edits from the
   dispatched arguments. The demonstration authorizes only `public-guide`.
3. Pass the checked name and arguments to `execute`. The host remains responsible for
   identity, permissions, tool selection, external requests, execution limits, and side
   effects. Do not dispatch the original JSON or unchecked proposal as a fallback.
4. Scan the complete returned string with `Guard.scan(..., stage=Stage.RETRIEVAL)`.
   The default policy's `MAX_RETURN_CHARS = 2000` bounds Python characters. Its policy
   blocks selected secret signatures first, then the application marker `internal-only`,
   then redacts the built-in supported email, phone, and SSN patterns. The literal marker
   is an application classification rule; it does not interpret instructions or meaning.
5. Call `require_text()` and give **only that checked text** to `consume`. The demonstration
   uses `agent_state.append`, so the raw return never enters that list. A host composing
   a prompt or making a subsequent model call must use the same checked value. The
   function returns the checked text as well; it never returns the original tool result.

`REDACT` delivers transformed text. `WARN` deliberately permits the current text to
continue; use it only where that is acceptable. `BLOCK` and `ERROR` raise `Rejected` and
prevent `consume` from running. An error means the check failed or exceeded a limit, not
that a prohibited pattern was necessarily found. Rejection after execution cannot undo
the tool's earlier side effects. A failing consumer may also have acted before it raised.

The optional `result_guard` is trusted application configuration. Configure its
`retrieval_scanners` and processing limits explicitly; an unconfigured retrieval stage
permits bounded content. Place blockers before redactors when they must see the original
content: for example, `internal-only@example.org` must be blocked before its email shape
can become `[PII]`.

## Keep every path behind the check

There is no automatic tool interception. Raw-return paths can bypass this handoff through
direct callbacks, earlier state insertion, prompt composition, caches, tracing, debug logs,
or an error fallback that reuses the raw return. Review each consumer and instrument the
host accordingly. Logging or caching the raw tool result before this check has already
exposed it; a later redaction cannot undo that capture.

This recipe checks complete plain text. It does not recursively traverse JSON objects,
scan non-text content, normalize encodings, or provide semantic prompt-injection detection.
Serialized JSON escape sequences can hide a signature from a text scanner. A host using
structured or mixed-content tool returns needs a separate validated schema and explicit
field/content policy. The [decoded-query recipe](decoded_query.md) demonstrates one bounded
decoded argument field; it is not a general structured tool-result scanner.

No model callback is part of this workflow. The host must check its own user input at
`Stage.INPUT` and any later complete model output at `Stage.OUTPUT` before delivery or
state insertion. Tool argument validation and returned-content checks have distinct
boundaries: [retrieval and tool calls](retrieval_tools.md) covers the earlier boundary,
while [stage policies and operations](policy_operations.md) shows broader host composition.

## Diagnose failures without logging the payload

The workflow generates an opaque request ID with `uuid4().hex`. Operation logs contain
that ID, a fixed event/boundary label, and `diagnostics()` for the checked result.
Callback failure logs use only fixed error metadata. Do not use the original tool name,
arguments, returned text, exception message, traceback, or arbitrary request header as
log content. Scanner names and finding codes must remain fixed trusted metadata;
custom scanners must not put matched content into those fields. Offsets and lengths can
still reveal structure, so the host owns log access, retention, and any stricter policy.

Callback exceptions become a fixed-message `WorkflowError` with displayed exception
chaining suppressed. Python can retain the original exception context and locals in
memory; configure error reporters not to capture them. `diagnostics()` and suppressed
reprs omit payloads from those interfaces; they do not encrypt or erase memory.
The normal result text and checked arguments intentionally contain deliverable data.
Do not serialize whole result objects or collect debugger locals as operational logs.

This synchronous workflow has no execution deadline. Character limits apply after the
host has received a Python string; enforce ingress bytes, bounded queues, concurrency,
tool-native timeouts, and an end-to-end request budget in the host. Async wait timeouts
cannot forcibly stop arbitrary threads or blocking code. Use process isolation where a
hard limit is required. See the [resource controls](resource_limits.md) and
[limitations](limitations.md) for coverage and operational constraints.

The focused tests exercise checked delivery, authorization, redaction, block/error and
oversized returns, callback failures, metadata-only logs, and raw-value bypass risks.
They establish this recipe's observed behavior with synthetic data, not comprehensive
PII removal, semantic safety, authorization enforcement outside this workflow, or a
production integration.
