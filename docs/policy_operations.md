# Stage policies and metadata-only operations

For an application that retrieves a document and proposes a lookup call, redacting the
initial prompt alone leaves retrieval, tool arguments, and final delivery unchecked. This
recipe shows where to place each check and how to diagnose failures without logging those values.

Run the credential-free [recipe](../examples/policy_operations.py) with core dependencies:

```sh
uv sync --frozen --group dev
uv run --frozen python examples/policy_operations.py
```

All data is fabricated. The callbacks use fixed local values and an in-memory public
document; no provider, framework, network call, or credential is needed. The script shows
redaction, a warning that continues, secret rejection, and a size-limit error. The
[focused tests](../tests/test_policy_operations_example.py) also exercise every rejected
boundary, a failing output scanner, callback failures, and the content of operation logs.

## Choose a policy for each boundary

These are explicit application choices, not recommended universal defaults:

| Boundary | Policy in this recipe | Next consumer |
| --- | --- | --- |
| Input | Block selected secret signatures; redact email patterns; warn on invisible controls | Retrieval callback receives `input_result.require_text()` |
| Retrieval | Block secret signatures and the application marker `internal-only`; redact email patterns | Proposal callback receives a prompt composed from checked input and `retrieval_result.require_text()` |
| Tool arguments | Exact tool-name allowlist, JSON syntax, secret blocking, email redaction, then schema validation | Execution callback receives only `tool_result.require_call()` |
| Output | Block secret signatures and supported email, phone, and SSN patterns | Delivery callback receives `output_result.require_text()` |

`WARN` continues with the checked text unchanged. `REDACT` continues with the transformed
text. Both `BLOCK` and `ERROR` stop the workflow with `Rejected`, without invoking the
next callback. An error means the check failed or exceeded its limits; it is not evidence
that a prohibited pattern was found. Do not fall back to the original value after either
outcome. A warning policy is advisory: the example deliberately lets a zero-width character
continue, so use it only where that is acceptable to the application.

Order matters because each scanner receives the current text, including earlier edits.
Put policies that must reject the original content before redactors that could erase their
evidence. For example, `LiteralScanner(["internal-only"])` must run before the email
redactor: `internal-only@example.org` should be rejected, not become `[PII]` and pass the
literal policy. A block stops scanning, so the trace is not a complete inventory of every
possible finding. `ToolGuard` runs its syntax check before argument scanners and validates
the schema after redaction.

Do not reuse the original tool proposal after validation, mutate checked arguments, or
reconstruct a prompt using raw retrieval text. The tool callback separately authorizes
`public-guide`: a schema-valid `private-guide` request is still denied. Output checks occur
**after execution** and cannot undo a tool's side effects. Authorize and constrain the
operation before execution, and check its returned data before delivery or another model
call. Use idempotency or a transaction where the application's side effects require it.

The policies intentionally cover different PII formats at different stages. Names and
many phone formats are outside built-in coverage; these examples do not establish that
all sensitive data has been removed. Tool text scanners inspect serialized JSON, so
escaped values can evade signature checks. The `internal-only` marker is an exact business
rule, not semantic prompt-injection detection. See the [limitations](limitations.md) and
[tool API](api.md#json-and-tool-calls).

## Record decisions without recording payloads

Each workflow generates an opaque random request ID using `uuid4().hex`. The application
owns that ID; it is not taken from a user, email address, arbitrary request header, or
callback value. All checks in the run share the ID, which connects events without putting
the input or output into logs. Production trace IDs can serve the same purpose if their
format and origin are controlled by the host.

`record_check` serializes only the ID, a fixed event label, and `result.diagnostics()`.
That supported interface contains actions, stages, finding codes, spans, and scanner
traces; it excludes text, argument values, and replacements. Scanner names and codes are
trusted static configuration and must never embed matched text. Do not substitute
`dataclasses.asdict(result)` or serialize the complete result. Offsets and finding counts
still reveal structural metadata, so apply your normal log access and retention policy.

Callback failure events contain only the generated ID, a fixed boundary name, `error`,
and `callback_error`. The recipe raises a generic `WorkflowError` with displayed exception
chaining suppressed. It does not log exception messages, `exc_info`, input/output, tool
arguments, or provider response objects. Python still retains the original exception
context in memory: configure error reporters not to collect exception locals or that
context, and use the fixed event metadata for operational logs. A delivery callback can
fail after sending data, so an error event alone does not prove nothing was delivered.

Count BLOCK separately from ERROR, group static finding codes by stage, and investigate
scanner/callback errors as operational failures. Do not automatically downgrade ERROR to
WARN or retry a side-effecting operation without an application-specific retry policy.

## Async admission and deadlines belong to the host

The runnable workflow is synchronous and has no deadline. For an async host, use
`Guard.ascan`, `ToolGuard.avalidate`, or `Guard.arun` where appropriate; do not run this
synchronous workflow directly on the event loop. Concrete host controls are:

1. Set an ingress byte limit before decoding and a bounded request queue before scanning.
   As an illustrative starting configuration, accept at most eight active requests and
   sixteen queued requests, then return an overload response. These numbers need workload
   measurement; a semaphore by itself does not cap the waiting queue.
2. Give the request an end-to-end budget, including admission wait, retrieval, model,
   execution, and output checks. For example, from a ten-second budget, stop admitting
   after one second and pass the remaining budget to each operation. Guard's
   `timeout_seconds` is per scanner or callback; it does not provide that overall budget.
3. Configure provider-native connect/read/request timeouts and retry limits. For a
   five-second model-call allocation, use a provider deadline no greater than that
   allocation and initially disable automatic retries; enable only retries that fit the
   remaining budget and the operation's idempotency rules. Provider APIs differ; follow
   the installed SDK's documented timeout controls rather than relying only on an outer
   `asyncio.timeout`.
4. Hold an active-work permit until the actual operation finishes. A timed-out Guard
   await may leave a synchronous worker thread running. Releasing a semaphore when that
   await returns would admit more work while the old worker still consumes resources.
   Use native cancellable async clients with confirmed cleanup, or track worker completion
   separately. For a hard execution limit, use a separately limited process and terminate
   and reap it before releasing capacity.
5. Pass cancellation through to native async callbacks, avoid blocking code on the event
   loop, and never deliver late results after the request has stopped. Track queue depth,
   actual active workers, timeouts, and external terminations using static event fields.

Cancellation cannot roll back side effects or preempt arbitrary code. The existing
[resource measurements](resource_limits.md#host-controls-supported-by-the-observations)
document these limits and the measurements needed before choosing service limits.
