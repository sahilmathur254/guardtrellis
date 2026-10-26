# API contracts

The [compatibility policy](compatibility.md) defines the supported public surface and
changes permitted across `0.1.x`. The contracts below retain their stated scope and limits.

## Integration and outcomes

`Guard` is a reusable configuration, with per-call pipeline state. Built-in scanners do
not store request text. Configure them once and do not mutate their attributes during use.
Custom scanners and callbacks must be safe for the application's concurrency model.

`run(text, model)` accepts a synchronous `str -> str` callable. `arun(text, model)` accepts
either synchronous or awaitable-returning callables. Both scan input, call the provider
only on acceptance, then scan the complete output. They do not retry, stream, call tools,
or issue network requests themselves. Callback invocation is the privacy boundary chosen
by the application. A callback exception yields an output ERROR with a generic reason;
original exception messages are discarded.

| Outcome | Deliverable text | Meaning |
| --- | --- | --- |
| ALLOW | Present, possibly empty | All configured checks passed without signals |
| WARN | Present | A configured signal exists; the application permits delivery |
| REDACT | Present after edits | At least one scanner transformed text |
| BLOCK | None | Policy rejected the content |
| ERROR | None | Checks could not complete reliably |

The aggregate priority is ERROR > BLOCK > REDACT > WARN > ALLOW. Individual findings and
trace entries preserve lower-priority decisions. The first BLOCK/ERROR stops the stage;
later scanners do not run. A REDACT result can still contain warnings from other scanners.
Unconfigured stages simply pass bounded strings. `accepted` includes WARN and REDACT.

All four stages are independently callable with `scan(text, stage=Stage.INPUT/OUTPUT/RETRIEVAL/TOOL)`
and `ascan`; the default stage is INPUT. `run` and `arun` invoke input/output only.
Scan retrieved material before it enters model prompts, logs, or persistent state. A raw
tool-stage scan does not validate a name; use `ToolGuard` for the full tool check.

## PII phone modes

`PIIScanner(formats=("email", "phone", "ssn"), action=Action.REDACT,
phone_mode="contiguous")` keeps the existing contiguous international-phone policy by
default. The optional `phone_mode="formatted"` accepts literal `+`, a nonzero first
digit, 8–15 ASCII digits, single spaces/hyphens between digit groups, and at most one
balanced digits-only parenthesized group after the first group. That group requires
separators from neighboring groups: `+1 (202) 555-0123` is supported;
`+1(202)5550123` is outside the grammar. See the full
[formatted-phone contract and examples](formatted_phone.md).

`formats` still gates detection: choosing a phone mode does not enable `"phone"` when
it is absent. An unsupported mode raises `ValueError` at construction. Both modes
retain `pii_phone`, `[PII]`, the selected action, and scanner-input-revision character
offsets. Email and SSN behavior is unchanged. Malformed or overlong formatted
candidates, including dotted numeric continuations, produce no phone finding rather
than a contiguous-prefix match or automatic request rejection. This is bounded shape
detection, not country-code, allocation, or identity validation.

## Secret connection-URI mode

`SecretScanner(action=Action.BLOCK, connection_strings=False)` retains existing token and
private-key rules by default. The `0.1.8` source candidate adds the explicit
`connection_strings=True` mode for bounded PostgreSQL/MongoDB password-bearing URIs.
The argument requires an actual boolean, and enabled mode requires BLOCK. A later action
change away from BLOCK yields `connection_string_configuration_error` rather than WARN
or partial URI redaction. Configure scanners once; do not mutate them during use.

The mode recognizes `postgresql`, `postgres`, `mongodb`, and `mongodb+srv` schemes,
password-bearing authority userinfo and PostgreSQL query `password` keys. Findings use
`secret_postgresql_uri` / `secret_mongodb_uri`, cover the complete candidate, and retain
overlapping existing token findings with scanner-input-revision character offsets.
Unsupported syntax is not credential validation or an automatic error. See the
[connection-URI contract](connection_strings.md) for separator, template, wrapper and
percent-escape rules, false positives, and explicit JSON handling.

Enabled mode also bounds direct calls: 100,000 input characters, 8,192 characters per
candidate, and 256 candidate attempts independently of findings. The existing combined
256-finding cap still applies. Increasing `Guard.max_chars` does not relax these private
budgets. Overflow produces static, spanless `connection_string_limit_exceeded`; unexpected
scanner failures produce `scanner_error`. Guard withholds checked output on ERROR.

## Custom scanners

```python
from guardtrellis import Action, Check, Finding, Guard, Stage


class LengthNotice:
    name = "length_notice"

    def scan(self, text: str, *, stage: Stage) -> Check:
        if len(text) > 200:
            return Check(Action.WARN, (Finding("long_text"),))
        return Check()


guard = Guard(input_scanners=[LengthNotice()])
```

The `Scanner` protocol accepts a `Check` or an awaitable `Check`. Async scanners require
async entry points. Findings and scanner names use static ASCII identifiers (1–64 characters,
first character a letter). Their values must never contain text or credentials, even if
the value would fit that syntax. A custom scanner is trusted application code, not a sandbox.

Every non-ALLOW Check needs at least one finding. A REDACT Check also needs edits, while
other actions may not contain edits. `Edit(start, end, replacement)` uses half-open
character indices. Edits must be in bounds, nonempty, and non-overlapping. The orchestrator
sorts and applies them from right to left; invalid responses yield ERROR. Built-in scanners
merge overlapping matches into one replacement while retaining all findings. Empty
replacement strings delete characters. No original matched strings are kept in result objects.

A finding's offsets reference that scanner's **input revision**, starting at revision 0.
Every REDACT step increments the revision, including length-preserving edits. A trace entry
records before/after revisions and the scanner's zero-based position within the stage. A
spanless finding refers to the entire check (e.g. schema failure). There is no cross-revision
offset mapping, input snapshot, or automatic rehydration.

## Limits and asynchronous work

The default maximum is 100,000 Python characters, checked before a stage and after each
edit. It is not a byte, token, request-body, or provider-allocation limit. The callback has
already produced its complete output before that output's size is checked. There is a cap
of 256 findings/edits per scanner. Literal configuration permits 1–128 strings of 1–1024
characters each. Limit failures yield ERROR, without usable output. Use Guard rather than
calling scanners directly to get the shared text-size and scanner-failure protections.
The opted-in connection-URI mode additionally enforces its own direct-call budgets and
static errors as described above; other scanner defaults are unchanged.

Async waits default to 5 seconds **per scanner or callback**, so a multi-step run can take
longer. Sync work runs in the event loop's thread executor with a copy of the caller's
context variables; awaitable results are then awaited on the caller's event loop.
On timeout, Guard cancels the task and returns ERROR without
accepting late results. Caller cancellation propagates as `CancelledError`.

Neither cancellation nor a returned timeout forcibly stops Python code. Threads can keep
running, retain input, and perform side effects; even loop shutdown may wait for them. A
coroutine that monopolizes the event loop delays the deadline. An operation can continue
if it suppresses cancellation. Apply admission limits, provider-native timeouts, and process
isolation where these behaviors are unacceptable. Synchronous entry points do not enforce
execution deadlines. Guard does not provide concurrency or rate limiting.

The [bounded resource measurements](resource_limits.md) reproduce input/finding limits,
expensive schema behavior, and work continuing after timeout or cancellation. Use the
recorded observations to choose host controls; they are not a production capacity estimate.

## JSON and tool calls

`JSONScanner()` accepts all JSON top-level types unless `require_object=True`. No Markdown
fence stripping or automatic repair occurs. Duplicate keys (including escaped aliases),
NaN, Infinity, overflow to infinite floats, trailing data, and invalid syntax are blocked.
Finite fractional numbers use Python floats; very large integers follow the interpreter's
integer conversion limit. Container depth defaults to 32, configurable from 1 through 64;
brackets inside strings do not count.

Schemas use `jsonschema.Draft202012Validator`, with these explicit restrictions:

- Only Draft 2020-12 (or an omitted `$schema`) is accepted in schema positions.
- `$ref` and `$dynamicRef` must be fragment references starting with `#`. No network or
  filesystem retrieval is configured. Missing/cyclic unresolvable references yield ERROR.
- `pattern` and `patternProperties` are rejected, including in nested schema positions.
  There is no unsafe regex opt-in. `format` is an annotation, not a check.
- Configured schemas are snapshotted, limited to 100,000 serialized characters and depth 64,
  and checked at construction. Bad configurations raise a generic ValueError. Unknown
  annotation keywords follow jsonschema's behavior and are not extra validators.
- Schema mismatch findings omit instance contents, values, and property paths. The code
  `json_schema_mismatch` is intentionally coarse because keys may themselves be sensitive.

`ToolGuard({"name": schema}, argument_scanners=[...])` uses exact, case-sensitive names.
An unknown name blocks before parsing. Arguments must be JSON text, not pre-parsed dicts,
so duplicate keys can still be detected. It checks JSON syntax/object type, runs optional
argument text scanners, then validates the transformed JSON against the selected schema.
`validate` / `avalidate` return `ToolResult`. Only accepted results carry a name and parsed
argument dict. `require_call()` returns that checked pair. Execute that pair only after
your own authorization checks; this package never dispatches tool code. Treat the returned
arguments as read-only until use: later caller mutations are not revalidated.

`avalidate()` applies `timeout_seconds` separately to the syntax scanner, each argument
scanner, and the final schema scanner; it is not a deadline for the complete validation
or tool execution. Scanner exceptions or malformed checks yield ERROR with
`scanner_error`; an expired scanner wait yields ERROR with `scanner_timeout`. BLOCK and
ERROR results expose neither a tool name nor arguments, and `require_call()` raises
`Rejected`. Redaction is accepted only if the edited JSON still satisfies the schema.

Caller cancellation propagates as `CancelledError`, without returning a dispatchable
result. A timed-out or cancelled scanner may continue running in a thread or suppress
coroutine cancellation; its late result cannot release a checked call. Scanners are
trusted code: their own side effects are not undone or prevented by this handoff contract.
The caller must await validation, authorize the checked pair, then dispatch that pair;
dispatching original arguments or scheduling execution before validation bypasses it.
Apply caller-owned execution budgets and isolation as described in
[limits and asynchronous work](#limits-and-asynchronous-work).

Reference behavior follows the upstream [jsonschema referencing documentation](https://python-jsonschema.readthedocs.io/en/stable/referencing/).
