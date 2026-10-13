# Checking one decoded search query

JSON escape sequences can hide a matching value from a scanner that sees serialized
characters. For example, these fabricated proposals decode to the same query:

```json
{"query":"Contact casey@example.org"}
{"query":"Contact casey\u0040example.org"}
```

The [offline example](../examples/decoded_query.py) checks that one decoded field through
existing public GuardTrellis APIs. Both proposals produce the final checked call
`("search", {"query": "Contact [PII]"})`. This is an application-owned recipe: it adds no
SDK runtime API, scanner behavior, or recursive structured-data traversal.

Run it with core dependencies:

```sh
uv sync --frozen --group dev
uv run --frozen python examples/decoded_query.py
```

The callbacks use fabricated data and local values. The example makes no network calls
and needs no provider, framework, or credentials. Runnable-example tests and distribution
smokes execute it against both installed package formats, including core-only environments.

## Follow the checked value through each boundary

The trusted schema allows the exact tool name `search` and an object containing only a
required string `query`, with a decoded length of 1–200 Python characters. The recipe uses
these explicit bounds:

| Boundary | Limit |
| --- | --- |
| Original serialized arguments | `MAX_JSON_CHARS = 4096` Python characters |
| JSON parser nesting | `MAX_DEPTH = 2` container levels; the schema still rejects nested fields |
| Decoded query and transformed query | `MAX_QUERY_CHARS = 200` Python characters |
| Fresh serialized arguments | `MAX_OUTPUT_CHARS = 4096` Python characters, checked again before acceptance |

`check_query(name, args_json, *, query_guard=QUERY_POLICY)` follows this sequence:

1. Preflight the original argument string through `ToolGuard`, configured without argument
   text scanners. Consume its `require_call()` pair before reading `query`. This checks the
   exact tool name, strict JSON, duplicate decoded keys, schema, serialized size, and depth.
   Invalid originals cannot be repaired into accepted arguments by redaction.
2. Reject unpaired surrogates in the decoded query, then scan that string with
   `Guard.scan(..., stage=Stage.TOOL)`. The default policy blocks selected secret signatures
   before redacting supported ASCII email patterns. Consume only `require_text()`.
3. Reject unpaired surrogates and oversized transformed text. Construct a fresh
   `{"query": checked_text}` object and serialize it as compact new JSON with
   `ensure_ascii=False` and `allow_nan=False`. Unicode literals remain UTF-8-safe after
   the surrogate check. Do not reuse the original JSON string or decoded object.
4. Validate that fresh JSON through `ToolGuard` again. This rechecks size, depth, name,
   and the 1–200-character string schema after the edits. Return only that final
   `ToolResult`; the next consumer must call its `require_call()`.

`run_workflow(name, args_json, authorize, execute, *, query_guard=QUERY_POLICY)` consumes the
final checked name and arguments, asks the host's `authorize(name, arguments)` callback for
permission with a copy of the checked dictionary, then passes the final checked dictionary
to the local `execute(name, arguments)` callback. Mutating the authorization copy cannot
alter the dispatched arguments. The authorization callback must return the boolean `True`;
other values deny the request. A valid schema is not permission to execute. A denied
authorization raises `PermissionError("Tool request is not authorized")` and prevents
execution. Any rejected check raises `Rejected` before authorization or execution;
there is no fallback to the original proposal.

The optional `query_guard` is trusted application configuration. Use its `tool_scanners`
and choose bounded processing appropriate to the host; the recipe still rechecks transformed
length and the final schema. `WARN` deliberately permits the checked query to continue.
Only the fixed `query` field receives this policy; the recipe does not select fields from
untrusted input or traverse nested objects and arrays.

## Keep locations and diagnostics separate

A finding from the decoded-field scan uses offsets into that decoded query and its input
revision. Those offsets cannot be applied to the original JSON string or the fresh serialized
JSON. The example keeps decoded-query results separate internally and never merges their
findings into the final `ToolResult`. The returned result describes final validation, not
an aggregate of every check; its diagnostics refer to the fresh serialized arguments.
An accepted final validation can therefore report `ALLOW` even when the earlier decoded
query scan redacted content.

Use `diagnostics()` if metadata is needed. Do not serialize whole results, log the original
proposal, log callback exceptions, or treat suppressed reprs as memory erasure. Custom
scanner names and finding codes must be static trusted metadata. Offsets and lengths can
still reveal structure; decoded offsets must retain their boundary and revision if a host
records them separately.

Callback failures raise a fixed-message `WorkflowError` with displayed exception chaining
suppressed. Python can retain the original exception context and locals in memory; configure
error reporters accordingly. Execution may have side effects before it fails, and this
example supplies no rollback, deadline, sandbox, output check, or execution budget.

## Scope of the evidence

The recipe decodes JSON escapes once. It rejects unpaired surrogates, permits valid Unicode
surrogate pairs, and does not normalize Unicode, decode base64, parse embedded JSON, or
interpret a literal `\u0040` sequence a second time. It closes the escaped-value gap for
configured signatures in this one field; it does not add name detection, internationalized
email matching, arbitrary phone-format detection, semantic injection detection, or a general
guarantee that sensitive values are removed.

The focused boundary tests cover equivalent plain/escaped inputs, strict JSON and schema
rejection, transformed-value validation, policy failure, resource limits, and checked callback
delivery. Synthetic observations demonstrate this recipe's behavior only. Historical
evaluation corpora and their recorded misses remain unchanged. A nested or multi-field
caller needs a separately scoped design and validation; the [decoded-JSON decision](decoded_json_design.md)
records that possible future work. See the [tool API](api.md#json-and-tool-calls),
[limitations](limitations.md), and [host resource controls](resource_limits.md).
