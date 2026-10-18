# Checking two decoded contact fields

The [offline contact example](../examples/decoded_contact.py) handles one proposed tool
call through current public GuardTrellis APIs. It is an application-owned synchronous
helper, not a new SDK entry point or an automatic change to `ToolGuard`.
The maintainer accepted this bounded [#50](https://github.com/sahilmathur254/guardtrellis/issues/50)
design on 2026-10-18; [#62](https://github.com/sahilmathur254/guardtrellis/issues/62) tracks
the implementation and comparison. The [decision record](decoded_json_design.md#accepted-contact-comparison-50)
keeps the general structured-data SDK proposal deferred.

These fabricated proposals have the same decoded contact fields:

```json
{"email":"casey@example.org","phone":"+447700900123"}
{"email":"casey\u0040example.org","phone":"\u002b447700900123"}
```

The helper checks decoded values, so both produce the checked pair
`("contact", {"email": "[PII]", "phone": "[PII]"})`. The host still decides whether the
checked call is authorized. Decoding closes a representation gap for the configured
signatures; it does not validate contact details or add phone-number formats to the SDK.

Run the credential-free local example with core dependencies:

```sh
uv sync --frozen --group dev
uv run --frozen python examples/decoded_contact.py
```

The local callbacks make no network calls and need no provider or framework. Distribution
smokes run this example against installed wheels and source archives in core-only and
all-extras environments.

## Fixed input and whole-call limits

`check_contact(name, arguments_json)` accepts only the exact tool name `contact` and
serialized JSON text. Its trusted schema permits exactly two required strings: `email`
and `phone`. They must be nonempty and at most 254 and 64 Python characters respectively.
Their names describe the application fields; the schema checks shape and length, not
email-address syntax, phone-number validity, ownership, reachability, or identity.

| Boundary | Limit |
| --- | --- |
| Original serialized arguments | 4,096 Python characters |
| JSON nesting | Two container levels; the field schema still rejects nested values |
| Decoded fields, before and after edits | `email`: 1–254 characters; `phone`: 1–64 characters; 318 aggregate characters |
| Content scanning | Four fixed scanner invocations at most, with 1,024 cumulative input characters presented to scanners |
| Findings | 16 across the whole call; overflow rejects instead of truncating |
| Fresh serialized arguments | 4,096 characters, checked before final validation |

Budgets apply to the complete call, not independently to each field or scanner. A block
may stop the call before all four invocations. Input and post-edit length checks, cumulative
work accounting, findings accounting and final schema validation all remain required.
These deterministic limits bound admitted work. They do not impose a hard execution
deadline on a synchronous scanner, schema check, authorization callback or execution callback.

## Follow only the checked delivery

The helper has a fixed policy, with no arbitrary scanner list, decoder or field-selection
argument:

1. Preflight the original arguments through `ToolGuard` without text scanners, then
   consume `require_call()` before reading either field. This checks the exact tool name,
   serialized bounds, strict JSON, duplicate decoded keys and the original schema. It
   rejects both ordinary duplicate names and escaped equivalents such as `"email"` and
   `"\u0065mail"`. Redaction cannot repair an invalid original into a valid call.
2. Reject unpaired Unicode surrogates. Treat a valid surrogate pair as one decoded JSON
   value and decode exactly one JSON layer. A literal backslash sequence such as
   `\\u0040` in the wire JSON remains literal `\u0040` text after decoding; it is never
   interpreted a second time.
3. Run `SecretScanner` on `email`, then on `phone`, before either field reaches PII
   redaction. Next run `PIIScanner` on `email`, then on `phone`, with email and contiguous
   international-phone patterns enabled and SSN matching disabled. Both patterns apply to
   both fields. All four invocations use `Stage.TOOL` and existing public `Guard` APIs.
   Consume only accepted `require_text()` values and recheck the field, aggregate, work
   and findings limits throughout the operation.
4. Construct a fresh object from the checked strings. Serialize compact JSON with
   `ensure_ascii=False` and `allow_nan=False`, reject invalid transformed Unicode or
   limits, and run the same name/schema validation again. No partial checked object or
   original argument string is a fallback if any stage fails.
5. Return an accepted `ContactResult`. Its `require_call()` exposes only the final
   checked name and fresh arguments. `run_workflow(name, arguments_json, authorize, execute)`
   consumes that pair, passes a copy of its dictionary to host authorization, and then
   passes the checked arguments to execution only if authorization returns the boolean
   `True`. Mutation of the authorization copy cannot change dispatched arguments.

Any rejected check raises payload-free `Rejected` before authorization or execution.
Wrong tool names, malformed JSON, duplicate keys, wrong types, extra fields, schema failures,
unpaired surrogates, scanner blocks/errors and any limit failure prevent dispatch.
There is no success response containing partially checked fields.
Denied authorization raises a fixed-message `PermissionError`; callback failures raise a
fixed-message `WorkflowError`, with displayed exception chaining suppressed. The helper
does not undo execution side effects. Python may retain original exception contexts and
locals in memory; configure application error reporters accordingly.

## Keep decoded evidence separate from wire validation

`ContactResult.action` preserves the aggregate decoded content outcome, including REDACT.
Its `.final` is the separate `ToolResult` for the fresh serialized arguments. That final
validation can report ALLOW after decoded content was redacted; it has no content scanners
and does not describe the preceding content policy.

The helper's finding envelopes use opaque field IDs (`field-0`, `field-1`), pass indices,
decoded revisions and half-open Python-character offsets within the decoded string at that
revision. They do not use source property names or claim positions in serialized JSON.
Offsets from different fields, revisions or boundaries cannot be combined or applied to
the original wire text. The result keeps decoded findings separate from `.final.findings`.

Use `diagnostics()` for metadata-only action, finding and work counts. The result's `repr`
also suppresses payloads. Explicit whole-object serialization such as `dataclasses.asdict()`
includes the checked arguments inside `.final`; it is not a logging interface. Do not log
original arguments, checked contact strings, callback exceptions or payload-bearing local
variables. Opaque IDs, offsets and counts still disclose limited structure. Suppressed reprs
and fixed messages are logging boundaries, not memory erasure.

## Reproduce the comparison and retain the limits

The [contact comparison](../evaluation/decoded_contact/README.md) runs the same two-field
meanings through raw serialized scanning, separate uses of the existing single-field query
recipe, and the fixed contact helper. Run a fresh report outside the checkout:

```sh
uv run --frozen python evaluation/decoded_contact/run.py \
  --report-dir /tmp/guardtrellis-decoded-contact-v1
```

Each profile has its documented policy and handoff behavior. The comparison is authored
development evidence, not an independent benchmark or a scanner performance comparison.
The [0.1.4 baseline](../evaluation/policy_combinations/coverage_baseline_0.1.4/REPORT.md)
and earlier corpora remain unchanged.

The helper decodes one JSON layer and does not normalize Unicode, scan keys, traverse nested
objects or arrays, parse embedded JSON, decode base64 or recursively unescape strings.
The current PII scanner can still miss spaced, hyphenated or otherwise unsupported phone
formats. Those detector changes remain [#60](https://github.com/sahilmathur254/guardtrellis/issues/60)
work; the comparison must retain their misses. Name recognition, internationalized email,
semantic injection detection and comprehensive sensitive-data removal are not provided.

This recipe and its evaluation fit a `0.1.5` patch candidate because they use current SDK
contracts. Publication status is recorded on [PyPI](https://pypi.org/project/guardtrellis/)
and [GitHub releases](https://github.com/sahilmathur254/guardtrellis/releases); this guide
does not establish that publication has happened. A shared structured-data SDK abstraction
still needs a separate contract and versioning decision at the proposed `0.2.0` boundary.
See the [API guide](api.md#json-and-tool-calls), [limitations](limitations.md), and
[host resource controls](resource_limits.md).
