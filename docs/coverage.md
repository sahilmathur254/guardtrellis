# Control coverage and evidence

Snapshot: 2026-10-27. The published baseline is
[`0.1.8`](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.8), which adds
explicit connection-URI detection while preserving default scanner rules. The Gemini
example's explicit continuation control shipped in `0.1.7`; applications with copied
examples must adopt that code separately. See the [changelog](../CHANGELOG.md) and
[package availability](https://pypi.org/project/guardtrellis/).

These matrices connect configured behavior to implementation, regression cases and
retained evidence. Tests describe the checked contracts; consult the relevant CI run
for execution status. Historical reports retain their own source versions, hashes,
policies and platforms. None is a general accuracy estimate or proof of host enforcement.

## Detection and structured values

| Configured boundary | Source and evidence | Coverage limits and application choices |
| --- | --- | --- |
| `PIIScanner()` redacts selected ASCII email, contiguous international `+` phone and hyphenated US SSN shapes. `formats` selects the families. | [Implementation](../src/guardtrellis/scanners.py), [format/benign tests](../tests/test_scanners.py), [retained Unicode challenge](../evaluation/challenges/unicode_pii_v1/REPORT.md). | No name, address or credit-card detection; no identifier issuance, phone ownership or comprehensive de-identification. Default phones can match only a prefix of an unsupported formatted value. |
| `phone_mode="formatted"`, added in `0.1.6`, accepts bounded ASCII groups: literal `+`, 8–15 digits with a nonzero first digit, single spaces/hyphens and at most one separated parenthesized digit group. | [Grammar and exclusions](formatted_phone.md), [complete-span/default-preservation tests](../tests/test_formatted_phone.py), [retained comparison](../evaluation/formatted_phone/baseline_0.1.6/REPORT.md). | Malformed separators/parentheses and excessive digits in this ASCII grammar produce no phone finding, rather than a shorter prefix finding or automatic rejection. Excluded forms such as extensions and NBSP/zero-width separators can still receive partial redaction. Country validity and signed-integer ambiguity remain unresolved. |
| `SecretScanner()` blocks selected GitHub token signatures, AWS access-key IDs and PEM private-key envelopes. | [Implementation](../src/guardtrellis/scanners.py), [signature/envelope tests](../tests/test_scanners.py), [retained misses](../evaluation/REPORT.md#retained-failures-and-false-positive-challenges). | A match does not verify a live credential. Arbitrary passwords, generic bearer tokens, changed lengths and encodings can be missed. An AWS access-key ID is not its secret component. |
| `SecretScanner(connection_strings=True)`, released in `0.1.8`, adds BLOCK-only PostgreSQL/MongoDB userinfo and PostgreSQL query passwords. | [Grammar and limits](connection_strings.md), [implementation](../src/guardtrellis/_connection_strings.py), [scanner/delivery tests](../tests/test_connection_strings.py), [opt-in comparison](../evaluation/connection_strings/OPT_IN.md), [bounded probes](../evaluation/connection_strings/resources.py). | Explicit opt-in; defaults stay unchanged. Complete URI findings coexist with overlapping token findings. Placeholder/mask and malformed-URI false positives are intentional. No driver/credential validation, network access, generic URL secrets, implicit JSON decoding or selective redaction. Private work limits can produce ERROR even with a larger Guard input limit. |
| `InvisibleScanner()` warns on Unicode Cc/Cf except tab/CR/LF; `LiteralScanner` matches configured substrings with optional ASCII case folding. | [Implementations](../src/guardtrellis/scanners.py), [joiner/literal/offset tests](../tests/test_scanners.py), [Unicode challenge](../evaluation/challenges/unicode_pii_v1/REPORT.md). | WARN permits unchanged delivery. Joiners can be legitimate; removing them can damage text. Literal matches do not establish semantic prompt-injection detection, Unicode normalization or regex support. |
| `JSONScanner` checks strict JSON and an optional constrained Draft 2020-12 schema. Duplicate keys, non-finite values and excess nesting are rejected. | [Parser/schema implementation](../src/guardtrellis/json_check.py), [strict parsing/schema tests](../tests/test_json_tools.py), [API contract](api.md#json-and-tool-calls). | Schemas are trusted configuration, references are document-local, regex keywords are disallowed and `format` is only an annotation. Valid JSON does not establish safe values, commands or URLs. Text scanners still inspect serialized characters. |
| The decoded-query (`0.1.3`) and decoded-contact (`0.1.5`) recipes check selected strings after one JSON decode, then rebuild and revalidate the checked call. | [Query helper](../examples/decoded_query.py) and [tests](../tests/test_decoded_query_example.py); [contact helper](../examples/decoded_contact.py), [tests](../tests/test_decoded_contact_recipe.py) and [retained comparison](../evaluation/decoded_contact/baseline_0.1.5/REPORT.md). | Application-owned fixed schemas, not a shared recursive SDK API. No key scanning, repeated decoding or general nested traversal. The contact helper checks secrets across both fields before PII and retains its fixed contiguous-phone policy. Decoded offsets are not wire-text offsets. |

## Delivery and operations

| Configured boundary | Source and evidence | Coverage limits and host responsibilities |
| --- | --- | --- |
| The CLI added in `0.1.9` selects one fixed secrets/privacy policy and text stage, with explicit bounded file/stdin ingress and metadata/checked-text output. | [CLI guide](cli.md), [implementation](../src/guardtrellis/_cli.py), [transport/policy tests](../tests/test_cli.py), [URI handoff tests](../tests/test_cli_connection_strings.py), [strict CI consumer](../examples/cli_ci.py), [installed smokes](../scripts/smoke_dist.py). | [#78](https://github.com/sahilmathur254/guardtrellis/issues/78) tracks native CI/review evidence. No detector expansion, implicit JSON decode, input rewrite or hard process deadline. REDACT exits zero; checked stdout must be discarded on nonzero. TTY output is rejected; subsequent rendering and shell redirection remain host concerns. |
| `Guard.run` / `arun` check input before the callback and complete output before delivery. BLOCK/ERROR withhold that boundary's text; accepted data is obtained through `require_text()`. | [Guard implementation](../src/guardtrellis/guard.py), [delivery/order/rejection tests](../tests/test_guard.py), [policy/delivery baseline](../evaluation/policy_combinations/baseline_0.1.2/REPORT.md). | Configure every required stage: `Guard()` has no implicit scanners. WARN permits delivery; REDACT permits transformed text. Consume checked values instead of originals. There is no streaming API, and output checks cannot undo callback side effects. |
| `ToolGuard` checks exact tool names, JSON syntax/object type, configured argument text policies, then the edited schema. `require_call()` exposes only accepted pairs. | [ToolGuard implementation](../src/guardtrellis/tools.py), [schema/redaction tests](../tests/test_json_tools.py), [async handoff tests](../tests/test_async_tools.py). | It does not execute or authorize tools. The application must authorize the final checked pair and avoid later mutation; returned argument dictionaries are not revalidated after caller edits. Escaped sensitive values need explicit decoded handling. |
| The `0.1.4` tool-result recipe checks returned text at RETRIEVAL before state insertion or the next consumer. | [Recipe](../examples/tool_result_handoff.py), [no-dispatch/state/privacy tests](../tests/test_tool_result_handoff_example.py), [handoff guide](tool_result_handoff.md). | Tool argument validation does not check the return value. This recipe covers plain text, not arbitrary structured results. Earlier logs, caches, execution and raw-value fallback paths remain application responsibilities. |
| Guard bounds Python character counts and per-scanner findings/edits. Async waits apply separately to each scanner/callback. After Guard returns timeout ERROR, late results cannot release checked data. | [API limits](api.md#limits-and-asynchronous-work), [timeout/cancellation tests](../tests/test_guard.py), [async tool tests](../tests/test_async_tools.py), [resource evidence](resource_limits.md). | Character limits are not ingress-byte/token limits. Sync calls have no deadline. Cancellation cannot forcibly stop threads, remote requests or event-loop-blocking code; blocking the event loop can delay timeout handling and allow a result after the configured interval. The host owns admission, concurrency, provider timeouts and process containment. |
| Built-ins perform local checks without network calls, application logging or a request store. `diagnostics()` and built-in reprs omit payload text. | [Result implementation](../src/guardtrellis/models.py), [error/privacy tests](../tests/test_guard.py), [privacy and operations](limitations.md#privacy-and-operations). | Accepted text/arguments remain payload-bearing properties. Metadata includes offsets/counts; repr suppression is not secure erasure. Custom scanners, callbacks, provider SDKs, tracing, debuggers and host logs need their own controls. |
| Optional OpenAI/Azure/Gemini examples pass checked input across mocked HTTP boundaries and check complete output. The Gemini example disables automatic continuation as of `0.1.7`. | [OpenAI tests](../tests/test_openai_example.py), [Azure tests](../tests/test_azure_openai_example.py), [Gemini HTTP tests](../tests/test_gemini_example.py), [Gemini implementation](../examples/gemini_app.py). | Callback counts alone do not prove HTTP request counts. OpenAI/Azure are mock-verified; the [dated Gemini live smoke](gemini.md#recorded-live-smoke-2026-09-26) used older source/SDK versions. The continuation regression is mocked, not a new live trial. Provider retention, billing and side effects remain outside Guard's control. |

## Reading measurement evidence

The [48-scenario detector/delivery batch](../evaluation/detector_delivery/README.md)
for #45 freezes expectations before observation and separates primary-family findings,
incidental PII, complete desired protection and documented contracts. Its 384 observations
are correlated development evidence with author self-review only; #45 and its linked
PR track current native CI/review results. It preserves SDK behavior and historical reports.

The [evaluation guide](../evaluation/README.md) separates detection signals, complete
redaction and checked delivery. The original [72-case report](../evaluation/REPORT.md),
[40-case challenge](../evaluation/challenges/unicode_pii_v1/REPORT.md),
[policy/delivery baseline](../evaluation/policy_combinations/baseline_0.1.2/REPORT.md),
[escaped-JSON/phone baseline](../evaluation/policy_combinations/coverage_baseline_0.1.4/REPORT.md),
and contact/phone comparisons above are authored development evidence. Their misses,
false positives and failed desired outcomes remain visible. A successful runner exit
does not imply complete detection or an independent held-out benchmark.

The separate [bounded concurrency protocol](../evaluation/concurrency/README.md) under
[#45](https://github.com/sahilmathur254/guardtrellis/issues/45) uses existing `Guard.arun`
with fixed admission limits. Its [0.1.7 candidate baseline](../evaluation/concurrency/baseline_0.1.7/REPORT.md)
records 720/720 exact checked-delivery outcomes across twelve cells and 36 completed,
reaped children on macOS / Python 3.12.0. The raw metadata retains source hashes,
environment, measurement boundaries and observations. These repeated synthetic requests
do not establish general detection accuracy, native Windows execution, universal latency,
service capacity or production reliability.

The original `0.1.7` matrix contributed to
[#46](https://github.com/sahilmathur254/guardtrellis/issues/46) without changing detector
behavior. The connection-URI row now records the explicitly enabled `0.1.8` source change.
Broader evaluation and positioning work remain open. This matrix adds no vendor ranking,
threat-framework certification, compliance claim or wider API promise.
