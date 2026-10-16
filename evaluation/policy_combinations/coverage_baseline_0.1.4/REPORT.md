# Policy and delivery evaluation: detection-coverage-v1

Authored, AI-assisted synthetic development cases; no independent or native-language review.
These selected cases do not establish general accuracy, authorization or production safety.
Only metadata and equality checks are reported; fixture and delivered payloads are omitted.

Generated: 2026-10-16T12:43:51.552311+00:00
GuardTrellis 0.1.4; Python 3.12.0; Darwin arm64; jsonschema 4.26.0.
corpus_sha256: `1e30f87c5639b938f5fffae6aa84273a74415eb7293b0ee56021b6d5f426b7eb`.
source_sha256: `3ae877bff92e933ed0c28a1843f20c7db79573cdac3212da8f822875f883fc07`.
runner_sha256: `43783efa5f58df9498c74ac69109c44b86f9fd2eb8e303368707959170245af3`.
lockfile_sha256: `e1a3f56e032013d39d7c30d7337f2d561c29afaaa042db15f743c8cd45707cf5`.
Policy: Fixed named synchronous profiles in run.py; local synthetic callbacks and dispatch recorders only. Raw query ToolGuard and configured decoded-query recipe use SecretScanner then PII email/phone; the shipped recipe default covers secrets/email. Decoded finding offsets are separate from serialized handoff offsets. No network calls or general accuracy claims.

| Family | N (+/−) | TP | FP | TN | FN | Errors (expected/unexpected) | Mismatches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| delivery | 39 (23/16) | 9 | 1 | 15 | 14 | 0/0 | 18 |
| tool | 24 (20/4) | 12 | 0 | 4 | 8 | 0/0 | 8 |
| overall | 63 (43/20) | 21 | 1 | 19 | 22 | 0/0 | 26 |

recipe_sha256: `f282f29603add46db47fe031e184c1dab3aeee7818c85608bc9df4986d0428f4`.
Decoded recipe signals use the captured decoded query policy result;
the final serialized handoff can be ALLOW after decoded redaction.
Decoded offsets are half-open Python character indices in the query string
and are never merged into serialized ToolResult finding coordinates.

## Local observation timing

3 warmups and 100 timed iterations per case; maximum 1000 timed iterations.
Setup-inclusive synchronous observations: policy construction, SDK/recipe checks, local callbacks, exact comparisons and privacy checks. Microseconds from perf_counter_ns; short synthetic inputs on this host, not scanner-only timing, capacity evidence or a deadline guarantee.

| Profile | Timed observations | p50 µs | p95 µs |
| --- | --- | --- | --- |
| decoded_query_pii | 1200 | 203.35 | 367.42 |
| run_pii | 3500 | 88.54 | 115.83 |
| run_pii_block | 200 | 84.27 | 91.17 |
| run_pii_warn | 200 | 108.31 | 117.04 |
| tool_query_pii | 1200 | 724.50 | 809.38 |

## Coverage by profile

| Profile | Cases | TP | FP | TN | FN | Mismatches |
| --- | --- | --- | --- | --- | --- | --- |
| decoded_query_pii | 12 | 8 | 0 | 2 | 2 | 2 |
| run_pii | 35 | 7 | 1 | 15 | 12 | 16 |
| run_pii_block | 2 | 1 | 0 | 0 | 1 | 1 |
| run_pii_warn | 2 | 1 | 0 | 0 | 1 | 1 |
| tool_query_pii | 12 | 4 | 0 | 2 | 6 | 6 |

## Actions and delivery

WARN permits delivery; REDACT permits checked content; BLOCK/ERROR withhold content.
Callbacks may have run before an OUTPUT rejection; an INPUT rejection prevents them.

| Family | ALLOW | WARN | REDACT | BLOCK | ERROR | Callbacks | Dispatches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| delivery | 29 | 1 | 8 | 1 | 0 | 38 | 0 |
| tool | 18 | 0 | 3 | 3 | 0 | 0 | 21 |

## Retained outcomes and expectation mismatches

Signals and action/delivery expectations are separate. ERROR is not a detection.
FP/FN describe authored scenario intent, including benign lookalikes and unsupported
formats. They are not automatically SDK contract defects. Exact comparison fields
include checked text, callback inputs, delivered results, dispatches and selected
revision-aware finding spans/traces. See JSON results for every comparison.

- `phone-spaces-redact`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-hyphens-redact`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-parentheses-redact`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-mixed-ascii-separators`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-multiple-with-emoji`: **tp**; action `redact`; mismatches: checked_text, callback_inputs, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-complete-span-hyphen-suffix`: **tp**; action `redact`; mismatches: checked_text, callback_inputs, findings; privacy failures: none. One explicitly labelled 15-digit international contact uses a final hyphen-separated group. Replacing only its contiguous prefix is incomplete redaction even if detection is a TP; no extension is designated.
- `phone-spaces-warn`: **fn**; action `allow`; mismatches: action, findings; privacy failures: none. Proposed spaced-phone detection under WARN must retain original input and delivery while returning a complete-span finding.
- `phone-hyphens-block`: **fn**; action `allow`; mismatches: action, accepted, checked_text, callback_inputs, delivered, findings; privacy failures: none. Proposed hyphenated-phone detection under BLOCK must prevent the callback and delivery.
- `phone-formatted-output`: **fn**; action `allow`; mismatches: action, delivered, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-formatted-eight-digits`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-formatted-fifteen-digits`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Explicit synthetic contact phone: detect and cover the complete literal span, preserve surrounding text and deliver only the checked callback input/output. Labels express scenario intent, not current detector behavior.
- `phone-signed-integer-context`: **fp**; action `redact`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Benign scenario label: this synthetic numeric/code value is not a contact phone; preserve it without a finding. Context labels intentionally expose possible signature-only false positives and do not promise semantic discrimination.
- `phone-nbsp-deferred`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Synthetic contact with non-breaking-space separators; desired complete protection remains labelled positive but this format is explicitly deferred from the first implementation slice. A partial prefix finding does not satisfy full-span redaction.
- `phone-zwsp-deferred`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Synthetic contact with an internal zero-width space; desired complete protection remains labelled positive but this format is explicitly deferred from the first implementation slice. A partial prefix finding does not satisfy full-span redaction.
- `phone-fullwidth-deferred`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Synthetic contact with fullwidth plus and digits; desired complete protection remains labelled positive but this format is explicitly deferred from the first implementation slice. A partial prefix finding does not satisfy full-span redaction.
- `phone-national-deferred`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Synthetic contact with national syntax without explicit country prefix; desired complete protection remains labelled positive but this format is explicitly deferred from the first implementation slice. A partial prefix finding does not satisfy full-span redaction.
- `phone-extension-deferred`: **tp**; action `redact`; mismatches: checked_text, callback_inputs, findings; privacy failures: none. Synthetic contact with an explicitly designated extension; desired complete protection remains labelled positive but this format is explicitly deferred from the first implementation slice. A partial prefix finding does not satisfy full-span redaction.
- `phone-verbal-deferred`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs, findings; privacy failures: none. Synthetic contact with a verbal country digit; desired complete protection remains labelled positive but this format is explicitly deferred from the first implementation slice. A partial prefix finding does not satisfy full-span redaction.
- `json-email-raw-escaped`: **fn**; action `allow`; mismatches: action, checked_text, delivered, dispatches; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.
- `json-phone-raw-escaped`: **fn**; action `allow`; mismatches: action, checked_text, delivered, dispatches; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.
- `json-formatted-phone-raw-plain`: **fn**; action `allow`; mismatches: action, checked_text, delivered, dispatches, findings; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.
- `json-formatted-phone-raw-escaped`: **fn**; action `allow`; mismatches: action, checked_text, delivered, dispatches; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.
- `json-formatted-phone-decoded-plain`: **fn**; action `allow`; mismatches: checked_text, delivered, dispatches, decoded_action, decoded_findings; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.
- `json-formatted-phone-decoded-escaped`: **fn**; action `allow`; mismatches: checked_text, delivered, dispatches, decoded_action, decoded_findings; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.
- `json-emoji-email-phone-raw-escaped`: **fn**; action `allow`; mismatches: action, checked_text, delivered, dispatches; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.
- `json-secret-raw-escaped`: **fn**; action `allow`; mismatches: action, accepted, checked_text, delivered, dispatches, checked_json_valid; privacy failures: none. Equivalent plain and escaped JSON decode to the same schema-valid synthetic object. Require identical completely checked dispatches; retain raw representation and phone-format misses as expectation mismatches. Decoded final ToolResult action ALLOW describes fresh serialization, not the earlier value-policy action.

Privacy failures: 0; harness failures: 0.
Failed diagnostic privacy checks suppress that diagnostic surface in the report.
Exit 0 means the harness completed without privacy failures or unexpected errors;
it does not mean all scenario expectations passed. Known FP/FN and mismatches remain.
