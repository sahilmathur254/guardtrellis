# Policy and delivery evaluation: policy-delivery-v1

Authored, AI-assisted synthetic development cases; no independent or native-language review.
These selected cases do not establish general accuracy, authorization or production safety.
Only metadata and equality checks are reported; fixture and delivered payloads are omitted.

Generated: 2026-09-29T15:58:51.536275+00:00
GuardTrellis 0.1.2; Python 3.12.0; Darwin arm64; jsonschema 4.26.0.
corpus_sha256: `ae0b9d7f183b3b77a52d595ee8b28dbda60ad95d6cae023663c2d583d64f9511`.
source_sha256: `ce14e7979cf9c1105f98e845e4a10c9b8c363a0759bffd48f607674b30d34ebd`.
runner_sha256: `5c11aa50754c053270179caa4d139a549cf0d6437702134469fb6fc4b1d2451d`.
lockfile_sha256: `6591feedf8314ab12622c1c29d958cd33210d49c3a680ae980c1cd6bfba67384`.
Policy: Fixed named synchronous profiles in run.py; local synthetic callbacks and dispatch recorders only. No decoded JSON-value scanning, network calls or performance claims.

| Family | N (+/−) | TP | FP | TN | FN | Errors (expected/unexpected) | Mismatches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| secrets | 8 (6/2) | 5 | 1 | 1 | 1 | 0/0 | 2 |
| json | 6 (5/1) | 4 | 0 | 1 | 1 | 0/0 | 1 |
| ordering | 4 (4/0) | 4 | 0 | 0 | 0 | 0/0 | 0 |
| delivery | 6 (5/1) | 4 | 0 | 1 | 1 | 0/0 | 1 |
| tool | 7 (7/0) | 6 | 0 | 0 | 1 | 0/0 | 1 |
| errors | 3 (3/0) | 0 | 0 | 0 | 0 | 3/0 | 0 |
| overall | 34 (30/4) | 23 | 1 | 3 | 4 | 3/0 | 5 |

## Actions and delivery

WARN permits delivery; REDACT permits checked content; BLOCK/ERROR withhold content.
Callbacks may have run before an OUTPUT rejection; an INPUT rejection prevents them.

| Family | ALLOW | WARN | REDACT | BLOCK | ERROR | Callbacks | Dispatches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| secrets | 2 | 1 | 1 | 4 | 0 | 0 | 0 |
| json | 2 | 0 | 1 | 3 | 0 | 0 | 0 |
| ordering | 0 | 0 | 2 | 2 | 0 | 0 | 0 |
| delivery | 2 | 0 | 2 | 2 | 0 | 5 | 0 |
| tool | 1 | 0 | 1 | 5 | 0 | 0 | 2 |
| errors | 0 | 0 | 0 | 0 | 3 | 1 | 0 |

## Retained outcomes and expectation mismatches

Signals and action/delivery expectations are separate. ERROR is not a detection.
FP/FN describe authored scenario intent, including benign lookalikes and unsupported
formats. They are not automatically SDK contract defects. Exact comparison fields
include checked text, callback inputs, delivered results, dispatches and selected
revision-aware finding spans/traces. See JSON results for every comparison.

- `secret-documentation-lookalike`: **fp**; action `block`; mismatches: action, accepted, checked_text, delivered; privacy failures: none. Explicitly non-secret teaching text is a benign contextual challenge even though a detector may match its signature.
- `secret-unsupported-assignment`: **fn**; action `allow`; mismatches: action, accepted, checked_text, delivered; privacy failures: none. Scenario requests prevention of a password assignment; generic assignment detection is outside current signatures and a miss must remain visible.
- `json-escaped-email-miss`: **fn**; action `allow`; mismatches: action, checked_text, delivered; privacy failures: none. The decoded value is the same email as its plain pair; scenario expects redaction despite the raw-text decoding gap.
- `delivery-spaced-phone-miss`: **fn**; action `allow`; mismatches: action, checked_text, callback_inputs; privacy failures: none. The spaced representation is the same fabricated contact; retaining a positive expectation exposes the unsupported format.
- `tool-escaped-email-miss`: **fn**; action `allow`; mismatches: action, checked_text, delivered, dispatches; privacy failures: none. Decoded tool arguments contain the same email as the plain pair; a raw-text miss can dispatch the original contact.
- `error-input-scanner`: **error**; action `error`; mismatches: none; privacy failures: none. An intentionally failing scanner includes input in its exception; SDK results must fail closed without echoing it.
- `error-callback`: **error**; action `error`; mismatches: none; privacy failures: none. A callback failure occurs after invocation; the SDK error and rejection surfaces must omit its message.
- `error-tool-scanner`: **error**; action `error`; mismatches: none; privacy failures: none. A scanner error on arguments must withhold dispatchable data and its exception payload.

Privacy failures: 0; harness failures: 0.
Failed diagnostic privacy checks suppress that diagnostic surface in the report.
Exit 0 means the harness completed without privacy failures or unexpected errors;
it does not mean all scenario expectations passed. Known FP/FN and mismatches remain.
