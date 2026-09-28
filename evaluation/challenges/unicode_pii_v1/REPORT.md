# Synthetic evaluation: unicode-pii-v1

These are authored synthetic fixtures, not an independent or adversarial benchmark.
Results measure this corpus only. They do not establish production safety or language coverage.
Fixture usage: development. See individual provenance and label bases.

Generated: 2026-09-27T10:32:09.243249+00:00
Python 3.12.0, Darwin arm64; GuardTrellis 0.1.0a3, jsonschema 4.26.0.
Corpus SHA-256: `f3f0a01e032b13a187c3304d39d44cc00b4d18ef5a847a97d1f8f6acab8f710a`.
Package source SHA-256: `afb8dd8adcd7ece005f942158d26eadff060da63aa95a6107363376a9a625b67`.
Runner SHA-256: `f56dc7d96877c638bfcb61a329b71f32469483ef7b1ecec57bfd8a0c4c904113`.
Lockfile SHA-256: `7897b17a83f573342046afb67a798ff7a6e8b432de69288255c11ec7fa807569`.
Unicode database: 15.0.0.
Policy: Fixed per-family INPUT policies from this runner: PII REDACT, secrets BLOCK, invisible WARN, literal BLOCK, JSON/tool structural validation. No JSON-value decoding, normalization, provider calls, or pipeline interaction checks.
40 cases, 100 timed scans per case, 3 warmups per case.

| Family | N (+/−) | TP | FP | TN | FN | Errors | Precision | Recall | FPR | p50 µs | p95 µs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| pii | 24 (17/7) | 9 | 2 | 5 | 8 | 0 | 81.8% | 52.9% | 28.6% | 3.5 | 5.7 |
| invisible | 16 (6/10) | 5 | 4 | 6 | 1 | 0 | 55.6% | 83.3% | 40.0% | 3.7 | 5.6 |
| overall | 40 (23/17) | 14 | 6 | 11 | 9 | 0 | 70.0% | 60.9% | 35.3% | 3.5 | 5.6 |

## Per-family and language results

Small, deliberately selected samples; no population or language accuracy estimate.
`zxx` denotes content with no linguistic language (such as emoji).

| Family | Language | N (+/−) | TP | FP | TN | FN | Errors | Precision | Recall | FPR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| pii | ar | 1 (1/0) | 1 | 0 | 0 | 0 | 0 | 100.0% | 100.0% | n/a |
| pii | en | 16 (12/4) | 5 | 2 | 2 | 7 | 0 | 71.4% | 41.7% | 50.0% |
| pii | fr | 3 (2/1) | 1 | 0 | 1 | 1 | 0 | 100.0% | 50.0% | 0.0% |
| pii | hi | 2 (1/1) | 1 | 0 | 1 | 0 | 0 | 100.0% | 100.0% | 0.0% |
| pii | ja | 2 (1/1) | 1 | 0 | 1 | 0 | 0 | 100.0% | 100.0% | 0.0% |
| invisible | ar | 1 (0/1) | 0 | 1 | 0 | 0 | 0 | 0.0% | n/a | 100.0% |
| invisible | en | 8 (6/2) | 5 | 1 | 1 | 1 | 0 | 83.3% | 83.3% | 50.0% |
| invisible | fa | 1 (0/1) | 0 | 1 | 0 | 0 | 0 | 0.0% | n/a | 100.0% |
| invisible | fr | 2 (0/2) | 0 | 0 | 2 | 0 | 0 | n/a | n/a | 0.0% |
| invisible | hi | 1 (0/1) | 0 | 0 | 1 | 0 | 0 | n/a | n/a | 0.0% |
| invisible | ja | 1 (0/1) | 0 | 0 | 1 | 0 | 0 | n/a | n/a | 0.0% |
| invisible | zxx | 2 (0/2) | 0 | 1 | 1 | 0 | 0 | 0.0% | n/a | 50.0% |

## Actions, separate from detection

WARN permits delivery; REDACT permits transformed content; BLOCK and ERROR reject.
A detected signal does not establish complete redaction or safe structured output.

| Family | ALLOW | WARN | REDACT | BLOCK | ERROR |
| --- | --- | --- | --- | --- | --- |
| pii | 13 | 0 | 11 | 0 | 0 |
| invisible | 7 | 9 | 0 | 0 | 0 |

## Retained failures and false-positive challenges

Warnings count as detected signals, even though they permit delivery.
ERROR results are reported separately and excluded from metric denominators.
Expected signals reflect the authored scenario, including deliberately unsupported
formats and benign lookalikes. An FP/FN is not automatically a runtime contract defect.

- `pii-phone-spaced`: **fn**, Unsupported phone with spaces (observed `allow`).
- `pii-phone-hyphens`: **fn**, Unsupported phone with hyphens (observed `allow`).
- `pii-phone-parentheses`: **fn**, Unsupported phone with parentheses (observed `allow`).
- `pii-phone-fullwidth`: **fn**, Unsupported fullwidth phone characters (observed `allow`).
- `pii-email-international`: **fn**, Unsupported non-ASCII email local part (observed `allow`).
- `pii-email-obfuscated`: **fn**, Unsupported obfuscated email (observed `allow`).
- `pii-benign-integer`: **fp**, A signed integer that resembles a phone number (observed `redact`).
- `pii-benign-code`: **fp**, Code token that resembles an email address (observed `redact`).
- `pii-json-email-escaped`: **fn**, JSON-escaped at-sign conceals the email from text scanning (observed `allow`).
- `pii-json-phone-escaped`: **fn**, JSON-escaped plus sign conceals the phone from text scanning (observed `allow`).
- `invisible-emoji-joiner`: **fp**, Legitimate woman-scientist emoji joiner (observed `warn`).
- `invisible-persian-nonjoiner`: **fp**, Persian plural with a non-joiner (observed `warn`).
- `invisible-arabic-isolate`: **fp**, Latin filename isolated in Arabic prose (observed `warn`).
- `invisible-word-joiner`: **fp**, Word joiner used for typesetting (observed `warn`).
- `invisible-json-escaped`: **fn**, JSON escape conceals an invisible separator from text scanning (observed `allow`).

## Paired representations

Related cases express the same decoded value; scanners still receive the literal input.

| Pair | Case | Format | Signal expected | Outcome | Action |
| --- | --- | --- | --- | --- | --- |
| json-email | pii-json-email-plain | json-plain | True | tp | redact |
| json-email | pii-json-email-escaped | json-escaped | True | fn | allow |
| json-phone | pii-json-phone-plain | json-plain | True | tp | redact |
| json-phone | pii-json-phone-escaped | json-escaped | True | fn | allow |
| json-invisible | invisible-json-plain | json-plain | True | tp | warn |
| json-invisible | invisible-json-escaped | json-escaped | True | fn | allow |

All observed misses, false positives, and errors are retained above.
Compare corpus, source, and runner digests before attributing changes to detectors.
Language tags: ar, en, fa, fr, hi, ja, zxx.
There are very few cases per language. The overall score mixes different tasks and
is not a general accuracy estimate. Latency covers warm, short, synchronous
local scans; it excludes imports, provider calls, async scheduling, construction,
network time, and worst-case inputs. Reruns will vary.
