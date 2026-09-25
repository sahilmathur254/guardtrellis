# Synthetic smoke evaluation

These are authored synthetic fixtures, not an independent or adversarial benchmark.
Results measure this corpus only. They do not establish production safety or language coverage.

Generated: 2026-09-25T11:08:18.974660+00:00
Python 3.12.0, Darwin arm64; GuardTrellis 0.1.0a1, jsonschema 4.26.0.
Corpus SHA-256: `f75b7c1898734cd1742eba3acf885a543e0270254d2b0ba5b903f8a01861910f`.
Package source SHA-256: `dc9035e31fc54d03ea8626ac40c8df0b10cdb4a4b3d1add394513e2c2413c62a`.
72 cases, 100 timed scans per case, 3 warmups per case.

| Family | N (+/−) | TP | FP | TN | FN | Errors | Precision | Recall | FPR | p50 µs | p95 µs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| pii | 12 (7/5) | 5 | 0 | 5 | 2 | 0 | 100.0% | 71.4% | 0.0% | 3.3 | 5.8 |
| secrets | 12 (8/4) | 6 | 0 | 4 | 2 | 0 | 100.0% | 75.0% | 0.0% | 4.1 | 5.4 |
| invisible | 12 (6/6) | 6 | 2 | 4 | 0 | 0 | 75.0% | 100.0% | 33.3% | 4.0 | 5.5 |
| literal | 12 (6/6) | 6 | 0 | 6 | 0 | 0 | 100.0% | 100.0% | 0.0% | 4.4 | 5.0 |
| json | 12 (6/6) | 6 | 0 | 6 | 0 | 0 | 100.0% | 100.0% | 0.0% | 7.1 | 10.2 |
| tool | 12 (6/6) | 6 | 0 | 6 | 0 | 0 | 100.0% | 100.0% | 0.0% | 12.0 | 14.6 |
| overall | 72 (39/33) | 35 | 2 | 31 | 4 | 0 | 94.6% | 89.7% | 6.1% | 4.7 | 12.2 |

## Retained failures and false-positive challenges

Warnings count as detected signals, even though they permit delivery.
ERROR results are reported separately and excluded from metric denominators.
See README.md for definitions.

- `pii-06`: **fn**, Known unsupported obfuscated email (observed `allow`).
- `pii-07`: **fn**, Known unsupported spaced phone (observed `allow`).
- `secrets-07`: **fn**, Known unsupported arbitrary password (observed `allow`).
- `secrets-08`: **fn**, Known unsupported custom bearer token (observed `allow`).
- `invisible-10`: **fp**, Known false positive: legitimate emoji joiners (observed `warn`).
- `invisible-11`: **fp**, Known false positive: legitimate Persian non-joiner (observed `warn`).

No detector rules were changed to erase these evaluation failures.
The corpus contains English, Hindi, Japanese, Spanish, French, and Persian text,
with very few cases per language. The overall score mixes different tasks and
is not a general accuracy estimate. Latency covers warm, short, synchronous
local scans; it excludes imports, provider calls, async scheduling, construction,
network time, and worst-case inputs. Reruns will vary.
