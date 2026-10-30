# Bounded synchronous scan baseline, v1

AI-assisted public development fixtures, author self-review; no independent validation.
Only Guard.scan is timed; setup, outcome checks, callbacks and providers are excluded.
Repetitions are timing observations, not additional detector scenarios.

SDK: `0.1.10`. Mode: `full`. Measurement checks passed: `True`.
Pre-observation [freeze receipt](https://github.com/sahilmathur254/guardtrellis/issues/45#issuecomment-6507253813); SHA-256 `b562613a18195f8127f882a1a6ea739f7cc6cb3711b14e490a28c730f6684394`.

## Main comparable outcomes

| Profile | Case | Characters | Observed / expected | Exact matches | Incomplete runs | Scan median ms (range) |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| default | allow | 1000 | 300 / 300 | 300 | 0 | 0.051 (0.049–0.079) |
| default | redact | 1000 | 300 / 300 | 300 | 0 | 0.054 (0.052–0.086) |
| default | block | 1000 | 300 / 300 | 300 | 0 | 0.024 (0.023–0.058) |
| default | allow | 10000 | 300 / 300 | 300 | 0 | 0.478 (0.455–0.523) |
| default | redact | 10000 | 300 / 300 | 300 | 0 | 0.486 (0.464–0.543) |
| default | block | 10000 | 300 / 300 | 300 | 0 | 0.203 (0.195–0.249) |
| default | allow | 100000 | 300 / 300 | 300 | 0 | 4.723 (4.517–5.001) |
| default | redact | 100000 | 300 / 300 | 300 | 0 | 4.770 (4.592–9.448) |
| default | block | 100000 | 300 / 300 | 300 | 0 | 2.056 (1.971–5.292) |
| opt_in | allow | 1000 | 300 / 300 | 300 | 0 | 0.058 (0.055–0.097) |
| opt_in | redact | 1000 | 300 / 300 | 300 | 0 | 0.063 (0.059–0.218) |
| opt_in | block | 1000 | 300 / 300 | 300 | 0 | 0.031 (0.029–0.057) |
| opt_in | allow | 10000 | 300 / 300 | 300 | 0 | 0.553 (0.521–1.269) |
| opt_in | redact | 10000 | 300 / 300 | 300 | 0 | 0.545 (0.519–0.788) |
| opt_in | block | 10000 | 300 / 300 | 300 | 0 | 0.265 (0.252–0.317) |
| opt_in | allow | 100000 | 300 / 300 | 300 | 0 | 5.295 (5.157–10.501) |
| opt_in | redact | 100000 | 300 / 300 | 300 | 0 | 5.333 (5.199–5.819) |
| opt_in | block | 100000 | 300 / 300 | 300 | 0 | 2.585 (2.502–2.790) |

## Separate URI supplement

| Profile | Case | Characters | Observed / expected | Exact matches | Incomplete runs | Scan median ms (range) |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| default | uri_positive | 1000 | 300 / 300 | 300 | 0 | 0.053 (0.051–0.081) |
| default | uri_benign | 1000 | 300 / 300 | 300 | 0 | 0.053 (0.051–0.088) |
| opt_in | uri_positive | 1000 | 300 / 300 | 300 | 0 | 0.051 (0.049–0.091) |
| opt_in | uri_benign | 1000 | 300 / 300 | 300 | 0 | 0.081 (0.077–0.112) |

Raw samples, errors and missing denominators remain in results.json; missing times are not zero.
CPU/RSS describe whole children including setup; unsupported values are null.
No timing threshold, p95/p99 promise, capacity, general accuracy or cross-machine ranking is established.
URI-positive default/opt-in outcomes differ and are not a like-for-like speed comparison.
