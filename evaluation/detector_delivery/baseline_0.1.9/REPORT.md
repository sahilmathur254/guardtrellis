# Detector and checked-delivery challenge, v1

48 AI-assisted synthetic development scenarios; no independent per-case review.
384 correlated observations, not 384 independent examples. English context only.
No population accuracy, hidden-test, performance or superiority claim.

SDK 0.1.9; Darwin / Python 3.12.0. Source/runtime digests are in results.json.
Pre-observation [freeze receipt](https://github.com/sahilmathur254/guardtrellis/issues/45#issuecomment-6444217374); SHA-256 `261e01a4482dcdde5bd87880c8c80e7238b99321cc0fe7a1a121fd2f7c667e19`.

Measurement integrity: **True**; eligible contract/control checks: **True**.

| Family / profile | Observed / expected | TP / FP / TN / FN | Errors | Desired exact | Contract failures |
| --- | ---: | --- | ---: | ---: | ---: |
| email/default | 64/64 | 17 / 6 / 26 / 15 | 0 | 41 | 0 |
| email/opt_in | 64/64 | 17 / 6 / 26 / 15 | 0 | 41 | 0 |
| phone/default | 64/64 | 12 / 3 / 29 / 20 | 0 | 35 | 0 |
| phone/opt_in | 64/64 | 18 / 3 / 29 / 14 | 0 | 44 | 0 |
| connection_uri/default | 64/64 | 0 / 0 / 32 / 32 | 0 | 23 | 0 |
| connection_uri/opt_in | 64/64 | 15 / 3 / 29 / 17 | 0 | 35 | 0 |

Primary-family codes determine signals. Incidental PII never counts as a URI signal.
ERROR and incomplete rows remain separate. Undefined rates are null.
Desired exact requires action, full spans, checked text and consumer delivery.
Contract checks separately count disabled-feature and raw-escaped controls.
Benign shapes can meet the SDK contract while being scenario false positives.
Unsupported misses and partial redactions remain visible here and in results.json.
CPU/RSS describe whole-worker containment, not per-scan performance.
Historical fixtures/reports and SDK code remain unchanged.

## Retained mismatches

- `email-01-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-02-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-03-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-03-benign` / default / plain: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-03-benign` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-03-benign` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-04-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-05-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-06-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-06-sensitive` / default / json_literal: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `email-06-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-06-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-07-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-07-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-07-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-07-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-08-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-08-sensitive` / default / json_literal: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `email-08-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-08-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-08-benign` / default / plain: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-08-benign` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-08-benign` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-01-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-02-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-03-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-03-benign` / opt_in / plain: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-03-benign` / opt_in / json_literal: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-03-benign` / opt_in / decoded: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-04-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-05-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-06-sensitive` / opt_in / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-06-sensitive` / opt_in / json_literal: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `email-06-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-06-sensitive` / opt_in / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-07-sensitive` / opt_in / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-07-sensitive` / opt_in / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-07-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-07-sensitive` / opt_in / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-08-sensitive` / opt_in / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-08-sensitive` / opt_in / json_literal: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `email-08-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `email-08-sensitive` / opt_in / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `email-08-benign` / opt_in / plain: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-08-benign` / opt_in / json_literal: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `email-08-benign` / opt_in / decoded: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `phone-01-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-02-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-02-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-02-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-02-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-02-benign` / default / plain: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `phone-02-benign` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `phone-02-benign` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `phone-03-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-03-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-03-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-03-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-04-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-05-sensitive` / default / plain: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-05-sensitive` / default / json_literal: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-05-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-05-sensitive` / default / decoded: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-06-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-06-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-06-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-06-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-07-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-07-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-07-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-07-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-08-sensitive` / default / plain: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-08-sensitive` / default / json_literal: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-08-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-08-sensitive` / default / decoded: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-01-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-02-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-02-benign` / opt_in / plain: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `phone-02-benign` / opt_in / json_literal: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `phone-02-benign` / opt_in / decoded: redact; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `phone-03-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-04-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-05-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-06-sensitive` / opt_in / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-06-sensitive` / opt_in / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-06-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-06-sensitive` / opt_in / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-07-sensitive` / opt_in / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-07-sensitive` / opt_in / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-07-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-07-sensitive` / opt_in / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `phone-08-sensitive` / opt_in / plain: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-08-sensitive` / opt_in / json_literal: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `phone-08-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `phone-08-sensitive` / opt_in / decoded: redact; desired mismatches spans, text, delivery; contract unsupported / None.
- `connection-uri-01-sensitive` / default / plain: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-01-sensitive` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-01-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-01-sensitive` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-02-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-02-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-02-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-02-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-02-benign` / default / plain: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-02-benign` / default / json_literal: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-02-benign` / default / decoded: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-03-sensitive` / default / plain: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-03-sensitive` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-03-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-03-sensitive` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-04-sensitive` / default / plain: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-04-sensitive` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-04-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-04-sensitive` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-04-benign` / default / plain: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-04-benign` / default / json_literal: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-04-benign` / default / decoded: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-05-sensitive` / default / plain: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-05-sensitive` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-05-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-05-sensitive` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-06-sensitive` / default / plain: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-06-sensitive` / default / json_literal: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-06-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-06-sensitive` / default / decoded: redact; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-07-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-07-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-07-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-07-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-08-sensitive` / default / plain: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-08-sensitive` / default / json_literal: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-08-sensitive` / default / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-08-sensitive` / default / decoded: allow; desired mismatches action, spans, text, delivery; contract disabled_control / True.
- `connection-uri-08-benign` / default / plain: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-08-benign` / default / json_literal: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-08-benign` / default / decoded: redact; desired mismatches action, text, delivery; contract disabled_control / True.
- `connection-uri-01-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-02-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-02-benign` / opt_in / plain: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-02-benign` / opt_in / json_literal: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-02-benign` / opt_in / decoded: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-03-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-04-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-04-benign` / opt_in / plain: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-04-benign` / opt_in / json_literal: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-04-benign` / opt_in / decoded: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-05-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-06-sensitive` / opt_in / plain: redact; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-06-sensitive` / opt_in / json_literal: redact; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-06-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-06-sensitive` / opt_in / decoded: redact; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-06-benign` / opt_in / plain: block; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `connection-uri-06-benign` / opt_in / json_literal: block; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `connection-uri-06-benign` / opt_in / decoded: block; desired mismatches action, spans, text, delivery; contract contextual_shape / True.
- `connection-uri-07-sensitive` / opt_in / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-07-sensitive` / opt_in / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-07-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-07-sensitive` / opt_in / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-08-sensitive` / opt_in / plain: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-08-sensitive` / opt_in / json_literal: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-08-sensitive` / opt_in / json_escaped: allow; desired mismatches action, spans, text, delivery; contract raw_escaped_control / True.
- `connection-uri-08-sensitive` / opt_in / decoded: allow; desired mismatches action, spans, text, delivery; contract unsupported / None.
- `connection-uri-08-benign` / opt_in / plain: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-08-benign` / opt_in / json_literal: redact; desired mismatches action, text, delivery; contract supported / True.
- `connection-uri-08-benign` / opt_in / decoded: redact; desired mismatches action, text, delivery; contract supported / True.
