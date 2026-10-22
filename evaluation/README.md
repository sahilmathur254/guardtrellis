# Evaluation methodology

`corpus.jsonl` is a separate, static set of 72 authored synthetic cases: 12 each for
PII, secret signatures, invisible characters, literal policies, strict JSON/schema,
and tool validation. It was written after the initial detectors and unit tests.
It is separate from development examples, but shares authorship and assumptions;
it is **not an independently collected, blinded, or representative benchmark**.
Every token/key-shaped value is fabricated. No real credentials or personal records
belong in this corpus.

```sh
# Keep a comparison without replacing the recorded run:
uv run python evaluation/run.py --iterations 100 --report-dir /tmp/guardtrellis-comparison
```

## What belongs in Git

Keep the synthetic corpus, runner, methodology, and reviewed baseline (`REPORT.md` and
`results.json`) in version control. They let contributors reproduce the stated scope,
compare changes, and inspect known misses and false positives. Public availability is
intentional; these authored cases are not a secret or held-out security test set.

Keep private datasets, application transcripts, raw provider responses, credentials,
machine-local logs, and exploratory runs outside the checkout. Use `--report-dir` as above
for routine comparisons. It is now required and must name a new directory: the runner
refuses to overwrite earlier reports. Prepare any new reviewed baseline in a separate,
versioned directory with its corpus/source/runtime provenance.
The recorded `0.1.0a1` baseline remains historical evidence as new versions are released;
it must not be relabelled as a new run. Review generated reports before publishing them.

## Versioned challenge additions

The separate [Unicode and PII v1 challenge set](challenges/README.md) adds 40 authored
development cases without changing the original corpus or its recorded results. It covers
benign Unicode, multilingual context, contact-format variation, contextual lookalikes, and
paired plain/escaped JSON representations. No detector changes accompany this set.

```sh
uv run --frozen python evaluation/run.py \
  --corpus evaluation/challenges/unicode_pii_v1.jsonl \
  --report-dir /tmp/guardtrellis-challenges-comparison
```

Both corpora use the same fixed policies and metrics. Current runs also report confusion
matrices per family and language, action counts, accepted/rejected outcomes, Unicode database
version, and lockfile digest. Warnings, redactions, blocks, and errors remain separate.
Report schema 2 adds these fields; the original checked-in report remains unchanged.

## Method and limits

Each record has a stable ID, family, text, language tag, expected signal, and rationale.
`expected_signal: true` means sensitive data or a configured policy/validation violation.
It includes deliberately unsupported formats to expose scope limitations. Ordinary
tasks and legitimate Unicode usage are negative cases. Invisible-character detection
uses its default WARN action: a warning is a detection, **not a prevention**.
Literal policy terms and JSON/tool schemas live in the runner and are part of the
evaluation definition. Prompt injection and semantic safety are not evaluated.

For non-error results, any finding is a predicted positive. Precision = TP/(TP+FP),
recall = TP/(TP+FN), and false-positive rate = FP/(FP+TN). Undefined ratios are null/n/a.
ERROR results are reported separately and excluded from these ratios; the runner exits
nonzero if any occur. The summary provides positive/negative sample counts and the full
confusion matrix. The aggregate mixes different checks and must not be marketed as
general accuracy. Individual misses and false positives remain in the report.

For each case, the runner executes 3 unmeasured warmups and 100 sequential timed calls
using Python's `perf_counter_ns`. Reported p50 is the median; p95 is the nearest-rank
95th percentile across per-scan timings. It measures Guard orchestration plus scanning
(ToolGuard includes parsing), with scanners constructed once. It excludes process startup,
dependency imports, schema construction, provider/network calls, and asynchronous thread
scheduling. These are short inputs, not throughput, worst-case, or capacity measurements.

`REPORT.md` is the human-readable result. `results.json` stores corpus, source, and runner digests,
runtime/package versions, individual outcomes, and raw latency samples for reproducibility.
The exact dependency resolution is in `uv.lock`. Changing corpus labels or detector rules
requires a documented reason, a new report, and retention of failures rather than silently
converting them into passing examples. Larger independent corpora and real deployment
measurements remain future work.

New corpora require a `dataset_version`, `source`, `usage` (`development` or `held_out`),
`format`, and `label_basis` on every case, in addition to the original fields. Only the exact
historical corpus digest is accepted without those fields. Case IDs must be unique; labels
must be booleans, with a known scanner family and a language tag. Run one dataset version
at a time. A `held_out` label is an author assertion, not independent validation: contributors
must explain who withheld cases from which development process. All current cases are
development examples, were authored with knowledge of the implementation, and are public.

The runner does not copy input text, delivered output, or arbitrary extra case fields into
reports. Notes and provenance are authored public metadata; keep sensitive data out of them.

The separate [resource measurement harness](../docs/resource_limits.md) covers large inputs,
selected expensive schemas, and cancellation in bounded child processes. Its report in
`resource_limits/` does not replace this detector corpus or establish production capacity.

The separate [policy and delivery evaluation](policy_combinations/README.md) adds 34
AI-assisted synthetic development scenarios for selected secret signatures, JSON and tool
outcomes, scanner ordering, checked callback/dispatch data, revision-aware spans, and
payload-safe diagnostic/error surfaces. It records intended delivery comparisons alongside
detection outcomes without changing these historical corpora or baselines. A successful
harness exit does not mean all scenario expectations passed; retained misses, false positives,
and action/delivery mismatches must be read in its reports.

The [detection coverage v1 batch](policy_combinations/DETECTION_COVERAGE.md), tracked in
[#59](https://github.com/sahilmathur254/guardtrellis/issues/59), compares raw text,
serialized JSON, and the existing decoded-query recipe before detector changes. It adds
phone-format variation, benign lookalikes, and complete-redaction/delivery expectations.
Its corpus and baseline are separate from the historical reports above.

The [bounded concurrency evaluation](concurrency/README.md), a separate contribution to
[#45](https://github.com/sahilmathur254/guardtrellis/issues/45), uses a fixed `Guard.arun`
policy and synthetic in-memory callbacks. It compares 1/4 active calls over 10,000/100,000
characters and checks exact allowed/redacted delivery and callback suppression on rejection.
It records setup, admission wait, operation time and available process resources separately.
Its repeated development requests support observed ranges and medians, not population
accuracy, production capacity, tail-latency guarantees or a recommended concurrency limit.

The [connection-string evaluation](connection_strings/README.md), tracked in
[#67](https://github.com/sahilmathur254/guardtrellis/issues/67), freezes 52 synthetic
development cases before detector changes. It compares plain, raw serialized and explicitly
decoded values under the default secret scanner and shipped tool-return policy, preserving
incidental PII redactions, partial credential coverage, input-limit errors and unsupported
formats separately. Its published-0.1.7 baseline and detector proposal do not change SDK
defaults or establish general connection-string coverage.
