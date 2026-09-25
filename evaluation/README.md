# Evaluation methodology

`corpus.jsonl` is a separate, static set of 72 authored synthetic cases: 12 each for
PII, secret signatures, invisible characters, literal policies, strict JSON/schema,
and tool validation. It was written after the initial detectors and unit tests.
It is separate from development examples, but shares authorship and assumptions;
it is **not an independently collected, blinded, or representative benchmark**.
Every token/key-shaped value is fabricated. No real credentials or personal records
belong in this corpus.

```sh
uv run python evaluation/run.py
# Keep a comparison without replacing the recorded run:
uv run python evaluation/run.py --iterations 100 --report-dir /tmp/guardtrellis-comparison
```

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
