# Bounded synchronous scan baseline

This evaluation-only contribution to [#45](https://github.com/sahilmathur254/guardtrellis/issues/45)
is included in the `0.1.11` source. It measures synchronous `Guard.scan` behavior
without changing SDK behavior, defaults or dependencies. The retained baseline was
collected on SDK `0.1.10`; version preparation does not rewrite its frozen evidence.
Check [PyPI](https://pypi.org/project/guardtrellis/) for package availability.

```sh
uv run --frozen python evaluation/scan_performance/run.py --report-dir /tmp/scan-full

# All cells, reduced repetitions/sample count for CI:
uv run --frozen python evaluation/scan_performance/run.py --smoke --report-dir /tmp/scan-smoke
```

Choose a new output directory; existing reports are never overwritten. Normal runs use
no network, provider, database, external callbacks or credentials. Do not run other heavy
tests or benchmarks concurrently when collecting a baseline.

## Frozen expectations and provenance

The [protocol](PROTOCOL_v1.md) and [fixtures](fixtures_v1.json) were frozen before the
first SDK observation. The [manifest](freeze_v1.json) SHA-256 is
`b562613a18195f8127f882a1a6ea739f7cc6cb3711b14e490a28c730f6684394`;
its [external receipt](https://github.com/sahilmathur254/guardtrellis/issues/45#issuecomment-6507253813)
predates the first smoke metadata timestamp, `2026-10-29T20:14:09.533917+00:00`.
The immutable manifest records pre-observation fixture/protocol, SDK, helper, lockfile
and historical-file hashes. Its runner hash is explicitly from before receipt binding;
each report separately records the actual runner/helper and imported SDK file hashes.
Fixture/protocol hashes and the receipt anchor are checked before every run.
SDK/helper/lock hashes are pre-observation identity records rather than permanent
version pins: reports explicitly compare actual runtime hashes with that snapshot.
The retained local baseline matched all three when collected. Version preparation can
change SDK/lock identities without changing behavior. This permits future SDK comparisons
without rewriting frozen expectations or claiming unchanged runtime provenance.

The five fixture meanings are Codex-assisted public synthetic development cases,
Apache-2.0, with author self-review. Independent/blinded case review has not occurred.
Padding, repetitions and profiles are timing observations, not independent examples.

## Scope and measurement

The 18 main cells combine two secrets-before-PII policies, sizes 1k/10k/100k Python
characters, and ALLOW/REDACT/BLOCK. Default and opted-in policies use the same fixtures
and complete outcomes. Matches sit near the input tail after benign period padding.
A separate four-cell URI supplement exercises password-bearing/password-free shapes
under each policy at 1k. Its differing actions must not be pooled into a speed ratio.

Full mode has three fresh-process repetitions per cell, each with three warmups and
100 measured scans: 5,400 main plus 1,200 supplement samples. Smoke mode has one process
per cell and four measured scans: 72 main plus 16 supplement. All 22 cells remain present.

Only `Guard.scan(text, stage=RETRIEVAL)` is timed. Input construction, setup/imports,
warmups, outcome checks, diagnostics, `require_text()` and local consumer delivery are
outside that interval. Exact actions, stage, finding identity/spans/revision, complete
checked text, rejection/accessor behavior, delivery and metadata privacy are checked.
The reports retain per-scan timings, per-repetition/per-cell descriptive medians and
ranges, action/error counts, missing denominators and source/runtime provenance.

Each disposable worker has a 10-second wall budget, bounded capture and available
CPU/memory limits; the parent has a 180-second observation budget plus bounded cleanup.
CPU/RSS describe whole children including setup and warmups. Missing measurements are
unknown, not zero. No latency threshold, p95/p99 guarantee, throughput, production
capacity, broad detection accuracy or cross-machine ranking follows from this protocol.

## Results and platform limits

The reviewed [SDK 0.1.10 local baseline](baseline_sdk_0.1.10/REPORT.md) and
[raw metadata](baseline_sdk_0.1.10/results.json) retain the exact environment and hashes.
Native Windows execution is verified separately against the submitted commit's PR/CI
record. CI runs every smoke cell on the existing Linux/macOS/Windows matrix; the local
baseline and Windows launch/cleanup regressions do not establish native Windows execution.

The first exploratory smoke (88/88) and full run (6,600/6,600, 66 reaped children)
preceded failure-path review of the harness. Reporting/static argument handling,
exception-surface canary checks, strict numeric metadata and cleanup-prefix retention
were strengthened afterward; the successful fixture outcomes were unchanged. Their reports
remain outside the checkout; frozen labels and protocol were unchanged. Final source hashes identify
the retained baseline. Historical corpora/reports remain byte-identical.

This is a partial contribution to #45. Independent case review, broader benchmark work
and separately scoped detector changes remain open. Exit zero establishes the fixed
measurement/outcome contracts, not completion of that wider issue or release readiness.
