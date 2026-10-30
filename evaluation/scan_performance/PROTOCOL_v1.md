# Synchronous scan baseline, v1

This evaluation-only, `0.1.11`-target contribution to
[#45](https://github.com/sahilmathur254/guardtrellis/issues/45) measures repeated
`Guard.scan` calls on fixed synthetic strings. It adds no scanner behavior, SDK
deadline, dependency, default, API or source-version change. Release availability
and completion of the wider issue require separate evidence.

The five original fixture meanings are authored with Codex assistance and knowledge
of the documented SDK and source. Labels receive author self-review only. They are
Apache-2.0 public development cases, with no independent or blinded review, held-out
data, personal records or issued credentials. Repetition, padding, profiles and fresh
processes do not create additional independent detector examples. No network,
provider, database, DNS, external callback or host-tool invocation is part of this
protocol, and no environment file is loaded.

## Freeze before the first observation

[fixtures_v1.json](fixtures_v1.json) fixes all case text, expected actions, exact
finding codes, payload-relative half-open spans and checked payloads before any
new-fixture SDK observation. Python character counts and offsets, rather than UTF-8
bytes or grapheme counts, define the construction. A stdlib-only loader may validate
the fixture schema, lengths and projections without importing or running the SDK.
Expectations must never be inferred from observed scanner output.

Before any fixture scan, SDK-observing test, warmup, smoke or measured run, create a
freeze manifest binding the exact fixture/protocol bytes, runner/helper bytes, SDK
source files and dependency lockfile to repository-relative SHA-256 digests. Record
the source base commit, actual pre-observation phase and AI/self-review disclosure.
Post the manifest digest and reviewable description to #45 as an external receipt
before observation. An authored document alone is not that receipt. Runtime loaders
must verify the frozen assets before scanning; reports must identify actual runtime,
SDK source, runner/helper, fixture, protocol and lockfile digests.

Do not overwrite a frozen decision or silently relabel after results are known.
Any fixture/protocol correction requires a new version or explicit post-observation
erratum retaining the original receipt, decisions and outcomes. Runner corrections
must retain the original frozen bytes/digests and disclose their timing and actual
runtime hashes. A successful later run does not erase earlier incomplete or failed
observations. Historical evaluation fixtures and reports remain unchanged.

## Exact cell and input contract

Both profiles configure these scanners in this exact order at `Stage.RETRIEVAL`:

| Profile | Scanner index 0 | Scanner index 1 |
| --- | --- | --- |
| `default` | `SecretScanner()` | `PIIScanner()` |
| `opt_in` | `SecretScanner(connection_strings=True)` | `PIIScanner(phone_mode="formatted")` |

Secret action remains BLOCK and PII action remains REDACT. PII uses all default
formats, including email, phone and SSN; it is not restricted to phone. No other
stage scanner is configured. `Guard.max_chars` stays at its default 100,000. Each
worker constructs one policy before warmups and reuses it for its cell. The measured
call is exactly `policy.scan(text, stage=Stage.RETRIEVAL)`.

The main matrix has **18 cells**: two profiles × three sizes (1,000, 10,000 and
100,000 Python characters) × three outcomes (ALLOW, REDACT and BLOCK). The main
fixtures and required outcomes are identical across profiles. A separate **four-cell
URI supplement** uses the same two profiles × two URI fixtures at 1,000 characters
only. The supplement is always reported separately and is never pooled into the
main size/outcome comparison. All 22 cells remain present in full and smoke modes.

For a fixture `case` and declared input size `size`, construct only:

```python
padding = "." * (size - len(case["payload"]))
text = padding + case["payload"]
checked = (
    None
    if expected["checked_payload"] is None
    else padding + expected["checked_payload"]
)
```

Inputs contain no per-scan timestamps, IDs, suffix markers or randomness. The payload
is at the end after benign period padding; every positive span is near the tail,
avoiding an artificially favorable match at the input head. Each authored relative
span `[start, end]` becomes `[len(padding) + start, len(padding) + end]`. Never change
padding after redaction: the expected REDACT result is shorter than the input.

| Case | Exact required outcome |
| --- | --- |
| Main `allow` | ALLOW, no findings, complete unchanged text. |
| Main `redact` | REDACT, exactly one `pii_phone` at relative `[9, 21]`; the complete contiguous synthetic phone becomes `[PII]`. |
| Main `block` | BLOCK, exactly one `secret_github_classic` at relative `[7, 47]`; no checked text. The fabricated token is `ghp_` followed by 36 ASCII `A` characters. |
| Supplement `uri_positive` | Default ALLOW unchanged with no findings; opt-in BLOCK with exactly one complete `secret_postgresql_uri` at relative `[12, 63]`, with no checked text. |
| Supplement `uri_benign` | Both profiles ALLOW unchanged with no findings. |

The URI supplement exercises the enabled parser with a credential-bearing positive
and a URI without a password. Neither URI has an incidental PII shape. Its two cases
establish only these controls, not URI-format coverage or accuracy. The source names
the classic-token code `secret_github_classic`; no `secret_github_token` alias is
assumed. These labels and spans come from authored construction and source reading,
not an SDK scan.

Cell order is deterministic: all main cells first, with `default` then `opt_in`;
within each profile, ascending size then cases `allow`, `redact`, `block`. The
supplement follows with `default` then `opt_in`, cases `uri_positive`, `uri_benign`
at size 1,000. Repetitions use ascending indices.

## Samples and timing boundary

Full mode runs **three fresh-process repetitions per cell**, each with **three
sequential warmups and 100 measured scans**. This yields 5,400 main and 1,200
supplement measured observations (6,600 total), plus 198 untimed warmups. Smoke
mode runs **one fresh process per cell**, each with the same three warmups and
**four measured scans**: 72 main and 16 supplement observations (88 total), plus
66 untimed warmups. Warmups must satisfy the same exact contracts as measured scans.

For each scan, take `time.perf_counter_ns()` immediately before the synchronous
`Guard.scan` call and immediately after its return or raised exception. Retain the
individual elapsed duration; unit conversion occurs afterward. Input construction,
interpreter startup, SDK import, policy construction, warmups, outcome checks,
`require_text()`, diagnostics validation, local consumer delivery and report emission
are outside that per-scan interval. No callback or provider executes inside it. This
is whole `Guard.scan` latency for the ordered policy, including guard bookkeeping;
it does not isolate either scanner's internal time.

Report per-cell/per-repetition sample counts, outcome counts, exact-contract counts,
median and observed minimum/maximum, alongside incomplete/missing denominators.
Retain every valid individual timing, including returned mismatches or ERROR results;
an unsuccessful result is not deleted to improve timing. A raised unexpected exception
is a harness failure with a timing if available, never a successful guard decision.
Missing/stopped scans have no fabricated duration. Warmups never enter measured
denominators. There is no latency threshold and no p95/p99, throughput, service-capacity,
production-objective or comparative-performance claim.

## Exact outcomes, delivery and privacy

Every completed scan must match the frozen action, acceptance, finding count and
ordered codes, and every full absolute span. The result stage must be RETRIEVAL.
Findings must have original input revision 0, scanner `secrets`/index 0 for BLOCK
positives or `pii`/index 1 for the phone. ALLOW requires zero findings. Phone REDACT must retain
all padding and surrounding text and replace the entire phone once. No incidental
code, partial match, prefix-only redaction or extra finding is accepted.

Check the full result text and `require_text()` separately outside the timing interval.
Accepted results must expose exactly the authored checked text, and a local recording
consumer must receive that exact `require_text()` return once. Rejected results must
have `text is None`, `accepted is False`, raise the public `Rejected` type from
`require_text()`, and deliver nothing to the consumer. Do not use unguarded input or
direct result text as a substitute for checked delivery. The consumer is a local
integrity check, not a model callback or additional timed operation.

Validate `diagnostics()` as metadata with exact expected action/stage, finding
metadata and trace. ALLOW traces contain two ALLOW steps with revision 0 unchanged.
Phone REDACT traces contain secret ALLOW at revision 0, then PII REDACT from revision
0 to 1. BLOCK traces contain only secret BLOCK with revision 0 unchanged. Verify that
diagnostics, result/exception representations and built-in rejection reporting expose
neither the whole input/checked text nor the fabricated phone, token, URI or password
canaries. Exception wording is not a compatibility contract and must not be persisted.

Worker and report channels contain only validated timing, fixed IDs, actions, codes,
offsets, counts, booleans and bounded runtime/source provenance. They exclude payloads,
checked text, local consumer values, arbitrary worker strings, exception messages,
tracebacks, stderr contents, absolute checkout paths, hostname and environment values.
Validate ordered event types, exact keys, bounded strings/integers, finite nonnegative
timings and expected sequence/counts before accepting any row. Never copy malformed
events or arbitrary exception contents into reports. Report failures by static codes.

## External containment and incomplete work

Each cell/repetition uses a disposable child with a **10-second external wall budget**
and bounded 64 KiB stdout/stderr capture. Reuse existing resource helpers for sanitized
environments, tighter-existing-cap preservation, two-second soft/three-second hard CPU
caps where available, Linux 512 MiB address-space cap, core/output bounds and child
termination/reaping. Unsupported CPU/RSS/memory limits remain explicitly null. Worker
CPU/RSS and parent wall time include startup/setup and warmups; RSS is a whole-worker
peak, not per-scan allocation. They are separate containment metadata.

The parent has a **180-second observation budget**, followed by at most five seconds
to terminate/reap its current child and clean temporary resources. Repeated signals
do not restart cleanup allowances. Preserve validated prefix observations and mark
all remaining work incomplete/not started after interruption, timeout, limit, malformed
event or worker failure. Deferred SIGINT/SIGTERM handling must complete termination,
reaping and cleanup before temporary-directory removal and partial-report writing.
Bounded cleanup is not evidence that arbitrary synchronous code has an SDK deadline.
Process creation and OS scheduling can delay enforcement; this is not a process sandbox.

On Windows, launch the base interpreter with the selected virtual-environment launcher
in `__PYVENV_LAUNCHER__`, following the existing resource/concurrency harness pattern;
reap before deleting temporary files. Native Windows CI must actually execute all
22 smoke cells and cleanup regressions. Local macOS/Linux evidence cannot substitute
for that platform result.

## Reports, completion and scope

Write `results.json` and `REPORT.md` only to a new report directory. Refuse an existing
directory; retain all prior exploratory/baseline evidence. Reports identify full/smoke
mode, all expected cells and denominators, completed/missing scans, valid raw timing
metadata, exact-contract failures, worker/protocol/privacy errors and reaping state.
Do not publish a completed-baseline claim from partial work.

Exit zero requires every expected warmup and measured sample, valid protocol/privacy,
exact action/code/span/text/rejection/consumer contracts and all children reaped.
Unexpected/incomplete work exits 1; handled interruption exits 130; invalid arguments
or an existing report directory exit 2 with static CLI errors. Timings never determine
pass/fail. Contract mismatches pause acceptance for separate triage, not detector edits
or retrospective relabelling within this evaluation batch.

Relevant validation covers pure construction/freeze loading, every cell, corrupted
outcomes, payload-bearing diagnostics, malformed/oversize events, deadlines/signals,
cleanup, existing-report preservation and platform-specific launch. First complete
the pre-observation freeze/receipt gate. Commit, push, GitHub writes, merge, deployment,
release, live-provider work and any runtime SDK change require their separate
authorization and evidence; this document grants none of those actions.
