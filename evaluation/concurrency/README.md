# Bounded async checked-delivery baseline, v1

This is a partial contribution to [#45](https://github.com/sahilmathur254/guardtrellis/issues/45).
It measures a fixed application-owned admission limit around the existing `Guard.arun`
API. It does not change SDK scheduling, add a production worker pool, or establish
service capacity, tail latency, a safe concurrency setting, or general accuracy.

```sh
uv run --frozen python evaluation/concurrency/run.py \
  --report-dir /tmp/guardtrellis-concurrency-v1

# Reduced contract reproduction for CI; all twelve cells remain present:
uv run --frozen python evaluation/concurrency/run.py --smoke \
  --report-dir /tmp/guardtrellis-concurrency-smoke
```

The directory must not already exist. Exploratory reports belong outside the checkout.
The runner makes no network, provider or host-tool calls and loads no environment file.
`results.json` retains all safe observations; `REPORT.md` summarizes them. A reviewed
baseline must use its own versioned directory after implementation review; historical
detector, contact, phone and resource reports are never replaced.

The retained [0.1.7 candidate baseline](baseline_0.1.7/REPORT.md) records a full local
macOS / Python 3.12.0 run: all 720 measured requests matched their authored contracts,
all 36 children completed and were reaped, and no run was incomplete. Its
[raw metadata](baseline_0.1.7/results.json) records the exact source hashes and environment.
This result does not establish native Windows execution; that requires the candidate's CI.

## Fixed protocol and authored expectations

There are twelve cells: three payload families × two exact character sizes (10,000
and 100,000) × two active-call limits (one and four). Full mode runs twenty measured
requests per cell, with three fresh-process repetitions: 720 measured observations.
Smoke mode uses four requests and one repetition: 48 observations. Every child runs
three sequential warmups before its measured batch. Warmups have checked outcomes but
do not enter the measured request timings or sample counts.

One shared policy checks `SecretScanner(action=BLOCK)` before
`PIIScanner(formats=["phone"], action=REDACT, phone_mode="formatted")`. No output
scanners are configured. An in-memory synchronous callback returns a request-specific
receipt. One fixed four-thread default executor is used at both admission limits.
The limit governs active `arun` awaits in this measurement host, not the SDK's worker
lifetime after cancellation. Existing cancellation/resource evidence remains applicable.

| Family | Authored requirement |
| --- | --- |
| ALLOW | The callback receives exactly the unchanged input, including this request's markers; its receipt is delivered. |
| REDACT | One complete formatted phone becomes `[PII]` before the callback; padding and markers stay unchanged; its receipt is delivered. |
| BLOCK | A fabricated private-key envelope blocks before the phone check; there is no callback or delivered text. |

[fixtures_v1.json](fixtures_v1.json) contains the expected replacement strings and
finding codes independently of scanner output. The runner pads each payload to its
declared size and adds a unique per-request prefix and suffix. These markers and the
unique receipt detect changed callback input and cross-request result mixups. Finding
count and code, action, acceptance, callback count, exact callback input and exact final
delivery are checked. The four-active-call cells must actually reach four active awaits.

The three meanings are original AI-assisted authored synthetic development fixtures,
Apache-2.0 licensed, prepared with knowledge of the SDK contract. They are not held-out,
blinded, independently reviewed or representative of a language or deployment. Repetition,
padding and concurrency do not create independent detector examples. The private-key
envelope is fabricated and contains no key material; the phone is a synthetic example.

## Measurement boundaries

- `setup_ms` covers SDK import, fixture loading and policy construction in the child.
  Interpreter startup, initial harness imports and cap application precede it.
- `warmup_ms` covers the three sequential warmups, including request construction and
  executor startup. Warmup failure fails the run even if later measured calls pass.
- `admission_wait_ms` runs from a request's arrival at the host semaphore to admission.
  It excludes construction of that request's synthetic input.
- `arun_ms` runs from admission through return of `Guard.arun`. It includes the SDK's
  thread scheduling, input scanning and trivial callback, but excludes waiting for host
  admission, input construction and report emission. It is not isolated scanner time.
- `batch_ms` includes task scheduling, input construction, admission wait, `arun`,
  outcome checks and sample emission for the measured batch. At most twenty tasks are
  created; the executor has four threads. No unbounded arrival stream is simulated.
- Parent `wall_ms` also includes child startup, setup, warmups, executor shutdown,
  process exit and reaping. CPU and RSS are whole-child values, including setup/warmup;
  RSS is a peak, not a per-request allocation delta. Unavailable RSS is `null`.

Each cell reports sample count, action and accepted/rejected counts, exact matches,
incomplete runs, medians and observed ranges. Per-request times from retained valid
observations include any returned rejection/error or mismatch; inspect the outcome
alongside the time. Missing/stopped requests contribute no fabricated timing sample.
Raw metadata preserves failures and the expected denominator. The samples do not
justify p95/p99, performance rankings, throughput or production service objectives.
There is no time-based performance pass/fail threshold.

## Containment, privacy and verification

Each cell runs in a disposable child with a ten-second external wall budget, bounded
metadata capture and mandatory termination/reaping. The full parent run has a 180-second
measurement budget, followed by up to five seconds to reap the current child. Process
creation and OS scheduling can delay enforcement; this is not a general process sandbox.
Remaining cells after exhaustion/interruption stay visible as incomplete/not started.
SIGINT and SIGTERM are recorded during a child's lifetime and deferred through termination,
reaping and temporary-resource cleanup. Partial metadata is retained before the runner
returns its interrupted status; signals do not restart the cleanup allowance.

The existing [resource helpers](../measure_resources.py) supply a sanitized environment,
two-second soft / three-second hard CPU caps where available, Linux 512 MiB address-space
cap, output/core limits and child cleanup. Unsupported caps remain `null`. Tighter existing
caps are preserved. Windows uses its base interpreter with `__PYVENV_LAUNCHER__` to keep
the selected virtual environment without the known temporary-directory cleanup race.
The parent checks output sizes while waiting and reads at most 64 KiB of worker metadata;
fixed workers accept no arbitrary code, schema or user payload. Raw stderr is never copied.

Every worker event is validated against an ordered, exact-key protocol before any data
enters the report. Payload text, receipt strings, exception messages, traceback content,
environment values, hostname and absolute checkout paths are excluded. Malformed events
cannot inject arbitrary fields into reports. Source, runner/helper, fixture and lockfile
hashes use repository-relative POSIX paths. Source and installed SDK versions are separate;
platform/runtime and dependency metadata identify this observation's environment.

Exit zero requires complete samples, valid metadata, all outcome/warmup contracts, expected
active counts, no worker/protocol errors, and reaped children. Unexpected/incomplete work
returns one; interruption returns 130 while saving observations. A stopped child is not a
successful guard decision. Focused regressions validate corrupted outcomes, malformed
protocol, privacy, deadlines/cleanup, report preservation and platform-specific launch.
Native Windows CI remains required. These checks supplement the existing 21 resource
scenarios and phone probes; they do not replace them or complete the broader #45 issue.
