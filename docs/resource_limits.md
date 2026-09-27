# Resource limits and cancellation measurements

`evaluation/measure_resources.py` is a standalone, offline harness for issue
[#9](https://github.com/sahilmathur254/guardtrellis/issues/9). It measures fixed synthetic
inputs and trusted schema configurations in disposable child processes. It makes no
provider calls, loads no environment file, and needs only the installed core package.
It does not change Guard's runtime limits or supply a sandbox for application code.

## Reproduce

From a checkout with its frozen dependencies installed:

```sh
uv sync --frozen --group dev
uv run --frozen python evaluation/measure_resources.py \
  --report-dir /tmp/guardtrellis-resources-new
```

Choose a new output directory for each run: existing `results.json` or `REPORT.md` files
are never overwritten. Three repetitions of each scenario run sequentially by default.
For a smaller reproduction, select fixed scenarios with repeated `--case` arguments:

```sh
uv run --frozen python evaluation/measure_resources.py \
  --case reference_fanout_large --case sync_callback_timeout \
  --repetitions 1 --report-dir /tmp/guardtrellis-resource-focus
```

Use the parent command above. The hidden `--worker` argument is its internal subprocess
entry point and does not enforce its own wall-clock timeout. Do not invoke it directly.
There is no arbitrary schema, executable, payload, or plugin input to the harness.

## Coverage and containment

The 21 scenarios cover 100,000/100,001-character inputs; 256/257 PII findings and redaction
edits on large input; 128 maximum-length literal policies; JSON depths 32/33 and 64/65;
a 100,000-character schema; nested arrays; an `anyOf` mismatch with 128 branches;
500 unique objects; and document-local references that repeatedly visit the same subschema.
The small reference case has 256 possible leaf visits; the larger case has 1,048,576,
despite a one-character instance and a schema under 2,000 characters.

Async cases measure a synchronous callback and scanner outliving a Guard timeout, caller
cancellation, an async callback suppressing cancellation, and a callback blocking the event
loop. Events keep controlled workers alive until the observation is captured, then release
and join them. A deliberate sleeping-worker case checks external termination and reaping.

| Control | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Parent wall deadline, then force termination and wait | Yes | Yes | Yes |
| Child CPU soft/hard limit | 2/3 seconds | 2/3 seconds | Unavailable |
| Child address-space cap | 512 MiB | Not applied | Unavailable |
| Core dumps disabled; each output file capped at 64 KiB | Yes | Yes | Unavailable |
| Whole-child peak resident memory | Recorded | Recorded | Unknown |

The wall budget is five seconds per child, including imports and setup after process
creation. The supervisor self-check uses one second. Process creation and OS scheduling
can delay enforcement; termination/reaping gets a separate five-second allowance. The
parent kills the child's process group on POSIX, or the child on Windows. These fixed
workers create threads, never nested processes. Ctrl-C and SIGTERM run the same cleanup;
a killed parent or OS failure still requires an external supervisor. This is not a general
process-tree sandbox. Python's [subprocess documentation](https://docs.python.org/3/library/subprocess.html#subprocess.Popen.wait)
describes timeout and process-wait behavior.

CPU/file caps are applied before importing Guard in the child; Linux address-space limits
include the interpreter and all mappings, not just Python objects. Existing tighter
limits are preserved. Unsupported limits are recorded as `null`; a failed attempt to
apply a supported limit is an error. A Linux address-space cap is not a portable RSS cap.
The [resource API](https://docs.python.org/3/library/resource.html) is Unix-specific.
On macOS and Windows, use a separately limited container or job for a hard memory budget.
The CLI caps repetitions at five, wall time at 30 seconds, CPU at five seconds, and address
space at 1,024 MiB; these are harness guardrails, not recommended application settings.

Children receive a small allowlist of OS environment settings, excluding credentials and
Python startup hooks. Reports contain sizes, static codes, timings, versions, hashes,
exit status, and cleanup observations. They omit raw input/output, environment values,
absolute checkout paths, hostnames, and exception messages. Raw child standard error is
discarded; a nonzero byte count fails measurement checks.

## Interpreting evidence

The [reviewed local report](../evaluation/resource_limits/REPORT.md) and
[individual samples](../evaluation/resource_limits/results.json) retain all results.
The original 72-case detector corpus and its historical baseline are unchanged.

The 2026-09-26 local run used Python 3.12.0 on macOS ARM64, with three repetitions of all
21 scenarios. Its core and lockfile came from
[`bfc5d5e`](https://github.com/sahilmathur254/guardtrellis/commit/bfc5d5ea3b6c0b596b4d09ea67143a3d7a802559);
the report identifies the new harness by its separate digest. Later development-tool
updates do not rewrite this recorded baseline. All 63 children were reaped and the
measurement checks passed. Observations:

- The 100,000-character PII/invisible scan had a 6.8 ms median operation time. Redacting
  256 fabricated email occurrences in 100,000 characters took 4.6 ms at the median;
  a 257th occurrence produced `finding_limit_exceeded` with no deliverable text.
- All three large-reference scans reached the two-second CPU cap after construction.
  No completed validation decision or final resource sample exists for those runs.
  The 500-object uniqueness check took 91.7 ms at the median; these sizes do not prove
  an upper bound for other supported schemas or instances.
- Callback/scanner waits returned timeout ERROR around 101 ms while controlled threads
  were still running. Explicit caller cancellation propagated while its worker continued.
  All controlled workers finished after release. A callback blocking the event loop for
  300 ms returned ALLOW around 306 ms despite a 100 ms Guard wait setting.

These match documented limitations. No new contract violation was observed in this set.
macOS CPU and file caps were applied; address-space enforcement was unavailable. CI tests
exercise containment on the supported runner matrix, but do not make this local timing
baseline representative of Linux, Windows, or deployment workloads.

Each repetition starts a fresh interpreter. Setup includes fixture construction and scanner
configuration. Operation time covers the scan or await; cancellation cases time the await
after explicit cancellation. Parent wall time includes imports, setup, operation, cleanup,
and process exit. CPU time is whole-child CPU through the final sample. Peak RSS is the
whole-child maximum, normalized to bytes on Linux/macOS, not an allocation delta. Killed
children have no final CPU/RSS or operation sample: missing data is unknown, never zero.
Preparation metadata is flushed before synchronous scans, so stopped scans retain their
input/schema sizes. Import/construction failures remain distinguishable from scan stops.

The report records every sample, setup time, cleanup observation, Python/OS/architecture,
dependency versions, and SHA-256 digests of package source, harness, and lockfile. The lock
digest identifies the checkout's lockfile, while installed versions describe the runtime.
Three samples support observed ranges and medians only, not reliable tail-latency or
throughput estimates. Completed-only medians exclude CPU/wall stops, which stay visible
in a separate column. No warm-cache, production-concurrency, or universal worst-case
claim is made.

Exit zero means the measurement protocol and expected behavior checks passed. The large
reference scan can finish or reach its external CPU/wall budget; the supervisor probe
must be externally stopped. Neither stop means Guard returned a safe decision. Other
worker errors, unexpected stops, contract mismatches, stderr, or incomplete cleanup
produce exit one. Parent interruption saves completed samples and returns 130.

## Host controls supported by the observations

- Keep ingress byte limits and provider token limits in addition to Guard's character
  limit. Full callback output exists before the output-size check, and small JSON can
  still select expensive schema work.
- Review and reuse trusted schemas. Repeated local-reference branches and comparisons
  across unique objects can be expensive even within structural and text limits. For a
  hard deadline, isolate both schema construction and scanning under a process CPU,
  wall, and memory budget. Treat termination as a failed check and release no payload.
- Bound active work and queue depth at the host. An await returning ERROR does not free
  a worker thread that is still running. Admission accounting must cover actual worker
  completion, or terminate/reap the isolated process before admitting replacement work.
- Set provider-native request deadlines and retry budgets. Callback side effects already
  performed cannot be undone by Guard cancellation.
- Keep blocking work off the event loop. The blocking-coroutine measurement shows why
  an async wait is not a preemptive deadline; cancellation-resistant work also needs
  external containment. Guard's timeout remains per operation, not an end-to-end budget.
- Record static outcome codes, queue depth, active workers, external termination counts,
  and process resources. Measure your deployment to choose limits; these short local
  samples do not establish a safe concurrency setting or service-level objective.

These results quantify limitations already described in the [API contract](api.md#limits-and-asynchronous-work).
This measurement work does not alter detection rules or claim arbitrary schema execution
is bounded inside the Guard process. Any failure of a documented contract needs a separate
minimal reproduction and issue; undisclosed security defects follow [the security policy](https://github.com/sahilmathur254/guardtrellis/blob/main/SECURITY.md).
