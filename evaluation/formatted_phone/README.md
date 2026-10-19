# Formatted-phone opt-in comparison, v1

This batch implements the evaluation slice of
[#60](https://github.com/sahilmathur254/guardtrellis/issues/60). It compares the
unchanged default `PIIScanner()` policy with explicit
`PIIScanner(phone_mode="formatted")` on the same authored desired outcomes.
It does not change the historical corpora, their labels, runners or reports.

Run from the repository root with locked development dependencies:

```sh
uv run --frozen python evaluation/formatted_phone/run.py \
  --resources --report-dir /tmp/guardtrellis-formatted-phone-v1
```

Choose a fresh report directory. The runner never overwrites evidence and makes
no provider, network or host-tool requests. `results.json` records source/runtime
versions, hashes, action metadata, exact comparison booleans and optional resource
measurements. `REPORT.md` provides a compact comparison. Source version and
installed-distribution version are separate because an editable checkout may not
have refreshed distribution metadata after a version edit.

The retained [0.1.6 candidate report](baseline_0.1.6/REPORT.md) records 50/93 exact
default outcomes and 81/93 formatted outcomes, with zero unexpected or detected
privacy failures. The twelve remaining formatted mismatches are the signed-integer
ambiguity, six deferred forms, and five raw escaped-JSON cases. Both resource modes
completed all eight contracts on the recorded local macOS/Python environment.
[results.json](baseline_0.1.6/results.json) retains the exact source hashes and
platform details; this local observation does not establish native Windows CI success.

## Versioned inputs and provenance

The 93 cases are **AI-assisted authored synthetic development fixtures** prepared
with knowledge of detector behavior and the proposed grammar, Apache-2.0 licensed.
They are not held-out, blinded, independently reviewed, multilingual, or
production accuracy evidence. Expected spans, action, checked callback input and
final delivery are stored in the fixtures; detector outputs do not generate labels.

- The unchanged [63-case detection corpus](../policy_combinations/detection_coverage_v1.jsonl)
  provides all 39 historical phone scenarios: six existing contiguous positives,
  eleven proposed formatted cases, sixteen benign lookalikes and six deferred
  forms. Its other 24 cases retain six plain/escaped JSON meanings under raw and
  explicitly decoded workflows. Every historical ID, label and dataset version
  remains intact; this is an attributable reuse, not a newly independent sample.
- [grammar_v1.jsonl](grammar_v1.jsonl) adds 30 separately versioned boundary cases:
  nine positives and twenty-one negatives. They cover 7/8/15/16-digit limits,
  identifiers (including unsupported Unicode numeric continuations), punctuation,
  adjacent numeric groups, repeated/mixed separators,
  missing or unmatched parentheses, multiple or non-digit groups and leading zero.
  A parenthesized group at the end is supported. If another group follows it,
  a separator is required. Malformed or overlong candidates have desired ALLOW,
  unchanged delivery and no finding; these are syntax boundaries, not claims that
  the strings are safe to share.

The comparison uses two modes, yielding 186 observations. `default` invokes the
existing policy runner without substituting any scanner or patching its globals.
`formatted` uses the same fixed policy order and action wiring with only the
explicit phone mode changed. The regression suite compares every default
historical action, finding/delivery comparison and callback/dispatch count with
the preserved 0.1.4 report. This establishes compatibility for those fixtures; it
is not a new measurement of the old installed wheel.

## Interpreting the comparison

The reviewed candidate should satisfy all eleven proposed phone cases, all six
existing positives, and all fifteen unambiguous historical negatives. The signed
ledger integer is deliberately retained as a false positive: its characters are
indistinguishable from a phone shape. Six deferred forms retain positive desired
protection labels, so their misses or incomplete coverage remain visible.

The original `+12025550123-4567` case requires one complete fifteen-digit span;
a prefix-only redaction fails even if it produces a positive detection signal.
Other expectations verify original Python character offsets after emoji, WARN
preservation, BLOCK callback prevention, output redaction, and checked delivery.
Neither a phone-shaped string nor a match establishes country-code validity,
allocation, ownership, identity or user intent.

For JSON, the raw profile scans wire text. The decoded profile invokes the shipped
`decoded_query.check_query` policy hook with secrets followed by email/phone PII
in `Stage.TOOL`, then dispatches only the final checked pair to an in-memory
recorder. It preserves earlier decoded REDACT separately from final schema ALLOW.
Decoded findings refer to the decoded query string, while raw findings refer to
wire text. Expected checked dictionaries are independently identical for each
plain/escaped pair. Raw escaped JSON misses remain failed desired outcomes;
enabling formatted phones does not add decoding to the SDK. The shipped fixed
contact helper does not silently opt in and its historical report stays unchanged.

Reports contain no input, expected/released text, dispatched dictionaries,
exceptions or diagnostic payloads. The reused canary checks inspect selected
metadata/repr/rejection surfaces against exact synthetic input and decoded/wire
markers; they are regression evidence, not exhaustive leak detection. The new
adapter also checks rejected exception repr for direct formatted workflows.

Exit zero means the comparison had no unexpected harness error, detected privacy
failure or failed resource contract. **Known outcome mismatches do not make the
exit code nonzero.** Review their IDs and exact comparisons. Tests enforce the
scoped acceptance counts and preserve known gaps rather than relabelling them.

## Resource probes

`--resources` runs one child for each mode with an external ten-second wall
deadline, bounded output capture and mandatory reaping. Existing resource-harness
helpers supply process cleanup and platform-dependent CPU/address-space caps;
its code and recorded results are unchanged. Windows uses the base interpreter
with the virtual-environment launcher setting to avoid the known cleanup race.
Unavailable OS caps remain `null`; a deadline/error is never recorded as a
completed scanner observation. Omitting the flag records `resource_probes: null`.

Each child exercises eight fixed cases: 100,000 and 100,001-character inputs,
long digit/separator/parenthesis/plus runs, and 256/257 formatted-phone findings.
The accepted 256-finding case must redact; 257 must fail closed without deliverable
text. Operation times exclude import/setup; wall times include child startup and
cleanup. RSS is whole-process peak where available. These are bounded local
measurements, not throughput estimates, worst-case proofs or a synchronous SDK
execution deadline. The isolated helper is also runnable directly:

```sh
uv run --frozen python evaluation/formatted_phone/resources.py
```

This batch supplements SDK unit tests, retained evaluation reproductions,
distribution smokes and native Windows CI; it does not replace those gates.
