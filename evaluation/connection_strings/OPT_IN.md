# Connection-URI opt-in comparison

This separately versioned comparison exercises the local `connection_strings=True`
implementation against the same three frozen development corpora and the unchanged
default scanner. It does not rewrite earlier labels, runners or reports. The original
52 cases, 60-case supplement and 16-case boundary addendum produce 1,280 observations per
mode across two fixed policies and five representations. Some supplement cases inherit
original inputs; these are not 128 independent samples or held-out evaluation data.

## Acceptance authored before observation

`acceptance_v1.json` was generated from the finalized contract and original authored spans
on 2026-10-26, before the opt-in scanner was edited or observed. Its SHA-256 is
`1c1aeb4110b6c4545233c59560726bc96799a6713c4ad83adb5e9a628981a4d8`.
All three original corpus hashes are included and validated. The file remains immutable.

The 640 case/representation decisions have these explicit rules:

- Selected literal and explicitly decoded inputs use the original authored URI spans.
- Raw `json_plain` is eligible only when JSON encoding leaves the original string content
  literal. Adding wrapper quotes and the fixed object prefix shifts offsets by ten.
- Raw input whose quotes, backslashes, newlines or non-ASCII characters are escaped has
  separately retained desired-outcome comparisons but no URI acceptance claim. These
  transformations can change literal candidate boundaries. Eligibility does not depend
  on which candidates the detector happens to match.
- Fully Unicode-escaped raw JSON is outside the selected detector grammar. Decode the
  fixed string explicitly to compare its supported decoded equivalent.
- Deferred, ambiguous, excluded and resource-pending cases stay outside acceptance.
  Original token-only controls expect zero new URI spans and retain their token checks.
- The existing handoff recipe's 2,000-character return bound is applied independently by
  represented input length. Its expected ERROR rows are not credential-detection passes.

There are 402 grammar-eligible case/representation entries. The fixed return bound leaves
794 effective opt-in observations across the two policies. The accepted negative URI cases
still permit existing token findings or incidental PII redaction; those must match the
unchanged policy. Positive URI acceptance requires exact URI-code-only spans and complete
BLOCK with no consumer delivery. Existing overlapping token findings are checked separately.

### Transparent correction to the acceptance projection

The first observed run exposed one harness-authoring error: the initial projection treated
all `control` labels as token-only. `contract-existing-token-overlap` was already an authored
whole-URI case in the frozen supplement, with target `[0,81]`, and the contract explicitly
requires retaining its embedded token finding too. Its four eligible representations
therefore produced eight acceptance mismatches despite the scanner matching that contract.

`acceptance_corrections_v1.json` records this **post-observation harness correction**, using
the original `[0,81]` target (or `[10,91]` in literal raw JSON). SHA-256:
`9c5c1e7fddd813ad6629c9c15c07b7ec9d9c9e33fb4a32d8b5fc9e3e07ef34de`.
The loader verifies it against the already-frozen corpus targets. Neither the initial
acceptance file nor original corpus labels/spans are changed. This is a recorded correction,
not a claim that every final acceptance byte preceded observations.

## Reproduce

```sh
uv run --frozen python evaluation/connection_strings/opt_in.py \
  --resources --report-dir /tmp/guardtrellis-connection-opt-in-new
```

Use a fresh directory. `--resources` includes separately bounded direct-scanner and Guard
probes from `resources.py`; omit it for the comparison alone. Report source hashes cover the
runner, expectations, corrections, original corpora, baseline reports and actual imported
SDK Python files, including its private URI helper. Version strings identify the local
source build and do not establish publication.

Default compatibility compares all safe observation fields with the retained published
0.1.7 reports; runtime/source provenance is recorded separately. Desired BLOCK/ALLOW and
complete-output scores remain visible even for unsupported representations and formats.
Contract acceptance, existing token findings and incidental PII are separately represented,
so overlapping token findings or PII-only mismatches cannot be mistaken for URI coverage.
The inherited `secret_signature_signal` and `positive_cases_without_secret_signature`
fields refer only to the original token signatures; URI detection has its own fields.
The report contains static metadata, offsets and comparisons, never raw input, passwords,
accepted output, environment values or exception text. Synthetic credentials and provider
mocks only; no database, DNS, provider or credential-validity requests occur.

Exit zero requires unchanged default observations, all eligible URI contracts passing,
zero unexpected/harness/privacy failures and, when requested, successful resource contracts
with child cleanup. It does not require every desired-outcome score to pass or establish
production coverage, driver compatibility, secret validity or a performance guarantee.

## Retained local result

The [0.1.8 source-candidate report](opt_in_baseline_0.1.8/REPORT.md), recorded on
2026-10-26 with Python 3.12.0 on macOS ARM64, contains 2,560 observations:

- All 794 eligible opt-in observations satisfy the selected contract.
- All 1,280 default observations match the historical 0.1.7 behavior.
- Desired exact outcomes improve from 254 to 820 of 1,080 scored observations per mode;
  unsupported representations and deferred formats still contribute misses.
- Unexpected errors, privacy failures and harness failures are all zero.
- All 36 bounded resource observations match their expected outcomes; both child
  processes completed and were reaped, with no stderr output.

This is local development evidence for an unpublished candidate. Native Windows and Linux
validation must come from CI on the implementation commit. The earlier evaluation-only PR's
CI does not validate this detector. The [complete metadata](opt_in_baseline_0.1.8/results.json)
records source hashes, actual processing budgets and platform-specific resource limits.
