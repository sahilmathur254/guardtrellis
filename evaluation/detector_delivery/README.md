# Detector and checked-delivery challenges, v1

This evaluation-only contribution to [#45](https://github.com/sahilmathur254/guardtrellis/issues/45)
belongs to unpublished `0.1.9`. It adds **48 original synthetic scenarios**, eight sensitive
and eight benign cases each for email, phone and credential-bearing connection metadata.
The 24 contrast pairs and English context are authored with knowledge of the SDK. All
values are fabricated and covered by Apache-2.0. No personal records, credentials,
provider/database/DNS requests or independently collected data are used.

The maintainer approved scope. Labels received author self-review with Codex assistance;
there is no independent, blinded or native-language per-case review. These public
development cases are not a representative or held-out benchmark. Repeated representations
are correlated: **384 observations do not mean 384 independent examples**.

## Reproduce

```sh
uv run --frozen python evaluation/detector_delivery/run.py \
  --report-dir /tmp/guardtrellis-detector-delivery-new
```

Choose a directory that does not exist. Reports never replace prior evidence. The full
384-observation protocol runs in every native CI matrix job. The issue and its linked
draft PR track current CI/review evidence; the retained local baseline alone does not
establish native Windows execution.

## Freeze before observing

The [protocol](PROTOCOL_v1.md), [corpus](corpus_v1.jsonl),
[384 explicit expectations](expectations_v1.json) and stdlib-only
[projection code](contract.py) were validated without importing the SDK. The
[freeze manifest](freeze_v1.json) binds their bytes, pre-scan SDK and lockfile hashes,
historical evaluation hashes, authorship and the pre-observation phase. Its SHA-256 is
`261e01a4482dcdde5bd87880c8c80e7238b99321cc0fe7a1a121fd2f7c667e19`.
The [external receipt](https://github.com/sahilmathur254/guardtrellis/issues/45#issuecomment-6444217374)
was posted before the first SDK observation. Runtime loaders verify every frozen asset
and independently reproduce its pure expectation projections before scanning.
The frozen protocol records the original local-only authorization. Later maintainer
authorization permits commit, push and draft review; the issue tracks that transition.
The historical protocol and its digest remain unchanged. Merge/publication require a
separate decision.

The initial exploratory run completed against that freeze before later harness tests and
report-format refinements. No frozen bytes or expectations were changed after observation.
The diagnostic checker was strengthened after that exploratory run to check isolated
authored password canaries as well as whole values; this changes no labels or SDK scoring.
Late-interruption handling during report writing was also hardened. Earlier exploratory
reports remain outside the checkout; the retained baseline was generated anew from the
final runner against the same unchanged freeze.
Any future label/projection correction needs a new, explicitly post-observation erratum;
retain the original decisions and results. Git attributes preserve frozen LF bytes on
Windows. Actual SDK/runtime/source digests in each report identify the code that ran;
the base commit alone does not identify local uncommitted evaluation changes.

## Matrix, labels and bounds

Two profiles configure `SecretScanner(BLOCK)` before `PIIScanner(REDACT)` at RETRIEVAL:
`default` keeps contiguous phones/URI checking disabled; `opt_in` selects formatted phones
and connection URIs. Other configuration is identical. Four representations are plain
text, literal JSON, fully Unicode-escaped JSON, and a fixed `value` explicitly decoded
once by the evaluation host. Both wire forms must decode identically; the duplicate
decoded value is scanned once. This adds no SDK decoder or tool authorization API.

Scenario intent has one desired action: benign ALLOW unchanged; sensitive email/phone
complete REDACT; sensitive connection metadata BLOCK. It includes known unsupported
contact/connection formats. Desired full text and Python character spans are fixed before
observation, including raw-wire projections and astral-character prefix offsets.

Contract expectations are a separate axis:

| Category | Observations | Meaning |
| --- | ---: | --- |
| Supported | 165 | Exact primary code/span/action contract, including clear negatives. |
| Contextual shape | 21 | Benign-intent templates/code still satisfy a supported shape and can trigger. |
| URI disabled control | 48 | No URI findings; incidental PII outcomes remain separate. |
| Raw escaped control | 96 | No implicit decoding: no primary finding and ALLOW. |
| Unsupported | 54 | Desired protection still scored; no promised primary span contract. |

The **330 eligible contract/control observations** include all four eligible categories;
they are not 330 supported-format detections. An incidental email finding never counts
as URI detection. A phone prefix can count as a signal while failing full-span redaction.
ERROR never counts as a detection. Scenario false positives may comply with the documented
shape contract. Report these meanings separately instead of relabelling after a run.

Inputs are at most 2,000 characters; the frozen maximum represented input is 750. Six
fixed children emit 64 ordered observations each, with 10-second wall budgets, 64 KiB
stdout/stderr bounds and a 90-second parent observation budget. Existing helpers supply
sanitized environments, supported CPU/memory limits and kill/reap behavior. Windows uses
the base interpreter plus the selected virtual-environment launcher, and cleanup precedes
temporary-directory removal. OS/process creation can delay enforcement; this is no process
sandbox or production deadline. CPU/RSS and wall time describe containment including setup,
not isolated scan timing, capacity, p95/p99 or an appropriate concurrency recommendation.

## Read the results

`results.json` contains validated metadata, per-observation actions, primary spans,
incidental codes and comparisons; it omits raw/checked payload, passwords, exception
messages, paths and environment values. `REPORT.md` summarizes per-family/profile counts
and retained mismatches. Reports also split observations by representation and language,
including expected positive/negative denominators, primary TP/FP/TN/FN, null undefined
rates, ERROR and incomplete work. Counts/rates describe only these selected observations.

`desired_exact` requires every frozen comparison: desired action, complete primary spans,
checked text and actual consumer delivery. `delivery_integrity` checks a different boundary:
the consumer receives exactly accepted `require_text()` data, or nothing on rejection.
Known undetected content can be accepted and correctly handed on, while still failing the
scenario's desired protection. The latter stays visible as a failed desired outcome.

The retained [local 0.1.9 baseline](baseline_0.1.9/REPORT.md) and
[full provenance](baseline_0.1.9/results.json) record complete observations with all
eligible contracts, no unexpected SDK/report-privacy/handoff failures, and all children
reaped. Desired exact outcomes are 99/192 default and 120/192 opted in. Contextual false
positives rise from 9 to 12 observations because the opt-in intentionally blocks a
documentation password placeholder. Unsupported forms and raw escaped JSON remain misses.
This does not rank general accuracy or assert that enabling options always improves a workflow.

Exit zero requires complete, valid, reaped measurements; no unexpected errors, metadata
privacy leaks or handoff corruption; and all eligible contracts. Desired-protection misses
remain visible without making known exclusions into unexpected SDK defects. Contract
violations pause acceptance for separate triage. Timeouts/interruption/protocol failures
retain validated prefix rows and explicit missing denominators; malformed worker content
is never copied into reports. Handled interruption exits 130, other evaluation failures
exit 1, invalid arguments/existing output directory exit 2. CLI errors are static.

## Boundaries and further work

SDK files, defaults, dependency versions, source version and every historical evaluation
file remain unchanged. Independent case review, broader benchmark coverage and any
competitor comparison remain open in #45. The CLI and this separate evaluation are the
two substantive `0.1.9` contributions; publication still needs a separate decision.
