# Connection-URI contract supplement, v1

This evaluation-only batch accompanies the revised [#68 contract](PROPOSAL.md).
The SDK, default policies, dependency set and version remain unchanged at 0.1.7.
No connection-string detector is implemented or simulated by this evaluator.

## Frozen authorship and decisions

[contract_supplement_v1.jsonl](contract_supplement_v1.jsonl) contains 60 fabricated cases
authored with Codex assistance on 2026-10-22. The complete file, labels, rationales and
character intervals were frozen before any SDK observations, at SHA-256
`586d3e9d6a0bff898dd6d593f7927a95039c3d6b607fe14e1a1b371a0563a13c`.
Hosts use example/reserved forms; no credential, network or database validation occurs.

| Contract status | Cases | Comparison |
| --- | ---: | --- |
| `selected` | 52 | 40 sensitive URI cases, 11 benign cases and one existing-token overlap control; desired BLOCK/ALLOW and complete spans are authored expectations. |
| `excluded` | 6 | MongoDB query-only credentials, double-encoded keys, aliases, fragment-like fields, missing userinfo terminator and malformed query key; null comparisons make no safety claim. |
| `resource_pending` | 2 | Existing 2,000/2,001-character input conditions; null comparisons do not select future detector limits. |

Every row adds `case_group`, `origin_case_id` and `contract_status` to the v1 schema, with
`dataset_version=connection-strings-contract-v1`. All twelve originally ambiguous inputs
are copied byte-for-byte as decoded text into separate rows with their original IDs in
`origin_case_id`. Eleven now have selected decisions; the MongoDB query-only example
remains excluded. The original corpus, runner and published baseline are untouched.

The cases cover ASCII scheme/key casing, once-encoded query keys, literal and encoded
delimiters, `#`, apostrophes, explicit prose wrappers, environment/angle templates,
empty username versus empty password, invalid URI syntax with visible credentials,
duplicate query values, userinfo plus query credentials, multiple URIs, Unicode offsets,
existing token overlap and benign scheme lookalikes. They are a bounded development set,
not exhaustive grammar coverage or independent/held-out data. Repeated representations
are correlated observations and do not establish population accuracy.

## Reproduce unchanged-SDK observations

```sh
uv run --frozen python evaluation/connection_strings/run_supplement.py \
  --report-dir /tmp/guardtrellis-connection-contract-v1

uv run --frozen pytest tests/test_connection_string_evaluation.py \
  tests/test_connection_string_supplement.py -W error
```

Use a fresh report directory. The supplement runner reuses the frozen v1 observation,
checked-delivery, coordinate mapping and diagnostic-canary logic. It validates the extra
metadata separately, then validates the common fields through an in-memory projection
to the v1 schema; no file or historical label is rewritten. Origin IDs must identify
an original ambiguous case with exactly matching text and cannot repeat.

Both existing policies (`secret_only` and `tool_return`) run across the same five plain,
raw-JSON and explicitly decoded representations: 600 observations, 520 with selected
decisions and 80 unscored. The two resource-pending cases only observe the existing
recipe's input limit; this is not a resource probe of the proposed detector.

Reports record `opt_in_status=not_implemented`, both runner hashes, both corpus hashes,
the contract hash, actual imported SDK hashes and runtime dependencies. They retain
summaries by contract status, case group, family, label and policy/representation, plus
all safe observations. No raw payload, accepted text, credential value or exception text
is reported. Existing token BLOCKs and incidental PII redactions remain distinguishable
from the proposed whole-URI targets. Authored canaries test selected diagnostic surfaces;
they do not establish that every possible secret fragment or logging path is covered.

Exit codes follow v1: zero for completed observations including known coverage gaps;
one for unexpected SDK, harness or diagnostic-privacy failures; two for invalid corpus
or report arguments. Reports refuse to overwrite previous evidence.

The same command is wired into the existing CI matrix for future Linux, macOS and native
Windows runs. Local results do not establish native Windows success. Keep this batch
separate from the later opt-in implementation, resource probes and version decision.

## Retained 0.1.7 observations

The [supplemental report](contract_baseline_0.1.7/REPORT.md) and
[complete results](contract_baseline_0.1.7/results.json) use an external installation of
published 0.1.7 on local macOS/Python 3.12.1. All six imported SDK Python files were
compared byte-for-byte with the previously verified published wheel, SHA-256
`ba8b6fb0056a561b9cd4e1c9f1dedf4cd2461910170f497065f2c50ad66263c4`.
The report hashes the actual imported sources, evaluation inputs and revised contract.

Of 600 observations, 520 have selected decisions: 110 match the desired action/delivery
and 102 match every authored comparison. The eight existing-token BLOCKs do not match
the proposed whole-URI spans. There are 14 expected input-limit errors and zero unexpected
errors, harness failures or detected diagnostic leaks. Eight benign observations have
incidental findings; these remain visible instead of being relabelled.

These are measurements of the current SDK's gaps. They establish neither the proposed
detector's behavior nor production coverage. Structural-boundary refinements and resource
probes listed in the contract remain explicit gates before the corresponding SDK work.
