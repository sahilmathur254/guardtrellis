# Connection-URI structural boundaries, v1

This 16-case addendum completes the grammar decisions for the [#68 contract](PROPOSAL.md).
It changes no SDK behavior, policy, dependency or source version. The proposed opt-in
detector remains unimplemented; these are observations of the current 0.1.7 policies.

## Authored decisions

[boundaries_v1.jsonl](boundaries_v1.jsonl) contains original synthetic development inputs
authored with Codex assistance on 2026-10-22. All IDs, actions, rationales and spans were
fixed before SDK observations. Final pre-observation SHA-256:
`a54ede2cdfb221e63e3af03d7e94eb86f7bd9cbadd927884b4a7646e5ab6d7b6`.
The final static review made the query-lookalike controls test `?` directly after the
authority, before any SDK run. No labels were selected from observed detector outcomes.

There are ten selected BLOCK cases and six selected ALLOW controls, covering twenty
candidates. The longest input is 143 Python characters. Hosts use reserved example forms
and every credential is fabricated. These are public, correlated development examples,
not held-out data, a population benchmark or credential-validity checks.

| Boundary | Decision fixed before observation |
| --- | --- |
| Extra literal colons | The first colon begins the opaque password region; later colons remain within it. |
| Multiple literal `@` characters | The last `@` ends the region. Nonempty content before it BLOCKs, including an initially empty gap before an earlier `@`. |
| Username-only or exactly empty region | No userinfo finding. This is a detector decision, not a claim that the driver accepts the URI. |
| Path and unrelated query lookalikes | `/` and `?` end the authority. `user:value@host` in those later components cannot supply userinfo. |
| Encoded delimiters | Encoded colon/`@` never create structure; they remain opaque inside a literal credential slot. |
| Malformed unrelated query pairs | A recognizable PostgreSQL password before or after the malformed pair still requires BLOCK. |

Every positive targets the full candidate, with its password region separately annotated.
Every control deliberately expects no connection-URI finding; that does not assert that
arbitrary content in an unsupported component is safe. The conservative multiple-separator
rule may block malformed or illustrative strings and does not reproduce database-driver
acceptance rules. All rows are `selected`, with `origin_case_id=null` and
`dataset_version=connection-strings-boundaries-v1`.

## Reproduce

```sh
uv run --frozen python evaluation/connection_strings/run_supplement.py \
  --corpus evaluation/connection_strings/boundaries_v1.jsonl \
  --report-dir /tmp/guardtrellis-connection-boundaries-v1

uv run --frozen pytest tests/test_connection_string_boundaries.py \
  tests/test_connection_string_supplement.py tests/test_connection_string_evaluation.py -W error
```

Use a fresh report directory. The existing supplement runner now accepts either known
dataset version, rejects mixed-version files, rejects inherited origin IDs in this new
batch, and records the version from the supplied corpus. Its default remains the frozen
60-case supplement. It reuses the original v1 observation machinery and validates the
same bounds and span contracts. It contains no connection-URI parser or simulated opt-in.

Two unchanged policies and five plain/raw-JSON/explicitly decoded representations produce
160 observations. Reports retain exact safe finding metadata and checked-delivery
comparisons, source/corpus/contract hashes and actual imported SDK provenance. No raw
payload, credentials, accepted output or exception text is retained. Known coverage gaps
do not fail the evaluator; unexpected SDK errors and privacy/harness failures do.

Historical corpora and reports remain byte-for-byte unchanged. Their old contract/runner
hashes identify those earlier snapshots; do not update them to the current files. The new
report belongs in its own directory. JSONL line endings remain LF for reproducible hashes
on Windows. CI includes this batch, but an unpushed local run establishes no native Windows
result for the addendum.

## Retained 0.1.7 observations

The [boundary report](boundary_baseline_0.1.7/REPORT.md) and
[complete results](boundary_baseline_0.1.7/results.json) use an external installed 0.1.7
SDK on local macOS/Python 3.12.1. All six imported SDK files were compared byte-for-byte
with the previously verified published wheel, SHA-256
`ba8b6fb0056a561b9cd4e1c9f1dedf4cd2461910170f497065f2c50ad66263c4`.
The report records the actual corpus, runner and finalized contract hashes separately
from imported SDK hashes and runtime dependencies.

All 160 observations completed: 116 ALLOW and 44 incidental PII REDACT, with no BLOCK.
Forty observations match all authored comparisons. Twenty benign-control observations
have incidental findings, and all 100 sensitive-case observations lack a secret-signature
finding. These are retained limitations of the current policies, not reasons to change
the authored labels. No unexpected errors, input-limit errors, harness failures or detected
diagnostic leaks occurred. This result makes no claim that the unimplemented detector
passes any case.

## Implementation gate

The boundary decisions complete preparation for the agreed opt-in implementation.
Numeric candidate/work limits will be selected using bounded subprocess probes of that
implementation before acceptance, including direct scanner calls and Guard pipelines.
The earlier 2,000-character recipe examples do not select production detector limits.
No resource probe or new limit is implemented by this addendum.

Existing-token overlap, default compatibility, exact spans, all-stage checked delivery,
safe static failures, Windows CI and package smokes remain implementation acceptance
requirements. Version 0.1.8 remains a tentative later batch, not a publication decision.
