# Connection-string development evaluation, v1

This is the evaluation-only increment for
[#67](https://github.com/sahilmathur254/guardtrellis/issues/67), a bounded contribution
to #45. It records the published 0.1.7 SDK's behavior before the separately gated
[#68 detector proposal](https://github.com/sahilmathur254/guardtrellis/issues/68).
It changes no SDK behavior, default, dependency or version.

## Reproduce

```sh
uv run --frozen python evaluation/connection_strings/run.py \
  --report-dir /tmp/guardtrellis-connection-strings-v1

uv run --frozen pytest tests/test_connection_string_evaluation.py -W error
```

Use a new report directory. The runner refuses to overwrite earlier evidence.
Exploratory reports belong outside the checkout; the retained published baseline
is [baseline_0.1.7/REPORT.md](baseline_0.1.7/REPORT.md), with all observations and
provenance in [results.json](baseline_0.1.7/results.json).

Exit zero means observations completed without unexpected SDK errors, delivery contract
failures or detected diagnostic leaks. Known coverage misses and false positives remain
visible and do not fail CI. An exit of one means a harness, privacy or unexpected-error
failure; invalid corpus/report arguments return two. No detection-score or timing threshold
is enforced.

## Authorship, labels and bounds

[corpus_v1.jsonl](corpus_v1.jsonl) has 52 original, AI-assisted synthetic development
cases authored with Codex assistance on 2026-10-21. Case IDs, scenario labels,
target/credential intervals and rationales were fixed before recording SDK outcomes.
All credentials are fabricated and hosts use reserved/example forms. No database,
DNS, provider, network probe or credential-validity check runs.

| Authored label | Cases | Intended decision |
| --- | ---: | --- |
| `sensitive` | 24 | BLOCK credential-bearing PostgreSQL/MongoDB URI content. |
| `benign` | 10 | ALLOW unchanged, including credential-free and username-only URIs. |
| `ambiguous` | 12 | Record behavior; exclude from success denominators until policy review. |
| `control` | 2 | BLOCK already supported GitHub/AWS-shaped token signatures. |
| `deferred` | 4 | Retain desired BLOCK and gaps for keyword/value and SQL Server/ODBC forms. |

These are desired scenario outcomes, not claims about current supported formats or live
credentials. Empty, masked, environment-reference, documentation, malformed and unusual
grammar cases are explicitly policy-dependent. Do not relabel them from detector output.
Deferred formats stay visible without broadening #68.

Every row records `dataset_version`, `source`, `usage=development` and `label_basis`.
These public fixtures are not held-out, blinded, independently collected or representative.
Five representations and two policies produce 520 correlated observations, not 520
independent examples. There is one repetition; no population accuracy or latency claim.

The loader caps corpus bytes at 256 KiB, cases at 60, original text at 2,100 Python
characters, authored candidates at four and span lists at eight. Fixed JSON wire values
are capped at 14,000 characters; both scan policies use the recipe's 2,000-character
limit. The corpus includes exact 2,000/2,001-character candidates. JSON expansion can cross
the scan limit too. These bounds constrain this runner's work, without establishing a
production deadline or containment of arbitrary scanner code.

Format provenance:
[PostgreSQL libpq connection strings](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING),
[MongoDB standard and SRV connection strings](https://www.mongodb.com/docs/manual/reference/connection-string-formats/),
and [ADO.NET connection-string syntax](https://learn.microsoft.com/en-us/dotnet/framework/data/adonet/connection-string-syntax).
They inform authored syntax and deferred examples, not full driver compatibility.

## Fixed policies and representation coordinates

Both policies run at `Stage.RETRIEVAL` through the actual
[tool-result handoff recipe](../../examples/tool_result_handoff.py), with a valid
fixed tool call, local authorization and in-memory tool/consumer callbacks.

- `secret_only`: default `SecretScanner()` with BLOCK behavior.
- `tool_return`: shipped `RETURN_POLICY`, ordered as `SecretScanner()` BLOCK,
  `LiteralScanner(["internal-only"])` BLOCK, then default `PIIScanner()` REDACT.

`plain` scans the original string. `json_plain` scans a fixed one-field serialized
object with normal JSON escaping; `json_escaped` scans the same value with every
character encoded as JSON Unicode escapes. `decoded_plain` and `decoded_escaped`
strictly parse their respective fixed objects once, then scan the decoded string.
The parser rejects duplicate keys, non-finite values, wrong shapes, empty strings,
invalid Unicode and over-limit values. It does not recursively decode literal escapes.

Plain and decoded offsets refer to the scanned Python string. Raw JSON offsets refer
to serialized wire characters, including expansion and surrogate pairs. Finding revision
and scanner identity remain explicit. The harness maps authored intervals for each wire
representation; it never presents decoded offsets as wire offsets. JSON handling here
is application-owned evaluation code, not a new SDK decoding API.

## What is measured

For each observation the runner records exact safe finding metadata, action, acceptance
and consumer count, plus four distinct authored comparisons:

1. `action`: desired BLOCK/ALLOW against the actual action.
2. `delivery`: no consumer for desired BLOCK; exactly unchanged text for desired ALLOW.
3. `target_spans`: revision-zero secret findings against complete authored URI targets,
   or supported token intervals for controls; benign cases must have no finding.
4. `credential_coverage`: a valid rejection withholds everything, or actual redaction
   intervals cover every authored credential component and its raw/wire/explicit marker
   spellings are absent from consumer data. Benign cases must have no finding.

The complete checked transformation is also verified independently: merged overlapping
PII spans must become `[PII]`, with all other text preserved. Actual `Result.text`, the
recipe's return value and consumer history must agree with this reconstruction. Rejected
results must expose no text and invoke no consumer. Regressions deliberately corrupt
checked output and inject original-text fallback to prove those checks fail.

An email-shaped userinfo match is **incidental PII**, not connection-string detection.
REDACT can fail the desired BLOCK contract even when an authored password is removed.
Removing one component is not complete coverage if a query password survives. An expected
input-limit ERROR withholds content but is not a secret detection or desired BLOCK-action
match. Existing signature controls exercise the current detector; fully escaped raw-wire
controls retain their misses until explicit decoding.

Actual diagnostics, result repr, rejection messages/repr and recipe logs are checked in
memory for authored canaries and escaped spellings. Automatic complete-input privacy markers
have an eight-character minimum to avoid matching ordinary metadata words. Explicit credential
canaries are at least eight characters. Reports contain no input, output, exception text or
credential values, and allowlist finding metadata. This tests selected surfaces and canaries,
not every possible log channel or secret fragment.

`results.json` retains all rows, summaries by policy/representation, database family and
authored label, actual action counts and known mismatches. `exact_outcome_matches` requires
all four authored comparisons with no unexpected, harness or privacy failure. Policy-dependent
rows have null comparisons and never enter that denominator. Positive missing-signature
counts include deferred forms, raw escaped controls and limit errors; inspect their labels
and actions instead of interpreting the aggregate as detector accuracy.

## Published 0.1.7 baseline

The retained run uses an isolated installed 0.1.7 SDK, outside this checkout, on local macOS
and Python 3.12.1. All six imported SDK Python files were compared byte-for-byte with the
previously verified published wheel before running. The wheel SHA-256 is
`ba8b6fb0056a561b9cd4e1c9f1dedf4cd2461910170f497065f2c50ad66263c4`;
the release commit is `9ee817b857f72ffbbc5fcc8cc7c1927dc9f8ff44`.
The evaluation runner is new local work based on that release; it is not part of the
published 0.1.7 artifact. Runtime dependencies were jsonschema 4.26.0 and referencing 0.37.0.

The report hashes the actual imported SDK files separately from the corpus, runner,
unchanged handoff recipe, pyproject and lockfile. Paths are relative POSIX names, without
machine-local checkout locations. Preserve this directory for future comparisons; use a
new versioned report and do not rewrite its misses.

Across 520 observations, 400 have authored decisions and 120 remain policy-dependent.
There are 112 complete authored matches, 126 desired delivery matches, 14 expected input-limit
errors and no unexpected SDK errors, harness failures or detected diagnostic leaks. Those
112 complete matches comprise 96 benign outcomes and 16 signature controls.

For the 240 sensitive-URI observations, none BLOCK: 159 ALLOW, 67 REDACT through incidental
PII and 14 exceed the input limit. Of the 67 redactions, four leave an authored credential
component uncovered. All 40 deferred-format observations ALLOW. Four of 100 benign
observations are unnecessarily redacted. These are concrete development gaps, not a
population error-rate estimate.

CI is wired to reproduce this batch on the existing Python/OS matrix, including native
Windows. Local macOS tests and portable-path regressions do not establish native Windows
success; check the CI results for the exact commit under review.

## Next decision

Review these outcomes and the [proposed detector contract](PROPOSAL.md) before any #68
SDK change. #67 remains open until contract review and required platform checks are complete.
An opt-in detector and accompanying documentation may join a later batched release,
tentatively 0.1.8; this evaluation does not select or publish that version.
