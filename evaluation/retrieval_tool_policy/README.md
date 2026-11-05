# Retrieval and tool trust-boundary evaluation, v1

Evaluation contribution to [#35](https://github.com/sahilmathur254/guardtrellis/issues/35)
under the [accepted design](../../docs/retrieval_tool_policy_design.md). The SDK remains
0.1.11. Source availability, native CI and package publication are separate evidence.

## Scope and reproduction

Twelve original English-language synthetic scenarios form six attack-intent/legitimate
contrast pairs. Eleven harness controls are reported separately. Proposals are scripted
data; no model, provider, database, network tool, live credential or attacker page is used.
These AI-assisted public development cases have author self-review and internal assistant
review, not independent external review or a hidden held-out benchmark.

```sh
uv run --frozen python evaluation/retrieval_tool_policy/run.py \
  --report-dir /tmp/guardtrellis-retrieval-tool-new
```

Choose a directory that does not exist. Existing reports are never replaced. CI runs the
same bounded 23-workflow batch on the platform matrix. Native Windows evidence comes from
the actual workflow run for the commit under review. The Windows launcher/cleanup
regressions are local contract checks, not a native CI pass.

## Pre-observation freeze

The [protocol](PROTOCOL_v1.md), [twelve scenarios](corpus_v1.jsonl),
[eleven controls](harness_controls_v1.jsonl), [23 exact expectations](expectations_v1.json),
[pure projection code](contract.py) and [primary-source ledger](sources_v1.json) were frozen
before the first new-fixture SDK observation. Projection and validation used only the
standard library and did not import GuardTrellis.

The accepted design and manifest retain the authorization scope recorded when they were
created. Later authorization to commit and push this contribution for review does not
retroactively change those historical records or authorize a merge or release.

The [manifest](freeze_v1.json) SHA-256 is
`d08e3c0fa5909e087364e98f71390ce4e85d81d51e4c5b7f49bf13c9b69d771d`.
Its [external receipt](https://github.com/sahilmathur254/guardtrellis/issues/35#issuecomment-6634543759)
was created at `2026-11-04T15:23:43Z`, before the first supervised observation timestamp
`2026-11-04T15:26:01.165621+00:00`. The loader verifies all frozen asset bytes and reproduces
their pure authored projections before scanning. Labels and expectations are not tuned
after observing the SDK; a correction requires a new version or explicit erratum.

The manifest records base `3ca712fc62006a33a222566ad7d8705c5c1979fd`, SDK 0.1.11,
accepted-design/SDK/helper/lockfile hashes and identities of all 76 historical evaluation
files. Actual imported SDK, dependency versions, source and runner hashes are recorded
separately for each run. A single identity is pinned across the batch and required of each
child; a changed identity is a failed observation, never silently mixed into that baseline.

## What the batch establishes

| Pair | Boundary | Interpretation |
| --- | --- | --- |
| P1 | Retrieval instruction override versus quoted instructions | Both can ALLOW unchanged; the configured pattern policy does not classify instruction intent. |
| P2 | Returned tool/approval spoofing versus quoted definitions | Text cannot replace the host's fixed tool configuration, but instruction-like returned text can still reach the consumer. |
| P3 | Extra destination property | Schema restriction prevents this proposed call; it is not URL/SSRF protection. |
| P4 | Unknown tool name | Exact name validation rejects before authorization/dispatch. |
| P5 | Schema-valid private document | SDK validity and host authorization are separate; the host denies before execution. |
| P6 | Fabricated supported secret versus legitimate contact | Secret BLOCK precedes PII redaction; the contact control delivers exactly the redacted value. |

Both text boundaries use default secret-BLOCK-before-PII-REDACT rules at RETRIEVAL with
2,000-character limits. The fixed flat `lookup` schema and host permission gate follow
the existing handoff recipe. No SDK default, detector, dependency requirement, provider
integration or shared API is changed.

The oracle asserts exact per-boundary diagnostics/actions/spans, ordered events, callback
counts, checked proposer input, authorization/dispatch pairs and consumer text. It keeps
payload values inside assertion memory and emits fixed metadata/comparison booleans.
Harness controls separately cover initial retrieval REDACT/BLOCK/ERROR, return ERROR,
literal-True authorization, copy isolation, callback failure, strict JSON and seven
deliberate checked-handoff bypasses. They do not inflate the twelve-scenario denominator.

The two semantic-intent limitations R01/R03 remain unfulfilled desired policy goals.
Current-contract conformance does not make those strings harmless or establish model
resistance. Desired-goal counts are descriptive labels for this scripted batch, not
precision/recall, an injection detection score, or an attack-success percentage.

## Bounds, failures and retained evidence

Each scheduled workflow uses a fresh child, a ten-second observation budget clipped to
the parent's remaining 180 seconds, and 64 KiB stdout/stderr caps per stream. Existing
helpers supply platform-specific resource controls, sanitized environments and kill/reap
behavior. Cleanup has its own five-second reap wait, followed by size-bounded reporting;
there is no 180-second whole-process or hard filesystem-I/O deadline.

Reports account for all 12 research cases and 11 controls, including not-started cases,
ineligible later boundaries, timeouts, capture/protocol failures and actual cleanup state.
Validated completed-prefix rows survive later failures. JSON plus Markdown is capped at
512 KiB. Report writing and interruption status are finalized consistently; unavailable
storage cannot guarantee retained evidence. Reports omit raw/checked text, arguments,
synthetic token/email canaries, exception messages and host paths.

The first exploratory run completed all 23 contracts against the unchanged freeze.
Subsequent harness review tightened late-interruption reporting, pinned batch source
identity and explicit unexpected-ERROR accounting. Exploratory output stays outside the
checkout; the final reviewed baseline identifies the actual runner that produced it.

The retained [SDK 0.1.11 local report](baseline_0.1.11/REPORT.md) and
[raw metadata](baseline_0.1.11/results.json) record all twelve research and eleven control
contracts matched, all 23 children completed/reaped, and zero unexpected errors, incomplete
records, report-privacy failures or handoff-integrity failures. Two SDK ERROR controls and
three callback-error controls are expected and counted separately. The two semantic
limitations remain visible; their outcomes were not relabelled. The source/runtime hashes
match the pre-observation SDK/lock snapshot and identify the reviewed runner.

Local macOS arm64 / Python 3.12.0 verification passed 1,950 tests with warnings treated
as errors, including 85 focused evaluation regressions. Ruff, formatting, strict existing
SDK/example mypy checks, source-version agreement, offline wheel/sdist build, strict Twine
and fresh core/OpenAI-only/all-extras mocked installation checks also passed. This local
evidence is separate from native Windows CI results for the proposed commit.

Exit zero requires complete/reaped work, exact eligible contracts and handoff integrity,
privacy safety and no unexpected SDK/runtime failures. Expected SDK ERROR and callback
failure controls remain separate from unexpected errors. Known semantic limitations
remain visible without turning the runner into a semantic catch-score gate.

This contribution adds no SDK behavior, defaults, dependency requirements or version
changes, and preserves historical evaluation files. The maintainer accepted #35 as completed
bounded research on 2026-11-05; its [acceptance record](https://github.com/sahilmathur254/guardtrellis/issues/35)
retains R01/R03's semantic limitations and accepts no new SDK API, detector or reusable
recipe. Any future behavior change needs a separately scoped decision. This batch and its
tests/docs are one contribution; it does not by itself authorize a release.

## Post-maintenance local comparison

The original baseline retains base `3ca712fc62006a33a222566ad7d8705c5c1979fd` and its
original dependency lock. The local contribution now inherits approved main
`263b6bd4907f35fa8a6fbe3384da6279c5ec15f1`, including PR #90's patched `pyasn1` 0.6.5
lock and macOS 26 ARM64 CI image. These maintenance changes are separate from #35.

A separate local replay on 2026-11-05 matched all twelve research contracts and eleven
harness controls, with all 23 public outcome rows identical to the original baseline.
Every child completed and was reaped; there were no unexpected errors, privacy failures,
integrity failures or incomplete records. Expected error controls and the two R01/R03
instruction-intent ALLOW limitations remain unchanged. The frozen assets, manifest,
accepted design and original baseline were not rewritten.

The actual checkout base and installed `pyasn1` version are recorded in separate local
comparison notes. The new report records the patched lock digest, while its
`metadata.baseline_commit` intentionally identifies the original freeze base. Reproduction
uses a new report directory rather than replacing `baseline_0.1.11`.

The refreshed local environment passed all 1,950 tests with warnings treated as errors,
lint/format/type checks and all fourteen evaluation commands. Main's native macOS and
Windows results do not validate the new #35 files; inspect the contribution's actual CI
run for its commit. These results establish no missing SDK primitive or semantic-injection
protection, and do not by themselves justify another workflow wrapper or a core API change.
