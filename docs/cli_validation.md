# Local CLI and connection-URI verification

Local verification on 2026-10-27, macOS arm64/Python 3.12.0, for the unpublished `0.1.9`
source candidate on top of `f41648815f0e06fe8e2afb385258b230669a973b`. This snapshot was taken
before committing the implementation; the base commit does not contain these changes. It records
authored development checks, not independent detection accuracy or native Windows evidence.

## CLI checks

- The full suite passed **1,546 tests** with warnings treated as errors, including 242 new
  CLI/CI/URI-handoff tests. New CLI regressions cover direct
  SDK policy parity at every stage; default/opt-in options; secret-before-PII ordering;
  complete reports, exact checked text and absence of rejected payload.
- Real subprocess checks cover strict UTF-8, Unicode/space paths, CRLF/BOM/NUL/escape
  preservation, empty input, inclusive 400,000-byte/100,000-character boundaries, invalid
  sources/encoding, stalled stdin with host termination/reaping and bootstrap failure.
- Fault injection and real descriptor tests cover short/zero/partial writes, broken
  stdout/stderr, both streams failing, flush failures, shutdown status 120 prevention,
  metadata-before-payload order, no payload after metadata failure, no second record after
  payload failure, handled KeyboardInterrupt and exit precedence. POSIX terminal/signal
  tests supplement portable injected tests; those POSIX-only cases skip on Windows.
- The strict privacy CI consumer rejects PII redactions, blocks, malformed/duplicate/
  mismatched reports and failed/timed-out child processes while retaining the privacy policy.
- Wheel and sdist install into separate disposable environments outside the checkout.
  Both real console/module launchers pass version, file/stdin byte, redaction and URI-block
  checks with core dependencies only. Existing core, OpenAI-only and all-extras mocked
  examples still run. Strict Twine checks pass for both artifacts.
- Ruff lint/format, strict mypy (SDK and documented examples), source-version agreement
  and `uv lock --check` pass. The lockfile changes only this package's source version;
  dependency versions and detector implementations are unchanged.

The source version, generated README block and changelog agree on candidate `0.1.9`;
publication and completion of its multi-improvement batch remain separate decisions.

## Connection strings

Fresh comparison command, using the unchanged three frozen corpora and historical reports:

```sh
python evaluation/connection_strings/opt_in.py --resources --report-dir /tmp/fresh-uri-comparison
```

The output directory must not already exist. The local run used
`/private/tmp/guardtrellis-78-connection-final`, with SDK and distribution metadata both
`0.1.9`. Its `results.json` SHA-256 is
`b6db64b44fa0b20d496bc5c2bdaa5d02fb5d3a46a9754e22206d7b31ebe96386`.
The report contains source/corpus/acceptance hashes; it is a disposable local artifact,
and historical checked-in reports have not been replaced.

| Check | Local result |
| --- | --- |
| Total observations | 2,560, split 1,280 per mode |
| Default compatibility | 1,280 matches; zero failures |
| Eligible opt-in contract observations | 794; zero contract failures |
| Unexpected errors / privacy failures / harness failures | Zero in both modes |
| Authored desired exact outcomes, scored subset | Default 254/1,080; opt-in 820/1,080 |
| Resource observations | 18 direct + 18 Guard; both protocols matched, children reaped, no stderr |

The scored subset includes unsupported formats and intentional conservative outcomes.
Its remaining mismatches are retained; a successful contract runner is not a claim that
all connection strings are detected. Raw escaped JSON, excluded driver/keyword formats,
double encoding and MongoDB query-only passwords remain outside the selected grammar.
Nonempty placeholders and masks intentionally block. URI work exhaustion remains ERROR.

New CLI handoff regressions independently state expected whole-candidate spans for
PostgreSQL userinfo/query passwords, case/percent-encoded keys, MongoDB host lists/SRV,
Unicode passwords and placeholder values at every stage under both policies. They assert
empty checked stdout and block-before-redact ordering, plus default/no-password/unsupported
outcomes and explicit application-owned JSON decoding. No database/provider requests run.

## Native CI and review gate

No native Windows runtime was available for this local snapshot. The existing CI matrix runs the CLI
tests and the enhanced wheel/sdist launcher smokes on Windows, macOS and Linux Python
3.11–3.14 on the submitted branch/PR. The Windows launcher uses `Scripts/guardtrellis.exe`;
stdio payloads use binary UTF-8. These are portability measures, not a Windows pass.
[#78](https://github.com/sahilmathur254/guardtrellis/issues/78) tracks the current draft PR,
native results and review status. This local snapshot alone does not complete its acceptance
gates. Commit/push/draft-PR authorization was given after this local verification; merge,
deployment and publication remain separate decisions.
