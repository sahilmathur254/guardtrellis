# Changelog

See [PyPI](https://pypi.org/project/guardtrellis/) for package availability and
[GitHub releases](https://github.com/sahilmathur254/guardtrellis/releases) for published
artifacts and verification evidence.

## 0.1.8

- Add explicitly enabled `SecretScanner(connection_strings=True)` for password-bearing
  PostgreSQL and MongoDB URIs, including PostgreSQL query passwords. The option requires
  BLOCK, reports whole candidate spans, and preserves overlapping token signatures.
- Bound opted-in input size, candidate length and candidate attempts, including direct
  scanner calls. Processing failures and changed block-only configuration return static
  ERROR results without checked output.
- Add default-versus-opt-in comparisons against the frozen connection-string corpora,
  separate supported-format acceptance, all-stage delivery regressions and bounded resource
  probes. Preserve raw escaped-JSON misses and historical evidence.
- Refresh locked optional/development dependencies, including certifi and OpenTelemetry,
  and pinned CI/publishing actions. Declared dependency ranges remain unchanged.

Upgrade note: existing `SecretScanner()` calls and dependency requirements are unchanged.
Enable the option explicitly before redactors in each required stage. Nonempty masks and
placeholders can block; malformed or unsupported formats can remain undetected. JSON
decoding stays application-owned. See the [connection-URI guide](docs/connection_strings.md)
for supported boundaries, processing limits and exclusions.

## 0.1.7

- Preserve the Gemini example's one-request contract with newer Google Gen AI SDKs by
  disabling automatic continuation. Incomplete responses with continuation tokens become
  `ERROR` without another HTTP request or deliverable text. Retain compatibility with older
  supported SDKs that do not expose the continuation option, with mocked regressions at the
  actual HTTP boundary.
- Refresh the locked optional integrations and development tooling: FastAPI, LangGraph,
  LangGraph Checkpoint, LangSmith, OpenAI, Google Gen AI, and Ruff. Declared dependency
  ranges remain unchanged.
- Add a separate bounded concurrency evaluation for existing async APIs, with exact
  checked callback delivery, rejection isolation, resource observations and a reduced
  cross-platform CI protocol. Retain historical evidence and incomplete measurements;
  no detector, scheduler or SDK deadline change is included.
- Add a control-coverage guide linking configured behavior to source, regression tests,
  retained evidence and application responsibilities. Refresh current roadmap and recipe
  status while preserving historical reports and decisions.

Upgrade note: applications that copied `examples/gemini_app.py` should adopt its explicit
continuation configuration when updating the Gemini SDK. No core SDK API, default-policy,
or detector behavior changes from `0.1.6`.

## 0.1.6

- Add optional `PIIScanner(phone_mode="formatted")` for a bounded ASCII international
  phone grammar: an explicit plus, 8–15 digits, single spaces/hyphens between groups,
  and at most one balanced parenthesized digit group. Match and redact complete original
  spans, including `+12025550123-4567`; invalid/overlong candidates do not fall back to
  a contiguous-prefix match. Such candidates remain undetected, rather than being blocked.
- Add regression coverage and a versioned default-versus-formatted evaluation with exact
  action, span and checked-delivery comparisons, retained limitations, and bounded resource
  observations. Preserve all historical corpora, profiles and baseline reports.
- Simplify the distribution smoke stages while preserving core-only, OpenAI-only and
  all-extras installations, assertions and example executions for both distributions.

Upgrade note: existing calls retain the default `phone_mode="contiguous"`, including its
known partial-prefix matches. Enable formatted mode explicitly in each desired stage;
`formats` still controls whether phones are checked. This additive optional API retains
the `0.1.x` compatibility contract. Malformed candidates can lose legacy prefix findings
when opting in. Phone-like signed numbers remain ambiguous; national numbers, extensions,
Unicode separators/digits, dotted formats and verbal obfuscation remain unsupported.
There is no implicit JSON decoding, dependency change, or change to the fixed contact recipe.

## 0.1.5

- Add an application-owned decoded contact recipe for a fixed two-field schema using
  existing public APIs. Check both decoded fields for secrets before PII redaction,
  enforce whole-call limits, retain separate decoded provenance, and authorize only the
  final schema-validated checked arguments. Include regression and fresh-install smokes.
- Add a separate authored contact comparison and the retained 63-case escaped-JSON/phone
  development baseline. Keep raw-text misses, formatted-phone limitations and exact-delivery
  mismatches visible; these evaluations do not establish general detection accuracy.
- Fix Windows temporary-directory cleanup in the resource evaluation worker and simplify
  distribution smoke setup. Add a PyPI download badge outside the generated release block.

No core runtime API, dependency-requirement, default-policy, or detection-rule changes from
`0.1.4`. Applications must explicitly adopt the contact recipe; upgrading alone does not
enable decoded-value inspection. Formatted-phone coverage remains a separate follow-up.

## 0.1.4

- Add a core-only tool-result handoff recipe using the existing public API. Validate and
  authorize the tool call, then check returned text before the next model or agent-state
  consumer receives it. Include redaction, rejection, callback/scanner failure, privacy,
  original-return reuse, and fresh distribution installation coverage.

No core runtime API, dependency-requirement, or detection-rule changes from `0.1.3`.

## 0.1.3

- Add a core-only decoded `search.query` recipe that checks equivalent plain/escaped
  supported values using current public APIs, revalidates edited JSON, and dispatches
  only final checked arguments after application authorization. Include bounded-input,
  Unicode, scanner-failure, privacy, and no-dispatch tests and fresh distribution smokes.
- Record the accepted recipe-first decoded-JSON decision. A shared nested/multi-field
  checker remains deferred until a concrete caller need justifies a separate core API.

No core runtime API, dependency, or detection-rule changes from `0.1.2`.

## 0.1.2

- Document and regression-test async tool handoff after redaction, rejection, scanner
  failure, timeout, and caller cancellation, including late scanner completion.
  Clarify per-scanner deadlines and caller-owned authorization/execution limits.
- Add a core-only policy/operations recipe showing separate input, retrieval, tool, and
  output policies, checked-data handoff, metadata-only logging, and application resource
  controls. Include rejection/failure tests and distribution smoke coverage.
- Add a separate versioned synthetic evaluation for scanner combinations, secret signatures,
  JSON/tool validation, and checked callback/tool delivery. Report detection and delivery
  mismatches separately while retaining known misses, false positives, and historical corpora.
- Expand the roadmap and propose a decoded-JSON values contract for maintainer review.
  The proposal does not implement or change structured-value scanning.

No core runtime API, dependency, or detection-rule changes from `0.1.1`.

## 0.1.1

- Add the GuardTrellis logo to the repository README and packaged PyPI description.
  Include the original image in the source archive.
- Make callback-timeout regression tests deterministic across platforms, covering both
  callbacks that start before cancellation and coroutine cleanup when startup is delayed.

No runtime API, dependency, or detection-rule changes from `0.1.0`.

## 0.1.0

- Adopt a [compatibility and support policy](docs/compatibility.md) for the `0.1.x`
  final-release series: preserve documented public imports, call signatures, result fields,
  action/stage meanings, and existing diagnostics; define detection-fix exceptions,
  deprecation notices, supported Python versions, and dependency/maintenance expectations.
- Prepare non-alpha package metadata and matching installation instructions. Update current
  documentation to describe the compatibility promise while retaining historical alpha notes,
  evaluation reports, and provider verification limits.
- Define changelog maintenance rules for user-visible changes, compatibility/dependency
  changes, detection fixes, and migration guidance. Distinguish normal GitHub releases from
  prereleases in the publishing checklist.

No core runtime or scanner-rule changes from `0.1.0a4`. Applications using its documented
API need only update their version pin and run their application checks. Copied OpenAI/Azure
SDK 2 adapters from earlier alphas still need the
[SDK 3 migration](docs/openai.md#sdk-3-compatibility) already included in `0.1.0a4`.
Detection coverage, serialized-JSON scanning, async cancellation, and host-owned authorization
retain their [documented limitations](docs/limitations.md).

## 0.1.0a4 — 2026-09-28

- Add a runnable retrieval/tool-call recipe using only core dependencies. It demonstrates
  checking retrieved text before prompt assembly, validating proposed tool arguments, and
  executing the checked call behind application-owned authorization. Rejection tests and
  fresh distribution smokes cover the complete recipe.
- Add a separate 40-case synthetic Unicode/PII development challenge set with provenance,
  multilingual context, benign cases, escaped JSON pairs, and retained failures. Reports
  include per-family/language results and action counts; the original 72-case corpus and
  historical reports are preserved. These development results are not an independent benchmark.
- Migrate the optional OpenAI/Azure examples to OpenAI SDK 3 and HTTPX2. The `openai` extra
  now requires `openai>=3,<4` and `httpx2>=2.12,<3`. Custom transports, clients, and exception
  handling must use HTTPX2; its default certificate trust comes from the operating system.
  See the [migration guide](docs/openai.md#sdk-3-compatibility). Both provider paths remain
  mock-verified; no new live provider verification is claimed.
- Refresh the package description, versioned installation commands, guide links for PyPI,
  and roadmap completion evidence.

No core Guard/scanner API or detection-rule changes. This remains an experimental alpha;
application authorization, execution limits, and output handling remain the host's responsibility.

## 0.1.0a3

- Generate the module version and README installation instructions from `pyproject.toml`.
  CI checks source, lockfile, and changelog agreement; release validation checks the README
  embedded in both distributions and the description returned by TestPyPI and PyPI.
  Corrects the stale `0.1.0a1` installation pin shipped in the `0.1.0a2` description.

- Reproducible offline resource measurements in bounded child processes, with retained
  CPU/wall stops, input/finding/depth boundary cases, expensive schemas, and cancellation
  observations. Includes host-control guidance and a separate reviewed local baseline;
  no core runtime limits or detection rules change.

## 0.1.0a2 — 2026-09-26

- Optional OpenAI Responses callback example with a credential-free HTTP mock, tested
  input/output boundaries, and a separately opted-in one-request live smoke. Adds the
  `openai` extra without changing core dependencies or public Guard APIs. Live verification
  is pending; see the [integration guide](docs/openai.md).
- Standalone Azure OpenAI Chat Completions example using the same optional SDK extra,
  with mocked HTTP boundary/failure tests and a separate, explicitly opted-in bounded
  live command. Azure live verification is also pending; see its [guide](docs/azure_openai.md).
- CI installation coverage for macOS and Windows alongside Linux Python 3.11–3.14.
- Optional Gemini Developer API example with a separate `gemini` extra, mocked boundary
  tests, and a one-request live smoke for an approved Free Tier project. See the
  [Gemini guide](docs/gemini.md#recorded-live-smoke-2026-09-26) for the passing one-request
  live smoke on 2026-09-26 (10 input and 5 output tokens).
- Clarified which synthetic evaluation fixtures and baselines belong in version control.

No core Guard/scanner API or detection-rule changes. The recorded `0.1.0a1` synthetic
baseline is retained. Gemini supplies the recorded live provider evidence; OpenAI and
Azure remain mock-verified only. Published after the
[TestPyPI rehearsal](https://github.com/sahilmathur254/guardtrellis/actions/runs/36245484256)
and [PyPI promotion](https://github.com/sahilmathur254/guardtrellis/actions/runs/36245714535).
Its package description contains an outdated installation pin; use the latest release instead.

## 0.1.0a1 — 2026-09-25

The first alpha is available on [PyPI](https://pypi.org/project/guardtrellis/0.1.0a1/).
The [GitHub prerelease](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.0a1)
records the exact source commit, unchanged rehearsed artifacts, and verification evidence.
Publication is tracked in [#4](https://github.com/sahilmathur254/guardtrellis/issues/4).

### Included

- Typed `Guard` and scanner contracts with synchronous/asynchronous entry points,
  explicit input/output/retrieval/tool stages, and ordered redaction provenance.
- Explicit allow, warn, redact, block, and error outcomes. Rejected inputs do not reach
  callbacks; blocked/error results do not expose ordinary deliverable text or arguments.
- Local checks for documented PII shapes, selected secret signatures, Unicode control/format
  characters, literal policies, strict JSON/constrained Draft 2020-12 schemas, and tool-call
  name/object-argument validation.
- Bounded text, findings, and JSON depth; per-operation async waits with documented
  cancellation limitations; metadata-only diagnostics and payload-free rejection errors.
- Optional, credential-free callable, FastAPI, and LangGraph examples. The core requires
  only jsonschema and referencing plus their dependencies, with no provider SDK or model download.
- Python 3.11–3.14 support, typed package metadata, Apache-2.0 licensing, wheel/sdist
  installation checks, and a reproducible synthetic smoke evaluation with retained failures.

### Compatibility and known limitations

This is an experimental API. Names, contracts, and dependencies can change before a stable
version; such changes will be documented with migration guidance. Pin an exact alpha version
or source commit when evaluating it. No new runtime API changes are included in release preparation.

Checks inspect only explicitly supplied text and configured formats. Coverage excludes many
PII/secret formats and semantic safety judgments. WARN permits delivery, unconfigured stages
permit bounded text, and tool validation supplies neither authorization nor sandboxing.
Outputs are checked only after the complete callback response; there is no streaming API.
Async timeout does not terminate arbitrary Python code or undo callback side effects.

The 72-case authored smoke corpus includes four known misses and two false positives. Its
aggregate results are not a general accuracy estimate or an independent security benchmark.
See [limitations](docs/limitations.md), [API contracts](docs/api.md), and the
[evaluation report](evaluation/REPORT.md) before integrating.
