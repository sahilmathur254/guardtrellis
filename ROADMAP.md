# GuardTrellis roadmap

GuardTrellis is a small, provider-independent Python SDK for explicit checks around model
inputs, complete outputs, retrieved text, and proposed tool calls. Keep the core local,
typed, composable, and independent of provider SDKs. Improvements should come with clear
contracts, failure behavior, and evidence for the formats they actually cover.

The [public GitHub Project](https://github.com/users/sahilmathur254/projects/3) is the source
of current status, priority, and ownership. This document explains direction and milestone
exit criteria. Each linked issue contains its scope, starting files, acceptance criteria,
and dependencies. Horizons are an order of work, not promised dates. Updated 2026-09-29.

The workstreams below are tracked on the Project in the agreed order. Design proposals and
demand-led validation remain distinct from implementation-ready work; a tracking issue does
not promise a feature, assignee, or delivery date. Project fields hold their current status.

## Available now

The [completed MVP](https://github.com/sahilmathur254/guardtrellis/issues/1) provides sync/async
orchestration, six checking capabilities, metadata-only diagnostics, explicit stage boundaries,
and credential-free callable, FastAPI, and LangGraph examples. The source is Apache-2.0 licensed.
CI validates Python 3.11–3.14 on Linux and Python 3.12 on macOS 15 ARM64 and Windows Server
2025 x64, including installation of both distribution formats. See the
[contributor guide](CONTRIBUTING.md) for the matrix and checks.

As of this update, the latest release is
[`0.1.1`](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.1).
The [release record](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.0)
documents the completed stable `0.1.0` publication and its verification evidence.
The [0.1.x compatibility policy](docs/compatibility.md) now applies. Check
[PyPI](https://pypi.org/project/guardtrellis/) for current package availability.
The [README](README.md) contains installation instructions matching this source checkout;
merged source changes may precede publication.

See the [quickstart](README.md), [API contracts](docs/api.md), and [limitations](docs/limitations.md)
before integrating. The [72-case synthetic evaluation](evaluation/REPORT.md) retains its misses
and false positives; it is not an independent benchmark or a production-readiness claim.

## Direction after the first stable release

Help application developers put explicit checks at the right boundaries, consume checked
results correctly, and measure their chosen policies against representative inputs. Prioritise
observed integration gaps over adding scanner families or framework wrappers for their own sake.

| Order | Workstream | Next outcome | Tracking |
| --- | --- | --- | --- |
| First | Structured values | Decide how to check decoded JSON strings without losing schema, privacy, or provenance guarantees. | Existing [#11](https://github.com/sahilmathur254/guardtrellis/issues/11); design before implementation |
| In parallel | Evaluation and coverage | Broaden independent contributions and test combinations of checks, then use evidence to select small detector improvements. | [#29](https://github.com/sahilmathur254/guardtrellis/issues/29); Now, P1 |
| In parallel | Integration recipes | Make policy ordering, checked-data handoff, and metadata-only operations easier to get right. | [#30](https://github.com/sahilmathur254/guardtrellis/issues/30); Now, P2 |
| After a concrete workflow is agreed | Local policy testing | Define a small CLI for running configured checks and inspecting outcomes outside application code. | [#31](https://github.com/sahilmathur254/guardtrellis/issues/31); Next, P2, design first |
| As adopters need them | Optional provider coverage | Validate requested provider paths and add examples only for distinct integration behavior. | [#32](https://github.com/sahilmathur254/guardtrellis/issues/32); Later, P2 |
| Later | Streaming | Decide whether a bounded release model is useful and defensible for a named caller. | Existing [#12](https://github.com/sahilmathur254/guardtrellis/issues/12); exploratory |

Maintain the current `0.1.x` series alongside this work. Patch fixes follow the existing
compatibility and changelog rules. New API surfaces need an explicit versioning decision;
planned incompatible changes require migration guidance and a later minor release. These
workstreams do not promise a `0.2.0` date or bundle every proposal into one release.

## Next: decoded JSON values

The [Unicode/PII challenge set](evaluation/challenges/README.md) contains equivalent plain and
escaped JSON inputs with different detection outcomes. Applications using structured model
outputs or tool arguments need an explicit way to check decoded strings. This is the clearest
existing coverage gap to investigate first; it does not imply that every encoding is supported.

Use [#11](https://github.com/sahilmathur254/guardtrellis/issues/11) for the design decision.
Compare a documented application recipe with an opt-in core API using a concrete caller
example. Keep existing text scanning and `ToolGuard` semantics intact while evaluating both.
The [decoded-JSON proposal](docs/decoded_json_design.md) defines a values-only option,
its limits and alternatives; the maintainer decision remains pending.

**Design exit criteria:**

- Specify whether values, keys, nested objects, and arrays are checked; bound total work,
  nesting, string sizes, and findings. Define handling of non-string values explicitly.
- Preserve strict JSON parsing and duplicate-key rejection before information is lost.
  Define immutability, redaction, reserialization, and schema revalidation after edits.
- Define finding locations and revisions for decoded strings without treating them as
  serialized-text offsets. Do not expose raw key names, values, or replacements in diagnostics.
- Cover escaped/plain equivalence, Unicode, invalid JSON, limits, scanner failures, and
  rejected-result access. If key edits are supported, address collisions after edits.
- Show that callers consume only checked values and that errors expose no ordinary payload.
  Record a maintainer decision on recipe versus API and the compatibility impact.

**Implementation gate:** an accepted design and a separately scoped implementation issue.
Retain the current challenge corpus and add new comparison evidence; do not rewrite historical
results to make the new behavior appear better.

Starting points: [tool validation](src/guardtrellis/tools.py),
[strict JSON checks](src/guardtrellis/json_check.py), and [API contracts](docs/api.md).

## Next: stronger evaluation and targeted coverage

**Tracked in [#29](https://github.com/sahilmathur254/guardtrellis/issues/29).** The existing
corpora are development evidence. More fixtures alone do not make
them independent or representative. Start with a bounded evaluation contribution, separate
from any detector implementation.

- Add benign and positive cases for secrets, JSON/tool behavior, and ordered scanner
  combinations. Include redaction followed by another check, blocked input preventing a
  callback, and rejection preventing tool dispatch.
- Seek independently authored cases and native-language review where language context
  affects the label. Record provenance, reviewer scope, and development versus held-out use;
  openly shared cases must not be described as a hidden independent test.
- Measure the intended outcome as well as detection: correct retained text, redaction spans,
  JSON validity, delivery decisions, and absence of raw payload in diagnostics/errors.
- Select detector improvements from a concrete supported-format defect or caller need.
  Each proposed format needs benign lookalikes, explicit exclusions, bounded processing,
  and a comparison against retained baselines. Avoid unqualified multilingual/PII claims.

**Exit criteria:** a versioned, attributable batch; reproducible per-family results with sample
counts, actions, errors, misses, and false positives; a documented reason for any label change.
Any detector change ships separately with a coverage statement, regression evidence, and
changelog entry. No arbitrary target accuracy is a release gate.

Existing text-policy evaluation can start independently. Decoded-value tests depend on the
#11 contract; streaming tests depend on #12. Use the [evaluation guide](evaluation/README.md),
[challenge methodology](evaluation/challenges/README.md), and
[resource harness](docs/resource_limits.md).

## Next: practical policy and operations recipes

**Tracked in [#30](https://github.com/sahilmathur254/guardtrellis/issues/30).** Extend the
existing [retrieval/tool recipe](docs/retrieval_tools.md) with small,
copyable examples of decisions that application developers currently have to assemble.

- Demonstrate different policies for input, retrieval, complete output, and tool arguments,
  with blocking checks placed before redactors when they must inspect original content.
- Show the behavior of `WARN`, `REDACT`, `BLOCK`, and `ERROR`, including consuming
  `require_text()` / `require_call()` results and avoiding accidental original-data reuse.
- Add one metadata-only logging/metrics recipe using `diagnostics()`, with application-owned
  request IDs and no prompt, response, matched-value, or raw tool-argument logging.
- Show host-owned concurrency limits and provider timeouts using the existing resource
  guidance. Do not imply that cancelling an async wait terminates the underlying work.

**Exit criteria:** each recipe has a specific caller problem, runs without credentials, and
includes rejection/error examples demonstrating the boundary it claims to enforce. Public
examples remain application-owned recipes, not new supported framework abstractions.
Add optional dependencies only when a recipe needs them.

This work can start on the current API. General decoded-value recipes should follow #11;
do not quietly introduce a second structured-data contract through an example.

## Next: local policy testing interface

**Design proposal [#31](https://github.com/sahilmathur254/guardtrellis/issues/31).**
A CLI could let a developer check selected text or fixtures from
a terminal or CI job using the same SDK policies as their application. This has standalone
value; no editor or agent integration is required to justify it.

Keep the first proposal small: one bounded text input from standard input or an explicit file,
an explicit stage/policy, a readable result, and a machine-readable metadata result. Decide
whether a declarative policy format is needed before adding a configuration system.

**Design exit criteria:**

- Specify invocation, policy ordering, limits, and stable exit statuses that distinguish
  accepted results, policy rejection, invalid configuration, and scanner/runtime errors.
- Keep content out of command-line arguments and default reports. Make emitting checked
  text an explicit choice; never echo rejected input or overwrite the source file implicitly.
- If configuration is supported, validate a versioned schema and reject unknown fields;
  do not execute arbitrary Python, import paths, or shell commands from configuration.
- Reuse SDK results without duplicating detector logic. Document that diagnostics may still
  reveal offsets/lengths and that CI logs or external instrumentation remain caller-owned.
- Define installation and process behavior on the supported platforms, including malformed
  input, encoding, stdin limits, scanner failures, and cancellation.

**Implementation gate:** agree a repeatable terminal/CI use case and the smallest interface
that serves it, then open a scoped implementation issue. Plain-text checking can reuse today's SDK;
structured-value support must wait for #11. Recursive repository scanning, automatic file
rewrites, and a general policy language are outside this initial proposal.

## As needed: provider and deployment evidence

**Demand-led proposal [#32](https://github.com/sahilmathur254/guardtrellis/issues/32).**
The [Gemini live smoke](docs/gemini.md#recorded-live-smoke-2026-09-26) remains
one dated request; [OpenAI](docs/openai.md) and [Azure OpenAI](docs/azure_openai.md) remain
mock-verified. Broaden this evidence when an adopter needs a particular path, rather than
equating another SDK wrapper with validated integration.

**Exit criteria for each selected path:** mocked acceptance, rejection, provider failure,
and timeout tests; an explicitly approved, bounded live smoke with synthetic data; recorded
source/SDK/model/date and the exact boundary exercised. Normal tests stay credential-free
and offline. A live smoke does not establish model quality or general production readiness.

Keep framework/provider dependencies optional. Add deployment guidance for observed problems,
building on the existing host-control recipe. A new provider, framework, or hosted service
is not a prerequisite for the structured-value or local-testing work.

## Completed: first PyPI alpha

[Milestone: First PyPI alpha](https://github.com/sahilmathur254/guardtrellis/milestone/1)

Make the existing implementation easy to install and honest about its maturity. New scanner
families, streaming, and the entire validation roadmap are not prerequisites for the alpha.

| Work | Outcome | Status |
| --- | --- | --- |
| [#2 Package metadata and release notes](https://github.com/sahilmathur254/guardtrellis/issues/2) | Verified package URLs, readable description, version agreement, and inspected artifacts. | Complete |
| [#3 Reviewed publishing workflow](https://github.com/sahilmathur254/guardtrellis/issues/3) | An explicit TestPyPI/PyPI artifact flow using Trusted Publishing, with maintainer-controlled publication. | Complete |
| [#4 First alpha publication](https://github.com/sahilmathur254/guardtrellis/issues/4) | Verified TestPyPI rehearsal, an approved PyPI alpha, and a matching GitHub prerelease. | Complete |

**Exit criteria:** the approved version installs from PyPI outside the checkout; its artifacts,
metadata, examples, and limitations have been checked; release evidence is linked from the issue.
These criteria were met for `0.1.0a1` on 2026-09-25. The
[prerelease](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.0a1) records the
source commit, hashes, and verification runs. Future releases follow the [release checklist](docs/releasing.md).

## Completed: broader validation

[Milestone: Broader validation](https://github.com/sahilmathur254/guardtrellis/milestone/2)

The initial validation tasks are complete. Their evidence remains bounded to the documented
formats, platform matrix, synthetic corpora, and provider requests.

| Work | Outcome |
| --- | --- |
| [#5 Retrieval and tool-call recipe](https://github.com/sahilmathur254/guardtrellis/issues/5) | [Runnable core-only recipe](docs/retrieval_tools.md) with checked retrieval, validated tool arguments, rejection tests, and distribution smoke coverage. [PR #24](https://github.com/sahilmathur254/guardtrellis/pull/24) merged. |
| [#6 macOS and Windows installation coverage](https://github.com/sahilmathur254/guardtrellis/issues/6) | Remote installation/example evidence on both platforms while retaining the Linux Python matrix. |
| [#7 Multilingual and benign challenge fixtures](https://github.com/sahilmathur254/guardtrellis/issues/7) | First [40-case Unicode/PII development set](evaluation/challenges/README.md) with provenance, per-family/language results, action counts, and retained failures. [PR #23](https://github.com/sahilmathur254/guardtrellis/pull/23) merged; independent contributions and native-language review remain welcome. |
| [#8 One real provider integration](https://github.com/sahilmathur254/guardtrellis/issues/8) | [Gemini live smoke passed](docs/gemini.md#recorded-live-smoke-2026-09-26) on 2026-09-26; included in `0.1.0a2`. [OpenAI](docs/openai.md) and [Azure](docs/azure_openai.md) remain mock-verified. |
| [#9 Resource-limit measurements](https://github.com/sahilmathur254/guardtrellis/issues/9) | [Bounded harness and host controls](docs/resource_limits.md), with a separate [local report](evaluation/resource_limits/REPORT.md) for large inputs, expensive schemas, and cancellation. [PR #20](https://github.com/sahilmathur254/guardtrellis/pull/20) merged. |

**Exit criteria:** each result is reproducible, its supported scope and limitations are documented,
and relevant CI or measurement evidence is linked. Collect actual adopter feedback alongside
this work. Do not expand safety claims based only on more passing synthetic examples.

## Completed: stable 0.1.0 release

[Milestone: Stable 0.1.0 review](https://github.com/sahilmathur254/guardtrellis/milestone/3)

[#10 Compatibility and release review](https://github.com/sahilmathur254/guardtrellis/issues/10)
closed after the approved `0.1.0` publication on 2026-09-29. It records the release decision,
exact-commit CI, TestPyPI rehearsal, PyPI promotion, and installation evidence. The
[0.1.x compatibility policy](docs/compatibility.md) and
[migration notes](docs/compatibility.md#upgrading-from-an-alpha) define the support commitment.

**Exit criteria:** a maintainer records a go/no-go decision tied to a specific commit and its
evidence. Remaining limitations are explicit. A stable version is a compatibility/support
decision; it does not certify comprehensive detection or safe tool execution. These criteria
were met for `0.1.0`; future releases still require their own approved evidence and publication.

## Later: streaming design

| Proposal | Decision needed before implementation |
| --- | --- |
| [#12 Streaming](https://github.com/sahilmathur254/guardtrellis/issues/12) | Buffering/release semantics, cross-chunk detection, bounded resources, and which checks can make meaningful guarantees. |

This remains exploratory, without a committed release or date. Compare full buffering and
bounded-window approaches for a concrete caller before adding an API. Specify exactly when
content becomes deliverable and which checks remain meaningful at that point.

**Design exit criteria:** a falsifiable validation plan covering split signatures, Unicode
boundaries, incomplete JSON, redaction, size limits, backpressure, cancellation, and errors;
explicit latency/memory tradeoffs; and a maintainer decision before implementation. A late
rejection cannot retract content already delivered. Keep complete-response behavior dependable.

## Scope boundaries

Provider frameworks and model downloads remain optional; arbitrary regex, automatic PII
rehydration, hosted services, and broad semantic safety claims require separate justification.
GuardTrellis continues to validate explicitly supplied data. It does not supply authorization,
a tool sandbox, comprehensive prompt-injection prevention, or compliance certification.

## Contribute and maintain the roadmap

Start in the Project's **Ready to contribute** view, read the issue, and comment before starting.
Choose an open issue whose scope and dependencies match the contribution.
Use the [contributor guide](CONTRIBUTING.md) for setup, validation, and the fork/PR workflow.

Status moves through **Backlog → Ready → In progress → In review → Done**. Use **Blocked**
when an issue names a dependency or maintainer decision that prevents completion. P1 marks
release readiness or important validation, P2 adoption/compatibility work, and P3 exploratory
design. No assignee or delivery date is implied by an issue's presence on the board.

Maintainers update project fields when work starts, enters review, or is completed, and link
the PR or other completion evidence in the issue. Before adding new work, check for duplicates
and create a scoped repository issue with starting files, acceptance criteria, dependencies,
and proposed priority. Link that issue here and on the Project. Design-only issues require
their recorded decision before implementation; backlog proposals do not imply assignments.

Review the ordering after concrete adopter feedback, evaluation findings, or a shipped release.
Keep historical completion evidence and limitations intact, and update this document when
milestone intent or exit criteria change. Public contributors can use issues and forks without
board edit access.
