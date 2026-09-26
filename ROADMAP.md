# GuardTrellis roadmap

GuardTrellis is a small, provider-independent Python SDK for explicit checks around model
inputs, complete outputs, retrieved text, and proposed tool calls. Keep the core local,
typed, composable, and independent of provider SDKs. Improvements should come with clear
contracts, failure behavior, and evidence for the formats they actually cover.

The [public GitHub Project](https://github.com/users/sahilmathur254/projects/3) is the source
of current status, priority, and ownership. This document explains direction and milestone
exit criteria. Each linked issue contains its scope, starting files, acceptance criteria,
and dependencies. Horizons are an order of work, not promised dates. Updated 2026-09-26.

## Available now

The [completed MVP](https://github.com/sahilmathur254/guardtrellis/issues/1) provides sync/async
orchestration, six checking capabilities, metadata-only diagnostics, explicit stage boundaries,
and credential-free callable, FastAPI, and LangGraph examples. The source is Apache-2.0 licensed.
CI validates Python 3.11–3.14 on Linux and Python 3.12 on macOS 15 ARM64 and Windows Server
2025 x64, including installation of both distribution formats. See the
[contributor guide](CONTRIBUTING.md) for the matrix and checks.

The current alpha, [0.1.0a1](https://pypi.org/project/guardtrellis/0.1.0a1/), is available on PyPI:

```sh
python -m pip install 'guardtrellis==0.1.0a1'
```

See the [quickstart](README.md), [API contracts](docs/api.md), and [limitations](docs/limitations.md)
before integrating. The [72-case synthetic evaluation](evaluation/REPORT.md) retains its misses
and false positives; it is not an independent benchmark or a production-readiness claim.

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

## Now: broader validation

[Milestone: Broader validation](https://github.com/sahilmathur254/guardtrellis/milestone/2)

These tasks can start independently while users evaluate the published alpha.

| Work | Outcome |
| --- | --- |
| [#5 Retrieval and tool-call recipe](https://github.com/sahilmathur254/guardtrellis/issues/5) | A runnable, tested example that passes checked data across boundaries. Good first issue. |
| [#6 macOS and Windows installation coverage](https://github.com/sahilmathur254/guardtrellis/issues/6) | Remote installation/example evidence on both platforms while retaining the Linux Python matrix. |
| [#7 Multilingual and benign challenge fixtures](https://github.com/sahilmathur254/guardtrellis/issues/7) | Attributed, versioned evaluation cases with per-family results and retained failures. |
| [#8 One real provider integration](https://github.com/sahilmathur254/guardtrellis/issues/8) | [Gemini live smoke passed](docs/gemini.md#recorded-live-smoke-2026-09-26) on 2026-09-26; [PR #16](https://github.com/sahilmathur254/guardtrellis/pull/16) merged. The `0.1.0a2` candidate remains unpublished. [OpenAI](docs/openai.md) and [Azure](docs/azure_openai.md) remain mock-verified. |
| [#9 Resource-limit measurements](https://github.com/sahilmathur254/guardtrellis/issues/9) | [Bounded harness and host controls](docs/resource_limits.md), with a separate [local report](evaluation/resource_limits/REPORT.md) for large inputs, expensive schemas, and cancellation. Implementation is ready for review; issue completion awaits merge. |

**Exit criteria:** each result is reproducible, its supported scope and limitations are documented,
and relevant CI or measurement evidence is linked. Collect actual adopter feedback alongside
this work. Do not expand safety claims based only on more passing synthetic examples.

## Next: stable 0.1.0 review

[Milestone: Stable 0.1.0 review](https://github.com/sahilmathur254/guardtrellis/milestone/3)

[#10 Compatibility and release review](https://github.com/sahilmathur254/guardtrellis/issues/10)
depends on the alpha and validation work above. Review at least one external integration
report, resolve release-blocking defects, define public API compatibility expectations, and
write migration notes for any alpha changes.

**Exit criteria:** a maintainer records a go/no-go decision tied to a specific commit and its
evidence. Remaining limitations are explicit. A stable version is a compatibility/support
decision; it does not certify comprehensive detection or safe tool execution. The project can
remain alpha if the evidence does not support a stable release.

## Later: proposals requiring design decisions

| Proposal | Decision needed before implementation |
| --- | --- |
| [#11 Checks for decoded JSON values](https://github.com/sahilmathur254/guardtrellis/issues/11) | Whether a core API is justified; traversal, schema revalidation, redaction provenance, and privacy contracts. |
| [#12 Streaming](https://github.com/sahilmathur254/guardtrellis/issues/12) | Buffering/release semantics, cross-chunk detection, bounded resources, and which checks can make meaningful guarantees. |

These are exploratory proposals, without a committed release or date. Keep complete-response
behavior and the existing explicit policy model dependable while discussing new capabilities.
Provider frameworks and model downloads remain optional; arbitrary regex, automatic PII
rehydration, hosted services, and broad semantic safety claims require separate justification.

## Contribute and maintain the roadmap

Start in the Project's **Ready to contribute** view, read the issue, and comment before starting.
[#5](https://github.com/sahilmathur254/guardtrellis/issues/5) is a small entry point.
Use the [contributor guide](CONTRIBUTING.md) for setup, validation, and the fork/PR workflow.

Status moves through **Backlog → Ready → In progress → In review → Done**. Use **Blocked**
when an issue names a dependency or maintainer decision that prevents completion. P1 marks
release readiness or important validation, P2 adoption/compatibility work, and P3 exploratory
design. No assignee or delivery date is implied by an issue's presence on the board.

Maintainers update project fields when work starts, enters review, or is completed, and link
the PR or other completion evidence in the issue. Add a repository issue before adding new
roadmap work, check for duplicates, and update this document when milestone intent or exit
criteria change. Public contributors can use issues and forks without board edit access.
