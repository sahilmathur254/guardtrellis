# Google GenAI 3 migration contract

Status: **Design and #96 implementation plan accepted 2026-11-09; local implementation ready for review.** Reviewed
[#95](https://github.com/sahilmathur254/guardtrellis/pull/95)'s dependency patch at
`7f0d43a1aa6070341057e60571b576006bbb9344`. Its CI retry at
`ad9246a30fa52042b3c6bab31c19d20800b6017f` has an identical source tree.
The accepted dependency, example and migration scope targets `0.2.0`, subject to the
implementation and release gates below. The published `0.1.x` requirements and SDK
behavior remain unchanged. Plan acceptance authorizes the scoped local implementation and
board updates. It does not approve #95 as written or authorize commits, pushes, merges
or publication. Native Windows CI and exact-head CodeQL remain later verification gates.

## Operational need and pre-migration gap

#95 broadens `google-genai>=2.25,<3` to `>=2.25,<4` and locks SDK 3.0.0 while retaining
the HTTPX-based [Gemini example](../examples/gemini_app.py), tests and documentation.
Google 3 changes the default HTTP backend to HTTPX2 and the Developer API default to
`v1`. The example explicitly selects `v1beta`, so that API default change is already
isolated; its production client still needs a deliberate HTTP-backend contract.

The pre-migration tests inject HTTPX transports. SDK 3 detects those objects and selects HTTPX,
while `transport=None` selects HTTPX2 under its default environment. Passing those
mocks therefore does not establish coverage of the production construction path.
The pre-migration installed smokes isolate OpenAI but exercise Gemini only with all extras.

The concrete goal is a dependable SDK 3-backed, credential-free example and an explicit
upgrade path for applications that copied the SDK 2 example. This is dependency and
application-adapter maintenance, not evidence of a customer commitment or a missing
core scanner primitive. The [compatibility policy](compatibility.md#python-dependencies-and-maintenance)
requires SDK-major migrations in a later minor release with migration notes.

## Primary sources

Reviewed 2026-11-09; the interpretations are limited to the pinned SDK version.

- [S1: Google GenAI 3.0.0 release](https://github.com/googleapis/python-genai/releases/tag/v3.0.0)
  documents the API/backend defaults, model-alias caveat and certificate-trust change.
- [S2: SDK 3 backend selection](https://github.com/googleapis/python-genai/blob/v3.0.0/google/genai/_api_client.py#L776-L852)
  checks the backend environment variable before inspecting supplied HTTP objects.
- [S3: SDK 3 client initialization](https://github.com/googleapis/python-genai/blob/v3.0.0/google/genai/_api_client.py#L1069-L1095)
  chooses client classes and accepts supplied clients.
- [S4: SDK 3 synchronous context cleanup](https://github.com/googleapis/python-genai/blob/v3.0.0/google/genai/client.py#L585-L615)
  closes the synchronous client, without closing the async client.
- [S5: SDK 3 dependency metadata](https://github.com/googleapis/python-genai/blob/v3.0.0/pyproject.toml#L25-L36)
  declares `httpx2>=2.0.0,<3`; the stronger floor selected below is a project choice.
- [S6: HTTPX2 2.12.0 metadata](https://pypi.org/pypi/httpx2/2.12.0/json)
  declares Python `>=3.10`; SDK 3.0.0 declares Python `>=3.11`.

## Accepted dependency and backend contract

Select one supported major/backend for the existing optional `gemini` extra:

- Accepted implementation requirements: `google-genai>=3.0.0,<4` and `httpx2>=2.12,<3`.
  Select `2.12` as a project support floor aligned with the existing
  [OpenAI extra](../pyproject.toml), rather than claiming SDK 3 requires that minimum.
  Core dependency requirements and provider-independent imports stay intact.
- Use HTTPX2 consistently for the example's client transport annotation, fixtures,
  request/response objects, timeout/connection exceptions and package-version report.
- Remove the example's direct HTTPX requirement from the `gemini` extra. Other extras
  may independently require HTTPX; all-extras availability must not mask Gemini needs.
- Prefer SDK-owned clients configured through `HttpOptions.client_args`, preserving
  context-manager ownership. Do not inject separately owned clients merely to force
  selection; doing so requires an additional explicit client-cleanup contract.
- Do not silently fall back to SDK 2 or HTTPX after a configuration or provider error.

This deliberately replaces the proposed cross-major range in #95. Maintaining both
SDK majors would require separate resolver/test environments and a supported branching
contract; that broader maintenance promise is outside the accepted scope.

The declared-minimum profile constrains both `google-genai==3.0.0` and `httpx2==2.12.0`;
the second profile is the reviewed implementation lock. The two direct packages' metadata
permits the project's Python 3.11-3.14 matrix; this is not validation of the transitive
resolver closure or runtime behavior. Before implementation merge, resolve both profiles
for those Python versions in fresh Gemini-only environments and assert the actual
installed versions. Run the no-network construction, HTTPX2 mock, synchronous-cleanup
and privacy regressions against the minimum pair on Python 3.11, including isolated
wheel/sdist smokes; run the locked profile through the full native CI matrix. A failure
returns the bounds to contract review; do not silently raise or broaden them.

## Accepted version and older-series support decision

Target `0.2.0` for the SDK-major dependency transition; keep this change out of the
compatible `0.1.x` maintenance line. The accepted scope removes no
documented core API. Any later API removal still needs the preceding deprecation and
migration steps promised by the [compatibility policy](compatibility.md#diagnostics-and-deprecations).

Until a separately authorized `0.2.0` publication, the current `0.1.x` maintenance policy
continues. The accepted position for a future `0.2.0` publication follows the existing
[security maintenance policy](../SECURITY.md#supported-versions): target `main` and the
latest published release, then in `0.2.x`. Existing `0.1.x` releases remain available;
applications retaining the SDK 2 extra can pin `guardtrellis[gemini]<0.2` and their own
provider dependencies. Pinning is not a promise of continuing upstream service or fixes.
No parallel `0.1.x` backport line, support lifetime or response deadline is committed;
continued older-series maintenance needs its own explicit announcement.

Record the approved support statement and migration options in the compatibility guide
and `0.2.0` release notes before publication. These decisions are accepted for subsequent
implementation and release review; this local document changes no published requirements,
support statement or security policy.

## Preserved request and delivery boundaries

The [documented example contract](gemini.md#one-approved-live-request) remains fixed:

- Explicit Developer API mode (`enterprise=False`, `vertexai=False`), explicit key,
  base URL `https://generativelanguage.googleapis.com` and API version `v1beta`.
- Current model `gemini-3.5-flash-lite`, one candidate, 128 maximum output tokens,
  text-only response and the existing minimal-thinking configuration.
- One generation attempt, no redirects, tools, automatic function execution,
  automatic continuation, streaming, model fallback, files or cached context.
- Twenty-second HTTP phase/inactivity timeout, without a whole-command deadline claim.
- Input checks precede the callback; only checked input reaches the HTTP boundary.
  Join complete accepted text parts before output checks and deliver `require_text()`.
  Rejected or incomplete results never produce raw-input/output fallback delivery.

The model and endpoint are configuration to preserve, not a claim of current service
availability. Any future model or endpoint change needs a separate reviewed decision.

## Accepted environment precedence

Explicit endpoint, API-version, key and Developer-mode settings must take precedence
over ambient Google API, Vertex/enterprise and base-URL settings. Test the actual request
URL and key placement, not just the arguments supplied to the SDK constructor.

SDK 3 gives `GOOGLE_GENAI_HTTP_CLIENT` precedence over HTTP-object detection. For this
fixed-backend example, accept an absent/empty value, `auto` or `httpx2`, using
the SDK's whitespace/case normalization. Reject `httpx` and unknown values with a static,
payload-free configuration error before constructing a client or attempting network I/O.
Document this accepted restriction in the migration notes. Do not mutate
the process environment or log the rejected value. Applying it only to this example must
not change another application's independently constructed SDK client.

Continue to respect supported host TLS/proxy configuration. HTTPX2's OS trust-store
default needs migration notes; do not disable certificate verification. A fixed logical
API destination does not itself establish proxy/egress enforcement or host trust safety.
The default command must never send a live request when ambient live-opt-in credentials,
API settings or enterprise variables are present. Supported backend settings retain the
in-memory mock; conflicting backend settings fail before client construction.

## Failure, privacy and lifecycle contract

Retain [existing response checks](gemini.md#failure-and-privacy-boundaries): one complete
STOP response, nonblank text, no safety-block signal, and no mixed tool/media/code parts.
Treat the new `MALFORMED_RESPONSE` finish reason as an error with no deliverable text.
Opaque thought signatures and provider response identifiers remain excluded from output.

Provider status errors, malformed responses and HTTPX2 transport failures produce the
existing generic `callback_error` through Guard, without raw exception text or content.
Pre-client configuration failures use static errors and the established CLI failure path;
they must not masquerade as a completed checked request or enable a live fallback.
Reports must identify `google-genai` and `httpx2` versions accurately while excluding
keys, prompts/responses, account settings, private error text and response metadata.

Close the SDK-owned synchronous client and its used response/transport resources through
the existing context manager on success and failure. The synchronous context does not
close the SDK's unused async client; this contract makes no all-client cleanup guarantee.
Test synchronous cleanup without broad exception catches or swallowing caller interruption.
No async execution or new async cleanup lifecycle is introduced. Existing Guard
cancellation cannot stop a running worker thread, retract an already-sent request or
undo provider processing; retain those limitations.

## Required regression and installation evidence

Use fabricated credentials and in-memory transports; forbid sockets where appropriate.

1. Construct and close `make_client(transport=None)` with socket access forbidden. Prove
   HTTPX2 is selected and construction makes no request. Keep any inspection of SDK
   internals in version-scoped tests, not in the adapter's application contract.
2. Run the actual HTTPX2 transport path for input redaction, exact URL/body/timeout,
   zero requests after input BLOCK, output redaction and joined split-secret rejection.
3. Exercise 401/403/429/500, redirects, HTTPX2 timeout/connection exceptions, malformed
   JSON, unsupported content, continuation and `MALFORMED_RESPONSE`. Assert one request,
   generic failure, no deliverable text and payload-free diagnostics/reports.
4. Test the following environment outcomes separately, including case/whitespace
   normalization. Do not mutate environment variables in the adapter or send live requests:

   | Environment input | Required outcome |
   | --- | --- |
   | Backend unset, empty, `auto` or `httpx2` | Construct successfully, select HTTPX2, and run the default command against its in-memory mock. |
   | Backend `httpx` or an unknown value | Static configuration failure before client construction, with zero network I/O and no rejected value in output. |
   | Conflicting ambient API-version, enterprise/Vertex, key or base-URL settings with an allowed backend | Explicit fixed settings win; verify the actual URL/key placement and successful default mock execution. |

   Live-opt-in environment variables alone must never activate a live command. Combine
   them with each backend case to distinguish a successful mock from a pre-client failure.
5. Assert used synchronous client/transport cleanup on successful and failed checks and
   interruption propagation; preserve the existing response, usage-validation and
   metadata-privacy regressions. Do not treat an async client as closed by the sync context.
6. Run a Gemini-only installed smoke in a fresh environment for each wheel and source
   archive, independent of the OpenAI-only and all-extras environments. Install only the
   candidate's `[gemini]` extra and its resolved dependencies; the source-archive environment
   may additionally contain the reviewed build tooling. Never reuse an environment already
   populated by another optional extra: running "before all-extras" alone is insufficient.
   Assert that OpenAI, FastAPI and LangGraph are absent, verify the SDK/backend versions
   and selected HTTPX2 transport, and execute the copied mocked example outside the source
   tree. Preserve the existing core/OpenAI-only/all-extras checks; do not reuse their
   environments for the Gemini-only profile.
7. Run the full suite, lint/format/types, frozen evaluations, native Linux Python
   3.11-3.14, macOS/Windows Python 3.12 and actual Python/Actions CodeQL uploads on the
   exact review head. Recheck post-merge CI before any separately approved publication.

Mocked compatibility evidence does not verify provider availability, billing, deployment
certificate configuration, production latency or real-model effectiveness. A live smoke
is a separate explicitly approved action with synthetic data and current account checks.

## Implementation surface and review gates

The scoped implementation plan covers [pyproject.toml](../pyproject.toml),
[uv.lock](../uv.lock), [the example](../examples/gemini_app.py),
[its regressions](../tests/test_gemini_example.py),
[installed smokes](../scripts/smoke_dist.py), [Gemini guidance](gemini.md),
[compatibility guidance](compatibility.md), [coverage](coverage.md),
[changelog](../CHANGELOG.md) and [roadmap](../ROADMAP.md) as needed. A CI adjustment
must serve an identified missing check. Work from a dedicated `0.2.0` migration branch
based on current main, including #94. After functional validation, review version metadata,
changelog and generated release pins separately on that branch. The reviewed `0.2.0`
metadata must accompany the migration before it merges to main; no SDK-major change
should land there labelled as a `0.1.x` maintenance update. Publication remains separate.

Preserve all core scanner/orchestration behavior, historical SDK 2 live-smoke records,
frozen corpora/manifests/baselines and their original dependency/source identities.
Existing examples are application-owned source recipes, not new supported core imports.

## Acceptance record and next gate

The maintainer accepted this design on 2026-11-09, including:

- SDK 3-only HTTPX2 support in the existing extra, the declared bounds and the separate
  minimum-pair/locked validation gates. Metadata eligibility is not runtime evidence.
- The three environment outcomes, static conflicting-backend failures before construction,
  and the preserved endpoint/model/request and checked-delivery boundaries.
- Used synchronous-resource cleanup and fresh Gemini-only environments for both artifact
  formats, independent of OpenAI and all-extras installation stages.
- The `0.2.0` target, migration guidance and older-series support position above.

The maintainer accepted the separately scoped [implementation plan #96](https://github.com/sahilmathur254/guardtrellis/issues/96)
on 2026-11-09 and authorized local implementation, constrained dependency profiles,
regression tests and board updates. Local implementation is ready for review; no completed native
Windows or CodeQL result is claimed for this local work. Core scanner/orchestration
behavior remains unchanged. Commit, push, merge and publication require separate
authorization. The current two-file #95 patch remains unapproved and unmerged.

### Local implementation evidence, 2026-11-09

The uncommitted migration branch is based on `a46f37bbe4a380a7378983cde597370f41d548af`.
Local validation on macOS passed 1,987 tests with warnings treated as errors, all fourteen
evaluation commands, lint/format/types and version agreement. Both fresh Gemini-only
profiles passed on Python 3.11–3.14: the minimum pair is SDK 3.0.0 / HTTPX2 2.12.0 and
the reviewed lock is SDK 3.0.0 / HTTPX2 2.16.0. Python 3.11 minimum-pair checks passed
all 72 adapter regressions; wheel/sdist smokes passed for the minimum pair and locked
profile alongside the existing installation profiles. The `0.2.0` metadata received a
separate local review after functional validation.

Both dependency profiles resolve to Windows Python 3.12 binary distributions, and native
executable-path selection has regression coverage. These checks do not establish native
Windows execution. Full native CI and completed Python/Actions CodeQL uploads remain
pending a separately authorized commit/push. No live-provider request or publication ran.

## Alternatives and explicit exclusions

Keeping SDK 2 until the separately approved migration preserves the existing `0.1.x`
optional dependency contract. Retaining HTTPX with SDK 3 was considered, but explicit
HTTPX2 support was selected to align the mock and production paths. Supporting both
majors or adding a `gemini3` extra would add ongoing validation and documentation
obligations; neither is included in the accepted scope. A new evidenced requirement
would need a separate design decision.

No core API/detector/default changes, new privacy guarantees, generic provider wrapper,
native async/streaming support, Vertex/enterprise integration, tools or automatic agent
continuation, NLP model, hosted service, credential setup, paid/live requests, migration
of other repositories, security-policy changes, merge, tag or publication is included.
