# Compatibility and support

Starting with `0.1.0`, GuardTrellis supports the documented public API throughout the
`0.1.x` final-release series. This is a project-specific compatibility promise within
that series; it does not promise compatibility across every future `0.x` minor release.
Alpha, beta, release-candidate, and development versions are outside this promise.
Availability is recorded on [PyPI](https://pypi.org/project/guardtrellis/).

## Public API covered by the promise

Use the names exported from the top-level `guardtrellis` package:

- `Guard`, `Scanner`, `ToolGuard`, `PIIScanner`, `SecretScanner`, `InvisibleScanner`,
  `LiteralScanner`, and `JSONScanner`.
- `Action`, `Stage`, `Check`, `Finding`, `Edit`, `Trace`, `Result`, `RunResult`,
  `ToolResult`, `Rejected`, and `__version__`.

Their documented constructors, arguments, return types, properties, and methods remain
compatible across `0.1.x`. Existing accepted call signatures and result fields remain
available; existing enum values retain their meaning. The version string changes with
each release. Private helpers, internal module layout, undocumented attributes, and
scripts under `examples/`, `evaluation/`, or `scripts/` are not supported import APIs.

The [API contracts](api.md) define the behavior this promise covers, including:

- Explicit stages and configured scanner order, followed by the documented action priority.
- Accepted `ALLOW`, `WARN`, and `REDACT` results; rejected `BLOCK` and `ERROR` results
  without ordinary deliverable text or tool arguments. Input rejection prevents the callback.
- `require_text()` and `require_call()` returning checked data or raising `Rejected`.
- The synchronous/asynchronous scanner contract, per-operation waits, caller cancellation,
  and the documented limits of cancellation. A timeout does not terminate arbitrary code.
- Character offsets tied to scanner input revisions, ordered redactions, and schema
  validation after tool-argument text transformations.
- Metadata-only `diagnostics()` output and payload-free built-in rejection/error reporting.

## Changes within 0.1.x

Patch releases preserve the public API above and the documented defaults. They can fix
incorrect behavior, improve diagnostics, and update dependencies within the policy below.
New required arguments, removal or renaming of existing public fields, changed enum
meanings, and routine changes to default actions belong in a later minor release.

The optional `PIIScanner(phone_mode="formatted")` argument released in `0.1.6` is an
additive choice within this policy. Existing callers keep `phone_mode="contiguous"`
and their existing detector outcomes. Selecting the new mode changes the accepted
phone grammar and rejects malformed candidates as matches; it does not automatically
block those inputs. The [formatted-phone guide](formatted_phone.md) records complete
redaction, no-prefix-fallback behavior, exclusions, and explicit recipe adoption.
See the [0.1.6 release record](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.6)
and [control-coverage matrix](coverage.md) for versioned evidence and limitations.

The `SecretScanner(connection_strings=True)` option released in `0.1.8` is another additive
opt-in. Existing callers keep `connection_strings=False`, their existing actions and token
rules. Enabled mode requires BLOCK, adds complete connection-URI findings alongside existing
token findings, and introduces documented direct-call processing limits and static error
codes. Applications choose the new policy explicitly and should test supported formats,
intentional placeholder false positives, and raw-versus-decoded JSON boundaries before
adoption. See the [connection-URI guide](connection_strings.md) and
[0.1.8 release record](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.8).

Detection results are not frozen. A correction to a supported pattern, a false-positive
fix, or a privacy/security fix can change findings, redacted spans, or whether a particular
input is accepted. A privacy/security correction can reject input that an earlier patch
accepted. Such changes must be called out in [CHANGELOG.md](../CHANGELOG.md), with affected
formats and an upgrade note. The API compatibility promise does not preserve a bug or
expand the [documented detection coverage](limitations.md#detector-coverage).

Applications that require an unchanged policy outcome for specific inputs should pin an
exact version and run their own representative cases before upgrading. Retained evaluation
failures remain evidence of coverage limits, not guarantees that those failures persist.

## Diagnostics and deprecations

The CLI added in `0.1.9` is an additive core interface. Its
[`report_version=1` envelope and exit statuses](cli.md) have their own explicit contract;
configuration errors precede structured reporting. Existing Python API defaults and
detector rules were unchanged by that addition. The published `0.1.10` release adds the
schema-work rejection described in the [upgrade note](../CHANGELOG.md#0110);
the [release record](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.10)
links publication verification. The `0.1.11` release added the benchmark/control-mapping
batch while preserving SDK behavior and dependency requirements. The `0.1.12` release
adds accepted retrieval/tool research and locked optional/development dependency
maintenance, including the optional Gemini chain's pyasn1 security update. It preserves
SDK behavior, defaults and declared dependency ranges; applications manage their own
resolved dependency locks. See the [0.1.12 upgrade note](../CHANGELOG.md#0112).
Version preparation changes the version constant and package metadata; historical
measurements retain their actual SDK version. Check
[package availability](https://pypi.org/project/guardtrellis/) separately.

Existing diagnostic keys, value types, and meanings remain supported across `0.1.x`.
Additional metadata keys and finding codes may be introduced; consumers should tolerate
unknown keys/codes and use `action` and the checked-result accessors for delivery decisions.
Existing finding codes will not be silently renamed or repurposed, but a detector fix can
change which findings occur. JSON dictionary key order, exact exception wording, `repr`
formatting, timing, and benchmark scores are not compatibility guarantees. The documented
privacy exclusions continue to apply to new diagnostics.

For a planned incompatible API change, announce the deprecation in a preceding final
release's changelog, describe the replacement, and provide a migration example. Keep the
old API working throughout `0.1.x`; removal requires `0.2.0` or a later minor release.
Any wider promise for `1.0.0` will be stated explicitly when that release is prepared.

## Python, dependencies, and maintenance

- Python 3.11–3.14 remains supported throughout `0.1.x`. The CI matrix covers those
  versions on Linux and Python 3.12 on macOS and Windows; see [CONTRIBUTING.md](../CONTRIBUTING.md).
  This is the tested matrix, not a claim about every operating-system/Python combination.
- Core dependencies remain provider-independent. The package metadata declares allowed
  dependency ranges; CI checks the locked environment and fresh distribution installs,
  not every possible dependency combination.
- Optional extras are opt-in. SDK-major migrations, such as moving the `openai` extra
  beyond SDK 3/HTTPX2, require a later minor release and migration notes. A patch may raise
  a dependency minimum to obtain a correctness or security fix; the changelog must identify
  the new requirement. Python-version support and the public API promise still apply.
- While `0.1.x` is the current final-release series, maintenance targets its latest patch
  and `main`. Upgrade to the latest patch for fixes; backports to older patches are not
  guaranteed. Maintenance of `0.1.x` after a newer minor series ships requires a separate
  announcement. No response deadline, support lifetime, or availability SLA is promised.

Provider services, models, endpoint availability, and copied application adapters remain
outside the core API guarantee. Shipped examples retain their stated verification scope;
OpenAI and Azure are currently mock-verified. Report vulnerabilities through the existing
[security reporting process](../SECURITY.md).

## Gemini SDK 3 transition

The accepted [Google GenAI 3 migration](google_genai3_migration_design.md), implemented
under [#96](https://github.com/sahilmathur254/guardtrellis/issues/96), targets `0.2.0`.
Its local implementation and validation precede separate review, merge and publication.
This optional dependency-major transition does not remove a documented core API or change
scanner/orchestration behavior, defaults, Python support or non-Gemini declared requirements.

The existing `[gemini]` extra selects `google-genai>=3.0.0,<4` and `httpx2>=2.12,<3`.
Applications copying the example must migrate HTTPX-specific objects and exceptions to
HTTPX2, review OS certificate trust, and adopt the example's explicit backend environment
restriction. See the [migration steps](gemini.md#sdk-3-migration-for-020). No SDK 2 branch
or automatic HTTPX fallback is supported by that example.

Until a separately authorized `0.2.0` publication, the current `0.1.x` maintenance policy
above continues. After `0.2.0` publication, maintenance follows `main` and the latest
published release, then in `0.2.x`, under the existing
[security maintenance policy](../SECURITY.md#supported-versions). Existing `0.1.x` packages
remain available; applications retaining SDK 2 can pin `guardtrellis[gemini]<0.2` and their
own provider dependencies. A pin is not a promise of upstream service availability or fixes.
There is no parallel `0.1.x` backport commitment, support lifetime or response deadline;
continued older-series maintenance requires a separate announcement.

## Upgrading from an alpha

Applications using the documented `0.1.0a4` API need no code migration for `0.1.0`; update
the installed version and run application checks. This release changes the version,
compatibility/support documentation, and package metadata, with no scanner-rule changes.

If an application copied the OpenAI/Azure examples from an earlier SDK 2-based alpha,
follow the [SDK 3 migration notes](openai.md#sdk-3-compatibility), including HTTPX2 clients,
exceptions, transports, and operating-system certificate trust. The migration was already
included in `0.1.0a4`; a copied adapter is application-owned code.
