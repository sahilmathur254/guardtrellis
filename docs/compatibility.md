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

## Upgrading from an alpha

Applications using the documented `0.1.0a4` API need no code migration for `0.1.0`; update
the installed version and run application checks. This release changes the version,
compatibility/support documentation, and package metadata, with no scanner-rule changes.

If an application copied the OpenAI/Azure examples from an earlier SDK 2-based alpha,
follow the [SDK 3 migration notes](openai.md#sdk-3-compatibility), including HTTPX2 clients,
exceptions, transports, and operating-system certificate trust. The migration was already
included in `0.1.0a4`; a copied adapter is application-owned code.
