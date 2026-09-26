# Security policy

## Supported versions

GuardTrellis is an alpha Python library. Security maintenance targets `main` and the
latest published alpha, currently `0.1.0a1`. Report the exact package version or commit
you tested. Backports to older releases are not guaranteed.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/sahilmathur254/guardtrellis/security/advisories/new).
Avoid public issues or pull requests containing an undisclosed vulnerability or exploit.
If the private reporting form is unavailable, open an issue asking for a private contact
without including vulnerability details.

Include:

- The affected version, Python version, optional dependencies, and relevant configuration.
- A minimal reproduction using fabricated data, with expected and observed behavior.
- The input an attacker can control, required preconditions, and practical impact.
- Relevant paths, sanitized output, and a proposed fix if available.

Do not include live credentials, personal records, or production payloads. Test only
systems you own or have permission to assess. Coordinate public disclosure through the
private report so a fix and advisory can be prepared. No response or remediation deadline
is guaranteed.

## Scope and trust boundaries

The scope includes the core package, shipped examples, dependency handling, and repository
build and release workflows. GuardTrellis runs inside the calling application's process.
Text and tool arguments supplied to configured checks may be attacker-controlled. Scanner
configuration, JSON schemas, custom scanners, and callbacks are trusted application code
or configuration; GuardTrellis does not sandbox them.

The host application must configure the relevant stages and consume checked results.
`WARN` permits delivery, and an unconfigured stage permits bounded text. Tool validation
checks names and argument structure; the host still owns execution and authorization.

## Security properties and reportable issues

Please report failures of the documented boundaries, including:

- A blocked or failed input reaching a callback through `Guard.run` or `Guard.arun`.
- Blocked or failed results exposing normal deliverable text or tool arguments.
- Original text bypassing configured redaction before later checks or callbacks.
- Raw payloads leaking through built-in diagnostics, representations, or generic errors.
- JSON schema validation retrieving remote resources or reading files.
- Attacker-controlled inputs bypassing documented size or depth limits, or causing
  disproportionate resource use under supported configuration.
- Compromise of package integrity, dependency handling, or build and release controls.

Describe the supported entry point and reachable impact. An issue in an example can still
be reportable; being an example is not an automatic exclusion. If you are unsure whether
an issue qualifies, report it privately.

## Documented limitations

The [limitations and trust boundaries](docs/limitations.md),
[API limits](docs/api.md#limits-and-asynchronous-work), and
[evaluation methodology](evaluation/README.md) describe the current coverage. Pattern
detectors do not guarantee detection of every secret or personal identifier. The library
does not provide semantic prompt-injection protection, authentication, or process isolation.
Asynchronous cancellation cannot forcibly terminate arbitrary worker-thread code.

These limitations are context for assessing a report, not a blanket exclusion of bypasses
or additional impact. Published synthetic evaluation values are fabricated; any suspected
real credential exposure should still be reported privately.
