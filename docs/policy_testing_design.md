# Local policy testing: CLI versus Python

Status: design accepted for [#31](https://github.com/sahilmathur254/guardtrellis/issues/31)
on 2026-10-27 after the contract re-review. Implementation is separately scoped in
[#78](https://github.com/sahilmathur254/guardtrellis/issues/78), with implementation review
and current native CI evidence tracked on that issue.
GuardTrellis `0.1.8` has no CLI. This document retains the accepted target contract;
the later implementation shipped in `0.1.9` after native CI and review. See the
[implementation guide](cli.md) for runnable commands and the
[0.1.9 release record](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.9)
for publication evidence. The dated feasibility checks below remain historical design evidence.

## Selected workflow and success criteria

A developer checks one explicitly chosen synthetic tool-return fixture in a terminal or CI
job. They select the stage and policy, inspect the action/findings, and use the exit status
to distinguish acceptance, rejection and failure. This builds on the maintainer's terminal
demo requests and the shipped SDK; no external adopter or IDE enforcement is established.

Success means a fresh core installation can check that fixture without an application
wrapper, default output omits its contents, and rejected input never becomes checked-text
output. The same policy/input/stage must produce the same SDK result as a Python caller.
The CLI opens selected input files only for reading and offers no implicit rewrite.
This does not prevent a shell from truncating a redirection destination before the CLI
starts. Never redirect stdout or stderr to the input file or an alias of it; use capture
or a distinct destination and check the exit status before consuming checked output.
The CLI cannot restore bytes already lost to shell redirection. No provider, database,
tool execution or network request is part of checking. General tool-call validation still
belongs to `ToolGuard` and its host.

## Alternatives and accepted decision

| Choice | Benefit | Cost and decision |
| --- | --- | --- |
| Documented Python recipe | Uses the current API and allows application-specific ordering and schemas. | Each caller owns stdin/file decoding, bounds, safe errors, reporting and exit conventions. Keep it available for custom workflows. |
| Small CLI with fixed policies and explicit options | Gives terminal/CI callers one reusable input/output contract while retaining SDK behavior. | Adds a public command, report schema and exit-status contract. Accepted for this concrete fixture workflow. |
| Minimal versioned JSON policy manifest | Can share a named configuration across several commands or applications. | Needs another parser/schema, precedence and compatibility rules. Two fixed policies do not yet justify it; defer it. |

The manifest alternative would have to version its schema, reject duplicate/unknown fields
and wrong types, bound its size, and forbid imports, commands, remote references or dynamic
scanner loading. A future accepted manifest might describe `version`, `stage`, `policy` and
the two scanner options below; the accepted increment adds no config-file format or schema.
Reconsider it only when a named caller cannot represent its repeated workflow with the fixed
options and a Python recipe. YAML, OPA/Rego and a general policy language remain excluded.

## Accepted command and fixed policies

Accepted target names: `guardtrellis check` and an equivalent `python -m guardtrellis check`, sharing
one implementation. Require exactly one of `--file PATH` or `--stdin`, plus explicit
`--stage` and `--policy`. Do not accept payload text as a positional argument or option.
There is no automatic stdin read, interactive prompt, environment-driven policy or directory
discovery. Help/version can exit without selecting an input or policy.
Reject repeated options and abbreviated flag names rather than using last-value-wins or
prefix matching. Validate the complete configuration before reading any payload input.

```sh
# Accepted interface; not available in 0.1.8.
guardtrellis check --file fixture.txt --stage retrieval --policy secrets --connection-strings
guardtrellis check --stdin --stage retrieval --policy privacy --phone-mode formatted --format json
```

| Option | Accepted contract |
| --- | --- |
| `--stage` | Required: `input`, `output`, `retrieval` or `tool`. Configure that exact Guard pipeline; an omitted policy must not silently become an empty pipeline. |
| `--policy secrets` | One `SecretScanner(action=Action.BLOCK)`. |
| `--policy privacy` | `SecretScanner(action=Action.BLOCK)` followed by `PIIScanner(action=Action.REDACT)`. A secret rejection ends the pipeline before PII redaction. |
| `--connection-strings` | Explicit opt-in on either policy's secret scanner; absent means false. Preserve the SDK's BLOCK requirement, private work budgets and exclusions. |
| `--phone-mode` | `contiguous` by default, or explicitly `formatted`; valid only with `privacy`. Supplying it with `secrets` is configuration error, even if its value is `contiguous`. |
| `--format` | `text` by default or `json`; affects metadata only. |
| `--output` | `metadata` by default, or explicitly `checked-text` for accepted text on non-terminal stdout. No output-file, overwrite or unsafe-terminal override option. |

These are fixed compositions of public SDK scanners, not a new detector or a guarantee
about arbitrary secrets/PII. A credential URI can be allowed under `secrets` unless the URI
option is selected; without it, `privacy` can redact only an incidental email-like portion
of that URI. REDACT is not a claim of complete secret removal. Raw escaped JSON stays raw
text; no implicit decoding, schema inference or recursive traversal is introduced.
`--stage tool` labels a text scan and does not validate
a tool name, arguments, schema or authorization. The CLI does not invoke callbacks or tools.

## Input, output and work bounds

Use strict UTF-8 binary input on every platform, with an initial limit of 400,000 bytes
and 100,000 decoded Python characters. Read at most the byte limit plus one before rejecting
overflow, then check the decoded character limit before scanning. These are selected fixed
ingress budgets, not performance-derived optimal values or new SDK configuration knobs.
Invalid UTF-8 and unpaired-surrogate encodings reject; no replacement decoding occurs.
Preserve BOM characters, CRLF/LF, NUL and Unicode as literal text. Do not normalize or append
a newline. Empty input is valid, as it is for the SDK.

An explicitly chosen file must be a regular file; reject directories and special files.
Check type before reading and validate the opened descriptor. A symlink to a regular file
may be followed; there is no sandbox/root-boundary or immutable-file guarantee. File changes
and filesystem races remain host concerns. `--stdin` requires noninteractive input and EOF;
reject a terminal rather than prompting. The byte bound does not guarantee that a stalled
pipe or changing filesystem completes before a deadline.

Reuse `Guard(max_chars=100_000).scan(text, stage=...)` and the SDK's existing per-scanner
256-finding limit. In these fixed policies the secret scanner either allows with no findings
or blocks before PII, so findings from both scanners cannot accumulate. This is a property
of these compositions, not an aggregate Guard limit. The URI option additionally bounds
candidate length and attempts. Rejection/ERROR must not fall back to the original text.

Buffer bounded metadata and any accepted checked-text bytes before output. Use a
128 KiB encoded metadata ceiling and a 400,000-byte/100,000-character checked-text ceiling.
On overflow return a static error; do not truncate findings or emit a shortened result.
Write checked text as UTF-8 bytes to prevent Windows newline/locale conversion. Its output
is the exact `result.require_text()` value with no extra newline, including an empty value.
These bounds require boundary/protocol tests before implementation acceptance.

For `checked-text`, reject terminal stdout with `invalid_configuration`, exit 2 and empty
stdout, before reading payload input. This also applies to empty, BLOCK or ERROR cases;
destination eligibility is a configuration check, not a decision based on the contents.
Metadata mode remains available on a terminal because it contains only static/escaped
metadata. If querying the output destination fails, handle it as output I/O failure rather
than assuming that the destination is safe. Both selected policies can accept terminal
escape sequences; accepted text does not establish rendering safety. Do not escape or
strip those bytes, since that would change the checked value. Preserve exact UTF-8 only
for a non-terminal destination. This gate covers direct TTY output, not a later consumer
that renders, logs or executes text received through a pipe/file.

## Reports, privacy and exit status

In metadata mode, write the result report to stdout. Human scan output contains only stage,
action, finding count and static finding codes. JSON uses exactly the top-level fields
`report_version: 1`, `sdk_version`, `stage`, `policy`, `options`, `result` and `error`.
Structured reports start only after syntax and semantic configuration validation succeed.
`stage`/`policy` are the validated selected names.
`options` contains only `connection_strings` (boolean) and `phone_mode` (selected mode for
`privacy`, null for `secrets`); it is never null in a structured report.
For a scan result, `result` is the existing `Result.diagnostics()` structure and `error` is
null. For a CLI input/runtime failure, `result` is null and `error` has a static `code`.
After validation, human wrapper-error output contains only the stage and static CLI error code.
An SDK ERROR retains its SDK diagnostics in `result`, with `error: null`, and exits 3.
Do not add payload text, replacements, paths, argv, exception messages or environment values.
Do not use `dataclasses.asdict(result)` or serialize `.text` in the metadata path.

All syntax and semantic configuration errors produce one static ASCII error on stderr,
empty stdout and exit 2, even when `--format json` was supplied. This includes unknown,
missing, repeated, abbreviated or conflicting arguments, invalid enum values, incompatible
policy options, and checked-text terminal output. Use `invalid_command` for argument
structure and `invalid_configuration` for invalid values/combinations/destination choice.
No payload is read on these paths. An unexpected failure after CLI entry but before valid
configuration uses a static `runtime_error` on stderr and exit 3. No structured report is
promised before configuration succeeds.

After validation, preserve the selected metadata format for input and check-time runtime
failures. Report placement follows the selected output mode. Errors never echo an unknown
argument, invalid value, source path or exception message. Help text contains only fixed
examples. Unexpected exceptions get no default traceback. Shell tracing and external
CI/terminal logs are caller-owned and can expose arguments independently of the CLI.
Offsets and counts in SDK diagnostics may themselves be sensitive metadata; omitting text
does not make a report anonymous. JSON reports are one UTF-8 line with a final LF, counted
within the report byte budget, and omit timing/path/host/environment fields.

Proposed CLI error codes are `invalid_command`, `invalid_configuration`, `invalid_source`,
`input_io_error`, `invalid_encoding`, `input_limit_exceeded`, `runtime_error`,
`report_limit_exceeded`, `checked_output_limit_exceeded`, `output_io_error` and `interrupted`.
They contain no dynamic suffixes. Existing SDK finding codes stay inside SDK diagnostics;
the wrapper does not translate them into invented detector findings.

### Emission order and failure precedence

Prepare the complete bounded report and any accepted checked-text bytes before emission.
Serialize report/output overflow as a compact wrapper-error report (`result: null` and the
static error code), not a shortened ordinary report. It must fit the same metadata bound.

| Outcome after valid configuration | `metadata` mode | `checked-text` mode | Normal exit |
| --- | --- | --- | --- |
| ALLOW / REDACT / WARN | One report on stdout | One report on stderr, then accepted checked bytes on stdout | 0 |
| BLOCK | One report on stdout | One report on stderr; empty stdout | 1 |
| Input failure, such as unreadable/nonregular input, invalid encoding or ingress overflow | One wrapper-error report on stdout | One wrapper-error report on stderr; empty stdout | 2 |
| SDK ERROR or wrapper runtime/report/checked-output failure | One report on stdout | One report on stderr; empty stdout | 3 |
| Handled KeyboardInterrupt before emission | One `interrupted` wrapper-error report on stdout | One `interrupted` wrapper-error report on stderr; empty stdout | 130 |

In checked-text mode, write and explicitly flush the metadata on stderr successfully before
writing any stdout payload. Then write the complete accepted byte sequence and flush stdout
inside the handled I/O boundary. In metadata mode, write and flush its sole stdout report
inside that boundary. Handle short writes without duplicating a prefix; a zero-progress or
failed write is output I/O failure. Help and pre-configuration errors also use handled writes.
Do not rely on interpreter-shutdown flushing to determine success.

An output write/flush failure overrides an ordinary 0/1/2 result with exit 3. A handled
KeyboardInterrupt takes precedence with 130, including failure of its best-effort report.
If stderr has not started a report and remains usable, a single best-effort static
`output_io_error` line may be written there. Never retry a failed channel, send an error to checked-text stdout,
append a second report, or recursively report a failed diagnostic write. If neither channel
is usable, exit status alone reports failure. After any partial emission, output may be
incomplete or invalid JSON; the one-complete-report guarantee applies only when its write
and flush succeed. A completed metadata record describes the scan, not delivery success.

When checked-text metadata fails, withhold the entire stdout payload. When payload output
fails after metadata succeeded, stdout may contain an accepted prefix and stderr may already
contain an accepted scan record; do not append a second record. Consumers must discard
checked-text stdout on any nonzero exit, even if it appears complete. No ordinary raw-input
fallback or atomic file/pipe write is promised.

Catch stream errors before returning the final status, and neutralize only failed standard
streams for interpreter cleanup so another buffered flush cannot change the exit to 120 or
print an unraisable traceback. Do not restore SIGPIPE to a disposition that bypasses this
handled-error contract. Suppression must not turn the failed operation into success.
If KeyboardInterrupt interrupts emission, return 130, do not start another structured
record, and apply the same failed-stream cleanup. Partial accepted output may remain.
External termination remains outside these handled exit guarantees.

| Exit | Meaning |
| --- | --- |
| `0` | Accepted SDK result: ALLOW, REDACT or WARN. The selected policies currently have no WARN scanner. Help/version also exit zero. |
| `1` | Policy rejection: BLOCK. |
| `2` | Invalid command/configuration or ingress input: missing/conflicting options, incompatible policy flag, unreadable/nonregular input, invalid UTF-8, or ingress size overflow. |
| `3` | SDK ERROR, unexpected runtime failure, report/checked-output overflow, or output I/O failure. A URI processing limit is SDK ERROR, distinct from ingress overflow. |
| `130` | KeyboardInterrupt handled by the CLI, with no traceback or raw text. External termination retains the host/platform's status rather than promising this code. |

REDACT means the policy accepts a transformed value, so a completed CLI operation exits 0;
it does not mean the original fixture is finding-free or was rewritten. Strict PII CI must
retain `privacy` and inspect its report. Switching to `secrets` removes PII checking and is
not an equivalent stricter policy. There is no CLI PII-blocking profile or new `--fail-on`
option in this increment. Report codes and envelope version need compatibility tests.

For example, under `privacy`, public text yields ALLOW/zero findings/exit 0; an email yields
REDACT/one finding/exit 0 and must fail a zero-findings gate; a selected secret yields BLOCK/
exit 1 and fails that gate. The following CI consumer for the accepted interface retains the selected coverage,
fails on malformed/mismatched reports, and prints no captured input/report/exception text.
It is not runnable against `0.1.8`, which has no CLI. The deadline belongs to the CI host.

```python
import json
import subprocess


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid report")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Invalid report")


def clean_privacy_report(payload):
    try:
        if (
            type(payload) is not bytes
            or len(payload) > 128 * 1024
            or not payload.endswith(b"\n")
            or payload.count(b"\n") != 1
            or b"\r" in payload
        ):
            return False
        report = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
        result = report.get("result") if type(report) is dict else None
        return (
            type(report) is dict
            and set(report)
            == {"report_version", "sdk_version", "stage", "policy", "options", "result", "error"}
            and type(report.get("report_version")) is int
            and report["report_version"] == 1
            and type(report.get("sdk_version")) is str
            and bool(report["sdk_version"])
            and report.get("stage") == "retrieval"
            and report.get("policy") == "privacy"
            and report.get("options") == {"connection_strings": True, "phone_mode": "formatted"}
            and type(report["options"]["connection_strings"]) is bool
            and "error" in report
            and report["error"] is None
            and type(result) is dict
            and set(result) == {"action", "stage", "findings", "trace"}
            and result.get("stage") == "retrieval"
            and result.get("action") == "allow"
            and result.get("findings") == []
            and type(result.get("trace")) is list
        )
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


try:
    completed = subprocess.run(
        [
            "guardtrellis",
            "check",
            "--file",
            "fixture.txt",
            "--stage",
            "retrieval",
            "--policy",
            "privacy",
            "--connection-strings",
            "--phone-mode",
            "formatted",
            "--format",
            "json",
        ],
        capture_output=True,
        timeout=15,
        check=False,
    )
    clean = (
        completed.returncode == 0
        and completed.stderr == b""
        and clean_privacy_report(completed.stdout)
    )
except (OSError, subprocess.TimeoutExpired):
    clean = False
raise SystemExit(0 if clean else 1)
```

## Cancellation and installation boundaries

Use the synchronous built-in scanners; do not create executors, worker processes or async
deadline machinery for this increment. Catch KeyboardInterrupt at the entry boundary,
close only owned file handles and withhold any result not yet approved for emission.
There is no built-in whole-command hard timeout. CI/host processes must bound stalled
input/output and terminate/reap the process when they need such a deadline. The SDK's
async wait setting is not a substitute for an I/O or process deadline.

The accepted console entry point and module launcher belong to the core package and reuse
one internal CLI module, with stdlib argument/IO handling and no optional provider dependency.
Validate supported Python 3.11–3.14 on the existing Linux/macOS/Windows matrix, including
both installed distribution formats outside the source checkout.

A missing interpreter, unavailable executable or broken dependency import can fail before
the CLI starts. Shell/launcher failures do not promise the CLI's JSON or exit-status contract;
document how to verify the active environment and reinstall. The CLI must not read payload
input until its parsing and required SDK imports succeed. Failures caught after entry use
the static error contract. Isolated install/launcher tests must distinguish these boundaries.

## Feasibility evidence and implementation acceptance

An offline probe on 2026-10-27 used installed `0.1.8` public APIs only. Eight authored
synthetic profile cases across four explicit stages produced 32 expected SDK observations:
public/empty text ALLOW; a URI without opt-in ALLOW under the secrets policy; URI opt-in
and a random fabricated GitHub-shaped token BLOCK; email/formatted phone REDACT; and
secret blocking before PII redaction. Accepted redactions matched the complete expected
checked string and rejections exposed no checked text. No input, token or checked payload
was retained in the probe output.

This dated probe verified policy composition feasibility, not a CLI, its I/O/error contract,
native Windows CLI behavior or independent detection accuracy. It preceded implementation.

The separate [implementation issue #78](https://github.com/sahilmathur254/guardtrellis/issues/78)
must satisfy these acceptance gates:

1. Same SDK actions, findings, revisions and checked output for the selected profile/stage;
   all four stages, opt-in/default distinctions and block-before-redact ordering.
2. Real subprocess invocation, paths with spaces/non-ASCII, strict UTF-8, CRLF/BOM preservation,
   empty input, wrong source type, all ingress/report/output limits and incompatible options.
3. Exact stdout/stderr/exit behavior for acceptance, rejection, syntax and semantic errors
   (including `--format json`), scanner errors, missing/broken installation, interruption
   and slow/no-EOF input. Exercise failures of each output stream, flush/shutdown failures,
   short writes, partial records, no duplicate reports, no payload after metadata failure,
   and strict-CI acceptance/rejection without dropping PII coverage.
4. Canary checks across parser failures, human/JSON output, exceptions and rejected checked-text
   mode; direct TTY rejection before input reads, non-TTY byte preservation (including escape
   sequences), no raw-value fallback, CLI input writes or silent finding truncation. Verify
   the documented shell-redirection boundary without claiming the CLI can undo truncation.
5. A bounded fresh-process CI example using fabricated fixtures, installed console/module
   entry points and wheel/sdist smokes on the supported native platform matrix.
6. Source-backed command/report documentation and upgrade notes; preserve detector rules,
   current SDK defaults, historical evaluation corpora and retained reports.

### Follow-up contract review — 2026-10-27

The three review findings and the input-file wording correction are addressed above:
configuration/report routing is explicit; writes/flushes have ordered handling and failure
precedence; checked text requires non-terminal stdout; strict PII CI retains `privacy` and
examines its findings; and the read-only CLI promise excludes prior shell truncation.

The documented Python CI consumer parsed successfully and passed 27 local SDK/report cases,
covering clean acceptance, PII/secret/error rejection and malformed/mismatched reports.
Three bounded Python 3.12.0 stdio probes demonstrated handled exit 3 without shutdown
tracebacks, no payload after metadata failure, and no second record after payload failure.
These are local feasibility checks, not a CLI implementation, full transport verification
or native Windows evidence. The implementation gates above still apply.

## Decision and release gate

The maintainer accepted the fixed-policy CLI on 2026-10-27, including both command names,
the two policies and explicit options, fixed budgets, report/exit contract, non-terminal
checked-text restriction and the re-reviewed I/O/input-file rules. A manifest and hard
whole-command deadline remain deferred. #31 is complete as a design decision; #78 is now
implemented through [#79](https://github.com/sahilmathur254/guardtrellis/pull/79), with
review and native CI tracked separately. Design acceptance alone does not establish
shipped CLI behavior; the release record above does.

The new CLI is additive under the existing `0.1.x` compatibility policy. `report_version=1`
and the exit codes are accepted interface commitments for the implementation to verify;
existing SDK APIs and defaults were unchanged by the CLI addition. `0.1.9` shipped the
CLI with the scoped #45 detector/delivery evaluation; CLI tests/docs are part of that
same improvement. This document, release tracking
cleanup and a patch to stale status prose do not justify a new package version or publication.
IDE/MCP adapters, streaming, arbitrary/custom policies, schema checking, recursive scans,
automatic edits and new detector families remain separate work.
