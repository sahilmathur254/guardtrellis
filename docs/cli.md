# Check one local fixture

Added in `0.1.9` through [#78](https://github.com/sahilmathur254/guardtrellis/issues/78).
See [PyPI](https://pypi.org/project/guardtrellis/0.1.9/) for availability.
The `0.1.8` package has no CLI. From this checkout, install into an activated
environment with `python -m pip install -e .`, or use the repository's locked `uv sync`.
Both `guardtrellis check` and `python -m guardtrellis check` use the same core implementation;
optional provider dependencies and credentials are unnecessary. No network requests occur.

```sh
guardtrellis check --file fixture.txt --stage retrieval --policy privacy --format json
python -m guardtrellis check --stdin --stage retrieval --policy secrets --connection-strings
```

Select exactly one source (`--file PATH` or `--stdin`), one explicit `--stage`
(`input`, `output`, `retrieval`, `tool`) and one `--policy`. `secrets` blocks selected secret
signatures. `privacy` blocks secrets first, then redacts supported personal details.
There is no default/empty policy, automatic stdin selection, payload argument, recursive
scan, manifest, custom scanner/action or file rewrite. `tool` is a text-scanning stage;
tool schema checks and authorization remain with `ToolGuard` and its host.

| Option | Default and meaning |
| --- | --- |
| `--connection-strings` | Absent/false. Explicitly enable BLOCK-only supported PostgreSQL/MongoDB credential URIs. |
| `--phone-mode contiguous\|formatted` | `contiguous` under `privacy`; invalid with `secrets`, including an explicit `contiguous`. |
| `--format text\|json` | `text`; affects metadata only. |
| `--output metadata\|checked-text` | `metadata`; checked text requires non-terminal stdout. |
| `--help` / `-h`, `--version` | Use alone, optionally after `check`; no input is read. |

Options may use `--name=value`. Unknown, repeated, abbreviated, conflicting and invalid
options reject before reading input, even if help or JSON was also requested.
Configuration is independent of environment variables. Source paths can still be exposed
by the caller's shell tracing or CI logs.

## Reports and checked delivery

Default output contains only metadata. Human reports contain the selected stage, action,
finding count and static finding codes. JSON is one UTF-8 line with final LF, using exactly:

```json
{"report_version":1,"sdk_version":"0.1.9","stage":"retrieval","policy":"secrets","options":{"connection_strings":false,"phone_mode":null},"result":{"action":"allow","stage":"retrieval","findings":[],"trace":[{"scanner":"secrets","scanner_index":0,"action":"allow","revision_before":0,"revision_after":0}]},"error":null}
```

`result` is the SDK's `Result.diagnostics()` structure. A wrapper error sets `result` to
null and `error` to `{"code":"STATIC_CODE"}`. An SDK ERROR keeps SDK diagnostics in `result`
and leaves `error` null. No report contains source/checked text, replacements, source paths,
argv, environment values, exception messages or timings. Offsets and counts are still
potentially sensitive metadata. See [the accepted contract](policy_testing_design.md)
for the full static error-code set and failure precedence.

`--output checked-text` sends the report to stderr and accepted UTF-8 bytes to stdout.
The command buffers and bounds both, then writes and flushes the report before releasing
payload bytes. Stdout is exactly `result.require_text()` with no added newline. BLOCK and
ERROR produce no checked text. A direct TTY destination rejects before input reads, even
for empty or blocked content. There is no unsafe-terminal override. Accepted escape
sequences remain unchanged in a pipe/file; a later renderer is the host's responsibility.

An output failure exits 3. A metadata failure withholds all payload; a payload failure can
leave a prefix after a successful scan record. No second report is appended. Always discard
checked stdout on nonzero exit; the scan record alone does not prove successful delivery.
Successful writes/flushes guarantee a complete report; a broken channel may contain only
a partial record. Failed standard streams are neutralized for interpreter cleanup.

| Exit | Meaning |
| --- | --- |
| 0 | ALLOW, REDACT or WARN; also help/version. These profiles have no WARN scanner. |
| 1 | BLOCK. |
| 2 | Invalid command/configuration/source, input I/O, encoding or ingress bounds. |
| 3 | SDK ERROR, wrapper/runtime/output/report failure. Overrides ordinary 0/1/2. |
| 130 | Handled KeyboardInterrupt, including failure of its best-effort report. |

Configuration failures always use one static ASCII stderr line and empty stdout, even
with `--format json`. Once configuration is valid, input/runtime errors retain the selected
report format and output channel. Unexpected failures after entry are sanitized.
Shell launch errors or broken imports before entry are outside this report contract.

## Bytes, files and deadlines

Input is strict UTF-8, at most 400,000 bytes and 100,000 Python characters. The reader
consumes at most 400,001 bytes. Invalid UTF-8/surrogate encodings reject. Empty input is
valid. BOM, CRLF/LF, NUL and Unicode are preserved without normalization. Files must be
regular both before opening and at descriptor validation; symlinks to regular files are
allowed. This is no filesystem sandbox or immutable snapshot. Interactive stdin rejects;
a selected pipe requires EOF.

Reports are at most 128 KiB including their final LF. Checked output is at most 400,000
bytes/100,000 characters. Overflow becomes a compact static error rather than truncating
findings or text. The fixed Guard uses the existing scanner finding and URI work budgets.
URI work exhaustion is SDK ERROR (exit 3), distinct from ingress overflow (exit 2).

The CLI opens input files read-only. **Never redirect stdout or stderr to that input or an
alias:** shells can truncate it before Python starts. Use process capture or a distinct
destination, then check the status. The CLI cannot restore prior shell truncation.

There is no built-in hard I/O or whole-command deadline. A stalled pipe, output consumer,
or changing filesystem can block. The host owns a process timeout, termination and reaping;
the [CI example](../examples/cli_ci.py) uses `subprocess.run(..., timeout=15)` for this boundary.
External termination retains platform-specific status. It is separate from handled Ctrl-C.

## Strict PII CI and limitations

REDACT exits zero because the transformed value is accepted. For a zero-findings gate,
retain `privacy` and inspect the report; changing to `secrets` removes PII coverage.
The bounded [Python CI example](../examples/cli_ci.py) requires exit 0, empty stderr, a
complete version-1 report matching the selected stage/policy/options, ALLOW and no findings.
It rejects malformed/duplicate/mismatched/error reports and prints no captured content:

```sh
python examples/cli_ci.py fixture.txt
```

The CLI preserves the [connection-URI grammar and exclusions](connection_strings.md).
URI passwords can pass the default secrets policy; enable `--connection-strings` explicitly.
The privacy policy without that option can redact only an incidental email-like URI portion.
Raw escaped JSON remains raw; decoding belongs to the application. No driver validation,
database connection or guarantee about arbitrary secrets is added. Detection and delivery
remain distinct, as in the [control coverage](coverage.md) and [limitations](limitations.md).

If the command is unavailable, verify `python -m pip show guardtrellis` in the active
environment and reinstall the intended version. `python -m guardtrellis --version` avoids
a stale console launcher but still needs a working installation and dependencies.
Supported native CI targets remain Linux Python 3.11–3.14, macOS and Windows. Both wheel
and sdist installed launchers run byte-protocol smokes outside the checkout; local macOS
results alone do not establish native Windows success.

See the [local validation record](cli_validation.md) for executed checks, connection-URI
comparison results and the remaining native-platform gate.
