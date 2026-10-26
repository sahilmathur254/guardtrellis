# Connection-URI detection

The `0.1.8` source candidate adds `SecretScanner(connection_strings=True)`. Publication
is separate; check [PyPI](https://pypi.org/project/guardtrellis/) before installing that
version. Existing `SecretScanner()` calls retain their token/private-key rules and actions.

The option detects explicit password-bearing PostgreSQL and MongoDB URIs in text. It
checks disclosure shapes locally: it does not connect to a database, resolve hosts,
validate credentials, or reproduce a driver's complete connection-string parser.

## Enable the policy

```python
from guardtrellis import Guard, PIIScanner, SecretScanner, Stage

guard = Guard(
    retrieval_scanners=[SecretScanner(connection_strings=True), PIIScanner()],
)
examples = {
    "Public information": "Opening hours: 9am to 5pm.",
    "Personal details": "Contact demo@example.org",
    "Synthetic connection URI": "postgresql://demo:ExampleOnly7@db.example.invalid/demo",
}
for label, text in examples.items():
    result = guard.scan(text, stage=Stage.RETRIEVAL)
    print(f"{label}: {result.action.value.upper()}")
```

Output: `Public information: ALLOW`, `Personal details: REDACT`, and
`Synthetic connection URI: BLOCK`. All inputs are fabricated; no network call occurs.
The example prints outcomes only. To pass accepted content onward, use
`result.require_text()`; BLOCK and ERROR have no checked text and raise `Rejected` there.

The constructor requires an actual boolean. Enabling the option requires `Action.BLOCK`;
`WARN` and `REDACT` raise `ValueError` at construction. Configure scanners once and do not
mutate them during use. An opted-in scanner whose action is later changed away from BLOCK
returns a static ERROR instead of weakening the policy. Disabled/default mode retains its
existing action behavior.

For tool returns, configure this blocking scanner before PII redactors at the explicit
`Stage.RETRIEVAL` boundary. Check before inserting text into state, composing another
prompt, or invoking another consumer. The existing [tool-result recipe](tool_result_handoff.md)
keeps its original policy; adopting this option is an application decision. Tool argument
validation, execution authorization, and result checking remain separate responsibilities.

## Supported text grammar

| Component | Recognition rule |
| --- | --- |
| Schemes | ASCII-case-insensitive `postgresql://`, `postgres://`, `mongodb://`, and `mongodb+srv://`. The preceding character must be absent or outside ASCII letters, digits, `_`, `+`, `.`, and `-`. |
| Userinfo | The authority ends at the first literal `/` or `?`, or candidate end. A nonempty interval between its first literal colon and last literal `@` is treated as a password. Extra colons/earlier `@` remain opaque password text. |
| PostgreSQL query | Split at literal `&` and the first `=`. Match exactly `password`, ASCII-case-insensitively, after one bounded `%HH` decoding pass on the key. Any nonempty matching value blocks, including duplicate keys. |
| Values and escapes | Password values are opaque. Encoded delimiters do not create structure; values are not decoded, `+` stays literal, and literal `#` is retained. A malformed unrelated query pair does not hide a later clear password. |
| Empty credentials | A username without a password separator, or an exactly empty password interval/value, adds no URI finding. An empty username with a nonempty password blocks. |
| Templates | Nonempty masks, placeholder words, `${ENV}` expressions and inner `<placeholder>` text block in recognized password slots. No environment expansion or template exemption occurs. |

Only authority text supplies userinfo. A lookalike such as `user:value@host` in a path or
unrelated query value does not become userinfo. Host validity, port syntax and usable
connections are not prerequisites: an invalid-looking URI can still disclose a password.
The conservative separator/template rules can therefore block documentation or malformed
examples intentionally. A no-finding result means only that this policy found no supported
shape; it is not a safety or credential-validity decision.

Whitespace, including actual newlines, ends a candidate. A matching enclosing double
quote or backtick ends its wrapped candidate; that enclosing context can begin before
prose preceding the URI. The other quote type, or an unwrapped quote/backtick inside a
candidate, remains opaque punctuation. An outer angle wrapper is excluded when `<`
immediately precedes the scheme; balanced inner angle placeholders remain included.
Apostrophes are retained, including a possible single-quote wrapper. Other adjacent
punctuation is retained conservatively rather than stripped heuristically. Lines are never
joined. Commas remain candidate content, including host lists; scheme spellings nested or
concatenated without a delimiter inside an earlier candidate are not scanned again.

One URI finding covers the complete recognized candidate, excluding supported outer
wrappers. Codes are `secret_postgresql_uri` and `secret_mongodb_uri`, with scanner name
`secrets`. Offsets are half-open Python character indices into that scanner's input
revision. Existing token findings remain present when they overlap the URI; all findings
share the existing deterministic `(start, end, code)` ordering and 256-finding ceiling.
No username, host, password, decoded component, or parser exception is added to diagnostics.

## Explicit JSON decoding and exclusions

Scanning raw JSON inspects its literal wire characters. Fully escaped text such as
`postgresql\u003a\u002f\u002f...` does not expose the literal scheme delimiters to this
detector. Escaped quotes and newlines can also change literal candidate boundaries and
offsets. The option does not add JSON decoding, recursive traversal, or escape repair.

For a structured workflow, validate and bound the input, explicitly decode the selected
field once, scan that string with the opted-in policy, and use only its checked value.
When creating tool arguments, rebuild and revalidate the final call. The
[decoded-query](decoded_query.md) and [decoded-contact](decoded_contact.md) recipes explain
these application-owned boundaries; their existing policies do not change automatically.
Decoded findings refer to the decoded string, not the original JSON wire.

This increment excludes PostgreSQL keyword/value strings, SQL Server/ODBC, JDBC, other
schemes, generic URL-password detection, MongoDB query-only password fields, key aliases
such as `pwd`, double-encoded keys, fragment-like `#password=...` without a recognized
credential slot, arbitrary encodings and Unicode normalization. Selective URI redaction
is not supported. Existing token signatures may independently detect something inside an
excluded form; this does not establish complete connection-string protection.

## Processing limits and errors

The opt-in uses fixed private budgets; they are not constructor tuning options:

| Budget | Limit and outcome |
| --- | --- |
| Scanner input | At most 100,000 Python characters, including direct scanner calls. |
| Candidate length | At most 8,192 characters, including the scheme. An oversized candidate errors without accepting a shortened prefix. |
| Candidate attempts | At most 256 per scan. Benign and malformed supported-scheme candidates count even when they produce no finding. |
| Combined findings | At most 256 token plus URI findings, using the existing scanner ceiling. |

Increasing `Guard.max_chars` does not disable these opt-in budgets. A smaller Guard input
limit can reject earlier with `text_limit_exceeded`. URI budget overflow returns
`connection_string_limit_exceeded`; changing the opted-in action returns
`connection_string_configuration_error`; an unexpected scanner failure returns
`scanner_error`. These are static, spanless ERROR findings, including on direct calls.
The existing combined finding overflow uses `finding_limit_exceeded`. Guard exposes no
checked output on any ERROR. Malformed syntax alone is not an ERROR: recognized passwords
block, and unsupported structures add no URI finding.

Candidate walking advances monotonically. The query matcher decodes only enough ASCII
key characters to compare with `password`; it never decodes the full URI or a value.
These limits bound this detector's work, not ingress bytes, model tokens, database work,
application concurrency, or memory retained elsewhere. Synchronous calls have no wall
deadline; the general [async and host-control limits](api.md#limits-and-asynchronous-work)
still apply.

## Verification and retained evidence

The [scanner and delivery regressions](../tests/test_connection_strings.py) exercise
the supported grammar, default compatibility, complete spans, overlapping token findings,
configuration changes, static errors, and checked delivery. The separately versioned
[opt-in comparison](../evaluation/connection_strings/OPT_IN.md) and
[runner](../evaluation/connection_strings/opt_in.py) compare all three frozen case sets
without rewriting their historical reports. Supported-format acceptance is separate from
broader desired outcomes, unsupported raw escaped-JSON cases, incidental PII and resource
limits. Synthetic development examples are not a general accuracy benchmark.

The [resource probes](../evaluation/connection_strings/resources.py) and
[protocol/cleanup tests](../tests/test_connection_string_resources.py) run 18 fixed
scenarios for both direct scanning and Guard in disposable child processes. They cover
input/candidate/finding limits, long keys, malformed candidates, repeated near-matches,
and cleanup after interruption. Parent wall deadlines apply on all supported platforms;
unavailable OS limits remain explicitly unknown. Local macOS runs completed all 36
observations with matching actions and reaped children. They validate the selected
boundaries, not optimal budgets, universal latency, or native Windows execution. Consult
the implementation commit's CI and package-smoke evidence before merging or releasing.
