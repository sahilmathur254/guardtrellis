# Connection-URI implementation contract for #68

**Status: contract finalized on 2026-10-22; SDK implementation has not started.**
The [published-0.1.7 baseline](baseline_0.1.7/REPORT.md) establishes the coverage gap.
The separately versioned [contract supplement](SUPPLEMENT.md) records the decisions below
before a detector is written. It preserves all original v1 labels, text and results,
including the twelve previously ambiguous cases. Supplemental outcomes still come from
the unchanged SDK; they do not demonstrate the planned API. The separately frozen
[structural-boundary addendum](BOUNDARIES.md) completes the pre-implementation decisions.
This document defines the implementation scope; SDK edits, commit/push and publication
still require their separately authorized steps.

## API, findings and checked delivery

Add a keyword-only `connection_strings: bool = False` to `SecretScanner`. Require an actual
boolean, and require `action=Action.BLOCK` when it is true. Defaults, existing signatures,
and existing WARN/REDACT/BLOCK behavior when false remain unchanged. Keep the existing
scanner name `secrets`; no separate public scanner, result fields, dependency or public
parser-tuning options are needed for this increment.

Use fixed codes `secret_postgresql_uri` and `secret_mongodb_uri`. Each URI finding covers
the complete recognized candidate with half-open Python character offsets into the current
scanner-input revision. Retain existing token-signature findings when they overlap a URI;
the new evaluation must compare URI targets separately from existing signature spans.
Do not put usernames, hosts, passwords, decoded components or parser exceptions in metadata.

BLOCK and ERROR expose no accepted text. Integration checks must demonstrate zero downstream
model/consumer/state delivery, with no original-input fallback. Configure blocking secret
checks before PII redactors. This scan detects disclosure, not credential validity or full
driver syntax: an invalid host or port cannot make a visibly embedded password safe.

## Selected recognition rules

| Decision | Initial contract |
| --- | --- |
| Schemes | ASCII case-insensitive `postgresql://`, `postgres://`, `mongodb://`, `mongodb+srv://`. Do not apply Unicode case folding or normalize the whole input. |
| Start boundary | Start of input or a preceding character outside ASCII letters, digits, `_`, `+`, `.`, `-`. Do not recognize a supported spelling embedded in a longer scheme-like token. |
| Structural delimiters | Identify literal separators before any decoding. Authority starts after `://` and ends at the first literal `/` or `?`, or at candidate end if neither occurs; only this region supplies userinfo. The first literal `?` starts the query. An encoded delimiter stays within its original component. Do not percent-decode the entire URI. |
| Userinfo | Within the authority only, take the first literal colon and last literal `@`. If the colon precedes that `@` with at least one character between them, BLOCK. Treat the intervening text as an opaque password, including extra colons or earlier `@` characters. An empty username is allowed by this detector rule; decoding the password is unnecessary. |
| Host/port syntax | Do not require a usable connection. Omitted PostgreSQL hosts, invalid hosts/ports, multi-host content and invalid SRV port syntax still BLOCK when an explicit password slot is recognizable. No DNS or driver parser is used. |
| PostgreSQL query | Split on literal `&` and the first literal `=`. Match `password` ASCII case-insensitively after one bounded percent-decoding pass on the key. This deliberately conservative detector policy is not a claim that every driver accepts the spelling. |
| Repeated credentials | Any nonempty recognized password occurrence BLOCKs, including duplicates with an empty last value and simultaneous userinfo/query credentials. Inspect query pairs independently: a malformed unrelated pair before or after a clear password must not erase it. Emit one URI finding for the candidate, rather than one for each exposed component. |
| Percent escapes | Decode query keys once only; malformed keys are unsupported unless another explicit credential is present. Malformed escapes inside a nonempty recognized password do not exempt it. Do not decode `+` as space or treat encoded separators as structure. |
| Empty values | Username-only and exactly empty password slots add no connection-URI finding. Empty username with a nonempty password BLOCKs. Other existing scanners may still report findings. |
| Templates | Nonempty masks, ordinary placeholder words, `${ENV}` and `<placeholder>` in recognizable password slots BLOCK. Do not expand environment variables. These intentional template false positives must be documented. |
| Literal `#` | Do not globally truncate candidates at `#`: retain it in recognizable userinfo/query password values, including at the beginning of a value. No separate fragment-password grammar is added. |
| Unsupported forms | MongoDB query-only password fields, double-encoded PostgreSQL keys and key aliases have excluded/null supplemental comparisons, without a safety claim. Credential-free scheme lookalikes are selected benign negatives; credential-bearing unsupported schemes remain deferred. |
| JSON | Decoding remains explicit and application-owned. Compare raw wire and one-layer decoded equivalents separately; no implicit traversal or recursive decoding. |

The first-colon/last-`@` rule is deliberately conservative disclosure detection. For
example, an empty gap before the first `@` does not exempt nonempty text before a later
`@`. Conversely, a username with no literal colon, or an exactly empty interval between
the selected colon and `@`, produces no userinfo finding. A colon occurring only after
the final `@` is not a password separator. A PostgreSQL query password can still require
BLOCK independently of these userinfo decisions.

Apply that rule only before the authority's first literal `/` or `?`. Credential-like
text in a path or unrelated query value cannot be promoted into userinfo, even if it
contains both `:` and `@`. Percent-encoded separators never create structural boundaries.
The addendum fixes exact targets and credential intervals for the selected cases before
observing the SDK; no driver, network or credential-validity check supplies those labels.

This policy can intentionally block malformed or illustrative strings. PostgreSQL's
parser selects the first literal `@` and the first preceding colon, while MongoDB's
specification requires driver rejection of embedded `@` or multiple userinfo colons.
GuardTrellis does not claim to reproduce either driver's acceptance rules. The primary
references below document that distinction.

## Candidate boundaries and offsets

Walk the input monotonically and preserve original character offsets. Whitespace, including
a physical line break, ends a candidate; do not join lines. The inherited broken-line case
has an explicit first-line credential slot and therefore targets that prefix, without
claiming recovery of the second-line host text.

An apostrophe can belong to userinfo and must not be a universal terminator or be trimmed
heuristically. The selected prose wrappers are double quotes, backticks and outer angle
brackets, which are excluded from the target. An inner `<placeholder>` in a password slot
remains part of it. Single-quote wrapper removal is not selected by this batch. Implement
the authored wrapper contexts explicitly; do not strip arbitrary credential punctuation
or assume a generic URL parser's token boundaries. Preserve other adjacent punctuation
conservatively in the candidate. Exact supported boundaries are reviewable in the authored
`target_spans`, independently of current detector results.

Literal `#` needs particular care: RFC fragment semantics are not a safe substitute for
libpq's password/query parsing. The PostgreSQL parser scans query pairs to `&` or end, and
userinfo to its literal delimiters; stripping a fragment first could hide a password.
This contract does not infer credentials from fragment-like `#password=...` text with no
recognized userinfo/query password slot.

## Failure and resource boundaries

Separate three outcomes:

1. A recognizable nonempty password gives BLOCK even if surrounding URI syntax is invalid.
2. A structure outside the selected grammar gives no URI finding, with a documented gap.
   A malformed URI alone is not an ERROR condition or an assertion of safety.
3. A processing budget overflow or unexpected scanner failure gives a static, spanless
   ERROR and no checked output. Do not leak parser exception text.

Reuse `Guard.max_chars` and the existing 256-finding ceiling. Count candidate attempts
separately from findings so repeated credential-free or malformed candidates also consume
the work budget. Bound candidate walking, component decoding and total candidate work;
avoid repeated rescans of a shared suffix. Select any additional numeric limits from
bounded subprocess resource probes before final implementation acceptance. The corpus's
2,000-character scan/four-candidate conditions are **not production limits**.

The supplemental and boundary baselines perform no resource-limit experiment and cannot settle these
numbers. Probe long benign text, repeated near-matches, many credential-free candidates,
oversized candidates and each overflow boundary. Preserve incomplete work and avoid a
machine-dependent latency threshold. Include direct `SecretScanner.scan()` calls as well
as `Guard` pipelines, so work bounds do not silently depend on `Guard.max_chars`. Select
numeric budgets against the implementation before acceptance; benchmarking the unfinished
detector is not a prerequisite to starting it. No new public performance knobs are proposed.

## Preparation complete; implementation acceptance gates

1. Preserve the three independently versioned case sets and their historical reports.
   The supplement retains all twelve original ambiguous inputs with origin IDs; the
   16-case boundary addendum records the final separator and query-ownership decisions.
   Selected cases have authored decisions; excluded/resource-pending cases remain unscored.
   The grammar/API/action/compatibility decisions above complete the preparation gate.
2. Implement the opt-in bounded scan, constructor validation and static diagnostics with
   existing dependencies and default signature behavior unchanged. Add focused tests for
   exact offsets, overlapping token signatures, multiple credentials and deterministic
   finding order. Decide numeric processing limits using the probes above.
3. Add a separately versioned opt-in comparator. The frozen v1 harness continues to report
   current/default behavior; it must not be retrofitted to erase historical misses. Compare
   defaults and opt-in across all three case sets, raw/decoded coordinates and both fixed policies.
4. Verify every authored credential is withheld for BLOCK/ERROR and exact allowed text is
   delivered. Add integration coverage for INPUT, OUTPUT, RETRIEVAL and TOOL stages, and
   checked tool arguments and state insertion. Keep PII-only false positives separate.
5. Document supported formats and exclusions, compatibility, template tradeoffs and resource
   limits. Require full checks, native Windows CI and fresh wheel/sdist smokes before merge.
   Add a changelog entry/version change only as part of an agreed implementation release.

Passing the current evaluator means that observations completed safely, not that the
connection-string detector exists or that its detection score is sufficient.

## Deferred work and release scope

Defer PostgreSQL keyword/value, SQL Server/ODBC, JDBC, other schemes, generic URL-secret
detection, selective redaction, credential validity/ownership, database/network access,
arbitrary encoding, Unicode normalization and enterprise/IDE adapters. Retain deferred v1
misses. PII matching improvements are a separate scope.

The reusable detector belongs in the public SDK. Tentative 0.1.8 remains a later batched
release subject to review; this local contract/evaluation batch changes no source version
and authorizes no publication.

## Primary format references

- [PostgreSQL libpq connection strings](https://www.postgresql.org/docs/current/libpq-connect.html#LIBPQ-CONNSTRING): optional URI components, omitted hosts and query parameters.
- [PostgreSQL 18 parser source](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/interfaces/libpq/fe-connect.c): literal userinfo/query delimiters, including the reason not to strip `#` globally.
- [MongoDB connection-string specification](https://specifications.readthedocs.io/en/latest/connection-string/connection-string-spec/): userinfo and sub-delimiters, including apostrophes; driver rules are wider than this detector's purpose.
- [MongoDB standard/SRV formats](https://www.mongodb.com/docs/manual/reference/connection-string-formats/): format context, without requiring driver-valid SRV syntax before protecting an exposed password.
- [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986): case-insensitive scheme names and userinfo characters. Database-specific behavior still requires the references above.
