# Proposed connection-URI contract for #68

**Status: proposal for maintainer review; not an approved API or implemented feature.**
This follows the [published-0.1.7 development baseline](baseline_0.1.7/REPORT.md).
The baseline supports dedicated handling of explicit URI credentials and demonstrates why
partial incidental PII redaction is insufficient. It does not settle every grammar decision.
Keep the frozen v1 corpus and results unchanged while collecting the supplemental cases below.

## Smallest proposed increment

Propose `SecretScanner(connection_strings=True)` as an explicit opt-in, with existing
`SecretScanner()` behavior unchanged. Initially require `action=Action.BLOCK` when enabled;
WARN and partial redaction are outside this increment. Validate the option and action
combination at construction. A separate scanner remains an alternative if implementation
review finds this combination complicates the existing scanner contract.

Use fixed finding codes such as `secret_postgresql_uri` and `secret_mongodb_uri`. Findings
cover each complete recognized credential-bearing URI, with half-open Python character
offsets into the current scanner-input revision. Never put usernames, hosts, passwords,
decoded values or parser exceptions in finding metadata. BLOCK withholds the complete
checked text. Configure this scanner before redactors and verify zero model/consumer/state
delivery on BLOCK or ERROR, with no raw-input fallback.

## Proposed grammar to review

| Decision | Proposed initial behavior |
| --- | --- |
| Schemes | Exact lowercase `postgresql://`, `postgres://`, `mongodb://`, `mongodb+srv://`. Upper/mixed-case variants remain explicit exclusions unless supplemental evidence supports expanding this. |
| Start boundary | Beginning of input, or a preceding character outside ASCII letters, digits, `_`, `+`, `.`, `-`. No recognition inside a longer scheme-like token. |
| Candidate end | Whitespace, quote, backtick or angle bracket. Preserve other trailing punctuation instead of heuristically stripping it. Plain prose punctuation needs authored examples before acceptance. |
| Structure | Split literal URI delimiters before any component decoding. Preserve original positions. Support authored PostgreSQL/MongoDB host lists and bracketed IPv6. MongoDB SRV has one host and no port. PostgreSQL permits an omitted host. |
| Userinfo | A literal separator colon followed by a nonempty password is sensitive. Percent-encoded `:` or `@` remains part of its original component, not a new structural separator. Decide empty username handling from additional cases. |
| PostgreSQL query password | Split pairs on literal `&` and first literal `=`. A key equal to lowercase `password` after at most one bounded percent decode identifies a password. Any nonempty occurrence blocks, including duplicates and simultaneous userinfo/query passwords. No driver-precedence rule makes an exposed earlier value harmless. |
| MongoDB query fields | Do not infer that arbitrary query keys are passwords. Keep the current ambiguous query-password fixture outside supported detection. |
| Empty values | Username-only and empty-password forms produce no connection-string finding. This is a scope decision, not credential-validity verification. |
| Placeholders | Nonempty literal mask strings and ordinary documentation placeholder words in a supported password position block. Their spelling is not a reliable exemption. Environment expressions and angle-bracket templates require a separate explicit boundary decision. |
| Escapes and malformed input | One percent-decoding pass only where needed for credential components/query keys; no form-style `+` conversion. Bad escapes and structurally unsupported candidates remain outside the supported grammar, with visible misses. Do not concatenate broken lines or normalize Unicode. |
| Fragments | Do not interpret fragment contents as authentication fields. Define whether a syntactically present fragment stays in the whole-URI finding span using supplemental fixtures. |
| JSON | Keep decoding explicit and application-owned. Support the evaluated one-layer decoded string workflow; no implicit traversal or recursive decoding in the scanner. |

A candidate outside this grammar may still be sensitive. Absence of a finding is not a
claim that a driver rejects it. In particular, v1's truncated-context PostgreSQL example
remains policy-dependent: an omitted host is supported by libpq and is not inherently
malformed. The existing source references in [README.md](README.md) describe wider driver
grammars; this proposal intentionally requires a documented subset.

## Bounded work and implementation sequence

1. Approve the API/action and grammar above, including unresolved placeholder, fragment,
   empty-username and malformed-candidate decisions. Add separately versioned supplemental
   fixtures before modifying detection. Do not silently change v1 labels after observation.
2. Implement a local bounded candidate scan and minimal component parser. Preserve offsets,
   avoid whole-text normalization, repeated decoding and a general-purpose URI API. Keep
   dependencies and existing default signature checks unchanged.
3. Set explicit candidate-length, candidate-count and component-decoding work limits;
   exceeding them must produce a static metadata-only ERROR with no checked output. The
   evaluation's 2,000-character/four-candidate bounds are starting test conditions, **not
   evidence for production limits**. Choose supported numeric limits after bounded resource
   probes, including long benign input and overflow, before finalizing the public contract.
4. Compare unchanged defaults and the opt-in policy against v1 plus the supplement. Assert
   exact complete spans/actions, all authored credentials withheld, benign behavior and
   metadata-only failures. Include actual checked handoff and explicit decoded equivalents.
5. Add focused scanner and integration regressions, resource/limit tests, coverage and
   compatibility documentation, and a changelog entry under an agreed unpublished version.
   Require full checks, native Windows CI and fresh wheel/sdist smokes before merge/release.

The v1 corpus does not yet establish case-sensitive scheme/key behavior, percent-encoded
query keys, fragments, adjacent unquoted punctuation, misleading scheme boundaries, empty
usernames, environment/angle-template decisions or candidate-limit overflow behavior.
Those are prerequisites for accepting the corresponding proposal, not claims of existing
test coverage. No SDK work starts solely because the evaluation runner exits successfully.

## Deferred work and release scope

Defer PostgreSQL keyword/value, SQL Server/ODBC, JDBC/other schemes, generic URL-password
detection, credential validity/ownership, database/network access, arbitrary encoding or
Unicode normalization, selective redaction, and enterprise/IDE adapters. Retain the four
deferred v1 cases (40 observations) and their misses.

The reusable detector belongs in the public SDK and does not depend on enterprise adapters.
Tentative 0.1.8 remains a later batched release subject to compatibility and scope review;
this local evaluation neither changes the source version nor authorizes publication.
