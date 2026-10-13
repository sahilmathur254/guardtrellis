# Decoded JSON decision and deferred core proposal

**Status: recipe-first decision accepted on 2026-10-13; general core API deferred.**
This records the design decision for
[#11](https://github.com/sahilmathur254/guardtrellis/issues/11).
The `0.1.x` text scanners, `JSONScanner`, and `ToolGuard` keep their current behavior.
The bounded recipe is scoped in [#41](https://github.com/sahilmathur254/guardtrellis/issues/41).
The general core contract below remains a proposal and requires a separate decision.

## Problem and concrete caller

Consider an application that accepts a proposed `search` call with this trusted schema:
an object containing only a required string `query`, at most 200 characters. Its policy
redacts email addresses before the search callback receives the checked argument.
These two fabricated wire representations have the same decoded value:

```json
{"query":"Contact casey@example.org"}
{"query":"Contact casey\u0040example.org"}
```

Today's `ToolGuard` validates JSON and the schema, but its argument scanners inspect
serialized characters. A text email scanner can redact the first representation and miss
the second. The desired outcome for both is a callback argument of
`{"query": "Contact [PII]"}`. Neither the original argument text nor the original decoded
dictionary should reach dispatch. The existing [Unicode/PII challenge set](../evaluation/challenges/README.md)
retains observed plain/escaped differences; this proposal does not change that evidence.

This is a concrete, synthetic caller scenario derived from the existing search recipe,
not evidence of an external adopter or a requirement to intercept every tool invocation.
It closes a representation gap for configured scanners, not the detectors' format gaps:
decoding does not add name recognition, arbitrary phone formats, or semantic injection detection.

## Recommendation and alternatives

Recommend an **application-owned fixed-field recipe on the current public API first**.
The concrete caller above has one known `query` field; no confirmed nested/multi-field
adopter requirement has been recorded in #11. A shared core values-only checker remains
a possible later feature, rather than the next implementation commitment.

If a shared checker becomes justified, keep it separate from text `Guard` and `ToolGuard`;
a later tool adapter can compose it without silently changing existing serialized-text
behavior. Do not introduce a policy language, recursive decoding framework, or automatic
interception. The proposed general contract below remains subject to separate review.

| Choice | Benefits | Costs and boundary |
| --- | --- | --- |
| Application-owned recipe for the named `query` field | Uses today's public API; application owns a narrow schema and handoff; no new public types. | Use a `ToolGuard` preflight without text policies for strict JSON/name/schema checks, then `Guard` on the decoded field, a fresh object, serialization, and final `ToolGuard` validation. The application must bound work, reject unpaired surrogates, handle failures, and preserve field provenance; no private parser helpers are needed for this fixed schema. |
| Explicit core values-only checker | Shares parsing, traversal limits, all-or-nothing output, and decoded-value provenance across callers with nested structures. | Adds a new result/location contract, schema and serialization decisions, tests, and maintenance. Justified only if the shared guarantees are needed beyond one fixed field. |
| Implicit decoding inside existing text scanners or `ToolGuard` | Fewer visible calls. | Changes existing offsets, ordering, output representation, and detection behavior. Reject this option for `0.1.x`. |

The first option serves the evidenced single-field scenario. Reconsider the shared checker
when a named caller needs nested objects/arrays or multiple protected fields, and a comparison
shows why application-owned handling is insufficient. Synthetic nested examples can test a
design but do not themselves establish adopter demand. The decision adds no runtime feature;
the separately scoped recipe uses existing public APIs.

## Fixed-field feasibility evidence

A local offline probe on 2026-10-10 used GuardTrellis `0.1.2` public imports only. It passed
12 original synthetic cases: plain/escaped email equivalence, ordinary/escaped-equivalent
duplicate names, wrong field type, extra field, oversized field, invalid JSON, unpaired
surrogate, policy block, scanner exception, and schema rejection after an edit.
The two accepted inputs produced the same `("search", {"query": "Contact [PII]"})` pair;
each rejected case left the local dispatch recorder empty. Accepted-case repr/diagnostics
and rejection messages were checked for the probe's synthetic canaries.

The tested sequence was:

1. Public `ToolGuard` with exact name `search`, a fixed object schema containing only a
   required 1–200-character `query`, no argument text scanners, `max_chars=4096`, and
   `max_depth=2`. Call `require_call()` before reading the decoded field. This preflight
   checks shape and syntax; it has not applied the field's content policy.
2. Reject unpaired surrogates in the decoded query. Run its ordered scanners through
   `Guard.scan(..., stage=Stage.TOOL)` with `max_chars=200`; consume only `require_text()`.
3. Reject unpaired replacement surrogates, build a fresh `{"query": checked_text}` object,
   serialize it, and revalidate through the same `ToolGuard` before consuming its final
   `require_call()` pair. Host authorization and dispatch follow that pair.

This is narrow design feasibility evidence, not a shipped example, independent benchmark,
complete boundary suite, or general structured-data implementation. The probe does not
test nested traversal, cross-leaf ordering, all resource thresholds, or async document
deadlines. Existing historical evaluation corpora and baselines remain unchanged.

## Proposed input, traversal, and policy contract

These are proposed requirements, not available constructor parameters or imports.

- Accept one serialized JSON `str` plus trusted, snapshotted scanner/schema configuration.
  Do not initially accept caller-owned dictionaries: duplicate names have already been lost
  and mutable aliases complicate isolation. Reject wrong input types with payload-free errors.
- Accept an explicit `Stage`, defaulting to INPUT as in text `Guard.scan`. Pass that same
  stage to every scanner invocation and record it in result diagnostics. The search caller
  selects TOOL; a stage does not authorize or automatically perform a host operation.
  Reject invalid stage configuration before processing input.
- Parse strictly once. Reject duplicate **decoded** object names, including `"a"` alongside
  `"\u0061"`; reject invalid JSON, non-finite numbers, and excessive depth before scanning.
  Apply an optional trusted schema to the complete decoded input before any edits.
  Use the current constrained Draft 2020-12 schema subset and local-reference rules;
  remote schema fetching and new schema features are outside this proposal.
- Visit every string value in objects and arrays, including a string at the root. Traverse
  depth first in parsed object insertion order and array index order. Empty strings count.
  Object names are preserved, never scanned or edited. Consequently this mode does not
  protect sensitive keys; callers needing that must reject such payloads by their own policy.
  No key edits means no new key collisions; initial duplicate detection remains mandatory.
- Preserve array/object structure and decoded booleans, nulls, and numbers. Integers follow
  Python integer decoding within the input/parser limits; fractional/exponent numbers use
  finite Python floats, matching the current strict parser's numeric model. Decimal precision,
  numeric spellings such as `1e0`, whitespace, and escape spelling are not preserved.
  Applications requiring exact decimal or byte-preserving round trips cannot use this mode.
  Schema validation sees these decoded numbers, not their source spelling.
- Decode JSON escapes, including valid surrogate pairs, once. Reject unpaired surrogates in
  keys, values, and scanner replacements to make UTF-8 output well-defined. Do not normalize
  Unicode, case-fold beyond a configured scanner, parse embedded JSON strings, decode base64,
  or interpret an already decoded literal `\u0040` sequence again.
- Run in **scanner-major order**: scanner 0 across all leaves, then scanner 1 across all
  leaves, and so on. A blocking scanner placed before a redactor therefore sees every
  original leaf. A later scanner sees each leaf's preceding edits. Do not implement this as
  independent complete `Guard` pipelines per leaf, which changes cross-leaf ordering.
- Stop immediately at the first BLOCK or ERROR. Aggregate permitted actions as
  ALLOW < WARN < REDACT; WARN intentionally permits delivery. Validate each scanner result
  and all its edits before applying them. The existing span/non-overlap invariants apply to
  each decoded string, not to the serialized document.

[RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html) explains JSON object names, escapes,
Unicode interoperability, and implementation limits (§§4, 7–9). The tighter rejection and
scanning policies above are this proposal's choices, not guarantees supplied by JSON itself.

## Proposed bounds and failure behavior

Use deterministic counters for the whole operation, not a fresh budget per leaf. The
following initial defaults are review targets; configurable limits must be positive bounded
integers and any higher ceilings need measurement before implementation approval.

| Resource | Proposed default / meaning |
| --- | --- |
| Serialized input and serialized output | 100,000 Python characters each; cap construction before return. |
| Nesting | 32 container levels, matching the existing parser convention. |
| Traversal | 4,096 total nodes, including containers and scalar values; count each object key separately against the same cap. |
| String size | 100,000 characters per key or value and 100,000 total decoded characters across keys and string values. Recheck after edits. |
| Policy size/work | At most 32 scanners; at most 16,384 scanner/leaf invocations and 1,000,000 cumulative input characters presented to scanners. |
| Findings and trace | At most 256 findings and 16,384 fixed-shape trace entries across the operation. Overflow rejects instead of silently truncating. |

Budget checks precede the next invocation or allocation where possible. Input size and
parser depth checks bound parsing before a tree exists; post-parse node checks alone cannot
prevent parser allocation. Count keys even though their content is not scanned. A policy
with many redactions must also satisfy output and cumulative-work limits. These counters
bound admitted work, not the cost of an arbitrary scanner or schema.

Invalid input JSON, duplicate names, unpaired input surrogates, schema mismatch, or an input
resource limit produces BLOCK. Scanner exceptions, invalid scanner results/replacements,
work/output/findings overflow after execution starts, schema-engine failures, and unexpected
serialization failures produce ERROR. Reject invalid trusted configuration at construction
with a payload-free configuration error. Use fixed reason codes; never pass through parser,
schema, scanner, or callback exception messages.

A synchronous checker has no hard execution deadline. Defer an async entry point from the
first implementation; the design must not multiply today's per-operation waits across all
leaves and call that a document deadline. A later async design needs a single remaining-time
budget for the operation and explicit cancellation semantics. Threads cannot be forcibly
terminated; application concurrency control and process isolation remain host concerns.

## Edits, schema revalidation, and checked handoff

1. Parse and validate the original document against the supplied schema. A redactor does
   not repair otherwise invalid input into an accepted call.
2. Scan/update a private working tree. Never mutate caller state or expose partial output.
3. Validate the entire edited tree against the same schema. A replacement that violates
   `minLength`, `enum`, or any other supported constraint produces BLOCK, with no output.
   Do not weaken the schema or silently undo an edit to pass validation.
4. Serialize with a fixed documented policy (UTF-8-safe JSON, finite numbers, compact
   separators, preserved object order), enforce the output cap, and strictly reparse/revalidate
   the bytes-equivalent text before acceptance. This catches serialization contract failures;
   a discrepancy here is ERROR, not a successful partial check.
5. Return only immutable checked JSON text through the successful result/accessor. BLOCK
   and ERROR contain no normal text or decoded object; the accessor raises a payload-free
   rejection. A caller may parse the checked text into its own new object after acceptance.

For the search scenario, the application should validate the exact tool name separately,
obtain the checked JSON, perform final `ToolGuard` schema/name validation on that text, and
dispatch only `require_call()`'s returned name/arguments behind application authorization.
No callback belongs inside the initial checker API. Its result cannot force callers to stop
using a separately retained original; tests and examples must demonstrate the checked path.
Output checks after dispatch cannot undo tool side effects.

## Locations, revisions, and privacy

Use a distinct structured result/finding type; do not reinterpret `Result.findings` or
`Finding.start/end` from the text API. Assign each string value a sequential opaque leaf ID
during deterministic traversal. Do not include a JSON Pointer, property name, value, matched
substring, replacement, source excerpt, or exception message in generic diagnostics/reprs.
Leaf IDs are local to one call, not stable identifiers for tracking a person or field.

Each decoded finding records a fixed reason code, scanner ID/index, leaf ID, leaf input
revision, and half-open Python character offsets within that revision of that decoded value.
Increment a leaf's revision for each redacting scanner invocation, following the text API's
revision convention. Offsets cannot be applied to wire JSON, another leaf, a later revision,
or UTF-8 byte positions. Do not retain an original-to-redacted rehydration map.

Fixed-shape traversal/scanner trace entries may record leaf ID, revision, scanner index,
action, and counts. Document that these reveal structure/length metadata. Names for custom
scanners and codes must obey the same trusted-metadata restrictions as current diagnostics;
this is not a sanitizer for arbitrary configuration strings. No full mutable tree belongs
in the result, exception attributes, or repr. This is a logging boundary, not memory erasure:
the caller and Python runtime may retain inputs, locals, and exception tracebacks.

## Validation required for a future core implementation

| Case | Required observation |
| --- | --- |
| Plain vs escaped email/selected synthetic secret | Same decoded outcome and checked callback argument for equivalent values. Preserve old corpus and publish a separate comparison. |
| Nested objects, arrays, root strings, empty strings | Every value visited once per reached scanner in defined order; keys untouched. |
| Cross-leaf ordering | A block in a later leaf stops before an earlier leaf reaches a later redactor. |
| Stage-sensitive scanner | The caller's selected stage reaches every invocation; the default is INPUT and the search scenario uses TOOL. Invalid stages reject. |
| Unicode and repeated encoding | Valid pairs decode once; unpaired surrogates reject; normalization is not implicit; embedded escapes/base64 remain literal. |
| Duplicate/escaped-equivalent names | Reject before ordinary dictionary construction can discard information. |
| Key collision concerns | Keys cannot be edited; no rename/collision behavior is implicitly promised. |
| Non-string values and numeric round trips | Structure preserved; booleans/null/integers unchanged; float behavior and precision limitation demonstrated; non-finite values reject. |
| Schema before and after redaction | Invalid originals and invalid replacements reject; accepted final serialized text also validates. |
| Every bound at/below/above threshold | Deterministic complete rejection, no partial text; total counters cannot reset per leaf. Include expansion by replacements. |
| Scanner exception or malformed Check | ERROR with fixed metadata; no checked value or raw exception in ordinary output. |
| Sequential redactions/findings | Correct decoded leaf revisions and spans; no conversion into wire offsets. |
| Rejected accessor and accidental original reuse | Accessor rejects; callback/dispatch spy remains uncalled; positive handoff uses only checked text. |
| Privacy and mutation | Keys/values/replacements absent from repr/diagnostics/errors; no caller-owned object mutation or original map retention. |
| Compatibility | Existing text/scanner/ToolGuard tests remain unchanged and pass. |

Use original synthetic fixtures and explicit provenance. Detection misses on unsupported
formats remain misses; these tests must not relabel them to claim broader PII accuracy.
No performance threshold or production-capacity claim follows from the proposed counters.

## Decision record and versioning gate

**Maintainer decision: recipe-first accepted on 2026-10-13.** The maintainer confirmed the
bounded single-field search scenario as the next contribution. No nested/multi-field adopter
requirement has been established. The accepted decision is:

| Decision | Accepted disposition |
| --- | --- |
| Immediate scope | Implement a fixed-field `search.query` recipe in #41, using current public APIs. |
| General core API | Defer until a concrete nested/multi-field requirement and comparative evidence justify its maintenance cost. |
| Current contracts | Preserve `Guard`, `JSONScanner`, `ToolGuard`, diagnostics, and serialized-text behavior. No implicit decoding or new public types. |
| Versioning | The current-API recipe remains `0.1.x` work, prepared for unpublished `0.1.3`. If a structured core API is later accepted, review it at a `0.2.0` feature boundary; no publication or release date is authorized. |
| General proposal | Retain values-only scope, scanner-major ordering, sync-only initial scope, numeric/Unicode semantics, aggregate budgets, and opaque provenance as review material, not accepted defaults. |

The acceptance authorizes the recipe scoped in #41. It does not authorize a shared checker,
implicit decoding in existing scanners, or broader nested/multi-field behavior. Reopen the
core design question when a named caller requires those shared guarantees.

### Accepted follow-up scope (#41)

**Title:** Add a bounded decoded `search.query` recipe using public SDK APIs.

**Scope:** one core-only, credential-free synchronous example plus documentation and
behavior tests. Show public name/schema preflight, selected decoded-field scanning at TOOL,
fresh-object serialization, final schema/name validation, and application authorization
before a local dispatch recorder. Add no runtime API, provider dependency, nested traversal,
general parser wrapper, async document deadline, or host adapter.

**Acceptance criteria:**

- Plain and escaped equivalent supported email/secret fixtures deliver identical checked
  arguments; unsupported detector formats remain explicitly excluded.
- Unknown names, invalid/duplicate JSON, extra/wrong/oversized fields, non-finite values,
  unpaired input/replacement surrogates, scanner errors/malformed checks, and post-edit
  schema failures yield no actual dispatch or normal rejected payload.
- Positive dispatch consumes only the final checked pair after host authorization; a host
  authorization denial invokes no tool. The preflight result is never used for dispatch.
- Input, decoded field, transformed field, serialized output, and parser-depth bounds are
  stated and tested at/below/above limits. Configuration limits are concrete, not capacity
  claims; synchronous work has no hard deadline.
- Repr, diagnostics, and rejection/error output exclude synthetic canary values and raw
  exception messages. Field locations stay application-owned and distinct from wire offsets.
- The example runs offline, ships in the source archive, participates in wheel/source
  installation smokes, and passes the applicable repository checks. Retain existing corpora.

The scoped implementation issue is [#41](https://github.com/sahilmathur254/guardtrellis/issues/41).
If a later caller justifies the core option, its implementation issue must additionally record:

- whether there is sufficient nested/multi-field caller need for a shared core checker, or
  whether to proceed only with the fixed-field recipe;
- acceptance or revision of values-only scope, scanner-major order, float serialization
  semantics, initial sync-only scope, budgets, and metadata contract;
- a separately scoped implementation issue, including final public names and signatures,
  types, tests, documentation, and comparison evidence;
- the intended release series. Recommend a separately reviewed `0.2.0` feature boundary
  for the new structured API, with explicit migration notes if any existing contract changes.
  Documentation/evaluation/current-API recipes can remain patch-level `0.1.x` work.

No public API names are reserved by this document. Existing applications require no migration
for this proposal; `Guard`, `JSONScanner`, `ToolGuard`, and their diagnostics continue to
mean what the [compatibility policy](compatibility.md) and [API guide](api.md) document.
