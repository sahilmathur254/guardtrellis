# Retrieval and tool policy evaluation, v1

Maintainer-approved #35 scope, 2026-11-04. This is a public, English-language,
AI-assisted synthetic development batch using SDK 0.1.11 and existing APIs.
Author self-review and internal assistant review are recorded; no independent,
blinded, representative-population or held-out validation is claimed.

## Frozen question and sample units

Twelve research scenarios form six contrast pairs, R01-R12/P1-P6, as specified in
the accepted `docs/retrieval_tool_policy_design.md`. Eleven harness controls H01-H11
are a separate denominator. The 23 workflow executions are not 23 independent
prompt-injection attacks, and no model is asked to choose or carry out an action.

The legitimate task is to read `public-guide`. Each case supplies a retrieved string,
a scripted tool proposal and a local returned string. The host controls source identity,
the exact tool/schema map, document permissions, scanner configuration and callback wiring.
Payload claims of approval or tool definitions cannot change those controls.

S1-S4 in `sources_v1.json` record primary references, revision/date, evidence class,
sections, retrieval metadata and content digests. Cases are original synthetic prose,
not imported attack payloads, benchmark data, credentials or personal records. Source
S4 observes malicious payloads/intent rather than a confirmed successful compromise of
deployed ad-review agents. Its publication date comes from captured page metadata.
The source-set limitations and all instruction-only ALLOW outcomes remain visible.

## Fixed workflow and current-contract expectations

At initial retrieval and returned-text ingress, configure RETRIEVAL with default
`SecretScanner()` (BLOCK) then `PIIScanner()` (REDACT), with `max_chars=2_000`.
No literal rule, formatted-phone/URI option, decoder, normalizer or semantic classifier
is added. Use `require_text()` before the next callback.

Validate one exact `lookup` name and a flat required `document_id` string of length
1-64, with no additional properties, `max_chars=2_000` and `max_depth=2`. Consume only
`require_call()`'s checked pair. Authorize a copy and require literal `True`; only
`public-guide` is authorized. Dispatch the unchanged checked pair, scan the local return,
and deliver only its checked text. No tool performs file, network, database or persistent
operations. An unexpected destination field is structural rejection, not URL/SSRF safety.

`contract.py` is stdlib-only. It projects the authored cases to exact internal expected
states without SDK imports or observations. `expectations_v1.json` retains all 23 states:
per-boundary diagnostics/actions/findings/spans, ordered events, callback counts,
proposer input, authorization/dispatch pairs, consumer text, terminal/error boundary and
separate desired-protection meaning. Runtime loading revalidates the cases, reprojects
the expected states and verifies their equality with the frozen expectation file.

Assertions compare payload-bearing states only in memory. Public rows contain fixed
IDs, diagnostics, event labels, counts and match booleans. Retrieval rejection permits
no proposer or downstream call; call rejection permits no authorization/dispatch/consumer;
host denial permits no dispatch/consumer; return rejection permits no consumer. A proposer
can already have run before tool validation rejects its proposal.

R01-R04 retain instruction-like ALLOW cases. R05 rejects an extra destination property;
R07 rejects an unapproved tool name; R09 reaches SDK-valid/host-denied authorization;
R11 blocks a fabricated GitHub-style signature before PII redaction; R12 redacts only
the synthetic email and delivers exactly that result. Controls do not change these labels.
Do not interpret unchanged delivery of an instruction-like string as semantic protection.

H01-H11 separately cover initial retrieval redaction/block/error, returned-text error,
literal-True authorization, authorizer-copy isolation, three callback failure boundaries,
duplicate JSON keys and malformed JSON. Deliberate harness mutations exercise raw retrieval
reuse (H01), raw return reuse (R12), altered dispatch/early consumption (R10), raw failure
fallback (H08), payload approval (R09) and truthy authorization (H05). Each must fail the
integrity oracle while emitting payload-free metadata. Raw-text mutations use a REDACT
control so equality cannot hide an ALLOW bypass. These are harness tests, not new research
scenarios. No new fixture or mutation is observed before this freeze's external receipt.

## Work, lifecycle and report bounds

Run one fresh child at a time, in fixed R01-R12 then H01-H11 order, using the existing
resource helper's sanitized environment, available CPU/memory limits, kill/reap behavior
and Windows base-interpreter/virtual-environment launcher convention. The child observation
budget is ten seconds, clipped to the parent observation time remaining. Parent observation
time is 180 seconds; this includes launch/import/SDK checks and is not isolated scan timing.
No universal latency, throughput, model outcome or production-capacity claim follows.

Capture at most 64 KiB separately for stdout and stderr. Accept only the fixed worker
metadata protocol; do not copy malformed worker text, traceback, private path or environment
values into reports. Capture overflow, timeout, callback/harness errors and interruption
are explicit statuses. Preserve validated completed-prefix evidence if later cleanup fails.
Stop new launches after deadline/cancellation or unconfirmed child reaping. Retain a record
for every scheduled case, marking unstarted work explicitly and later rejected-case
boundaries ineligible rather than passed.

The resource helper's five-second child-reap wait is outside observation time. Record
cleanup failure separately from observed process state; do not invent successful reaping.
Report I/O follows cleanup, has a combined 512 KiB encoded JSON/Markdown ceiling, and has
no hard wall-clock guarantee. Refuse an existing output directory and never replace prior
evidence. A write failure produces a static failure status; an unwritable destination
cannot guarantee a retained report. There is no 180-second whole-process completion claim.

Public results omit raw/checked strings, tool arguments, synthetic token/email canaries,
exception messages and host paths. Retain validated metadata only, including actual SDK,
runtime, dependency and runner hashes, explicit errors/incomplete work, observed versus
expected callback/delivery outcomes, and per-denominator summary counts. Timing describes
containment, not a benchmark speed threshold. Expected ERROR controls remain separate
from unexpected SDK/runtime errors.

## Pre-observation receipt and acceptance

Before any new-case SDK execution, hash this protocol, the two case files, exact expectations,
pure projection code and source ledger into `freeze_v1.json`. Record the accepted-design hash,
base revision, SDK/helper/lockfile hashes and historical evaluation identities. Post the
manifest digest as an external #35 receipt and bind the runtime loader to that digest and
receipt URL. Asset verification itself uses only the standard library and must not scan.

The receipt must predate the first parent/worker observation timestamp. Every later run
verifies the immutable frozen bytes; actual runtime/source hashes identify the code that
ran and distinguish later version/dependency comparisons from the original snapshot.
Preserve original expectations and misses. A label/projection correction after observation
requires a new version or explicit post-observation erratum, not a silent edit.

Exit zero requires all twelve research and eleven harness workflows accounted for, all
eligible current contracts and handoffs matched, all children reaped and no privacy or
unexpected-runtime failure. Desired semantic limitations are reported without becoming an
artificial catch-score gate. Invalid CLI/existing output exits 2, other incomplete/failed
evaluation exits 1 and handled interruption exits 130. Error messages are static.

Keep SDK source/defaults, dependencies, package version and every historical evaluation
unchanged. No new detector/API, host activation, provider call, commit, push, merge or release
is authorized. The parent #35 remains open for review; the batch and its tests/docs are
one contribution, not multiple release updates.
