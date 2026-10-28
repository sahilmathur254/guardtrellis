# Detector and checked-delivery challenge, v1

Approved #45 / unpublished 0.1.9 scope, 2026-10-27. Author: Codex-assisted original
synthetic fixtures with knowledge of the implementation. The maintainer approved the
scope, not the individual labels. Labels and projections receive author self-review;
there is no independent, blinded or native-language per-case review. These public
Apache-2.0 development fixtures do not establish population accuracy or hidden-test evidence.

## Fixed matrix and pre-observation expectations

48 scenarios form 24 sensitive/benign contrast pairs: eight pairs each for email, phone
and connection URI. Context is English; non-ASCII prose/markers exercise representation
and character offsets without establishing multilingual detection support. All addresses,
phone shapes and credential values are fabricated. No provider/database/DNS requests run.

One RETRIEVAL scan uses secret BLOCK before default PII REDACT. The `default` profile
keeps contiguous phones and URI detection disabled; `opt_in` selects formatted phones
and URI detection. All other configuration is identical. Four representations are plain
text, literal JSON, fully Unicode-escaped JSON, and an explicitly decoded fixed `value`
field. Both wire forms must decode to the same string; one decoded observation is counted.
This is 384 observations, not 384 independent scenarios. All represented inputs are at
most 2,000 Python characters. Expected action, full checked text and Python half-open
target spans are frozen separately for every case/profile/representation before scanning.

Scenario intent and format contracts are separate. Sensitive email/phones desire complete
redaction; sensitive connection metadata desires BLOCK. Benign scenarios desire unchanged
ALLOW. Template/code lookalikes can be scenario false positives while satisfying documented
shape-matching contracts. Supported-contract primary spans/action are authored from the
documented grammar; unsupported forms have no asserted span contract. Disabled URI profiles
assert no URI findings but allow incidental PII outcomes. Fully escaped raw values assert
no primary findings and ALLOW, reflecting the absence of implicit decoding. These controls
are separately counted, not claims of supported detector coverage. Incidental PII findings
are never credited as URI signals. Non-target findings still participate in action/delivery.

`contract.py` performs only deterministic JSON encoding, index projection and desired
string replacement. It imports no SDK and never infers expectations from observed output.
`freeze_v1.json` binds corpus, projections, this protocol and contract source, plus the
pre-scan SDK/lockfile hashes and author-review disclosure. Its digest is posted to #45
before the first observation. Existing frozen files are not overwritten. Any later correction
must be a separately recorded, explicitly post-observation erratum, never a silent relabel.

## Scoring and integrity

Report primary-family TP/FP/TN/FN, positive/negative counts and descriptive precision/recall
per family, profile, representation and language. Undefined ratios are null. ERROR and
incomplete observations remain separate and never count as detections or vanish from
expected denominators. Representation variants and repeated runs do not add independent
examples. Publish counts with rates; no population, comparative or p95/p99 claim is made.

Separately compare desired action, exact primary spans, complete checked text and actual
consumer delivery against frozen expectations. Accepted text alone is passed to the local
recording consumer via `require_text()`; rejected/error text must never be delivered.
Preserve signal-only successes, partial redactions, incidental findings, conservative
false positives, unsupported misses and desired-action mismatches. Compare supported
contract spans/action independently. Contract failures pause acceptance for triage; no
SDK fix or baseline relabelling belongs to this batch.

Six fixed children (three families by two profiles) emit 64 ordered observations each.
Reuse existing sanitized-environment, platform limit and kill/reap helpers, including the
Windows base-interpreter launch. Each child has a 10-second wall budget and bounded 64 KiB
stdout/stderr files; the parent has a 90-second observation budget. Preserve valid prefix
rows and explicit missing denominators after interruption, timeout or protocol failure.
Cleanup runs before temporary-directory deletion. Synchronous scanning has no new SDK
deadline. Available CPU/RSS describe the whole worker including startup/setup and are
diagnostic containment metadata, not per-scan performance measurements.

Reports contain only validated static IDs, codes, offsets, counts, comparisons and runtime/
source provenance. Exclude raw/checked text, passwords, paths, environment and exception
messages. Malformed or payload-bearing worker records fail closed; never copy arbitrary
records into a report. CLI errors are static. A successful runner requires complete samples,
valid/reaped children, exact SDK-to-consumer handoff, zero protocol/privacy/unexpected
errors and all eligible contracts. Desired-outcome misses remain visible without being
silently turned into SDK defects or an all-scenarios pass.

## Deliverables and gates

Retain a new local baseline with actual source/runtime/lockfile digests. Add loader,
projection, scoring, corruption/privacy, deadline/interruption and cleanup regressions,
plus all-cell native CI reproduction. Use bounded case IDs on every platform. Preserve
all historical evidence and SDK source/defaults/dependencies/version. Native Windows CI
for this patch requires later commit/push authorization; local results do not replace it.
Independent case review and the wider #45 benchmark program remain open. No commit, push,
release, competitor comparison, live provider benchmark or detector change is authorized.
