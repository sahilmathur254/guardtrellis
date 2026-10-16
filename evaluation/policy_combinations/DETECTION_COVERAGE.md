# Detection coverage development batch, v1

This batch starts [#59](https://github.com/sahilmathur254/guardtrellis/issues/59)
under the reproducible-evidence work in
[#45](https://github.com/sahilmathur254/guardtrellis/issues/45). It measures the
escaped-JSON and phone-format proposals before an SDK change. It does not change
scanners, defaults, the shipped decoded-query recipe, or the historical corpora and
reports. The decoded-value design remains a separate, opt-in proposal in
[#50](https://github.com/sahilmathur254/guardtrellis/issues/50).

The [63 fixtures](detection_coverage_v1.jsonl) are original, **AI-assisted authored
synthetic development data**, prepared with knowledge of existing detector
coverage. They have no independent, blinded, held-out, or native-language review.
They are Apache-2.0 licensed. Contact details, credential-shaped strings, and
callback receipts are fabricated; no credentials or real records were collected.
These English/non-linguistic examples are not multilingual evidence or estimates
of real-world prevalence, recall, precision, or production safety.

## Reproduce before and after

Run from the repository root with the locked development dependencies:

```sh
uv run --frozen python evaluation/policy_combinations/run.py \
  --corpus evaluation/policy_combinations/detection_coverage_v1.jsonl \
  --iterations 100 \
  --report-dir /tmp/guardtrellis-detection-coverage-v1-before
```

Use a new directory for every run; the runner refuses to replace existing reports.
Keep exploratory reports outside the checkout. The reviewed initial SDK 0.1.4
baseline is recorded separately in [REPORT.md](coverage_baseline_0.1.4/REPORT.md) and
[results.json](coverage_baseline_0.1.4/results.json); the package label
alone does not identify source. Compare source, runner, corpus, and lockfile hashes
and runtime metadata. Preserve the same corpus and runner when comparing an SDK
implementation. A changed label or profile requires a separately reviewed dataset
version and report, rather than silently rewriting the baseline.

Iterations repeat these selected synchronous local workflows for timing evidence;
they do not create independent samples. There are no model, network, tool-service,
or paid-provider requests. Timing includes the fixed profile's checks and local
recording/recipe overhead; it does not isolate regex latency or predict service
throughput. Machine/runtime differences and the absence of a deadline on
synchronous custom scanner code limit comparisons. This batch does not replace
the existing resource harness, maximum-input tests, or native Windows CI.
The raw query profile constructs its `ToolGuard` per observation, while the shipped
recipe reuses its module-level preflight validator. Their setup costs differ;
these timings must not be used to rank raw versus decoded scanning efficiency.

The report retains misses, false positives, and expectation mismatches. Exit zero
means the bounded evaluation completed without an unexpected SDK/harness error or
a detected diagnostic privacy failure; it does **not** mean all desired protection
passed. Review the per-case comparisons as well as detection signals.

## Coverage and explicit limits

| Group | Cases | Authored intent |
| --- | ---: | --- |
| Existing contiguous phones | 6 | Minimum/maximum documented digit counts, input/output redaction, WARN and BLOCK |
| Proposed ASCII phone formats | 11 | Single spaces, hyphens, balanced parentheses, mixed separators, multiple spans after emoji, complete suffix coverage, checked callback delivery |
| Benign phone lookalikes | 16 | Unsigned/signed integers, SKU, date, documentation IP, decimal price, short/long codes, doubled plus, word boundaries, malformed separators and cross-line ledger rows |
| Deferred phone forms | 6 | NBSP, zero-width separators, fullwidth symbols/digits, national syntax, designated extension, verbal substitution |
| JSON representation comparisons | 24 | Six decoded objects, each in two equivalent representations and two fixed profiles |

`coverage_scope` is `baseline`, `proposed`, `benign`, or `deferred`. It states the
implementation scope, not whether a scenario should be considered sensitive.
Deferred contacts retain positive protection labels so that known limitations stay
visible; the first phone implementation is not required to support those formats.
Phone shapes are not proof of allocation, ownership, a valid country code, or a
person's identity. National-number parsing and semantic intent remain outside the
first slice.

The explicitly labelled signed ledger integer has the same characters as a phone
shape. Its negative scenario label exposes the contextual cost of pattern matching;
it does not imply that a regex should infer arithmetic meaning or that default
phone protection should be weakened. Review this ambiguity separately from
unambiguous numeric/code negatives before selecting acceptance thresholds.

The six added grammar counterparts preserve an unmatched-parenthesis code,
separate ledger rows across a newline, repeated-hyphen code, leading-zero numeric
key, trailing-word identifier and sixteen-digit separated key. They require
ALLOW, unchanged checked callback input and no findings. These authored labels
set boundaries for the proposed grammar; they are not snapshots of detector
behavior or evidence that all benign codes can be distinguished from contacts.

The `+12025550123-4567` fixture labels one 15-digit contact, with no designated
extension. The desired finding and redaction cover the entire span. A prefix match
is a detection signal but still fails the complete-redaction and checked-delivery
comparisons. The separate `ext. 4567` case is explicitly deferred.

## Fixed profiles and paired JSON

`run_pii` uses ordinary `Guard.run` input/output policies. `run_pii_warn` and
`run_pii_block` change only the input PII action; output PII checks retain redaction.
No new detector option is introduced. Each callback records the checked input and
returns its fixed fabricated receipt. WARN intentionally delivers the original
input; input BLOCK prevents callbacks and delivery. Output redaction occurs after
the callback. Findings and exact checked/delivered text are independently authored
expectations, including complete literal spans and Python string offsets after
emoji. The SDK is not used to generate expected labels or replacement text.

The JSON rows use the shipped recipe's `search` schema: exactly one nonempty
`query` string, at most 200 characters, with no additional keys; the serialized
input bound is 4,096 characters and the depth bound is two. Both fixed profiles
check fabricated secrets before the email/phone policy so the representation
comparison does not depend on differing scanner selection:

- `tool_query_pii` applies those scanners directly to serialized JSON through
  `ToolGuard`. This intentionally exposes raw-text representation gaps.
- `decoded_query_pii` calls the existing application `check_query` recipe with an
  explicit `Stage.TOOL` policy of `SecretScanner()` followed by
  `PIIScanner(formats=["email", "phone"])`. It strictly parses, checks the decoded
  value once, constructs a fresh object, serializes it, and validates the schema
  again. This is evaluation wiring of public APIs, not a new SDK decoded-value API.

The six objects contain an email, contiguous phone, proposed formatted phone,
emoji plus two contact spans, a nonfunctional secret signature, or a benign literal
escape template. For each object, `pair_id` joins four rows: raw/decoded profiles
and plain/escaped representations. Decoding the two representations once produces
the same object. Accepted variants must dispatch the same completely checked
dictionary. The literal template contains an actual backslash followed by
`u0040`; a second recursive decode would incorrectly turn it into an email. Keys,
nested traversal, embedded encodings, and automatic Unicode normalization are not
covered by this slice.

The decoded recipe's final `ToolResult.action` describes its newly serialized
schema check: it can be ALLOW after the query policy returned REDACT. Separate
`decoded_action` and `decoded_findings` comparisons retain that earlier result.
Decoded offsets refer to the query string, and raw profile offsets refer to the
serialized text. They are never presented as interchangeable wire offsets.
The secret pair expects BLOCK before dispatch. Invalid JSON, duplicate decoded
keys, surrogate/postcondition failures, depth/input limits, and schema failures are
covered by existing recipe/SDK tests; those rejection contracts are not newly
inferred from valid-object pairs here.

## Inspectable evidence and next gate

Rows include stable IDs, provenance, development use, language, format, label basis,
scope and pair IDs. The mandatory expectations compare action, acceptance, checked
text, callback input, delivered result and dispatch arguments; selected metadata
also checks exact findings, decoded-stage action and JSON validity. A TP alone
cannot establish complete redaction or safe delivery.

Reports omit fixture text, callback/delivered payloads and dispatch values. Each
fixture declares synthetic privacy markers of at least eight characters. Escaped
JSON positives include both decoded canaries and the exact raw escaped sensitive
fragments; full decoded-query markers are retained. The
harness additionally checks complete original input/response strings of 8–10,000
characters, retaining their original wire spelling. It checks selected
diagnostic/repr/rejection surfaces against these markers;
this is neither exhaustive leakage detection nor a guarantee about application
logging. Authored public prose and metadata still require review.

Before SDK implementation, review the baseline's per-case gaps and the proposed
ASCII grammar, including ambiguous signed-integer tradeoffs. Then evaluate each
implementation independently against unchanged negatives, action semantics,
complete spans and checked delivery, plus repository checks and native Windows
CI. Later detection work should use independently reviewed data and application
usefulness measurements; this small authored batch cannot substitute for them.
