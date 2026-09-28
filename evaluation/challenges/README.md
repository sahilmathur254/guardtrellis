# Unicode and PII challenges, v1

This is the first scoped addition for [#7](https://github.com/sahilmathur254/guardtrellis/issues/7):
40 original, AI-assisted synthetic **development** fixtures. It is not independent,
held-out, blinded, representative, or reviewed by native speakers. No real contact records,
credentials, external model calls, or private application data were used. The fixtures are
covered by the repository's Apache-2.0 license. The original 72-case corpus and baseline
remain intact.

The [corpus](unicode_pii_v1.jsonl), [recorded report](unicode_pii_v1/REPORT.md), and
[machine-readable results](unicode_pii_v1/results.json) are versioned separately. JSONL
uses ASCII escapes so invisible characters and representation differences are inspectable.
Git attributes preserve LF endings for these fixtures so their hashes survive Windows checkouts.
Decode each JSONL record once to obtain the exact scanner input in its `text` field.

## Scope and labels

| Family | Cases | Coverage |
| --- | --- | --- |
| PII | 24 | ASCII email in English, French, Hindi, Japanese, and Arabic contexts; plus-addressing; contiguous/formatted/fullwidth phones; internationalized and obfuscated email; numeric/code lookalikes; plain/escaped JSON pairs |
| Invisible | 16 | Identifier/terminal controls; legitimate emoji joiners, Persian non-joiners, Arabic bidi isolation, typesetting controls, combining accents, whitespace, variation selectors, Hindi/Japanese prose; plain/escaped JSON pair |

Language tags describe the authored context, not detector language support. `zxx` denotes
non-linguistic emoji. Contact values are fabricated: emails use reserved example/invalid
domains and phone examples use a 555-0123 shape. Multilingual wording and contextual labels
still need independent review. The fixture `source` and `usage` fields disclose authorship
and development use; `label_basis` explains the intended meaning, and `format` names the
specific shape. Each ID is stable within the versioned corpus.

`expected_signal` reflects the **authored scenario**, not a prediction of the implementation:

- A fabricated contact remains a positive case even when its formatting is deliberately
  outside current support. Misses are recorded rather than relabelled as negatives.
- A signed integer in an arithmetic task and an email-shaped parser token are benign
  contextual challenges. A pattern match can be a false positive against that intent
  while still complying with the scanner's documented format-matching contract.
- Legitimate Unicode layout or joining controls are benign in these specified scenarios.
  Their warnings are false positives against scenario intent, not claims of incorrect
  Unicode classification. Removing such characters can damage meaning or presentation.

Three pairs contain valid JSON with identical decoded objects but different literal text.
PII scanners receive the serialized email/phone inputs; the invisible scanner receives the
serialized identifier inputs. The runner does **not** decode their values before scanning.
Fixture tests verify strict JSON validity (including duplicate-key rejection) and pair
equivalence. These are concrete examples for the [structured-value design, #11](https://github.com/sahilmathur254/guardtrellis/issues/11),
not an implementation of recursive decoded-value checking or schema-safe redaction.

## Reproduce and interpret

From the repository root, choose an output directory that does not already exist:

```sh
uv sync --frozen --all-extras --group dev
uv run --frozen python evaluation/run.py \
  --corpus evaluation/challenges/unicode_pii_v1.jsonl \
  --iterations 100 --report-dir /tmp/guardtrellis-unicode-pii-v1-comparison
```

The reviewed baseline uses this same command with
`--report-dir evaluation/challenges/unicode_pii_v1` when that directory was new. The report
records exact corpus, runner, SDK-source, and lockfile digests, package/Python versions,
platform, Unicode database version, 3 warmups, and 100 timed scans per case. Digests identify
the actual inputs and implementation even when the installed SDK version is unchanged.
Timing varies by host; these short inputs are not a performance or capacity benchmark.

Detection uses findings, not action names: WARN still counts as a signal and still permits
delivery. REDACT permits transformed text; BLOCK and ERROR reject. Reports include each
action separately and retain all misses, false positives, and errors. An ERROR is never a
true positive; it is shown separately and excluded from precision/recall/FPR denominators.
The command fails on errors, not merely because a documented challenge is missed. See the
[metric definitions](../README.md#method-and-limits).

The report provides sample counts and confusion matrices for each family and each
family/language combination. Some groups have only one positive or negative example;
undefined ratios are `null`/`n/a`. Neither the aggregate nor a language subgroup establishes
general accuracy. A match does not prove complete redaction, valid structured output,
authorization, or safe downstream execution.

## Extend without erasing history

Add small, attributable batches with stable IDs and explicit expectations. Preserve v1
and its reports. For a revised label or fixture, create a new corpus version and document
the old/new IDs, label, and reason here or in the new version's methodology. No prior
labels were changed in this initial addition. Do not tune detectors and rewrite challenge
labels in the same change. Publish new measurement evidence separately when detectors change.

Independent contributions are welcome; contributors must describe their relationship to
the implementation and whether cases were used during development. Public, collaboratively
edited cases cannot be presented as an independent hidden test. Do not submit personal
records, credentials, private transcripts, or unsupported claims of language coverage.

Long inputs, expensive schemas, and timeout containment have a separate
[resource harness](../../docs/resource_limits.md). Existing unit tests cover overlap and
scanner-order contracts; this first challenge batch measures single-scanner families and
does not claim evaluation of arbitrary policy combinations, secrets, or all JSON/tool behavior.

Primary references for the representation and label rationale:

- [Unicode 17, chapter 23](https://www.unicode.org/versions/Unicode17.0.0/core-spec/chapter-23/):
  layout, joining, bidi controls, and variation selectors can have legitimate uses. The
  actual Python Unicode database used for scanning is recorded in each run.
- [RFC 8259, sections 7 and 8.3](https://www.rfc-editor.org/rfc/rfc8259.html#section-7): JSON
  string escapes and comparison after decoding. The fixture pairs are original examples.
