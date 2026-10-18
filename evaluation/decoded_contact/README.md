# Explicit decoded contact comparison, v1

This is the small application-helper batch for
[#62](https://github.com/sahilmathur254/guardtrellis/issues/62), following the
recipe-first decision in [#50](https://github.com/sahilmathur254/guardtrellis/issues/50).
It adds no SDK detector or shared structured-data API. Historical corpora and
reports remain unchanged.

The 24 original fixtures are **AI-assisted authored synthetic development data**
with knowledge of current behavior, Apache-2.0 licensed. Eight contact meanings
each have a plain and a fully escaped JSON representation; eight additional rows
exercise rejection. Their labels and complete expected checked dictionaries are
authored in [contact_workflow_v1.jsonl](contact_workflow_v1.jsonl), not generated
from detector results. They use fabricated contact/credential shapes. There is no
blinded, held-out, independent, multilingual or production accuracy evidence here.

Run from the repository root with the locked development dependencies:

```sh
uv run --frozen python evaluation/decoded_contact/run.py \
  --report-dir /tmp/guardtrellis-decoded-contact-v1
```

Choose a fresh directory for every run; existing reports are never replaced. The
runner writes `REPORT.md` and `results.json`, recording SDK/runtime versions and
source, helper, recipe, corpus and lockfile hashes. No network, paid provider,
host tool, deployment or publication is invoked. There is no timing experiment.
The reviewed initial candidate run is preserved in
[baseline_0.1.5/REPORT.md](baseline_0.1.5/REPORT.md) and its
[results.json](baseline_0.1.5/results.json). Its 24 observations per profile produce
15 exact outcome matches for raw serialized checks and 22 for each decoded
workflow, with zero unexpected errors or detected privacy failures. Both decoded
workflows retain the two formatted-phone mismatches. The contact helper makes no
accuracy-gain claim over the existing recipe on this corpus; its proposed benefit
is the explicit two-field contract, ordering, work bounds and finding provenance.

## Fixed workflows and comparison limits

All three profiles receive the same `contact` name and serialized object with
exactly two required strings, `email` and `phone`. The common schema has length
bounds of 254 and 64 characters, a 4,096-character JSON bound, depth two and no
additional properties. These names and bounds do not validate real email/phone
syntax or ownership. The selected valid fields are shorter than the existing
query recipe's separate 200-character limit.

| Profile | Fixed application wiring |
| --- | --- |
| `raw_serialized` | `ToolGuard` scans serialized JSON with secrets, then email/phone PII. |
| `per_field_query_recipe` | Strict common contact preflight, then the existing `decoded_query.check_query` recipe once for each named field through its `query` envelope, with an explicit TOOL secret/email/phone policy; construct and revalidate a fresh contact dictionary. |
| `contact_helper` | New explicit `decoded_contact.check_contact` application helper; secrets across both fields precede all PII checks, bounded findings/work, fresh final schema-checked object. |

The per-field recipe comparison is evaluation wiring using public APIs, not a
previously shipped contact workflow or a general traversal implementation. Its
per-field scanner order and 200-character limit differ from the contact helper.
It resets scanner indexes and revisions in each field call. The helper records
opaque field/pass provenance. Finding counts across profiles are descriptive,
not interchangeable detector or coordinate-space evidence: raw findings refer to
serialized JSON, decoded findings to individual string revisions. Rejected helper
calls expose no result action; their reports retain `null` rather than inventing
a BLOCK action or findings.

`protection_action` retains observed decoded REDACT even when the freshly
serialized final schema check returns ALLOW. The harness calls `require_call()`
and compares its exact checked name and dictionary in memory; `checked_call_count`
counts these handoffs, not real dispatch. Authorization, callback execution and
zero-dispatch failures are covered by the helper regression tests separately.

## Coverage and honest failure accounting

The paired meanings include email, contiguous phone, contacts in both fields,
email after emoji, secret shapes in either field, formatted phone and a benign
literal backslash escape. A single JSON decode must preserve the literal
`backslash + u0040` string. Recursive decoding would change its meaning.
Rejections cover duplicate decoded keys, extra/missing fields, wrong types,
unknown tool names, malformed JSON, an unpaired surrogate and an oversized field.

The formatted-phone pair retains desired complete redaction with `known_limit`
labels. Existing detector misses remain outcome mismatches; those improvements
belong to [#60](https://github.com/sahilmathur254/guardtrellis/issues/60). Equality
between two unprotected representations does not count as successful protection.
The raw profile's surrogate acceptance likewise remains a desired-outcome failure.

The report stores IDs, action/count metadata and equality/mismatch booleans. It
omits input, expected/observed checked values and exception text. Before reporting,
the harness checks diagnostics, repr and rejection surfaces for bounded exact
wire input, decoded values and actual quoted wire fragments, including their repr
and JSON spellings. These synthetic canaries are regression evidence, not an
exhaustive privacy guarantee or permission to log payload-bearing result fields.

Exit zero means no unexpected execution error or detected privacy-canary failure.
It does **not** mean every desired protection expectation passed. Review exact
outcome mismatches, retained limitations and paired-delivery equality together.
The unchanged 63-case historical detection corpus remains a separate comparison;
this contact batch does not replace it or native Windows CI.
