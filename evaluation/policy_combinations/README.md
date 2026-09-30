# Policy combinations and delivery, v1

This separate development corpus addresses
[#29](https://github.com/sahilmathur254/guardtrellis/issues/29) with 34 original,
AI-assisted synthetic fixtures. Authorship used Codex assistance and knowledge of the
current implementation. There has been **no independent, blinded, held-out, or
native-language review**. The examples are English/non-linguistic structured content,
not multilingual coverage evidence. Fixtures are Apache-2.0 licensed; credentials,
contact details, and callback responses are fabricated. No network or model calls run.

The original smoke corpus, Unicode/PII challenge set, and their reports remain separate.
This harness evaluates composed policies and local application delivery behavior; it
does not replace either detection corpus or the resource measurement harness.

```sh
uv run --frozen python evaluation/policy_combinations/run.py \
  --report-dir /tmp/guardtrellis-policy-comparison
```

Use a new output directory for every run. The command refuses to overwrite prior
reports. Review reports before selecting a baseline for version control; exploratory
outputs belong outside the checkout. Corpus and runner changes require a new review
and a new report, not relabelling the old report.

The [recorded local baseline](baseline_0.1.2/REPORT.md) and
[machine-readable results](baseline_0.1.2/results.json) describe source candidate `0.1.2`
on Python 3.12/macOS ARM64. Source, runner, corpus, and lockfile hashes identify the run;
the candidate label does not mean that version is published. It retains 1 false positive,
4 misses, 5 scenario expectation mismatches, and 3 expected injected errors. There were
no unexpected errors, harness failures, or detected privacy failures in that run.

## Scope and authored expectations

| Family | Cases | What is exercised |
| --- | --- | --- |
| Secrets | 8 | Selected classic/fine-grained token and private-key envelope signatures; WARN/REDACT/BLOCK; short benign prefix, contextual lookalike, unsupported password assignment |
| JSON | 6 | Syntax/duplicate keys, schema, plain versus escaped email, schema failure after redaction |
| Ordering | 4 | Rules before/after redaction, multiple text revisions and finding spans, warning followed by block |
| Delivery | 6 | Checked callback input and output, input versus output rejection, benign callback, contiguous versus spaced phone |
| Tools | 7 | Checked parsed arguments, unknown name, duplicate keys, schema failures, secret rejection, escaped email |
| Errors | 3 | Deliberately failing input/tool scanner or callback with payload-bearing exceptions |

Each JSONL row includes a stable ID, dataset version, family, named profile, language,
format, authorship, development use, and scenario label basis. `text` and `response`
are fixture payloads. `expected` holds intended action, acceptance, checked text,
callback inputs, delivered result, and tool-dispatch arguments. Selected ordering
fixtures also expect exact finding spans and revision traces. JSON/tool fixtures
also compare `checked_json_valid`: a separate strict `JSONScanner` validates accepted
checked JSON, and the field is null when no accepted JSON deliverable is present.
This checks syntax and duplicate keys; the profile's final scanner checks its schema.
`privacy_markers` list
synthetic payload fragments which must not appear in diagnostics, reprs, or rejection
messages. JSONL uses ASCII escapes so special characters and serialization differences
are visible in review; decoding the JSONL row once obtains the exact scanner input.

Expectations express the scenario's intent, **not a prediction of scanner behavior**:

- Escaped JSON emails and spaced phone numbers remain positive sensitive-data cases
  even though current raw-text/phone-format coverage misses them.
- A generic password assignment is a deliberately unsupported positive case, without
  claiming that every assignment or passphrase can be detected.
- An explicitly fake token in a teaching example is a benign contextual challenge.
  Its pattern-based rejection can be an FP against that intent while satisfying the
  SDK's documented signature-matching behavior.
- An input block should prevent the callback. An output block occurs after callback
  invocation and should prevent delivery to the caller. These are distinct outcomes.
- ToolGuard validates data; the harness's small synthetic application recorder runs
  only after `require_call()` succeeds, using its returned arguments. This records
  the example application's dispatch boundary; it does not test external tool
  authorization, actual execution, shell safety, or other applications' wiring.
- A schema may accept the original JSON and reject the redacted JSON. The profiles
  intentionally validate again after text edits. Decoded-value traversal remains a
  separate design question in #11; no detector changes accompany this corpus.

The fixed profile registry in `run.py` defines policies, schemas, and synthetic failure
injection explicitly. There is no arbitrary scanner loader or policy DSL. Each case
runs once through synchronous SDK calls; no latency or throughput claims are made.
Inputs and corpus size are bounded. This is trusted development input, not an
untrusted-dataset sandbox or containment benchmark.

## Reports and exit status

`results.json` contains source, runner, corpus, and lockfile SHA-256 digests, runtime
and package versions, per-case actions, acceptance, finding/trace metadata, callback
and dispatch counts, and equality-comparison results. `REPORT.md` summarizes family
counts, actions, observed errors, FP/FN, and every mismatched case. Input, callback,
delivered, expected-output, and tool-argument payloads are not copied into either
report. Public prose/provenance is authored metadata and must also be reviewed for
privacy; arbitrary extra fixture fields are never copied into reports.

A failed diagnostic privacy check suppresses that diagnostic surface. Diagnostics
are checked recursively, including string keys and values. Raw markers and standard
JSON/repr escape forms are checked in repr and exception text in memory, and those
surfaces are never serialized. These checks cover
selected markers and SDK surfaces, not arbitrary leaks from trusted custom code,
application logging, partial-value transformations, or third-party integrations.

For non-error results, any finding counts as a signal. TP/FP/TN/FN use the authored
`expected_signal` label. WARN is detection **with delivery**, not prevention. ERROR
is reported separately from detection, with intentionally injected and unexpected
errors distinguished. Action/delivery mismatches are separate comparisons; a TP does
not prove the expected redaction or delivery outcome occurred. The families mix
different tasks and small selected samples, so no aggregate accuracy claim is made.

**Exit 0 means execution completed without a harness failure, a detected privacy
failure, or an unexpected ERROR. It does not mean every policy expectation passed.**
Known misses, false positives, and delivery/action mismatches stay visible without
making CI enforce a detection score. The command prints this distinction. Invalid
fixtures/options return exit 2; unexpected SDK errors, harness failures, or detected
privacy failures return exit 1 after writing the report. Expected injected ERROR
outcomes remain visible and do not by themselves cause exit 1.

Compare all provenance hashes when evaluating a change. Installed package version
alone does not identify edited source. Fixtures are public development evidence;
larger independently collected corpora, deployment measurements, async combinations,
provider adapters, and downstream application coverage remain future work.

The retained escaped-value misses support the narrow #11 decoded JSON design work.
The spaced-phone miss suggests a demand-led phone-format proposal with paired benign
numeric examples, explicit supported separators and exclusions, and independent
review of relevant formats before expanding detection. The contextual token FP does
not justify weakening default secret blocking; applications may choose explicit
advisory policies for clearly identified teaching/test material. These are follow-up
directions, not detector changes or claims of broader coverage.
