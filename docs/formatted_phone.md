# Opt-in formatted-phone detection

Released in [`0.1.6`](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.6),
this explicit `PIIScanner` mode checks a bounded set of international phone shapes.
Existing callers keep `phone_mode="contiguous"` by default.

```python
from guardtrellis import Guard, PIIScanner

guard = Guard(
    input_scanners=[PIIScanner(formats=["phone"], phone_mode="formatted")],
)
result = guard.scan("Call +1 (202) 555-0123.")
assert result.require_text() == "Call [PII]."
assert result.findings[0].code == "pii_phone"
```

`formats` still selects which detectors run. Setting `phone_mode="formatted"` with
`formats=["email"]` does not enable phone detection. The only mode values are
`"contiguous"` and `"formatted"`; an unsupported value raises `ValueError` at
construction. The option does not change email or SSN matching.

## Supported grammar

Formatted mode examines the original text, without normalization or decoding:

- Start with literal ASCII `+`, followed by a digit from `1` through `9`.
- Contain 8–15 ASCII digits in total, including the initial group.
- Join nonempty digit groups with exactly one ASCII space or hyphen. A candidate
  may use both separator types.
- Optionally enclose one digits-only group after the initial group in balanced
  parentheses. Use a separator before it and, when another group follows, after it.
- Keep the candidate separate from adjacent identifier characters or another plus
  sign. Ordinary surrounding prose punctuation is not part of the phone span. An
  extra closing `)` is treated as a prose wrapper only when `(` immediately precedes
  the initial `+`; an unmatched closing `)` rejects the candidate as a match.

| Input | Formatted-mode checked text with REDACT |
| --- | --- |
| `+12025550123` | `[PII]` |
| `+1 202 555 0123` | `[PII]` |
| `+1 (202) 555-0123` | `[PII]` |
| `+12025550 (123)` | `[PII]`; a parenthesized group may end the candidate |
| `+12025550123-4567` | `[PII]` |
| `(+12025550123).` | `([PII]).` |
| `+1(202)5550123` | Unchanged; separators around the parenthesized group are required |
| `+1  202 555 0123` | Unchanged; repeated spaces between digit groups are invalid |
| `+12025550123.4567` | Unchanged; dotted numeric continuation is unsupported |
| `+1202555012345678` | Unchanged; exceeds 15 digits |

For the ASCII digit/group syntax above, malformed separators or parentheses and
excessive digit counts prevent a shorter contiguous-prefix match in formatted mode.
Those candidates produce no phone finding, rather than automatically blocking the
request. A phone-only policy therefore allows these unmatched inputs.
Repeated spaces before ordinary prose end the candidate; repeated spaces before
another numeric group make that candidate invalid. Trailing sentence punctuation
is retained, while a dot followed by digits is treated as a numeric continuation.

This is shape detection. It does not validate country codes, allocation, reachability,
ownership, identity, or whether the digits denote a telephone number. A signed ledger
integer with the same characters as a supported phone shape is still ambiguous and
can be a false positive.

National numbers, extensions, dotted phone formats, Unicode digits, NBSP/zero-width
separators, verbal obfuscation, and country-specific validation remain outside this
scope. Extensions and NBSP/zero-width separators may end a recognized span and leave
a suffix untouched: `+12025550123 ext 45` becomes `[PII] ext 45`. The no-prefix-fallback
rule above does not promise complete handling of these excluded forms. A REDACT
outcome therefore does not establish that an entire unsupported form was protected.
Use separate application validation when a field must contain a valid phone number.

## Actions, offsets, and delivery

Both modes use finding code `pii_phone` and the existing `[PII]` replacement. Choose
`Action.WARN`, `Action.REDACT` (the default), or `Action.BLOCK` as before. WARN preserves
the input; REDACT replaces the complete supported span; BLOCK exposes no deliverable
text and prevents a `Guard.run` input callback from running.

Offsets remain half-open Python character indices into that scanner's input revision,
including spaces, hyphens, and parentheses inside the matched span. No normalized
offset mapping is introduced. Overlapping matches retain their individual findings
and share a merged redaction, following the existing [API contract](api.md#custom-scanners).
The mode works at any explicitly configured stage. Consume only `require_text()` or
`require_call()` results at the next application boundary.

Use `Guard` to apply the existing maximum of 100,000 characters per stage and 256
findings/edits per scanner. Exceeding those limits yields ERROR without usable output.
Synchronous execution still has no hard deadline. The implementation uses the standard
library and adds no dependency, provider call, or configuration layer.

## Escaped JSON and application recipes

This option does not decode JSON text. Tool argument text scanners still inspect the
serialized representation. The [decoded-query recipe](decoded_query.md) already has a
trusted `query_guard` hook; an application can explicitly select the formatted mode
when checking its one bounded decoded field:

```python
from examples.decoded_query import check_query
from guardtrellis import Guard, PIIScanner, SecretScanner

query_policy = Guard(
    tool_scanners=[
        SecretScanner(),
        PIIScanner(formats=["email", "phone"], phone_mode="formatted"),
    ],
    max_chars=200,
)
plain = '{"query":"Call +1 (202) 555-0123"}'
escaped = r'{"query":"Call \u002b1 (202) 555\u002d0123"}'
for arguments in (plain, escaped):
    final = check_query("search", arguments, query_guard=query_policy)
    assert final.require_call() == ("search", {"query": "Call [PII]"})
```

Run this from a source checkout; examples are application-owned recipes rather than
installed package APIs. The recipe decodes one JSON layer, checks the decoded query,
reserializes a fresh object, and validates it again. Host authorization is still required
before executing the checked pair. The fixed-policy [contact helper](decoded_contact.md)
keeps its existing contiguous-phone policy; upgrading the package does not opt it
or any existing caller into formatted detection.

## Evaluation and compatibility

The separate [formatted-phone comparison](../evaluation/formatted_phone/README.md)
compares default and opt-in outcomes against versioned synthetic development cases.
Historical fixtures and reports remain unchanged. The comparison includes supported
formats, benign lookalikes, explicit exclusions, exact delivered text and spans, and
plain/escaped decoded handling. These cases establish observed behavior only; they
are not an independent estimate of real-world accuracy.

The additive optional argument shipped in `0.1.6` under the
[0.1.x compatibility policy](compatibility.md#changes-within-01x). Existing default
behavior is preserved, including legacy partial-prefix matches on some formatted
inputs. Applications adopting formatted mode should review both complete redaction
of supported forms and the no-finding behavior of malformed candidates against
their own inputs. The [control-coverage matrix](coverage.md) links these limits to
source, regression cases and retained evaluation evidence.
