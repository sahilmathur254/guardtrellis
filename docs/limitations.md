# Limitations and trust boundaries

GuardTrellis is an alpha library running **inside your application process**. Its checks
operate on text you explicitly pass in. It is not a firewall, agent runtime, authorization
service, compliance certification, prompt-injection solution, factuality checker, or
sandbox. This is an independent Python implementation; no Dart implementation was copied.

The server-to-provider boundary is the relevant boundary when used in a Python backend.
Client input has already left the end user's device before server-side redaction. Input
validation cannot undo earlier network transfer, logging, tracing, or storage. Output
checks run before Guard returns a complete response, but cannot undo side effects inside
the callback or data captured by provider instrumentation. There is no streaming API.

## Detector coverage

- PII: pragmatic ASCII email addresses with a dotted domain, contiguous international
  `+` phone numbers containing 8–15 digits, and hyphenated US SSN shapes (excluding invalid
  area/group/serial zero ranges and 666/9xx area ranges). No name/address recognition,
  ID issuance checks, internationalized email, obfuscation handling, national phone
  formatting, or general international identifier coverage. Email-shaped code and
  non-phone numeric identifiers can produce false positives. Strings are not normalized.
- Secrets: classic GitHub `gh[pousr]_` plus 36 alphanumerics; `github_pat_` plus 82
  alphanumeric/underscore characters; AWS `AKIA`/`ASIA` plus 16 uppercase alphanumerics;
  and PEM private-key envelopes (generic, RSA, EC, DSA, OpenSSH, encrypted). These are
  signatures, not live-credential verification. An AWS access-key ID is an identifier,
  not the secret component, but it is deliberately flagged. Unknown vendor formats,
  arbitrary passwords, generic bearer tokens, encodings, and changed token lengths can
  be missed. Incomplete PEM envelopes cover the rest of the string when redacted.
- Invisible characters: Unicode categories Cc/Cf, excluding tab, CR, and LF. Default
  WARN permits content. Joiners, non-joiners, and bidirectional controls can serve
  legitimate languages or emoji. REDACT removes them and can damage meaning or display.
  Homoglyphs, combining marks, and variation selectors are not comprehensively detected.
- Literal policies: substring matching, not semantic interpretation or word boundaries.
  Optional case-insensitivity folds ASCII A–Z only, preserving offsets. Obfuscation,
  Unicode confusables, and paraphrases can evade a policy. Arbitrary regex is unsupported.
- JSON/schema: structural validity does not establish factual correctness, safe URLs,
  safe commands, or harmless values. Schemas are trusted developer configuration.
  Complex schemas can still consume substantial CPU despite regex restrictions and
  text/depth limits. Use appropriate `additionalProperties`, lengths, enums, and numeric
  constraints; an empty schema deliberately accepts all structurally valid data.
- Tool validation: names and argument structure complement execution-time identity,
  permissions, resource constraints, and approvals. An allowed, schema-valid tool call
  can still be dangerous or unauthorized. GuardTrellis executes no tools.

PII, secret, and literal checks do not decode quoted JSON escape sequences: they inspect
the actual characters passed to them. Tool argument text scanners likewise see JSON text.
For semantic PII checks on structured values, decode and validate each relevant value
before reserializing and performing the final tool/schema check. Do not assume scanning
serialized JSON catches escaped or encoded sensitive values.

Ordering matters: redaction can obscure signals that a later scanner would have seen.
Put blocking policies before redactors when they must see the original content. WARN is
a deliberate allow-with-signal policy. Unconfigured stages permit bounded content.
Applications must inspect result actions and consume checked text/arguments, not reuse
the original payload. No probabilistic safety score or automatic PII rehydration is offered.

## Privacy and operations

Built-ins make no network calls, emit no logs, store no request history, and omit text and
replacement strings from reprs. `diagnostics()` is the supported metadata-only logging
interface. The normal text/argument properties intentionally contain deliverable data;
`dataclasses.asdict`, arbitrary serialization, debugger locals, memory dumps, and application
logs can expose it. Object repr suppression is not encryption or secure memory erasure.
Custom scanner names/codes must be static metadata, never raw content. Offsets/lengths can
themselves reveal information. Do not log diagnostics where even such metadata is sensitive.

Custom scanners and callbacks are trusted code and may send data elsewhere. Libraries
cannot prevent their side effects. Framework logging can precede validation. The FastAPI
example hides request-validation echoes but is not a hardened service: add authentication,
request-body limits at ingress, concurrency controls, and appropriate deployment safeguards.
The LangGraph example validates before initial graph state and before generated output is
returned to state; it uses no checkpointer and disables tracing during its demo invocation.
Moving checks into a graph after sensitive state is captured would be too late.
The optional [OpenAI](openai.md), [Azure](azure_openai.md), and [Gemini](gemini.md) examples
default to HTTP mocks.
Their live paths send only checked input to the provider and check complete output,
with explicit timeouts and no
automatic retries; provider processing/billing and external instrumentation remain outside
Guard's control. One [Gemini live smoke](gemini.md#recorded-live-smoke-2026-09-26) passed;
OpenAI and Azure remain mock-verified only. Evidence for one API/model does not verify others.

See [async execution limitations](api.md#limits-and-asynchronous-work) and the retained
failures in the [synthetic evaluation](../evaluation/REPORT.md). Local tests and synthetic
measurements establish observed behavior only. Independent evaluation, production workload
testing, broader format coverage, and additional live integrations remain future work.
