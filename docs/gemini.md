# Gemini callback example

This standalone example connects `Guard.run` to the Gemini Developer API through the
official Google Gen AI Python SDK. The `gemini` extra is optional; the core GuardTrellis
package has no provider SDK dependency. The example is part of the unpublished `0.1.0a2`
candidate, not the `0.1.0a1` artifacts on PyPI.

## Run without credentials

From a source checkout:

```sh
uv sync --frozen --extra gemini --group dev
uv run --frozen --extra gemini python examples/gemini_app.py
uv run --frozen --extra gemini pytest tests/test_gemini_example.py
```

The default command uses the real SDK with `httpx.MockTransport` and makes no network
requests. It remains mocked even when credentials and live opt-in variables exist.
The fabricated input is `Reply with exactly: Contact demo@example.org`; only
`Reply with exactly: Contact [PII]` reaches the SDK. The mocked response contains another
fabricated email so output redaction is exercised too. Only checked `Contact [PII]` is
printed after a JSON report. Mock token counts are fixture values, not real usage.

The reusable callback is `GeminiModel(client)`. Call `make_guard().run(user_text, model)`
and deliver `result.require_text()` only after acceptance. Otherwise retain metadata from
`result.diagnostics()`. The complete script owns the client in a context manager and closes
it on both success and failure. Choose stage policies explicitly in your own application.

## One approved live request

Use a Gemini API key from an approved account and confirm its project's billing tier in
AI Studio. As checked on 2026-09-26, Google lists `gemini-3.5-flash-lite` text input and output
as free of charge on the **Free Tier**, subject to quota. A key inherits its project's
billing tier; the script cannot infer that tier from the key and does not enforce a dollar
budget. Keep a zero-budget test on a Free Tier project. Check current
[pricing](https://ai.google.dev/gemini-api/docs/pricing) and
[billing status](https://ai.google.dev/gemini-api/docs/billing) before running.

Google's [unpaid-service terms](https://ai.google.dev/gemini-api/terms#unpaid-services)
allow submitted content and responses to be used for product improvement, including human
review. Use synthetic data only, not personal, confidential, or application-derived inputs.

Set `GEMINI_API_KEY` privately in the runner's environment. Never paste credentials into
issues, reports, or command arguments. The script does not load `.env` files. After approval,
run once from the reviewed source commit:

```sh
GUARDTRELLIS_GEMINI_LIVE=1 uv run --frozen --extra gemini python examples/gemini_app.py --live
```

The live command first confirms a fabricated GitHub-token signature is blocked with no
callback request, then sends the single fixed prompt above with its email already redacted.
Its request uses:

- `gemini-3.5-flash-lite` at the fixed Gemini Developer API `v1beta` GenerateContent endpoint.
- One candidate and at most 128 output tokens, including thinking tokens; minimal thinking
  effort and no returned thoughts. Minimal thinking does not guarantee zero reasoning tokens.
- Complete text only, no streaming, tools, automatic function calls, files, or cached context.
- One SDK attempt, with retries and HTTP redirects disabled; no automatic model fallback.

Do not repeat an uncertain or failed request automatically. Quota, model access, authentication,
or network failures stop the test. Provider-side processing may already have occurred.
The script explicitly selects the Developer API, regardless of enterprise/Vertex environment
settings. Custom endpoint environment variables cannot override its fixed destination.

Exit 0 means the input-block assertion and one accepted complete response passed. Exit 1
means failure; exit 2 means missing opt-in/key prerequisites. The live report includes UTC
date, script SHA-256, package/Python versions, configured model, SDK request attempts,
output-token cap, numeric usage when supplied, and Guard diagnostics. Missing usage remains
unknown. No key, raw prompt/response, thought signature, provider response ID, account
configuration, or raw exception contents are printed. Record the source commit separately.

## Failure and privacy boundaries

The callback requires one model response with finish reason `STOP`, no prompt/candidate
block signal, and nonblank text. It joins all text parts before output scanning, so a
signature split across parts is still checked. Truncated, filtered, empty, thought, tool,
code, or media output becomes `ERROR`; mixed text/non-text parts are rejected. Opaque thought
signatures are ignored as metadata and never retained in results or reports. This is not
a semantic refusal or factual-quality detector: a refusal expressed as ordinary text is
subject only to the configured scanners.

SDK/provider failures become a generic `callback_error` through `Guard.run`. The 20-second
HTTP timeout bounds network phases/inactivity, not the complete wall-clock duration.
Synchronous callbacks have no Guard execution deadline. Async cancellation cannot terminate
a running worker thread or undo a remote request; see the [async contract](api.md#limits-and-asynchronous-work).

The standalone command suppresses standard Python logging, including SDK/HTTP logging.
Importing it leaves application logging untouched. Review tracing/APM exporters, HTTP hooks,
debugger capture, and wrappers before integrating; these may observe data before checking.
Guard cannot undo provider processing, retention, billing, or callback side effects.

## Verification status

Ordinary tests and CI use mocks, including tests of the live reporting path. They verify
actual HTTP serialization, redaction, zero requests for blocked input, checked complete
output, malformed/unsupported responses, generic failures, and no retry/redirect/tool loop.
Distribution smokes check core installs exclude the SDK, then run all examples with extras.

### Recorded live smoke: 2026-09-26

The maintainer authorized one synthetic request using a privately supplied key for a
Free Tier project. The exact command above passed with the following metadata:

| Evidence | Value |
| --- | --- |
| UTC date | `2026-09-26T12:46:30.274314+00:00` |
| Tested source | [`d722ec2c044f5f84c8033c00b6f60bdd45515340`](https://github.com/sahilmathur254/guardtrellis/commit/d722ec2c044f5f84c8033c00b6f60bdd45515340) |
| Example SHA-256 | `10dbf0f79782f21f4cf61ee6cb7c25fcf6c642fb9280a03f5d38fc1f30605474` |
| Python / GuardTrellis | `3.12.0` / `0.1.0a2` from the source commit above |
| Google Gen AI SDK / httpx | `2.25.0` / `0.28.1` |
| Model / API | `gemini-3.5-flash-lite` / Developer API GenerateContent `v1beta` |
| Generation request attempts | `1`, with retries and redirects disabled |
| Output-token cap | `128` |
| Reported input / output / total tokens | `10` / `5` / `15` |
| Reported thought tokens | Not supplied; not inferred as zero |
| Synthetic secret input | `BLOCK`, zero callback requests |
| Fabricated email input | `REDACT` before the SDK request |
| Complete provider output | `ALLOW` after output checks |
| Overall result / command exit | Accepted, `REDACT` / `0` |
| Standard error | Empty |

The report contained metadata only; no raw response, key, account identifier, or provider
response ID was retained in this record. The Free Tier selection was supplied by the
maintainer; API usage metadata is not an independent billing statement. The example's
code and lockfile identify the tested path even though the candidate remains unpublished.

This evidence supports the live-smoke criterion of
[#8](https://github.com/sahilmathur254/guardtrellis/issues/8). Output redaction/blocking and
failure cases were verified with mocks; the live response needed no output redaction.
This one result does not verify the separate OpenAI/Azure examples, other models, general
detection quality, or production reliability. Future live runs require separate approval.

References: [Google Gen AI SDK](https://googleapis.github.io/python-genai/),
[GenerateContent API](https://ai.google.dev/api/generate-content),
[thinking controls](https://ai.google.dev/gemini-api/docs/generate-content/thinking).
