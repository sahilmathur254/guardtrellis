# OpenAI callback example

This source example connects `Guard.run` to the OpenAI Responses API using the optional
OpenAI Python SDK. It uses the same callback for a credential-free HTTP mock and an
explicitly opted-in live smoke. The GuardTrellis core has no provider dependency.

The example and `openai` extra are **unreleased source additions**; they are not included
in the published `0.1.0a1` artifacts. Clone the repository as described in the
[README](../README.md#examples-and-development), then run:

```sh
uv sync --frozen --extra openai --group dev
uv run --frozen --extra openai python examples/openai_app.py
uv run --frozen --extra openai pytest tests/test_openai_example.py
```

Alternatively, install `'.[openai]'` from the checkout into an activated virtual environment.
Examples are source scripts, not installed console commands.

## Default: no provider calls

The default command uses the real SDK with `httpx.MockTransport`. It does not open a
network connection or require credentials. It stays mocked even if `OPENAI_API_KEY` and
the live opt-in environment variable are present, unless `--live` is also passed.

The fabricated input is `Reply with exactly: Contact demo@example.org`. Only
`Reply with exactly: Contact [PII]` crosses the callback boundary. The HTTP mock returns
another fabricated email so the example also demonstrates output redaction, printing
`Contact [PII]` only after checking. The JSON report says `"mode": "mock"`; its token
counts are fabricated fixture values, not usage evidence.

The reusable boundary is:

```python
from examples.openai_app import OpenAIModel, make_guard

# Own a configured OpenAI client in your application; see make_client in the example.
model = OpenAIModel(client)
result = make_guard().run(user_text, model)
if result.accepted:
    deliver(result.require_text())  # Use the checked text, not a raw SDK response.
else:
    record_metadata(result.diagnostics())
```

`client`, `user_text`, `deliver`, and `record_metadata` above are application-owned.
The runnable script provides a complete demonstration. In an application, choose policies
appropriate for each stage and configure logging before invoking the callback.

## Explicit live smoke

A maintainer must approve the account, destination, and spending before the live smoke.
Set `OPENAI_API_KEY` privately in the runner's environment using your usual secret manager
or private shell setup; never paste it into an issue, chat, command argument, or report.
The script does not load `.env` files or reuse Codex/ChatGPT credentials.

After approval, run **once** from the checked source commit:

```sh
GUARDTRELLIS_OPENAI_LIVE=1 uv run --frozen --extra openai python examples/openai_app.py --live
```

The live path first confirms a fabricated GitHub-token signature is blocked without a
callback request. It then sends the fixed prompt above, with its email already redacted,
to `https://api.openai.com/v1/responses`. It makes at most **one generation request**:

- Model: `gpt-5.6-luna`, reasoning effort `none`, default service tier.
- Maximum output: 128 tokens; fixed short text input, no files or additional context.
- No tools, streaming, background work, response storage, automatic retries, or redirects.
- No CLI model/prompt override or automatic fallback to another model.

The model's published standard rates on 2026-09-25 are $0.20 per million input tokens and
$1.20 per million output tokens; cache writes have a 1.25x input rate. Even conservatively
allowing 1,000 input tokens plus 128 output tokens gives less than $0.001 in token charges.
This is an estimate at the cited rates, not an enforced dollar budget or a promise about
account-specific charges. The command bounds requests and generated tokens. Confirm
[current model pricing and access](https://developers.openai.com/api/docs/models/gpt-5.6-luna)
before approving; a failed/uncertain request must not be automatically repeated.

Exit status 0 means the input-block assertion and one accepted, checked complete response
passed. Status 1 means the smoke failed; status 2 means an opt-in/key prerequisite is
missing. Model access, billing, networking, and provider behavior can prevent live success.

The live command prints only JSON metadata: UTC date, Python/package versions, configured
model, request attempts, output-token cap, token usage if available, and Guard diagnostics.
It prints no prompts, response contents, credentials, raw errors, or request IDs. Record the
exact source commit separately so an unreleased checkout is not mistaken for the published
package just because their version strings currently match.

## Failure, logging, and side-effect boundaries

The callback requires a `completed` response with complete text messages. Refusals (including
mixed text/refusal content), empty text, incomplete responses, and unsupported output items
produce an output `ERROR`; they cannot accidentally become an accepted empty string through
the SDK's `output_text` convenience property. The SDK joins all text blocks before Guard
scans the complete output. There is no partial response delivery or tool execution.

Provider connection, authentication, rate-limit, and timeout failures propagate to
`Guard.run`, which produces a generic `callback_error` without exception contents.
`max_retries=0` prevents the SDK from retrying failed requests. The client is closed by
a context manager, including on failure.

The SDK/HTTP timeout uses 5-second connect, write, and connection-pool timeouts and a
20-second read timeout. These bound network phases/inactivity, not total wall-clock
execution. `Guard.run` has no execution deadline. Using this synchronous callback with
`Guard.arun` moves it into a thread; Guard's async wait/cancellation does not terminate that
thread or cancel already accepted remote work. Configure provider timeouts and application
admission limits for your workload; see the [async contract](api.md#limits-and-asynchronous-work).

The standalone command suppresses Python standard logging for its process, including SDK
and HTTP debug logging. It installs no tracing integration. Importing the example leaves
application logging untouched: review `OPENAI_LOG`, HTTP event hooks, tracing/APM exporters,
debugger capture, and any existing wrappers before integrating. They may record data before
Guard checks it. Do not print SDK exceptions or raw responses. Suppressing standard logging
does not disable arbitrary instrumentation or erase data from memory.

Accepted input is still sent to OpenAI, and rejected output was already generated remotely.
Blocking, redaction, timeouts, and cancellation cannot undo provider processing, billing,
retention, or callback side effects. `store=False` opts out of stored response state; it
does not establish Zero Data Retention. Review OpenAI's
[data controls](https://developers.openai.com/api/docs/guides/your-data) for the account in use.
This example uses a fixed official API endpoint; `OPENAI_BASE_URL` does not override it.
It does not validate Azure OpenAI or other compatible endpoints.

## Verification and live evidence

Normal CI always uses mocks, including the test of the live command's reporting path.
Tests verify the actual serialized request, blocked input, complete-output redaction/blocking,
failure privacy, no retry/redirect, explicit opt-in, and metadata-only live reporting.
Wheel and source-distribution smokes verify the SDK is absent from core installs, then run
the mocked example with extras against each installed artifact.

**Live verification is pending.** No mocked result is evidence of a successful provider call.
After an approved live run, record the maintainer approval, UTC date, exact commit, package
versions, model, request count, outcome, and token usage from the metadata report in
[#8](https://github.com/sahilmathur254/guardtrellis/issues/8). The only payloads are the
fabricated prompt and synthetic blocked signature documented above. Do not close #8 until
that evidence is present. One live smoke establishes that specific integration path, not
general detection quality, production readiness, or model-output reliability.

Official references: [OpenAI Python SDK setup](https://developers.openai.com/api/docs/libraries),
[Responses API](https://developers.openai.com/api/reference/resources/responses/methods/create).
