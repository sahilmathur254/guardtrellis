# Azure OpenAI callback example

This standalone source example uses `AzureOpenAI` from the optional OpenAI Python SDK
with `Guard.run`. It calls Chat Completions and checks complete text before delivery.
No provider SDK is added to the GuardTrellis core. This example is part of the unpublished
`0.1.0a2` candidate, not the `0.1.0a1` artifacts on PyPI.

## Run without credentials

From the source checkout:

```sh
uv sync --frozen --extra openai --group dev
uv run --frozen --extra openai python examples/azure_openai_app.py
uv run --frozen --extra openai pytest tests/test_azure_openai_example.py
```

The default command uses the real SDK with `httpx.MockTransport`, without socket access.
It remains mocked even when live configuration exists in the environment. It first blocks
a fabricated secret signature without invoking the callback, then redacts the email in
`Reply with exactly: Contact demo@example.org` before the HTTP request. The mock returns
another fabricated email; only the checked `Contact [PII]` is printed. Reports say
`"mode": "mock"`; their usage counts are fixture values, not real billing evidence.

## Opt into one live request

A maintainer must approve the account, destination, and spending. Supply these four
variables privately in the runner's environment; the script does not load `.env` files:

| Variable | Value |
| --- | --- |
| `AZURE_OPENAI_API_KEY` | Key for the approved Azure resource |
| `AZURE_OPENAI_ENDPOINT` | Resource root such as `https://YOUR-RESOURCE.openai.azure.com` |
| `OPENAI_API_VERSION` | API version supported by that resource and deployment |
| `AZURE_OPENAI_DEPLOYMENT` | Name of a deployment supporting the request described below |

This example supports API-key authentication and HTTPS public-cloud Azure OpenAI resource
roots only. Paths, query strings, embedded credentials, proxy/gateway endpoints, and other
cloud domains are rejected. Deployment names must be 1–128 letters, digits, dots, hyphens,
or underscores and begin with a letter or digit. Unset `AZURE_OPENAI_AD_TOKEN`: the SDK
otherwise prefers it to the explicitly supplied API key. Do not put configuration values
in issues, reports, command arguments, or version control.

Choose a deployment supporting `max_completion_tokens=128`, `reasoning_effort="none"`,
`n=1`, `store=False`, and `stream=False`. Support depends on the deployed model and API
version; this example does not infer compatibility from a deployment name. An unsupported
combination fails without a retry or automatic fallback. No tools are configured.

After approval, run **once** from the reviewed source commit:

```sh
GUARDTRELLIS_AZURE_OPENAI_LIVE=1 uv run --frozen --extra openai python examples/azure_openai_app.py --live
```

The command repeats the input-block assertion locally, then makes at most **one generation
request** with the fixed, redacted prompt and a 128-token completion cap (including any
reasoning tokens). It disables SDK retries and HTTP redirects. Check the approved Azure
deployment's pricing before running: the request/token limits are not a dollar budget.
Do not automatically repeat a failed or uncertain request.

Exit status 0 means the blocked-input assertion and one accepted complete response passed;
1 means failure; 2 means configuration/opt-in prerequisites failed. The live command prints
only UTC date, script SHA-256, runtime/package versions, request count, token cap, usage if
available, and Guard diagnostics. It excludes endpoints, deployment names, provider response
IDs, raw prompts/responses/errors, and credentials. Record the exact source commit separately.

## Integration and failure boundaries

Use `AzureOpenAIModel(client, deployment=deployment)` as the callback to
`make_guard().run(user_text, model)`. Construct and close the client in your application.
Deliver only `result.require_text()` after acceptance, or retain `result.diagnostics()`.
The script provides the complete runnable wiring; application policies remain explicit.

The callback requires exactly one assistant text choice with `finish_reason="stop"`.
Empty text, truncation, content filtering, refusals (including mixed text/refusal), tool or
function calls, audio, and annotated content become `ERROR`. Provider failures become a
generic `callback_error`; rejected content and SDK exception payloads are not delivered.
There is no streaming delivery or tool execution.

Network timeouts are 5 seconds for connect/write/pool and 20 seconds for read inactivity,
not a total execution deadline. `Guard.run` cannot interrupt the synchronous callback;
async cancellation cannot terminate a worker thread or undo remote processing. The command
suppresses standard Python logging, including SDK/HTTP debug logs; importing the module
leaves application logging untouched. Application tracing, custom event hooks, debugger
capture, provider processing/retention, and billing remain outside Guard's control.
`store=False` is not a claim about all Azure data retention. Review the resource's policies.
See the [general callback boundaries](openai.md#failure-logging-and-side-effect-boundaries).

## Verification status

Tests use the SDK's actual HTTP serialization with mocked responses. They cover input
blocking/redaction, output redaction/blocking, invalid or unsupported responses, provider
failures, no retries/redirects, opt-in/configuration checks, and report privacy. CI and
wheel/sdist installation smokes run the default mock command only.

**Live verification is pending.** A mocked test of the live reporting path is not a real
provider call. An approved run must record its date, exact commit, script digest, versions,
request/token counts, and outcome before being cited as live evidence in
[#8](https://github.com/sahilmathur254/guardtrellis/issues/8). Keep account configuration and
raw provider output private. Azure Chat Completions and direct OpenAI Responses are distinct
paths: evidence for one does not verify the other, other models, or production reliability.

SDK reference: [official Python SDK setup](https://developers.openai.com/api/docs/libraries).
The example's request fields follow the installed OpenAI SDK's `AzureOpenAI` client and
Chat Completions types; consult your Azure deployment's documentation for compatibility.
