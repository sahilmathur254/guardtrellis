# GuardTrellis

A small Python SDK for local checks around model inputs, complete outputs, retrieved text,
and proposed tool calls. Policies are explicit, composable, and independent of model providers.

**Published alpha: 0.1.0a1.** APIs may change before a stable release.
Supported Python: 3.11–3.14. Apache-2.0 licensed. Available on
[PyPI](https://pypi.org/project/guardtrellis/0.1.0a1/), with
[release notes and verified artifacts](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.0a1).
This source checkout prepares `0.1.0a2`; that candidate is not yet published.

Install the exact alpha version in an activated virtual environment:

```sh
python -m pip install 'guardtrellis==0.1.0a1'
```

The explicit version opts into this prerelease. Optional integrations are available with
`'guardtrellis[fastapi]==0.1.0a1'` or `'guardtrellis[langgraph]==0.1.0a1'`.

```python
from guardtrellis import Guard, PIIScanner, SecretScanner

guard = Guard(
    input_scanners=[SecretScanner(), PIIScanner()],
    output_scanners=[SecretScanner(), PIIScanner()],
)

# Deterministic local demonstration, not a real model integration.
result = guard.run("Contact casey@example.org", lambda text: f"Received: {text}")
print(result.require_text())  # Received: Contact [PII]
print(result.diagnostics())  # Metadata only; no matched strings or prompt text.
```

`run` calls your callback only after accepted input checks, then checks the **complete**
returned string before exposing it. Use `await guard.arun(text, callback)` for async work;
both sync and async callbacks work there. Provider SDKs are not required by the core.

| Check | Default | Scope |
| --- | --- | --- |
| `PIIScanner` | redact | ASCII email, contiguous international phone, US SSN shapes |
| `SecretScanner` | block | Selected GitHub tokens, AWS access-key IDs, PEM private keys |
| `InvisibleScanner` | warn | Unicode control/format characters except tab and newlines |
| `LiteralScanner([...])` | block | Configured literal substrings; optional ASCII case folding |
| `JSONScanner(schema)` | block invalid data | Strict JSON and constrained Draft 2020-12 schemas |
| `ToolGuard({name: schema})` | block invalid calls | Exact tool names and object argument schemas |

No scanners are installed implicitly: `Guard()` permits bounded text. Choose policies for each
boundary. Heuristic matches are signals, not probabilities or comprehensive protection.

```python
from guardtrellis import Action, Guard, JSONScanner, LiteralScanner, Stage, ToolGuard

guard = Guard(
    retrieval_scanners=[LiteralScanner(["confidential"], action=Action.BLOCK)],
    output_scanners=[JSONScanner({"type": "object", "required": ["answer"]})],
)
retrieval = guard.scan("A public reference", stage=Stage.RETRIEVAL)
# In async code: await guard.ascan("A public reference", stage=Stage.RETRIEVAL)

tools = ToolGuard(
    {
        "search": {
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 200}},
            "required": ["query"],
            "additionalProperties": False,
        },
    }
)
call = tools.validate("search", '{"query":"public documentation"}')
name, arguments = call.require_call()
# Your application must still enforce identity, permissions, and execution limits.
```

`ALLOW`, `WARN`, and `REDACT` expose `result.text`; `BLOCK` and `ERROR` expose `None`.
`require_text()` / `require_call()` raise a payload-free `Rejected` exception on rejection.
WARN deliberately permits delivery. Scanner/callback exceptions are errors, never successful
checks. The first block/error stops its stage. Input rejection prevents the callback entirely.

Stages have separate scanner lists: `input_scanners`, `output_scanners`, `retrieval_scanners`,
and `tool_scanners`. Use `scan(text, stage=Stage.INPUT/OUTPUT/RETRIEVAL/TOOL)` or `ascan`;
the default stage is `Stage.INPUT`. Retrieval/tool checks must be invoked explicitly;
`run` does not discover or intercept these operations. `ToolGuard` adds name/schema validation.

Scanners run in configuration order. Each sees the text produced by preceding redactions.
Findings record half-open character offsets, scanner index, and the **input revision** they
refer to; every redacting scanner increments the revision. Offsets from different revisions
must not be applied to the original string. No originals or rehydration maps are retained.

Defaults: 100,000 characters per stage, 256 findings per scanner, JSON nesting at most 32,
and a 5-second **per-operation async wait**. Synchronous calls have no execution deadline.
Async cancellation cannot terminate a running thread or preempt a coroutine that blocks
the event loop. Timed-out work may continue and have side effects. Use process isolation
and application concurrency limits when execution must be forcibly bounded.

## Examples and development

Clone the source to run the examples or contribute:

```sh
git clone https://github.com/sahilmathur254/guardtrellis.git
cd guardtrellis
uv sync --all-extras --group dev
uv run python examples/plain_callable.py
uv run python examples/fastapi_app.py       # Local TestClient demo, no server needed
uv run python examples/langgraph_app.py     # Local graph, no provider credentials
uv run python examples/openai_app.py        # Real SDK, in-memory HTTP mock by default
uv run python examples/azure_openai_app.py  # Azure SDK, in-memory HTTP mock by default
uv run python examples/gemini_app.py        # Gemini SDK, in-memory HTTP mock by default
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run python evaluation/run.py --report-dir /tmp/guardtrellis-eval
uv build
uv run python scripts/smoke_dist.py
```

FastAPI and LangGraph are optional extras (`.[fastapi]`, `.[langgraph]`). LangGraph input
checks run **before** text enters graph state. The example also checks model output before
returning it to graph state. Instrumentation around callbacks may still capture raw data.

The optional provider examples (`.[openai]`) use direct OpenAI Responses or Azure OpenAI
Chat Completions through guarded callbacks. Their default modes and ordinary tests make
no provider calls. See the [OpenAI guide](docs/openai.md) and [Azure guide](docs/azure_openai.md)
for setup, privacy/failure boundaries, and separately approved one-request live smokes.
This extra and these examples are part of the unpublished `0.1.0a2` candidate, not the
published `0.1.0a1` artifacts. Live verification of both paths is pending.

The separate [Gemini example](docs/gemini.md) uses the optional `.[gemini]` extra and also
defaults to mocked HTTP. Its one-request live smoke can use an approved Gemini Free Tier
project with the documented model and limits. A maintainer-approved live smoke passed on
2026-09-26; the guide records the exact source, versions, token counts, and evidence limits.

See [API details](https://github.com/sahilmathur254/guardtrellis/blob/main/docs/api.md),
[limitations and trust boundaries](https://github.com/sahilmathur254/guardtrellis/blob/main/docs/limitations.md),
[evaluation methodology](https://github.com/sahilmathur254/guardtrellis/blob/main/evaluation/README.md),
[measured smoke results](https://github.com/sahilmathur254/guardtrellis/blob/main/evaluation/REPORT.md),
[resource measurements and host controls](https://github.com/sahilmathur254/guardtrellis/blob/main/docs/resource_limits.md),
and [contribution guidance](https://github.com/sahilmathur254/guardtrellis/blob/main/CONTRIBUTING.md).
These checks do not provide comprehensive
prompt-injection prevention, factual verification, regulatory compliance, or a tool sandbox.

## Roadmap and contributions

Use the public [GitHub Project](https://github.com/users/sahilmathur254/projects/3) to find
ready work and track progress. The [roadmap](https://github.com/sahilmathur254/guardtrellis/blob/main/ROADMAP.md) explains the release milestones,
dependencies, and longer-term proposals. Start with a
[good first issue](https://github.com/sahilmathur254/guardtrellis/labels/good%20first%20issue)
or a [help wanted issue](https://github.com/sahilmathur254/guardtrellis/labels/help%20wanted),
then follow the [contributor workflow](https://github.com/sahilmathur254/guardtrellis/blob/main/CONTRIBUTING.md).

See the [changelog](https://github.com/sahilmathur254/guardtrellis/blob/main/CHANGELOG.md)
for version-specific behavior and the [release guide](https://github.com/sahilmathur254/guardtrellis/blob/main/docs/releasing.md)
for packaging checks, TestPyPI rehearsal, and maintainer-approved publication.
