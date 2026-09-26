"""OpenAI Responses callback. Defaults to an HTTP mock; see docs/openai.md for live use."""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
from datetime import UTC, datetime
from importlib.metadata import version

import httpx
from openai import OpenAI

from guardtrellis import Action, Guard, PIIScanner, SecretScanner

MODEL = "gpt-5.6-luna"
MAX_OUTPUT_TOKENS = 128
PROMPT = "Reply with exactly: Contact demo@example.org"
TIMEOUT = httpx.Timeout(20.0, connect=5.0, write=5.0, pool=5.0)


def make_client(*, api_key: str, transport: httpx.BaseTransport | None = None) -> OpenAI:
    """Own this client with a context manager. A missing transport permits live HTTP."""
    return OpenAI(
        api_key=api_key,
        base_url="https://api.openai.com/v1",
        max_retries=0,
        timeout=TIMEOUT,
        http_client=httpx.Client(transport=transport, timeout=TIMEOUT, follow_redirects=False),
    )


class OpenAIModel:
    """Synchronous complete-text callback; retain only request count and usage metadata."""

    def __init__(self, client: OpenAI):
        self.client = client
        self.requests = 0
        self.usage: dict[str, int] | None = None

    def __call__(self, text: str) -> str:
        self.usage = None
        self.requests += 1
        response = self.client.responses.create(
            model=MODEL,
            input=text,
            reasoning={"effort": "none"},
            max_output_tokens=MAX_OUTPUT_TOKENS,
            store=False,
            stream=False,
            tools=[],
            service_tier="default",
        )
        # output_text alone can be empty on refusal, or contain an incomplete answer.
        # This text-only example rejects non-message output and mixed refusal content.
        if (
            response.status != "completed"
            or response.error is not None
            or response.incomplete_details is not None
            or not response.output
        ):
            raise ValueError("Provider did not return a complete text response")
        for item in response.output:
            if item.type != "message" or item.status != "completed" or not item.content:
                raise ValueError("Provider returned unsupported output")
            if any(part.type != "output_text" for part in item.content):
                raise ValueError("Provider did not return text-only content")
        text = response.output_text
        if not text.strip():
            raise ValueError("Provider returned empty text")
        if response.usage is not None:
            usage = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.total_tokens,
            }
            if any(type(value) is not int or value < 0 for value in usage.values()):
                raise ValueError("Provider returned invalid usage metadata")
            self.usage = usage
        return text


def make_guard() -> Guard:
    return Guard(
        input_scanners=[SecretScanner(), PIIScanner()],
        output_scanners=[SecretScanner(), PIIScanner()],
        max_chars=2_000,
    )


def mock_response(request: httpx.Request) -> httpx.Response:
    """Fabricated provider response handled entirely in memory, with no socket access."""
    return httpx.Response(
        200,
        json={
            "id": "resp_mock",
            "object": "response",
            "created_at": 0,
            "model": MODEL,
            "status": "completed",
            "error": None,
            "incomplete_details": None,
            "output": [
                {
                    "type": "message",
                    "id": "msg_mock",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Contact demo@example.org",
                            "annotations": [],
                        }
                    ],
                }
            ],
            "usage": {
                "input_tokens": 12,
                "output_tokens": 6,
                "total_tokens": 18,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 0},
            },
        },
        request=request,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Opt into one paid OpenAI request")
    args = parser.parse_args(argv)
    if args.live and os.environ.get("GUARDTRELLIS_OPENAI_LIVE") != "1":
        parser.exit(2, "Live smoke requires GUARDTRELLIS_OPENAI_LIVE=1 and spending approval.\n")
    api_key = os.environ.get("OPENAI_API_KEY") if args.live else "mock-not-a-credential"
    if not api_key:
        parser.exit(2, "Set OPENAI_API_KEY privately before opting into the live smoke.\n")

    # Standalone demo only: suppress standard SDK/HTTP logging, even with OPENAI_LOG=debug.
    # Importing this module does not change an application's logging configuration.
    logging.disable(logging.CRITICAL)
    transport = None if args.live else httpx.MockTransport(mock_response)
    try:
        with make_client(api_key=api_key, transport=transport) as client:
            model = OpenAIModel(client)
            guard = make_guard()
            # Fabricated signature; it must never cause a provider request.
            blocked = guard.run("ghp_" + "A" * 36, model)
            blocked_before_request = blocked.action == Action.BLOCK and model.requests == 0
            if not blocked_before_request:
                print("Input-boundary smoke failed; stopping.")
                return 1
            result = guard.run(PROMPT, model)
            passed = result.accepted and model.requests == 1
            report = {
                "mode": "live" if args.live else "mock",
                "passed": passed,
                "date_utc": datetime.now(UTC).isoformat(),
                "versions": {
                    "python": platform.python_version(),
                    **{name: version(name) for name in ("guardtrellis", "openai", "httpx")},
                },
                "model": MODEL,
                "requests": model.requests,
                "max_output_tokens": MAX_OUTPUT_TOKENS,
                "blocked_input_prevented_request": blocked_before_request,
                "usage": model.usage,
                "result": result.diagnostics(),
            }
            # Live evidence never includes a prompt, response, key, or exception payload.
            print(json.dumps(report, sort_keys=True))
            if not args.live and passed:
                print(result.require_text())
            return 0 if passed else 1
    except Exception:
        # Initialization/cleanup failures are outside Guard.run's callback boundary.
        print("Provider smoke failed; no response or exception contents were printed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
