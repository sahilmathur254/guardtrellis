"""Azure OpenAI callback. Defaults to an HTTP mock; see docs/azure_openai.md for live use."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import re
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

import httpx
from openai import AzureOpenAI

from guardtrellis import Action, Guard, PIIScanner, SecretScanner

MAX_COMPLETION_TOKENS = 128
PROMPT = "Reply with exactly: Contact demo@example.org"
TIMEOUT = httpx.Timeout(20.0, connect=5.0, write=5.0, pool=5.0)
MOCK_ENDPOINT = "https://guardtrellis-example.openai.azure.com"
MOCK_DEPLOYMENT = "example-deployment"
MOCK_API_VERSION = "2024-10-21"


def validate_endpoint(endpoint: str) -> str:
    """Limit this example to a public-cloud Azure resource root, without echoing values."""
    if re.fullmatch(r"https://[a-z0-9][a-z0-9-]*\.openai\.azure\.com/?", endpoint) is None:
        raise ValueError("Expected an HTTPS Azure OpenAI resource root URL")
    return endpoint.rstrip("/")


def make_client(
    *,
    api_key: str,
    endpoint: str,
    api_version: str,
    transport: httpx.BaseTransport | None = None,
) -> AzureOpenAI:
    """Own this client with a context manager. A missing transport permits live HTTP."""
    return AzureOpenAI(
        api_key=api_key,
        azure_endpoint=validate_endpoint(endpoint),
        api_version=api_version,
        organization="",
        default_headers={"OpenAI-Project": ""},
        max_retries=0,
        timeout=TIMEOUT,
        http_client=httpx.Client(transport=transport, timeout=TIMEOUT, follow_redirects=False),
    )


class AzureOpenAIModel:
    """Complete text only; deployment names and raw SDK responses stay out of reports."""

    def __init__(self, client: AzureOpenAI, *, deployment: str):
        self.client = client
        self.deployment = deployment
        self.requests = 0
        self.usage: dict[str, int] | None = None

    def __call__(self, text: str) -> str:
        self.usage = None
        self.requests += 1
        response = self.client.chat.completions.create(
            model=self.deployment,
            messages=[{"role": "user", "content": text}],
            max_completion_tokens=MAX_COMPLETION_TOKENS,
            reasoning_effort="none",
            n=1,
            store=False,
            stream=False,
        )
        if len(response.choices) != 1 or response.choices[0].finish_reason != "stop":
            raise ValueError("Provider did not return one complete text response")
        message = response.choices[0].message
        if (
            message.role != "assistant"
            or message.refusal is not None
            or message.tool_calls
            or message.function_call is not None
            or message.audio is not None
            or message.annotations
            or not isinstance(message.content, str)
            or not message.content.strip()
        ):
            raise ValueError("Provider returned unsupported or empty content")
        if response.usage is not None:
            usage = {
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
            if any(type(value) is not int or value < 0 for value in usage.values()):
                raise ValueError("Provider returned invalid usage metadata")
            self.usage = usage
        return message.content


def make_guard() -> Guard:
    return Guard(
        input_scanners=[SecretScanner(), PIIScanner()],
        output_scanners=[SecretScanner(), PIIScanner()],
        max_chars=2_000,
    )


def mock_response(request: httpx.Request) -> httpx.Response:
    """Fabricated fixture served in memory, without socket access."""
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl_mock",
            "object": "chat.completion",
            "created": 0,
            "model": "mock-model",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Contact demo@example.org"},
                }
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
        },
        request=request,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Opt into one paid Azure request")
    args = parser.parse_args(argv)
    if args.live and os.environ.get("GUARDTRELLIS_AZURE_OPENAI_LIVE") != "1":
        parser.exit(
            2, "Live smoke requires GUARDTRELLIS_AZURE_OPENAI_LIVE=1 and spending approval.\n"
        )

    api_key, endpoint, api_version, deployment = (
        "mock-not-a-credential",
        MOCK_ENDPOINT,
        MOCK_API_VERSION,
        MOCK_DEPLOYMENT,
    )
    if args.live:
        names = (
            "AZURE_OPENAI_API_KEY",
            "AZURE_OPENAI_ENDPOINT",
            "OPENAI_API_VERSION",
            "AZURE_OPENAI_DEPLOYMENT",
        )
        values = [os.environ.get(name, "").strip() for name in names]
        if not all(values):
            parser.exit(2, "Set the four Azure configuration variables privately; see the guide.\n")
        if os.environ.get("AZURE_OPENAI_AD_TOKEN") is not None:
            parser.exit(2, "Unset AZURE_OPENAI_AD_TOKEN for this API-key-only example.\n")
        api_key, endpoint, api_version, deployment = values
        try:
            validate_endpoint(endpoint)
        except ValueError:
            parser.exit(2, "Expected an HTTPS Azure OpenAI resource root URL; see the guide.\n")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", deployment) is None:
            parser.exit(2, "Unsupported deployment name format; see the guide.\n")

    # Only the standalone command changes logging; importing this module does not.
    logging.disable(logging.CRITICAL)
    transport = None if args.live else httpx.MockTransport(mock_response)
    try:
        with make_client(
            api_key=api_key, endpoint=endpoint, api_version=api_version, transport=transport
        ) as client:
            model = AzureOpenAIModel(client, deployment=deployment)
            guard = make_guard()
            blocked = guard.run("ghp_" + "A" * 36, model)
            blocked_before_request = blocked.action == Action.BLOCK and model.requests == 0
            if not blocked_before_request:
                print("Input-boundary smoke failed; stopping.")
                return 1
            result = guard.run(PROMPT, model)
            passed = result.accepted and model.requests == 1
            report = {
                "mode": "live" if args.live else "mock",
                "provider": "azure_openai_chat_completions",
                "passed": passed,
                "date_utc": datetime.now(UTC).isoformat(),
                "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "versions": {
                    "python": platform.python_version(),
                    **{name: version(name) for name in ("guardtrellis", "openai", "httpx")},
                },
                "requests": model.requests,
                "max_completion_tokens": MAX_COMPLETION_TOKENS,
                "blocked_input_prevented_request": blocked_before_request,
                "usage": model.usage,
                "result": result.diagnostics(),
            }
            # Never print endpoints, deployment names, keys, raw errors, or live content.
            print(json.dumps(report, sort_keys=True))
            if not args.live and passed:
                print(result.require_text())
            return 0 if passed else 1
    except Exception:
        print("Provider smoke failed; no response or exception contents were printed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
