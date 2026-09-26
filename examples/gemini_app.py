"""Gemini callback. Defaults to an HTTP mock; see docs/gemini.md for live use."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

import httpx
from google import genai
from google.genai import types

from guardtrellis import Action, Guard, PIIScanner, SecretScanner

MODEL = "gemini-3.5-flash-lite"
MAX_OUTPUT_TOKENS = 128
PROMPT = "Reply with exactly: Contact demo@example.org"
TIMEOUT_MS = 20_000


def make_client(*, api_key: str, transport: httpx.BaseTransport | None = None) -> genai.Client:
    """Own this client with a context manager. A missing transport permits live HTTP."""
    return genai.Client(
        api_key=api_key,
        enterprise=False,
        vertexai=False,
        http_options=types.HttpOptions(
            base_url="https://generativelanguage.googleapis.com",
            api_version="v1beta",
            timeout=TIMEOUT_MS,
            retry_options=types.HttpRetryOptions(attempts=1),
            client_args={"transport": transport, "follow_redirects": False},
        ),
    )


class GeminiModel:
    """One complete text response, with no automatic tool execution or content logging."""

    def __init__(self, client: genai.Client):
        self.client = client
        self.requests = 0
        self.usage: dict[str, int | None] | None = None

    def __call__(self, text: str) -> str:
        self.usage = None
        self.requests += 1
        response = self.client.models.generate_content(
            model=MODEL,
            contents=text,
            config=types.GenerateContentConfig(
                candidate_count=1,
                max_output_tokens=MAX_OUTPUT_TOKENS,
                response_mime_type="text/plain",
                response_modalities=["TEXT"],
                thinking_config=types.ThinkingConfig(
                    thinking_level=types.ThinkingLevel.MINIMAL, include_thoughts=False
                ),
                tools=[],
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            ),
        )
        feedback = response.prompt_feedback
        if feedback is not None and (
            feedback.block_reason not in (None, types.BlockedReason.BLOCKED_REASON_UNSPECIFIED)
            or any(rating.blocked for rating in feedback.safety_ratings or [])
        ):
            raise ValueError("Provider rejected the prompt")
        if not response.candidates or len(response.candidates) != 1:
            raise ValueError("Provider did not return one response")
        candidate = response.candidates[0]
        content = candidate.content
        if (
            candidate.finish_reason != types.FinishReason.STOP
            or any(rating.blocked for rating in candidate.safety_ratings or [])
            or content is None
            or content.role != "model"
            or not content.parts
        ):
            raise ValueError("Provider did not return complete text")
        pieces = []
        for part in content.parts:
            # Opaque thought signatures are metadata, never delivery or report content.
            # Reject mixed text/tool/media parts instead of silently selecting .text.
            fields = part.model_dump(exclude_none=True)
            if (
                not isinstance(part.text, str)
                or part.thought
                or fields.keys() - {"text", "thought", "thought_signature"}
            ):
                raise ValueError("Provider returned unsupported content")
            pieces.append(part.text)
        complete_text = "".join(pieces)
        if not complete_text.strip():
            raise ValueError("Provider returned empty text")
        if response.usage_metadata is not None:
            usage = {
                "input_tokens": response.usage_metadata.prompt_token_count,
                "output_tokens": response.usage_metadata.candidates_token_count,
                "thought_tokens": response.usage_metadata.thoughts_token_count,
                "total_tokens": response.usage_metadata.total_token_count,
            }
            if any(
                value is not None and (type(value) is not int or value < 0)
                for value in usage.values()
            ):
                raise ValueError("Provider returned invalid usage metadata")
            self.usage = usage
        return complete_text


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
            "candidates": [
                {
                    "content": {"role": "model", "parts": [{"text": "Contact demo@example.org"}]},
                    "finishReason": "STOP",
                    "index": 0,
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 12,
                "candidatesTokenCount": 6,
                "thoughtsTokenCount": 0,
                "totalTokenCount": 18,
            },
            "modelVersion": MODEL,
            "responseId": "mock-response-never-print",
        },
        request=request,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Opt into one approved Gemini request")
    args = parser.parse_args(argv)
    if args.live and os.environ.get("GUARDTRELLIS_GEMINI_LIVE") != "1":
        parser.exit(2, "Live smoke requires GUARDTRELLIS_GEMINI_LIVE=1 and an approved account.\n")
    api_key = os.environ.get("GEMINI_API_KEY") if args.live else "mock-not-a-credential"
    if not api_key or not api_key.strip():
        parser.exit(2, "Set GEMINI_API_KEY privately before opting into the live smoke.\n")

    # Only the standalone command changes logging; importing this module does not.
    logging.disable(logging.CRITICAL)
    transport = None if args.live else httpx.MockTransport(mock_response)
    try:
        with make_client(api_key=api_key, transport=transport) as client:
            model = GeminiModel(client)
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
                "provider": "gemini_developer_api_generate_content",
                "passed": passed,
                "date_utc": datetime.now(UTC).isoformat(),
                "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "versions": {
                    "python": platform.python_version(),
                    **{name: version(name) for name in ("guardtrellis", "google-genai", "httpx")},
                },
                "model": MODEL,
                "requests": model.requests,
                "max_output_tokens": MAX_OUTPUT_TOKENS,
                "blocked_input_prevented_request": blocked_before_request,
                "usage": model.usage,
                "result": result.diagnostics(),
            }
            print(json.dumps(report, sort_keys=True))
            if not args.live and passed:
                print(result.require_text())
            return 0 if passed else 1
    except Exception:
        print("Provider smoke failed; no response or exception contents were printed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
