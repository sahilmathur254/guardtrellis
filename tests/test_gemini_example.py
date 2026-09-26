"""Gemini SDK boundary tests over MockTransport; no provider calls or credentials."""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("google.genai")
import httpx

from examples import gemini_app as demo
from guardtrellis import Action, Rejected

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def provider():
    requests = []
    response = demo.mock_response(httpx.Request("POST", "https://example.invalid")).json()

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json=response)

    with demo.make_client(
        api_key="mock-key-never-print", transport=httpx.MockTransport(handle)
    ) as client:
        yield demo.GeminiModel(client), requests, response


def test_blocked_input_prevents_http_and_hides_rejected_content(provider):
    model, requests, _ = provider
    token = "ghp_" + "A" * 36
    result = demo.make_guard().run(token, model)
    assert result.action == Action.BLOCK and result.text is None
    assert model.requests == 0 and requests == []
    assert token not in repr(result) + repr(result.diagnostics())


def test_redaction_at_actual_http_and_delivery_boundaries(provider):
    model, requests, _ = provider
    result = demo.make_guard().run(demo.PROMPT, model)
    assert len(requests) == model.requests == 1
    request = requests[0]
    assert str(request.url) == (
        f"https://generativelanguage.googleapis.com/v1beta/models/{demo.MODEL}:generateContent"
    )
    assert request.method == "POST"
    assert request.headers["x-goog-api-key"] == "mock-key-never-print"
    assert "mock-key-never-print" not in str(request.url)
    body = json.loads(request.content)
    assert body["contents"] == [
        {"role": "user", "parts": [{"text": "Reply with exactly: Contact [PII]"}]}
    ]
    assert body["generationConfig"] == {
        "candidateCount": 1,
        "maxOutputTokens": 128,
        "responseMimeType": "text/plain",
        "responseModalities": ["TEXT"],
        "thinkingConfig": {"thinking_level": "MINIMAL", "include_thoughts": False},
    }
    assert body.get("tools", []) == []
    assert "cachedContent" not in body and "systemInstruction" not in body
    assert request.extensions["timeout"] == {"connect": 20, "read": 20, "write": 20, "pool": 20}
    assert result.action == Action.REDACT and result.require_text() == "Contact [PII]"
    assert "demo@example.org" not in repr(result) + repr(result.diagnostics())
    assert model.usage == {
        "input_tokens": 12,
        "output_tokens": 6,
        "thought_tokens": 0,
        "total_tokens": 18,
    }


def test_split_output_secret_is_joined_and_blocked_before_delivery(provider):
    model, requests, response = provider
    token = "ghp_" + "B" * 36
    response["candidates"][0]["content"]["parts"] = [{"text": token[:20]}, {"text": token[20:]}]
    result = demo.make_guard().run("Fabricated test", model)
    assert len(requests) == 1 and result.action == Action.BLOCK and result.text is None
    with pytest.raises(Rejected) as error:
        result.require_text()
    assert token not in repr(result) + repr(result.diagnostics()) + str(error.value)


@pytest.mark.parametrize("finish_reason", ["MAX_TOKENS", "SAFETY", "RECITATION", "OTHER", None])
def test_noncompleted_response_is_not_delivered(provider, finish_reason):
    model, _, response = provider
    response["candidates"][0]["finishReason"] = finish_reason
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"


@pytest.mark.parametrize(
    "case",
    [
        "empty",
        "multiple",
        "no_content",
        "no_parts",
        "blank",
        "null",
        "role",
        "thought",
        "tool",
        "mixed_tool",
        "image",
        "code",
        "blocked_prompt",
        "blocked_candidate",
    ],
)
def test_unsupported_or_blocked_content_is_not_delivered(provider, case):
    model, requests, response = provider
    candidate = response["candidates"][0]
    content = candidate["content"]
    if case == "empty":
        response["candidates"] = []
    elif case == "multiple":
        response["candidates"] *= 2
    elif case == "no_content":
        candidate.pop("content")
    elif case == "no_parts":
        content["parts"] = []
    elif case in {"blank", "null"}:
        content["parts"][0]["text"] = "  " if case == "blank" else None
    elif case == "role":
        content["role"] = "user"
    elif case == "thought":
        content["parts"][0]["thought"] = True
    elif case in {"tool", "mixed_tool"}:
        part = {"functionCall": {"name": "lookup", "args": {"query": "Fabricated private data"}}}
        if case == "mixed_tool":
            part["text"] = "Some text"
        content["parts"] = [part]
    elif case == "image":
        content["parts"] = [{"inlineData": {"mimeType": "image/png", "data": "ZmFrZQ=="}}]
    elif case == "code":
        content["parts"] = [{"executableCode": {"language": "PYTHON", "code": "print('fake')"}}]
    elif case == "blocked_prompt":
        response["promptFeedback"] = {"blockReason": "SAFETY"}
    else:
        candidate["safetyRatings"] = [{"category": "HARM_CATEGORY_HARASSMENT", "blocked": True}]
    result = demo.make_guard().run("Fabricated test", model)
    assert len(requests) == 1  # In particular, tool output must not trigger another request.
    assert result.action == Action.ERROR and result.text is None
    assert "Fabricated private data" not in repr(result) + repr(result.diagnostics())


def test_signature_metadata_and_unblocked_feedback_are_not_delivered(provider):
    model, _, response = provider
    response["promptFeedback"] = {"blockReason": "BLOCKED_REASON_UNSPECIFIED"}
    response["candidates"][0]["content"]["parts"][0]["thoughtSignature"] = "ZmFrZQ=="
    result = demo.make_guard().run("Fabricated test", model)
    assert result.require_text() == "Contact [PII]"
    assert "ZmFrZQ==" not in repr(result) + repr(result.diagnostics())


@pytest.mark.parametrize("usage", ["Fabricated private metadata", -1, []])
def test_malformed_usage_cannot_leak_into_metadata_report(provider, usage):
    model, _, response = provider
    response["usageMetadata"]["promptTokenCount"] = usage
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert model.usage is None
    assert "Fabricated private metadata" not in repr(result.diagnostics())


def test_missing_usage_is_unknown_not_zero(provider):
    model, _, response = provider
    response.pop("usageMetadata")
    assert demo.make_guard().run("Fabricated test", model).accepted
    assert model.usage is None


@pytest.mark.parametrize(
    "failure", [401, 403, 429, 500, 307, "timeout", "connection", "invalid_json"]
)
def test_provider_failures_are_generic_without_retry_or_redirect(failure):
    requests = []
    private = "Fabricated provider error: demo@example.org"

    def handle(request):
        requests.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout(private, request=request)
        if failure == "connection":
            raise httpx.ConnectError(private, request=request)
        if failure == "invalid_json":
            return httpx.Response(200, text=private)
        return httpx.Response(
            failure,
            headers={"location": "https://example.invalid/elsewhere"},
            json={"error": {"message": private, "code": failure, "status": "MOCK_ERROR"}},
        )

    with demo.make_client(
        api_key="mock-not-a-credential", transport=httpx.MockTransport(handle)
    ) as client:
        result = demo.make_guard().run("Fabricated test", demo.GeminiModel(client))
    assert len(requests) == 1
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"
    assert private not in repr(result) + repr(result.diagnostics())


@pytest.mark.parametrize(
    "opt_in,key", [(None, "mock-key"), ("0", "mock-key"), ("1", ""), ("1", " ")]
)
def test_live_prerequisites_are_checked_before_client_creation(monkeypatch, opt_in, key):
    monkeypatch.delenv("GUARDTRELLIS_GEMINI_LIVE", raising=False)
    if opt_in is not None:
        monkeypatch.setenv("GUARDTRELLIS_GEMINI_LIVE", opt_in)
    monkeypatch.setenv("GEMINI_API_KEY", key)
    monkeypatch.setattr(demo, "make_client", lambda **kwargs: pytest.fail("Unexpected client"))
    with pytest.raises(SystemExit) as error:
        demo.main(["--live"])
    assert error.value.code == 2


def test_live_reporting_uses_metadata_only_with_mocked_http(monkeypatch, capsys):
    real_make_client = demo.make_client
    requests = []

    def handle(request):
        requests.append(request)
        return demo.mock_response(request)

    def fake_live_client(*, api_key, transport):
        assert transport is None
        return real_make_client(api_key=api_key, transport=httpx.MockTransport(handle))

    monkeypatch.setenv("GUARDTRELLIS_GEMINI_LIVE", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "mock-key-never-print")
    monkeypatch.setattr(demo, "make_client", fake_live_client)
    previous_disable = logging.root.manager.disable
    try:
        assert demo.main(["--live"]) == 0
    finally:
        logging.disable(previous_disable)
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert len(requests) == report["requests"] == 1
    assert report["passed"] and report["blocked_input_prevented_request"]
    assert report["mode"] == "live"  # Mocked reporting test, not real live evidence.
    assert report["versions"]["google-genai"] and len(report["script_sha256"]) == 64
    for private in (
        "mock-key-never-print",
        "demo@example.org",
        "Contact",
        "mock-response-never-print",
    ):
        assert private not in captured.out
    assert captured.err == ""


def test_default_command_stays_mocked_with_live_environment_and_other_google_settings():
    process = subprocess.run(
        [sys.executable, str(ROOT / "examples/gemini_app.py")],
        env=dict(
            os.environ,
            GUARDTRELLIS_GEMINI_LIVE="1",
            GEMINI_API_KEY="mock-key-never-print",
            GOOGLE_API_KEY="another-mock-key-never-print",
            GOOGLE_GENAI_USE_ENTERPRISE="true",
            GOOGLE_GENAI_USE_VERTEXAI="true",
            GOOGLE_GEMINI_BASE_URL="https://example.invalid",
            GOOGLE_CLOUD_PROJECT="mock-project-never-print",
        ),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    report = json.loads(process.stdout.splitlines()[0])
    assert report["mode"] == "mock" and report["passed"]
    assert "Contact [PII]" in process.stdout
    for private in ("demo@example.org", "mock-key-never-print", "mock-project-never-print"):
        assert private not in process.stdout + process.stderr
    assert process.stderr == ""
