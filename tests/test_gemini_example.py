"""Gemini SDK boundary tests over MockTransport; no provider calls or credentials."""

import json
import logging
import os
import socket
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

import pytest

pytest.importorskip("google.genai")
import httpx2

from examples import gemini_app as demo
from guardtrellis import Action, Rejected

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated_backend(monkeypatch):
    monkeypatch.delenv("GOOGLE_GENAI_HTTP_CLIENT", raising=False)
    previous_disable = logging.root.manager.disable
    yield
    logging.disable(previous_disable)


@pytest.fixture
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("Socket access is forbidden in the Gemini regression tests")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def synchronous_http_client(client):
    # This test-only inspection is scoped to the SDK 3 backend/lifecycle contract.
    assert version("google-genai").split(".")[0] == "3"
    http_client = client._api_client._httpx_client
    assert isinstance(http_client, httpx2.Client)
    return http_client


@pytest.fixture
def provider():
    requests = []
    response = demo.mock_response(httpx2.Request("POST", "https://example.invalid")).json()

    def handle(request):
        requests.append(request)
        return httpx2.Response(200, json=response)

    with demo.make_client(
        api_key="mock-key-never-print", transport=httpx2.MockTransport(handle)
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


@pytest.mark.parametrize(
    "finish_reason", ["MAX_TOKENS", "SAFETY", "RECITATION", "OTHER", "MALFORMED_RESPONSE", None]
)
def test_noncompleted_response_is_not_delivered(provider, finish_reason):
    model, _, response = provider
    response["candidates"][0]["finishReason"] = finish_reason
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"


@pytest.mark.parametrize("finish_reason", ["CONTINUATION", None])
def test_continuation_does_not_send_another_request_or_deliver_text(finish_reason):
    requests = []
    token = "c3ludGhldGljLWNvbnRpbnVhdGlvbi10b2tlbg=="
    raw_output = "Synthetic continuation output"

    def handle(request):
        requests.append(request)
        response = demo.mock_response(request).json()
        candidate = response["candidates"][0]
        candidate["content"]["parts"] = [{"text": raw_output}]
        # A second response completes so a regression fails without an infinite loop.
        if len(requests) == 1:
            candidate["finishReason"] = finish_reason
            candidate["continuationToken"] = token
        return httpx2.Response(200, json=response)

    with demo.make_client(
        api_key="mock-key-never-print", transport=httpx2.MockTransport(handle)
    ) as client:
        model = demo.GeminiModel(client)
        result = demo.make_guard().run("Fabricated test", model)

    assert len(requests) == model.requests == 1
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"
    with pytest.raises(Rejected) as error:
        result.require_text()
    metadata = repr(result) + repr(result.diagnostics()) + str(error.value)
    assert token not in metadata and raw_output not in metadata
    assert "synthetic-continuation-token" not in metadata


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
            raise httpx2.ReadTimeout(private, request=request)
        if failure == "connection":
            raise httpx2.ConnectError(private, request=request)
        if failure == "invalid_json":
            return httpx2.Response(200, text=private)
        return httpx2.Response(
            failure,
            headers={"location": "https://example.invalid/elsewhere"},
            json={"error": {"message": private, "code": failure, "status": "MOCK_ERROR"}},
        )

    with demo.make_client(
        api_key="mock-not-a-credential", transport=httpx2.MockTransport(handle)
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
        return real_make_client(api_key=api_key, transport=httpx2.MockTransport(handle))

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
    assert report["versions"]["google-genai"] == version("google-genai")
    assert report["versions"]["httpx2"] == version("httpx2") and "httpx" not in report["versions"]
    assert len(report["script_sha256"]) == 64
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


@pytest.mark.parametrize("backend", [None, "", "auto", "httpx2", " AuTo ", " HTTPX2 ", "  "])
def test_real_client_construction_selects_httpx2_without_network(monkeypatch, no_network, backend):
    if backend is not None:
        monkeypatch.setenv("GOOGLE_GENAI_HTTP_CLIENT", backend)
    before = dict(os.environ)
    with demo.make_client(api_key="mock-key-never-print", transport=None) as client:
        http_client = synchronous_http_client(client)
        assert not http_client.is_closed
    assert http_client.is_closed
    assert dict(os.environ) == before


@pytest.mark.parametrize("backend", ["httpx", " HTTPX ", "synthetic-private-backend@example.org"])
def test_conflicting_backend_fails_before_client_construction(
    monkeypatch, no_network, caplog, backend
):
    monkeypatch.setenv("GOOGLE_GENAI_HTTP_CLIENT", backend)
    monkeypatch.setattr(demo.genai, "Client", lambda **kwargs: pytest.fail("Unexpected client"))
    before = dict(os.environ)
    with pytest.raises(ValueError, match="^This example requires the HTTPX2 backend\\.$") as error:
        demo.make_client(api_key="mock-key-never-print")
    assert backend not in str(error.value) + caplog.text
    assert not caplog.records
    assert dict(os.environ) == before


@pytest.mark.parametrize("backend", [None, "", "auto", "httpx2", " AuTo ", " HTTPX2 ", "  "])
def test_default_command_uses_mock_and_explicit_settings_with_allowed_backend(
    monkeypatch, no_network, capsys, backend
):
    if backend is not None:
        monkeypatch.setenv("GOOGLE_GENAI_HTTP_CLIENT", backend)
    for name, value in {
        "GUARDTRELLIS_GEMINI_LIVE": "1",
        "GEMINI_API_KEY": "mock-ambient-key-never-print",
        "GOOGLE_API_KEY": "mock-other-key-never-print",
        "GOOGLE_GENAI_USE_ENTERPRISE": "true",
        "GOOGLE_GENAI_USE_VERTEXAI": "true",
        "GOOGLE_GEMINI_BASE_URL": "https://private-base.example.invalid",
        "GOOGLE_VERTEX_BASE_URL": "https://private-vertex.example.invalid",
        "GOOGLE_GENAI_API_VERSION": "private-version-never-print",
        "GOOGLE_CLOUD_PROJECT": "mock-project-never-print",
        "GOOGLE_CLOUD_LOCATION": "mock-location-never-print",
    }.items():
        monkeypatch.setenv(name, value)
    before = dict(os.environ)
    requests = []
    mock_response = demo.mock_response

    def handle(request):
        requests.append(request)
        return mock_response(request)

    monkeypatch.setattr(demo, "mock_response", handle)
    assert demo.main([]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out.splitlines()[0])
    assert report["mode"] == "mock" and report["passed"]
    assert report["requests"] == len(requests) == 1
    assert report["blocked_input_prevented_request"]
    request = requests[0]
    assert isinstance(request, httpx2.Request)
    assert str(request.url) == (
        f"https://generativelanguage.googleapis.com/v1beta/models/{demo.MODEL}:generateContent"
    )
    assert request.headers["x-goog-api-key"] == "mock-not-a-credential"
    assert "mock-not-a-credential" not in str(request.url)
    assert report["versions"]["google-genai"] == version("google-genai")
    assert report["versions"]["httpx2"] == version("httpx2") and "httpx" not in report["versions"]
    assert "Contact [PII]" in captured.out
    for private in (
        "mock-ambient-key-never-print",
        "mock-other-key-never-print",
        "private-base.example.invalid",
        "private-vertex.example.invalid",
        "private-version-never-print",
        "mock-project-never-print",
        "mock-location-never-print",
        "demo@example.org",
        "mock-response-never-print",
    ):
        assert private not in captured.out + captured.err
    assert not captured.err
    assert dict(os.environ) == before


@pytest.mark.parametrize("backend", ["httpx", " HTTPX ", "synthetic-private-backend@example.org"])
def test_default_command_conflicting_backend_is_static_failure_before_construction(
    monkeypatch, no_network, capsys, backend
):
    monkeypatch.setenv("GOOGLE_GENAI_HTTP_CLIENT", backend)
    monkeypatch.setenv("GUARDTRELLIS_GEMINI_LIVE", "1")
    monkeypatch.setenv("GEMINI_API_KEY", "mock-ambient-key-never-print")
    monkeypatch.setattr(demo.genai, "Client", lambda **kwargs: pytest.fail("Unexpected client"))
    before = dict(os.environ)
    assert demo.main([]) == 1
    captured = capsys.readouterr()
    assert (
        captured.out == "Provider smoke failed; no response or exception contents were printed.\n"
    )
    assert not captured.err
    assert dict(os.environ) == before


@pytest.mark.parametrize(
    "outcome",
    ["success", "input_block", "output_block", "provider_error", "invalid_json", "timeout"],
)
def test_used_synchronous_resources_close_on_success_and_failure(no_network, outcome):
    streams = []
    responses = []
    requests = []

    class TrackedStream(httpx2.SyncByteStream):
        def __init__(self, data):
            self.data = data
            self.closed = False

        def __iter__(self):
            yield self.data

        def close(self):
            self.closed = True

    def handle(request):
        requests.append(request)
        if outcome == "timeout":
            raise httpx2.ReadTimeout("Synthetic private timeout", request=request)
        body = demo.mock_response(request).json()
        status = 200
        if outcome == "output_block":
            body["candidates"][0]["content"]["parts"] = [{"text": "ghp_" + "A" * 36}]
        elif outcome == "provider_error":
            status = 500
            body = {"error": {"code": 500, "message": "Synthetic private error"}}
        data = (
            b"Synthetic private invalid JSON"
            if outcome == "invalid_json"
            else json.dumps(body).encode()
        )
        stream = TrackedStream(data)
        streams.append(stream)
        response = httpx2.Response(
            status, headers={"content-type": "application/json"}, stream=stream, request=request
        )
        responses.append(response)
        return response

    class TrackedTransport(httpx2.MockTransport):
        closed = False

        def close(self):
            self.closed = True
            super().close()

    transport = TrackedTransport(handle)
    with demo.make_client(api_key="mock-key-never-print", transport=transport) as client:
        http_client = synchronous_http_client(client)
        result = demo.make_guard().run(
            "ghp_" + "A" * 36 if outcome == "input_block" else "Fabricated test",
            demo.GeminiModel(client),
        )
        assert not transport.closed and not http_client.is_closed
    assert transport.closed and http_client.is_closed
    assert all(response.is_closed for response in responses)
    assert all(stream.closed for stream in streams)
    assert len(requests) == (0 if outcome == "input_block" else 1)
    if outcome == "success":
        assert result.require_text() == "Contact [PII]"
    else:
        assert result.text is None
        assert result.action == (Action.BLOCK if outcome.endswith("block") else Action.ERROR)
    assert "Synthetic private" not in repr(result) + repr(result.diagnostics())


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_caller_interruption_propagates_and_closes_used_synchronous_client(
    monkeypatch, no_network, interruption
):
    transports = []
    clients = []
    requests = []
    make_client = demo.make_client

    class TrackedTransport(httpx2.MockTransport):
        closed = False

        def close(self):
            self.closed = True
            super().close()

    def handle(request):
        requests.append(request)
        raise interruption("Synthetic private interruption")

    def client_factory(*, api_key, transport):
        owned_transport = TrackedTransport(handle)
        transports.append(owned_transport)
        client = make_client(api_key=api_key, transport=owned_transport)
        clients.append(synchronous_http_client(client))
        return client

    monkeypatch.setattr(demo, "make_client", client_factory)
    with pytest.raises(interruption, match="Synthetic private interruption"):
        demo.main([])
    assert len(requests) == len(clients) == len(transports) == 1
    assert clients[0].is_closed and transports[0].closed
