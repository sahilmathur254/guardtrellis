"""Real Azure SDK serialization over HTTP mocks; never a live provider test."""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("openai")
import httpx

from examples import azure_openai_app as demo
from guardtrellis import Action, Rejected

ROOT = Path(__file__).resolve().parents[1]
CONFIG = {
    "api_key": "mock-key-never-print",
    "endpoint": demo.MOCK_ENDPOINT,
    "api_version": demo.MOCK_API_VERSION,
}
LIVE_ENV = {
    "GUARDTRELLIS_AZURE_OPENAI_LIVE": "1",
    "AZURE_OPENAI_API_KEY": CONFIG["api_key"],
    "AZURE_OPENAI_ENDPOINT": CONFIG["endpoint"],
    "OPENAI_API_VERSION": CONFIG["api_version"],
    "AZURE_OPENAI_DEPLOYMENT": demo.MOCK_DEPLOYMENT,
}


@pytest.fixture(autouse=True)
def isolate_auth_environment(monkeypatch):
    monkeypatch.delenv("AZURE_OPENAI_AD_TOKEN", raising=False)


@pytest.fixture
def provider():
    requests = []
    response = demo.mock_response(httpx.Request("POST", "https://example.invalid")).json()

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json=response)

    with demo.make_client(**CONFIG, transport=httpx.MockTransport(handle)) as client:
        yield demo.AzureOpenAIModel(client, deployment=demo.MOCK_DEPLOYMENT), requests, response


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
        f"{demo.MOCK_ENDPOINT}/openai/deployments/{demo.MOCK_DEPLOYMENT}"
        f"/chat/completions?api-version={demo.MOCK_API_VERSION}"
    )
    assert request.method == "POST"
    assert request.headers["api-key"] == CONFIG["api_key"]
    assert "authorization" not in request.headers
    body = json.loads(request.content)
    assert body["messages"] == [{"role": "user", "content": "Reply with exactly: Contact [PII]"}]
    assert body["model"] == demo.MOCK_DEPLOYMENT
    assert body["max_completion_tokens"] == 128 and body["n"] == 1
    assert body["reasoning_effort"] == "none"
    assert body["store"] is body["stream"] is False
    assert "tools" not in body and "functions" not in body
    assert request.extensions["timeout"] == {"connect": 5, "read": 20, "write": 5, "pool": 5}
    assert result.action == Action.REDACT and result.require_text() == "Contact [PII]"
    assert "demo@example.org" not in repr(result) + repr(result.diagnostics())
    assert model.usage == {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}


def test_output_secret_is_blocked_before_delivery(provider):
    model, requests, response = provider
    token = "ghp_" + "B" * 36
    response["choices"][0]["message"]["content"] = token
    result = demo.make_guard().run("Fabricated test", model)
    assert len(requests) == 1 and result.action == Action.BLOCK and result.text is None
    with pytest.raises(Rejected) as error:
        result.require_text()
    assert token not in repr(result) + repr(result.diagnostics()) + str(error.value)


@pytest.mark.parametrize("usage", ["Fabricated private metadata", None, -1, []])
def test_malformed_usage_cannot_leak_into_metadata_report(provider, usage):
    model, _, response = provider
    response["usage"]["prompt_tokens"] = usage
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert model.usage is None
    assert "Fabricated private metadata" not in repr(result.diagnostics())


@pytest.mark.parametrize("finish_reason", ["length", "content_filter", "tool_calls", None])
def test_noncompleted_response_is_not_delivered(provider, finish_reason):
    model, _, response = provider
    response["choices"][0]["finish_reason"] = finish_reason
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"


@pytest.mark.parametrize(
    "case",
    [
        "empty",
        "multiple",
        "blank",
        "null",
        "nontext",
        "role",
        "refusal",
        "tool",
        "function",
        "audio",
        "annotations",
    ],
)
def test_unsupported_content_is_rejected_without_exposing_provider_payload(provider, case):
    model, _, response = provider
    message = response["choices"][0]["message"]
    private = "Fabricated private response"
    if case == "empty":
        response["choices"] = []
    elif case == "multiple":
        response["choices"] *= 2
    elif case in {"blank", "null", "nontext"}:
        message["content"] = {"blank": "  ", "null": None, "nontext": [private]}[case]
    elif case == "role":
        message["role"] = "user"
    elif case == "refusal":
        message["refusal"] = private  # Mixed text/refusal must fail too.
    elif case == "tool":
        message["tool_calls"] = [
            {"id": "mock", "type": "function", "function": {"name": "lookup", "arguments": "{}"}}
        ]
    elif case == "function":
        message["function_call"] = {"name": "lookup", "arguments": "{}"}
    elif case == "audio":
        message["audio"] = {"id": "mock", "data": private, "expires_at": 0, "transcript": private}
    else:
        message["annotations"] = [{"type": "url_citation", "url_citation": {"title": private}}]
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert private not in repr(result) + repr(result.diagnostics())


@pytest.mark.parametrize("failure", [401, 429, 500, 307, "timeout", "connection", "invalid_json"])
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
            json={"error": {"message": private, "type": "mock_error"}},
        )

    with demo.make_client(**CONFIG, transport=httpx.MockTransport(handle)) as client:
        result = demo.make_guard().run(
            "Fabricated test", demo.AzureOpenAIModel(client, deployment=demo.MOCK_DEPLOYMENT)
        )
    assert len(requests) == 1
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"
    assert private not in repr(result) + repr(result.diagnostics())


@pytest.mark.parametrize("missing", list(LIVE_ENV))
def test_live_prerequisites_are_checked_before_client_creation(monkeypatch, missing):
    for name, value in LIVE_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(missing)
    monkeypatch.setattr(demo, "make_client", lambda **kwargs: pytest.fail("Unexpected client"))
    with pytest.raises(SystemExit) as error:
        demo.main(["--live"])
    assert error.value.code == 2


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.openai.azure.com",
        "https://example.invalid",
        "https://example.openai.azure.com.evil.invalid",
        "https://private@example.openai.azure.com",
        "https://example.openai.azure.com/openai",
        "https://example.openai.azure.com?private=value",
        "https://example.openai.azure.com#private",
    ],
)
def test_live_endpoint_restrictions_fail_without_echoing_configuration(
    monkeypatch, capsys, endpoint
):
    for name, value in LIVE_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", endpoint)
    monkeypatch.setattr(demo, "make_client", lambda **kwargs: pytest.fail("Unexpected client"))
    with pytest.raises(SystemExit) as error:
        demo.main(["--live"])
    assert error.value.code == 2
    assert endpoint not in capsys.readouterr().err


@pytest.mark.parametrize(
    "name,value",
    [("AZURE_OPENAI_AD_TOKEN", "mock-token"), ("AZURE_OPENAI_DEPLOYMENT", "../private")],
)
def test_ambiguous_auth_and_unsupported_deployment_stop_before_client(monkeypatch, name, value):
    for key, content in LIVE_ENV.items():
        monkeypatch.setenv(key, content)
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(demo, "make_client", lambda **kwargs: pytest.fail("Unexpected client"))
    with pytest.raises(SystemExit) as error:
        demo.main(["--live"])
    assert error.value.code == 2


def test_live_reporting_excludes_configuration_and_content_using_mock_http(monkeypatch, capsys):
    for name, value in LIVE_ENV.items():
        monkeypatch.setenv(name, value)
    real_make_client = demo.make_client
    requests = []

    def handle(request):
        requests.append(request)
        return demo.mock_response(request)

    def fake_live_client(**kwargs):
        assert kwargs["transport"] is None
        return real_make_client(**(kwargs | {"transport": httpx.MockTransport(handle)}))

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
    assert report["versions"]["openai"] and len(report["script_sha256"]) == 64
    for private in (
        *CONFIG.values(),
        demo.MOCK_DEPLOYMENT,
        "demo@example.org",
        "Contact",
        "mock-model",
    ):
        assert private not in captured.out
    assert captured.err == ""


def test_default_command_stays_mocked_with_live_environment_and_debug_logging():
    process = subprocess.run(
        [sys.executable, str(ROOT / "examples/azure_openai_app.py")],
        env=dict(os.environ, **LIVE_ENV, OPENAI_LOG="debug", AZURE_OPENAI_AD_TOKEN="mock-ad-token"),
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    report = json.loads(process.stdout.splitlines()[0])
    assert report["mode"] == "mock" and report["passed"]
    assert "Contact [PII]" in process.stdout
    for private in (*CONFIG.values(), "demo@example.org", "mock-ad-token"):
        assert private not in process.stdout + process.stderr
    assert process.stderr == ""
