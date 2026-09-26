"""Exercise the real SDK over MockTransport. No credentials or provider network calls."""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("openai")
import httpx

from examples import openai_app as demo
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
        api_key="mock-not-a-credential", transport=httpx.MockTransport(handle)
    ) as c:
        yield demo.OpenAIModel(c), requests, response


def test_blocked_input_never_invokes_provider(provider):
    model, requests, _ = provider
    token = "ghp_" + "A" * 36
    result = demo.make_guard().run(token, model)
    assert result.action == Action.BLOCK
    assert result.text is None and result.output_result is None
    assert model.requests == 0 and requests == []
    assert token not in repr(result.diagnostics())


def test_only_redacted_input_crosses_http_boundary_and_output_is_checked(provider):
    model, requests, _ = provider
    result = demo.make_guard().run(demo.PROMPT, model)
    assert len(requests) == model.requests == 1
    request = requests[0]
    assert str(request.url) == "https://api.openai.com/v1/responses"
    assert request.method == "POST"
    body = json.loads(request.content)
    assert body["input"] == "Reply with exactly: Contact [PII]"
    assert body["max_output_tokens"] == 128
    assert body["model"] == demo.MODEL
    assert body["store"] is body["stream"] is False
    assert body["tools"] == []
    assert body["reasoning"] == {"effort": "none"}
    assert body["service_tier"] == "default"
    assert request.extensions["timeout"] == {"connect": 5, "read": 20, "write": 5, "pool": 5}
    assert result.action == Action.REDACT
    assert result.require_text() == "Contact [PII]"
    assert "demo@example.org" not in repr(result) + repr(result.diagnostics())
    assert model.usage == {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}


def test_blocked_complete_output_is_never_delivered(provider):
    model, requests, response = provider
    token = "ghp_" + "B" * 36
    # Separate text blocks only form the signature after the SDK joins complete output.
    response["output"][0]["content"] = [
        {"type": "output_text", "text": token[:20], "annotations": []},
        {"type": "output_text", "text": token[20:], "annotations": []},
    ]
    result = demo.make_guard().run("Fabricated test", model)
    assert len(requests) == 1
    assert result.action == Action.BLOCK and result.text is None
    assert token not in repr(result) + repr(result.diagnostics())
    with pytest.raises(Rejected, match="blocked|block") as error:
        result.require_text()
    assert token not in str(error.value)


@pytest.mark.parametrize("usage", ["Fabricated private metadata", None, -1, True])
def test_malformed_usage_cannot_leak_into_metadata_report(provider, usage):
    model, _, response = provider
    response["usage"]["input_tokens"] = usage
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert model.usage is None
    assert "Fabricated private metadata" not in repr(result.diagnostics())


@pytest.mark.parametrize("status", ["incomplete", "failed", "cancelled", "in_progress"])
def test_noncompleted_response_is_an_error(provider, status):
    model, _, response = provider
    response["status"] = status
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"


@pytest.mark.parametrize("case", ["empty", "blank", "refusal", "mixed", "tool", "partial"])
def test_unsupported_content_is_not_mistaken_for_accepted_text(provider, case):
    model, _, response = provider
    message = response["output"][0]
    refusal = {"type": "refusal", "refusal": "Fabricated private response"}
    if case == "empty":
        response["output"] = []
    elif case == "blank":
        message["content"][0]["text"] = "  "
    elif case == "refusal":
        message["content"] = [refusal]
    elif case == "mixed":
        message["content"].append(refusal)
    elif case == "tool":
        response["output"] = [
            {"type": "function_call", "call_id": "mock", "name": "lookup", "arguments": "{}"}
        ]
    else:
        message["status"] = "incomplete"
    result = demo.make_guard().run("Fabricated test", model)
    assert result.action == Action.ERROR and result.text is None
    assert "Fabricated private response" not in repr(result.diagnostics())


@pytest.mark.parametrize("failure", [401, 429, 500, "timeout", "connection"])
def test_provider_failures_are_generic_and_do_not_retry(failure):
    requests = []
    private = "Fabricated provider error: demo@example.org"

    def handle(request):
        requests.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout(private, request=request)
        if failure == "connection":
            raise httpx.ConnectError(private, request=request)
        return httpx.Response(failure, json={"error": {"message": private, "type": "mock_error"}})

    with demo.make_client(
        api_key="mock-not-a-credential", transport=httpx.MockTransport(handle)
    ) as c:
        result = demo.make_guard().run("Fabricated test", demo.OpenAIModel(c))
    assert len(requests) == 1
    assert result.action == Action.ERROR and result.text is None
    assert result.output_result.findings[0].code == "callback_error"
    assert private not in repr(result) + repr(result.diagnostics())


def test_redirect_is_not_followed_or_delivered():
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(307, headers={"location": "https://example.invalid/elsewhere"})

    with demo.make_client(
        api_key="mock-not-a-credential", transport=httpx.MockTransport(handle)
    ) as c:
        result = demo.make_guard().run("Fabricated test", demo.OpenAIModel(c))
    assert len(requests) == 1
    assert result.action == Action.ERROR and result.text is None


@pytest.mark.parametrize("opt_in,key", [(None, "mock-key"), ("0", "mock-key"), ("1", "")])
def test_live_requires_opt_in_and_credentials_before_client_creation(monkeypatch, opt_in, key):
    monkeypatch.delenv("GUARDTRELLIS_OPENAI_LIVE", raising=False)
    if opt_in is not None:
        monkeypatch.setenv("GUARDTRELLIS_OPENAI_LIVE", opt_in)
    monkeypatch.setenv("OPENAI_API_KEY", key)

    def unexpected(**kwargs):
        pytest.fail("Client construction must not occur before live prerequisites")

    monkeypatch.setattr(demo, "make_client", unexpected)
    with pytest.raises(SystemExit) as error:
        demo.main(["--live"])
    assert error.value.code == 2


def test_live_reporting_is_metadata_only_using_mocked_http(monkeypatch, capsys):
    real_make_client = demo.make_client
    requests = []

    def handle(request):
        requests.append(request)
        return demo.mock_response(request)

    def fake_live_client(*, api_key, transport):
        assert transport is None
        return real_make_client(api_key=api_key, transport=httpx.MockTransport(handle))

    monkeypatch.setenv("GUARDTRELLIS_OPENAI_LIVE", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "mock-key-never-print")
    monkeypatch.setattr(demo, "make_client", fake_live_client)
    previous_disable = logging.root.manager.disable
    try:
        assert demo.main(["--live"]) == 0
    finally:
        logging.disable(previous_disable)
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert len(requests) == report["requests"] == 1
    assert report["blocked_input_prevented_request"] and report["passed"]
    assert report["mode"] == "live"  # This unit test itself is mocked, not live evidence.
    assert report["versions"]["openai"] and report["date_utc"]
    assert "demo@example.org" not in captured.out
    assert "mock-key-never-print" not in captured.out
    assert "Contact" not in captured.out and captured.err == ""


def test_default_command_remains_mocked_even_with_live_environment_and_debug_logging():
    env = dict(
        os.environ,
        GUARDTRELLIS_OPENAI_LIVE="1",
        OPENAI_API_KEY="mock-key-never-print",
        OPENAI_BASE_URL="https://example.invalid",
        OPENAI_LOG="debug",
    )
    process = subprocess.run(
        [sys.executable, str(ROOT / "examples/openai_app.py")],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env=env,
    )
    report = json.loads(process.stdout.splitlines()[0])
    assert report["mode"] == "mock" and report["passed"]
    assert "Contact [PII]" in process.stdout
    assert "demo@example.org" not in process.stdout + process.stderr
    assert "mock-key-never-print" not in process.stdout + process.stderr
    assert process.stderr == ""
