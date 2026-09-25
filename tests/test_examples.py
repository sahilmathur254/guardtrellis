import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "script,module",
    [("plain_callable.py", None), ("fastapi_app.py", "fastapi"), ("langgraph_app.py", "langgraph")],
)
def test_example_script_runs(script, module):
    if module:
        pytest.importorskip(module)
    env = dict(os.environ, LANGSMITH_TRACING="false", LANGCHAIN_TRACING_V2="false")
    process = subprocess.run(
        [sys.executable, str(ROOT / "examples" / script)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env=env,
    )
    assert "[PII]" in process.stdout
    assert "demo@example.org" not in process.stdout


def test_fastapi_success_block_and_validation_privacy():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from examples.fastapi_app import app

    with TestClient(app) as client:
        response = client.post("/chat", json={"text": "person@example.net"})
        assert response.status_code == 200
        assert response.json()["text"] == "Local demo received: [PII]"
        token = "ghp_" + "B" * 36
        blocked = client.post("/chat", json={"text": token})
        assert blocked.status_code == 422
        assert token not in blocked.text
        invalid = client.post("/chat", json={"text": {"sensitive": "hidden"}})
        assert invalid.status_code == 422
        assert "hidden" not in invalid.text


def test_langgraph_initial_and_final_state_are_sanitized():
    pytest.importorskip("langgraph")
    from examples.langgraph_app import guarded_invoke
    from guardtrellis import Rejected

    state = guarded_invoke("person@example.net")
    assert state["prompt"] == "[PII]"
    assert state["answer"] == "Local demo received: [PII]"
    with pytest.raises(Rejected):
        guarded_invoke("ghp_" + "B" * 36)
