"""Shared, explicit dependency profiles for the Gemini compatibility checks."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("minimum", "locked")
MINIMUM = {"google-genai": "3.0.0", "httpx2": "2.12.0"}


def profile_constraints(work: Path, profile: str) -> tuple[Path, dict[str, str]]:
    """Constrain consumer installs; a project uv sync cannot constrain another venv."""
    if profile not in PROFILES:
        raise ValueError("Unknown Gemini dependency profile")
    requirements = work / f"gemini-{profile}.txt"
    if profile == "minimum":
        requirements.write_bytes((ROOT / "scripts/constraints/gemini-minimum.txt").read_bytes())
        return requirements, MINIMUM.copy()
    subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--extra",
            "gemini",
            "--no-emit-project",
            "--no-hashes",
            "--output-file",
            str(requirements),
        ],
        cwd=ROOT,
        check=True,
    )
    text = requirements.read_text(encoding="utf-8")
    expected = {}
    for name in MINIMUM:
        versions = set(re.findall(rf"^{re.escape(name)}==([^\s;\\]+)", text, re.MULTILINE))
        if len(versions) != 1:
            raise ValueError("Locked Gemini profile must select one direct package version")
        expected[name] = versions.pop()
    return requirements, expected


def fresh_environment(work: Path) -> Path:
    environment = work / "venv"
    subprocess.run(["uv", "venv", "--python", sys.executable, str(environment)], check=True)
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def build_options(python: Path, work: Path, artifact: Path) -> list[str]:
    """Install only reviewed build tooling into source-archive environments."""
    if artifact.suffix == ".whl":
        return []
    requirements = work / "build-requirements.txt"
    subprocess.run(
        [
            "uv",
            "export",
            "--locked",
            "--only-group",
            "build",
            "--no-emit-project",
            "--output-file",
            str(requirements),
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "--requirements",
            str(requirements),
        ],
        cwd=work,
        check=True,
    )
    return ["--no-build-isolation-package", "guardtrellis"]


def assert_gemini_profile(python: Path, work: Path, expected: dict[str, str]) -> None:
    """Check installed versions and the actual socket-forbidden default client path.

    The SDK-private client inspection is scoped to the selected SDK 3 test profile;
    application code must not rely on those internals.
    """
    example = work / "gemini_app.py"
    example.write_bytes((ROOT / "examples/gemini_app.py").read_bytes())
    probe = f"""
import json
import runpy
import socket
from importlib.metadata import version
from importlib.util import find_spec
import httpx2

expected = {expected!r}
actual = {{name: version(name) for name in expected}}
assert actual == expected, (actual, expected)
assert actual['google-genai'].split('.')[0] == '3'
for name in ('openai', 'fastapi', 'langgraph', 'httpx'):
    assert find_spec(name) is None, name

def forbidden(*args, **kwargs):
    raise AssertionError('Socket access is forbidden in a Gemini profile check')

socket.create_connection = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.getaddrinfo = forbidden
example = runpy.run_path({str(example)!r})
with example['make_client'](api_key='mock-not-a-credential', transport=None) as client:
    assert isinstance(client._api_client._httpx_client, httpx2.Client)
    assert not client._api_client._httpx_client.is_closed
assert client._api_client._httpx_client.is_closed
print(json.dumps({{'gemini_profile_versions': actual, 'backend': 'httpx2'}}, sort_keys=True))
"""
    subprocess.run([str(python), "-I", "-c", probe], cwd=work, check=True, timeout=30)


def run_mocked_example(python: Path, work: Path, expected: dict[str, str]) -> None:
    """Deliver the copied example's checked mock result, never an ambient live request."""
    example = work / "gemini_app.py"
    runner = f"""
import runpy
import socket
import sys

def forbidden(*args, **kwargs):
    raise AssertionError('Socket access is forbidden in a Gemini profile check')

socket.create_connection = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.getaddrinfo = forbidden
sys.argv = [{str(example)!r}]
runpy.run_path({str(example)!r}, run_name='__main__')
"""
    completed = subprocess.run(
        [str(python), "-I", "-c", runner],
        cwd=work,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    lines = completed.stdout.splitlines()
    report = json.loads(lines[0])
    assert report["mode"] == "mock" and report["passed"]
    assert report["requests"] == 1 and report["blocked_input_prevented_request"]
    assert {name: report["versions"][name] for name in expected} == expected
    assert lines[1:] == ["Contact [PII]"] and not completed.stderr
    print(completed.stdout, end="", flush=True)
