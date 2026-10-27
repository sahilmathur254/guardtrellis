"""Strict CI keeps PII coverage and rejects malformed, mismatched or failed reports."""

import copy
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from examples import cli_ci
from tests.test_cli import BASE, capture


def clean_report(monkeypatch):
    argv = BASE + ["--connection-strings", "--phone-mode", "formatted"]
    status, stdout, stderr, _, _ = capture(monkeypatch, argv)
    assert status == 0 and not stderr
    return stdout


@pytest.mark.parametrize(
    "text,clean",
    [
        (b"Opening hours: 9am to 5pm.", True),
        (b"Contact demo@example.org", False),
        (b"Call +1 (202) 555-0123", False),
        (b"postgresql://app:Synthetic42@db.invalid/demo", False),
    ],
)
def test_real_example_gate(tmp_path, text, clean):
    source = tmp_path / "fixture.txt"
    source.write_bytes(text)
    completed = subprocess.run(
        [sys.executable, str(Path(cli_ci.__file__)), str(source)], capture_output=True, timeout=20
    )
    assert completed.returncode == (0 if clean else 1)
    assert not completed.stdout and not completed.stderr and source.read_bytes() == text


@pytest.mark.parametrize(
    "field,value",
    [
        ("report_version", True),
        ("report_version", 2),
        ("sdk_version", ""),
        ("stage", "input"),
        ("policy", "secrets"),
        ("options", None),
        ("options", {"connection_strings": 1, "phone_mode": "formatted"}),
        ("options", {"connection_strings": False, "phone_mode": "formatted"}),
        ("result", None),
        ("result", []),
        ("error", {"code": "runtime_error"}),
    ],
)
def test_envelope_mismatch_fails(monkeypatch, field, value):
    original = clean_report(monkeypatch)
    assert cli_ci.clean_privacy_report(original)
    report = json.loads(original)
    report[field] = value
    assert not cli_ci.clean_privacy_report((json.dumps(report) + "\n").encode())


def test_malformed_duplicate_extra_or_incomplete_reports_fail(monkeypatch):
    original = clean_report(monkeypatch)
    for payload in (
        b"",
        b"null\n",
        b"[]\n",
        b"NaN\n",
        b"\xff\n",
        original[:-1],
        original + b"\n",
        original + original,
        original.replace(b"\n", b"\r\n"),
        original.replace(b'"report_version":1', b'"report_version":1,"report_version":1'),
        b"x" * (128 * 1024 + 1),
    ):
        assert not cli_ci.clean_privacy_report(payload)
    report = json.loads(original)
    for altered in (
        {**report, "extra": 1},
        {key: value for key, value in report.items() if key != "error"},
    ):
        assert not cli_ci.clean_privacy_report((json.dumps(altered) + "\n").encode())
    for field, value in (
        ("findings", [{"code": "pii_email"}]),
        ("action", "redact"),
        ("action", "block"),
        ("action", "error"),
        ("trace", None),
        ("stage", "tool"),
    ):
        altered = copy.deepcopy(report)
        altered["result"][field] = value
        assert not cli_ci.clean_privacy_report((json.dumps(altered) + "\n").encode())


@pytest.mark.parametrize("failure", ["nonzero", "stderr", "timeout", "missing"])
def test_child_failure_is_rejected_without_logging(monkeypatch, failure):
    payload = clean_report(monkeypatch)

    def fake_run(command, **kwargs):
        assert "privacy" in command and "--connection-strings" in command
        assert kwargs["timeout"] == 15 and kwargs["capture_output"] is True
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 15)
        if failure == "missing":
            raise OSError("DoNotDisclose42")
        return SimpleNamespace(
            returncode=3 if failure == "nonzero" else 0,
            stdout=payload,
            stderr=b"unexpected" if failure == "stderr" else b"",
        )

    monkeypatch.setattr(cli_ci.subprocess, "run", fake_run)
    assert cli_ci.main(Path("fixture.txt")) == 1
