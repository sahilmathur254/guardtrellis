"""Authored URI boundaries at the CLI handoff; preserve unsupported-format outcomes."""

import json

import pytest

from guardtrellis import Stage
from tests.test_cli import capture


# Each positive's entire candidate is expected, not only its password component.
@pytest.mark.parametrize(
    "uri,code",
    [
        ("postgresql://app:Synthetic42@db.invalid/demo", "secret_postgresql_uri"),
        (
            "POSTGRES://app:Synthetic%40Value42@db.invalid:5432/demo?sslmode=require",
            "secret_postgresql_uri",
        ),
        ("postgresql://app:@db.invalid/demo?%70assWORD=Synthetic42", "secret_postgresql_uri"),
        (
            "postgresql://db.invalid/demo?password=&password=Synthetic42#fragment",
            "secret_postgresql_uri",
        ),
        ("postgresql://app:<PASSWORD>@db.invalid/demo", "secret_postgresql_uri"),
        ("mongodb://app:Synthetic42@db1.invalid,db2.invalid/demo", "secret_mongodb_uri"),
        ("mongodb+srv://app:合成42@cluster.invalid/demo?retryWrites=true", "secret_mongodb_uri"),
        ("mongodb://:***@db.invalid/demo", "secret_mongodb_uri"),
    ],
)
@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize("policy", ["secrets", "privacy"])
def test_supported_uris_block_whole_candidate_before_handoff(monkeypatch, uri, code, stage, policy):
    prefix = "Tool returned <"
    text = prefix + uri + "> Contact demo@example.org"
    argv = [
        "check",
        "--stdin",
        "--stage",
        stage.value,
        "--policy",
        policy,
        "--connection-strings",
        "--format",
        "json",
        "--output",
        "checked-text",
    ]
    status, stdout, stderr, _, _ = capture(monkeypatch, argv, text.encode())
    assert status == 1 and stdout == b""
    report = json.loads(stderr)
    assert report["error"] is None
    result = report["result"]
    assert result["action"] == "block"
    assert [(item["code"], item["start"], item["end"]) for item in result["findings"]] == [
        (code, len(prefix), len(prefix) + len(uri))
    ]
    assert len(result["trace"]) == 1  # Secret block precedes the privacy redactor.
    assert b"Synthetic" not in stderr and uri.encode() not in stderr


@pytest.mark.parametrize(
    "text",
    [
        "postgresql://app:@db.invalid/demo",  # Empty password.
        "mongodb://app@db.invalid/demo",  # Username only.
        "postgresql://db.invalid/demo?password=",  # Empty query password.
        "postgresql://db.invalid/demo?password_hint=Synthetic42",  # Exact key only.
        "postgresql://db.invalid/demo?%2570assword=Synthetic42",  # No repeated decoding.
        "mongodb://db.invalid/demo?password=Synthetic42",  # Query-only MongoDB excluded.
        "mysql://app:Synthetic42@db.invalid/demo",  # Driver excluded.
        "Server=db.invalid;User Id=app;Password=Synthetic42",  # Keyword syntax excluded.
        r"postgresql:\/\/app:Synthetic42@db.invalid/demo",  # Escaped JSON stays raw.
        "https://app:Synthetic42@db.invalid/demo",  # Generic URLs excluded.
    ],
)
def test_empty_passwords_and_explicit_exclusions_remain_allowed(monkeypatch, text):
    argv = [
        "check",
        "--stdin",
        "--stage",
        "retrieval",
        "--policy",
        "secrets",
        "--connection-strings",
        "--format",
        "json",
        "--output",
        "checked-text",
    ]
    status, stdout, stderr, _, _ = capture(monkeypatch, argv, text.encode())
    assert status == 0 and stdout == text.encode()
    report = json.loads(stderr)
    assert report["result"]["action"] == "allow" and report["result"]["findings"] == []


def test_default_does_not_claim_uri_coverage_and_manual_decoding_is_explicit(monkeypatch):
    uri = "postgresql://app:Synthetic42@db.invalid/demo"
    argv = [
        "check",
        "--stdin",
        "--stage",
        "input",
        "--policy",
        "secrets",
        "--format",
        "json",
        "--output",
        "checked-text",
    ]
    status, stdout, stderr, _, _ = capture(monkeypatch, argv, uri.encode())
    assert status == 0 and stdout == uri.encode()
    assert json.loads(stderr)["options"]["connection_strings"] is False
    raw = r'"postgresql:\/\/app:Synthetic42@db.invalid/demo"'
    decoded = json.loads(raw)
    status, stdout, stderr, _, _ = capture(
        monkeypatch, argv + ["--connection-strings"], decoded.encode()
    )
    assert status == 1 and stdout == b""
    assert json.loads(stderr)["result"]["findings"][0]["end"] == len(uri)
