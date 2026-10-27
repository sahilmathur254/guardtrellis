"""Strict zero-findings privacy gate for one explicitly selected UTF-8 fixture.

Run: python examples/cli_ci.py fixture.txt
Exit zero only after a complete, matching CLI report allows the unchanged fixture.
The host deadline bounds the child; captured reports and payloads are never printed.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid report")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("Invalid report")


def clean_privacy_report(payload: bytes) -> bool:
    """Validate the selected version-1 report, without weakening the PII policy."""
    try:
        if (
            type(payload) is not bytes
            or len(payload) > 128 * 1024
            or not payload.endswith(b"\n")
            or payload.count(b"\n") != 1
            or b"\r" in payload
        ):
            return False
        report = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique,
            parse_constant=_constant,
        )
        result = report.get("result") if type(report) is dict else None
        return (
            type(report) is dict
            and set(report)
            == {"report_version", "sdk_version", "stage", "policy", "options", "result", "error"}
            and type(report.get("report_version")) is int
            and report["report_version"] == 1
            and type(report.get("sdk_version")) is str
            and bool(report["sdk_version"])
            and report.get("stage") == "retrieval"
            and report.get("policy") == "privacy"
            and report.get("options") == {"connection_strings": True, "phone_mode": "formatted"}
            and type(report["options"]["connection_strings"]) is bool
            and "error" in report
            and report["error"] is None
            and type(result) is dict
            and set(result) == {"action", "stage", "findings", "trace"}
            and result.get("stage") == "retrieval"
            and result.get("action") == "allow"
            and result.get("findings") == []
            and type(result.get("trace")) is list
        )
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


def main(source: Path) -> int:
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "guardtrellis",
                "check",
                "--file",
                str(source),
                "--stage",
                "retrieval",
                "--policy",
                "privacy",
                "--connection-strings",
                "--phone-mode",
                "formatted",
                "--format",
                "json",
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
        clean = (
            completed.returncode == 0
            and completed.stderr == b""
            and clean_privacy_report(completed.stdout)
        )
    except (OSError, subprocess.TimeoutExpired):
        clean = False
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])) if len(sys.argv) == 2 else 2)
