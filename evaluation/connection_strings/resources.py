"""Fixed connection-URI resource probes under parent deadlines, not capacity claims."""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

HERE = Path(__file__).resolve()
SPEC = spec_from_file_location(
    "connection_resource_helpers", HERE.parents[1] / "measure_resources.py"
)
assert SPEC is not None and SPEC.loader is not None
limits = module_from_spec(SPEC)
sys.modules[SPEC.name] = limits
SPEC.loader.exec_module(limits)
MODES = ("direct", "guard")
WALL_SECONDS = 10
URI_CODE = "secret_postgresql_uri"
LIMIT_CODE = "connection_string_limit_exceeded"
TOKEN_CODE = "secret_github_classic"


def scenarios(mode):
    """Authored dimensions and expectations are independent of detector constants/results."""
    if mode not in MODES:
        raise ValueError("Unknown connection resource mode")
    uri = "postgresql://demo:ResourceFixture7@db.example.invalid/demo"
    benign = "postgresql://db.example.invalid/demo "
    malformed = "postgresql://demo:missing_at "
    token = "ghp_" + "A" * 36 + " "
    query = "postgresql://db.example.invalid/demo?"
    input_code = LIMIT_CODE if mode == "direct" else "text_limit_exceeded"
    return (
        ("maximum_text", "a" * 100_000, "allow", 0, []),
        ("over_maximum_text", "a" * 100_001, "error", 1, [input_code]),
        ("long_near_matches", ("postgresql:/ " * 8_000)[:100_000], "allow", 0, []),
        ("late_credential", "a" * (99_999 - len(uri)) + " " + uri, "block", 1, [URI_CODE]),
        ("candidate_2048", uri.ljust(2_048, "p"), "block", 1, [URI_CODE]),
        ("candidate_8192", uri.ljust(8_192, "p"), "block", 1, [URI_CODE]),
        ("candidate_8193", uri.ljust(8_193, "p"), "error", 1, [LIMIT_CODE]),
        ("candidate_32768", uri.ljust(32_768, "p"), "error", 1, [LIMIT_CODE]),
        ("long_query_key", query + "p" * 8_000 + "=v&password=x", "block", 1, [URI_CODE]),
        (
            "long_encoded_key",
            query + "%70" * 2_660 + "=v&password=x",
            "block",
            1,
            [URI_CODE],
        ),
        (
            "malformed_pairs_then_password",
            query + "%ZZ=ignored&" * 600 + "password=x",
            "block",
            1,
            [URI_CODE],
        ),
        ("benign_candidates_256", benign * 256, "allow", 0, []),
        ("benign_candidates_257", benign * 257, "error", 1, [LIMIT_CODE]),
        ("malformed_candidates_256", malformed * 256, "allow", 0, []),
        ("malformed_candidates_257", malformed * 257, "error", 1, [LIMIT_CODE]),
        (
            "combined_findings_256",
            token * 255 + uri,
            "block",
            256,
            sorted([TOKEN_CODE, URI_CODE]),
        ),
        ("combined_findings_257", token * 256 + uri, "error", 1, ["finding_limit_exceeded"]),
        # One uninterrupted candidate: a monotonic walker must not rescan every suffix.
        ("nested_scheme_suffix", "postgresql://" * 600 + "public", "allow", 0, []),
    )


def worker(mode):
    applied = limits.apply_limits(cpu_seconds=2, memory_mib=512)
    from guardtrellis import Action, Guard, SecretScanner, Stage

    scanner = SecretScanner(connection_strings=True)
    guard = Guard(input_scanners=[scanner])
    rows = []
    for name, text, expected, _, _ in scenarios(mode):
        started = time.perf_counter()
        result = scanner.scan(text, stage=Stage.INPUT) if mode == "direct" else guard.scan(text)
        accepted = result.action not in (Action.BLOCK, Action.ERROR)
        rows.append(
            {
                "scenario": name,
                "input_chars": len(text),
                "operation_ms": (time.perf_counter() - started) * 1000,
                "expected_action": expected,
                "action": result.action.value,
                "accepted": accepted,
                # A direct Check has no text field or payload-delivery API.
                "has_deliverable_text": None if mode == "direct" else result.text is not None,
                "finding_count": len(result.findings),
                "finding_codes": sorted({item.code for item in result.findings}),
                "error_spanless": result.action != Action.ERROR
                or all(item.start is None and item.end is None for item in result.findings),
            }
        )
    return {"limits": applied, "resources": limits.resource_usage(), "rows": rows}


def finite_nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_observations(observed, mode):
    """Validate the fixed protocol before copying any child-supplied fields into reports."""
    if (
        not isinstance(observed, dict)
        or observed.keys() != {"limits", "resources", "rows"}
        or not isinstance(observed["limits"], dict)
        or observed["limits"].keys()
        != {"cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes"}
        or not isinstance(observed["resources"], dict)
        or observed["resources"].keys() != {"process_cpu_ms", "peak_rss_bytes"}
        or observed["resources"]["process_cpu_ms"] is None
        or any(
            value is not None and not finite_nonnegative(value)
            for value in [*observed["limits"].values(), *observed["resources"].values()]
        )
        or not isinstance(observed["rows"], list)
        or len(observed["rows"]) != len(scenarios(mode))
    ):
        raise ValueError("Invalid worker metadata")
    matches = []
    for row, (name, text, action, count, codes) in zip(
        observed["rows"], scenarios(mode), strict=True
    ):
        if (
            not isinstance(row, dict)
            or row.keys()
            != {
                "scenario",
                "input_chars",
                "operation_ms",
                "expected_action",
                "action",
                "accepted",
                "has_deliverable_text",
                "finding_count",
                "finding_codes",
                "error_spanless",
            }
            or row["scenario"] != name
            or row["expected_action"] != action
            or type(row["input_chars"]) is not int
            or row["input_chars"] != len(text)
            or not finite_nonnegative(row["operation_ms"])
            or row["action"] not in ("allow", "warn", "redact", "block", "error")
            or type(row["accepted"]) is not bool
            or (mode == "direct" and row["has_deliverable_text"] is not None)
            or (mode == "guard" and type(row["has_deliverable_text"]) is not bool)
            or type(row["finding_count"]) is not int
            or not 0 <= row["finding_count"] <= 256
            or not isinstance(row["finding_codes"], list)
            or any(
                code
                not in {
                    URI_CODE,
                    TOKEN_CODE,
                    LIMIT_CODE,
                    "finding_limit_exceeded",
                    "text_limit_exceeded",
                    "scanner_error",
                    "connection_string_configuration_error",
                }
                for code in row["finding_codes"]
            )
            or row["finding_codes"] != sorted(set(row["finding_codes"]))
            or type(row["error_spanless"]) is not bool
        ):
            raise ValueError("Invalid worker observation")
        accepted = action == "allow"
        matches.append(
            row["action"] == action
            and row["accepted"] == accepted
            and row["has_deliverable_text"] == (None if mode == "direct" else accepted)
            and row["finding_count"] == count
            and row["finding_codes"] == codes
            and row["error_spanless"]
        )
    return all(matches)


def measure(mode):
    if mode not in MODES:
        raise ValueError("Unknown connection resource mode")
    executable, environment = sys.executable, limits.child_environment()
    if sys.platform == "win32":
        executable = sys._base_executable
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    row = {"mode": mode, "wall_budget_seconds": WALL_SECONDS, "status": "worker_error"}
    with tempfile.TemporaryDirectory(prefix="guardtrellis-connection-resource-") as directory:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            started = time.perf_counter()
            process = subprocess.Popen(
                [executable, str(HERE), "--worker", mode],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                cwd=directory,
                env=environment,
                start_new_session=os.name == "posix",
            )
            try:
                process.wait(timeout=WALL_SECONDS)
            except subprocess.TimeoutExpired:
                row["status"] = "wall_timeout"
            finally:
                limits.kill_and_reap(process)
            row.update(
                wall_ms=(time.perf_counter() - started) * 1000,
                returncode=process.returncode,
                child_reaped=process.poll() is not None,
            )
            output.seek(0)
            captured = output.read(limits.MAX_CAPTURE_BYTES + 1)
            errors.seek(0, os.SEEK_END)
            row["stderr_bytes"] = errors.tell()
    if row["status"] != "wall_timeout":
        if os.name == "posix" and process.returncode == -signal.SIGXCPU:
            row["status"] = "cpu_limit"
        elif process.returncode is not None and process.returncode < 0:
            row["status"] = "worker_signal"
        elif process.returncode == 0 and not row["stderr_bytes"]:
            try:
                if len(captured) > limits.MAX_CAPTURE_BYTES:
                    raise ValueError("Worker output exceeds limit")
                observed = json.loads(captured)
                matches = validate_observations(observed, mode)
                row.update(status="completed", contract_matches=matches, **observed)
            except (ValueError, KeyError, TypeError, OverflowError):
                row["status"] = "protocol_error"
    row.setdefault("contract_matches", False)
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=MODES, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    if arguments.worker:
        try:
            print(json.dumps(worker(arguments.worker)))
            return 0
        except Exception:
            # Neither payloads nor parser exception text may escape a failed worker.
            print(json.dumps({"worker_error": True}))
            return 1
    rows = [measure(mode) for mode in MODES]
    print(json.dumps(rows, indent=2))
    return int(any(not row["contract_matches"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
