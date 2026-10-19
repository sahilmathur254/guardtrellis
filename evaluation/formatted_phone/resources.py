"""Fixed phone resource probes under a parent deadline; no capacity claims."""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from guardtrellis import Guard, PIIScanner

HERE = Path(__file__).resolve()
SPEC = spec_from_file_location("phone_resource_helpers", HERE.parents[1] / "measure_resources.py")
assert SPEC is not None and SPEC.loader is not None
limits = module_from_spec(SPEC)
sys.modules[SPEC.name] = limits
SPEC.loader.exec_module(limits)
MODES = ("default", "formatted")
WALL_SECONDS = 10


def scenarios():
    # Dimensions and expected actions are authored without calling a detector.
    return (
        ("maximum_text", "a" * 100_000, "allow", "allow"),
        ("over_maximum_text", "a" * 100_001, "error", "error"),
        ("long_digits", "+" + "1" * 99_999, "allow", "allow"),
        ("long_separators", "+1" + " 1" * 49_999, "allow", "allow"),
        ("long_parentheses", "+" + "(" * 99_999, "allow", "allow"),
        ("dense_pluses", "+" * 100_000, "allow", "allow"),
        ("at_finding_limit", ("+1-202-555-0123;" * 256).ljust(100_000, "."), "allow", "redact"),
        ("over_finding_limit", ("+1-202-555-0123;" * 257).ljust(100_000, "."), "allow", "error"),
    )


def worker(mode):
    applied = limits.apply_limits(cpu_seconds=2, memory_mib=512)
    policy = Guard(
        input_scanners=[
            PIIScanner(
                formats=["phone"], **({"phone_mode": "formatted"} if mode == "formatted" else {})
            )
        ]
    )
    rows = []
    for name, text, default, formatted in scenarios():
        started = time.perf_counter()
        result = policy.scan(text)
        rows.append(
            {
                "scenario": name,
                "input_chars": len(text),
                "operation_ms": (time.perf_counter() - started) * 1000,
                "expected_action": formatted if mode == "formatted" else default,
                **limits.result_metadata(result),
            }
        )
    return {"limits": applied, "resources": limits.resource_usage(), "rows": rows}


def validate_observations(observed, mode):
    """Accept only the fixed protocol; expected contracts belong to the parent."""
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
            value is not None
            and (type(value) not in (int, float) or not math.isfinite(value) or value < 0)
            for value in [*observed["limits"].values(), *observed["resources"].values()]
        )
        or not isinstance(observed["rows"], list)
        or len(observed["rows"]) != len(scenarios())
    ):
        raise ValueError("Invalid worker metadata")
    contracts = []
    for result, (name, text, default, formatted) in zip(observed["rows"], scenarios(), strict=True):
        expected = formatted if mode == "formatted" else default
        if (
            not isinstance(result, dict)
            or result.keys()
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
            }
            or result["scenario"] != name
            or result["expected_action"] != expected
            or type(result["input_chars"]) is not int
            or result["input_chars"] != len(text)
            or type(result["operation_ms"]) not in (int, float)
            or not math.isfinite(result["operation_ms"])
            or result["operation_ms"] < 0
            or result["action"] not in ("allow", "warn", "redact", "block", "error")
            or type(result["accepted"]) is not bool
            or type(result["has_deliverable_text"]) is not bool
            or type(result["finding_count"]) is not int
            or result["finding_count"] < 0
            or not isinstance(result["finding_codes"], list)
            or any(
                code not in {"pii_phone", "text_limit_exceeded", "finding_limit_exceeded"}
                for code in result["finding_codes"]
            )
        ):
            raise ValueError("Invalid worker observation")
        finding_count = 256 if expected == "redact" else int(expected == "error")
        contracts.append(
            result["action"] == expected
            and result["accepted"] == (expected != "error")
            and result["has_deliverable_text"] == (expected != "error")
            and result["finding_count"] == finding_count
        )
    return all(contracts)


def measure(mode):
    if mode not in MODES:
        raise ValueError("Unknown phone mode")
    executable, environment = sys.executable, limits.child_environment()
    if sys.platform == "win32":
        executable = sys._base_executable
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    row = {"phone_mode": mode, "wall_budget_seconds": WALL_SECONDS, "status": "worker_error"}
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        started = time.perf_counter()
        process = subprocess.Popen(
            [executable, str(HERE), "--worker", mode],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
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
    if (
        row["status"] != "wall_timeout"
        and process.returncode == 0
        and not row["stderr_bytes"]
        and len(captured) <= limits.MAX_CAPTURE_BYTES
    ):
        try:
            observed = json.loads(captured)
            contract_matches = validate_observations(observed, mode)
            row.update(status="completed", contract_matches=contract_matches, **observed)
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
            # Neither exceptions nor traceback may echo fixture data.
            print(json.dumps({"worker_error": True}))
            return 1
    rows = [measure(mode) for mode in MODES]
    print(json.dumps(rows, indent=2))
    return int(any(not row["contract_matches"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
