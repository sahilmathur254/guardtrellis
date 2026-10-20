"""Bounded synthetic async delivery measurements, not production capacity evidence."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
FIXTURES = HERE.with_name("fixtures_v1.json")
SPEC = spec_from_file_location(
    "concurrency_resource_helpers", ROOT / "evaluation/measure_resources.py"
)
assert SPEC is not None and SPEC.loader is not None
limits = module_from_spec(SPEC)
sys.modules[SPEC.name] = limits
SPEC.loader.exec_module(limits)
EXECUTOR_WORKERS = 4
WARMUPS = 3
WALL_SECONDS = 10.0
TOTAL_SECONDS = 180.0
CELLS = tuple(
    {"family": family, "input_chars": size, "concurrency": concurrency}
    for family in ("allow", "redact", "block")
    for size in (10_000, 100_000)
    for concurrency in (1, 4)
)
ACTION_CODES = {"allow": [], "redact": ["pii_phone"], "block": ["secret_private_key"]}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate metadata key")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def load_fixtures():
    with FIXTURES.open("rb") as source:
        raw = source.read(16_385)
    if len(raw) > 16_384:
        raise ValueError("Invalid fixed fixtures")
    document = decode(raw)
    if (
        not isinstance(document, dict)
        or document.keys()
        != {"dataset_version", "source", "license", "usage", "independent_review", "cases"}
        or document["dataset_version"] != "async-delivery-v1"
        or document["license"] != "Apache-2.0"
        or document["usage"] != "development"
        or document["independent_review"] is not False
        or not isinstance(document["source"], str)
        or not isinstance(document["cases"], list)
        or len(document["cases"]) != 3
    ):
        raise ValueError("Invalid fixed fixtures")
    for case, family in zip(document["cases"], ACTION_CODES, strict=True):
        if (
            not isinstance(case, dict)
            or case.keys()
            != {
                "id",
                "payload",
                "expected_checked",
                "expected_action",
                "expected_codes",
                "label_basis",
            }
            or case["id"] != family
            or case["expected_action"] != family
            or case["expected_codes"] != ACTION_CODES[family]
            or not isinstance(case["payload"], str)
            or not 1 <= len(case["payload"]) <= 500
            or not isinstance(case["label_basis"], str)
            or (family == "block" and case["expected_checked"] is not None)
            or (
                family != "block"
                and (
                    not isinstance(case["expected_checked"], str)
                    or not 1 <= len(case["expected_checked"]) <= 500
                )
            )
        ):
            raise ValueError("Invalid fixed fixtures")
    return {case["id"]: case for case in document["cases"]}


def request_text(case, size, index):
    """Expected content uses authored replacement text, never scanner output."""
    prefix, suffix = f"request-{index:04d}: ", f" end-{index:04d}"
    padding = "." * (size - len(prefix) - len(case["payload"]) - len(suffix))
    text = prefix + case["payload"] + padding + suffix
    expected = (
        None
        if case["expected_checked"] is None
        else prefix + case["expected_checked"] + padding + suffix
    )
    return text, expected, f"receipt-{index:04d}"


def emit(event):
    print(json.dumps(event, separators=(",", ":"), allow_nan=False), flush=True)


async def exercise(policy, case, cell, count, emit_event):
    """One shared immutable policy; admission bounds belong only to this harness."""
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=EXECUTOR_WORKERS)
    )
    semaphore = asyncio.Semaphore(cell["concurrency"])
    active = 0
    maximum = 0

    async def observe(index):
        nonlocal active, maximum
        text, expected, receipt = request_text(case, cell["input_chars"], index)
        callbacks = []

        def callback(checked):
            callbacks.append(checked == expected)
            return receipt

        queued = time.perf_counter()
        async with semaphore:
            started = time.perf_counter()
            active += 1
            maximum = max(maximum, active)
            try:
                result = await policy.arun(text, callback)
                ended = time.perf_counter()
                codes = sorted({finding.code for finding in result.input_result.findings})
                observation = {
                    "index": index,
                    "action": result.action.value,
                    "accepted": result.accepted,
                    "callback_count": len(callbacks),
                    "callback_matches": all(callbacks),
                    "delivery_matches": result.text == (receipt if expected is not None else None),
                    "findings_match": codes == case["expected_codes"]
                    and len(result.input_result.findings) == len(case["expected_codes"]),
                    "error": False,
                }
            except Exception:
                ended = time.perf_counter()
                # Neither exception messages nor repr nor worker-returned data enters reports.
                observation = {
                    "index": index,
                    "action": "error",
                    "accepted": False,
                    "callback_count": len(callbacks),
                    "callback_matches": all(callbacks),
                    "delivery_matches": False,
                    "findings_match": False,
                    "error": True,
                }
            finally:
                active -= 1
            observation.update(
                admission_wait_ms=(started - queued) * 1000,
                arun_ms=(ended - started) * 1000,
            )
        return observation

    warm_started = time.perf_counter()
    warmups = [await observe(count + index) for index in range(WARMUPS)]
    warmup_matches = all(sample_matches(sample, cell) for sample in warmups)
    emit_event(
        {
            "event": "warmup",
            "warmup_ms": (time.perf_counter() - warm_started) * 1000,
            "warmup_matches": warmup_matches,
        }
    )
    maximum = 0
    batch_started = time.perf_counter()

    async def measured(index):
        row = await observe(index)
        emit_event({"event": "sample", **row})

    await asyncio.gather(*(measured(index) for index in range(count)))
    return {"batch_ms": (time.perf_counter() - batch_started) * 1000, "max_active": maximum}


def worker(cell, count):
    applied = limits.apply_limits(cpu_seconds=2, memory_mib=512)
    emit({"event": "limits", "limits": applied})
    started = time.perf_counter()
    from guardtrellis import Action, Guard, PIIScanner, SecretScanner

    case = load_fixtures()[cell["family"]]
    policy = Guard(
        input_scanners=[
            SecretScanner(action=Action.BLOCK),
            PIIScanner(formats=["phone"], action=Action.REDACT, phone_mode="formatted"),
        ]
    )
    emit({"event": "prepared", "setup_ms": (time.perf_counter() - started) * 1000})
    observed = asyncio.run(exercise(policy, case, cell, count, emit))
    # asyncio.run has joined the fixed executor before the final observation is emitted.
    emit({"event": "finished", **observed, "resources": limits.resource_usage()})


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def sample_matches(sample, cell):
    accepted = cell["family"] != "block"
    return (
        sample["action"] == cell["family"]
        and sample["accepted"] == accepted
        and sample["callback_count"] == int(accepted)
        and sample["callback_matches"]
        and sample["delivery_matches"]
        and sample["findings_match"]
        and not sample["error"]
    )


def read_protocol(raw, cell, count):
    """Copy only fully validated metadata; retain valid samples before a bad/stopped event."""
    result = {"samples": [], "protocol_error": False, "worker_error": False}
    phase = "limits"
    seen = set()
    for line in raw.splitlines():
        try:
            event = decode(line)
            if not isinstance(event, dict):
                raise ValueError
            kind = event.get("event")
            if kind == "error" and event == {"event": "error"} and phase != "done":
                result["worker_error"] = True
                phase = "done"
            elif kind == "limits" and phase == "limits":
                values = event.get("limits")
                if (
                    event.keys() != {"event", "limits"}
                    or not isinstance(values, dict)
                    or values.keys()
                    != {"cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes"}
                    or any(value is not None and not number(value) for value in values.values())
                ):
                    raise ValueError
                result["limits"] = values
                phase = "prepared"
            elif kind == "prepared" and phase == "prepared":
                if event.keys() != {"event", "setup_ms"} or not number(event["setup_ms"]):
                    raise ValueError
                result["setup_ms"] = event["setup_ms"]
                phase = "warmup"
            elif kind == "warmup" and phase == "warmup":
                if (
                    event.keys() != {"event", "warmup_ms", "warmup_matches"}
                    or not number(event["warmup_ms"])
                    or type(event["warmup_matches"]) is not bool
                ):
                    raise ValueError
                result.update(warmup_ms=event["warmup_ms"], warmup_matches=event["warmup_matches"])
                phase = "samples"
            elif kind == "sample" and phase == "samples":
                if (
                    event.keys()
                    != {
                        "event",
                        "index",
                        "action",
                        "accepted",
                        "callback_count",
                        "callback_matches",
                        "delivery_matches",
                        "findings_match",
                        "error",
                        "admission_wait_ms",
                        "arun_ms",
                    }
                    or type(event["index"]) is not int
                    or not 0 <= event["index"] < count
                    or event["index"] in seen
                    or event["action"] not in ("allow", "warn", "redact", "block", "error")
                    or type(event["callback_count"]) is not int
                    or not 0 <= event["callback_count"] <= 1
                    or any(
                        type(event[key]) is not bool
                        for key in (
                            "accepted",
                            "callback_matches",
                            "delivery_matches",
                            "findings_match",
                            "error",
                        )
                    )
                    or not number(event["admission_wait_ms"])
                    or not number(event["arun_ms"])
                ):
                    raise ValueError
                seen.add(event["index"])
                sample = {key: value for key, value in event.items() if key != "event"}
                sample["contract_matches"] = sample_matches(sample, cell)
                result["samples"].append(sample)
            elif kind == "finished" and phase == "samples":
                usage = event.get("resources")
                if (
                    event.keys() != {"event", "batch_ms", "max_active", "resources"}
                    or len(seen) != count
                    or not number(event["batch_ms"])
                    or type(event["max_active"]) is not int
                    or event["max_active"] != cell["concurrency"]
                    or not isinstance(usage, dict)
                    or usage.keys() != {"process_cpu_ms", "peak_rss_bytes"}
                    or not number(usage["process_cpu_ms"])
                    or usage["peak_rss_bytes"] is not None
                    and not number(usage["peak_rss_bytes"])
                ):
                    raise ValueError
                result.update(
                    batch_ms=event["batch_ms"], max_active=event["max_active"], resources=usage
                )
                phase = "done"
            else:
                raise ValueError
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            result["protocol_error"] = True
            break
    result["finished"] = phase == "done" and "resources" in result
    result["samples"].sort(key=lambda sample: sample["index"])
    return result


def launch_settings():
    environment = limits.child_environment()
    executable = sys.executable
    if sys.platform == "win32":
        executable = sys._base_executable
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    return executable, environment


def measure(cell_index, count, repeat, deadline):
    cell = CELLS[cell_index]
    budget = max(0, min(WALL_SECONDS, deadline - time.perf_counter()))
    row = {
        "cell": cell,
        "repeat": repeat,
        "status": "not_started",
        "samples": [],
        "expected_samples": count,
        "wall_budget_seconds": budget,
        "child_reaped": None,
    }
    if budget <= 0:
        row["status"] = "total_timeout"
        return row
    executable, environment = launch_settings()
    started = time.perf_counter()
    interrupted = False

    def defer_interrupt(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    handlers = {item: signal.getsignal(item) for item in (signal.SIGINT, signal.SIGTERM)}
    try:
        # A signal must not unwind process creation, reaping or temporary-file cleanup.
        # Record it and finish the current child's bounded cleanup before returning.
        for item in handlers:
            signal.signal(item, defer_interrupt)
        with tempfile.TemporaryDirectory(prefix="guardtrellis-concurrency-") as directory:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                process = None
                try:
                    process = subprocess.Popen(
                        [
                            executable,
                            str(HERE),
                            "--worker",
                            str(cell_index),
                            "--samples",
                            str(count),
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=errors,
                        cwd=directory,
                        env=environment,
                        start_new_session=os.name == "posix",
                    )
                    row["status"] = "worker_error"
                    while True:
                        if interrupted:
                            break
                        if (
                            os.fstat(output.fileno()).st_size > limits.MAX_CAPTURE_BYTES
                            or os.fstat(errors.fileno()).st_size > limits.MAX_CAPTURE_BYTES
                        ):
                            row["status"] = "output_limit"
                            break
                        remaining = budget - (time.perf_counter() - started)
                        if remaining <= 0:
                            row["status"] = "wall_timeout"
                            break
                        try:
                            process.wait(timeout=min(0.05, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                except KeyboardInterrupt:
                    row["status"] = "interrupted"
                finally:
                    if process is not None:
                        limits.kill_and_reap(process)
                        row.update(
                            returncode=process.returncode, child_reaped=process.poll() is not None
                        )
                output.seek(0)
                raw = output.read(limits.MAX_CAPTURE_BYTES + 1)
                row["stderr_bytes"] = os.fstat(errors.fileno()).st_size
        row.update(read_protocol(raw[: limits.MAX_CAPTURE_BYTES], cell, count))
        if len(raw) > limits.MAX_CAPTURE_BYTES:
            row["status"] = "output_limit"
        elif row["status"] == "worker_error":
            if row["protocol_error"]:
                row["status"] = "protocol_error"
            elif row["returncode"] == 0 and row["finished"] and not row["stderr_bytes"]:
                row["status"] = "completed"
            elif os.name == "posix" and row["returncode"] == -signal.SIGXCPU:
                row["status"] = "cpu_limit"
    except KeyboardInterrupt:
        row["status"] = "interrupted"
    except (OSError, subprocess.SubprocessError):
        row["status"] = "supervisor_error"
    finally:
        for item, handler in handlers.items():
            signal.signal(item, handler)
    if interrupted:
        row["status"] = "interrupted"
    row["wall_ms"] = (time.perf_counter() - started) * 1000
    row["contract_matches"] = (
        row["status"] == "completed"
        and row.get("warmup_matches", False)
        and row.get("child_reaped", False)
        and not row.get("worker_error", False)
        and all(sample["contract_matches"] for sample in row["samples"])
    )
    return row


def metadata():
    import guardtrellis

    paths = [HERE, FIXTURES, ROOT / "evaluation/measure_resources.py", ROOT / "uv.lock"]
    paths.extend(sorted((ROOT / "src/guardtrellis").glob("*.py")))
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source_version": guardtrellis.__version__,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "dependencies": {
            name: version(name)
            for name in (
                "guardtrellis",
                "jsonschema",
                "referencing",
                "attrs",
                "rpds-py",
                "jsonschema-specifications",
            )
        },
        "sha256": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths
        },
    }


def summary(values):
    return (
        None
        if not values
        else {
            "count": len(values),
            "median": statistics.median(values),
            "min": min(values),
            "max": max(values),
        }
    )


def summarize(rows):
    result = []
    for cell in CELLS:
        selected = [row for row in rows if row["cell"] == cell]
        samples = [sample for row in selected for sample in row["samples"]]
        result.append(
            {
                "cell": cell,
                "expected_samples": sum(row["expected_samples"] for row in selected),
                "observed_samples": len(samples),
                "matching_samples": sum(sample["contract_matches"] for sample in samples),
                "incomplete_runs": sum(row["status"] != "completed" for row in selected),
                "actions": {
                    action: sum(sample["action"] == action for sample in samples)
                    for action in ("allow", "warn", "redact", "block", "error")
                },
                "accepted": sum(sample["accepted"] for sample in samples),
                "rejected": sum(not sample["accepted"] for sample in samples),
                "arun_ms": summary([sample["arun_ms"] for sample in samples]),
                "admission_wait_ms": summary([sample["admission_wait_ms"] for sample in samples]),
            }
        )
    return result


def render_report(report):
    lines = [
        "# Bounded async checked-delivery baseline, v1",
        "",
        "Authored synthetic development fixtures; no accuracy, capacity, "
        "tail-latency or SLO claim.",
        "Timings include Guard async scheduling and an in-memory callback. "
        "Admission wait is separate.",
        "Repeated requests are timing observations, not independent detector cases.",
        "",
        f"Mode: `{report['configuration']['mode']}`. Measurement checks passed: "
        f"`{report['measurement_checks_passed']}`.",
        "",
        "| Family | Characters | Active limit | Observed / expected | Exact matches | "
        "Incomplete runs | arun median ms (range) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in report["summary"]:
        cell, times = row["cell"], row["arun_ms"]
        timing = (
            "unknown"
            if times is None
            else (f"{times['median']:.3f} ({times['min']:.3f}–{times['max']:.3f})")
        )
        lines.append(
            f"| {cell['family']} | {cell['input_chars']} | {cell['concurrency']} | "
            f"{row['observed_samples']} / {row['expected_samples']} | {row['matching_samples']} | "
            f"{row['incomplete_runs']} | {timing} |"
        )
    lines.extend(
        [
            "",
            "Stopped, failed and missing samples remain in results.json "
            "and are not zero-duration successes.",
            "CPU/RSS are whole-process observations; unavailable measurements are null.",
            "Raw metadata, startup/setup/warmup boundaries, outcomes and hashes "
            "are in results.json.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--worker", type=int, choices=range(len(CELLS)), help=argparse.SUPPRESS)
    parser.add_argument("--samples", type=int, choices=(4, 20), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker is not None:
        if args.samples is None or args.report_dir is not None or args.smoke:
            parser.error("Invalid worker invocation")
        try:
            worker(CELLS[args.worker], args.samples)
            return 0
        except Exception:
            emit({"event": "error"})
            return 1
    if args.samples is not None or args.report_dir is None:
        parser.error("--report-dir is required; choose a new directory")
    if args.report_dir.exists():
        parser.error("Report directory already exists; choose a new directory")
    count, repetitions = (4, 1) if args.smoke else (20, 3)
    deadline = time.perf_counter() + TOTAL_SECONDS
    try:
        load_fixtures()
        provenance = metadata()
    except Exception:
        parser.exit(1, "Cannot prepare fixed evaluation metadata.\n")
    rows = []
    report = {
        "schema_version": 1,
        "dataset_version": "async-delivery-v1",
        "fixture_provenance": {
            "usage": "development",
            "authorship": "AI-assisted synthetic",
            "independent_review": False,
            "license": "Apache-2.0",
        },
        "metadata": provenance,
        "configuration": {
            "mode": "smoke" if args.smoke else "full",
            "samples_per_cell": count,
            "repetitions": repetitions,
            "warmups_per_child": WARMUPS,
            "executor_workers": EXECUTOR_WORKERS,
            "child_wall_seconds": WALL_SECONDS,
            "total_wall_seconds": TOTAL_SECONDS,
            "cleanup_allowance_seconds": 5,
            "cpu_seconds": 2,
            "memory_mib": 512,
        },
        "runs": rows,
        "interrupted": False,
    }

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    old_handler = signal.signal(signal.SIGTERM, interrupt)
    try:
        for repeat in range(repetitions):
            for cell_index in range(len(CELLS)):
                if report["interrupted"]:
                    rows.append(
                        {
                            "cell": CELLS[cell_index],
                            "repeat": repeat,
                            "status": "not_started",
                            "samples": [],
                            "expected_samples": count,
                            "child_reaped": None,
                        }
                    )
                    continue
                row = measure(cell_index, count, repeat, deadline)
                rows.append(row)
                if row["status"] == "interrupted":
                    report["interrupted"] = True
    except KeyboardInterrupt:
        report["interrupted"] = True
    finally:
        signal.signal(signal.SIGTERM, old_handler)
    # An interrupt between child runs must not erase the remaining planned denominator.
    scheduled = {(row["repeat"], CELLS.index(row["cell"])) for row in rows}
    for repeat in range(repetitions):
        for cell_index, cell in enumerate(CELLS):
            if (repeat, cell_index) not in scheduled:
                rows.append(
                    {
                        "cell": cell,
                        "repeat": repeat,
                        "status": "not_started",
                        "samples": [],
                        "expected_samples": count,
                        "child_reaped": None,
                    }
                )
    report["measurement_checks_passed"] = (
        not report["interrupted"]
        and len(rows) == repetitions * len(CELLS)
        and all(row.get("contract_matches", False) for row in rows)
    )
    report["summary"] = summarize(rows)
    args.report_dir.mkdir(parents=True, exist_ok=False)
    (args.report_dir / "results.json").write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    (args.report_dir / "REPORT.md").write_text(render_report(report), encoding="utf-8")
    return 130 if report["interrupted"] else (0 if report["measurement_checks_passed"] else 1)


if __name__ == "__main__":
    raise SystemExit(main())
