"""Bounded synthetic resource measurements, not a capacity or security certification."""

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
import threading
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

HERE = Path(__file__).resolve()
MAX_CAPTURE_BYTES = 65_536


@dataclass(frozen=True)
class Scenario:
    name: str
    kind: str
    size: int
    expected_action: str | None = "allow"


SCENARIOS = (
    Scenario("text_at_limit", "text", 100_000),
    Scenario("text_over_limit", "text", 100_001, "error"),
    Scenario("pii_at_finding_limit", "pii", 256, "redact"),
    Scenario("pii_over_finding_limit", "pii", 257, "error"),
    Scenario("literal_max_configuration", "literal", 128),
    Scenario("json_at_default_depth", "json", 32),
    Scenario("json_over_default_depth", "json", 33, "block"),
    Scenario("json_at_maximum_depth", "json", 64),
    Scenario("json_over_maximum_depth", "json", 65, "block"),
    Scenario("schema_at_size_limit", "schema_size", 100_000),
    Scenario("nested_schema", "nested", 24),
    Scenario("reference_fanout_small", "references", 8),
    Scenario("reference_fanout_large", "references", 20),
    Scenario("wide_anyof_mismatch", "anyof", 128, "block"),
    Scenario("unique_object_array", "unique", 500),
    Scenario("sync_callback_timeout", "async", 0, "error"),
    Scenario("sync_scanner_timeout", "async", 0, "error"),
    Scenario("caller_cancels_sync_callback", "async", 0, None),
    Scenario("callback_suppresses_cancellation", "async", 0, "error"),
    Scenario("callback_blocks_event_loop", "async", 0, None),
    Scenario("supervisor_wall_timeout", "supervisor", 0, None),
)
BY_NAME = {case.name: case for case in SCENARIOS}


def apply_limits(cpu_seconds, memory_mib):
    """Only lower child limits; unsupported limits remain explicitly unavailable."""
    limits = {
        "cpu_seconds": None,
        "address_space_bytes": None,
        "core_bytes": None,
        "output_file_bytes": None,
    }
    try:
        import resource
    except ImportError:
        return limits

    def lower(resource_id, soft, hard):
        old_soft, old_hard = resource.getrlimit(resource_id)
        if old_hard != resource.RLIM_INFINITY:
            hard = min(hard, old_hard)
        if old_soft != resource.RLIM_INFINITY:
            soft = min(soft, old_soft)
        resource.setrlimit(resource_id, (min(soft, hard), hard))
        return resource.getrlimit(resource_id)[0]

    # Failure to apply an advertised limit is a worker error, never silently ignored.
    limits["cpu_seconds"] = lower(resource.RLIMIT_CPU, cpu_seconds, cpu_seconds + 1)
    limits["core_bytes"] = lower(resource.RLIMIT_CORE, 0, 0)
    limits["output_file_bytes"] = lower(resource.RLIMIT_FSIZE, MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES)
    if sys.platform.startswith("linux"):
        cap = memory_mib * 1024 * 1024
        limits["address_space_bytes"] = lower(resource.RLIMIT_AS, cap, cap)
    return limits


def resource_usage():
    usage = {"process_cpu_ms": time.process_time() * 1000, "peak_rss_bytes": None}
    try:
        import resource
    except ImportError:
        return usage
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        usage["peak_rss_bytes"] = peak
    elif sys.platform.startswith("linux"):
        usage["peak_rss_bytes"] = peak * 1024
    return usage


def result_metadata(result):
    from guardtrellis import RunResult

    checks = (
        [result.input_result, result.output_result] if isinstance(result, RunResult) else [result]
    )
    findings = [finding for check in checks if check is not None for finding in check.findings]
    return {
        "action": result.action.value,
        "accepted": result.accepted,
        "has_deliverable_text": result.text is not None,
        "finding_count": len(findings),
        "finding_codes": sorted({item.code for item in findings}),
    }


def measure_sync(case):
    from guardtrellis import Guard, InvisibleScanner, JSONScanner, LiteralScanner, PIIScanner

    before = time.perf_counter()
    schema = None
    dimensions = {"max_chars": 100_000}
    if case.kind == "text":
        text = ("plain text " * 10_001)[: case.size]
        scanners = [PIIScanner(), InvisibleScanner()]
    elif case.kind == "pii":
        text = ("demo@example.org " * case.size).ljust(100_000, ".")
        scanners = [PIIScanner()]
        dimensions["email_occurrences"] = case.size
    elif case.kind == "literal":
        text = "a" * 100_000
        scanners = [LiteralScanner([f"{i:03d}" + "a" * 1020 + "z" for i in range(case.size)])]
        dimensions.update(literal_count=case.size, literal_chars_each=1024)
    elif case.kind == "json":
        text = "[" * case.size + "0" + "]" * case.size
        depth_limit = 32 if case.size <= 33 else 64
        scanners = [JSONScanner(max_depth=depth_limit)]
        dimensions.update(container_depth=case.size, max_depth=depth_limit)
    else:
        if case.kind == "schema_size":
            schema = {"type": "integer", "description": ""}
            schema["description"] = "a" * (case.size - len(json.dumps(schema)))
            text = "0"
        elif case.kind == "nested":
            schema = {"type": "integer"}
            for _ in range(case.size):
                schema = {"type": "array", "items": schema}
            text = "[" * case.size + "0" + "]" * case.size
            dimensions["schema_array_depth"] = case.size
        elif case.kind == "references":
            definitions = {"n0": {"type": "integer"}}
            for i in range(1, case.size + 1):
                definitions[f"n{i}"] = {"allOf": [{"$ref": f"#/$defs/n{i - 1}"} for _ in range(2)]}
            schema = {"$defs": definitions, "$ref": f"#/$defs/n{case.size}"}
            text = "0"
            dimensions.update(reference_levels=case.size, potential_leaf_visits=2**case.size)
        elif case.kind == "anyof":
            schema = {"anyOf": [{"const": i} for i in range(case.size)]}
            text = "-1"
            dimensions["schema_branches"] = case.size
        elif case.kind == "unique":
            schema = {"type": "array", "uniqueItems": True, "items": {"type": "object"}}
            text = json.dumps([{"i": i} for i in range(case.size)])
            dimensions["array_items"] = case.size
        else:
            raise ValueError("Unknown fixed scenario")
        scanners = [JSONScanner(schema)]
        dimensions["schema_chars"] = len(json.dumps(schema))
    guard = Guard(input_scanners=scanners)
    dimensions["input_chars"] = len(text)
    setup_ms = (time.perf_counter() - before) * 1000
    print(
        json.dumps({"event": "prepared", "dimensions": dimensions, "setup_ms": setup_ms}),
        flush=True,
    )
    started = time.perf_counter()
    result = guard.scan(text)
    return {
        "dimensions": dimensions,
        "setup_ms": setup_ms,
        "operation_ms": (time.perf_counter() - started) * 1000,
        **result_metadata(result),
    }


async def measure_async(case):
    from guardtrellis import Check, Guard

    timeout = 0.1
    observation = {"dimensions": {"input_chars": 1, "guard_timeout_seconds": timeout}}
    if case.name in {
        "sync_callback_timeout",
        "sync_scanner_timeout",
        "caller_cancels_sync_callback",
    }:
        release = threading.Event()
        ended = threading.Event()
        started = asyncio.Event()
        loop = asyncio.get_running_loop()

        def worker(_):
            loop.call_soon_threadsafe(started.set)
            release.wait(3)
            ended.set()
            return "complete"

        class Scanner:
            name = "controlled_worker"

            def scan(self, text, *, stage):
                worker(text)
                return Check()

        cancellation = case.name == "caller_cancels_sync_callback"
        if cancellation:
            timeout = 3.0
            observation["dimensions"]["guard_timeout_seconds"] = timeout
        guard = Guard(
            timeout_seconds=timeout, input_scanners=[Scanner()] if "scanner" in case.name else []
        )
        pending = asyncio.create_task(
            guard.ascan("x") if "scanner" in case.name else guard.arun("x", worker)
        )
        before = time.perf_counter()
        try:
            if cancellation:
                await asyncio.wait_for(started.wait(), 2)
                before = time.perf_counter()
                pending.cancel()
            try:
                result = await pending
                observation.update(result_metadata(result))
            except asyncio.CancelledError:
                observation["caller_cancellation_propagated"] = True
            observation.update(
                operation_ms=(time.perf_counter() - before) * 1000,
                worker_started=started.is_set(),
                worker_running_after_await=started.is_set() and not ended.is_set(),
            )
        finally:
            cleanup = time.perf_counter()
            release.set()
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            if started.is_set():
                observation["worker_finished_after_release"] = await asyncio.to_thread(
                    ended.wait, 2
                )
            observation["cleanup_ms"] = (time.perf_counter() - cleanup) * 1000
        return observation

    if case.name == "callback_suppresses_cancellation":
        cancelled = asyncio.Event()
        release_async = asyncio.Event()
        finished = asyncio.Event()

        async def callback(_):
            try:
                await asyncio.sleep(3)
            except asyncio.CancelledError:
                cancelled.set()
                await release_async.wait()
            finally:
                finished.set()
            return "late"

        before = time.perf_counter()
        try:
            result = await Guard(timeout_seconds=timeout).arun("x", callback)
            observation.update(result_metadata(result))
            observation["operation_ms"] = (time.perf_counter() - before) * 1000
            await asyncio.wait_for(cancelled.wait(), 2)
            observation["callback_running_after_await"] = not finished.is_set()
        finally:
            release_async.set()
            await asyncio.wait_for(finished.wait(), 2)
        observation["callback_finished_after_release"] = finished.is_set()
        return observation

    async def blocking_callback(_):
        # Deliberately occupy the event loop in this disposable child only.
        time.sleep(0.3)  # noqa: ASYNC251 - the isolated measurement deliberately blocks the loop.
        return "complete"

    before = time.perf_counter()
    result = await Guard(timeout_seconds=timeout).arun("x", blocking_callback)
    observation.update(result_metadata(result))
    observation.update(operation_ms=(time.perf_counter() - before) * 1000)
    observation["dimensions"]["event_loop_block_seconds"] = 0.3
    return observation


def worker_main(case, cpu_seconds, memory_mib):
    try:
        limits = apply_limits(cpu_seconds, memory_mib)
        print(json.dumps({"event": "limits", "limits": limits}), flush=True)
        if case.kind == "supervisor":
            time.sleep(60)
            return 1
        if case.kind == "async":
            observation = asyncio.run(measure_async(case))
        else:
            observation = measure_sync(case)
        print(
            json.dumps(
                {"event": "result", "observation": observation, "resources": resource_usage()}
            ),
            flush=True,
        )
        return 0
    except Exception as exc:
        # Exception messages, tracebacks, inputs, environment and paths are never reported.
        print(json.dumps({"event": "error", "error_type": type(exc).__name__}), flush=True)
        return 1


def child_environment():
    allowed = ("PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR")
    return {
        **{name: os.environ[name] for name in allowed if name in os.environ},
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
    }


def kill_and_reap(process):
    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
    # A child contains only fixed scenarios and threads, never nested processes.
    process.wait(timeout=5)


def run_case(case, *, wall_seconds=5.0, cpu_seconds=2, memory_mib=512):
    budget = min(wall_seconds, 1.0) if case.kind == "supervisor" else wall_seconds
    row = {"scenario": asdict(case), "wall_budget_seconds": budget, "status": "worker_error"}
    with tempfile.TemporaryDirectory(prefix="guardtrellis-resource-") as directory:
        # Files avoid unbounded communicate() buffering; only bounded metadata is read back.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            before = time.perf_counter()
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(HERE),
                    "--worker",
                    case.name,
                    "--cpu-seconds",
                    str(cpu_seconds),
                    "--memory-mib",
                    str(memory_mib),
                ],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                cwd=directory,
                env=child_environment(),
                start_new_session=os.name == "posix",
            )
            try:
                try:
                    process.wait(timeout=budget)
                except subprocess.TimeoutExpired:
                    row["status"] = "wall_timeout"
            finally:
                kill_and_reap(process)
            row.update(
                wall_ms=(time.perf_counter() - before) * 1000,
                returncode=process.returncode,
                child_reaped=process.poll() is not None,
            )
            output.seek(0)
            captured = output.read(MAX_CAPTURE_BYTES + 1)
            errors.seek(0, os.SEEK_END)
            row["stderr_bytes"] = errors.tell()
    if len(captured) <= MAX_CAPTURE_BYTES:
        try:
            events = [json.loads(line) for line in captured.splitlines()]
            for event in events:
                if event["event"] == "limits":
                    row["limits"] = event["limits"]
                elif event["event"] == "prepared":
                    row["prepared"] = {
                        "dimensions": event["dimensions"],
                        "setup_ms": event["setup_ms"],
                    }
                elif event["event"] == "result":
                    row.update(observation=event["observation"], resources=event["resources"])
                elif event["event"] == "error":
                    row["error_type"] = event["error_type"]
        except (ValueError, KeyError, TypeError):
            row["protocol_error"] = True
    else:
        row["protocol_error"] = True
    if row["status"] != "wall_timeout":
        if os.name == "posix" and process.returncode == -signal.SIGXCPU:
            row["status"] = "cpu_limit"
        elif process.returncode is not None and process.returncode < 0:
            row["status"] = "worker_signal"
        elif process.returncode == 0 and "observation" in row and not row.get("protocol_error"):
            row["status"] = "completed"
    observation = row.get("observation", {})
    row["contract_matches"] = (
        observation.get("action") == case.expected_action
        if case.expected_action is not None and row["status"] == "completed"
        else None
    )
    return row


def metadata():
    import guardtrellis

    package_hash = hashlib.sha256()
    for path in sorted(Path(guardtrellis.__file__).parent.glob("*.py")):
        package_hash.update(path.name.encode() + b"\0" + path.read_bytes())
    lockfile = HERE.parent.parent / "uv.lock"
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "runner_sha256": hashlib.sha256(HERE.read_bytes()).hexdigest(),
        "package_source_sha256": package_hash.hexdigest(),
        "lock_sha256": hashlib.sha256(lockfile.read_bytes()).hexdigest()
        if lockfile.exists()
        else None,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
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
    }


def render_report(report):
    meta = report["metadata"]
    lines = [
        "# Bounded resource measurements",
        "",
        "Fixed synthetic scenarios; no provider calls, private inputs, or general capacity claims.",
        "CPU/wall stops are retained measurements, not completed Guard checks. "
        "Missing values are unknown.",
        "",
        f"Generated: {meta['generated_at_utc']}",
        f"Runtime: {meta['python']}, {meta['system']} {meta['os_release']}, {meta['machine']}.",
        f"Dependencies: `{json.dumps(meta['dependencies'], sort_keys=True)}`.",
        f"Package source SHA-256: `{meta['package_source_sha256']}`.",
        f"Harness SHA-256: `{meta['runner_sha256']}`.",
        f"Lock SHA-256: `{meta['lock_sha256']}`.",
        f"Configuration: `{json.dumps(report['configuration'], sort_keys=True)}`.",
        "",
        "Each repetition uses a fresh child. Operation times exclude imports and setup; "
        "process wall",
        "times include startup and cleanup. RSS is whole-child peak memory, "
        "not incremental allocations.",
        "Only completed operation samples contribute to the median; "
        "interrupted work is never a zero.",
        "",
        "| Scenario | Completed / runs | Stops or errors | Operation median ms | "
        "Max process wall ms | Max RSS MiB |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for name in dict.fromkeys(row["scenario"]["name"] for row in report["cases"]):
        rows = [row for row in report["cases"] if row["scenario"]["name"] == name]
        completed = [row for row in rows if row["status"] == "completed"]
        times = [row["observation"]["operation_ms"] for row in completed]
        rss = [
            row["resources"]["peak_rss_bytes"]
            for row in completed
            if row["resources"]["peak_rss_bytes"] is not None
        ]
        stops = (
            ", ".join(sorted({row["status"] for row in rows if row["status"] != "completed"}))
            or "none"
        )
        elapsed = f"{statistics.median(times):.3f}" if times else "unknown"
        memory = f"{max(rss) / 1024**2:.2f}" if rss else "unknown"
        lines.append(
            f"| {name} | {len(completed)}/{len(rows)} | {stops} | {elapsed} | "
            f"{max(row['wall_ms'] for row in rows):.1f} | {memory} |"
        )
    lines.extend(["", "## Retained observations", ""])
    for row in report["cases"]:
        observation = row.get("observation", {})
        if row["scenario"]["kind"] == "async" or row["contract_matches"] is False:
            lines.append(
                f"- `{row['scenario']['name']}` repetition {row['repetition']}: "
                f"`{json.dumps(observation, sort_keys=True)}`."
            )
    lines.extend(
        [
            "",
            "All raw samples, setup/cleanup times, resource caps, process exit codes, and errors",
            "are in `results.json`. See the resource-limits guide in `docs/` "
            "for methodology and host controls.",
            "",
        ]
    )
    return "\n".join(lines)


def acceptable_measurement(row):
    if not row["child_reaped"] or row["stderr_bytes"] or row.get("protocol_error"):
        return False
    if row["scenario"]["kind"] == "supervisor":
        return row["status"] == "wall_timeout" and "limits" in row
    if row["status"] in {"wall_timeout", "cpu_limit"}:
        return (
            row["scenario"]["name"] == "reference_fanout_large"
            and "limits" in row
            and "prepared" in row
        )
    if row["status"] != "completed" or row["contract_matches"] is False:
        return False
    observation = row["observation"]
    if observation.get("action") in {"block", "error"} and (
        observation["accepted"] or observation["has_deliverable_text"]
    ):
        return False
    if (
        row["scenario"]["name"].startswith("sync_")
        or row["scenario"]["name"] == "caller_cancels_sync_callback"
    ):
        if not all(
            observation.get(key)
            for key in (
                "worker_started",
                "worker_running_after_await",
                "worker_finished_after_release",
            )
        ):
            return False
    if row["scenario"]["name"] == "caller_cancels_sync_callback":
        return observation.get("caller_cancellation_propagated") is True
    if row["scenario"]["name"] == "callback_suppresses_cancellation":
        return (
            observation.get("callback_running_after_await") is True
            and observation.get("callback_finished_after_release") is True
        )
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--case", choices=BY_NAME, action="append", dest="cases")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--wall-seconds", type=float, default=5.0)
    parser.add_argument("--cpu-seconds", type=int, default=2)
    parser.add_argument("--memory-mib", type=int, default=512)
    parser.add_argument("--worker", choices=BY_NAME, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if (
        not 1 <= args.repetitions <= 5
        or not math.isfinite(args.wall_seconds)
        or not 1 <= args.wall_seconds <= 30
    ):
        parser.error("Use 1-5 repetitions and a finite 1-30 second wall budget")
    if not 1 <= args.cpu_seconds <= 5 or not 256 <= args.memory_mib <= 1024:
        parser.error("Use 1-5 CPU seconds and 256-1024 MiB address-space budget")
    if args.worker:
        return worker_main(BY_NAME[args.worker], args.cpu_seconds, args.memory_mib)
    if args.report_dir is None:
        parser.error("--report-dir is required; choose a new directory outside the checkout")
    if any((args.report_dir / name).exists() for name in ("results.json", "REPORT.md")):
        parser.error(
            "Report files already exist; choose a new directory to preserve earlier evidence"
        )
    cases = [BY_NAME[name] for name in dict.fromkeys(args.cases)] if args.cases else list(SCENARIOS)
    report = {
        "format_version": 1,
        "metadata": metadata(),
        "configuration": {
            "repetitions": args.repetitions,
            "wall_seconds": args.wall_seconds,
            "cpu_seconds": args.cpu_seconds,
            "memory_mib": args.memory_mib,
            "scenario_names": [case.name for case in cases],
        },
        "cases": [],
    }

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    previous_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        for case in cases:
            for repetition in range(1, args.repetitions + 1):
                row = run_case(
                    case,
                    wall_seconds=args.wall_seconds,
                    cpu_seconds=args.cpu_seconds,
                    memory_mib=args.memory_mib,
                )
                row["repetition"] = repetition
                report["cases"].append(row)
                print(f"{case.name} {repetition}: {row['status']}", flush=True)
    except KeyboardInterrupt:
        report["interrupted"] = True
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    report["measurement_checks_passed"] = not report.get("interrupted", False) and all(
        acceptable_measurement(row) for row in report["cases"]
    )
    args.report_dir.mkdir(parents=True, exist_ok=True)
    (args.report_dir / "results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (args.report_dir / "REPORT.md").write_text(render_report(report), encoding="utf-8")
    return 130 if report.get("interrupted") else (0 if report["measurement_checks_passed"] else 1)


if __name__ == "__main__":
    raise SystemExit(main())
