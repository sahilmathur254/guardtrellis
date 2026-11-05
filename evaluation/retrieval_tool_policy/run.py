"""Bounded offline evaluation of frozen retrieval/tool policy cases; no provider calls."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation.retrieval_tool_policy import assets, contract  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "retrieval_tool_limits", ROOT / "evaluation/measure_resources.py"
)
assert SPEC is not None and SPEC.loader is not None
limits = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = limits
SPEC.loader.exec_module(limits)

WALL_SECONDS = 10.0
TOTAL_SECONDS = 180.0
MAX_CAPTURE_BYTES = 65_536
MAX_REPORT_BYTES = 512 * 1024
LIMIT_KEYS = {"cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes"}
EVENTS = {
    "retrieval_checked",
    "retrieval_delivered",
    "proposer",
    "call_checked",
    "call_delivered",
    "authorize",
    "execute",
    "returned_checked",
    "returned_delivered",
    "consume",
}
COMPARISONS = {
    "diagnostics",
    "events",
    "counts",
    "proposer_input",
    "authorize_pair",
    "execute_pair",
    "consumer_text",
    "terminal",
    "error_boundary",
}
TERMINALS = {
    "accepted",
    "retrieval_rejected",
    "call_rejected",
    "host_denied",
    "return_rejected",
    "callback_error",
    "unexpected_error",
}
ROW_FIELDS = {
    "id",
    "intent",
    "focus",
    "terminal",
    "error_boundary",
    "diagnostics",
    "events",
    "counts",
    "eligible",
    "comparisons",
    "contract_matches",
    "delivery_integrity",
    "diagnostics_private",
    "unexpected_error",
    "desired",
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_identity():
    """Describe actual imported SDK and evaluation source without returning host paths."""
    assets.load_frozen()
    import guardtrellis

    package = Path(guardtrellis.__file__).resolve().parent
    files = {path.name: digest(path.read_bytes()) for path in sorted(package.glob("*.py"))}
    return {
        "sdk_version": guardtrellis.__version__,
        "sdk_sha256": digest(json.dumps(files, sort_keys=True).encode()),
        "lock_sha256": digest((ROOT / "uv.lock").read_bytes()),
        "project_metadata_sha256": digest((ROOT / "pyproject.toml").read_bytes()),
        "resource_helper_sha256": digest((ROOT / "evaluation/measure_resources.py").read_bytes()),
        "core_dependency_versions": {
            name: version(name)
            for name in (
                "attrs",
                "jsonschema",
                "jsonschema-specifications",
                "referencing",
                "rpds-py",
                "typing-extensions",
            )
        },
        "workflow_sha256": digest((HERE / "workflow.py").read_bytes()),
        "runner_sha256": digest(Path(__file__).read_bytes()),
    }


def validate_public_row(row, case, expectation):
    """Validate untrusted worker metadata before retaining any of it in reports."""
    from evaluation.retrieval_tool_policy import workflow

    try:
        if type(row) is not dict or row.keys() != ROW_FIELDS:
            return False
        if any(row[key] != case[key] for key in ("id", "intent", "focus")):
            return False
        if row["terminal"] not in TERMINALS or row["error_boundary"] not in (
            None,
            "authorize",
            "execute",
            "consume",
        ):
            return False
        if (
            type(row["events"]) is not list
            or len(row["events"]) > 12
            or not all(type(event) is str and event in EVENTS for event in row["events"])
        ):
            return False
        counts = row["counts"]
        if type(counts) is not dict or counts.keys() != {
            "proposer",
            "authorize",
            "execute",
            "consume",
        }:
            return False
        if not all(type(value) is int and 0 <= value <= 2 for value in counts.values()):
            return False
        for key in counts:
            if row["events"].count(key) != counts[key]:
                return False
        diagnostics = row["diagnostics"]
        if type(diagnostics) is not dict or diagnostics.keys() != {"retrieval", "call", "returned"}:
            return False
        if not all(workflow._valid_diagnostics(value) for value in diagnostics.values()):
            return False
        if type(row["eligible"]) is not dict or row["eligible"].keys() != diagnostics.keys():
            return False
        if not all(type(value) is bool for value in row["eligible"].values()):
            return False
        if row["diagnostics_private"] is True and row["eligible"] != {
            key: value is not None for key, value in diagnostics.items()
        }:
            return False
        comparisons = row["comparisons"]
        if type(comparisons) is not dict or comparisons.keys() != COMPARISONS:
            return False
        if not all(type(value) is bool for value in comparisons.values()):
            return False
        flags = (
            "contract_matches",
            "delivery_integrity",
            "diagnostics_private",
            "unexpected_error",
        )
        if not all(type(row[key]) is bool for key in flags):
            return False
        if row["diagnostics_private"] and row["unexpected_error"] != workflow.unexpected_error(
            row, expectation
        ):
            return False
        desired = row["desired"]
        if type(desired) is not dict or desired.keys() != {"kind", "met", "reason"}:
            return False
        if (
            type(desired["met"]) is not bool
            or desired["kind"] != expectation["desired"]["kind"]
            or desired["reason"] != expectation["desired"]["reason"]
            or desired["met"] != (expectation["desired"]["met"] and row["contract_matches"])
        ):
            return False
        if row["contract_matches"]:
            if (
                not all(comparisons.values())
                or not row["delivery_integrity"]
                or not row["diagnostics_private"]
            ):
                return False
            if row["unexpected_error"]:
                return False
            if any(
                row[key] != expectation[key]
                for key in ("diagnostics", "events", "counts", "terminal", "error_boundary")
            ):
                return False
        encoded = json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False)
        markers = [
            *case["privacy_markers"],
            case["retrieval_text"],
            case["returned_text"],
            case["proposal"]["arguments_json"],
        ]
        if any(len(marker) >= 8 and marker in encoded for marker in markers):
            return False
        return len(encoded.encode()) <= workflow.MAX_ROW_BYTES
    except (KeyError, TypeError, ValueError, RecursionError):
        return False


def read_protocol(raw, case, expectation, identity):
    try:
        if type(raw) is not bytes or len(raw) > MAX_CAPTURE_BYTES:
            raise ValueError
        lines = raw.decode("utf-8").splitlines()
        if len(lines) != 2:
            raise ValueError
        row_event, complete = [contract.strict_json(line) for line in lines]
        if (
            type(row_event) is not dict
            or row_event.keys() != {"event", "row"}
            or row_event["event"] != "row"
        ):
            raise ValueError
        if not validate_public_row(row_event["row"], case, expectation):
            raise ValueError
        if type(complete) is not dict or complete.keys() != {"event", "id", "source", "limits"}:
            raise ValueError
        if (
            complete["event"] != "complete"
            or complete["id"] != case["id"]
            or complete["source"] != identity
        ):
            raise ValueError
        applied = complete["limits"]
        if type(applied) is not dict or applied.keys() != LIMIT_KEYS:
            raise ValueError
        if not all(
            value is None or (type(value) is int and value >= 0) for value in applied.values()
        ):
            raise ValueError
        return {"row": row_event["row"], "limits": applied}
    except (ValueError, UnicodeError, KeyError, TypeError, RecursionError):
        raise ValueError("Invalid worker protocol") from None


def launch_settings():
    executable = sys.executable
    environment = limits.child_environment()
    if sys.platform == "win32":
        executable = sys._base_executable
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    return executable, environment


def supervise_case(
    case, expectation, *, deadline, interrupted, worker_command=None, expected_identity=None
):
    budget = max(0.0, min(WALL_SECONDS, deadline - time.perf_counter()))
    record = {
        "id": case["id"],
        "status": "not_started",
        "reason": None,
        "row": None,
        "child_reaped": None,
        "cleanup_failed": False,
        "returncode": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "wall_budget_seconds": budget,
        "wall_elapsed_seconds": 0.0,
        "protocol_error": False,
        "limits": None,
    }
    if budget <= 0 or interrupted[0]:
        record["reason"] = "interrupted" if interrupted[0] else "budget_exhausted"
        return record
    identity = source_identity() if expected_identity is None else expected_identity
    executable, environment = launch_settings()
    budget = max(0.0, min(budget, deadline - time.perf_counter()))
    record["wall_budget_seconds"] = budget
    if budget <= 0 or interrupted[0]:
        record["reason"] = "interrupted" if interrupted[0] else "budget_exhausted"
        return record
    command = (
        worker_command
        if worker_command is not None
        else [executable, str(Path(__file__).resolve()), "--worker", case["id"]]
    )
    started = time.perf_counter()
    process = None
    raw = b""
    try:
        with tempfile.TemporaryDirectory(prefix="guardtrellis-policy-worker-") as directory:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=errors,
                        cwd=directory,
                        env=environment,
                        start_new_session=os.name == "posix",
                    )
                    record["status"] = "worker_error"
                    while True:
                        if interrupted[0]:
                            record["status"] = "interrupted"
                            break
                        if any(
                            os.fstat(stream.fileno()).st_size > MAX_CAPTURE_BYTES
                            for stream in (output, errors)
                        ):
                            record["status"] = "output_limit"
                            break
                        remaining = min(
                            budget - (time.perf_counter() - started),
                            deadline - time.perf_counter(),
                        )
                        if remaining <= 0:
                            record["status"] = "wall_timeout"
                            break
                        try:
                            process.wait(timeout=min(0.05, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            continue
                except KeyboardInterrupt:
                    interrupted[0] = True
                    record["status"] = "interrupted"
                except (OSError, ValueError, TypeError):
                    record["status"] = "worker_error"
                finally:
                    if process is not None:
                        try:
                            limits.kill_and_reap(process)
                        except (OSError, subprocess.SubprocessError):
                            record["cleanup_failed"] = True
                            record["status"] = "cleanup_error"
                        finally:
                            record["child_reaped"] = process.poll() is not None
                            record["returncode"] = process.returncode
                    record["stdout_bytes"] = os.fstat(output.fileno()).st_size
                    record["stderr_bytes"] = os.fstat(errors.fileno()).st_size
                    output.seek(0)
                    raw = output.read(MAX_CAPTURE_BYTES + 1)
                try:
                    parsed = read_protocol(raw, case, expectation, identity)
                    record.update(parsed)
                except ValueError:
                    record["protocol_error"] = True
                if (
                    record["stdout_bytes"] > MAX_CAPTURE_BYTES
                    or record["stderr_bytes"] > MAX_CAPTURE_BYTES
                ):
                    record["status"] = "output_limit"
                elif record["status"] == "worker_error" and process is not None:
                    if record["protocol_error"]:
                        record["status"] = "protocol_error"
                    elif process.returncode == 0 and record["stderr_bytes"] == 0:
                        record["status"] = "completed"
    except KeyboardInterrupt:
        interrupted[0] = True
        record["status"] = "interrupted"
    except OSError:
        # A valid captured row survives temporary-directory cleanup failure.
        record["status"] = "cleanup_error"
        record["cleanup_failed"] = True
    record["wall_elapsed_seconds"] = time.perf_counter() - started
    return record


def _summary(records):
    rows = [record["row"] for record in records if record["row"] is not None]
    research = [row for row in rows if row["id"] in contract.RESEARCH_IDS]
    controls = [row for row in rows if row["id"] in contract.CONTROL_IDS]
    return {
        "scheduled_research": 12,
        "scheduled_controls": 11,
        "observed_research": len(research),
        "observed_controls": len(controls),
        "completed_children": sum(record["status"] == "completed" for record in records),
        "contract_matches": sum(row["contract_matches"] for row in rows),
        "desired_research_met": sum(row["desired"]["met"] for row in research),
        "semantic_limitations": sum(
            row["desired"]["reason"] == "semantic_intent_unclassified" for row in research
        ),
        "unexpected_errors": sum(row["unexpected_error"] for row in rows),
        "expected_sdk_errors": sum(
            not row["unexpected_error"]
            and any(
                diagnostic is not None and diagnostic["action"] == "error"
                for diagnostic in row["diagnostics"].values()
            )
            for row in rows
        ),
        "expected_callback_errors": sum(
            row["terminal"] == "callback_error" and not row["unexpected_error"] for row in rows
        ),
        "privacy_failures": sum(not row["diagnostics_private"] for row in rows),
        "delivery_integrity_failures": sum(not row["delivery_integrity"] for row in rows),
        "incomplete_records": sum(record["status"] != "completed" for record in records),
    }


def render_report(report):
    lines = [
        "# Retrieval/tool policy evaluation, v1",
        "",
        "Twelve AI-assisted public synthetic research scenarios and eleven harness controls.",
        "Scripted proposals establish no model attack-success rate or semantic protection.",
        "",
        f"Contract checks passed: `{report['contract_checks_passed']}`.",
        f"Observed research scenarios: `{report['summary']['observed_research']}/12`.",
        f"Observed harness controls: `{report['summary']['observed_controls']}/11`.",
        "",
        "| ID | Worker status | Terminal | Contract | Desired protection |",
        "| --- | --- | --- | --- | --- |",
    ]
    for record in report["runs"]:
        row = record["row"]
        terminal = row["terminal"] if row else "not observed"
        matches = row["contract_matches"] if row else "unknown"
        desired = row["desired"]["met"] if row else "unknown"
        lines.append(
            f"| {record['id']} | {record['status']} | {terminal} | {matches} | {desired} |"
        )
    lines.extend(
        [
            "",
            "Instruction-only ALLOWs remain recorded as semantic limitations.",
            "No independent per-case review or live provider/network/database experiment occurred.",
            "",
        ]
    )
    return "\n".join(lines)


def run_batch(report_dir):
    report_dir = Path(report_dir)
    if report_dir.exists():
        print("Select a new evaluation report directory.", file=sys.stderr)
        return 2
    try:
        research, controls, expectations, _manifest = assets.load_frozen()
        identity = source_identity()
        freeze_sha256 = digest((HERE / "freeze_v1.json").read_bytes())
    except (OSError, ValueError, ImportError):
        print("Cannot prepare frozen evaluation assets.", file=sys.stderr)
        return 1
    interrupted = [False]
    records = []
    report = {
        "schema_version": 1,
        "dataset_version": contract.VERSION,
        "metadata": {
            "baseline_commit": _manifest.get("base_commit"),
            "source": identity,
            "freeze_sha256": freeze_sha256,
            "receipt": getattr(assets, "RECEIPT", None),
            "first_observation_utc": datetime.now(UTC).isoformat(),
            "python": platform.python_version(),
            "platform": sys.platform,
            "machine": platform.machine(),
            "authorship": contract.PROVENANCE,
        },
        "configuration": {
            "child_observation_seconds": WALL_SECONDS,
            "parent_observation_seconds": TOTAL_SECONDS,
            "cleanup_allowance_seconds": 5,
            "capture_bytes_per_stream": MAX_CAPTURE_BYTES,
            "combined_report_bytes": MAX_REPORT_BYTES,
        },
        "runs": records,
        "interrupted": False,
        "contract_checks_passed": False,
    }
    deadline = time.perf_counter() + TOTAL_SECONDS
    handlers = {}

    def interrupt(_signum, _frame):
        interrupted[0] = True

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupt)
        aborted = False
        for case in [*research, *controls]:
            if aborted:
                record = {
                    "id": case["id"],
                    "status": "not_started",
                    "reason": "unreaped_child",
                    "row": None,
                    "child_reaped": None,
                    "cleanup_failed": False,
                    "returncode": None,
                    "stdout_bytes": 0,
                    "stderr_bytes": 0,
                    "wall_budget_seconds": 0.0,
                    "wall_elapsed_seconds": 0.0,
                    "protocol_error": False,
                    "limits": None,
                }
            else:
                record = supervise_case(
                    case,
                    expectations[case["id"]],
                    deadline=deadline,
                    interrupted=interrupted,
                    expected_identity=identity,
                )
            records.append(record)
            if record["child_reaped"] is False:
                aborted = True
        report["summary"] = _summary(records)

        def encode():
            report["interrupted"] = interrupted[0]
            report["contract_checks_passed"] = (
                not interrupted[0]
                and len(records) == 23
                and all(
                    record["status"] == "completed"
                    and record["child_reaped"] is True
                    and record["row"]["contract_matches"]
                    for record in records
                )
            )
            payload = (
                json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False).encode() + b"\n"
            )
            markdown = render_report(report).encode()
            if len(payload) + len(markdown) > MAX_REPORT_BYTES:
                raise ValueError
            return payload, markdown

        payload, markdown = encode()
        report_dir.mkdir(parents=True, exist_ok=False)
        writing_started = time.perf_counter()
        (report_dir / "results.json").write_bytes(payload)
        (report_dir / "REPORT.md").write_bytes(markdown)
        report["report_write_elapsed_seconds"] = time.perf_counter() - writing_started
        report["report_write_timing_scope"] = "initial save; final status persistence excluded"
        # Interruption changes only False -> True, so at most one corrective save is
        # needed. Seal the exit decision to the status actually persisted; a signal
        # after this finalization point cannot relabel the completed record.
        for _attempt in range(2):
            payload, markdown = encode()
            saved_interrupted = report["interrupted"]
            saved_passed = report["contract_checks_passed"]
            (report_dir / "results.json").write_bytes(payload)
            (report_dir / "REPORT.md").write_bytes(markdown)
            if interrupted[0] == saved_interrupted:
                return 130 if saved_interrupted else (0 if saved_passed else 1)
        return 130
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError):
        print("Cannot write evaluation report.", file=sys.stderr)
        return 130 if interrupted[0] else 1
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)


def worker(identifier):
    try:
        research, controls, expectations, _manifest = assets.load_frozen()
        case = next(case for case in [*research, *controls] if case["id"] == identifier)
        identity = source_identity()
        applied = limits.apply_limits(2, 512)
        from evaluation.retrieval_tool_policy.workflow import observe

        row = observe(case, expectations[identifier])
        print(json.dumps({"event": "row", "row": row}, sort_keys=True, allow_nan=False), flush=True)
        print(
            json.dumps(
                {"event": "complete", "id": identifier, "source": identity, "limits": applied},
                sort_keys=True,
                allow_nan=False,
            ),
            flush=True,
        )
        return 0
    except Exception:
        # No exception repr/traceback, fixture text or environment reaches a capture.
        print('{"event":"worker_error"}', flush=True)
        return 1


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "Invalid evaluation arguments; select a new report directory.\n")


def main(argv=None):
    parser = _Parser(description="Run the frozen offline retrieval/tool policy evaluation.")
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument(
        "--worker", choices=contract.RESEARCH_IDS + contract.CONTROL_IDS, help=argparse.SUPPRESS
    )
    args = parser.parse_args(argv)
    if args.worker is not None:
        if args.report_dir is not None:
            parser.error("worker arguments")
        return worker(args.worker)
    if args.report_dir is None:
        parser.error("report directory required")
    return run_batch(args.report_dir)


if __name__ == "__main__":
    raise SystemExit(main())
