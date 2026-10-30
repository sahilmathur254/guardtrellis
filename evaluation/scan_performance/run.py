"""Frozen, bounded synchronous scan measurements; no performance release threshold."""

from __future__ import annotations

import argparse
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
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
FIXTURES = HERE.with_name("fixtures_v1.json")
PROTOCOL = HERE.with_name("PROTOCOL_v1.md")
FREEZE = HERE.with_name("freeze_v1.json")
FREEZE_SHA256 = "b562613a18195f8127f882a1a6ea739f7cc6cb3711b14e490a28c730f6684394"
RECEIPT = "https://github.com/sahilmathur254/guardtrellis/issues/45#issuecomment-6507253813"
SPEC = spec_from_file_location("scan_performance_limits", ROOT / "evaluation/measure_resources.py")
assert SPEC is not None and SPEC.loader is not None
limits = module_from_spec(SPEC)
sys.modules[SPEC.name] = limits
SPEC.loader.exec_module(limits)
WARMUPS = 3
WALL_SECONDS = 10.0
TOTAL_SECONDS = 180.0
PROFILES = ("default", "opt_in")
CASE_IDS = ("allow", "redact", "block", "uri_positive", "uri_benign")
CODES = ("pii_phone", "secret_github_classic", "secret_postgresql_uri")
CELLS = tuple(
    {"group": "main", "profile": profile, "case": case, "input_chars": size}
    for profile in PROFILES
    for size in (1_000, 10_000, 100_000)
    for case in CASE_IDS[:3]
) + tuple(
    {"group": "uri_supplement", "profile": profile, "case": case, "input_chars": 1_000}
    for profile in PROFILES
    for case in CASE_IDS[3:]
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


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
    """Check the externally receipted expectations without importing/scanning with the SDK."""
    frozen = FREEZE.read_bytes()
    if digest(frozen) != FREEZE_SHA256 or not RECEIPT.startswith("https://github.com/"):
        raise ValueError("Invalid pre-observation freeze")
    freeze = decode(frozen)
    for path in (FIXTURES, PROTOCOL):
        if digest(path.read_bytes()) != freeze["files"][path.name]:
            raise ValueError("Frozen expectations changed")
    raw = FIXTURES.read_bytes()
    if len(raw) > 32_768:
        raise ValueError("Invalid fixed fixtures")
    document = decode(raw)
    if (
        not isinstance(document, dict)
        or document.keys()
        != {
            "dataset_version",
            "source",
            "license",
            "usage",
            "independent_review",
            "reviewer",
            "padding_char",
            "profiles",
            "main_input_chars",
            "supplement_input_chars",
            "cases",
        }
        or document["dataset_version"] != "sync-scan-performance-v1"
        or document["license"] != "Apache-2.0"
        or document["usage"] != "public-development"
        or document["independent_review"] is not False
        or document["padding_char"] != "."
        or document["profiles"] != list(PROFILES)
        or document["main_input_chars"] != [1_000, 10_000, 100_000]
        or document["supplement_input_chars"] != [1_000]
        or not isinstance(document["source"], str)
        or not isinstance(document["reviewer"], str)
        or not isinstance(document["cases"], list)
        or len(document["cases"]) != len(CASE_IDS)
    ):
        raise ValueError("Invalid fixed fixtures")
    for case, case_id in zip(document["cases"], CASE_IDS, strict=True):
        if (
            not isinstance(case, dict)
            or case.keys() != {"id", "group", "payload", "expected_by_profile", "label_basis"}
            or case["id"] != case_id
            or case["group"] != ("main" if case_id in CASE_IDS[:3] else "uri_supplement")
            or not isinstance(case["payload"], str)
            or not 1 <= len(case["payload"]) <= 500
            or not isinstance(case["label_basis"], str)
            or not isinstance(case["expected_by_profile"], dict)
            or case["expected_by_profile"].keys() != set(PROFILES)
        ):
            raise ValueError("Invalid fixed case")
        for expected in case["expected_by_profile"].values():
            if (
                not isinstance(expected, dict)
                or expected.keys() != {"action", "codes", "spans", "checked_payload"}
                or expected["action"] not in ("allow", "redact", "block")
                or not isinstance(expected["codes"], list)
                or any(code not in CODES for code in expected["codes"])
                or not isinstance(expected["spans"], list)
                or len(expected["codes"]) != len(expected["spans"])
                or len(expected["codes"]) > 1
                or any(
                    not isinstance(span, list)
                    or len(span) != 2
                    or any(type(value) is not int for value in span)
                    or not 0 <= span[0] < span[1] <= len(case["payload"])
                    for span in expected["spans"]
                )
                or (expected["action"] == "block" and expected["checked_payload"] is not None)
                or (
                    expected["action"] != "block"
                    and not isinstance(expected["checked_payload"], str)
                )
            ):
                raise ValueError("Invalid fixed expectation")
    return {case["id"]: case for case in document["cases"]}


def represented(case, cell):
    """Append authored content after padding; expectations never come from a scan."""
    padding = "." * (cell["input_chars"] - len(case["payload"]))
    expected = case["expected_by_profile"][cell["profile"]]
    checked = expected["checked_payload"]
    spans = [[len(padding) + start, len(padding) + end] for start, end in expected["spans"]]
    return padding + case["payload"], None if checked is None else padding + checked, spans


def policy(profile):
    from guardtrellis import Guard, PIIScanner, SecretScanner

    return Guard(
        retrieval_scanners=[
            SecretScanner(connection_strings=profile == "opt_in"),
            PIIScanner(phone_mode="formatted" if profile == "opt_in" else "contiguous"),
        ]
    )


def emit(event):
    print(json.dumps(event, separators=(",", ":"), allow_nan=False), flush=True)


def privacy_markers(case, text, checked):
    markers = [case["payload"], text]
    markers.extend(
        case["payload"][start:end]
        for expectation in case["expected_by_profile"].values()
        for start, end in expectation["spans"]
    )
    if checked is not None:
        markers.append(checked)
    markers.extend(
        expected["checked_payload"]
        for expected in case["expected_by_profile"].values()
        if expected["checked_payload"] is not None
    )
    if case["id"] == "uri_positive":
        markers.append("synthetic-password")
    return markers


def exact_metadata(value, expected):
    """Reject bool-for-integer equality as well as extra/missing metadata."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(
            exact_metadata(value[key], item) for key, item in expected.items()
        )
    if isinstance(expected, (list, tuple)):
        return len(value) == len(expected) and all(
            exact_metadata(item, other) for item, other in zip(value, expected, strict=True)
        )
    return value == expected


def observe(scan, case, cell, index, clock=time.perf_counter_ns):
    from guardtrellis import Rejected, Stage

    text, checked, spans = represented(case, cell)
    expected = case["expected_by_profile"][cell["profile"]]
    markers = privacy_markers(case, text, checked)
    started = clock()
    try:
        result = scan(text, stage=Stage.RETRIEVAL)
    except Exception as error:
        ended = clock()
        try:
            surface = str(error) + repr(error)
            privacy_ok = not any(marker in surface for marker in markers)
        except Exception:
            privacy_ok = False
        return {
            "index": index,
            "scan_ms": (ended - started) / 1_000_000,
            "action": "error",
            "accepted": False,
            "stage_matches": False,
            "findings_match": False,
            "diagnostics_match": False,
            "text_matches": False,
            "delivery_matches": False,
            "privacy_ok": privacy_ok,
            "error": True,
        }
    ended = clock()
    row = {"index": index, "scan_ms": (ended - started) / 1_000_000}
    try:
        if result.action.value not in ("allow", "warn", "redact", "block", "error"):
            raise ValueError("Unknown action")
        findings = [
            (
                finding.code,
                finding.start,
                finding.end,
                finding.revision,
                finding.scanner,
                finding.scanner_index,
            )
            for finding in result.findings
        ]
        authored = [
            (
                code,
                *span,
                0,
                "pii" if code == "pii_phone" else "secrets",
                1 if code == "pii_phone" else 0,
            )
            for code, span in zip(expected["codes"], spans, strict=True)
        ]
        delivered = []
        rejection_surface = ""
        try:
            delivered.append(result.require_text())
            accessor_rejected = False
        except Rejected as rejected:
            accessor_rejected = True
            rejection_surface = str(rejected) + repr(rejected)
        diagnostics = result.diagnostics()
        trace = [
            {
                "scanner": "secrets",
                "scanner_index": 0,
                "action": "block" if expected["action"] == "block" else "allow",
                "revision_before": 0,
                "revision_after": 0,
            }
        ]
        if expected["action"] != "block":
            trace.append(
                {
                    "scanner": "pii",
                    "scanner_index": 1,
                    "action": expected["action"],
                    "revision_before": 0,
                    "revision_after": int(expected["action"] == "redact"),
                }
            )
        expected_diagnostics = {
            "action": expected["action"],
            "stage": "retrieval",
            "findings": [
                dict(
                    zip(
                        ("code", "start", "end", "revision", "scanner", "scanner_index"),
                        finding,
                        strict=True,
                    )
                )
                for finding in authored
            ],
            "trace": trace,
        }
        surfaces = (repr(result), json.dumps(diagnostics, ensure_ascii=True), rejection_surface)
        # Both fixture payloads and sensitive components are synthetic, fixed canaries.
        privacy = not any(marker in surface for marker in markers for surface in surfaces)
        row.update(
            action=result.action.value,
            accepted=result.accepted,
            stage_matches=type(result.stage) is Stage and result.stage == Stage.RETRIEVAL,
            findings_match=exact_metadata(findings, authored),
            diagnostics_match=exact_metadata(diagnostics, expected_diagnostics),
            text_matches=result.text == checked,
            delivery_matches=(
                delivered == ([checked] if checked is not None else [])
                and accessor_rejected == (checked is None)
            ),
            privacy_ok=privacy,
            error=False,
        )
    except Exception:
        row.update(
            action="error",
            accepted=False,
            stage_matches=False,
            findings_match=False,
            diagnostics_match=False,
            text_matches=False,
            delivery_matches=False,
            privacy_ok=False,
            error=True,
        )
    return row


def sample_matches(row, cell, fixtures):
    action = fixtures[cell["case"]]["expected_by_profile"][cell["profile"]]["action"]
    return (
        row["action"] == action
        and row["accepted"] == (action != "block")
        and all(
            row[key]
            for key in (
                "stage_matches",
                "findings_match",
                "diagnostics_match",
                "text_matches",
                "delivery_matches",
                "privacy_ok",
            )
        )
        and not row["error"]
    )


def worker(cell, count):
    applied = limits.apply_limits(cpu_seconds=2, memory_mib=512)
    emit({"event": "limits", "limits": applied})
    started = time.perf_counter()
    case = load_fixtures()[cell["case"]]
    guard = policy(cell["profile"])
    emit({"event": "prepared", "setup_ms": (time.perf_counter() - started) * 1000})
    warm_started = time.perf_counter()
    warm = [observe(guard.scan, case, cell, index) for index in range(WARMUPS)]
    fixtures = {cell["case"]: case}
    emit(
        {
            "event": "warmup",
            "warmup_ms": (time.perf_counter() - warm_started) * 1000,
            "warmup_matches": all(sample_matches(row, cell, fixtures) for row in warm),
        }
    )
    for index in range(count):
        emit({"event": "sample", **observe(guard.scan, case, cell, index)})
    emit({"event": "finished", "resources": limits.resource_usage()})


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def read_protocol(raw, cell, count, fixtures):
    result = {"samples": [], "protocol_error": False, "worker_error": False}
    phase = "limits"
    for line in raw.splitlines():
        try:
            event = decode(line)
            if not isinstance(event, dict):
                raise ValueError
            kind = event.get("event")
            if kind == "error" and event == {"event": "error"} and phase not in ("done", "failed"):
                result["worker_error"] = True
                phase = "failed"
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
                        "scan_ms",
                        "action",
                        "accepted",
                        "stage_matches",
                        "findings_match",
                        "diagnostics_match",
                        "text_matches",
                        "delivery_matches",
                        "privacy_ok",
                        "error",
                    }
                    or type(event["index"]) is not int
                    or event["index"] != len(result["samples"])
                    or event["index"] >= count
                    or event["action"] not in ("allow", "warn", "redact", "block", "error")
                    or not number(event["scan_ms"])
                    or any(
                        type(event[key]) is not bool
                        for key in (
                            "accepted",
                            "stage_matches",
                            "findings_match",
                            "diagnostics_match",
                            "text_matches",
                            "delivery_matches",
                            "privacy_ok",
                            "error",
                        )
                    )
                ):
                    raise ValueError
                row = {key: value for key, value in event.items() if key != "event"}
                row["contract_matches"] = sample_matches(row, cell, fixtures)
                result["samples"].append(row)
            elif kind == "finished" and phase == "samples":
                usage = event.get("resources")
                if (
                    event.keys() != {"event", "resources"}
                    or len(result["samples"]) != count
                    or not isinstance(usage, dict)
                    or usage.keys() != {"process_cpu_ms", "peak_rss_bytes"}
                    or not number(usage["process_cpu_ms"])
                    or usage["peak_rss_bytes"] is not None
                    and not number(usage["peak_rss_bytes"])
                ):
                    raise ValueError
                result["resources"] = usage
                phase = "done"
            else:
                raise ValueError
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            result["protocol_error"] = True
            break
    result["finished"] = phase == "done"
    return result


def launch_settings():
    environment = limits.child_environment()
    executable = sys.executable
    if sys.platform == "win32":
        executable = sys._base_executable
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    return executable, environment


def measure(cell_index, count, repeat, deadline, fixtures, interruption):
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
    if budget <= 0 or interruption[0]:
        row["status"] = "not_started" if interruption[0] else "total_timeout"
        return row
    executable, environment = launch_settings()
    started = time.perf_counter()
    try:
        with tempfile.TemporaryDirectory(prefix="guardtrellis-scan-performance-") as directory:
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
                        if interruption[0]:
                            row["status"] = "interrupted"
                            break
                        if any(
                            os.fstat(stream.fileno()).st_size > limits.MAX_CAPTURE_BYTES
                            for stream in (output, errors)
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
                    interruption[0] = True
                    row["status"] = "interrupted"
                finally:
                    if process is not None:
                        try:
                            limits.kill_and_reap(process)
                        except (OSError, subprocess.SubprocessError):
                            row["status"] = "cleanup_error"
                        finally:
                            row.update(
                                returncode=process.returncode,
                                child_reaped=process.poll() is not None,
                            )
                output.seek(0)
                raw = output.read(limits.MAX_CAPTURE_BYTES + 1)
                row["stderr_bytes"] = os.fstat(errors.fileno()).st_size
                # Retain validated prefix rows even if temporary-directory cleanup fails.
                row.update(read_protocol(raw[: limits.MAX_CAPTURE_BYTES], cell, count, fixtures))
        if len(raw) > limits.MAX_CAPTURE_BYTES or row["stderr_bytes"] > limits.MAX_CAPTURE_BYTES:
            row["status"] = "output_limit"
        elif row["status"] == "worker_error":
            if row["protocol_error"]:
                row["status"] = "protocol_error"
            elif row["returncode"] == 0 and row["finished"] and not row["stderr_bytes"]:
                row["status"] = "completed"
            elif os.name == "posix" and row["returncode"] == -signal.SIGXCPU:
                row["status"] = "cpu_limit"
    except KeyboardInterrupt:
        interruption[0] = True
        row["status"] = "interrupted"
    except (OSError, subprocess.SubprocessError):
        row["status"] = "supervisor_error"
    if interruption[0]:
        row["status"] = "interrupted"
    row["wall_ms"] = (time.perf_counter() - started) * 1000
    row["scan_ms"] = summary([sample["scan_ms"] for sample in row["samples"]])
    row["actions"] = {
        action: sum(sample["action"] == action for sample in row["samples"])
        for action in ("allow", "warn", "redact", "block", "error")
    }
    row["matching_samples"] = sum(sample["contract_matches"] for sample in row["samples"])
    row["contract_matches"] = (
        row["status"] == "completed"
        and row.get("warmup_matches", False)
        and row.get("child_reaped", False)
        and not row.get("worker_error", False)
        and len(row["samples"]) == count
        and all(sample["contract_matches"] for sample in row["samples"])
    )
    return row


def metadata():
    import guardtrellis

    source_dir = Path(guardtrellis.__file__).resolve().parent
    files = [
        HERE,
        FIXTURES,
        PROTOCOL,
        FREEZE,
        ROOT / "uv.lock",
        ROOT / "evaluation/measure_resources.py",
    ]
    hashes = {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in files}
    actual_sdk = {
        f"src/guardtrellis/{p.name}": digest(p.read_bytes())
        for p in sorted(source_dir.glob("*.py"))
    }
    hashes.update(actual_sdk)
    frozen = decode(FREEZE.read_bytes())
    return {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source_version": guardtrellis.__version__,
        "installed_version": version("guardtrellis"),
        "source_base_commit": frozen["source_base_commit"],
        "pre_observation_comparison": {
            "sdk_matches": actual_sdk == frozen["sdk_sha256"],
            "helper_matches": all(
                hashes[name] == value for name, value in frozen["helper_sha256"].items()
            ),
            "lock_matches": hashes["uv.lock"] == frozen["lockfile_sha256"],
        },
        "freeze_sha256": FREEZE_SHA256,
        "freeze_receipt": RECEIPT,
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
        "sha256": hashes,
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
                "matching_samples": sum(row["contract_matches"] for row in samples),
                "incomplete_runs": sum(row["status"] != "completed" for row in selected),
                "errors": sum(row["error"] or row["action"] == "error" for row in samples),
                "actions": {
                    action: sum(row["action"] == action for row in samples)
                    for action in ("allow", "warn", "redact", "block", "error")
                },
                "scan_ms": summary([row["scan_ms"] for row in samples]),
            }
        )
    return result


def render_report(report):
    lines = [
        "# Bounded synchronous scan baseline, v1",
        "",
        "AI-assisted public development fixtures, author self-review; no independent validation.",
        "Only Guard.scan is timed; setup, outcome checks, callbacks and providers are excluded.",
        "Repetitions are timing observations, not additional detector scenarios.",
        "",
        f"SDK: `{report['metadata']['source_version']}`. "
        f"Mode: `{report['configuration']['mode']}`. "
        f"Measurement checks passed: `{report['measurement_checks_passed']}`.",
        f"Pre-observation [freeze receipt]({RECEIPT}); SHA-256 `{FREEZE_SHA256}`.",
        "",
    ]
    for group in ("main", "uri_supplement"):
        lines.extend(
            [
                "## Main comparable outcomes" if group == "main" else "## Separate URI supplement",
                "",
                "| Profile | Case | Characters | Observed / expected | Exact matches | "
                "Incomplete runs | Scan median ms (range) |",
                "| --- | --- | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for row in report["summary"]:
            cell, times = row["cell"], row["scan_ms"]
            if cell["group"] != group:
                continue
            timing = (
                "unknown"
                if times is None
                else f"{times['median']:.3f} ({times['min']:.3f}–{times['max']:.3f})"
            )
            lines.append(
                f"| {cell['profile']} | {cell['case']} | {cell['input_chars']} | "
                f"{row['observed_samples']} / {row['expected_samples']} | "
                f"{row['matching_samples']} | "
                f"{row['incomplete_runs']} | {timing} |"
            )
        lines.append("")
    lines.extend(
        [
            "Raw samples, errors and missing denominators remain in results.json; "
            "missing times are not zero.",
            "CPU/RSS describe whole children including setup; unsupported values are null.",
            "No timing threshold, p95/p99 promise, capacity, general accuracy "
            "or cross-machine ranking is established.",
            "URI-positive default/opt-in outcomes differ "
            "and are not a like-for-like speed comparison.",
            "",
        ]
    )
    return "\n".join(lines)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid evaluation arguments; select a new report directory.\n")


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--worker", type=int, choices=range(len(CELLS)), help=argparse.SUPPRESS)
    parser.add_argument("--samples", type=int, choices=(4, 100), help=argparse.SUPPRESS)
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
    count, repetitions = (4, 1) if args.smoke else (100, 3)
    try:
        fixtures = load_fixtures()
        provenance = metadata()
    except Exception:
        parser.exit(1, "Cannot prepare frozen evaluation metadata.\n")
    deadline = time.perf_counter() + TOTAL_SECONDS
    interruption = [False]
    aborted = False
    rows = []
    report = {
        "schema_version": 1,
        "dataset_version": "sync-scan-performance-v1",
        "metadata": provenance,
        "fixture_provenance": {
            "usage": "public-development",
            "authorship": "AI-assisted synthetic",
            "independent_review": False,
            "license": "Apache-2.0",
        },
        "configuration": {
            "mode": "smoke" if args.smoke else "full",
            "samples_per_cell": count,
            "repetitions": repetitions,
            "warmups_per_child": WARMUPS,
            "child_wall_seconds": WALL_SECONDS,
            "total_wall_seconds": TOTAL_SECONDS,
            "cleanup_allowance_seconds": 5,
            "cpu_seconds": 2,
            "memory_mib": 512,
        },
        "runs": rows,
    }

    def interrupt(_signum, _frame):
        interruption[0] = True

    handlers = {item: signal.getsignal(item) for item in (signal.SIGINT, signal.SIGTERM)}
    try:
        for item in handlers:
            signal.signal(item, interrupt)
        for repeat in range(repetitions):
            for index, cell in enumerate(CELLS):
                if interruption[0] or aborted:
                    row = {
                        "cell": cell,
                        "repeat": repeat,
                        "status": "not_started",
                        "samples": [],
                        "expected_samples": count,
                        "child_reaped": None,
                    }
                else:
                    try:
                        row = measure(index, count, repeat, deadline, fixtures, interruption)
                    except KeyboardInterrupt:
                        interruption[0] = True
                        row = {
                            "cell": cell,
                            "repeat": repeat,
                            "status": "interrupted",
                            "samples": [],
                            "expected_samples": count,
                            "child_reaped": None,
                        }
                rows.append(row)
                if row.get("child_reaped") is False:
                    aborted = True
        report["summary"] = summarize(rows)

        def save():
            report["interrupted"] = interruption[0]
            report["measurement_checks_passed"] = (
                not interruption[0]
                and len(rows) == repetitions * len(CELLS)
                and all(row.get("contract_matches", False) for row in rows)
            )
            (args.report_dir / "results.json").write_text(
                json.dumps(report, indent=2, allow_nan=False) + "\n",
                encoding="utf-8",
            )
            (args.report_dir / "REPORT.md").write_text(render_report(report), encoding="utf-8")

        args.report_dir.mkdir(parents=True, exist_ok=False)
        save()
        if report["interrupted"] != interruption[0]:
            save()
        return 130 if interruption[0] else (0 if report["measurement_checks_passed"] else 1)
    except OSError:
        parser.exit(1, "Cannot write evaluation report.\n")
    finally:
        for item, handler in handlers.items():
            signal.signal(item, handler)


if __name__ == "__main__":
    raise SystemExit(main())
