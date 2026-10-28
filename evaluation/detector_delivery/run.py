"""Frozen 48-scenario detector and checked-delivery comparison; synthetic data only."""

from __future__ import annotations

import argparse
import io
import json
import logging
import math
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

if __package__:
    from . import assets, contract
else:
    import assets
    import contract

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
SPEC = spec_from_file_location(
    "detector_delivery_resources", ROOT / "evaluation/measure_resources.py"
)
assert SPEC is not None and SPEC.loader is not None
limits = module_from_spec(SPEC)
sys.modules[SPEC.name] = limits
SPEC.loader.exec_module(limits)
CELLS = tuple((family, profile) for family in contract.FAMILIES for profile in contract.PROFILES)
WALL_SECONDS = 10
TOTAL_SECONDS = 90
ACTIONS = {"allow", "redact", "warn", "block", "error"}
CODES = set().union(*contract.PRIMARY_CODES.values()) | {
    "pii_ssn",
    "secret_github_classic",
    "secret_github_fine_grained",
    "secret_aws_access_key_id",
    "secret_private_key",
    "scanner_error",
    "invalid_check",
    "text_limit_exceeded",
    "finding_limit_exceeded",
    "connection_string_limit_exceeded",
    "connection_string_configuration_error",
}
COMPARISONS = {"action", "spans", "text", "delivery"}
ROW_FIELDS = {
    "id",
    "representation",
    "action",
    "accepted",
    "primary",
    "incidental_codes",
    "consumer_calls",
    "comparisons",
    "delivery_integrity",
    "contract_match",
    "privacy_ok",
}


def sdk_fingerprint():
    import guardtrellis

    files = {
        f"src/guardtrellis/{path.name}": assets.digest(path.read_bytes())
        for path in sorted(Path(guardtrellis.__file__).parent.glob("*.py"))
    }
    digest = assets.digest(json.dumps(files, sort_keys=True).encode())
    return guardtrellis.__version__, files, digest


def cell_cases(cases, cell):
    family, _ = CELLS[cell]
    return [
        (case, representation)
        for case in cases
        if case["family"] == family
        for representation in contract.REPRESENTATIONS
    ]


def contains_marker(value, markers):
    surface = str(value)
    return any(
        spelling in surface
        for marker in markers
        for spelling in (
            marker,
            repr(marker),
            json.dumps(marker),
            json.dumps(marker)[1:-1],
            "".join(map(contract.escaped_character, marker)),
        )
    )


def diagnostic_markers(case):
    # Authored fixture canaries, not additional SDK credential patterns.
    components = re.findall(r"FabricatedUri[A-H][0-9]+", case["text"])
    return [*case["privacy_markers"], *components]


def deliver(result, consumer):
    if result.accepted:
        consumer(result.require_text())


def observe(case, expected, scan, delivery=deliver):
    from guardtrellis import Action, Rejected, Stage

    text = contract.represented(case, expected["representation"], [])[0]
    log = io.StringIO()
    handler = logging.StreamHandler(log)
    logger = logging.getLogger()
    logger.addHandler(handler)
    try:
        result = scan(text, stage=Stage.RETRIEVAL)
        diagnostics = result.diagnostics()
        safe = not any(
            contains_marker(surface, diagnostic_markers(case))
            for surface in (repr(result), diagnostics, log.getvalue())
        )
        primary, incidental = [], set()
        if len(result.findings) > 8:
            raise ValueError("Finding protocol limit")
        for finding in result.findings:
            if finding.code not in CODES:
                raise ValueError("Unknown finding code")
            if finding.code in contract.PRIMARY_CODES[case["family"]]:
                if (
                    type(finding.start) is not int
                    or type(finding.end) is not int
                    or not 0 <= finding.start < finding.end <= len(text)
                    or finding.revision != 0
                ):
                    raise ValueError("Invalid primary finding")
                primary.append({"code": finding.code, "start": finding.start, "end": finding.end})
            else:
                incidental.add(finding.code)
        consumed = []
        delivery(result, consumed.append)
        if result.accepted:
            checked = result.require_text()
            integrity = (
                consumed == [checked]
                and type(checked) is str
                and len(checked) <= contract.MAX_INPUT_CHARS
                and (result.action != Action.ALLOW or checked == text)
            )
        else:
            checked = None
            integrity = not consumed and result.text is None
            try:
                result.require_text()
            except Rejected as error:
                safe &= not contains_marker(str(error), diagnostic_markers(case))
            else:
                integrity = False
        desired = expected["desired"]
        spans = [[item["start"], item["end"]] for item in primary]
        comparisons = {
            "action": result.action.value == desired["action"],
            "spans": spans == desired["spans"],
            "text": checked == desired["text"],
            "delivery": consumed == ([] if desired["action"] == "block" else [desired["text"]]),
        }
        row = dict(
            id=case["id"],
            representation=expected["representation"],
            action=result.action.value,
            accepted=result.accepted,
            primary=primary,
            incidental_codes=sorted(incidental),
            consumer_calls=len(consumed),
            comparisons=comparisons,
            delivery_integrity=bool(integrity),
            contract_match=None,
            privacy_ok=bool(safe),
        )
        row["contract_match"] = contract_matches(row, expected)
        return row
    finally:
        logger.removeHandler(handler)


def contract_matches(row, expected):
    target = expected["contract"]
    if not target["eligible"]:
        return None
    return (
        row["action"] != "error"
        and [[item["start"], item["end"]] for item in row["primary"]] == target["spans"]
        and [item["code"] for item in row["primary"]] == target["codes"]
        and (target["action"] is None or row["action"] == target["action"])
    )


def emit(event):
    print(json.dumps(event, ensure_ascii=True, separators=(",", ":")), flush=True)


def worker(cell):
    cases, expectations, _ = assets.load_frozen()
    applied = limits.apply_limits(2, 512)
    from guardtrellis import Action, Guard, PIIScanner, SecretScanner

    profile = CELLS[cell][1]
    guard = Guard(
        retrieval_scanners=[
            SecretScanner(action=Action.BLOCK, connection_strings=profile == "opt_in"),
            PIIScanner(
                action=Action.REDACT,
                phone_mode="formatted" if profile == "opt_in" else "contiguous",
            ),
        ],
        max_chars=contract.MAX_INPUT_CHARS,
    )
    for case, representation in cell_cases(cases, cell):
        expected = expectations[case["id"], profile, representation]
        emit({"event": "row", "row": observe(case, expected, guard.scan)})
    sdk_version, _, sdk_sha = sdk_fingerprint()
    emit(
        {
            "event": "complete",
            "count": 64,
            "limits": applied,
            "resources": limits.resource_usage(),
            "sdk_version": sdk_version,
            "sdk_sha256": sdk_sha,
        }
    )


def validate_row(row, case, expected):
    if (
        type(row) is not dict
        or row.keys() != ROW_FIELDS
        or row["id"] != case["id"]
        or row["representation"] != expected["representation"]
        or row["action"] not in ACTIONS
        or any(
            type(row[key]) is not bool for key in ("accepted", "delivery_integrity", "privacy_ok")
        )
        or row["accepted"] != (row["action"] in ("allow", "redact", "warn"))
        or type(row["consumer_calls"]) is not int
        or not 0 <= row["consumer_calls"] <= 8
        or type(row["comparisons"]) is not dict
        or row["comparisons"].keys() != COMPARISONS
        or any(type(value) is not bool for value in row["comparisons"].values())
        or type(row["primary"]) is not list
        or len(row["primary"]) > 8
        or type(row["incidental_codes"]) is not list
        or any(type(code) is not str or code not in CODES for code in row["incidental_codes"])
        or row["incidental_codes"] != sorted(set(row["incidental_codes"]))
    ):
        raise ValueError("Invalid row protocol")
    text = contract.represented(case, expected["representation"], [])[0]
    for finding in row["primary"]:
        if (
            type(finding) is not dict
            or finding.keys() != {"code", "start", "end"}
            or finding["code"] not in contract.PRIMARY_CODES[case["family"]]
            or type(finding["start"]) is not int
            or type(finding["end"]) is not int
            or not 0 <= finding["start"] < finding["end"] <= len(text)
        ):
            raise ValueError("Invalid primary protocol")
    if (
        type(row["contract_match"]) not in (bool, type(None))
        or row["contract_match"] != contract_matches(row, expected)
        or row["comparisons"]["action"] != (row["action"] == expected["desired"]["action"])
        or row["comparisons"]["spans"]
        != (
            [[item["start"], item["end"]] for item in row["primary"]]
            == expected["desired"]["spans"]
        )
        or row["delivery_integrity"]
        and row["consumer_calls"] != int(row["accepted"])
    ):
        raise ValueError("Contradictory row protocol")
    if contains_marker(row, diagnostic_markers(case)):
        raise ValueError("Unsafe row protocol")
    return row


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_end(event, sdk_version, sdk_sha):
    if (
        type(event) is not dict
        or event.keys() != {"event", "count", "limits", "resources", "sdk_version", "sdk_sha256"}
        or type(event["count"]) is not int
        or event["count"] != 64
        or event["sdk_version"] != sdk_version
        or event["sdk_sha256"] != sdk_sha
        or type(event["limits"]) is not dict
        or event["limits"].keys()
        != {"cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes"}
        or any(value is not None and not finite(value) for value in event["limits"].values())
        or type(event["resources"]) is not dict
        or event["resources"].keys() != {"process_cpu_ms", "peak_rss_bytes"}
        or not finite(event["resources"]["process_cpu_ms"])
        or event["resources"]["peak_rss_bytes"] is not None
        and not finite(event["resources"]["peak_rss_bytes"])
    ):
        raise ValueError("Invalid completion protocol")


def read_protocol(raw, cases, expectations, cell, sdk_version, sdk_sha):
    rows, end = [], None
    expected_cases = cell_cases(cases, cell)
    profile = CELLS[cell][1]
    valid = len(raw) <= limits.MAX_CAPTURE_BYTES
    try:
        for line in raw.splitlines(keepends=True):
            if not line.endswith(b"\n") or end is not None:
                raise ValueError
            event = contract.strict_json(line)
            if type(event) is not dict:
                raise ValueError
            if event.keys() == {"event", "row"} and event["event"] == "row":
                if len(rows) >= 64:
                    raise ValueError
                case, representation = expected_cases[len(rows)]
                expected = expectations[case["id"], profile, representation]
                row = validate_row(event["row"], case, expected)
                rows.append(
                    {
                        **row,
                        "family": case["family"],
                        "label": case["label"],
                        "language": case["language"],
                        "profile": profile,
                        "contract_scope": expected["contract"]["scope"],
                    }
                )
            elif event.get("event") == "complete" and len(rows) == 64:
                validate_end(event, sdk_version, sdk_sha)
                end = event
            else:
                raise ValueError
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        valid = False
    return rows, end, valid and end is not None


def measure(cell, cases, expectations, deadline, sdk_version, sdk_sha):
    row = dict(
        family=CELLS[cell][0],
        profile=CELLS[cell][1],
        expected_observations=64,
        status="not_started",
        child_reaped=False,
        rows=[],
    )
    if time.perf_counter() >= deadline:
        return row
    executable, environment = sys.executable, limits.child_environment()
    if sys.platform == "win32":
        executable = sys._base_executable
        environment["__PYVENV_LAUNCHER__"] = sys.executable
    interrupted = False
    handlers = {}

    def defer_interrupt(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    process = None
    started = time.perf_counter()
    try:
        for item in (signal.SIGINT, signal.SIGTERM):
            handlers[item] = signal.signal(item, defer_interrupt)
        with tempfile.TemporaryDirectory(prefix="guardtrellis-detector-delivery-") as directory:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                try:
                    process = subprocess.Popen(
                        [executable, str(HERE), "--worker", str(cell)],
                        stdin=subprocess.DEVNULL,
                        stdout=output,
                        stderr=errors,
                        cwd=directory,
                        env=environment,
                        start_new_session=os.name == "posix",
                    )
                    row["status"] = "worker_error"
                    stop = min(deadline, started + WALL_SECONDS)
                    while process.poll() is None:
                        if interrupted:
                            row["status"] = "interrupted"
                            break
                        if time.perf_counter() >= stop:
                            row["status"] = "wall_timeout"
                            break
                        if any(
                            os.fstat(stream.fileno()).st_size > limits.MAX_CAPTURE_BYTES
                            for stream in (output, errors)
                        ):
                            row["status"] = "output_limit"
                            break
                        try:
                            process.wait(timeout=min(0.05, max(0.001, stop - time.perf_counter())))
                        except subprocess.TimeoutExpired:
                            pass
                except KeyboardInterrupt:
                    interrupted = True
                    row["status"] = "interrupted"
                finally:
                    if process is not None:
                        limits.kill_and_reap(process)
                        row["child_reaped"] = process.poll() is not None
                output.seek(0)
                captured = output.read(limits.MAX_CAPTURE_BYTES + 1)
                errors.seek(0, os.SEEK_END)
                row["stderr_bytes"] = errors.tell()
                row["stdout_bytes"] = len(captured)
                row["returncode"] = None if process is None else process.returncode
                rows, end, valid = read_protocol(
                    captured, cases, expectations, cell, sdk_version, sdk_sha
                )
                row["rows"] = rows
                if end is not None:
                    row.update(resources=end["resources"], limits=end["limits"])
                if interrupted:
                    row["status"] = "interrupted"
                elif row["status"] == "worker_error":
                    row["status"] = (
                        "completed"
                        if valid and row["returncode"] == 0 and row["stderr_bytes"] == 0
                        else "protocol_error"
                    )
    except (OSError, ValueError, subprocess.SubprocessError):
        row["status"] = "interrupted" if interrupted else "supervisor_error"
    finally:
        for item, handler in handlers.items():
            signal.signal(item, handler)
    row["wall_ms"] = (time.perf_counter() - started) * 1000
    return row


def ratio(a, b):
    return a / b if b else None


def summarize(rows, inventory):
    counts = Counter()
    for row in rows:
        if row["action"] == "error":
            counts["errors"] += 1
        else:
            positive = row["label"] == "sensitive"
            predicted = bool(row["primary"])
            counts[
                ("tp" if predicted else "fn") if positive else ("fp" if predicted else "tn")
            ] += 1
    return {
        "base_scenarios": len({row["id"] for row in inventory}),
        "expected_observations": len(inventory),
        "observations": len(rows),
        "incomplete_observations": len(inventory) - len(rows),
        "positive_expected": sum(row["label"] == "sensitive" for row in inventory),
        "negative_expected": sum(row["label"] == "benign" for row in inventory),
        "positive_observed": sum(row["label"] == "sensitive" for row in rows),
        "negative_observed": sum(row["label"] == "benign" for row in rows),
        "positive_errors": sum(
            row["label"] == "sensitive" and row["action"] == "error" for row in rows
        ),
        "negative_errors": sum(
            row["label"] == "benign" and row["action"] == "error" for row in rows
        ),
        **{key: counts[key] for key in ("tp", "fp", "tn", "fn", "errors")},
        "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
        "actions": {
            action: sum(row["action"] == action for row in rows) for action in sorted(ACTIONS)
        },
        "desired_exact": sum(all(row["comparisons"].values()) for row in rows),
        "desired_mismatches": {
            key: sum(not row["comparisons"][key] for row in rows) for key in sorted(COMPARISONS)
        },
        "contract_eligible_expected": sum(row["eligible"] for row in inventory),
        "contract_checked": sum(row["contract_match"] is not None for row in rows),
        "contract_failures": sum(row["contract_match"] is False for row in rows),
        "contract_scopes": {
            scope: {
                "expected": sum(row["scope"] == scope for row in inventory),
                "observed": sum(row["contract_scope"] == scope for row in rows),
            }
            for scope in sorted({row["scope"] for row in inventory})
        },
        "incidental_finding_observations": sum(bool(row["incidental_codes"]) for row in rows),
        "delivery_integrity_failures": sum(not row["delivery_integrity"] for row in rows),
        "privacy_failures": sum(not row["privacy_ok"] for row in rows),
    }


def inventory(cases, expectations):
    return [
        {
            "id": case["id"],
            "family": case["family"],
            "language": case["language"],
            "label": case["label"],
            "profile": profile,
            "representation": representation,
            "eligible": expectations[case["id"], profile, representation]["contract"]["eligible"],
            "scope": expectations[case["id"], profile, representation]["contract"]["scope"],
        }
        for case in cases
        for profile in contract.PROFILES
        for representation in contract.REPRESENTATIONS
    ]


def metadata(freeze):
    sdk_version, sdk_files, sdk_sha = sdk_fingerprint()
    files = [
        HERE,
        HERE.with_name("assets.py"),
        *[HERE.with_name(name) for name in freeze["files"]],
        HERE.with_name("freeze_v1.json"),
        ROOT / "evaluation/measure_resources.py",
        ROOT / "uv.lock",
    ]
    return {
        "created_utc": datetime.now(UTC).isoformat(),
        "sdk_version": sdk_version,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "source_base_commit": freeze["source_base_commit"],
        "worktree_evidence": "source hashes identify local edits; base commit excludes this patch",
        "freeze_sha256": assets.FREEZE_SHA256,
        "freeze_receipt": assets.RECEIPT,
        "sdk_sha256": sdk_files,
        "worker_sdk_fingerprint": sdk_sha,
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
        "source_sha256": {
            path.relative_to(ROOT).as_posix(): assets.digest(path.read_bytes()) for path in files
        },
        "authorship": "AI-assisted implementation-aware synthetic development cases",
        "case_review": "author self-review only; maintainer approved scope",
        "independent_case_review": False,
        "license": "Apache-2.0",
        "usage": "development",
    }


def build_report(cases, expectations, freeze, runs, interrupted, provenance):
    rows = [row for run in runs for row in run["rows"]]
    planned = inventory(cases, expectations)
    summary = summarize(rows, planned)
    measurement_ok = (
        not interrupted
        and len(runs) == 6
        and all(
            run["status"] == "completed" and run["child_reaped"] and len(run["rows"]) == 64
            for run in runs
        )
        and not any(
            summary[key]
            for key in (
                "errors",
                "incomplete_observations",
                "delivery_integrity_failures",
                "privacy_failures",
            )
        )
    )
    report = {
        "schema_version": 1,
        "dataset_version": contract.VERSION,
        "metadata": provenance,
        "configuration": {
            "stage": "retrieval",
            "profiles": list(contract.PROFILES),
            "representations": list(contract.REPRESENTATIONS),
            "child_wall_seconds": WALL_SECONDS,
            "total_wall_seconds": TOTAL_SECONDS,
            "cleanup_allowance_seconds": 5,
            "max_capture_bytes": limits.MAX_CAPTURE_BYTES,
            "max_input_chars": contract.MAX_INPUT_CHARS,
            "expected_children": 6,
        },
        "interrupted": interrupted,
        "measurement_checks_passed": measurement_ok,
        "contract_checks_passed": (
            measurement_ok
            and summary["contract_checked"] == summary["contract_eligible_expected"]
            and summary["contract_failures"] == 0
        ),
        "summary": summary,
        "runs": [
            {
                **{key: value for key, value in run.items() if key != "rows"},
                "observed_observations": len(run["rows"]),
            }
            for run in runs
        ],
        "rows": rows,
    }
    for dimension, values in (
        ("profile", contract.PROFILES),
        ("family", contract.FAMILIES),
        ("representation", contract.REPRESENTATIONS),
        ("language", ("en",)),
    ):
        report[f"by_{dimension}"] = {
            value: summarize(
                [row for row in rows if row[dimension] == value],
                [row for row in planned if row[dimension] == value],
            )
            for value in values
        }
    report["by_family_profile"] = {
        f"{family}/{profile}": summarize(
            [row for row in rows if row["family"] == family and row["profile"] == profile],
            [row for row in planned if row["family"] == family and row["profile"] == profile],
        )
        for family, profile in CELLS
    }
    report["by_family_profile_representation"] = {
        f"{family}/{profile}/{representation}": summarize(
            [
                row
                for row in rows
                if (row["family"], row["profile"], row["representation"])
                == (family, profile, representation)
            ],
            [
                row
                for row in planned
                if (row["family"], row["profile"], row["representation"])
                == (family, profile, representation)
            ],
        )
        for family, profile in CELLS
        for representation in contract.REPRESENTATIONS
    }
    return report


def render(report):
    lines = [
        "# Detector and checked-delivery challenge, v1",
        "",
        "48 AI-assisted synthetic development scenarios; no independent per-case review.",
        "384 correlated observations, not 384 independent examples. English context only.",
        "No population accuracy, hidden-test, performance or superiority claim.",
        "",
        f"SDK {report['metadata']['sdk_version']}; {report['metadata']['system']} / "
        f"Python {report['metadata']['python']}. Source/runtime digests are in results.json.",
        f"Pre-observation [freeze receipt]({assets.RECEIPT}); SHA-256 `{assets.FREEZE_SHA256}`.",
        "",
        f"Measurement integrity: **{report['measurement_checks_passed']}**; "
        f"eligible contract/control checks: **{report['contract_checks_passed']}**.",
        "",
        "| Family / profile | Observed / expected | TP / FP / TN / FN | "
        "Errors | Desired exact | Contract failures |",
        "| --- | ---: | --- | ---: | ---: | ---: |",
    ]
    for name, row in report["by_family_profile"].items():
        lines.append(
            f"| {name} | {row['observations']}/{row['expected_observations']} | "
            f"{row['tp']} / {row['fp']} / {row['tn']} / {row['fn']} | {row['errors']} | "
            f"{row['desired_exact']} | {row['contract_failures']} |"
        )
    lines.extend(
        [
            "",
            "Primary-family codes determine signals. Incidental PII never counts as a URI signal.",
            "ERROR and incomplete rows remain separate. Undefined rates are null.",
            "Desired exact requires action, full spans, checked text and consumer delivery.",
            "Contract checks separately count disabled-feature and raw-escaped controls.",
            "Benign shapes can meet the SDK contract while being scenario false positives.",
            "Unsupported misses and partial redactions remain visible here and in results.json.",
            "CPU/RSS describe whole-worker containment, not per-scan performance.",
            "Historical fixtures/reports and SDK code remain unchanged.",
            "",
            "## Retained mismatches",
            "",
        ]
    )
    for row in report["rows"]:
        failed = [key for key, matched in row["comparisons"].items() if not matched]
        if failed or row["contract_match"] is False or row["action"] == "error":
            lines.append(
                f"- `{row['id']}` / {row['profile']} / {row['representation']}: "
                f"{row['action']}; desired mismatches {', '.join(failed) or 'none'}; "
                f"contract {row['contract_scope']} / {row['contract_match']}."
            )
    return "\n".join(lines) + "\n"


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Invalid evaluation arguments.\n")


def write_report(report, directory):
    (directory / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (directory / "REPORT.md").write_text(render(report), encoding="utf-8")


def main(argv=None):
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--worker", type=int, choices=range(6), help=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
    except KeyboardInterrupt:
        print("Evaluation interrupted.", file=sys.stderr)
        return 130
    if args.worker is not None:
        if args.report_dir is not None:
            parser.error("Invalid worker arguments")
        try:
            worker(args.worker)
            return 0
        except KeyboardInterrupt:
            emit({"event": "error", "code": "interrupted"})
            return 130
        except Exception:
            emit({"event": "error", "code": "worker_error"})
            return 1
    if args.report_dir is None or args.report_dir.exists():
        parser.error("A new report directory is required")
    try:
        cases, expectations, freeze = assets.load_frozen()
        provenance = metadata(freeze)
    except KeyboardInterrupt:
        print("Evaluation interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print("Cannot prepare frozen evaluation.", file=sys.stderr)
        return 1
    interrupted, handlers, runs = [False], {}, []

    def defer_interrupt(_signum, _frame):
        interrupted[0] = True

    try:
        for item in (signal.SIGINT, signal.SIGTERM):
            handlers[item] = signal.signal(item, defer_interrupt)
        deadline = time.perf_counter() + TOTAL_SECONDS
        for cell, (family, profile) in enumerate(CELLS):
            if interrupted[0]:
                result = dict(
                    family=family,
                    profile=profile,
                    expected_observations=64,
                    status="not_started",
                    child_reaped=False,
                    rows=[],
                )
            else:
                result = measure(
                    cell,
                    cases,
                    expectations,
                    deadline,
                    provenance["sdk_version"],
                    provenance["worker_sdk_fingerprint"],
                )
            runs.append(result)
            interrupted[0] |= result["status"] == "interrupted"
        report = build_report(cases, expectations, freeze, runs, interrupted[0], provenance)
        args.report_dir.mkdir(parents=True)
        write_report(report, args.report_dir)
        if interrupted[0] and not report["interrupted"]:
            report.update(
                interrupted=True, measurement_checks_passed=False, contract_checks_passed=False
            )
            write_report(report, args.report_dir)
    except (OSError, ValueError):
        print("Cannot complete frozen evaluation.", file=sys.stderr)
        return 1
    finally:
        for item, handler in handlers.items():
            signal.signal(item, handler)
    print(
        json.dumps(
            {
                "measurement_checks_passed": report["measurement_checks_passed"],
                "contract_checks_passed": report["contract_checks_passed"],
                "summary": report["summary"],
            },
            sort_keys=True,
        )
    )
    return 130 if report["interrupted"] else int(not report["contract_checks_passed"])


if __name__ == "__main__":
    raise SystemExit(main())
