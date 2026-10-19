"""Compare unchanged default and opt-in phone policies on authored development data."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import guardtrellis
from guardtrellis import Action, Guard, JSONScanner, PIIScanner, Rejected, SecretScanner, ToolGuard

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
HISTORICAL = ROOT / "evaluation/policy_combinations/detection_coverage_v1.jsonl"
CORPUS = HERE / "grammar_v1.jsonl"
MODES = ("default", "formatted")
SPEC = spec_from_file_location("formatted_phone_policy_evaluation", HISTORICAL.parent / "run.py")
assert SPEC is not None and SPEC.loader is not None
legacy = module_from_spec(SPEC)
SPEC.loader.exec_module(legacy)


def load_corpus(path):
    with path.open("rb") as source:
        return legacy.load_cases(source.read(1_000_001))


def load_cases():
    """Preserve historical rows/labels; the new grammar is a separate dataset version."""
    old, new = load_corpus(HISTORICAL), load_corpus(CORPUS)
    if {case["dataset_version"] for case in old} != {"detection-coverage-v1"} or {
        case["dataset_version"] for case in new
    } != {"formatted-phone-grammar-v1"}:
        raise ValueError("Unexpected dataset version")
    cases = old + new
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Duplicate comparison ID")
    if any(
        case["profile"]
        not in {"run_pii", "run_pii_warn", "run_pii_block", "tool_query_pii", "decoded_query_pii"}
        for case in cases
    ):
        raise ValueError("Unsupported comparison profile")
    return cases


def formatted_policy(profile):
    if profile.startswith("run_"):
        action = Action(profile.removeprefix("run_pii_")) if profile != "run_pii" else Action.REDACT
        return Guard(
            input_scanners=[PIIScanner(action=action, phone_mode="formatted")],
            output_scanners=[PIIScanner(phone_mode="formatted")],
        )
    scanners = [SecretScanner(), PIIScanner(formats=["email", "phone"], phone_mode="formatted")]
    if profile == "tool_query_pii":
        return ToolGuard(
            {"search": legacy.QUERY_SCHEMA},
            argument_scanners=scanners,
            max_chars=legacy.decoded_query.MAX_JSON_CHARS,
            max_depth=legacy.decoded_query.MAX_DEPTH,
        )
    return Guard(tool_scanners=scanners, max_chars=legacy.decoded_query.MAX_QUERY_CHARS)


def observe(case, mode):
    if mode == "default":
        return legacy.observe(case)
    if mode != "formatted":
        raise ValueError("Unknown fixed comparison mode")
    policy = formatted_policy(case["profile"])
    if case["profile"] == "decoded_query_pii":
        return legacy.observe_decoded_query(case, policy)
    callbacks, dispatches = [], []

    def callback(checked):
        callbacks.append(checked)
        return case["response"]

    tool = case["profile"] == "tool_query_pii"
    if tool:
        result = policy.validate(case.get("tool", "search"), case["text"])
        checked_text = result.validation.text
        stages = [result.validation]
        if result.accepted:
            name, arguments = result.require_call()
            assert name == "search"
            dispatches.append(arguments)
        delivered = result.arguments
    else:
        result = policy.run(case["text"], callback)
        checked_text = result.input_result.text
        stages = [result.input_result, *([result.output_result] if result.output_result else [])]
        delivered = result.text
    diagnostics = result.diagnostics()
    findings = [item for stage in stages for item in stage.diagnostics()["findings"]]
    rejection = ""
    if not result.accepted:
        try:
            result.require_call() if tool else result.require_text()
        except Rejected as error:
            rejection = [str(error), repr(error)]
        else:
            raise AssertionError("Rejected result released content")
    privacy = {
        key: not legacy.contains_marker(value, legacy.privacy_markers(case))
        for key, value in {
            "diagnostics_safe": diagnostics,
            "repr_safe": repr(result),
            "rejection_safe": rejection,
        }.items()
    }
    actual = {
        "action": result.action.value,
        "accepted": result.accepted,
        "checked_text": checked_text,
        "callback_inputs": callbacks,
        "delivered": delivered,
        "dispatches": dispatches,
        "findings": findings,
        "checked_json_valid": Guard(input_scanners=[JSONScanner()]).scan(checked_text).accepted
        if tool and result.accepted
        else None,
    }
    return {
        "observed_action": result.action.value,
        "accepted": result.accepted,
        "signal": bool(findings),
        "callback_count": len(callbacks),
        "dispatch_count": len(dispatches),
        "comparisons": {key: actual[key] == value for key, value in case["expected"].items()},
        **privacy,
    }


def evaluate(cases):
    rows = []
    for case in cases:
        for mode in MODES:
            try:
                observed = observe(case, mode)
                mismatches = [
                    key for key, matches in observed["comparisons"].items() if not matches
                ]
                privacy = [
                    key
                    for key in ("diagnostics_safe", "repr_safe", "rejection_safe")
                    if not observed[key]
                ]
                unexpected = observed["observed_action"] == "error"
            except Exception:
                # Exceptions may contain fixtures. Keep only fixed error metadata.
                observed, mismatches, privacy, unexpected = {}, [], [], True
            rows.append(
                {
                    **{
                        key: case[key]
                        for key in ("id", "dataset_version", "profile", "pair_id", "coverage_scope")
                    },
                    "phone_mode": mode,
                    "known_limit": case["coverage_scope"] == "deferred"
                    or case["id"] == "phone-signed-integer-context",
                    "expected_signal": case["expected_signal"],
                    "observed_action": observed.get("observed_action"),
                    "accepted": observed.get("accepted"),
                    "signal": observed.get("signal"),
                    "callback_count": observed.get("callback_count", 0),
                    "dispatch_count": observed.get("dispatch_count", 0),
                    "decoded_action": observed.get("decoded_action"),
                    "comparisons": observed.get("comparisons", {}),
                    "mismatches": mismatches,
                    "privacy_failures": privacy,
                    "unexpected_error": unexpected,
                }
            )
    return rows


def summarize(rows):
    return {
        "observations": len(rows),
        "exact_outcome_matches": sum(
            not row["mismatches"] and not row["unexpected_error"] for row in rows
        ),
        "mismatched_cases": sum(bool(row["mismatches"]) for row in rows),
        "known_limit_mismatches": sum(
            row["known_limit"] and bool(row["mismatches"]) for row in rows
        ),
        "false_positive_signals": sum(
            row["signal"] is True and not row["expected_signal"] for row in rows
        ),
        "missed_signals": sum(row["signal"] is False and row["expected_signal"] for row in rows),
        "unexpected_errors": sum(row["unexpected_error"] for row in rows),
        "privacy_failures": sum(bool(row["privacy_failures"]) for row in rows),
    }


def source_metadata():
    paths = [
        Path(__file__),
        HERE / "resources.py",
        ROOT / "evaluation/measure_resources.py",
        HISTORICAL,
        CORPUS,
        Path(legacy.__file__),
        ROOT / "examples/decoded_query.py",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
    ]
    paths.extend(sorted((ROOT / "src/guardtrellis").rglob("*.py")))
    return {
        "comparison_version": "formatted-phone-v1",
        "sdk_source_version": guardtrellis.__version__,
        "installed_distribution_version": version("guardtrellis"),
        "dependencies": {name: version(name) for name in ("jsonschema", "referencing")},
        "python": platform.python_version(),
        "platform": platform.platform(),
        "created_utc": datetime.now(UTC).isoformat(),
        "usage": "authored-development-only",
        "sha256": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths
        },
    }


def write_report(report_dir, rows, resource_rows=None):
    report_dir.mkdir(parents=True, exist_ok=False)
    summaries = {
        mode: summarize([row for row in rows if row["phone_mode"] == mode]) for mode in MODES
    }
    report = {
        "metadata": source_metadata(),
        "summary": summaries,
        "rows": rows,
        "resource_probes": resource_rows,
    }
    (report_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Formatted phone comparison, v1",
        "",
        "AI-assisted authored synthetic development fixtures; no production accuracy claim.",
        "Default and opt-in policies receive the same retained labels, spans and payloads.",
        "A detection signal alone does not establish complete redaction or checked delivery.",
        "",
        "| Mode | Observations | Exact matches | Mismatches | Known-limit mismatches |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for mode, summary in summaries.items():
        lines.append(
            f"| {mode} | {summary['observations']} | {summary['exact_outcome_matches']} "
            f"| {summary['mismatched_cases']} | {summary['known_limit_mismatches']} |"
        )
    if resource_rows is not None:
        completed = sum(row["contract_matches"] for row in resource_rows)
        lines.extend(
            [
                "",
                "Resource probes use separate children, each with a 10-second parent deadline.",
                "Fixed synthetic measurements are not service capacity or a scanner deadline.",
                f"Completed contract matches: {completed}/{len(resource_rows)} modes.",
            ]
        )
    lines += [
        "",
        "Signed-integer ambiguity, deferred forms and raw escaped-JSON misses remain visible.",
        "Exit zero means no harness/privacy error; review mismatches, not only exit status.",
        "[results.json](results.json) retains safe metadata and hashes, without payload text.",
        "",
    ]
    (report_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument(
        "--resources", action="store_true", help="Run fixed subprocess resource probes"
    )
    arguments = parser.parse_args(argv)
    if arguments.report_dir.exists():
        parser.error("Report directory already exists; choose a fresh directory")
    try:
        rows = evaluate(load_cases())
        resource_rows = None
        if arguments.resources:
            spec = spec_from_file_location("formatted_phone_resources", HERE / "resources.py")
            assert spec is not None and spec.loader is not None
            resource_module = module_from_spec(spec)
            spec.loader.exec_module(resource_module)
            resource_rows = [resource_module.measure(mode) for mode in MODES]
        report = write_report(arguments.report_dir, rows, resource_rows)
    except (OSError, ValueError, UnicodeError):
        parser.error("Evaluation input or report creation failed")
    print(json.dumps(report["summary"], sort_keys=True))
    return int(
        any(row["unexpected_error"] or row["privacy_failures"] for row in rows)
        or any(not row["contract_matches"] for row in resource_rows or [])
    )


if __name__ == "__main__":
    sys.exit(main())
