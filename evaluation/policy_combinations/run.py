"""Bounded synthetic policy/delivery evaluation, separate from detection benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import statistics
import sys
import unicodedata
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from time import perf_counter_ns

import guardtrellis
from guardtrellis import (
    Action,
    Guard,
    InvisibleScanner,
    JSONScanner,
    LiteralScanner,
    PIIScanner,
    Rejected,
    SecretScanner,
    ToolGuard,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = HERE / "policy_delivery_v1.jsonl"
RECIPE_PATH = ROOT / "examples/decoded_query.py"
RECIPE_SPEC = spec_from_file_location("evaluation_decoded_query_recipe", RECIPE_PATH)
assert RECIPE_SPEC is not None and RECIPE_SPEC.loader is not None
decoded_query = module_from_spec(RECIPE_SPEC)
RECIPE_SPEC.loader.exec_module(decoded_query)
FAMILIES = ("secrets", "json", "ordering", "delivery", "tool", "errors")
PROFILES = {
    "secret_block": "scan",
    "secret_redact": "scan",
    "secret_warn": "scan",
    "json_pii": "scan",
    "json_pii_min_length": "scan",
    "pii_then_literal": "scan",
    "literal_then_pii": "scan",
    "two_redactions": "scan",
    "warning_then_block": "scan",
    "run_pii": "run",
    "run_pii_warn": "run",
    "run_pii_block": "run",
    "run_secret_input": "run",
    "run_secret_output": "run",
    "run_scanner_error": "run",
    "run_callback_error": "run",
    "tool_pii": "tool",
    "tool_pii_min_length": "tool",
    "tool_secret": "tool",
    "tool_scanner_error": "tool",
    "tool_query_pii": "tool",
    "decoded_query_pii": "decoded",
}
VALUE_SCHEMA = {
    "type": "object",
    "properties": {"message": {"type": "string", "minLength": 1}},
    "required": ["message"],
    "additionalProperties": False,
}
LONG_VALUE_SCHEMA = {
    **VALUE_SCHEMA,
    "properties": {"message": {"type": "string", "minLength": 6}},
}
QUERY_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "minLength": 1, "maxLength": decoded_query.MAX_QUERY_CHARS}
    },
    "required": ["query"],
    "additionalProperties": False,
}
EXPECT_FIELDS = {"action", "accepted", "checked_text", "callback_inputs", "delivered", "dispatches"}
OPTIONAL_EXPECT_FIELDS = {
    "findings",
    "trace",
    "checked_json_valid",
    "decoded_action",
    "decoded_findings",
    "decoded_trace",
}
OPTIONAL_PUBLIC_FIELDS = ("pair_id", "coverage_scope")
PUBLIC_FIELDS = (
    "id",
    "family",
    "profile",
    "dataset_version",
    "source",
    "usage",
    "language",
    "format",
    "label_basis",
    "expected_signal",
)


class FailingScanner:
    name = "fixture_failure"

    def scan(self, text, *, stage):
        # Deliberately include the payload in an exception to test the SDK boundary.
        raise RuntimeError(text)


def policy(profile):
    """Named, fixed policies are part of this evaluation, not a configuration API."""
    pii = PIIScanner()
    if profile.startswith("secret_"):
        return Guard(input_scanners=[SecretScanner(action=Action(profile[7:]))])
    if profile in ("json_pii", "json_pii_min_length"):
        schema = LONG_VALUE_SCHEMA if profile.endswith("min_length") else VALUE_SCHEMA
        return Guard(input_scanners=[JSONScanner(), pii, JSONScanner(schema)])
    if profile == "pii_then_literal":
        return Guard(input_scanners=[pii, LiteralScanner(["[PII]"])])
    if profile == "literal_then_pii":
        return Guard(input_scanners=[LiteralScanner(["[PII]"]), pii])
    if profile == "two_redactions":
        return Guard(input_scanners=[pii, LiteralScanner(["private"], action=Action.REDACT)])
    if profile == "warning_then_block":
        return Guard(input_scanners=[InvisibleScanner(), SecretScanner()])
    if profile == "run_pii":
        return Guard(input_scanners=[pii], output_scanners=[PIIScanner()])
    if profile in ("run_pii_warn", "run_pii_block"):
        return Guard(
            input_scanners=[PIIScanner(action=Action(profile.removeprefix("run_pii_")))],
            output_scanners=[PIIScanner()],
        )
    if profile == "run_secret_input":
        return Guard(input_scanners=[SecretScanner()])
    if profile == "run_secret_output":
        return Guard(output_scanners=[SecretScanner()])
    if profile == "run_scanner_error":
        return Guard(input_scanners=[FailingScanner()])
    if profile == "run_callback_error":
        return Guard()
    if profile == "tool_query_pii":
        return ToolGuard(
            {"search": QUERY_SCHEMA},
            argument_scanners=[SecretScanner(), PIIScanner(formats=["email", "phone"])],
            max_chars=decoded_query.MAX_JSON_CHARS,
            max_depth=decoded_query.MAX_DEPTH,
        )
    if profile == "decoded_query_pii":
        return Guard(
            tool_scanners=[SecretScanner(), PIIScanner(formats=["email", "phone"])],
            max_chars=decoded_query.MAX_QUERY_CHARS,
        )
    if profile.startswith("tool_"):
        schema = LONG_VALUE_SCHEMA if profile.endswith("min_length") else VALUE_SCHEMA
        scanner = (
            FailingScanner()
            if profile == "tool_scanner_error"
            else SecretScanner()
            if profile == "tool_secret"
            else pii
        )
        return ToolGuard({"submit": schema}, argument_scanners=[scanner])
    raise ValueError("Unknown evaluation profile")


def load_cases(raw):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate metadata key")
            result[key] = value
        return result

    if len(raw) > 1_000_000:
        raise ValueError("Corpus exceeds one megabyte")
    cases, ids = [], set()
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        try:
            case = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, RecursionError) as error:
            raise ValueError(f"Invalid JSON in corpus row {number}") from error
        if not isinstance(case, dict) or any(
            not isinstance(case.get(key), str) or not 1 <= len(case[key]) <= 1000
            for key in PUBLIC_FIELDS
            if key != "expected_signal"
        ):
            raise ValueError(f"Invalid provenance in corpus row {number}")
        if (
            not re.fullmatch(r"[a-z0-9-]+", case["id"])
            or case["id"] in ids
            or not re.fullmatch(r"[a-z0-9-]+", case["dataset_version"])
            or case["family"] not in FAMILIES
            or case["profile"] not in PROFILES
            or case["usage"] != "development"
            or not re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", case["language"])
            or type(case.get("expected_signal")) is not bool
            or not isinstance(case.get("text"), str)
            or len(case["text"]) > 10_000
            or not isinstance(case.get("response", ""), str)
            or len(case.get("response", "")) > 10_000
            or PROFILES[case["profile"]] == "run"
            and "response" not in case
            or not isinstance(case.get("tool", "submit"), str)
        ):
            raise ValueError(
                f"Invalid label, profile, input or duplicate ID in corpus row {number}"
            )
        expected = case.get("expected")
        if (
            not isinstance(expected, dict)
            or not EXPECT_FIELDS <= expected.keys() <= EXPECT_FIELDS | OPTIONAL_EXPECT_FIELDS
            or not isinstance(expected["action"], str)
            or expected["action"] not in {action.value for action in Action}
            or type(expected["accepted"]) is not bool
            or not isinstance(expected["callback_inputs"], list)
            or not all(isinstance(value, str) for value in expected["callback_inputs"])
            or not isinstance(expected["dispatches"], list)
            or any(not isinstance(value, dict) for value in expected["dispatches"])
            or expected["checked_text"] is not None
            and not isinstance(expected["checked_text"], str)
            or expected["delivered"] is not None
            and not isinstance(expected["delivered"], (str, dict))
            or any(
                not isinstance(expected[key], list)
                for key in ("findings", "trace", "decoded_findings", "decoded_trace")
                if key in expected
            )
            or expected.get("checked_json_valid") is not None
            and type(expected["checked_json_valid"]) is not bool
            or expected.get("decoded_action") is not None
            and (
                not isinstance(expected["decoded_action"], str)
                or expected["decoded_action"] not in {action.value for action in Action}
            )
            or case["profile"] != "decoded_query_pii"
            and any(key.startswith("decoded_") for key in expected)
        ):
            raise ValueError(f"Invalid expectations in corpus row {number}")
        if (
            "pair_id" in case
            and (
                not isinstance(case["pair_id"], str)
                or not re.fullmatch(r"[a-z0-9-]+", case["pair_id"])
            )
            or "coverage_scope" in case
            and case["coverage_scope"] not in ("baseline", "proposed", "deferred", "benign")
        ):
            raise ValueError(f"Invalid pair or coverage scope in corpus row {number}")
        markers = case.get("privacy_markers")
        if (
            not isinstance(markers, list)
            or not markers
            or any(not isinstance(marker, str) or len(marker) < 8 for marker in markers)
        ):
            raise ValueError(f"Invalid privacy markers in corpus row {number}")
        cases.append(case)
        ids.add(case["id"])
    if not 1 <= len(cases) <= 200:
        raise ValueError("Supply between 1 and 200 cases")
    if len({case["dataset_version"] for case in cases}) != 1:
        raise ValueError("Evaluate one dataset version at a time")
    return cases


def contains_marker(value, markers):
    """Check decoded diagnostic strings and standard string serialization forms."""
    if isinstance(value, dict):
        return any(contains_marker(item, markers) for pair in value.items() for item in pair)
    if isinstance(value, (list, tuple)):
        return any(contains_marker(item, markers) for item in value)
    if not isinstance(value, str):
        return False
    return any(
        representation in value
        for marker in markers
        for representation in (
            marker,
            repr(marker)[1:-1],
            json.dumps(marker, ensure_ascii=False)[1:-1],
            json.dumps(marker, ensure_ascii=True)[1:-1],
        )
    )


def privacy_markers(case):
    """Include bounded whole payloads as well as authored decoded/wire canaries.

    Whole serialized JSON can retain noncanonical escapes that are absent from a
    decoded email marker. Do not decode or normalize the payload to inspect it.
    Very short values are excluded to avoid matching ordinary diagnostic metadata.
    """
    return list(
        dict.fromkeys(
            [
                *case["privacy_markers"],
                *(
                    value
                    for field in ("text", "response")
                    if isinstance(value := case.get(field), str) and 8 <= len(value) <= 10_000
                ),
            ]
        )
    )


def observe_decoded_query(case, guard):
    """Observe the shipped recipe without assigning decoded spans to serialized text."""
    decoded_results = []

    class RecordedPolicy:
        def scan(self, text, *, stage):
            result = guard.scan(text, stage=stage)
            decoded_results.append(result)
            return result

    handoff = None
    rejection = ""
    action_source = "handoff"
    try:
        handoff = decoded_query.check_query(
            case.get("tool", "search"), case["text"], query_guard=RecordedPolicy()
        )
        result = handoff
    except Rejected as error:
        rejection = str(error)
        if decoded_results and not decoded_results[-1].accepted:
            result = decoded_results[-1]
            action_source = "decoded-policy"
        else:
            # Recover a real SDK rejection for strict preflight failures. Recipe-owned
            # postconditions have no SDK action: retain them as harness errors rather
            # than inventing BLOCK/ERROR. Those cases are outside this comparison batch.
            result = decoded_query.TOOLS.validate(case.get("tool", "search"), case["text"])
            if result.accepted:
                raise
            action_source = "preflight"

    decoded_result = decoded_results[-1] if decoded_results else None
    decoded_diagnostics = decoded_result.diagnostics() if decoded_result else None
    decoded_findings = decoded_diagnostics["findings"] if decoded_diagnostics else []
    decoded_trace = decoded_diagnostics["trace"] if decoded_diagnostics else []
    final_diagnostics = handoff.diagnostics() if handoff else result.diagnostics()
    # A rejected decoded policy has no final serialized ToolResult. Do not put its
    # decoded-string offsets in the ordinary serialized findings/trace fields.
    final_findings = [] if action_source == "decoded-policy" else final_diagnostics["findings"]
    final_trace = [] if action_source == "decoded-policy" else final_diagnostics["trace"]
    dispatches = []
    checked_text = None
    delivered = None
    checked_json_valid = None
    if handoff is not None:
        name, arguments = handoff.require_call()
        assert name == "search"
        dispatches.append(arguments)
        checked_text = handoff.validation.text
        delivered = arguments
        checked_json_valid = Guard(input_scanners=[JSONScanner()]).scan(checked_text).accepted
    diagnostics = {
        "handoff": final_diagnostics if handoff else None,
        "rejection": final_diagnostics if not handoff else None,
        "decoded_query": decoded_diagnostics,
    }
    surfaces = {
        "diagnostics_safe": diagnostics,
        "repr_safe": [repr(result), *[repr(item) for item in decoded_results]],
        "rejection_safe": rejection,
    }
    privacy = {
        key: not contains_marker(value, privacy_markers(case)) for key, value in surfaces.items()
    }
    actual = {
        "action": result.action.value,
        "accepted": handoff is not None,
        "checked_text": checked_text,
        "callback_inputs": [],
        "delivered": delivered,
        "dispatches": dispatches,
        "findings": final_findings,
        "trace": final_trace,
        "checked_json_valid": checked_json_valid,
        "decoded_action": decoded_result.action.value if decoded_result else None,
        "decoded_findings": decoded_findings,
        "decoded_trace": decoded_trace,
    }
    return {
        "observed_action": actual["action"],
        "action_source": action_source,
        "accepted": actual["accepted"],
        "signal": bool(decoded_findings or final_findings),
        "callback_count": 0,
        "dispatch_count": len(dispatches),
        "checked_text_available": checked_text is not None,
        "delivered_available": delivered is not None,
        "checked_json_valid": checked_json_valid,
        "decoded_action": actual["decoded_action"],
        "decoded_coordinate_space": "decoded-query-string",
        "comparisons": {key: actual[key] == value for key, value in case["expected"].items()},
        **privacy,
        "diagnostics": diagnostics if privacy["diagnostics_safe"] else None,
    }


def observe(case):
    guard = policy(case["profile"])
    if case["profile"] == "decoded_query_pii":
        return observe_decoded_query(case, guard)
    callbacks, dispatches = [], []

    def callback(checked):
        callbacks.append(checked)
        if case["profile"] == "run_callback_error":
            raise RuntimeError(case["text"])
        return case["response"]

    mode = PROFILES[case["profile"]]
    if mode == "run":
        result = guard.run(case["text"], callback)
        checked_text = result.input_result.text
        stages = [result.input_result, *([result.output_result] if result.output_result else [])]
    elif mode == "tool":
        default_tool = "search" if case["profile"] == "tool_query_pii" else "submit"
        result = guard.validate(case.get("tool", default_tool), case["text"])
        checked_text = result.validation.text
        stages = [result.validation]
        if result.accepted:
            name, arguments = result.require_call()
            # This synthetic application dispatches only checked data to a local recorder.
            assert name == ("search" if case["profile"] == "tool_query_pii" else "submit")
            dispatches.append(arguments)
    else:
        result = guard.scan(case["text"])
        checked_text = result.text
        stages = [result]
    delivered = result.arguments if mode == "tool" else result.text
    findings = [item for stage in stages for item in stage.diagnostics()["findings"]]
    trace = [item for stage in stages for item in stage.diagnostics()["trace"]]
    diagnostics = result.diagnostics()
    rejection = ""
    if not result.accepted:
        try:
            result.require_call() if mode == "tool" else result.require_text()
        except Rejected as error:
            rejection = str(error)
        else:
            raise AssertionError("Rejected result unexpectedly released content")
    surfaces = {
        "diagnostics_safe": diagnostics,
        "repr_safe": repr(result),
        "rejection_safe": rejection,
    }
    privacy = {
        key: not contains_marker(value, privacy_markers(case)) for key, value in surfaces.items()
    }
    checked_json_valid = None
    if result.accepted and (mode == "tool" or case["profile"].startswith("json_")):
        checked_json_valid = Guard(input_scanners=[JSONScanner()]).scan(checked_text).accepted
    actual = {
        "action": result.action.value,
        "accepted": result.accepted,
        "checked_text": checked_text,
        "callback_inputs": callbacks,
        "delivered": delivered,
        "dispatches": dispatches,
        "findings": findings,
        "trace": trace,
        "checked_json_valid": checked_json_valid,
    }
    comparisons = {key: actual[key] == value for key, value in case["expected"].items()}
    return {
        "observed_action": result.action.value,
        "accepted": result.accepted,
        "signal": bool(findings),
        "callback_count": len(callbacks),
        "dispatch_count": len(dispatches),
        "checked_text_available": checked_text is not None,
        "delivered_available": delivered is not None,
        "checked_json_valid": checked_json_valid,
        "comparisons": comparisons,
        **privacy,
        # Never echo a diagnostic surface which fails a privacy check.
        "diagnostics": diagnostics if privacy["diagnostics_safe"] else None,
    }


def evaluate_cases(cases, iterations=1):
    if type(iterations) is not int or not 1 <= iterations <= 1000:
        raise ValueError("iterations must be between 1 and 1000")
    rows = []
    for case in cases:
        samples = []
        try:
            observed = None
            consistent = True
            warmups = 3 if iterations > 1 else 0
            for index in range(warmups + iterations):
                before = perf_counter_ns()
                current = observe(case)
                elapsed = (perf_counter_ns() - before) / 1_000
                if index >= warmups and iterations > 1:
                    samples.append(elapsed)
                if observed is not None and current != observed:
                    consistent = False
                observed = current
            if not consistent:
                observed = {
                    "observed_action": "error",
                    "harness_error": True,
                    "inconsistent_observations": True,
                    "comparisons": {},
                }
        except Exception:
            # The exception may contain a payload. Record failure without rendering it.
            observed = {"observed_action": "error", "harness_error": True, "comparisons": {}}
        if observed["observed_action"] == "error":
            outcome = "error"
        elif case["expected_signal"]:
            outcome = "tp" if observed["signal"] else "fn"
        else:
            outcome = "fp" if observed["signal"] else "tn"
        rows.append(
            {
                **{key: case[key] for key in PUBLIC_FIELDS},
                **{key: case[key] for key in OPTIONAL_PUBLIC_FIELDS if key in case},
                "expected_action": case["expected"]["action"],
                **observed,
                "outcome": outcome,
                "mismatches": [
                    key for key, matches in observed["comparisons"].items() if not matches
                ],
                "privacy_failures": [
                    key
                    for key in ("diagnostics_safe", "repr_safe", "rejection_safe")
                    if key in observed and not observed[key]
                ],
                "unexpected_error": observed["observed_action"] == "error"
                and case["expected"]["action"] != "error",
                **({"latency_us": samples} if iterations > 1 else {}),
            }
        )
    return rows


def summarize(rows):
    outcomes = Counter(row["outcome"] for row in rows)
    actions = Counter(row["observed_action"] for row in rows)
    summary = {
        "cases": len(rows),
        "positive_cases": sum(row["expected_signal"] for row in rows),
        "negative_cases": sum(not row["expected_signal"] for row in rows),
        **{key: outcomes[key] for key in ("tp", "fp", "tn", "fn", "error")},
        "expected_errors": sum(
            row["outcome"] == "error"
            and not row["unexpected_error"]
            and not row.get("harness_error")
            for row in rows
        ),
        "unexpected_errors": sum(row["unexpected_error"] for row in rows),
        "harness_errors": sum(row.get("harness_error", False) for row in rows),
        "mismatched_cases": sum(bool(row["mismatches"]) for row in rows),
        "privacy_failures": sum(
            any(
                not row.get(key, False)
                for key in ("diagnostics_safe", "repr_safe", "rejection_safe")
            )
            for row in rows
            if not row.get("harness_error")
        ),
        "actions": {action.value: actions[action.value] for action in Action},
        "callbacks": sum(row.get("callback_count", 0) for row in rows),
        "dispatches": sum(row.get("dispatch_count", 0) for row in rows),
    }
    latencies = sorted(sample for row in rows for sample in row.get("latency_us", []))
    if latencies:
        summary.update(
            latency_p50_us=statistics.median(latencies),
            latency_p95_us=latencies[math.ceil(len(latencies) * 0.95) - 1],
            timed_observations=len(latencies),
        )
    return summary


def build_report(cases, raw, rows, iterations=1):
    source_hash = hashlib.sha256()
    for path in sorted(Path(guardtrellis.__file__).parent.glob("*.py")):
        source_hash.update(path.name.encode("utf-8") + b"\0" + path.read_bytes())
    metadata = {
        "report_schema": 1,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "dataset_version": cases[0]["dataset_version"],
        "usage": "development",
        "independent_review": "none",
        "native_language_review": "none",
        "sources": sorted({case["source"] for case in cases}),
        "corpus_sha256": hashlib.sha256(raw).hexdigest(),
        "source_sha256": source_hash.hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "lockfile_sha256": hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest(),
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "unicode_database": unicodedata.unidata_version,
        "guardtrellis": version("guardtrellis"),
        "jsonschema": version("jsonschema"),
        "executions_per_case": 1,
        "policy": "Fixed named synchronous profiles in run.py; local synthetic callbacks and "
        "dispatch recorders only. No decoded JSON-value scanning, network calls "
        "or performance claims.",
    }
    expanded_profiles = {"run_pii_warn", "run_pii_block", "tool_query_pii", "decoded_query_pii"}
    expanded = any(case["profile"] in expanded_profiles for case in cases)
    if expanded:
        metadata.update(
            report_schema=2,
            recipe_sha256=hashlib.sha256(RECIPE_PATH.read_bytes()).hexdigest(),
            policy="Fixed named synchronous profiles in run.py; local synthetic callbacks "
            "and dispatch recorders only. Raw query ToolGuard and configured decoded-query "
            "recipe use SecretScanner then PII email/phone; the shipped recipe default "
            "covers secrets/email. Decoded finding offsets are separate from serialized "
            "handoff offsets. No network calls or general accuracy claims.",
        )
    if iterations > 1:
        metadata.update(
            report_schema=2,
            executions_per_case=iterations + 3,
            warmups_per_case=3,
            timed_iterations_per_case=iterations,
            iteration_limit=1000,
            timing_scope="Setup-inclusive synchronous observations: policy construction, "
            "SDK/recipe checks, local callbacks, exact comparisons and privacy checks. "
            "Microseconds from perf_counter_ns; short synthetic inputs on this host, "
            "not scanner-only timing, capacity evidence or a deadline guarantee.",
        )
    report = {
        "metadata": metadata,
        "overall": summarize(rows),
        "families": {
            family: summarize([row for row in rows if row["family"] == family])
            for family in FAMILIES
            if any(row["family"] == family for row in rows)
        },
        "cases": rows,
    }
    if expanded or iterations > 1:
        for field in ("profile", "format", "coverage_scope"):
            report[field + "s"] = {
                value: summarize([row for row in rows if row.get(field) == value])
                for value in sorted({row[field] for row in rows if field in row})
            }
    return report


def markdown(report):
    meta, total = report["metadata"], report["overall"]
    lines = [
        f"# Policy and delivery evaluation: {meta['dataset_version']}",
        "",
        "Authored, AI-assisted synthetic development cases; "
        "no independent or native-language review.",
        "These selected cases do not establish general accuracy, "
        "authorization or production safety.",
        "Only metadata and equality checks are reported; "
        "fixture and delivered payloads are omitted.",
        "",
        f"Generated: {meta['generated_at_utc']}",
        f"GuardTrellis {meta['guardtrellis']}; Python {meta['python']}; "
        f"{meta['platform']} {meta['machine']}; jsonschema {meta['jsonschema']}.",
        *[
            f"{key}: `{meta[key]}`."
            for key in ("corpus_sha256", "source_sha256", "runner_sha256", "lockfile_sha256")
        ],
        "Policy: " + meta["policy"],
        "",
        "| Family | N (+/−) | TP | FP | TN | FN | Errors (expected/unexpected) | Mismatches |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for family, data in [*report["families"].items(), ("overall", total)]:
        lines.append(
            f"| {family} | {data['cases']} ({data['positive_cases']}/{data['negative_cases']}) "
            f"| {data['tp']} | {data['fp']} | {data['tn']} | {data['fn']} "
            f"| {data['expected_errors']}/{data['unexpected_errors']} "
            f"| {data['mismatched_cases']} |"
        )
    if "recipe_sha256" in meta:
        lines += [
            "",
            f"recipe_sha256: `{meta['recipe_sha256']}`.",
            "Decoded recipe signals use the captured decoded query policy result;",
            "the final serialized handoff can be ALLOW after decoded redaction.",
            "Decoded offsets are half-open Python character indices in the query string",
            "and are never merged into serialized ToolResult finding coordinates.",
        ]
    if "timing_scope" in meta:
        lines += [
            "",
            "## Local observation timing",
            "",
            f"{meta['warmups_per_case']} warmups and {meta['timed_iterations_per_case']} "
            f"timed iterations per case; maximum {meta['iteration_limit']} timed iterations.",
            meta["timing_scope"],
            "",
            "| Profile | Timed observations | p50 µs | p95 µs |",
            "| --- | --- | --- | --- |",
        ]
        for profile, group in report["profiles"].items():
            if "timed_observations" in group:
                lines.append(
                    f"| {profile} | {group['timed_observations']} | "
                    f"{group['latency_p50_us']:.2f} | {group['latency_p95_us']:.2f} |"
                )
    if "profiles" in report:
        lines += [
            "",
            "## Coverage by profile",
            "",
            "| Profile | Cases | TP | FP | TN | FN | Mismatches |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for profile, group in report["profiles"].items():
            lines.append(
                f"| {profile} | {group['cases']} | {group['tp']} | {group['fp']} | "
                f"{group['tn']} | {group['fn']} | {group['mismatched_cases']} |"
            )
    lines += [
        "",
        "## Actions and delivery",
        "",
        "WARN permits delivery; REDACT permits checked content; BLOCK/ERROR withhold content.",
        "Callbacks may have run before an OUTPUT rejection; an INPUT rejection prevents them.",
        "",
        "| Family | ALLOW | WARN | REDACT | BLOCK | ERROR | Callbacks | Dispatches |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for family, data in report["families"].items():
        lines.append(
            f"| {family} | "
            + " | ".join(str(data["actions"][a.value]) for a in Action)
            + f" | {data['callbacks']} | {data['dispatches']} |"
        )
    lines += [
        "",
        "## Retained outcomes and expectation mismatches",
        "",
        "Signals and action/delivery expectations are separate. ERROR is not a detection.",
        "FP/FN describe authored scenario intent, including benign lookalikes and unsupported",
        "formats. They are not automatically SDK contract defects. Exact comparison fields",
        "include checked text, callback inputs, delivered results, dispatches and selected",
        "revision-aware finding spans/traces. See JSON results for every comparison.",
        "",
    ]
    for row in report["cases"]:
        if (
            row["outcome"] in ("fp", "fn", "error")
            or row["mismatches"]
            or row["privacy_failures"]
            or row.get("harness_error")
        ):
            lines.append(
                f"- `{row['id']}`: **{row['outcome']}**; action `{row['observed_action']}`; "
                f"mismatches: {', '.join(row['mismatches']) or 'none'}; "
                f"privacy failures: {', '.join(row['privacy_failures']) or 'none'}. "
                f"{row['label_basis']}"
            )
    lines += [
        "",
        f"Privacy failures: {total['privacy_failures']}; "
        f"harness failures: {total['harness_errors']}.",
        "Failed diagnostic privacy checks suppress that diagnostic surface in the report.",
        "Exit 0 means the harness completed without privacy failures or unexpected errors;",
        "it does not mean all scenario expectations passed. Known FP/FN and mismatches remain.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=1)
    args = parser.parse_args(argv)
    if not 1 <= args.iterations <= 1000:
        parser.error("iterations must be between 1 and 1000")
    if args.report_dir.exists():
        parser.error("report directory already exists; choose a new directory to retain prior runs")
    try:
        with args.corpus.open("rb") as source:
            raw = source.read(1_000_001)
        cases = load_cases(raw)
    except (OSError, UnicodeError, ValueError) as error:
        # Do not echo parser exception context or file contents.
        parser.error(
            "Cannot read a valid UTF-8 evaluation corpus"
            if isinstance(error, OSError | UnicodeError)
            else str(error)
        )
    report = build_report(cases, raw, evaluate_cases(cases, args.iterations), args.iterations)
    args.report_dir.mkdir(parents=True, exist_ok=False)
    (args.report_dir / "REPORT.md").write_text(markdown(report), encoding="utf-8")
    (args.report_dir / "results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    total = report["overall"]
    print(
        f"Evaluated {total['cases']} cases: {total['fp']} FP, {total['fn']} FN, "
        f"{total['mismatched_cases']} expectation mismatches, {total['unexpected_errors']} "
        f"unexpected errors, {total['privacy_failures']} privacy failures"
    )
    print("Exit 0 does not imply all scenario expectations passed; inspect both reports.")
    return int(
        bool(total["unexpected_errors"] or total["privacy_failures"] or total["harness_errors"])
    )


if __name__ == "__main__":
    sys.exit(main())
