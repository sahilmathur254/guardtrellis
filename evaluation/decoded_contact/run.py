"""Compare three fixed contact workflows on authored development fixtures, offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from guardtrellis import Action, Guard, PIIScanner, Rejected, SecretScanner, ToolGuard

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = HERE / "contact_workflow_v1.jsonl"
PROFILES = ("raw_serialized", "per_field_query_recipe", "contact_helper")
FIELDS = ("email", "phone")
SCHEMA = {
    "type": "object",
    "properties": {
        "email": {"type": "string", "minLength": 1, "maxLength": 254},
        "phone": {"type": "string", "minLength": 1, "maxLength": 64},
    },
    "required": list(FIELDS),
    "additionalProperties": False,
}


def recipe(name):
    path = ROOT / "examples" / f"{name}.py"
    spec = spec_from_file_location(f"evaluation_{name}", path)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


decoded_query = recipe("decoded_query")
decoded_contact = recipe("decoded_contact")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate corpus key")
        result[key] = value
    return result


def load_cases(raw):
    """Reject ambiguous labels and unknown metadata before executing any fixture."""
    if len(raw) > 1_000_000:
        raise ValueError("Corpus exceeds one megabyte")
    required = {
        "id",
        "pair_id",
        "dataset_version",
        "source",
        "usage",
        "representation",
        "label_basis",
        "known_limit",
        "tool",
        "arguments_json",
        "expected",
    }
    cases, ids = [], set()
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        try:
            case = json.loads(line, object_pairs_hook=unique_object)
            if not isinstance(case, dict) or case.keys() != required:
                raise ValueError
            if any(
                not isinstance(case[key], str) or not 1 <= len(case[key]) <= 500
                for key in ("id", "pair_id", "dataset_version", "source", "label_basis", "tool")
            ):
                raise ValueError
            if (
                not all(
                    re.fullmatch(r"[a-z0-9-]+", case[key])
                    for key in ("id", "pair_id", "dataset_version")
                )
                or case["id"] in ids
                or case["dataset_version"] != "contact-workflow-v1"
                or case["usage"] != "development"
                or case["representation"] not in ("plain", "escaped", "invalid")
                or type(case["known_limit"]) is not bool
                or not isinstance(case["arguments_json"], str)
                or not 1 <= len(case["arguments_json"]) <= 10_000
            ):
                raise ValueError
            expected = case["expected"]
            if (
                not isinstance(expected, dict)
                or expected.keys() != {"accepted", "arguments", "action"}
                or type(expected["accepted"]) is not bool
                or expected["action"] not in (None, "allow", "redact")
                or expected["accepted"] != (expected["arguments"] is not None)
                or expected["accepted"] != (expected["action"] is not None)
                or expected["accepted"]
                and (
                    not isinstance(expected["arguments"], dict)
                    or expected["arguments"].keys() != set(FIELDS)
                    or any(
                        not isinstance(expected["arguments"][field], str)
                        or not 1 <= len(expected["arguments"][field]) <= limit
                        for field, limit in (("email", 254), ("phone", 64))
                    )
                )
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError, RecursionError) as error:
            raise ValueError(f"Invalid corpus row {number}") from error
        ids.add(case["id"])
        cases.append(case)
    if not 1 <= len(cases) <= 100:
        raise ValueError("Corpus must contain one to one hundred cases")
    pairs = {}
    for case in cases:
        if case["representation"] == "invalid":
            continue
        pair = pairs.setdefault(case["pair_id"], {})
        if case["representation"] in pair:
            raise ValueError("Duplicate pair representation")
        pair[case["representation"]] = case
    for pair in pairs.values():
        if set(pair) != {"plain", "escaped"}:
            raise ValueError("Every valid meaning requires a plain and escaped pair")
        plain, escaped = pair["plain"], pair["escaped"]
        if (
            json.loads(plain["arguments_json"], object_pairs_hook=unique_object)
            != json.loads(escaped["arguments_json"], object_pairs_hook=unique_object)
            or plain["expected"] != escaped["expected"]
            or plain["known_limit"] != escaped["known_limit"]
            or plain["tool"] != escaped["tool"]
        ):
            raise ValueError("Pair meanings or expectations differ")
    return cases


def load_corpus(path):
    with path.open("rb") as source:
        return load_cases(source.read(1_000_001))


def markers(case):
    """Cover exact wire input and decoded field values without printing either."""
    values = [case["arguments_json"]]
    try:
        parsed = json.loads(case["arguments_json"])
        if isinstance(parsed, dict):
            values.extend(value for value in parsed.values() if isinstance(value, str))
    except (ValueError, RecursionError):
        pass
    # Preserve actual wire spellings too: escaped fragments need not equal json.dumps(value).
    for token in re.findall(r'"(?:\\.|[^"\\])*"', case["arguments_json"]):
        values.extend((token, token[1:-1]))
    return [value for value in values if 8 <= len(value) <= 10_000]


def contains_marker(surface, private):
    return any(
        spelling in surface
        for value in private
        for spelling in (value, repr(value), json.dumps(value), json.dumps(value)[1:-1])
    )


class Observation:
    """Internal values are equality inputs only and are never serialized to reports."""

    def __init__(self, case):
        self.private = markers(case)
        self.actions = []
        self.finding_count = 0
        self.privacy_failures = []
        self.delivered = None
        self.rejected = False
        self.unexpected_error = False
        self.final_action = None

    def inspect(self, result, *, decoded=False, final=False):
        if contains_marker(repr(result), self.private):
            self.privacy_failures.append("repr")
        diagnostics = result.diagnostics()
        if contains_marker(json.dumps(diagnostics), self.private):
            self.privacy_failures.append("diagnostics")
        if decoded or final:
            self.actions.append(result.action.value)
        if final:
            self.final_action = result.action.value
        self.finding_count += len(result.findings) if decoded else 0


class RecordingGuard(Guard):
    def __init__(self, observation):
        super().__init__(
            tool_scanners=[SecretScanner(), PIIScanner(formats=["email", "phone"])],
            max_chars=decoded_query.MAX_QUERY_CHARS,
        )
        self.observation = observation

    def scan(self, text, *, stage):
        result = super().scan(text, stage=stage)
        self.observation.inspect(result, decoded=True)
        return result


def observe(case, profile):
    observation = Observation(case)
    try:
        if profile == "raw_serialized":
            validator = ToolGuard(
                {"contact": SCHEMA},
                argument_scanners=[SecretScanner(), PIIScanner(formats=["email", "phone"])],
                max_chars=4096,
                max_depth=2,
            )
            result = validator.validate(case["tool"], case["arguments_json"])
            observation.inspect(result, final=True)
            observation.finding_count = len(result.validation.findings)
            observation.delivered = result.require_call()
        elif profile == "per_field_query_recipe":
            # Equal contact preflight; each existing recipe invocation still owns one query.
            validator = ToolGuard({"contact": SCHEMA}, max_chars=4096, max_depth=2)
            preflight = validator.validate(case["tool"], case["arguments_json"])
            observation.inspect(preflight)
            name, arguments = preflight.require_call()
            checked = {}
            for field in FIELDS:
                result = decoded_query.check_query(
                    "search",
                    json.dumps({"query": arguments[field]}, ensure_ascii=False),
                    query_guard=RecordingGuard(observation),
                )
                observation.inspect(result)
                checked[field] = result.require_call()[1]["query"]
            result = validator.validate(name, json.dumps(checked, ensure_ascii=False))
            observation.inspect(result, final=True)
            observation.delivered = result.require_call()
        elif profile == "contact_helper":
            result = decoded_contact.check_contact(case["tool"], case["arguments_json"])
            observation.inspect(result, decoded=True)
            observation.inspect(result.final, final=True)
            observation.delivered = result.require_call()
        else:
            raise ValueError("Unknown fixed profile")
    except Rejected as error:
        observation.rejected = True
        if contains_marker(str(error), observation.private) or contains_marker(
            repr(error), observation.private
        ):
            observation.privacy_failures.append("rejection")
    except Exception:
        # Never copy exception text, arguments or traceback into evidence.
        observation.unexpected_error = True
    return observation


def evaluate(cases):
    rows, deliveries = [], {}
    for case in cases:
        for profile in PROFILES:
            observed = observe(case, profile)
            accepted = observed.delivered is not None
            priority = [action.value for action in Action]
            action = max(observed.actions, key=priority.index) if observed.actions else None
            expected = case["expected"]
            mismatches = []
            if accepted != expected["accepted"]:
                mismatches.append("accepted")
            desired = (case["tool"], expected["arguments"]) if expected["accepted"] else None
            if observed.delivered != desired:
                mismatches.append("checked_delivery")
            # Rejected helper calls do not expose an action; never fabricate BLOCK findings.
            if expected["accepted"] and action != expected["action"]:
                mismatches.append("protection_action")
            rows.append(
                {
                    "id": case["id"],
                    "pair_id": case["pair_id"],
                    "profile": profile,
                    "representation": case["representation"],
                    "known_limit": case["known_limit"],
                    "accepted": accepted,
                    "rejected": observed.rejected,
                    "protection_action": action,
                    "final_validation_action": observed.final_action,
                    "finding_count": observed.finding_count,
                    "checked_call_count": int(accepted),
                    "mismatches": mismatches,
                    "privacy_failures": sorted(set(observed.privacy_failures)),
                    "unexpected_error": observed.unexpected_error,
                }
            )
            deliveries[(case["pair_id"], case["representation"], profile)] = observed.delivered
    for row in rows:
        if row["representation"] == "invalid":
            row["paired_delivery_equal"] = None
        else:
            key = (row["pair_id"], "plain", row["profile"])
            other = (row["pair_id"], "escaped", row["profile"])
            row["paired_delivery_equal"] = deliveries[key] == deliveries[other]
    return rows


def source_metadata(corpus):
    paths = [
        Path(__file__),
        corpus,
        ROOT / "examples/decoded_query.py",
        ROOT / "examples/decoded_contact.py",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
    ]
    paths.extend(sorted((ROOT / "src/guardtrellis").rglob("*.py")))
    return {
        "sdk_version": version("guardtrellis"),
        "dependencies": {name: version(name) for name in ("jsonschema", "referencing")},
        "python": platform.python_version(),
        "platform": platform.platform(),
        "created_utc": datetime.now(UTC).isoformat(),
        "dataset_version": "contact-workflow-v1",
        "usage": "authored-development-only",
        "sha256": {
            str(path.relative_to(ROOT))
            if path.is_relative_to(ROOT)
            else "external_corpus": hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths
        },
    }


def write_report(report_dir, metadata, rows):
    report_dir.mkdir(parents=True, exist_ok=False)
    summary = {}
    for profile in PROFILES:
        selected = [row for row in rows if row["profile"] == profile]
        summary[profile] = {
            "observations": len(selected),
            "exact_outcome_matches": sum(not row["mismatches"] for row in selected),
            "mismatched_cases": sum(bool(row["mismatches"]) for row in selected),
            "known_limit_mismatches": sum(
                row["known_limit"] and bool(row["mismatches"]) for row in selected
            ),
            "unexpected_errors": sum(row["unexpected_error"] for row in selected),
            "privacy_failures": sum(bool(row["privacy_failures"]) for row in selected),
        }
    report = {"metadata": metadata, "summary": summary, "rows": rows}
    (report_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Decoded contact workflow comparison",
        "",
        "Authored synthetic development fixtures; not production accuracy or held-out evidence.",
        "Known formatted-phone misses remain failed desired outcomes. Zero exit means no detected",
        "harness/privacy error, not complete protection. No payloads or timing are reported.",
        "",
        "| Profile | Observations | Exact matches | Mismatches | Known-limit mismatches |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for profile, counts in summary.items():
        lines.append(
            f"| {profile} | {counts['observations']} | {counts['exact_outcome_matches']} "
            f"| {counts['mismatched_cases']} | {counts['known_limit_mismatches']} |"
        )
    lines.extend(
        [
            "",
            "Source hashes, runtime, safe metadata and per-case equality outcomes are in",
            "[results.json](results.json). See the runner README for policy differences.",
            "",
        ]
    )
    (report_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--report-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.report_dir.exists():
        parser.error("Report directory already exists; choose a fresh directory")
    try:
        cases = load_corpus(arguments.corpus)
        rows = evaluate(cases)
        report = write_report(arguments.report_dir, source_metadata(arguments.corpus), rows)
    except (OSError, ValueError, UnicodeError):
        parser.error("Evaluation input or report creation failed")
    print(json.dumps(report["summary"], sort_keys=True))
    return int(any(row["unexpected_error"] or row["privacy_failures"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
