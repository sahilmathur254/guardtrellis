"""Compare the authored #68 contract supplement with unchanged SDK policies."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "contract_supplement_v1.jsonl"
VERSION = "connection-strings-contract-v1"
EXTRA_FIELDS = {"case_group", "origin_case_id", "contract_status"}
STATUSES = ("selected", "excluded", "resource_pending")
SPEC = spec_from_file_location("connection_strings_v1", HERE / "run.py")
assert SPEC is not None and SPEC.loader is not None
base = module_from_spec(SPEC)
SPEC.loader.exec_module(base)


def load_cases(raw):
    """Validate extra provenance, then reuse the frozen v1 shape and interval checks."""
    if len(raw) > base.MAX_CORPUS_BYTES:
        raise ValueError("Corpus exceeds byte limit")
    origins = {case["id"]: case for case in base.load_corpus() if case["label"] == "ambiguous"}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise ValueError("Corpus must be UTF-8") from None
    cases, projected, used_origins = [], [], set()
    for number, line in enumerate(lines, 1):
        try:
            case = json.loads(
                line, object_pairs_hook=base.unique_object, parse_constant=base.reject_constant
            )
            if not isinstance(case, dict) or not EXTRA_FIELDS <= case.keys():
                raise ValueError
            if (
                case["dataset_version"] != VERSION
                or not isinstance(case["case_group"], str)
                or not re.fullmatch(r"[a-z0-9-]{1,100}", case["case_group"])
                or case["contract_status"] not in STATUSES
            ):
                raise ValueError
            origin = case["origin_case_id"]
            if origin is not None:
                if (
                    not isinstance(origin, str)
                    or origin not in origins
                    or origin in used_origins
                    or case["text"] != origins[origin]["text"]
                ):
                    raise ValueError
                used_origins.add(origin)
            selected = case["contract_status"] == "selected"
            if selected != (case["expected_action"] is not None):
                raise ValueError
            # The original loader validates the common schema without relabelling its corpus.
            common = {key: value for key, value in case.items() if key not in EXTRA_FIELDS}
            common["dataset_version"] = "connection-strings-v1"
            projected.append(common)
            cases.append(case)
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ValueError(f"Invalid supplement row {number}") from None
    base.load_cases("".join(json.dumps(case) + "\n" for case in projected).encode("utf-8"))
    return cases


def load_corpus(path=CORPUS):
    with Path(path).open("rb") as stream:
        return load_cases(stream.read(base.MAX_CORPUS_BYTES + 1))


def evaluate(cases):
    """Observe only the existing policies; this does not simulate an opt-in scanner."""
    by_id = {case["id"]: case for case in cases}
    rows = base.evaluate(cases)
    for row in rows:
        case = by_id[row["id"]]
        extra = {key: case[key] for key in sorted(EXTRA_FIELDS)}
        row.update(extra)
        if base.contains_marker(
            json.dumps(row),
            [marker for marker in [case["text"], *case["privacy_markers"]] if len(marker) >= 8],
        ):
            raise ValueError("Unsafe supplement metadata")
    return rows


def write_report(report_dir, rows, corpus_path=CORPUS):
    metadata = base.source_metadata(Path(corpus_path).resolve())
    metadata.update(evaluation_version=VERSION, opt_in_status="not_implemented")
    for path in (Path(__file__), base.CORPUS, HERE / "PROPOSAL.md"):
        metadata["source_sha256"][path.relative_to(base.ROOT).as_posix()] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    report = {"metadata": metadata, "summary": base.summarize(rows)}
    report["by_policy_representation"] = {
        f"{policy}/{representation}": base.summarize(
            [
                row
                for row in rows
                if row["policy"] == policy and row["representation"] == representation
            ]
        )
        for policy in base.POLICIES
        for representation in base.REPRESENTATIONS
    }
    for field in ("family", "label", "contract_status", "case_group"):
        report[f"by_{field}"] = {
            value: base.summarize([row for row in rows if row[field] == value])
            for value in sorted({row[field] for row in rows})
        }
    report["rows"] = rows
    lines = [
        "# Connection-string contract supplement: current SDK observations",
        "",
        f"SDK {metadata['sdk_version']}; {len(rows)} observations; opt-in not implemented.",
        "",
        "Authored synthetic development cases, with desired decisions fixed before outcomes. "
        "This run exercises the frozen v1 harness's unchanged secret-only and tool-return "
        "policies. It does not execute the proposed connection-string detector. "
        "Excluded/resource-pending cases have null comparisons; absence of a finding is not "
        "a safety or driver-validity claim. No resource-limit experiment is performed here.",
        "",
        "| Contract status | Observations | Scored | Exact matches | ALLOW | REDACT | BLOCK "
        "| ERROR |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for status, summary in report["by_contract_status"].items():
        counts = summary["action_counts"]
        lines.append(
            f"| {status} | {summary['observations']} | {summary['scored']} | "
            f"{summary['exact_outcome_matches']} | {counts.get('allow', 0)} | "
            f"{counts.get('redact', 0)} | {counts.get('block', 0)} | {counts.get('error', 0)} |"
        )
    lines.extend(
        [
            "",
            "Whole-URI spans are proposed targets, including when an existing token signature "
            "already blocks a smaller span. Incidental PII redaction and input-limit ERROR "
            "remain distinct from URI detection. Raw JSON is scanned as wire text; explicit "
            "decoded equivalents use decoded-string offsets. No raw input/output, "
            "credentials or exception text are included in the report.",
            "",
            "## Retained mismatches",
            "",
            "| Case | Policy / representation | Mismatched comparisons |",
            "| --- | --- | --- |",
        ]
    )
    for row in rows:
        misses = [key for key, matched in row["comparisons"].items() if matched is False]
        if misses:
            lines.append(
                f"| {row['id']} | {row['policy']}/{row['representation']} | {', '.join(misses)} |"
            )
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=False)
    (report_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (report_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.report_dir.exists():
        parser.error("Report directory already exists")
    try:
        rows = evaluate(load_corpus(args.corpus))
        report = write_report(args.report_dir, rows, args.corpus)
    except (ValueError, OSError):
        parser.error("Invalid corpus or unavailable report path")
    print(json.dumps(report["summary"], sort_keys=True))
    return int(
        any(
            row["unexpected_error"] or row["privacy_failures"] or row["harness_failures"]
            for row in rows
        )
    )


if __name__ == "__main__":
    sys.exit(main())
