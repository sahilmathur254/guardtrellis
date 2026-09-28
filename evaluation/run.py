"""Reproducible synthetic smoke evaluation; never a production security benchmark."""

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
    SecretScanner,
    ToolGuard,
)

HERE = Path(__file__).resolve().parent
FAMILIES = ("pii", "secrets", "invisible", "literal", "json", "tool")
LEGACY_CORPUS_SHA256 = "f75b7c1898734cd1742eba3acf885a543e0270254d2b0ba5b903f8a01861910f"
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}, "count": {"type": "integer", "minimum": 0}},
    "required": ["answer"],
    "additionalProperties": False,
}
TOOL_SCHEMA = {
    "type": "object",
    "properties": {"city": {"type": "string", "minLength": 1, "maxLength": 100}},
    "required": ["city"],
    "additionalProperties": False,
}


def rate(numerator, denominator):
    return numerator / denominator if denominator else None


def summarize(rows):
    counts = Counter(row["outcome"] for row in rows)
    actions = Counter(row["observed_action"] for row in rows)
    latencies = sorted(value for row in rows for value in row["latency_us"])
    return {
        "cases": len(rows),
        "positive_cases": sum(row["expected_signal"] for row in rows),
        "negative_cases": sum(not row["expected_signal"] for row in rows),
        **{key: counts[key] for key in ("tp", "fp", "tn", "fn", "error")},
        "actions": {action.value: actions[action.value] for action in Action},
        "precision": rate(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": rate(counts["tp"], counts["tp"] + counts["fn"]),
        "false_positive_rate": rate(counts["fp"], counts["fp"] + counts["tn"]),
        "latency_p50_us": statistics.median(latencies),
        "latency_p95_us": latencies[math.ceil(len(latencies) * 0.95) - 1],
    }


def percent(value):
    return "n/a" if value is None else f"{100 * value:.1f}%"


def load_cases(corpus_bytes):
    """Require labelled, versioned provenance for additions; preserve the exact legacy corpus."""

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate metadata key")
            result[key] = value
        return result

    legacy = hashlib.sha256(corpus_bytes).hexdigest() == LEGACY_CORPUS_SHA256
    cases = []
    ids = set()
    for number, line in enumerate(corpus_bytes.decode("utf-8").splitlines(), 1):
        try:
            case = json.loads(line, object_pairs_hook=unique_object)
        except ValueError as error:
            raise ValueError(f"Invalid JSON in corpus row {number}") from error
        if not isinstance(case, dict) or any(
            not isinstance(case.get(field), str) or not case[field]
            for field in ("id", "family", "language", "note")
        ):
            raise ValueError(f"Missing or invalid text fields in corpus row {number}")
        if (
            not re.fullmatch(r"[a-z0-9-]+", case["id"])
            or case["id"] in ids
            or case["family"] not in FAMILIES
            or type(case.get("expected_signal")) is not bool
            or not isinstance(case.get("text"), str)
            or not re.fullmatch(r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", case["language"])
            or (case["family"] == "tool" and not isinstance(case.get("tool"), str))
        ):
            raise ValueError(
                f"Invalid label, family, language, or duplicate ID in corpus row {number}"
            )
        if legacy:
            case.update(
                dataset_version="smoke-v1",
                source="Original GuardTrellis authored synthetic corpus; evaluation/README.md",
                usage="development",
                format="legacy",
                label_basis="Original labels retained without modification",
            )
        elif (
            any(
                not isinstance(case.get(field), str) or not case[field]
                for field in ("dataset_version", "source", "usage", "format", "label_basis")
            )
            or case["usage"] not in ("development", "held_out")
            or not re.fullmatch(r"[a-z0-9-]+", case["dataset_version"])
        ):
            raise ValueError(
                f"Missing version, provenance, usage, or label basis in corpus row {number}"
            )
        if "pair_id" in case and not re.fullmatch(r"[a-z0-9-]+", str(case["pair_id"])):
            raise ValueError(f"Invalid pair ID in corpus row {number}")
        cases.append(case)
        ids.add(case["id"])
    if not cases or len(cases) > 1000:
        raise ValueError("Supply between 1 and 1000 cases")
    if len({case["dataset_version"] for case in cases}) != 1:
        raise ValueError("Evaluate one dataset version at a time")
    return cases


def evaluate_cases(cases, scan, iterations):
    rows = []
    for case in cases:
        for _ in range(3):
            scan(case)
        samples = []
        for _ in range(iterations):
            before = perf_counter_ns()
            result = scan(case)
            samples.append((perf_counter_ns() - before) / 1_000)
        signal = bool(result.findings)
        if result.action == Action.ERROR:
            outcome = "error"
        elif case["expected_signal"]:
            outcome = "tp" if signal else "fn"
        else:
            outcome = "fp" if signal else "tn"
        rows.append(
            {
                **{
                    key: case[key]
                    for key in (
                        "id",
                        "family",
                        "language",
                        "expected_signal",
                        "note",
                        "dataset_version",
                        "source",
                        "usage",
                        "format",
                        "label_basis",
                        "pair_id",
                    )
                    if key in case
                },
                "observed_action": result.action.value,
                "accepted": result.accepted,
                "finding_codes": sorted({finding.code for finding in result.findings}),
                "outcome": outcome,
                "latency_us": samples,
            }
        )
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--corpus", type=Path, default=HERE / "corpus.jsonl")
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.iterations <= 1000:
        parser.error("iterations must be between 1 and 1000")
    if args.report_dir.exists():
        parser.error("report directory already exists; choose a new directory to retain prior runs")
    corpus_bytes = args.corpus.read_bytes()
    try:
        cases = load_cases(corpus_bytes)
    except UnicodeError:
        parser.error("Corpus must be UTF-8 text")
    except ValueError as error:
        parser.error(str(error))
    guards = {
        "pii": Guard(input_scanners=[PIIScanner()]),
        "secrets": Guard(input_scanners=[SecretScanner()]),
        "invisible": Guard(input_scanners=[InvisibleScanner()]),
        "literal": Guard(
            input_scanners=[LiteralScanner(["drop table", "internal-only"], case_sensitive=False)]
        ),
        "json": Guard(input_scanners=[JSONScanner(OUTPUT_SCHEMA)]),
    }
    tools = ToolGuard({"lookup": TOOL_SCHEMA})

    def scan(case):
        if case["family"] == "tool":
            return tools.validate(case["tool"], case["text"]).validation
        return guards[case["family"]].scan(case["text"])

    rows = evaluate_cases(cases, scan, args.iterations)
    families = {
        family: summarize([row for row in rows if row["family"] == family])
        for family in FAMILIES
        if any(row["family"] == family for row in rows)
    }
    family_languages = {
        family: {
            language: summarize(
                [row for row in rows if row["family"] == family and row["language"] == language]
            )
            for language in sorted({row["language"] for row in rows if row["family"] == family})
        }
        for family in families
    }
    total = summarize(rows)
    package_dir = Path(guardtrellis.__file__).parent
    source_hash = hashlib.sha256()
    for path in sorted(package_dir.glob("*.py")):
        source_hash.update(path.name.encode("utf-8") + b"\0" + path.read_bytes())
    metadata = {
        "report_schema": 2,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "dataset_version": cases[0]["dataset_version"],
        "usage": sorted({case["usage"] for case in cases}),
        "sources": sorted({case["source"] for case in cases}),
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "source_sha256": source_hash.hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": platform.python_version(),
        "unicode_database": unicodedata.unidata_version,
        "platform": platform.system(),
        "machine": platform.machine(),
        "guardtrellis": version("guardtrellis"),
        "jsonschema": version("jsonschema"),
        "iterations_per_case": args.iterations,
        "warmups_per_case": 3,
        "timing": "synchronous wall-clock, per complete scan, microseconds",
        "languages": sorted({case["language"] for case in cases}),
        "lockfile_sha256": hashlib.sha256((HERE.parent / "uv.lock").read_bytes()).hexdigest(),
        "policy": "Fixed per-family INPUT policies from this runner: PII REDACT, secrets BLOCK, "
        "invisible WARN, literal BLOCK, JSON/tool structural validation. No JSON-value decoding, "
        "normalization, provider calls, or pipeline interaction checks.",
    }
    lines = [
        f"# Synthetic evaluation: {metadata['dataset_version']}",
        "",
        "These are authored synthetic fixtures, not an independent or adversarial benchmark.",
        "Results measure this corpus only. They do not establish production safety "
        "or language coverage.",
        f"Fixture usage: {', '.join(metadata['usage'])}. "
        "See individual provenance and label bases.",
        "",
        f"Generated: {metadata['generated_at_utc']}",
        f"Python {metadata['python']}, {metadata['platform']} {metadata['machine']}; "
        f"GuardTrellis {metadata['guardtrellis']}, jsonschema {metadata['jsonschema']}.",
        f"Corpus SHA-256: `{metadata['corpus_sha256']}`.",
        f"Package source SHA-256: `{metadata['source_sha256']}`.",
        f"Runner SHA-256: `{metadata['runner_sha256']}`.",
        f"Lockfile SHA-256: `{metadata['lockfile_sha256']}`.",
        f"Unicode database: {metadata['unicode_database']}.",
        "Policy: " + metadata["policy"],
        f"{len(cases)} cases, {args.iterations} timed scans per case, 3 warmups per case.",
        "",
        "| Family | N (+/−) | TP | FP | TN | FN | Errors | Precision | Recall | FPR "
        "| p50 µs | p95 µs |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for family, data in [*families.items(), ("overall", total)]:
        lines.append(
            f"| {family} | {data['cases']} ({data['positive_cases']}/{data['negative_cases']}) "
            f"| {data['tp']} | {data['fp']} | {data['tn']} | {data['fn']} | {data['error']} "
            f"| {percent(data['precision'])} | {percent(data['recall'])} "
            f"| {percent(data['false_positive_rate'])} | {data['latency_p50_us']:.1f} "
            f"| {data['latency_p95_us']:.1f} |"
        )
    lines.extend(
        [
            "",
            "## Per-family and language results",
            "",
            "Small, deliberately selected samples; no population or language accuracy estimate.",
            "`zxx` denotes content with no linguistic language (such as emoji).",
            "",
            "| Family | Language | N (+/−) | TP | FP | TN | FN | Errors "
            "| Precision | Recall | FPR |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for family, languages in family_languages.items():
        for language, data in languages.items():
            lines.append(
                f"| {family} | {language} | {data['cases']} "
                f"({data['positive_cases']}/{data['negative_cases']}) "
                f"| {data['tp']} | {data['fp']} "
                f"| {data['tn']} | {data['fn']} | {data['error']} | {percent(data['precision'])} "
                f"| {percent(data['recall'])} | {percent(data['false_positive_rate'])} |"
            )
    lines.extend(
        [
            "",
            "## Actions, separate from detection",
            "",
            "WARN permits delivery; REDACT permits transformed content; BLOCK and ERROR reject.",
            "A detected signal does not establish complete redaction or safe structured output.",
            "",
            "| Family | ALLOW | WARN | REDACT | BLOCK | ERROR |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for family, data in families.items():
        lines.append(
            f"| {family} | " + " | ".join(str(data["actions"][a.value]) for a in Action) + " |"
        )
    lines.extend(
        [
            "",
            "## Retained failures and false-positive challenges",
            "",
            "Warnings count as detected signals, even though they permit delivery.",
            "ERROR results are reported separately and excluded from metric denominators.",
            "Expected signals reflect the authored scenario, including deliberately unsupported",
            "formats and benign lookalikes. "
            "An FP/FN is not automatically a runtime contract defect.",
            "",
        ]
    )
    for row in rows:
        if row["outcome"] in ("fn", "fp", "error"):
            lines.append(
                f"- `{row['id']}`: **{row['outcome']}**, {row['note']} "
                f"(observed `{row['observed_action']}`)."
            )
    paired = [row for row in rows if row.get("pair_id")]
    if paired:
        lines.extend(
            [
                "",
                "## Paired representations",
                "",
                "Related cases express the same decoded value; "
                "scanners still receive the literal input.",
                "",
                "| Pair | Case | Format | Signal expected | Outcome | Action |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for row in paired:
            lines.append(
                f"| {row['pair_id']} | {row['id']} | {row['format']} | {row['expected_signal']} "
                f"| {row['outcome']} | {row['observed_action']} |"
            )
    lines.extend(
        [
            "",
            "All observed misses, false positives, and errors are retained above.",
            "Compare corpus, source, and runner digests before attributing changes to detectors.",
            "Language tags: " + ", ".join(metadata["languages"]) + ".",
            "There are very few cases per language. The overall score mixes different tasks and",
            "is not a general accuracy estimate. Latency covers warm, short, synchronous",
            "local scans; it excludes imports, provider calls, async scheduling, construction,",
            "network time, and worst-case inputs. Reruns will vary.",
            "",
        ]
    )
    args.report_dir.mkdir(parents=True, exist_ok=False)
    (args.report_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    (args.report_dir / "results.json").write_text(
        json.dumps(
            {
                "metadata": metadata,
                "overall": total,
                "families": families,
                "family_languages": family_languages,
                "cases": rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"Evaluated {len(cases)} cases: {total['tp']} TP, {total['fp']} FP, "
        f"{total['tn']} TN, {total['fn']} FN, {total['error']} errors"
    )
    print(f"Report: {args.report_dir / 'REPORT.md'}")
    return 1 if total["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
