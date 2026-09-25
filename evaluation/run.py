"""Reproducible synthetic smoke evaluation; never a production security benchmark."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import sys
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
    latencies = sorted(value for row in rows for value in row["latency_us"])
    return {
        "cases": len(rows),
        "positive_cases": sum(row["expected_signal"] for row in rows),
        "negative_cases": sum(not row["expected_signal"] for row in rows),
        **{key: counts[key] for key in ("tp", "fp", "tn", "fn", "error")},
        "precision": rate(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": rate(counts["tp"], counts["tp"] + counts["fn"]),
        "false_positive_rate": rate(counts["fp"], counts["fp"] + counts["tn"]),
        "latency_p50_us": statistics.median(latencies),
        "latency_p95_us": latencies[math.ceil(len(latencies) * 0.95) - 1],
    }


def percent(value):
    return "n/a" if value is None else f"{100 * value:.1f}%"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--report-dir", type=Path, default=HERE)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("iterations must be positive")
    corpus_bytes = (HERE / "corpus.jsonl").read_bytes()
    cases = [json.loads(line) for line in corpus_bytes.decode("utf-8").splitlines()]
    assert len({case["id"] for case in cases}) == len(cases), "Duplicate case IDs"
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

    rows = []
    for case in cases:
        for _ in range(3):
            scan(case)
        samples = []
        for _ in range(args.iterations):
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
                "id": case["id"],
                "family": case["family"],
                "expected_signal": case["expected_signal"],
                "observed_action": result.action.value,
                "outcome": outcome,
                "note": case["note"],
                "latency_us": samples,
            }
        )

    families = {
        family: summarize([row for row in rows if row["family"] == family])
        for family in ("pii", "secrets", "invisible", "literal", "json", "tool")
    }
    total = summarize(rows)
    package_dir = Path(guardtrellis.__file__).parent
    source_hash = hashlib.sha256()
    for path in sorted(package_dir.glob("*.py")):
        source_hash.update(path.name.encode("utf-8") + b"\0" + path.read_bytes())
    metadata = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "corpus_sha256": hashlib.sha256(corpus_bytes).hexdigest(),
        "source_sha256": source_hash.hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "python": platform.python_version(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "guardtrellis": version("guardtrellis"),
        "jsonschema": version("jsonschema"),
        "iterations_per_case": args.iterations,
        "warmups_per_case": 3,
        "timing": "synchronous wall-clock, per complete scan, microseconds",
        "languages": sorted({case["language"] for case in cases}),
    }
    lines = [
        "# Synthetic smoke evaluation",
        "",
        "These are authored synthetic fixtures, not an independent or adversarial benchmark.",
        "Results measure this corpus only. They do not establish production safety "
        "or language coverage.",
        "",
        f"Generated: {metadata['generated_at_utc']}",
        f"Python {metadata['python']}, {metadata['platform']} {metadata['machine']}; "
        f"GuardTrellis {metadata['guardtrellis']}, jsonschema {metadata['jsonschema']}.",
        f"Corpus SHA-256: `{metadata['corpus_sha256']}`.",
        f"Package source SHA-256: `{metadata['source_sha256']}`.",
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
            "## Retained failures and false-positive challenges",
            "",
            "Warnings count as detected signals, even though they permit delivery.",
            "ERROR results are reported separately and excluded from metric denominators.",
            "See README.md for definitions.",
            "",
        ]
    )
    for row in rows:
        if row["outcome"] in ("fn", "fp", "error"):
            lines.append(
                f"- `{row['id']}`: **{row['outcome']}**, {row['note']} "
                f"(observed `{row['observed_action']}`)."
            )
    lines.extend(
        [
            "",
            "No detector rules were changed to erase these evaluation failures.",
            "The corpus contains English, Hindi, Japanese, Spanish, French, and Persian text,",
            "with very few cases per language. The overall score mixes different tasks and",
            "is not a general accuracy estimate. Latency covers warm, short, synchronous",
            "local scans; it excludes imports, provider calls, async scheduling, construction,",
            "network time, and worst-case inputs. Reruns will vary.",
            "",
        ]
    )
    args.report_dir.mkdir(parents=True, exist_ok=True)
    (args.report_dir / "REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    (args.report_dir / "results.json").write_text(
        json.dumps(
            {
                "metadata": metadata,
                "overall": total,
                "families": families,
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
