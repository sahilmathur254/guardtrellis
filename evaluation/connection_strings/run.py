"""Authored connection-string coverage and actual tool-return delivery, without SDK edits."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import re
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import guardtrellis
from guardtrellis import Action, Guard, Rejected, SecretScanner

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = HERE / "corpus_v1.jsonl"
POLICIES = ("secret_only", "tool_return")
REPRESENTATIONS = ("plain", "json_plain", "json_escaped", "decoded_plain", "decoded_escaped")
MAX_CORPUS_BYTES = 256 * 1024
MAX_TEXT = 2100
MAX_WIRE = 14000
MAX_CASES = 60
SPEC = spec_from_file_location("connection_handoff", ROOT / "examples/tool_result_handoff.py")
assert SPEC is not None and SPEC.loader is not None
handoff = module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)
COMPARISONS = ("action", "delivery", "target_spans", "credential_coverage")
SECRET_CODES = {
    "secret_github_classic",
    "secret_github_fine_grained",
    "secret_aws_access_key_id",
    "secret_private_key",
}
FINDING_CODES = SECRET_CODES | {
    "pii_email",
    "pii_phone",
    "pii_ssn",
    "literal_match",
    "text_limit_exceeded",
    "scanner_error",
    "invalid_check",
    "finding_limit_exceeded",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("Non-finite JSON value")


def valid_string(value, maximum):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and not any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    )


def valid_spans(spans, text):
    return (
        isinstance(spans, list)
        and len(spans) <= 8
        and all(
            isinstance(span, list)
            and len(span) == 2
            and all(type(offset) is int for offset in span)
            and 0 <= span[0] < span[1] <= len(text)
            for span in spans
        )
        and all(left[1] <= right[0] for left, right in zip(spans, spans[1:], strict=False))
    )


def load_cases(raw):
    if len(raw) > MAX_CORPUS_BYTES:
        raise ValueError("Corpus exceeds byte limit")
    required = {
        "id",
        "dataset_version",
        "source",
        "usage",
        "family",
        "label",
        "label_basis",
        "text",
        "expected_action",
        "target_spans",
        "credential_spans",
        "privacy_markers",
        "candidate_count",
    }
    cases, ids = [], set()
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise ValueError("Corpus must be UTF-8") from None
    for number, line in enumerate(lines, 1):
        try:
            case = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
            if not isinstance(case, dict) or case.keys() != required:
                raise ValueError
            if (
                not all(
                    valid_string(case[key], 600)
                    for key in ("id", "dataset_version", "source", "label_basis")
                )
                or not re.fullmatch(r"[a-z0-9-]{1,100}", case["id"])
                or case["id"] in ids
                or case["dataset_version"] != "connection-strings-v1"
                or case["usage"] != "development"
                or case["family"] not in ("postgresql", "mongodb", "benign", "control", "deferred")
                or case["label"] not in ("sensitive", "benign", "ambiguous", "control", "deferred")
                or not valid_string(case["text"], MAX_TEXT)
                or type(case["candidate_count"]) is not int
                or not 0 <= case["candidate_count"] <= 4
                or not all(
                    valid_spans(case[key], case["text"])
                    for key in ("target_spans", "credential_spans")
                )
                or not isinstance(case["privacy_markers"], list)
                or len(case["privacy_markers"]) > 12
                or not all(
                    valid_string(marker, MAX_TEXT) and len(marker) >= 8
                    for marker in case["privacy_markers"]
                )
            ):
                raise ValueError
            expected = (
                None
                if case["label"] == "ambiguous"
                else "allow"
                if case["label"] == "benign"
                else "block"
            )
            if case["expected_action"] != expected:
                raise ValueError
            if expected == "block":
                if (
                    not case["target_spans"]
                    or not case["credential_spans"]
                    or not case["privacy_markers"]
                ):
                    raise ValueError
                if any(
                    not any(a <= start < end <= b for a, b in case["target_spans"])
                    for start, end in case["credential_spans"]
                ):
                    raise ValueError
            elif expected == "allow" and (case["target_spans"] or case["credential_spans"]):
                raise ValueError
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ValueError(f"Invalid corpus row {number}") from None
        cases.append(case)
        ids.add(case["id"])
    if not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Corpus case count out of bounds")
    return cases


def load_corpus(path=CORPUS):
    with Path(path).open("rb") as stream:
        return load_cases(stream.read(MAX_CORPUS_BYTES + 1))


def escaped_character(char):
    # UTF-16 code units retain valid JSON for astral characters.
    encoded = char.encode("utf-16-be")
    return "".join(r"\u" + encoded[i : i + 2].hex() for i in range(0, len(encoded), 2))


def wire_text(text, escaped=False):
    content = (
        "".join(escaped_character(char) for char in text)
        if escaped
        else json.dumps(text, ensure_ascii=True)[1:-1]
    )
    return '{"value":"' + content + '"}'


def decode_value(wire):
    try:
        if not isinstance(wire, str) or len(wire) > MAX_WIRE:
            raise ValueError
        parsed = json.loads(wire, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if (
            not isinstance(parsed, dict)
            or parsed.keys() != {"value"}
            or not valid_string(parsed["value"], MAX_TEXT)
        ):
            raise ValueError
        return parsed["value"]
    except (ValueError, TypeError, RecursionError):
        raise ValueError("Invalid fixed JSON value") from None


def represented(case, representation):
    if representation not in REPRESENTATIONS:
        raise ValueError("Unknown representation")
    text = case["text"]
    if representation == "plain" or representation.startswith("decoded_"):
        scanned = (
            text
            if representation == "plain"
            else decode_value(wire_text(text, representation == "decoded_escaped"))
        )
        return scanned, case["target_spans"], case["credential_spans"]
    escaped = representation == "json_escaped"
    offsets = [len('{"value":"')]
    for char in text:
        width = len(escaped_character(char) if escaped else json.dumps(char)[1:-1])
        offsets.append(offsets[-1] + width)
    return (
        wire_text(text, escaped),
        [[offsets[a], offsets[b]] for a, b in case["target_spans"]],
        [[offsets[a], offsets[b]] for a, b in case["credential_spans"]],
    )


def contains_marker(surface, markers):
    text = str(surface)
    return any(
        spelling in text
        for marker in markers
        for spelling in (
            marker,
            repr(marker),
            json.dumps(marker),
            json.dumps(marker)[1:-1],
            "".join(escaped_character(char) for char in marker),
        )
    )


class RecordingGuard:
    def __init__(self, policy):
        if policy not in POLICIES:
            raise ValueError("Unknown policy")
        self.delegate = (
            Guard(retrieval_scanners=[SecretScanner()], max_chars=handoff.MAX_RETURN_CHARS)
            if policy == "secret_only"
            else handoff.RETURN_POLICY
        )
        self.result = None
        self.calls = 0

    def scan(self, text, *, stage):
        self.calls += 1
        self.result = self.delegate.scan(text, stage=stage)
        return self.result


class SafeLogCapture(logging.Handler):
    def __init__(self, markers):
        super().__init__()
        self.markers = markers
        self.unsafe = False
        self.count = 0

    def emit(self, record):
        self.count += 1
        message = record.getMessage()
        self.unsafe |= len(message) > 16000 or contains_marker(message, self.markers)


def safe_findings(result):
    findings = []
    for item in result.findings:
        if (
            item.code not in FINDING_CODES
            or item.scanner not in ("", "guard", "secrets", "literal", "pii")
            or type(item.scanner_index) is not int
            or type(item.revision) is not int
            or any(value is not None and type(value) is not int for value in (item.start, item.end))
        ):
            raise ValueError("Unexpected finding metadata")
        findings.append(
            {
                "code": item.code,
                "start": item.start,
                "end": item.end,
                "scanner": item.scanner,
                "scanner_index": item.scanner_index,
                "revision": item.revision,
            }
        )
    return findings


def observe(case, policy, representation):
    scanned, targets, credentials = represented(case, representation)
    markers = [
        case["text"],
        scanned,
        *case["privacy_markers"],
        *(case["text"][a:b] for a, b in case["credential_spans"] if b - a >= 8),
        *(scanned[a:b] for a, b in credentials if b - a >= 8),
    ]
    # Short public words can also occur in safe metadata, such as action="allow".
    markers = [marker for marker in markers if len(marker) >= 8]
    guard = RecordingGuard(policy)
    captured = SafeLogCapture(markers)
    logger = handoff.LOGGER
    old = logger.handlers[:], logger.level, logger.propagate, logger.disabled
    logger.handlers, logger.propagate, logger.disabled = [captured], False, False
    logger.setLevel(logging.INFO)
    consumer, privacy, failures = [], [], []
    rejected = False
    returned = None
    try:
        try:
            returned = handoff.run_workflow(
                "lookup",
                '{"document_id":"public-guide"}',
                handoff.demo_authorize,
                lambda _name, _arguments: scanned,
                consumer.append,
                result_guard=guard,
            )
        except Rejected as error:
            rejected = True
            if contains_marker((str(error), repr(error)), markers):
                privacy.append("rejection")
    finally:
        logger.handlers, logger.level, logger.propagate, logger.disabled = old
    result = guard.result
    if result is None or guard.calls != 1:
        raise ValueError("Missing or repeated return scan")
    for name, value in (("diagnostics", result.diagnostics()), ("repr", repr(result))):
        if contains_marker(value, markers):
            privacy.append(name)
    if captured.unsafe:
        privacy.append("recipe_logs")
    if captured.count != 2:
        failures.append("recipe_log_count")
    if result.accepted:
        if rejected or consumer != [result.require_text()] or returned != result.require_text():
            failures.append("checked_delivery")
    elif not rejected or consumer or returned is not None or result.text is not None:
        failures.append("rejected_delivery")
    findings = safe_findings(result)
    secret_findings = [item for item in findings if item["code"] in SECRET_CODES]
    actual_spans = [
        [item["start"], item["end"]] for item in secret_findings if item["revision"] == 0
    ]
    # Only actual REDACT trace entries can establish removal; a finding alone cannot.
    redactors = {trace.scanner_index for trace in result.trace if trace.action == Action.REDACT}
    removed = [
        (item["start"], item["end"])
        for item in findings
        if item["scanner_index"] in redactors
        and item["revision"] == 0
        and item["start"] is not None
        and item["end"] is not None
    ]
    # This fixed policy has one redactor: PIIScanner, replacing each merged
    # overlapping interval with "[PII]". Check its output independently of
    # Result.text, which is also the value handed to the consumer.
    merged = []
    for start, end in sorted(removed):
        if not 0 <= start < end <= len(scanned):
            raise ValueError("Invalid redaction interval")
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    expected_checked = scanned
    for start, end in reversed(merged):
        expected_checked = expected_checked[:start] + "[PII]" + expected_checked[end:]
    if result.accepted and (
        result.text != expected_checked
        or consumer != [expected_checked]
        or returned != expected_checked
    ):
        failures.append("checked_transformation")
    credential_spellings = [
        *(case["text"][a:b] for a, b in case["credential_spans"]),
        *(scanned[a:b] for a, b in credentials),
        *case["privacy_markers"],
    ]
    covered = all(
        all(any(a <= position < b for a, b in removed) for position in range(start, end))
        for start, end in credentials
    ) and not contains_marker(consumer, credential_spellings)
    withheld = rejected and not result.accepted and not consumer and result.text is None
    expected = case["expected_action"]
    comparisons = {key: None for key in COMPARISONS}
    if expected is not None:
        comparisons = {
            "action": result.action.value == expected,
            "delivery": consumer == ([] if expected == "block" else [scanned]),
            "target_spans": sorted(actual_spans) == targets
            if expected == "block"
            else not findings,
            "credential_coverage": withheld or covered if credentials else not findings,
        }
    expected_limit = len(scanned) > handoff.MAX_RETURN_CHARS
    if expected_limit and (
        result.action != Action.ERROR
        or [item["code"] for item in findings] != ["text_limit_exceeded"]
    ):
        failures.append("input_limit_contract")
    return {
        "action": result.action.value,
        "accepted": result.accepted,
        "consumer_count": len(consumer),
        "findings": findings,
        "secret_signature_signal": bool(secret_findings),
        "incidental_pii": any(item["code"].startswith("pii_") for item in findings),
        "comparisons": comparisons,
        "harness_failures": failures,
        "privacy_failures": privacy,
        "expected_limit_error": expected_limit,
        "unexpected_error": result.action == Action.ERROR and not expected_limit,
    }


def evaluate(cases):
    rows = []
    for case in cases:
        for policy in POLICIES:
            for representation in REPRESENTATIONS:
                row = {
                    "id": case["id"],
                    "family": case["family"],
                    "label": case["label"],
                    "policy": policy,
                    "representation": representation,
                    "expected_action": case["expected_action"],
                    "coordinate_space": (
                        "json-wire"
                        if representation.startswith("json_")
                        else "decoded-string"
                        if representation.startswith("decoded_")
                        else "plain-text"
                    ),
                }
                try:
                    observed = observe(case, policy, representation)
                    # No arbitrary observation fields (or raw data) enter the report.
                    for key in (
                        "action",
                        "accepted",
                        "consumer_count",
                        "findings",
                        "secret_signature_signal",
                        "incidental_pii",
                        "comparisons",
                        "harness_failures",
                        "privacy_failures",
                        "expected_limit_error",
                        "unexpected_error",
                    ):
                        row[key] = observed[key]
                    if contains_marker(
                        json.dumps(row),
                        [
                            marker
                            for marker in [case["text"], *case["privacy_markers"]]
                            if len(marker) >= 8
                        ],
                    ):
                        raise ValueError("Unsafe observation")
                except Exception:
                    row.update(
                        {
                            "action": None,
                            "accepted": None,
                            "consumer_count": None,
                            "findings": [],
                            "secret_signature_signal": None,
                            "incidental_pii": None,
                            "comparisons": {key: None for key in COMPARISONS},
                            "harness_failures": ["observation_error"],
                            "privacy_failures": [],
                            "expected_limit_error": None,
                            "unexpected_error": True,
                        }
                    )
                rows.append(row)
    return rows


def summarize(rows):
    scored = [row for row in rows if row["expected_action"] is not None]
    positive = [row for row in scored if row["expected_action"] == "block"]
    negative = [row for row in scored if row["expected_action"] == "allow"]
    return {
        "observations": len(rows),
        "scored": len(scored),
        "policy_dependent": len(rows) - len(scored),
        "action_counts": {
            action or "not_observed": sum(row["action"] == action for row in rows)
            for action in ("allow", "warn", "redact", "block", "error", None)
            if any(row["action"] == action for row in rows)
        },
        "desired_action_matches": sum(row["comparisons"]["action"] is True for row in scored),
        "desired_delivery_matches": sum(row["comparisons"]["delivery"] is True for row in scored),
        "exact_outcome_matches": sum(
            all(value is True for value in row["comparisons"].values())
            and not row["unexpected_error"]
            and not row["harness_failures"]
            and not row["privacy_failures"]
            for row in scored
        ),
        "positive_cases_without_secret_signature": sum(
            row["secret_signature_signal"] is False for row in positive
        ),
        "negative_cases_with_any_finding": sum(bool(row["findings"]) for row in negative),
        "incidental_pii_observations": sum(row["incidental_pii"] is True for row in rows),
        "expected_limit_errors": sum(row["expected_limit_error"] is True for row in rows),
        "unexpected_errors": sum(row["unexpected_error"] for row in rows),
        "privacy_failures": sum(bool(row["privacy_failures"]) for row in rows),
        "harness_failures": sum(bool(row["harness_failures"]) for row in rows),
    }


def source_metadata(corpus_path):
    paths = [
        Path(__file__),
        Path(corpus_path),
        ROOT / "examples/tool_result_handoff.py",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
    ]
    imported = Path(guardtrellis.__file__).resolve().parent
    return {
        "evaluation_version": "connection-strings-v1",
        "sdk_version": guardtrellis.__version__,
        "distribution_version": version("guardtrellis"),
        "sdk_import": "checkout" if imported.is_relative_to(ROOT) else "external-install",
        "sdk_sha256": {
            path.relative_to(imported.parent).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(imported.rglob("*.py"))
        },
        "source_sha256": {
            path.relative_to(ROOT).as_posix()
            if path.is_relative_to(ROOT)
            else "external-corpus": hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths
        },
        "dependencies": {name: version(name) for name in ("jsonschema", "referencing")},
        "python": platform.python_version(),
        "platform": platform.platform(),
        "created_utc": datetime.now(UTC).isoformat(),
        "usage": "authored-development-only",
        "limits": {
            "cases": MAX_CASES,
            "text_chars": MAX_TEXT,
            "json_wire_chars": MAX_WIRE,
            "scan_chars": handoff.MAX_RETURN_CHARS,
            "candidates_per_case": 4,
            "repetitions": 1,
        },
    }


def write_report(report_dir, rows, corpus_path=CORPUS):
    report_dir = Path(report_dir)
    groups = {
        f"{policy}/{representation}": summarize(
            [
                row
                for row in rows
                if row["policy"] == policy and row["representation"] == representation
            ]
        )
        for policy in POLICIES
        for representation in REPRESENTATIONS
    }
    report = {
        "metadata": source_metadata(Path(corpus_path).resolve()),
        "summary": summarize(rows),
        "by_policy_representation": groups,
        "by_family": {
            family: summarize([row for row in rows if row["family"] == family])
            for family in sorted({row["family"] for row in rows})
        },
        "by_label": {
            label: summarize([row for row in rows if row["label"] == label])
            for label in sorted({row["label"] for row in rows})
        },
        "rows": rows,
    }
    lines = [
        "# Connection-string development baseline",
        "",
        f"SDK {report['metadata']['sdk_version']}; {len(rows)} observations.",
        "",
        "Authored synthetic development data; no accuracy, credential-validity or driver "
        "compatibility claim. Desired BLOCK/ALLOW labels precede detector changes. "
        "Policy-dependent rows are "
        "unscored. Historical gaps and incidental PII redactions remain visible.",
        "",
        "| Policy / representation | Scored | Action matches | Delivery matches | Incidental PII "
        "| Unexpected errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key, summary in groups.items():
        lines.append(
            f"| {key} | {summary['scored']} | {summary['desired_action_matches']} | "
            f"{summary['desired_delivery_matches']} | "
            f"{summary['incidental_pii_observations']} | {summary['unexpected_errors']} |"
        )
    lines.extend(
        [
            "",
            "## Observed actions by authored label",
            "",
            "| Label | Observations | ALLOW | REDACT | BLOCK | ERROR |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for label, summary in report["by_label"].items():
        counts = summary["action_counts"]
        lines.append(
            f"| {label} | {summary['observations']} | {counts.get('allow', 0)} | "
            f"{counts.get('redact', 0)} | {counts.get('block', 0)} | {counts.get('error', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A secret-signature finding is distinct from incidental PII and from dedicated "
            "connection-string detection (which is not implemented in this baseline). "
            "Whole-URI target-span comparisons are aspirational coverage checks; existing secret "
            "controls target their supported token spans. Credential coverage checks authored "
            "credential intervals and spellings against actual consumer data; accepted text is "
            "also compared with the fixed policy's independently reconstructed transformation. "
            "This is not a general sanitization guarantee. "
            "An input-limit ERROR withholds delivery but is not a credential detection.",
            "",
            "Plain/decoded offsets refer to that string; serialized offsets refer to JSON wire. "
            "All finding offsets retain their scanner revision. No input/output text or credential "
            "values are copied into this report.",
            "",
            "## Retained mismatches",
            "",
            "| Case | Policy / representation | Mismatched comparisons |",
            "| --- | --- | --- |",
        ]
    )
    for row in rows:
        misses = [key for key, matches in row["comparisons"].items() if matches is False]
        if misses:
            lines.append(
                f"| {row['id']} | {row['policy']}/{row['representation']} | {', '.join(misses)} |"
            )
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
        cases = load_corpus(args.corpus)
        rows = evaluate(cases)
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
