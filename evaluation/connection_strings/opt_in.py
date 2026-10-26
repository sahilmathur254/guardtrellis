"""Default-versus-opt-in URI comparison with frozen, independent acceptance targets."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from guardtrellis import Action, Guard, LiteralScanner, PIIScanner, Rejected, SecretScanner
from guardtrellis import _connection_strings as uri_limits

HERE = Path(__file__).resolve().parent
SPEC = spec_from_file_location("connection_contract_baseline", HERE / "run_supplement.py")
assert SPEC is not None and SPEC.loader is not None
supplement = module_from_spec(SPEC)
SPEC.loader.exec_module(supplement)
base = supplement.base
handoff = base.handoff
VERSION = "connection-uri-opt-in-v1"
ACCEPTANCE = HERE / "acceptance_v1.json"
ACCEPTANCE_SHA256 = "1c1aeb4110b6c4545233c59560726bc96799a6713c4ad83adb5e9a628981a4d8"
CORRECTIONS = HERE / "acceptance_corrections_v1.json"
CORRECTIONS_SHA256 = "9c5c1e7fddd813ad6629c9c15c07b7ec9d9c9e33fb4a32d8b5fc9e3e07ef34de"
CORPORA = ("corpus_v1.jsonl", "contract_supplement_v1.jsonl", "boundaries_v1.jsonl")
BASELINES = ("baseline_0.1.7", "contract_baseline_0.1.7", "boundary_baseline_0.1.7")
URI_CODES = {"secret_postgresql_uri", "secret_mongodb_uri"}
ERROR_CODES = {"connection_string_limit_exceeded", "connection_string_configuration_error"}
MODES = ("default", "connection_strings")


def load_cases():
    cases = []
    for name in CORPORA:
        rows = (
            base.load_corpus(HERE / name)
            if name == CORPORA[0]
            else supplement.load_corpus(HERE / name)
        )
        cases.extend(rows)
    if len(cases) != 128 or len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Unexpected comparison corpus")
    return cases


def load_acceptance(path=ACCEPTANCE):
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != ACCEPTANCE_SHA256:
        raise ValueError("Acceptance decisions changed")
    data = json.loads(
        raw, object_pairs_hook=base.unique_object, parse_constant=base.reject_constant
    )
    if data["version"] != "connection-uri-acceptance-v1":
        raise ValueError("Unexpected acceptance version")
    for name in CORPORA:
        if hashlib.sha256((HERE / name).read_bytes()).hexdigest() != data["corpus_sha256"][name]:
            raise ValueError("Frozen corpus changed")
    cases = {case["id"]: case for case in load_cases()}
    decisions = {}
    for row in data["rows"]:
        case = cases[row["id"]]
        key = row["id"], row["representation"]
        if key in decisions or row["dataset_version"] != case["dataset_version"]:
            raise ValueError("Unexpected acceptance identity")
        if row["representation"] not in base.REPRESENTATIONS or type(row["eligible"]) is not bool:
            raise ValueError("Invalid acceptance decision")
        text, _, _ = base.represented(case, row["representation"])
        if row["eligible"] and not base.valid_spans(row["uri_spans"], text):
            raise ValueError("Invalid acceptance spans")
        if not row["eligible"] and row["uri_spans"] is not None:
            raise ValueError("Unscored acceptance spans")
        decisions[key] = row
    if len(decisions) != len(cases) * len(base.REPRESENTATIONS):
        raise ValueError("Incomplete acceptance decisions")
    raw = CORRECTIONS.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CORRECTIONS_SHA256:
        raise ValueError("Acceptance corrections changed")
    corrections = json.loads(raw)
    for correction in corrections["rows"]:
        key = correction["id"], correction["representation"]
        # Check the correction against the prior authored corpus, never observations.
        _, targets, _ = base.represented(cases[key[0]], key[1])
        if correction["uri_spans"] != targets or decisions[key]["uri_spans"] != []:
            raise ValueError("Invalid acceptance correction")
        decisions[key] = {**decisions[key], "uri_spans": targets}
    return decisions


class RecordingGuard:
    def __init__(self, policy):
        if policy not in base.POLICIES:
            raise ValueError("Unknown policy")
        scanners = [SecretScanner(connection_strings=True)]
        if policy == "tool_return":
            # Preserve the recipe's ordered blocking literal and PII policies.
            scanners.extend([LiteralScanner(["internal-only"], action=Action.BLOCK), PIIScanner()])
        self.delegate = Guard(retrieval_scanners=scanners, max_chars=handoff.MAX_RETURN_CHARS)
        self.result = None
        self.calls = 0

    def scan(self, text, *, stage):
        self.calls += 1
        self.result = self.delegate.scan(text, stage=stage)
        return self.result


def safe_findings(result):
    findings = []
    for item in result.findings:
        if (
            item.code not in base.FINDING_CODES | URI_CODES | ERROR_CODES
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


def observe_opt_in(case, policy, representation):
    scanned, targets, credentials = base.represented(case, representation)
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
    captured = base.SafeLogCapture(markers)
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
            if base.contains_marker((str(error), repr(error)), markers):
                privacy.append("rejection")
    finally:
        logger.handlers, logger.level, logger.propagate, logger.disabled = old
    result = guard.result
    if result is None or guard.calls != 1:
        raise ValueError("Missing or repeated return scan")
    for name, value in (("diagnostics", result.diagnostics()), ("repr", repr(result))):
        if base.contains_marker(value, markers):
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
    secret_findings = [item for item in findings if item["code"] in base.SECRET_CODES | URI_CODES]
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
    ) and not base.contains_marker(consumer, credential_spellings)
    withheld = rejected and not result.accepted and not consumer and result.text is None
    expected = case["expected_action"]
    comparisons = {key: None for key in base.COMPARISONS}
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
        "secret_signature_signal": any(
            item["code"] in base.SECRET_CODES for item in secret_findings
        ),
        "incidental_pii": any(item["code"].startswith("pii_") for item in findings),
        "comparisons": comparisons,
        "harness_failures": failures,
        "privacy_failures": privacy,
        "expected_limit_error": expected_limit,
        "unexpected_error": result.action == Action.ERROR and not expected_limit,
    }


def token_findings(row):
    return [finding for finding in row["findings"] if finding["code"] in base.SECRET_CODES]


def acceptance_checks(row, default, decision):
    uri_spans = sorted(
        [finding["start"], finding["end"]]
        for finding in row["findings"]
        if finding["code"] in URI_CODES
    )
    eligible = decision["eligible"] and not row["expected_limit_error"]
    checks = {
        key: None
        for key in ("uri_spans", "blocking_delivery", "existing_tokens", "negative_policy")
    }
    if eligible:
        checks["uri_spans"] = uri_spans == decision["uri_spans"]
        checks["existing_tokens"] = token_findings(row) == token_findings(default)
        if decision["uri_spans"]:
            checks["blocking_delivery"] = (
                row["action"] == "block" and not row["accepted"] and row["consumer_count"] == 0
            )
        else:
            checks["negative_policy"] = all(
                row[key] == default[key]
                for key in ("action", "accepted", "consumer_count", "findings")
            )
    return {
        "contract_eligible": eligible,
        "acceptance_reason": "fixed_return_input_limit"
        if row["expected_limit_error"]
        else decision["reason"],
        "expected_uri_spans": decision["uri_spans"] if eligible else None,
        "uri_findings": [item for item in row["findings"] if item["code"] in URI_CODES],
        "existing_token_findings": token_findings(row),
        "acceptance_checks": checks,
        "contract_pass": all(value is not False for value in checks.values()) if eligible else None,
    }


def historical_rows():
    rows = {}
    for name in BASELINES:
        report = json.loads((HERE / name / "results.json").read_text(encoding="utf-8"))
        for row in report["rows"]:
            rows[row["id"], row["policy"], row["representation"]] = row
    return rows


def evaluate():
    decisions = load_acceptance()
    cases = load_cases()
    frozen = historical_rows()
    defaults = {
        (row["id"], row["policy"], row["representation"]): row for row in base.evaluate(cases)
    }
    rows = []
    for case in cases:
        for policy in base.POLICIES:
            for representation in base.REPRESENTATIONS:
                key = case["id"], policy, representation
                default = defaults[key]
                compatible = all(default[field] == frozen[key][field] for field in default)
                for mode in MODES:
                    row = dict(default)
                    if mode == "connection_strings":
                        # Fail closed in the evaluator too: never serialize arbitrary exceptions.
                        try:
                            row.update(observe_opt_in(case, policy, representation))
                        except Exception:
                            row.update(
                                action=None,
                                accepted=None,
                                consumer_count=None,
                                findings=[],
                                secret_signature_signal=None,
                                incidental_pii=None,
                                comparisons={name: None for name in base.COMPARISONS},
                                harness_failures=["observation_error"],
                                privacy_failures=[],
                                expected_limit_error=None,
                                unexpected_error=True,
                            )
                    row.update(
                        mode=mode,
                        dataset_version=case["dataset_version"],
                        default_compatible=compatible,
                    )
                    row.update(
                        acceptance_checks(row, default, decisions[case["id"], representation])
                    )
                    if mode == "default":
                        row["contract_pass"] = None
                    if base.contains_marker(
                        json.dumps(row),
                        [
                            marker
                            for marker in [case["text"], *case["privacy_markers"]]
                            if len(marker) >= 8
                        ],
                    ):
                        raise ValueError("Unsafe comparison metadata")
                    rows.append(row)
    return rows


def summarize(rows):
    opted_in = [row for row in rows if row["mode"] == "connection_strings"]
    return {
        "observations": len(rows),
        "default_compatibility_failures": sum(
            not row["default_compatible"] for row in rows if row["mode"] == "default"
        ),
        "eligible_opt_in_observations": sum(row["contract_eligible"] for row in opted_in),
        "contract_failures": sum(row["contract_pass"] is False for row in opted_in),
        "uri_finding_observations": sum(bool(row["uri_findings"]) for row in opted_in),
        "unexpected_errors": sum(row["unexpected_error"] for row in rows),
        "privacy_failures": sum(bool(row["privacy_failures"]) for row in rows),
        "harness_failures": sum(bool(row["harness_failures"]) for row in rows),
        "modes": {
            mode: base.summarize([row for row in rows if row["mode"] == mode]) for mode in MODES
        },
    }


def write_report(report_dir, rows, resources=None):
    metadata = base.source_metadata(HERE / CORPORA[0])
    metadata.update(
        evaluation_version=VERSION,
        acceptance_sha256=ACCEPTANCE_SHA256,
        acceptance_corrections_sha256=CORRECTIONS_SHA256,
        opt_in_status="implemented_unreleased",
        uri_processing_limits={
            "input_chars": uri_limits.MAX_TEXT_CHARS,
            "candidate_chars": uri_limits.MAX_CANDIDATE_CHARS,
            "candidate_attempts": uri_limits.MAX_CANDIDATES,
        },
    )
    for path in [
        Path(__file__),
        HERE / "run_supplement.py",
        ACCEPTANCE,
        CORRECTIONS,
        HERE / "PROPOSAL.md",
        *(HERE / name for name in CORPORA),
        *(HERE / name / "results.json" for name in BASELINES),
    ]:
        metadata["source_sha256"][path.relative_to(base.ROOT).as_posix()] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    report = {
        "metadata": metadata,
        "summary": summarize(rows),
        "by_dataset": {
            name: summarize([row for row in rows if row["dataset_version"] == name])
            for name in sorted({row["dataset_version"] for row in rows})
        },
        "rows": rows,
    }
    if resources is not None:
        report["resources"] = resources
        for path in (HERE / "resources.py", HERE.parent / "measure_resources.py"):
            metadata["source_sha256"][path.relative_to(base.ROOT).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    lines = [
        "# Connection-URI opt-in comparison",
        "",
        f"SDK {metadata['sdk_version']}; {len(rows)} observations; "
        "local implementation, unreleased.",
        "",
        "Authored synthetic development evidence. The original acceptance file precedes detector "
        "observations. A separately recorded post-observation harness correction restores the "
        "existing-token overlap case's already-authored URI target; see OPT_IN.md. "
        "Desired scores retain unsupported raw JSON/deferred misses and incidental PII findings. "
        "Contract acceptance checks eligible literal/explicitly decoded inputs and URI-only spans. "
        "Default compatibility compares historical safe observation fields, excluding provenance. "
        "Existing token findings are checked separately. No population accuracy claim is made.",
        "",
        "| Mode | Desired action matches | Desired exact matches | Unexpected errors |",
        "| --- | ---: | ---: | ---: |",
    ]
    for mode, summary in report["summary"]["modes"].items():
        lines.append(
            f"| {mode} | {summary['desired_action_matches']} | "
            f"{summary['exact_outcome_matches']} | {summary['unexpected_errors']} |"
        )
    summary = report["summary"]
    lines.extend(
        [
            "",
            f"Eligible opt-in observations: {summary['eligible_opt_in_observations']}; "
            f"contract failures: {summary['contract_failures']}; default compatibility failures: "
            f"{summary['default_compatibility_failures']}.",
            "",
            "Raw fully Unicode-escaped JSON remains outside the detector's grammar. Raw JSON whose "
            "encoding changes literal content has separately recorded desired outcomes but no "
            "URI acceptance claim. Decode explicitly before scanning those strings. The recipe's "
            "2,000-character return limit remains separate from SDK processing budgets.",
            "",
            "## Contract failures",
            "",
            "| Case | Policy / representation | Failed checks |",
            "| --- | --- | --- |",
        ]
    )
    for row in rows:
        if row["mode"] == "connection_strings" and row["contract_pass"] is False:
            failed = ", ".join(
                key for key, value in row["acceptance_checks"].items() if value is False
            )
            lines.append(f"| {row['id']} | {row['policy']}/{row['representation']} | {failed} |")
    lines.extend(
        [
            "",
            "Complete metadata-only observations, including retained desired-outcome misses, "
            "are in results.json.",
        ]
    )
    report_dir = Path(report_dir)
    report_dir.mkdir(parents=True, exist_ok=False)
    (report_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (report_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--resources", action="store_true")
    args = parser.parse_args(argv)
    if args.report_dir.exists():
        parser.error("Report directory already exists")
    try:
        rows = evaluate()
        probes = None
        if args.resources:
            spec = spec_from_file_location("connection_uri_resources", HERE / "resources.py")
            assert spec is not None and spec.loader is not None
            resource_module = module_from_spec(spec)
            spec.loader.exec_module(resource_module)
            probes = [resource_module.measure(mode) for mode in resource_module.MODES]
        report = write_report(args.report_dir, rows, probes)
    except (OSError, ValueError):
        parser.error("Invalid comparison sources or unavailable report path")
    print(json.dumps(report["summary"], sort_keys=True))
    failed = any(
        report["summary"][key]
        for key in (
            "default_compatibility_failures",
            "contract_failures",
            "unexpected_errors",
            "privacy_failures",
            "harness_failures",
        )
    )
    if probes is not None:
        failed |= any(
            not probe["contract_matches"] or not probe["child_reaped"] or probe["stderr_bytes"]
            for probe in probes
        )
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
