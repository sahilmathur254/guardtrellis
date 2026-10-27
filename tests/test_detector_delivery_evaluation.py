"""Frozen projections, family-specific scoring, protocol integrity and bounded execution."""

import copy
import json
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from evaluation.detector_delivery import assets, contract, run
from guardtrellis import Action, Guard, PIIScanner, Result, SecretScanner, Stage

CASES, EXPECTATIONS, FREEZE = assets.load_frozen()
BY_ID = {case["id"]: case for case in CASES}
CANARY = "NeverIncludeThisPrivatePayload82"


def guard(profile):
    return Guard(
        retrieval_scanners=[
            SecretScanner(connection_strings=profile == "opt_in"),
            PIIScanner(phone_mode="formatted" if profile == "opt_in" else "contiguous"),
        ],
        max_chars=contract.MAX_INPUT_CHARS,
    )


def observed(case_id, profile="default", representation="plain", **kwargs):
    case = BY_ID[case_id]
    row = run.observe(
        case, EXPECTATIONS[case_id, profile, representation], guard(profile).scan, **kwargs
    )
    return {
        **row,
        "family": case["family"],
        "label": case["label"],
        "language": case["language"],
        "profile": profile,
        "contract_scope": EXPECTATIONS[case_id, profile, representation]["contract"]["scope"],
    }


def events(cell=0):
    profile = run.CELLS[cell][1]
    scanner = guard(profile)
    output = [
        {
            "event": "row",
            "row": run.observe(
                case, EXPECTATIONS[case["id"], profile, representation], scanner.scan
            ),
        }
        for case, representation in run.cell_cases(CASES, cell)
    ]
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    output.append(
        {
            "event": "complete",
            "count": 64,
            "limits": {
                key: None
                for key in ("cpu_seconds", "address_space_bytes", "core_bytes", "output_file_bytes")
            },
            "resources": {"process_cpu_ms": 0.0, "peak_rss_bytes": None},
            "sdk_version": sdk_version,
            "sdk_sha256": sdk_sha,
        }
    )
    return output


def encoded(events):
    return b"".join((json.dumps(event) + "\n").encode() for event in events)


def parse(events, cell=0):
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    return run.read_protocol(encoded(events), CASES, EXPECTATIONS, cell, sdk_version, sdk_sha)


def test_freeze_is_complete_balanced_and_not_a_hidden_benchmark():
    assert assets.digest((assets.HERE / "freeze_v1.json").read_bytes()) == assets.FREEZE_SHA256
    assert len(CASES) == 48 and len(EXPECTATIONS) == 384
    assert FREEZE["phase"] == "before_first_new_scenario_observation"
    assert (
        FREEZE["independent_case_review"] is False and FREEZE["maintainer_approval"] == "scope only"
    )
    assert max(len(case["id"]) for case in CASES) <= 80
    assert all(
        case["usage"] == "development" and case["review"] == "author_self_review_only"
        for case in CASES
    )
    assert sum(row["contract"]["eligible"] for row in EXPECTATIONS.values()) == 330


def test_freeze_loader_performs_no_sdk_import():
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from evaluation.detector_delivery import assets; assets.load_frozen(); "
        "assert 'guardtrellis' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(run.ROOT)], capture_output=True, timeout=10
    )
    assert completed.returncode == 0 and not completed.stdout and not completed.stderr


@pytest.mark.parametrize(
    "name",
    ["corpus_v1.jsonl", "expectations_v1.json", "PROTOCOL_v1.md", "contract.py", "freeze_v1.json"],
)
def test_any_frozen_asset_change_is_rejected(tmp_path, name):
    for source in [*FREEZE["files"], "freeze_v1.json"]:
        (tmp_path / source).write_bytes((assets.HERE / source).read_bytes())
    with (tmp_path / name).open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError):
        assets.load_frozen(tmp_path)


@pytest.mark.parametrize(
    "mutation", ["duplicate", "count", "usage", "review", "target", "code", "unknown", "label"]
)
def test_invalid_scenarios_are_rejected_without_payload_errors(mutation):
    cases = copy.deepcopy(CASES)
    if mutation == "duplicate":
        cases[1]["id"] = cases[0]["id"]
    elif mutation == "count":
        cases.pop()
    elif mutation == "usage":
        cases[0]["usage"] = "held_out"
    elif mutation == "review":
        cases[0]["review"] = "independent"
    elif mutation == "target":
        cases[0]["targets"] = [[False, 4]]
    elif mutation == "code":
        cases[0]["contracts"]["default"]["codes"] = [CANARY]
    elif mutation == "unknown":
        cases[0][CANARY] = CANARY
    else:
        cases[0]["label"] = "ambiguous"
    with pytest.raises(ValueError) as caught:
        assets.validate_cases(b"\n".join(json.dumps(case).encode() for case in cases))
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize(
    "wire", ['{"value":"a","value":"b"}', '{"value":NaN}', '{"value":1}', '{"other":"a"}', '"a"']
)
def test_fixed_decoding_rejects_duplicate_nonfinite_and_wrong_shapes(wire):
    with pytest.raises(ValueError):
        contract.decode_value(wire)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_json_equivalence_and_frozen_spans_use_character_indices(case):
    assert contract.decode_value(contract.wire(case["text"])) == case["text"]
    assert contract.decode_value(contract.wire(case["text"], True)) == case["text"]
    for representation in contract.REPRESENTATIONS:
        text, spans = contract.represented(case, representation, case["targets"])
        assert len(text) <= 2000
        for (start, end), (original_start, original_end) in zip(
            spans, case["targets"], strict=True
        ):
            original = case["text"][original_start:original_end]
            fragment = (
                "".join(map(contract.escaped_character, original))
                if representation == "json_escaped"
                else json.dumps(original)[1:-1]
                if representation == "json_literal"
                else original
            )
            assert text[start:end] == fragment


def test_partial_phone_signal_is_not_complete_redaction():
    old = observed("phone-05-sensitive")
    new = observed("phone-05-sensitive", "opt_in")
    assert old["primary"] and not old["comparisons"]["spans"] and not old["comparisons"]["delivery"]
    assert old["contract_match"] is None
    assert new["primary"] and all(new["comparisons"].values()) and new["contract_match"]


def test_incidental_pii_is_never_a_uri_true_positive():
    row = observed("connection-uri-01-sensitive")
    assert row["primary"] == [] and "pii_email" in row["incidental_codes"]
    planned = [
        item
        for item in run.inventory(CASES, EXPECTATIONS)
        if item["id"] == row["id"]
        and item["profile"] == "default"
        and item["representation"] == "plain"
    ]
    summary = run.summarize([row], planned)
    assert summary["tp"] == 0 and summary["fn"] == 1 and row["contract_match"] is True


def test_documentation_placeholder_can_conform_and_remain_a_scenario_false_positive():
    row = observed("connection-uri-06-benign", "opt_in")
    assert row["action"] == "block" and row["primary"] and row["contract_match"] is True
    assert not row["comparisons"]["action"] and not row["comparisons"]["delivery"]
    assert row["delivery_integrity"] and row["consumer_calls"] == 0


def test_error_is_not_detection_and_missing_samples_keep_denominators():
    case = CASES[0]
    expected = EXPECTATIONS[case["id"], "default", "plain"]
    row = run.observe(
        case, expected, lambda *_args, **_kwargs: Result(Action.ERROR, Stage.RETRIEVAL, None)
    )
    row.update(
        family=case["family"],
        label=case["label"],
        language="en",
        profile="default",
        contract_scope="supported",
    )
    summary = run.summarize([row], run.inventory(CASES, EXPECTATIONS))
    assert summary["errors"] == 1 and summary["tp"] == summary["fn"] == 0
    assert summary["observations"] == 1 and summary["incomplete_observations"] == 383
    assert summary["positive_expected"] == summary["negative_expected"] == 192


@pytest.mark.parametrize(
    "case_id,profile",
    [("email-01-sensitive", "default"), ("connection-uri-01-sensitive", "opt_in")],
)
def test_corrupted_or_rejected_delivery_fails_integrity_without_exposing_data(case_id, profile):
    def corrupt(_result, consumer):
        consumer(CANARY)

    row = observed(case_id, profile, delivery=corrupt)
    assert not row["delivery_integrity"] and not row["comparisons"]["delivery"]
    assert CANARY not in json.dumps(row)


def test_payload_in_sdk_diagnostics_is_flagged_but_not_copied(monkeypatch):
    monkeypatch.setattr(Result, "diagnostics", lambda self: {"raw": CASES[0]["text"]})
    row = observed(CASES[0]["id"])
    assert not row["privacy_ok"]
    assert CASES[0]["text"] not in json.dumps(row)


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_field",
        "id",
        "accepted",
        "code",
        "offset",
        "comparison",
        "contract",
        "duplicate",
        "runtime",
        "nan",
    ],
)
def test_worker_protocol_rejects_corruption_and_retains_valid_prefix(mutation):
    stream = events()
    target = stream[1]["row"]
    if mutation == "unknown_field":
        target[CANARY] = CANARY
    elif mutation == "id":
        target["id"] = CANARY
    elif mutation == "accepted":
        target["accepted"] = not target["accepted"]
    elif mutation == "code":
        target["incidental_codes"] = [CANARY]
    elif mutation == "offset":
        target["primary"][0]["end"] = 99999
    elif mutation == "comparison":
        target["comparisons"]["action"] = not target["comparisons"]["action"]
    elif mutation == "contract":
        target["contract_match"] = not target["contract_match"]
    elif mutation == "duplicate":
        stream.insert(1, copy.deepcopy(stream[0]))
    elif mutation == "runtime":
        stream[-1]["sdk_sha256"] = "0" * 64
    else:
        stream[-1]["resources"]["process_cpu_ms"] = float("nan")
    rows, _, valid = parse(stream)
    assert not valid and 1 <= len(rows) <= 64
    assert CANARY not in json.dumps(rows)


def test_truncated_duplicate_and_oversized_protocols_are_not_complete():
    stream = events()
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    raw = encoded(stream)
    for payload in (raw[:-2], raw + encoded([stream[-1]]), raw + b"x" * 65537):
        rows, _, valid = run.read_protocol(payload, CASES, EXPECTATIONS, 0, sdk_version, sdk_sha)
        assert not valid and len(rows) == 64


def fake_process(monkeypatch, raw, *, interrupt=False, stderr=b"", stalled=False):
    state = {}

    class Process:
        returncode = None

        def __init__(self, args, **kwargs):
            state.update(args=args, directory=Path(kwargs["cwd"]), env=kwargs["env"])
            kwargs["stdout"].write(raw)
            kwargs["stdout"].flush()
            kwargs["stderr"].write(stderr)
            kwargs["stderr"].flush()
            if interrupt:
                signal.raise_signal(signal.SIGINT)
            if not stalled and not interrupt:
                self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("fixed worker", timeout)

    def reap(process):
        assert state["directory"].exists()
        process.returncode = -9 if stalled or interrupt else 0
        state["reaped"] = True

    monkeypatch.setattr(run.subprocess, "Popen", Process)
    monkeypatch.setattr(run.limits, "kill_and_reap", reap)
    return state


def test_post_launch_interrupt_is_deferred_through_reaping_and_tmp_cleanup(monkeypatch):
    stream = events()
    state = fake_process(monkeypatch, encoded(stream[:1]), interrupt=True)
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    old = signal.getsignal(signal.SIGINT)
    result = run.measure(0, CASES, EXPECTATIONS, time.perf_counter() + 10, sdk_version, sdk_sha)
    assert result["status"] == "interrupted" and result["child_reaped"]
    assert len(result["rows"]) == 1 and state["reaped"] and not state["directory"].exists()
    assert signal.getsignal(signal.SIGINT) == old


def test_timeout_preserves_prefix_and_missing_denominator(monkeypatch):
    state = fake_process(monkeypatch, encoded(events()[:1]), stalled=True)
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    clock = iter(range(0, 1000, 6))
    monkeypatch.setattr(run.time, "perf_counter", lambda: next(clock))
    result = run.measure(0, CASES, EXPECTATIONS, 100, sdk_version, sdk_sha)
    assert (
        result["status"] == "wall_timeout" and result["child_reaped"] and len(result["rows"]) == 1
    )
    assert state["reaped"] and not state["directory"].exists()


def test_worker_stderr_is_counted_without_copying_contents(monkeypatch):
    fake_process(monkeypatch, encoded(events()), stderr=CANARY.encode())
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    result = run.measure(0, CASES, EXPECTATIONS, time.perf_counter() + 10, sdk_version, sdk_sha)
    assert result["status"] == "protocol_error" and result["stderr_bytes"] == len(CANARY)
    assert CANARY not in json.dumps(result) and len(result["rows"]) == 64


def test_windows_uses_base_interpreter_with_venv_and_sanitized_environment(monkeypatch):
    state = fake_process(monkeypatch, encoded(events()))
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    monkeypatch.setattr(run.sys, "platform", "win32")
    result = run.measure(0, CASES, EXPECTATIONS, time.perf_counter() + 10, sdk_version, sdk_sha)
    assert result["status"] == "completed"
    assert state["args"][0] == sys._base_executable
    assert state["env"]["__PYVENV_LAUNCHER__"] == sys.executable
    assert "HOME" not in state["env"] and "PYTEST_CURRENT_TEST" not in state["env"]


@pytest.mark.parametrize("cell", range(6), ids=lambda cell: "/".join(run.CELLS[cell]))
def test_native_cell_completes_reaps_and_keeps_all_64_observations(cell):
    sdk_version, _, sdk_sha = run.sdk_fingerprint()
    result = run.measure(cell, CASES, EXPECTATIONS, time.perf_counter() + 20, sdk_version, sdk_sha)
    assert result["status"] == "completed", result["status"]
    assert result["child_reaped"] and result["stderr_bytes"] == 0
    assert 0 < result["stdout_bytes"] <= 65536 and len(result["rows"]) == 64
    assert all(
        row["delivery_integrity"] and row["privacy_ok"] and row["contract_match"] is not False
        for row in result["rows"]
    )


def test_deadline_exhaustion_writes_incomplete_report_without_starting_children(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(run, "TOTAL_SECONDS", 0)
    monkeypatch.setattr(
        run.subprocess, "Popen", lambda *_a, **_k: pytest.fail("No child should start")
    )
    target = tmp_path / "incomplete"
    assert run.main(["--report-dir", str(target)]) == 1
    report = json.loads((target / "results.json").read_text())
    assert report["summary"]["observations"] == 0
    assert report["summary"]["incomplete_observations"] == 384
    assert all(row["status"] == "not_started" for row in report["runs"])


def test_cli_reproduces_private_reports_and_refuses_overwrite(tmp_path):
    target = tmp_path / CANARY
    completed = subprocess.run(
        [sys.executable, str(run.HERE), "--report-dir", str(target)],
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0 and not completed.stderr
    report = json.loads((target / "results.json").read_text())
    assert report["measurement_checks_passed"] and report["contract_checks_passed"]
    assert report["summary"]["observations"] == 384 and len(report["runs"]) == 6
    groups = report["by_family_profile_representation"]
    assert len(groups) == 24 and sum(group["observations"] for group in groups.values()) == 384
    assert all(
        group["positive_expected"] == group["negative_expected"] == 8 for group in groups.values()
    )
    surfaces = (
        completed.stdout.decode()
        + (target / "results.json").read_text()
        + (target / "REPORT.md").read_text()
    )
    assert CANARY not in surfaces
    assert not any(run.contains_marker(surfaces, case["privacy_markers"]) for case in CASES)
    original = (target / "results.json").read_bytes()
    again = subprocess.run(
        [sys.executable, str(run.HERE), "--report-dir", str(target)],
        capture_output=True,
        timeout=10,
    )
    assert again.returncode == 2 and again.stdout == b""
    assert (
        CANARY.encode() not in again.stderr and (target / "results.json").read_bytes() == original
    )


def test_isolated_password_component_in_diagnostics_is_flagged(monkeypatch):
    marker = "FabricatedUriA51"
    monkeypatch.setattr(Result, "diagnostics", lambda self: {"password": marker})
    row = observed("connection-uri-01-sensitive", "opt_in")
    assert not row["privacy_ok"] and marker not in json.dumps(row)


def test_preparation_interrupt_returns_static_130(monkeypatch, tmp_path, capsys):
    def interrupted(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(run.assets, "load_frozen", interrupted)
    assert run.main(["--report-dir", str(tmp_path / "unused")]) == 130
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "Evaluation interrupted.\n"


def test_interrupt_during_report_write_is_not_reported_as_success(tmp_path, monkeypatch):
    original = run.write_report
    writes = []

    def interrupt_after_write(report, directory):
        original(report, directory)
        writes.append(1)
        if len(writes) == 1:
            signal.raise_signal(signal.SIGINT)

    monkeypatch.setattr(run, "write_report", interrupt_after_write)
    target = tmp_path / "late-interrupt"
    assert run.main(["--report-dir", str(target)]) == 130
    report = json.loads((target / "results.json").read_text())
    assert report["interrupted"] and not report["measurement_checks_passed"]
    assert report["summary"]["observations"] == 384
    assert report["summary"]["incomplete_observations"] == 0


def test_main_interruption_preserves_prefix_and_marks_remaining_cells(tmp_path, monkeypatch):
    rows, _, valid = parse(events())
    assert valid

    def interrupted(*_args):
        return dict(
            family="email",
            profile="default",
            expected_observations=64,
            status="interrupted",
            child_reaped=True,
            rows=rows[:1],
        )

    monkeypatch.setattr(run, "measure", interrupted)
    target = tmp_path / "interrupted"
    assert run.main(["--report-dir", str(target)]) == 130
    report = json.loads((target / "results.json").read_text())
    assert report["interrupted"] and report["summary"]["incomplete_observations"] == 383
    assert len(report["runs"]) == 6 and len(report["rows"]) == 1
    assert all(row["status"] == "not_started" for row in report["runs"][1:])
