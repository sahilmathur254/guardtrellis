"""Authored async delivery contracts, bounded workers and metadata-only evidence."""

import asyncio
import copy
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from evaluation.concurrency import run as evaluation
from guardtrellis import Guard, PIIScanner, SecretScanner


def policy():
    return Guard(
        input_scanners=[SecretScanner(), PIIScanner(formats=["phone"], phone_mode="formatted")]
    )


def test_authored_expected_payloads_have_exact_sizes_and_distinct_request_markers():
    fixtures = evaluation.load_fixtures()
    assert set(fixtures) == {"allow", "redact", "block"}
    assert len(evaluation.CELLS) == 12
    for cell in evaluation.CELLS:
        case = fixtures[cell["family"]]
        first, checked, receipt = evaluation.request_text(case, cell["input_chars"], 0)
        second, other_checked, other_receipt = evaluation.request_text(case, cell["input_chars"], 1)
        assert len(first) == len(second) == cell["input_chars"]
        assert first != second and receipt != other_receipt
        if cell["family"] == "block":
            assert checked is other_checked is None
        elif cell["family"] == "allow":
            assert checked == first and other_checked == second
        else:
            assert checked == first.replace("+1-202-555-0123", "[PII]")
            assert other_checked == second.replace("+1-202-555-0123", "[PII]")


@pytest.mark.parametrize(
    "corruption", ["callback_input", "wrong_receipt", "blocked_callback", "exception"]
)
def test_outcome_corruption_is_visible_without_payload_or_exception(corruption):
    cell = evaluation.CELLS[9 if corruption == "blocked_callback" else 5]
    case = evaluation.load_fixtures()[cell["family"]]
    underlying = policy()
    canary = "private-exception-canary"

    class CorruptPolicy:
        async def arun(self, text, callback):
            if corruption == "exception":
                raise ValueError(canary)
            if corruption == "blocked_callback":
                callback(text)
            if corruption == "callback_input":
                original = callback

                def callback(checked):
                    return original(checked.replace("request-", "another-request-"))

            result = await underlying.arun(text, callback)
            if corruption == "wrong_receipt":
                result = replace(
                    result, output_result=replace(result.output_result, text="wrong-receipt")
                )
            return result

    events = []
    asyncio.run(evaluation.exercise(CorruptPolicy(), case, cell, 4, events.append))
    assert not events[0]["warmup_matches"]
    samples = [event for event in events if event["event"] == "sample"]
    assert len(samples) == 4
    assert not any(evaluation.sample_matches(sample, cell) for sample in samples)
    rendered = json.dumps(events)
    for marker in (canary, case["payload"], "request-0000", "receipt-0000", "wrong-receipt"):
        assert marker not in rendered


def protocol_events():
    return [
        {
            "event": "limits",
            "limits": {
                "cpu_seconds": None,
                "address_space_bytes": None,
                "core_bytes": None,
                "output_file_bytes": None,
            },
        },
        {"event": "prepared", "setup_ms": 1.0},
        {"event": "warmup", "warmup_ms": 2.0, "warmup_matches": True},
        *[
            {
                "event": "sample",
                "index": index,
                "action": "allow",
                "accepted": True,
                "callback_count": 1,
                "callback_matches": True,
                "delivery_matches": True,
                "findings_match": True,
                "error": False,
                "admission_wait_ms": 0.1,
                "arun_ms": 1.0,
            }
            for index in range(4)
        ],
        {
            "event": "finished",
            "batch_ms": 5.0,
            "max_active": 1,
            "resources": {"process_cpu_ms": 4.0, "peak_rss_bytes": None},
        },
    ]


def encoded(events):
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_payload",
        "bad_action",
        "nan",
        "bool_time",
        "duplicate_index",
        "bad_callback_count",
        "bad_bool",
        "bad_limits",
        "bad_resources",
        "missing_sample",
        "wrong_active",
        "event_after_end",
    ],
)
def test_protocol_rejects_malformed_metadata_without_copying_unknown_content(mutation):
    events = protocol_events()
    if mutation == "extra_payload":
        events[4]["payload"] = "private-protocol-canary"
    elif mutation == "bad_action":
        events[4]["action"] = "private-protocol-canary"
    elif mutation == "nan":
        events[4]["arun_ms"] = float("nan")
    elif mutation == "bool_time":
        events[4]["arun_ms"] = True
    elif mutation == "duplicate_index":
        events[4]["index"] = 0
    elif mutation == "bad_callback_count":
        events[4]["callback_count"] = -1
    elif mutation == "bad_bool":
        events[4]["accepted"] = 1
    elif mutation == "bad_limits":
        events[0]["limits"]["extra"] = "private-protocol-canary"
    elif mutation == "bad_resources":
        events[-1]["resources"]["process_cpu_ms"] = "private-protocol-canary"
    elif mutation == "missing_sample":
        events.pop(4)
    elif mutation == "wrong_active":
        events[-1]["max_active"] = 4
    else:
        events.append({"event": "error"})
    observed = evaluation.read_protocol(encoded(events), evaluation.CELLS[0], 4)
    assert observed["protocol_error"]
    assert "private-protocol-canary" not in json.dumps(observed)
    if mutation == "extra_payload":
        assert [sample["index"] for sample in observed["samples"]] == [0]


def test_duplicate_keys_truncated_output_and_incomplete_samples_remain_failures():
    events = protocol_events()
    raw = encoded(events[:4]) + b'{"event":"sample","event":"private-canary"}\n'
    observed = evaluation.read_protocol(raw, evaluation.CELLS[0], 4)
    assert observed["protocol_error"] and not observed["finished"]
    assert len(observed["samples"]) == 1
    assert "private-canary" not in json.dumps(observed)
    partial = evaluation.read_protocol(encoded(events[:4]), evaluation.CELLS[0], 4)
    assert not partial["finished"] and not partial["protocol_error"]
    assert len(partial["samples"]) == 1


def test_four_call_cell_requires_observed_overlap():
    events = protocol_events()
    observed = evaluation.read_protocol(encoded(events), evaluation.CELLS[1], 4)
    assert observed["protocol_error"] and not observed["finished"]
    events[-1]["max_active"] = 4
    assert evaluation.read_protocol(encoded(events), evaluation.CELLS[1], 4)["finished"]


def test_launch_selection_preserves_windows_venv_without_inheriting_secrets(monkeypatch):
    monkeypatch.setenv("GUARDTRELLIS_TEST_SECRET", "environment-canary")
    monkeypatch.setenv("PYTHONPATH", "private-path-canary")
    monkeypatch.setattr(evaluation.sys, "platform", "win32")
    monkeypatch.setattr(evaluation.sys, "_base_executable", "base-interpreter")
    monkeypatch.setattr(evaluation.sys, "executable", "venv-interpreter")
    executable, environment = evaluation.launch_settings()
    assert executable == "base-interpreter"
    assert environment["__PYVENV_LAUNCHER__"] == "venv-interpreter"
    assert "GUARDTRELLIS_TEST_SECRET" not in environment and "PYTHONPATH" not in environment
    monkeypatch.setattr(evaluation.sys, "platform", "linux")
    executable, environment = evaluation.launch_settings()
    assert executable == "venv-interpreter"
    assert "__PYVENV_LAUNCHER__" not in environment


@pytest.mark.parametrize("interrupted", [False, True])
def test_actual_stuck_worker_is_terminated_reaped_and_temporary_directory_removed(
    tmp_path, monkeypatch, interrupted
):
    worker = tmp_path / "stuck.py"
    worker.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    real_popen = subprocess.Popen
    children = []

    def popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        children.append((process, Path(kwargs["cwd"])))
        if interrupted:
            original_wait = process.wait
            first = True

            def wait(*args, **kwargs):
                nonlocal first
                if first:
                    first = False
                    raise KeyboardInterrupt
                return original_wait(*args, **kwargs)

            process.wait = wait
        return process

    monkeypatch.setattr(evaluation, "HERE", worker)
    monkeypatch.setattr(evaluation, "WALL_SECONDS", 0.2)
    monkeypatch.setattr(evaluation.subprocess, "Popen", popen)
    row = evaluation.measure(0, 4, 0, time.perf_counter() + 5)
    assert row["status"] == ("interrupted" if interrupted else "wall_timeout")
    assert row["child_reaped"] and not row["contract_matches"]
    assert row["samples"] == []
    assert "resources" not in row
    assert children[0][0].poll() is not None
    assert not children[0][1].exists()


def test_interrupt_immediately_after_launch_still_reaps_the_child(tmp_path, monkeypatch):
    worker = tmp_path / "just_started.py"
    worker.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    real_popen = subprocess.Popen
    children = []
    interrupted = False

    def popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        children.append((process, Path(kwargs["cwd"])))
        return process

    def interrupt_after_launch(frame, event, _arg):
        nonlocal interrupted
        if (
            not interrupted
            and event == "line"
            and frame.f_code is evaluation.measure.__code__
            and frame.f_locals.get("process") is not None
        ):
            interrupted = True
            raise KeyboardInterrupt
        return interrupt_after_launch

    monkeypatch.setattr(evaluation, "HERE", worker)
    monkeypatch.setattr(evaluation.subprocess, "Popen", popen)
    previous_trace = sys.gettrace()
    try:
        sys.settrace(interrupt_after_launch)
        row = evaluation.measure(0, 4, 0, time.perf_counter() + 5)
    finally:
        sys.settrace(previous_trace)
        # A failing regression must not leave the reproducer itself alive.
        exited_before_test_cleanup = bool(children) and children[0][0].poll() is not None
        for process, _directory in children:
            evaluation.limits.kill_and_reap(process)
    assert interrupted
    assert row["status"] == "interrupted"
    assert row["child_reaped"] and exited_before_test_cleanup
    assert not row["contract_matches"]
    assert not children[0][1].exists()


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("boundary", ["before_kill", "during_reap"])
def test_signal_during_cleanup_reaps_child_and_preserves_partial_evidence(
    tmp_path, monkeypatch, signum, boundary
):
    prefix = encoded(protocol_events()[:4])
    worker = tmp_path / "partial_then_stuck.py"
    worker.write_text(
        f"import sys, time\nsys.stdout.buffer.write({prefix!r})\n"
        "sys.stdout.buffer.flush()\ntime.sleep(60)\n",
        encoding="utf-8",
    )
    real_popen = subprocess.Popen
    real_cleanup = evaluation.limits.kill_and_reap
    children = []
    cleaning = False
    emitted = False

    def send_signal():
        nonlocal emitted
        if not emitted:
            emitted = True
            signal.raise_signal(signum)

    def popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        children.append((process, Path(kwargs["cwd"])))
        original_wait = process.wait

        def wait(*args, **kwargs):
            if cleaning and boundary == "during_reap":
                send_signal()
            return original_wait(*args, **kwargs)

        process.wait = wait
        # Observe readiness before testing cleanup, without assuming startup speed.
        deadline = time.perf_counter() + 5
        while os.fstat(kwargs["stdout"].fileno()).st_size < len(prefix):
            assert process.poll() is None and time.perf_counter() < deadline
            time.sleep(0.01)
        return process

    def cleanup(process):
        nonlocal cleaning
        cleaning = True
        if boundary == "before_kill":
            send_signal()
        real_cleanup(process)

    def inherited_handler(_signum, _frame):
        raise KeyboardInterrupt

    previous = {item: signal.getsignal(item) for item in (signal.SIGINT, signal.SIGTERM)}
    monkeypatch.setattr(evaluation, "HERE", worker)
    monkeypatch.setattr(evaluation, "WALL_SECONDS", 0.1)
    monkeypatch.setattr(evaluation.subprocess, "Popen", popen)
    monkeypatch.setattr(evaluation.limits, "kill_and_reap", cleanup)
    try:
        for item in previous:
            signal.signal(item, inherited_handler)
        row = evaluation.measure(0, 4, 0, time.perf_counter() + 5)
        exited_before_test_cleanup = children[0][0].poll() is not None
        restored = all(signal.getsignal(item) is inherited_handler for item in previous)
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)
        for process, _directory in children:
            real_cleanup(process)
    assert emitted and restored
    assert row["status"] == "interrupted"
    assert row["child_reaped"] and exited_before_test_cleanup
    assert not row["contract_matches"]
    assert not children[0][1].exists()
    assert [sample["index"] for sample in row["samples"]] == [0]
    assert row["samples"][0]["contract_matches"]
    assert row["expected_samples"] == 4


def test_worker_error_protocol_and_stderr_do_not_leak_exception(tmp_path, monkeypatch):
    worker = tmp_path / "failure.py"
    worker.write_text(
        'import sys\nprint(\'{"event":"error"}\')\n'
        "print('private-stderr-canary', file=sys.stderr)\nraise SystemExit(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(evaluation, "HERE", worker)
    row = evaluation.measure(0, 4, 0, time.perf_counter() + 5)
    assert row["status"] == "worker_error" and row["worker_error"]
    assert row["child_reaped"] and row["stderr_bytes"] > 0
    assert not row["contract_matches"]
    assert "private-stderr-canary" not in json.dumps(row)


def test_output_capture_limit_is_a_failed_measurement(tmp_path, monkeypatch):
    worker = tmp_path / "excess.py"
    worker.write_text("print('private-output-canary' * 6000)\n", encoding="utf-8")
    monkeypatch.setattr(evaluation, "HERE", worker)
    row = evaluation.measure(0, 4, 0, time.perf_counter() + 5)
    assert row["status"] == "output_limit" and row["child_reaped"]
    assert not row["contract_matches"]
    assert "private-output-canary" not in json.dumps(row)


@pytest.mark.parametrize("interrupted", [False, True])
def test_full_planned_denominator_survives_total_timeout_or_interrupt(
    tmp_path, monkeypatch, interrupted
):
    target = tmp_path / "report"
    if interrupted:

        def interrupt(*args):
            raise KeyboardInterrupt

        monkeypatch.setattr(evaluation, "measure", interrupt)
    else:
        monkeypatch.setattr(evaluation, "TOTAL_SECONDS", 0)

        def unexpected_spawn(*args, **kwargs):
            pytest.fail("No child may start after the total deadline")

        monkeypatch.setattr(evaluation.subprocess, "Popen", unexpected_spawn)
    assert evaluation.main(["--report-dir", str(target)]) == (130 if interrupted else 1)
    report = json.loads((target / "results.json").read_text())
    assert not report["measurement_checks_passed"]
    assert len(report["runs"]) == 36
    assert sum(row["expected_samples"] for row in report["summary"]) == 720
    assert sum(row["observed_samples"] for row in report["summary"]) == 0
    assert all(row["arun_ms"] is None for row in report["summary"])


@pytest.mark.parametrize("args", [[], ["--samples", "1000"], ["--worker", "99"], ["--worker", "0"]])
def test_cli_rejects_unbounded_or_incomplete_arguments(args):
    with pytest.raises(SystemExit) as error:
        evaluation.main(args)
    assert error.value.code == 2


def test_actual_cli_runs_all_cells_outside_checkout_and_refuses_overwrite(tmp_path):
    target = tmp_path / "report"
    environment = evaluation.limits.child_environment()
    environment["PRIVATE_TEST_VALUE"] = "private-environment-canary"
    command = [sys.executable, str(evaluation.HERE), "--smoke", "--report-dir", str(target)]
    completed = subprocess.run(
        command, cwd=tmp_path, env=environment, capture_output=True, timeout=60
    )
    assert completed.returncode == 0, completed.stderr.decode()
    path = target / "results.json"
    original = path.read_bytes()
    report = json.loads(original)
    assert report["measurement_checks_passed"]
    assert report["configuration"]["mode"] == "smoke"
    assert report["configuration"]["executor_workers"] == 4
    assert len(report["runs"]) == 12
    assert sum(row["matching_samples"] for row in report["summary"]) == 48
    for row in report["runs"]:
        assert row["status"] == "completed" and row["child_reaped"]
        assert row["max_active"] == row["cell"]["concurrency"]
        assert row["resources"]["process_cpu_ms"] > 0
        assert len(row["samples"]) == 4
        if os.name == "posix":
            assert row["limits"]["cpu_seconds"] is not None
            assert row["resources"]["peak_rss_bytes"] > 0
        if sys.platform == "win32":
            assert row["resources"]["peak_rss_bytes"] is None
    hashes = report["metadata"]["sha256"]
    for name in (
        "evaluation/concurrency/run.py",
        "evaluation/concurrency/fixtures_v1.json",
        "evaluation/measure_resources.py",
        "src/guardtrellis/guard.py",
        "uv.lock",
    ):
        assert len(hashes[name]) == 64
    assert all("\\" not in path and not Path(path).is_absolute() for path in hashes)
    for marker in (
        "private-environment-canary",
        str(evaluation.ROOT),
        str(tmp_path),
        "+1-202-555-0123",
        "fabricated-not-a-key",
        "request-0000",
        "receipt-0000",
    ):
        assert marker.encode() not in original
    rerun = subprocess.run(command, cwd=tmp_path, capture_output=True, timeout=10)
    assert rerun.returncode == 2 and path.read_bytes() == original


def test_fixture_labels_cannot_be_replaced_with_detector_generated_or_ambiguous_metadata(
    tmp_path, monkeypatch
):
    document = json.loads(evaluation.FIXTURES.read_text())
    changed = copy.deepcopy(document)
    changed["independent_review"] = True
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(changed), encoding="utf-8")
    monkeypatch.setattr(evaluation, "FIXTURES", path)
    with pytest.raises(ValueError, match="Invalid fixed fixtures"):
        evaluation.load_fixtures()
