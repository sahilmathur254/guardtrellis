"""Frozen sync scan contracts, metadata privacy and disposable-worker containment."""

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from evaluation.scan_performance import run as evaluation
from guardtrellis import Action, Finding, Rejected, Result, Stage, Trace


def authored_result(case, cell):
    """Build the frozen expected contract without asking a detector for its labels."""
    _text, checked, spans = evaluation.represented(case, cell)
    expected = case["expected_by_profile"][cell["profile"]]
    action = Action(expected["action"])
    findings = tuple(
        Finding(
            code=code,
            start=start,
            end=end,
            scanner="pii" if code == "pii_phone" else "secrets",
            scanner_index=1 if code == "pii_phone" else 0,
            revision=0,
        )
        for code, (start, end) in zip(expected["codes"], spans, strict=True)
    )
    trace = [Trace("secrets", 0, Action.BLOCK if action == Action.BLOCK else Action.ALLOW, 0, 0)]
    if action != Action.BLOCK:
        trace.append(Trace("pii", 1, action, 0, int(action == Action.REDACT)))
    return Result(action, Stage.RETRIEVAL, checked, findings, tuple(trace))


class SurfaceResult:
    """Change one public result surface while preserving the remaining authored contract."""

    def __init__(self, base, *, accessor=None, diagnostics=None, representation=None):
        self.base = base
        self.accessor = accessor
        self.report = diagnostics
        self.representation = representation

    def __getattr__(self, name):
        return getattr(self.base, name)

    def __repr__(self):
        return repr(self.base) if self.representation is None else self.representation()

    def require_text(self):
        return self.base.require_text() if self.accessor is None else self.accessor()

    def diagnostics(self):
        return self.base.diagnostics() if self.report is None else self.report()


def test_frozen_inputs_project_to_the_exact_22_ordered_cells():
    fixtures = evaluation.load_fixtures()
    assert tuple(fixtures) == ("allow", "redact", "block", "uri_positive", "uri_benign")
    assert evaluation.CELLS == tuple(
        {"group": "main", "profile": profile, "case": case, "input_chars": size}
        for profile in ("default", "opt_in")
        for size in (1_000, 10_000, 100_000)
        for case in ("allow", "redact", "block")
    ) + tuple(
        {"group": "uri_supplement", "profile": profile, "case": case, "input_chars": 1_000}
        for profile in ("default", "opt_in")
        for case in ("uri_positive", "uri_benign")
    )
    assert len(evaluation.CELLS) == 22
    assert evaluation.WARMUPS == 3
    for cell in evaluation.CELLS:
        case = fixtures[cell["case"]]
        text, checked, spans = evaluation.represented(case, cell)
        expected = case["expected_by_profile"][cell["profile"]]
        padding = "." * (cell["input_chars"] - len(case["payload"]))
        assert len(text) == cell["input_chars"]
        assert text == padding + case["payload"]
        assert evaluation.represented(case, cell) == (text, checked, spans)
        assert spans == [
            [len(padding) + start, len(padding) + end] for start, end in expected["spans"]
        ]
        if checked is None:
            assert expected["action"] == "block"
        else:
            assert checked == padding + expected["checked_payload"]
            if expected["action"] == "redact":
                assert len(checked) == len(text) - 7
            else:
                assert checked == text
    assert fixtures["redact"]["expected_by_profile"]["default"]["spans"] == [[9, 21]]
    assert fixtures["block"]["expected_by_profile"]["default"]["spans"] == [[7, 47]]
    assert fixtures["uri_positive"]["expected_by_profile"]["opt_in"]["spans"] == [[12, 63]]


@pytest.mark.parametrize("asset", ["FIXTURES", "PROTOCOL", "FREEZE"])
def test_pre_observation_freeze_rejects_changed_asset_bytes(tmp_path, monkeypatch, asset):
    original = getattr(evaluation, asset)
    changed = tmp_path / original.name
    changed.write_bytes(original.read_bytes() + b"\n")
    monkeypatch.setattr(evaluation, asset, changed)
    with pytest.raises(
        ValueError, match="Invalid pre-observation freeze|Frozen expectations changed"
    ):
        evaluation.load_fixtures()


@pytest.mark.parametrize("cell", evaluation.CELLS)
def test_every_cell_has_exact_action_spans_diagnostics_and_checked_delivery(cell):
    fixtures = evaluation.load_fixtures()
    case = fixtures[cell["case"]]
    text, checked, _spans = evaluation.represented(case, cell)
    expected = authored_result(case, cell)
    actual = evaluation.policy(cell["profile"]).scan(text, stage=Stage.RETRIEVAL)
    assert actual == expected
    assert actual.diagnostics() == expected.diagnostics()
    delivered = []
    if checked is None:
        assert not actual.accepted and actual.text is None
        with pytest.raises(Rejected):
            delivered.append(actual.require_text())
        assert delivered == []
    else:
        delivered.append(actual.require_text())
        assert delivered == [checked]
    row = evaluation.observe(lambda _text, *, stage: actual, case, cell, 0)
    assert evaluation.sample_matches(row, cell, fixtures)
    assert row["scan_ms"] >= 0
    assert row["diagnostics_match"] and row["privacy_ok"]
    assert case["payload"] not in json.dumps(row)


@pytest.mark.parametrize("field", ["start", "end", "revision", "scanner", "scanner_index"])
def test_same_finding_code_with_corrupt_provenance_or_span_is_a_failed_sample(field):
    fixtures = evaluation.load_fixtures()
    cell = evaluation.CELLS[1]
    case = fixtures[cell["case"]]
    result = authored_result(case, cell)
    finding = result.findings[0]
    replacement = {
        "start": finding.start + 1,
        "end": finding.end - 1,
        "revision": 1,
        "scanner": "private-scanner-canary",
        "scanner_index": 0,
    }[field]
    result = replace(result, findings=(replace(finding, **{field: replacement}),))
    row = evaluation.observe(lambda _text, *, stage: result, case, cell, 0)
    assert not row["findings_match"] and not row["diagnostics_match"]
    assert not evaluation.sample_matches(row, cell, fixtures)
    assert "private-scanner-canary" not in json.dumps(row)


@pytest.mark.parametrize("field,value", [("revision", False), ("scanner_index", True)])
def test_boolean_finding_metadata_is_not_equal_to_integer_provenance(field, value):
    fixtures = evaluation.load_fixtures()
    cell = evaluation.CELLS[1]
    case = fixtures[cell["case"]]
    base = authored_result(case, cell)
    changed = replace(base, findings=(replace(base.findings[0], **{field: value}),))
    row = evaluation.observe(lambda _text, *, stage: changed, case, cell, 0)
    assert not row["findings_match"] and not row["diagnostics_match"]
    assert not evaluation.sample_matches(row, cell, fixtures)


@pytest.mark.parametrize(
    "trace_index,field,value",
    [
        (0, "revision_before", False),
        (0, "revision_after", False),
        (1, "revision_before", False),
        (1, "revision_after", True),
        (0, "scanner_index", False),
        (1, "scanner_index", True),
    ],
)
def test_boolean_diagnostic_trace_metadata_cannot_impersonate_integer_fields(
    trace_index, field, value
):
    fixtures = evaluation.load_fixtures()
    cell = evaluation.CELLS[1]
    case = fixtures[cell["case"]]
    base = authored_result(case, cell)
    diagnostics = base.diagnostics()
    diagnostics["trace"][trace_index][field] = value
    changed = SurfaceResult(base, diagnostics=lambda: diagnostics)
    row = evaluation.observe(lambda _text, *, stage: changed, case, cell, 0)
    assert row["findings_match"] and not row["diagnostics_match"]
    assert not evaluation.sample_matches(row, cell, fixtures)


@pytest.mark.parametrize(
    "corruption",
    [
        "stage",
        "text",
        "duplicate_finding",
        "accepted_accessor_rejects",
        "rejected_accessor_returns",
        "rejected_accessor_wrong_exception",
        "diagnostics_payload",
        "diagnostics_exception",
        "representation_payload",
        "scan_exception",
        "scan_private_exception",
    ],
)
def test_corrupt_result_surfaces_fail_without_persisting_private_values(corruption):
    fixtures = evaluation.load_fixtures()
    cell = evaluation.CELLS[2 if corruption.startswith("rejected_") else 1]
    case = fixtures[cell["case"]]
    base = authored_result(case, cell)
    result = base
    canary = case["payload"]

    def rejected():
        raise Rejected(canary)

    def failed():
        raise ValueError(canary)

    if corruption == "stage":
        result = replace(base, stage=Stage.INPUT)
    elif corruption == "text":
        result = replace(base, text="private-checked-canary")
    elif corruption == "duplicate_finding":
        result = replace(base, findings=base.findings * 2)
    elif corruption == "accepted_accessor_rejects":
        result = SurfaceResult(base, accessor=rejected)
    elif corruption == "rejected_accessor_returns":
        result = SurfaceResult(base, accessor=lambda: canary)
    elif corruption == "rejected_accessor_wrong_exception":
        result = SurfaceResult(base, accessor=failed)
    elif corruption == "diagnostics_payload":
        result = SurfaceResult(base, diagnostics=lambda: {**base.diagnostics(), "payload": canary})
    elif corruption == "diagnostics_exception":
        result = SurfaceResult(base, diagnostics=failed)
    elif corruption == "representation_payload":
        result = SurfaceResult(base, representation=lambda: canary)

    def scan(_text, *, stage):
        if corruption == "scan_exception":
            raise ValueError("private-exception-canary")
        if corruption == "scan_private_exception":
            start, end = case["expected_by_profile"][cell["profile"]]["spans"][0]
            raise ValueError(case["payload"][start:end])
        return result

    row = evaluation.observe(scan, case, cell, 0)
    assert not evaluation.sample_matches(row, cell, fixtures)
    if corruption in (
        "diagnostics_payload",
        "representation_payload",
        "accepted_accessor_rejects",
        "scan_private_exception",
    ):
        assert not row["privacy_ok"]
    rendered = json.dumps(row)
    for marker in (canary, "private-checked-canary", "private-exception-canary"):
        assert marker not in rendered


@pytest.mark.parametrize("raises", [False, True])
def test_scan_timer_excludes_construction_delivery_diagnostics_and_representation(
    monkeypatch, raises
):
    fixtures = evaluation.load_fixtures()
    cell = evaluation.CELLS[1]
    case = fixtures[cell["case"]]
    base = authored_result(case, cell)
    original_represented = evaluation.represented
    current = 0
    clock_calls = []
    events = []

    def advance(event, duration):
        nonlocal current
        events.append(event)
        current += duration

    def clock():
        clock_calls.append(current)
        return current

    def represented(*args):
        advance("construction", 3_000_000)
        return original_represented(*args)

    def deliver():
        advance("delivery", 11_000_000)
        return base.require_text()

    def diagnostics():
        advance("diagnostics", 13_000_000)
        return base.diagnostics()

    def representation():
        advance("representation", 17_000_000)
        return repr(base)

    result = SurfaceResult(
        base, accessor=deliver, diagnostics=diagnostics, representation=representation
    )

    def scan(text, *, stage):
        assert text.endswith(case["payload"]) and stage == Stage.RETRIEVAL
        advance("scan", 7_000_000)
        if raises:
            raise ValueError("private-timed-exception-canary")
        return result

    monkeypatch.setattr(evaluation, "represented", represented)
    row = evaluation.observe(scan, case, cell, 0, clock=clock)
    assert clock_calls == [3_000_000, 10_000_000]
    assert row["scan_ms"] == 7.0
    assert events[:2] == ["construction", "scan"]
    assert row["error"] is raises
    if raises:
        assert events == ["construction", "scan"]
    else:
        assert events[2:] == ["delivery", "diagnostics", "representation"]
        assert evaluation.sample_matches(row, cell, fixtures)
    assert "private-timed-exception-canary" not in json.dumps(row)


def protocol_events(count=4):
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
                "scan_ms": 1.0,
                "action": "allow",
                "accepted": True,
                "stage_matches": True,
                "findings_match": True,
                "diagnostics_match": True,
                "text_matches": True,
                "delivery_matches": True,
                "privacy_ok": True,
                "error": False,
            }
            for index in range(count)
        ],
        {"event": "finished", "resources": {"process_cpu_ms": 4.0, "peak_rss_bytes": None}},
    ]


def encoded(events):
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


def test_complete_ordered_protocol_accepts_only_the_expected_samples():
    fixtures = evaluation.load_fixtures()
    row = evaluation.read_protocol(encoded(protocol_events()), evaluation.CELLS[0], 4, fixtures)
    assert row["finished"] and not row["protocol_error"] and not row["worker_error"]
    assert [sample["index"] for sample in row["samples"]] == list(range(4))
    assert all(sample["contract_matches"] for sample in row["samples"])


def test_valid_error_and_contract_mismatch_samples_keep_their_individual_timings():
    fixtures = evaluation.load_fixtures()
    events = protocol_events()
    events[3]["findings_match"] = False
    events[4].update(action="error", accepted=False, error=True, scan_ms=2.5)
    row = evaluation.read_protocol(encoded(events), evaluation.CELLS[0], 4, fixtures)
    assert row["finished"] and not row["protocol_error"]
    assert len(row["samples"]) == 4
    assert [sample["scan_ms"] for sample in row["samples"]] == [1.0, 2.5, 1.0, 1.0]
    assert [sample["contract_matches"] for sample in row["samples"]] == [False, False, True, True]


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_payload",
        "bad_action",
        "nan",
        "bool_time",
        "bool_index",
        "bad_bool",
        "duplicate_index",
        "out_of_order_index",
        "negative_index",
        "bad_limits",
        "bad_resources",
        "missing_sample",
        "wrong_phase",
        "event_after_end",
    ],
)
def test_protocol_corruption_preserves_only_valid_prefix_and_never_copies_unknown_values(mutation):
    fixtures = evaluation.load_fixtures()
    events = protocol_events()
    if mutation == "extra_payload":
        events[4]["payload"] = "private-protocol-canary"
    elif mutation == "bad_action":
        events[4]["action"] = "private-protocol-canary"
    elif mutation == "nan":
        events[4]["scan_ms"] = float("nan")
    elif mutation == "bool_time":
        events[4]["scan_ms"] = True
    elif mutation == "bool_index":
        events[4]["index"] = True
    elif mutation == "bad_bool":
        events[4]["accepted"] = 1
    elif mutation == "duplicate_index":
        events[4]["index"] = 0
    elif mutation == "out_of_order_index":
        events[4]["index"] = 2
    elif mutation == "negative_index":
        events[4]["index"] = -1
    elif mutation == "bad_limits":
        events[0]["limits"]["cpu_seconds"] = True
    elif mutation == "bad_resources":
        events[-1]["resources"]["private"] = "private-protocol-canary"
    elif mutation == "missing_sample":
        events.pop(4)
    elif mutation == "wrong_phase":
        events[1], events[2] = events[2], events[1]
    else:
        events.append({"event": "error"})
    row = evaluation.read_protocol(encoded(events), evaluation.CELLS[0], 4, fixtures)
    assert row["protocol_error"]
    assert "private-protocol-canary" not in json.dumps(row)
    if mutation in (
        "extra_payload",
        "bad_action",
        "nan",
        "bool_time",
        "bool_index",
        "bad_bool",
        "duplicate_index",
        "out_of_order_index",
        "negative_index",
        "missing_sample",
    ):
        assert [sample["index"] for sample in row["samples"]] == [0]


@pytest.mark.parametrize(
    "suffix",
    [
        b'{"event":"sample","event":"private-protocol-canary"}\n',
        b'{"event":"sample","index":1,"index":2}\n',
        b'{"event":"sample",',
        b"\xff\n",
        b'{"event":"error"}\n{"event":"error"}\n',
    ],
)
def test_duplicate_truncated_invalid_or_repeated_error_events_preserve_prefix(suffix):
    fixtures = evaluation.load_fixtures()
    row = evaluation.read_protocol(
        encoded(protocol_events()[:4]) + suffix, evaluation.CELLS[0], 4, fixtures
    )
    assert row["protocol_error"] and not row["finished"]
    assert [sample["index"] for sample in row["samples"]] == [0]
    assert "private-protocol-canary" not in json.dumps(row)


def test_missing_events_and_worker_error_remain_incomplete_with_retained_samples():
    fixtures = evaluation.load_fixtures()
    prefix = encoded(protocol_events()[:4])
    for suffix, worker_error in ((b"", False), (b'{"event":"error"}\n', True)):
        row = evaluation.read_protocol(prefix + suffix, evaluation.CELLS[0], 4, fixtures)
        assert not row["finished"] and not row["protocol_error"]
        assert row["worker_error"] is worker_error
        assert [sample["index"] for sample in row["samples"]] == [0]


def test_windows_launch_uses_base_interpreter_and_sanitized_venv_environment(monkeypatch):
    monkeypatch.setenv("GUARDTRELLIS_TEST_SECRET", "private-environment-canary")
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


def test_unavailable_resource_module_keeps_windows_caps_and_rss_null(monkeypatch):
    import builtins

    original_import = builtins.__import__

    def without_resource(name, *args, **kwargs):
        if name == "resource":
            raise ImportError("resource unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(evaluation.sys, "platform", "win32")
    monkeypatch.setattr(builtins, "__import__", without_resource)
    assert evaluation.limits.apply_limits(2, 512) == {
        "cpu_seconds": None,
        "address_space_bytes": None,
        "core_bytes": None,
        "output_file_bytes": None,
    }
    usage = evaluation.limits.resource_usage()
    assert usage["process_cpu_ms"] >= 0 and usage["peak_rss_bytes"] is None


@pytest.mark.parametrize("interrupted", [False, True])
def test_stuck_child_is_reaped_before_temporary_directory_removal(
    tmp_path, monkeypatch, interrupted
):
    worker = tmp_path / "stuck.py"
    worker.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    real_popen = subprocess.Popen
    real_directory = evaluation.tempfile.TemporaryDirectory
    children = []
    checked_removal = []

    class CheckedDirectory:
        def __init__(self, *args, **kwargs):
            self.directory = real_directory(*args, **kwargs)

        def __enter__(self):
            return self.directory.__enter__()

        def __exit__(self, *args):
            assert children and all(process.poll() is not None for process, _path in children)
            checked_removal.append(True)
            return self.directory.__exit__(*args)

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
    monkeypatch.setattr(evaluation, "WALL_SECONDS", 0.1)
    monkeypatch.setattr(evaluation.subprocess, "Popen", popen)
    monkeypatch.setattr(evaluation.tempfile, "TemporaryDirectory", CheckedDirectory)
    try:
        row = evaluation.measure(
            0, 4, 0, time.perf_counter() + 5, evaluation.load_fixtures(), [False]
        )
        exited_before_cleanup = children[0][0].poll() is not None
    finally:
        for process, _directory in children:
            evaluation.limits.kill_and_reap(process)
    assert row["status"] == ("interrupted" if interrupted else "wall_timeout")
    assert row["child_reaped"] and exited_before_cleanup and checked_removal == [True]
    assert not row["contract_matches"] and row["samples"] == []
    assert "resources" not in row and not children[0][1].exists()


def test_cleanup_error_after_reaping_retains_valid_prefix_before_temporary_directory_removal(
    tmp_path, monkeypatch
):
    prefix = encoded(protocol_events()[:4])
    worker = tmp_path / "cleanup_error.py"
    worker.write_text(
        f"import sys, time\nsys.stdout.buffer.write({prefix!r})\n"
        "sys.stdout.buffer.flush()\ntime.sleep(60)\n",
        encoding="utf-8",
    )
    real_popen = subprocess.Popen
    real_cleanup = evaluation.limits.kill_and_reap
    real_protocol = evaluation.read_protocol
    real_directory = evaluation.tempfile.TemporaryDirectory
    children = []
    boundaries = []

    class CheckedDirectory:
        def __init__(self, *args, **kwargs):
            self.directory = real_directory(*args, **kwargs)

        def __enter__(self):
            return self.directory.__enter__()

        def __exit__(self, *args):
            assert children and children[0][0].poll() is not None
            boundaries.append("removed")
            return self.directory.__exit__(*args)

    def popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        children.append((process, Path(kwargs["cwd"])))
        deadline = time.perf_counter() + 5
        while os.fstat(kwargs["stdout"].fileno()).st_size < len(prefix):
            assert process.poll() is None and time.perf_counter() < deadline
            time.sleep(0.01)
        return process

    def cleanup(process):
        real_cleanup(process)
        boundaries.append("reaped")
        raise subprocess.TimeoutExpired("private-cleanup-canary", 5, output="private-output-canary")

    def read_protocol(*args):
        parsed = real_protocol(*args)
        boundaries.append("parsed")
        return parsed

    monkeypatch.setattr(evaluation, "HERE", worker)
    monkeypatch.setattr(evaluation, "WALL_SECONDS", 0.1)
    monkeypatch.setattr(evaluation.subprocess, "Popen", popen)
    monkeypatch.setattr(evaluation.limits, "kill_and_reap", cleanup)
    monkeypatch.setattr(evaluation, "read_protocol", read_protocol)
    monkeypatch.setattr(evaluation.tempfile, "TemporaryDirectory", CheckedDirectory)
    try:
        row = evaluation.measure(
            0, 4, 0, time.perf_counter() + 5, evaluation.load_fixtures(), [False]
        )
        exited_before_cleanup = children[0][0].poll() is not None
    finally:
        for process, _directory in children:
            real_cleanup(process)
    assert row["status"] == "cleanup_error" and row["child_reaped"]
    assert exited_before_cleanup and not children[0][1].exists()
    assert not row["contract_matches"] and not row["protocol_error"]
    assert [sample["index"] for sample in row["samples"]] == [0]
    assert row["samples"][0]["contract_matches"] and row["expected_samples"] == 4
    assert boundaries == ["reaped", "parsed", "removed"]
    assert "private-cleanup-canary" not in json.dumps(row)
    assert "private-output-canary" not in json.dumps(row)


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize(
    "boundary", ["before_kill", "during_reap", "after_protocol", "report_write"]
)
def test_signals_preserve_prefix_and_save_partial_report_after_reaping(
    tmp_path, monkeypatch, signum, boundary
):
    prefix = encoded(protocol_events()[:4])
    worker = tmp_path / "partial.py"
    worker.write_text(
        f"import sys, time\nsys.stdout.buffer.write({prefix!r})\n"
        "sys.stdout.buffer.flush()\ntime.sleep(60)\n",
        encoding="utf-8",
    )
    target = tmp_path / "report"
    real_popen = subprocess.Popen
    real_cleanup = evaluation.limits.kill_and_reap
    real_protocol = evaluation.read_protocol
    real_measure = evaluation.measure
    real_write = Path.write_text
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

    def read_protocol(*args):
        row = real_protocol(*args)
        if boundary == "after_protocol":
            send_signal()
        return row

    def write_text(path, *args, **kwargs):
        written = real_write(path, *args, **kwargs)
        if boundary == "report_write" and path == target / "results.json":
            send_signal()
        return written

    def inherited_handler(_signum, _frame):
        raise KeyboardInterrupt

    def first_child_only(index, count, repeat, deadline, fixtures, interruption):
        if index == 0:
            return real_measure(index, count, repeat, deadline, fixtures, interruption)
        return {
            "cell": evaluation.CELLS[index],
            "repeat": repeat,
            "status": "not_started",
            "samples": [],
            "expected_samples": count,
            "child_reaped": None,
        }

    previous = {item: signal.getsignal(item) for item in (signal.SIGINT, signal.SIGTERM)}
    monkeypatch.setattr(evaluation, "HERE", worker)
    monkeypatch.setattr(evaluation, "WALL_SECONDS", 0.1)
    monkeypatch.setattr(evaluation, "metadata", lambda: {"source_version": "test-runtime"})
    monkeypatch.setattr(evaluation.subprocess, "Popen", popen)
    monkeypatch.setattr(evaluation.limits, "kill_and_reap", cleanup)
    monkeypatch.setattr(evaluation, "read_protocol", read_protocol)
    monkeypatch.setattr(Path, "write_text", write_text)
    if boundary == "report_write":
        monkeypatch.setattr(evaluation, "measure", first_child_only)
    try:
        for item in previous:
            signal.signal(item, inherited_handler)
        assert evaluation.main(["--smoke", "--report-dir", str(target)]) == 130
        restored = all(signal.getsignal(item) is inherited_handler for item in previous)
        exited_before_cleanup = children[0][0].poll() is not None
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)
        for process, _directory in children:
            real_cleanup(process)
    report = json.loads((target / "results.json").read_text())
    assert emitted and restored and exited_before_cleanup
    assert report["interrupted"] and not report["measurement_checks_passed"]
    assert len(report["runs"]) == 22
    assert sum(row["expected_samples"] for row in report["summary"]) == 88
    samples = [sample for row in report["runs"] for sample in row["samples"]]
    assert len(samples) == 1 and samples[0]["index"] == 0 and samples[0]["contract_matches"]
    assert report["runs"][0]["child_reaped"]
    assert not children[0][1].exists() and len(children) == 1
    assert "Measurement checks passed: `False`" in (target / "REPORT.md").read_text()


@pytest.mark.parametrize("stop", ["deadline", "signal", "keyboard_interrupt"])
def test_full_planned_denominator_survives_total_deadline_or_interrupt(tmp_path, monkeypatch, stop):
    target = tmp_path / "report"
    interrupted = stop != "deadline"
    monkeypatch.setattr(evaluation, "metadata", lambda: {"source_version": "test-runtime"})

    def unexpected_spawn(*args, **kwargs):
        pytest.fail("No child may start after the total deadline or interruption")

    monkeypatch.setattr(evaluation.subprocess, "Popen", unexpected_spawn)
    if interrupted:

        def measure(index, count, repeat, deadline, fixtures, interruption):
            if stop == "keyboard_interrupt":
                raise KeyboardInterrupt
            signal.raise_signal(signal.SIGINT)
            return {
                "cell": evaluation.CELLS[index],
                "repeat": repeat,
                "status": "interrupted",
                "samples": [],
                "expected_samples": count,
                "child_reaped": None,
                "contract_matches": False,
            }

        monkeypatch.setattr(evaluation, "measure", measure)
    else:
        monkeypatch.setattr(evaluation, "TOTAL_SECONDS", 0)
    assert evaluation.main(["--report-dir", str(target)]) == (130 if interrupted else 1)
    report = json.loads((target / "results.json").read_text())
    assert not report["measurement_checks_passed"]
    assert report["interrupted"] is interrupted
    assert len(report["runs"]) == 66 and len(report["summary"]) == 22
    assert sum(row["expected_samples"] for row in report["summary"]) == 6_600
    assert sum(row["observed_samples"] for row in report["summary"]) == 0
    assert all(row["scan_ms"] is None for row in report["summary"])
    assert sum(row["expected_samples"] for row in report["summary"][:18]) == 5_400
    assert sum(row["expected_samples"] for row in report["summary"][18:]) == 1_200


@pytest.mark.parametrize("kind", ["worker_error", "stdout", "stderr"])
def test_worker_failure_and_oversize_output_never_copy_private_content(tmp_path, monkeypatch, kind):
    worker = tmp_path / "failure.py"
    prefix = encoded(protocol_events()[:4])
    prefix_source = f"import sys\nsys.stdout.buffer.write({prefix!r})\nsys.stdout.buffer.flush()\n"
    if kind == "worker_error":
        source = prefix_source + (
            'print(\'{"event":"error"}\')\n'
            "print('private-worker-canary', file=sys.stderr)\nraise SystemExit(1)\n"
        )
    else:
        destination = ", file=sys.stderr" if kind == "stderr" else ""
        source = prefix_source + f"print('private-worker-canary' * 6000{destination})\n"
    worker.write_text(source, encoding="utf-8")
    monkeypatch.setattr(evaluation, "HERE", worker)
    row = evaluation.measure(0, 4, 0, time.perf_counter() + 5, evaluation.load_fixtures(), [False])
    assert row["status"] == ("worker_error" if kind == "worker_error" else "output_limit")
    assert row["child_reaped"] and not row["contract_matches"]
    assert [sample["index"] for sample in row["samples"]] == [0]
    assert row["samples"][0]["contract_matches"] and row["expected_samples"] == 4
    assert "private-worker-canary" not in json.dumps(row)


@pytest.mark.parametrize(
    "args",
    [[], ["--samples", "1000"], ["--worker", "22"], ["--worker", "0"], ["--samples", "4"]],
)
def test_cli_rejects_unbounded_or_incomplete_arguments(args):
    with pytest.raises(SystemExit) as error:
        evaluation.main(args)
    assert error.value.code == 2


def test_existing_directory_is_refused_before_preparation_or_child_start(tmp_path, monkeypatch):
    target = tmp_path / "report"
    target.mkdir()
    marker = target / "prior-evidence.txt"
    marker.write_text("retain this evidence", encoding="utf-8")

    def unexpected_prepare():
        pytest.fail("Existing evidence must be rejected before preparation")

    monkeypatch.setattr(evaluation, "load_fixtures", unexpected_prepare)
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--smoke", "--report-dir", str(target)])
    assert error.value.code == 2
    assert list(target.iterdir()) == [marker]
    assert marker.read_text() == "retain this evidence"


def test_actual_cli_runs_all_smoke_cells_outside_checkout_and_preserves_existing_report(tmp_path):
    target = tmp_path / "report"
    environment = evaluation.limits.child_environment()
    environment["PRIVATE_TEST_VALUE"] = "private-environment-canary"
    command = [sys.executable, str(evaluation.HERE), "--smoke", "--report-dir", str(target)]
    completed = subprocess.run(
        command, cwd=tmp_path, env=environment, capture_output=True, timeout=120
    )
    assert completed.returncode == 0, completed.stderr.decode()
    path = target / "results.json"
    original = path.read_bytes()
    markdown = (target / "REPORT.md").read_bytes()
    report = json.loads(original)
    assert report["measurement_checks_passed"] and not report["interrupted"]
    assert report["configuration"]["mode"] == "smoke"
    assert report["configuration"]["samples_per_cell"] == 4
    assert report["configuration"]["repetitions"] == 1
    assert report["configuration"]["warmups_per_child"] == 3
    assert [row["cell"] for row in report["runs"]] == list(evaluation.CELLS)
    assert sum(row["matching_samples"] for row in report["summary"][:18]) == 72
    assert sum(row["matching_samples"] for row in report["summary"][18:]) == 16
    for row in report["runs"]:
        assert row["status"] == "completed" and row["child_reaped"]
        assert row["warmup_matches"] and len(row["samples"]) == 4
        assert all(sample["contract_matches"] for sample in row["samples"])
        assert [sample["index"] for sample in row["samples"]] == list(range(4))
        assert row["resources"]["process_cpu_ms"] > 0
        if os.name == "posix":
            assert row["limits"]["cpu_seconds"] is not None
            assert row["resources"]["peak_rss_bytes"] > 0
        if sys.platform == "win32":
            assert all(value is None for value in row["limits"].values())
            assert row["resources"]["peak_rss_bytes"] is None
    assert report["metadata"]["freeze_sha256"] == evaluation.FREEZE_SHA256
    assert report["metadata"]["freeze_receipt"] == evaluation.RECEIPT
    hashes = report["metadata"]["sha256"]
    for name in (
        "evaluation/scan_performance/run.py",
        "evaluation/scan_performance/fixtures_v1.json",
        "evaluation/scan_performance/PROTOCOL_v1.md",
        "evaluation/scan_performance/freeze_v1.json",
        "evaluation/measure_resources.py",
        "src/guardtrellis/guard.py",
        "uv.lock",
    ):
        assert len(hashes[name]) == 64
    assert all("\\" not in name and not Path(name).is_absolute() for name in hashes)
    combined = original + markdown
    markers = [
        "private-environment-canary",
        str(evaluation.ROOT),
        str(tmp_path),
        "+12025550123",
        "ghp_" + "A" * 36,
        "synthetic-password",
    ]
    markers.extend(case["payload"] for case in evaluation.load_fixtures().values())
    assert all(marker.encode() not in combined for marker in markers)
    rerun = subprocess.run(command, cwd=tmp_path, capture_output=True, timeout=10)
    assert rerun.returncode == 2
    assert path.read_bytes() == original and (target / "REPORT.md").read_bytes() == markdown
