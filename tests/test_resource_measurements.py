import json
import os
import subprocess
import sys

import pytest

from evaluation import measure_resources as measurements


@pytest.mark.parametrize(
    "case",
    [
        case
        for case in measurements.SCENARIOS
        if case.name not in {"reference_fanout_large", "supervisor_wall_timeout"}
    ],
    ids=lambda case: case.name,
)
def test_fixed_scenarios_complete_and_preserve_the_contract(case):
    row = measurements.run_case(case)
    assert row["status"] == "completed", row
    assert measurements.acceptable_measurement(row), row
    observation = row["observation"]
    assert observation["operation_ms"] >= 0
    assert row["resources"]["process_cpu_ms"] > 0
    if sys.platform.startswith("linux"):
        assert row["limits"]["address_space_bytes"] == 512 * 1024**2
    if os.name == "posix":
        assert row["limits"]["cpu_seconds"] == 2
        assert row["resources"]["peak_rss_bytes"] > 0
    if case.name == "text_over_limit":
        assert observation["finding_codes"] == ["text_limit_exceeded"]
    elif case.name == "pii_at_finding_limit":
        assert observation["finding_count"] == 256
    elif case.name == "pii_over_finding_limit":
        assert observation["finding_codes"] == ["finding_limit_exceeded"]
    elif case.kind == "json" and case.expected_action == "block":
        assert observation["finding_codes"] == ["json_too_deep"]
    elif case.name == "schema_at_size_limit":
        assert observation["dimensions"]["schema_chars"] == 100_000


@pytest.mark.parametrize("name", ["reference_fanout_large", "supervisor_wall_timeout"])
def test_expensive_or_stuck_workers_are_bounded_and_reaped(name):
    row = measurements.run_case(measurements.BY_NAME[name])
    assert measurements.acceptable_measurement(row), row
    assert row["child_reaped"]
    if row["status"] != "completed":
        assert "observation" not in row
        assert "resources" not in row
        assert row["contract_matches"] is None
    if name == "supervisor_wall_timeout":
        assert row["status"] == "wall_timeout"


def test_parent_interrupt_kills_and_reaps_the_actual_child(monkeypatch):
    real_popen = subprocess.Popen
    children = []

    def popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        real_wait = child.wait
        first_wait = True

        def wait(*args, **kwargs):
            nonlocal first_wait
            if first_wait:
                first_wait = False
                raise KeyboardInterrupt
            return real_wait(*args, **kwargs)

        monkeypatch.setattr(child, "wait", wait)
        return child

    monkeypatch.setattr(measurements.subprocess, "Popen", popen)
    with pytest.raises(KeyboardInterrupt):
        measurements.run_case(measurements.BY_NAME["supervisor_wall_timeout"])
    assert len(children) == 1
    assert children[0].poll() is not None


def test_child_environment_does_not_inherit_credentials_or_python_hooks(monkeypatch):
    for name in ("GEMINI_API_KEY", "OPENAI_API_KEY", "PYTHONPATH", "PYTHONSTARTUP", "HOME"):
        monkeypatch.setenv(name, "private-sentinel")
    env = measurements.child_environment()
    assert "private-sentinel" not in env.values()
    assert "HOME" not in env
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"


def test_worker_failure_reports_type_without_exception_payload(monkeypatch, capsys):
    monkeypatch.setattr(measurements, "apply_limits", lambda *args: {})

    def fail(_):
        raise RuntimeError("private-input-and-path-sentinel")

    monkeypatch.setattr(measurements, "measure_sync", fail)
    assert measurements.worker_main(measurements.BY_NAME["text_at_limit"], 2, 512) == 1
    captured = capsys.readouterr()
    assert "private-input-and-path-sentinel" not in captured.out + captured.err
    assert json.loads(captured.out.splitlines()[-1]) == {
        "event": "error",
        "error_type": "RuntimeError",
    }


def test_resource_cap_failure_cannot_be_reported_as_an_applied_limit(monkeypatch, capsys):
    def fail(*args):
        raise OSError("private-sentinel")

    monkeypatch.setattr(measurements, "apply_limits", fail)
    assert measurements.worker_main(measurements.BY_NAME["text_at_limit"], 2, 512) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"event": "error", "error_type": "OSError"}
    assert captured.err == ""


@pytest.mark.parametrize(
    "args",
    [
        ["--repetitions", "0"],
        ["--repetitions", "6"],
        ["--wall-seconds", "nan"],
        ["--wall-seconds", "inf"],
        ["--wall-seconds", "0"],
        ["--wall-seconds", "31"],
        ["--cpu-seconds", "0"],
        ["--cpu-seconds", "6"],
        ["--memory-mib", "128"],
        ["--memory-mib", "2048"],
    ],
)
def test_cli_rejects_unbounded_or_excessive_budgets(args):
    with pytest.raises(SystemExit) as exc:
        measurements.main(args)
    assert exc.value.code == 2


def test_reports_keep_stopped_samples_unknown_and_refuse_to_overwrite(tmp_path):
    directory = tmp_path / "report"
    process = subprocess.run(
        [
            sys.executable,
            str(measurements.HERE),
            "--report-dir",
            str(directory),
            "--repetitions",
            "1",
            "--case",
            "text_at_limit",
            "--case",
            "supervisor_wall_timeout",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    assert process.stderr == ""
    result_path = directory / "results.json"
    original = result_path.read_bytes()
    report = json.loads(original)
    assert report["measurement_checks_passed"]
    assert len(report["cases"]) == 2
    assert report["cases"][1]["status"] == "wall_timeout"
    assert "wall_timeout | unknown" in (directory / "REPORT.md").read_text()
    assert len(report["metadata"]["runner_sha256"]) == 64
    with pytest.raises(SystemExit) as exc:
        measurements.main(["--report-dir", str(directory)])
    assert exc.value.code == 2
    assert result_path.read_bytes() == original


def test_interruption_retains_completed_samples_and_returns_nonzero(tmp_path, monkeypatch):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(measurements, "run_case", interrupt)
    assert measurements.main(["--report-dir", str(tmp_path)]) == 130
    report = json.loads((tmp_path / "results.json").read_text())
    assert report["interrupted"]
    assert not report["measurement_checks_passed"]
    assert report["cases"] == []


def test_unexpected_failure_is_not_accepted_as_a_successful_measurement():
    row = {
        "scenario": {"name": "text_at_limit", "kind": "text"},
        "status": "wall_timeout",
        "child_reaped": True,
        "stderr_bytes": 0,
        "limits": {"cpu_seconds": 2},
        "contract_matches": None,
    }
    assert not measurements.acceptable_measurement(row)
    row["scenario"]["name"] = "reference_fanout_large"
    assert not measurements.acceptable_measurement(row)
    row["prepared"] = {"dimensions": {"input_chars": 1}}
    assert measurements.acceptable_measurement(row)
    row["stderr_bytes"] = 1
    assert not measurements.acceptable_measurement(row)
