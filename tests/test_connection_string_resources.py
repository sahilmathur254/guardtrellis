"""Fixed resource expectations, safe child protocols, and cross-platform cleanup."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from evaluation.connection_strings import resources


def payload(mode="direct"):
    return {
        "limits": {
            "cpu_seconds": None,
            "address_space_bytes": None,
            "core_bytes": None,
            "output_file_bytes": None,
        },
        "resources": {"process_cpu_ms": 1.0, "peak_rss_bytes": None},
        "rows": [
            {
                "scenario": name,
                "input_chars": len(text),
                "operation_ms": 0.1,
                "expected_action": action,
                "action": action,
                "accepted": action == "allow",
                "has_deliverable_text": None if mode == "direct" else action == "allow",
                "finding_count": count,
                "finding_codes": codes,
                "error_spanless": True,
            }
            for name, text, action, count, codes in resources.scenarios(mode)
        ],
    }


def stub_process(monkeypatch, observed, *, timeout=False, stderr=b"", raw=None):
    class Process:
        returncode = 0
        calls = 0

        def __init__(self, args, **kwargs):
            kwargs["stdout"].write(json.dumps(observed).encode() if raw is None else raw)
            kwargs["stdout"].flush()
            kwargs["stderr"].write(stderr)
            kwargs["stderr"].flush()

        def wait(self, timeout):
            self.calls += 1
            if timeout and self.calls == 1 and timed_out:
                raise subprocess.TimeoutExpired("fixed worker", timeout)
            return self.returncode

        def poll(self):
            return self.returncode

    timed_out = timeout
    monkeypatch.setattr(resources.subprocess, "Popen", Process)


@pytest.mark.parametrize("mode", resources.MODES)
def test_real_fixed_resource_protocol_is_bounded_and_reaps_its_child(mode, monkeypatch):
    real_popen = subprocess.Popen
    children = []

    def popen(args, **kwargs):
        child = real_popen(args, **kwargs)
        children.append((child, Path(kwargs["cwd"]), args[0], kwargs["env"]))
        return child

    monkeypatch.setattr(resources.subprocess, "Popen", popen)
    observed = resources.measure(mode)
    assert observed["status"] == "completed", observed
    assert observed["contract_matches"]
    assert observed["child_reaped"] and observed["stderr_bytes"] == 0
    assert observed["wall_budget_seconds"] == 10
    assert len(observed["rows"]) == 18
    assert all(row["error_spanless"] for row in observed["rows"])
    child, directory, executable, environment = children[0]
    assert child.poll() is not None and not directory.exists()
    assert executable == (sys._base_executable if sys.platform == "win32" else sys.executable)
    if sys.platform == "win32":
        assert environment["__PYVENV_LAUNCHER__"] == sys.executable
        assert all(value is None for value in observed["limits"].values())
        assert observed["resources"]["peak_rss_bytes"] is None
    serialized = json.dumps(observed)
    assert "ResourceFixture7" not in serialized
    assert "db.example.invalid" not in serialized
    assert "ghp_" not in serialized


def test_resource_expectations_fix_full_input_candidate_and_combined_finding_boundaries():
    direct = {
        name: (len(text), action, count, codes)
        for name, text, action, count, codes in resources.scenarios("direct")
    }
    assert direct["maximum_text"] == (100_000, "allow", 0, [])
    assert direct["over_maximum_text"] == (
        100_001,
        "error",
        1,
        ["connection_string_limit_exceeded"],
    )
    assert direct["candidate_8192"][0:3] == (8192, "block", 1)
    assert direct["candidate_8193"][0:3] == (8193, "error", 1)
    assert direct["candidate_32768"][0:3] == (32768, "error", 1)
    assert direct["combined_findings_256"][1:3] == ("block", 256)
    assert direct["combined_findings_257"][1:] == ("error", 1, ["finding_limit_exceeded"])
    assert direct["benign_candidates_257"][3] == ["connection_string_limit_exceeded"]
    assert direct["malformed_candidates_257"][3] == ["connection_string_limit_exceeded"]


def test_late_output_cannot_replace_a_parent_timeout(monkeypatch):
    stub_process(monkeypatch, payload(), timeout=True)
    observed = resources.measure("direct")
    assert observed["status"] == "wall_timeout"
    assert observed["child_reaped"] and not observed["contract_matches"]
    assert observed["returncode"] == 0
    assert "rows" not in observed and "resources" not in observed


@pytest.mark.parametrize(
    "failure",
    [
        "duplicate",
        "missing",
        "private-field",
        "wrong-id",
        "nonfinite",
        "huge-number",
        "wrong-type",
        "private-code",
        "wrong-mode-text",
    ],
)
def test_invalid_child_metadata_never_enters_the_parent_report(monkeypatch, failure):
    observed = payload()
    row = observed["rows"][0]
    if failure == "duplicate":
        observed["rows"][1] = copy.deepcopy(row)
    elif failure == "missing":
        observed["rows"].pop()
    elif failure == "private-field":
        row["payload"] = "private-sentinel"
    elif failure == "wrong-id":
        row["scenario"] = "private-sentinel"
    elif failure == "nonfinite":
        row["operation_ms"] = float("nan")
    elif failure == "huge-number":
        row["operation_ms"] = 10**1000
    elif failure == "wrong-type":
        row["input_chars"] = True
    elif failure == "private-code":
        row["finding_codes"] = ["private-sentinel"]
    else:
        row["has_deliverable_text"] = False
    stub_process(monkeypatch, observed)
    result = resources.measure("direct")
    assert result["status"] == "protocol_error"
    assert result["child_reaped"] and not result["contract_matches"]
    assert "rows" not in result
    assert "private-sentinel" not in json.dumps(result)


@pytest.mark.parametrize("failure", ["action", "count", "codes", "span", "delivery"])
def test_worker_outcomes_are_compared_with_parent_expectations(monkeypatch, failure):
    observed = payload("guard")
    row = observed["rows"][0]
    if failure == "action":
        row["action"] = "block"
    elif failure == "count":
        row["finding_count"] = 1
    elif failure == "codes":
        row["finding_codes"] = ["scanner_error"]
    elif failure == "span":
        row["error_spanless"] = False
    else:
        row["has_deliverable_text"] = False
    stub_process(monkeypatch, observed)
    result = resources.measure("guard")
    assert result["status"] == "completed"
    assert result["child_reaped"] and not result["contract_matches"]


@pytest.mark.parametrize("failure", ["stderr", "output-size"])
def test_raw_child_output_is_bounded_and_not_copied(monkeypatch, failure):
    marker = b"private-sentinel"
    stub_process(
        monkeypatch,
        payload(),
        stderr=marker if failure == "stderr" else b"",
        raw=marker * resources.limits.MAX_CAPTURE_BYTES if failure == "output-size" else None,
    )
    result = resources.measure("direct")
    assert not result["contract_matches"] and result["child_reaped"]
    assert "rows" not in result
    assert marker.decode() not in json.dumps(result)


def test_parent_interrupt_reaps_worker_before_removing_its_directory(tmp_path, monkeypatch):
    worker = tmp_path / "sleeping worker.py"
    worker.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    real_popen = subprocess.Popen
    children = []

    def popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append((child, Path(kwargs["cwd"])))
        original_wait = child.wait
        first = True

        def wait(*args, **kwargs):
            nonlocal first
            if first:
                first = False
                raise KeyboardInterrupt
            return original_wait(*args, **kwargs)

        monkeypatch.setattr(child, "wait", wait)
        return child

    monkeypatch.setattr(resources, "HERE", worker)
    monkeypatch.setattr(resources.subprocess, "Popen", popen)
    with pytest.raises(KeyboardInterrupt):
        resources.measure("direct")
    child, directory = children[0]
    assert child.poll() is not None
    assert not directory.exists()


def test_worker_failure_is_static_without_payload_or_traceback(monkeypatch, capsys):
    def fail(_):
        raise RuntimeError("private-sentinel")

    monkeypatch.setattr(resources, "worker", fail)
    assert resources.main(["--worker", "direct"]) == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {"worker_error": True}
    assert output.err == "" and "private-sentinel" not in output.out
