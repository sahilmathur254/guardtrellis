"""Frozen retrieval/tool contracts, privacy and deliberate checked-handoff bypasses."""

import copy
import hashlib
import json
import shutil
import signal
import sys
import time
from collections import Counter
from pathlib import Path

import pytest

from evaluation.retrieval_tool_policy import assets, contract, run, workflow

RESEARCH, CONTROLS, EXPECTATIONS, FREEZE = assets.load_frozen()
CASES = [*RESEARCH, *CONTROLS]
BY_ID = {case["id"]: case for case in CASES}
MUTATIONS = (
    ("H01", "raw_retrieval"),
    ("R12", "raw_return"),
    ("R10", "alter_call"),
    ("R10", "early_consume"),
    ("H08", "raw_fallback"),
    ("R09", "payload_approval"),
    ("H05", "truthy_auth"),
)


def assert_private(case, row, captured):
    rendered = json.dumps(row, allow_nan=False)
    assert not captured.out and not captured.err
    for marker in case["privacy_markers"]:
        assert marker not in rendered
    for text in (case["retrieval_text"], case["returned_text"], case["proposal"]["arguments_json"]):
        if len(text) >= 8:
            assert text not in rendered
    forbidden = {
        "retrieval_text",
        "returned_text",
        "arguments_json",
        "proposer_input",
        "authorize_pair",
        "execute_pair",
        "consumer_text",
        "exception_message",
        "traceback",
        "payload",
    }
    assert not (set(row) & forbidden)


def observe(case_id, **kwargs):
    return workflow.observe(BY_ID[case_id], EXPECTATIONS[case_id], **kwargs)


def test_freeze_keeps_twelve_research_scenarios_separate_from_harness_controls():
    assert [case["id"] for case in RESEARCH] == [f"R{i:02}" for i in range(1, 13)]
    assert [case["id"] for case in CONTROLS] == [f"H{i:02}" for i in range(1, 12)]
    assert Counter(case["pair_id"] for case in RESEARCH) == {f"P{i}": 2 for i in range(1, 7)}
    assert Counter(case["intent"] for case in RESEARCH) == {"adversarial": 6, "legitimate": 6}
    assert len(BY_ID) == len(EXPECTATIONS) == 23
    assert all(case["pair_id"] is None for case in CONTROLS)
    assert all(case["language"] == "en" for case in CASES)
    assert all(case["provenance"] == contract.PROVENANCE for case in CASES)
    assert all(case["provenance"]["independent_review"] is False for case in CASES)
    assert all(contract.validate_case(case) == case for case in CASES)
    assert hashlib.sha256((assets.HERE / "freeze_v1.json").read_bytes()).hexdigest() == (
        assets.FREEZE_SHA256
    )
    assert assets.RECEIPT.startswith("https://github.com/sahilmathur254/guardtrellis/issues/35#")
    assert FREEZE["phase"] == "before_first_new_scenario_observation"


@pytest.mark.parametrize("case_id", [case["id"] for case in CASES])
def test_frozen_workflows_match_exact_boundaries_without_reporting_payloads(case_id, capsys):
    case, expected = BY_ID[case_id], EXPECTATIONS[case_id]
    original_case, original_expected = copy.deepcopy(case), copy.deepcopy(expected)
    row = workflow.observe(case, expected)
    assert row["id"] == case_id
    assert row["terminal"] == expected["terminal"]
    assert row["error_boundary"] == expected["error_boundary"]
    assert row["diagnostics"] == expected["diagnostics"]
    assert row["events"] == expected["events"]
    assert row["counts"] == expected["counts"]
    assert row["desired"] == expected["desired"]
    assert row["contract_matches"] and row["delivery_integrity"] and row["diagnostics_private"]
    assert row["comparisons"] and all(value is True for value in row["comparisons"].values())
    assert case == original_case and expected == original_expected
    assert_private(case, row, capsys.readouterr())


@pytest.mark.parametrize("case_id,mutation", MUTATIONS, ids=[mode for _, mode in MUTATIONS])
def test_integrity_oracle_detects_each_deliberate_handoff_bypass(case_id, mutation, capsys):
    row = observe(case_id, mutation=mutation)
    assert not row["contract_matches"]
    assert not row["delivery_integrity"]
    assert any(value is False for value in row["comparisons"].values())
    assert_private(BY_ID[case_id], row, capsys.readouterr())


@pytest.mark.parametrize("case_id", ["R01", "R03"])
def test_instruction_only_allows_remain_visible_as_semantic_protection_limits(case_id):
    row = observe(case_id)
    assert row["contract_matches"] and row["delivery_integrity"]
    assert row["diagnostics"]["retrieval"]["action"] == "allow"
    assert row["counts"] == {"proposer": 1, "authorize": 1, "execute": 1, "consume": 1}
    assert row["desired"]["met"] is False


@pytest.mark.parametrize("case_id", ["R05", "R07"])
def test_structural_rejections_precede_authorization_and_execution(case_id):
    row = observe(case_id)
    assert row["diagnostics"]["call"]["action"] == "block"
    assert row["counts"] == {"proposer": 1, "authorize": 0, "execute": 0, "consume": 0}
    assert row["diagnostics"]["returned"] is None


def test_schema_valid_private_document_is_denied_by_host_not_the_sdk():
    row = observe("R09")
    assert row["diagnostics"]["call"]["action"] == "allow"
    assert row["counts"] == {"proposer": 1, "authorize": 1, "execute": 0, "consume": 0}
    assert row["diagnostics"]["returned"] is None


def test_supported_secret_blocks_return_before_pii_redaction_and_consumption():
    row = observe("R11")
    returned = row["diagnostics"]["returned"]
    assert returned["action"] == "block"
    assert [finding["code"] for finding in returned["findings"]] == ["secret_github_classic"]
    assert [entry["scanner"] for entry in returned["trace"]] == ["secrets"]
    assert row["counts"]["execute"] == 1 and row["counts"]["consume"] == 0


def test_legitimate_contact_is_redacted_before_delivery():
    row = observe("R12")
    returned = row["diagnostics"]["returned"]
    assert returned["action"] == "redact"
    assert [finding["code"] for finding in returned["findings"]] == ["pii_email"]
    assert row["comparisons"]["consumer_text"] is True
    assert row["counts"]["consume"] == 1


@pytest.mark.parametrize("case_id,action", [("H02", "block"), ("H03", "error")])
def test_retrieval_rejection_skips_proposer_and_every_later_boundary(case_id, action):
    row = observe(case_id)
    assert row["diagnostics"]["retrieval"]["action"] == action
    assert row["counts"] == {"proposer": 0, "authorize": 0, "execute": 0, "consume": 0}
    assert row["diagnostics"]["call"] is None
    assert row["diagnostics"]["returned"] is None


def test_truthy_non_boolean_authorization_does_not_permit_execution():
    row = observe("H05")
    assert row["counts"] == {"proposer": 1, "authorize": 1, "execute": 0, "consume": 0}
    assert row["contract_matches"]


def test_authorizer_mutation_of_flat_copy_does_not_change_dispatched_pair():
    row = observe("H06")
    assert EXPECTATIONS["H06"]["execute_pair"] == ["lookup", {"document_id": "public-guide"}]
    assert row["comparisons"]["execute_pair"] is True
    assert row["counts"]["execute"] == row["counts"]["consume"] == 1


@pytest.mark.parametrize("case_id", ["H07", "H08", "H09"])
def test_callback_failure_retains_attempt_counts_and_sanitized_boundary(case_id, capsys):
    row = observe(case_id)
    assert row["error_boundary"] == EXPECTATIONS[case_id]["error_boundary"]
    assert row["terminal"] == EXPECTATIONS[case_id]["terminal"]
    assert row["counts"] == EXPECTATIONS[case_id]["counts"]
    assert_private(BY_ID[case_id], row, capsys.readouterr())


@pytest.mark.parametrize(
    "raw",
    [
        '{"x":1,"x":2}',
        '{"x":NaN}',
        '{"x":Infinity}',
        '{"x":-Infinity}',
        '{"x":1e999}',
        '{"x":',
        b"\xff",
    ],
    ids=[
        "duplicate-key",
        "nan",
        "infinity",
        "negative-infinity",
        "overflow-float",
        "incomplete-json",
        "invalid-utf8",
    ],
)
def test_contract_json_rejects_ambiguous_or_nonfinite_expectation_input(raw):
    with pytest.raises(ValueError):
        contract.strict_json(raw)


@pytest.mark.parametrize("field,value", [("unexpected", "payload-canary"), ("language", "xx")])
def test_case_validation_rejects_unknown_fields_and_unreviewed_languages(field, value):
    case = copy.deepcopy(BY_ID["R01"])
    case[field] = value
    with pytest.raises(ValueError) as caught:
        contract.validate_case(case)
    assert "payload-canary" not in str(caught.value)


@pytest.mark.parametrize("field", ["desired_met", "start"])
def test_authored_annotation_types_cannot_treat_booleans_and_integers_as_interchangeable(field):
    case = copy.deepcopy(BY_ID["R12"])
    if field == "desired_met":
        case["expectation_spec"][field] = 1
    else:
        case["expectation_spec"]["returned_targets"][0][field] = True
    with pytest.raises(ValueError):
        contract.validate_case(case)


@pytest.mark.parametrize(
    "filename",
    [
        "corpus_v1.jsonl",
        "harness_controls_v1.jsonl",
        "expectations_v1.json",
        "contract.py",
        "PROTOCOL_v1.md",
        "sources_v1.json",
        "freeze_v1.json",
    ],
)
def test_freeze_rejects_changed_asset_bytes_before_sdk_execution(tmp_path, monkeypatch, filename):
    for source in assets.HERE.iterdir():
        if source.is_file():
            shutil.copyfile(source, tmp_path / source.name)
    target = tmp_path / filename
    target.write_bytes(target.read_bytes() + b"\n")
    monkeypatch.setattr(assets, "HERE", tmp_path)
    with pytest.raises(ValueError):
        assets.load_frozen()


def encoded_worker(row, identity):
    events = [
        {"event": "row", "row": row},
        {
            "event": "complete",
            "id": row["id"],
            "source": identity,
            "limits": {
                key: None
                for key in (
                    "cpu_seconds",
                    "address_space_bytes",
                    "core_bytes",
                    "output_file_bytes",
                )
            },
        },
    ]
    return b"".join((json.dumps(event) + "\n").encode() for event in events)


def test_worker_protocol_requires_a_complete_matching_source_record():
    case = BY_ID["R12"]
    row, identity = observe("R12"), run.source_identity()
    raw = encoded_worker(row, identity)
    parsed = run.read_protocol(raw, case, EXPECTATIONS["R12"], identity)
    assert parsed["row"] == row
    for changed in (raw.splitlines()[0], raw + raw, b"PrivateWorkerProtocolCanary"):
        with pytest.raises(ValueError) as caught:
            run.read_protocol(changed, case, EXPECTATIONS["R12"], identity)
        assert "PrivateWorkerProtocolCanary" not in str(caught.value)


@pytest.mark.parametrize(
    "corruption",
    [
        "boolean_count",
        "boolean_index",
        "integer_comparison",
        "integer_desired",
        "private_field",
        "private_diagnostic_field",
        "private_event",
        "wrong_source",
    ],
)
def test_worker_protocol_rejects_type_confusion_and_unknown_payload_surfaces(corruption):
    case = BY_ID["R12"]
    row, identity = copy.deepcopy(observe("R12")), run.source_identity()
    expected_identity = copy.deepcopy(identity)
    if corruption == "boolean_count":
        row["counts"]["proposer"] = True
    elif corruption == "boolean_index":
        row["diagnostics"]["returned"]["findings"][0]["scanner_index"] = True
    elif corruption == "integer_comparison":
        row["comparisons"]["events"] = 1
    elif corruption == "integer_desired":
        row["desired"]["met"] = 1
    elif corruption == "private_field":
        row["raw_return"] = "PrivateWorkerProtocolCanary"
    elif corruption == "private_diagnostic_field":
        row["diagnostics"]["returned"]["matched_text"] = "PrivateWorkerProtocolCanary"
    elif corruption == "private_event":
        row["events"].append("PrivateWorkerProtocolCanary")
    else:
        identity["unexpected_identity"] = "PrivateWorkerProtocolCanary"
    with pytest.raises(ValueError) as caught:
        run.read_protocol(
            encoded_worker(row, identity), case, EXPECTATIONS["R12"], expected_identity
        )
    assert "PrivateWorkerProtocolCanary" not in str(caught.value)


@pytest.mark.parametrize("interrupted", [False, True])
def test_stopped_observation_never_launches_a_child(monkeypatch, interrupted):
    def launch_forbidden(*_args, **_kwargs):
        raise AssertionError("A stopped observation must not launch a child")

    with monkeypatch.context() as patch:
        patch.setattr(run.subprocess, "Popen", launch_forbidden)
        result = run.supervise_case(
            BY_ID["R10"],
            EXPECTATIONS["R10"],
            deadline=time.perf_counter() + (10 if interrupted else -1),
            interrupted=[interrupted],
        )
    assert result["status"] == "not_started"
    assert result["child_reaped"] is None and result["row"] is None
    assert result["returncode"] is None


def test_windows_supervises_the_base_interpreter_with_the_selected_venv_launcher(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(run.sys, "platform", "win32")
        patch.setattr(run.sys, "executable", "selected-venv-python.exe")
        patch.setattr(run.sys, "_base_executable", "base-python.exe")
        executable, environment = run.launch_settings()
    assert executable == "base-python.exe"
    assert environment["__PYVENV_LAUNCHER__"] == "selected-venv-python.exe"


def test_metadata_preparation_cannot_extend_the_parent_observation_deadline(monkeypatch):
    identity = run.source_identity()
    now = [0.0]

    def prepare_identity():
        now[0] = 1.0
        return identity

    def launch_forbidden(*_args, **_kwargs):
        raise AssertionError("Metadata preparation exhausted the parent observation budget")

    with monkeypatch.context() as patch:
        patch.setattr(run.time, "perf_counter", lambda: now[0])
        patch.setattr(run, "source_identity", prepare_identity)
        patch.setattr(run.subprocess, "Popen", launch_forbidden)
        result = run.supervise_case(
            BY_ID["R10"], EXPECTATIONS["R10"], deadline=0.5, interrupted=[False]
        )
    assert result["status"] == "not_started"
    assert result["reason"] == "budget_exhausted"
    assert result["child_reaped"] is None and result["row"] is None


def test_supervisor_wall_timeout_kills_and_reaps_the_synthetic_worker(monkeypatch):
    monkeypatch.setattr(run, "WALL_SECONDS", 0.15)
    result = run.supervise_case(
        BY_ID["R10"],
        EXPECTATIONS["R10"],
        deadline=time.perf_counter() + 10,
        interrupted=[False],
        worker_command=[sys._base_executable, "-c", "import time; time.sleep(30)"],
    )
    assert result["status"] == "wall_timeout"
    assert result["child_reaped"] is True and result["returncode"] is not None
    assert result["row"] is None


@pytest.mark.parametrize("channel", ["stdout", "stderr"])
def test_capture_overflow_reaps_worker_without_retaining_its_output(channel):
    source = (
        "import sys; "
        f"sys.{channel}.write('PrivateWorkerCaptureCanary' * 4000); "
        f"sys.{channel}.flush()"
    )
    result = run.supervise_case(
        BY_ID["R10"],
        EXPECTATIONS["R10"],
        deadline=time.perf_counter() + 10,
        interrupted=[False],
        worker_command=[sys._base_executable, "-c", source],
    )
    assert result["status"] == "output_limit"
    assert result["child_reaped"] is True
    assert result["row"] is None
    assert "PrivateWorkerCaptureCanary" not in json.dumps(result)


def test_malformed_worker_output_is_not_a_completed_observation_or_report_payload():
    result = run.supervise_case(
        BY_ID["R10"],
        EXPECTATIONS["R10"],
        deadline=time.perf_counter() + 10,
        interrupted=[False],
        worker_command=[sys._base_executable, "-c", "print('PrivateMalformedWorkerCanary')"],
    )
    assert result["status"] == "protocol_error"
    assert result["protocol_error"] is True
    assert result["child_reaped"] is True and result["row"] is None
    assert "PrivateMalformedWorkerCanary" not in json.dumps(result)


def test_cleanup_failure_retains_the_confirmed_reap_state_and_validated_row(monkeypatch):
    cleanup = run.limits.kill_and_reap

    def reaped_then_failed(process):
        cleanup(process)
        raise OSError("PrivateCleanupFailureCanary")

    with monkeypatch.context() as patch:
        patch.setattr(run.limits, "kill_and_reap", reaped_then_failed)
        result = run.supervise_case(
            BY_ID["R10"],
            EXPECTATIONS["R10"],
            deadline=time.perf_counter() + 10,
            interrupted=[False],
        )
    assert result["status"] == "cleanup_error" and result["cleanup_failed"] is True
    assert result["child_reaped"] is True and result["returncode"] == 0
    assert result["row"]["contract_matches"] is True
    assert "PrivateCleanupFailureCanary" not in json.dumps(result)


def completed_record(case, expectation):
    return {
        "id": case["id"],
        "status": "completed",
        "reason": None,
        "row": workflow.observe(case, expectation),
        "child_reaped": True,
        "cleanup_failed": False,
        "returncode": 0,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "wall_budget_seconds": 10.0,
        "wall_elapsed_seconds": 0.0,
        "protocol_error": False,
        "limits": None,
    }


def test_interruption_during_final_report_write_is_retained_with_all_completed_rows(
    tmp_path, monkeypatch
):
    original_write = Path.write_bytes
    previous_handlers = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }
    output = tmp_path / "late-interruption"
    prepared = []
    final_writes = []
    triggered = [False]

    def completed(
        case, expectation, *, deadline, interrupted, worker_command=None, expected_identity=None
    ):
        return completed_record(case, expectation)

    def interrupt_final_write(path, payload):
        written = original_write(path, payload)
        if path.parent == output and path.name == "results.json":
            prepared.append(json.loads(payload))
        elif path.parent == output and path.name == "REPORT.md":
            # The initial timing write, if present, lacks this finalization field.
            # Interrupt after the final prepared snapshot has reached both files.
            if prepared and "report_write_elapsed_seconds" in prepared[-1]:
                final_writes.append(prepared[-1]["interrupted"])
                if not triggered[0]:
                    triggered[0] = True
                    handler = signal.getsignal(signal.SIGINT)
                    assert callable(handler)
                    handler(signal.SIGINT, None)
        return written

    with monkeypatch.context() as patch:
        patch.setattr(run, "supervise_case", completed)
        patch.setattr(Path, "write_bytes", interrupt_final_write)
        status = run.run_batch(output)

    report = json.loads((output / "results.json").read_bytes())
    assert triggered[0] and status == 130
    assert report["interrupted"] is True and report["contract_checks_passed"] is False
    assert [record["id"] for record in report["runs"]] == [case["id"] for case in CASES]
    assert all(record["status"] == "completed" for record in report["runs"])
    assert all(record["row"]["contract_matches"] for record in report["runs"])
    assert report["summary"]["observed_research"] == 12
    assert report["summary"]["observed_controls"] == 11
    assert final_writes == [False, True]
    contents = (output / "results.json").read_text() + (output / "REPORT.md").read_text()
    for case in CASES:
        assert all(marker not in contents for marker in case["privacy_markers"])
    assert "Contract checks passed: `False`" in (output / "REPORT.md").read_text()
    assert all(signal.getsignal(signum) == handler for signum, handler in previous_handlers.items())


def test_supervisor_rejects_changed_worker_source_against_the_pinned_batch_identity(monkeypatch):
    case, expectation = BY_ID["R10"], EXPECTATIONS["R10"]
    pinned = run.source_identity()
    changed = {**pinned, "workflow_sha256": "f" * 64}
    assert changed != pinned
    raw = encoded_worker(observe("R10"), changed)
    with pytest.raises(ValueError):
        run.read_protocol(raw, case, expectation, pinned)
    with monkeypatch.context() as patch:
        # Re-reading provenance from the parent must not replace the batch snapshot.
        patch.setattr(run, "source_identity", lambda: changed)
        result = run.supervise_case(
            case,
            expectation,
            deadline=time.perf_counter() + 10,
            interrupted=[False],
            expected_identity=pinned,
            worker_command=[
                sys._base_executable,
                "-c",
                f"import sys; sys.stdout.buffer.write({raw!r})",
            ],
        )
    assert result["status"] == "protocol_error" and result["protocol_error"] is True
    assert result["row"] is None and result["child_reaped"] is True


def test_batch_pins_source_identity_and_retains_prefix_when_later_worker_source_changes(
    tmp_path, monkeypatch
):
    pinned = run.source_identity()
    changed = {**pinned, "workflow_sha256": "f" * 64}
    identities = []
    output = tmp_path / "source-change"

    def supervised(
        case, expectation, *, deadline, interrupted, worker_command=None, expected_identity=None
    ):
        identities.append(copy.deepcopy(expected_identity))
        record = completed_record(case, expectation)
        if case["id"] != "R01":
            with pytest.raises(ValueError):
                run.read_protocol(
                    encoded_worker(record["row"], changed), case, expectation, expected_identity
                )
            record.update(status="protocol_error", protocol_error=True, row=None)
        return record

    with monkeypatch.context() as patch:
        patch.setattr(run, "source_identity", lambda: pinned)
        patch.setattr(run, "supervise_case", supervised)
        status = run.run_batch(output)
    report = json.loads((output / "results.json").read_bytes())
    assert status == 1 and report["contract_checks_passed"] is False
    assert identities == [pinned] * 23
    assert report["metadata"]["source"] == pinned
    assert len(report["runs"]) == 23
    assert report["runs"][0]["row"]["id"] == "R01"
    assert report["runs"][0]["row"]["contract_matches"] is True
    assert all(record["row"] is None for record in report["runs"][1:])


def test_unexpected_sdk_error_is_reported_as_unexpected_while_authored_error_controls_are_not(
    monkeypatch,
):
    from guardtrellis import Action, Finding, Result

    def failed_scan(self, text, *, stage):
        return Result(Action.ERROR, stage, None, (Finding("scanner_error", scanner="guard"),))

    with monkeypatch.context() as patch:
        patch.setattr(workflow.Guard, "scan", failed_scan)
        row = observe("R10")
    assert row["unexpected_error"] is True and row["contract_matches"] is False
    assert row["diagnostics"]["retrieval"]["action"] == "error"
    assert row["counts"] == {"proposer": 0, "authorize": 0, "execute": 0, "consume": 0}
    assert all(observe(identifier)["unexpected_error"] is False for identifier in ("H03", "H04"))
