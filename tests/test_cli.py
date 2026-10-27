"""CLI policy, privacy, byte protocol and handled transport regressions; no network."""

import io
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from guardtrellis import Action, Guard, PIIScanner, Result, SecretScanner, Stage, __version__, _cli

BASE = ["check", "--stdin", "--stage", "retrieval", "--policy", "privacy", "--format", "json"]
CANARY = "DoNotDiscloseFixtureOrPath42"
URI = "postgresql://app:SyntheticFixture42@db.example.invalid/demo"


def install_streams(monkeypatch, data=b"Public opening hours", *, out=None, err=None):
    stdin = io.BytesIO(data)
    stdout = io.BytesIO() if out is None else out
    stderr = io.BytesIO() if err is None else err
    for name, buffer in (("stdin", stdin), ("stdout", stdout), ("stderr", stderr)):
        monkeypatch.setattr(sys, name, SimpleNamespace(buffer=buffer, isatty=lambda: False))
    quarantined = []
    monkeypatch.setattr(_cli, "_quarantine", quarantined.append)
    return stdin, stdout, stderr, quarantined


def capture(monkeypatch, argv=BASE, data=b"Public opening hours", *, out=None, err=None):
    stdin, stdout, stderr, quarantined = install_streams(monkeypatch, data, out=out, err=err)
    status = _cli.main(argv)
    return status, stdout.getvalue(), stderr.getvalue(), stdin.tell(), quarantined


def run(argv, data=b"", **kwargs):
    return subprocess.run(
        [sys.executable, "-m", "guardtrellis", *argv],
        input=data,
        capture_output=True,
        timeout=10,
        **kwargs,
    )


@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize("policy", ["secrets", "privacy"])
@pytest.mark.parametrize(
    "text,options",
    [
        ("", []),
        ("Opening hours: 9am to 5pm.", []),
        ("Contact demo@example.org", []),
        ("Contact +1 (202) 555-0123", ["--phone-mode", "formatted"]),
        (URI, []),
        (URI, ["--connection-strings"]),
        ("Contact demo@example.org " + "ghp_" + "B" * 36, []),
    ],
)
def test_exact_sdk_policy_parity(monkeypatch, stage, policy, text, options):
    if policy == "secrets" and "--phone-mode" in options:
        argv = ["check", "--stdin", "--stage", stage.value, "--policy", policy, *options]
        status, stdout, stderr, read, _ = capture(monkeypatch, argv, text.encode())
        assert (status, stdout, stderr, read) == (
            2,
            b"",
            b"guardtrellis: invalid_configuration\n",
            0,
        )
        return
    argv = [
        "check",
        "--stdin",
        "--stage",
        stage.value,
        "--policy",
        policy,
        "--format",
        "json",
        "--output",
        "checked-text",
        *options,
    ]
    scanners = [SecretScanner(connection_strings="--connection-strings" in options)]
    if policy == "privacy":
        scanners.append(
            PIIScanner(
                phone_mode="formatted" if options == ["--phone-mode", "formatted"] else "contiguous"
            )
        )
    expected = Guard(**{f"{stage.value}_scanners": scanners}).scan(text, stage=stage)
    status, stdout, stderr, _, _ = capture(monkeypatch, argv, text.encode())
    assert status == (0 if expected.accepted else 1)
    assert stdout == (expected.require_text().encode() if expected.accepted else b"")
    report = json.loads(stderr)
    assert set(report) == {
        "report_version",
        "sdk_version",
        "stage",
        "policy",
        "options",
        "result",
        "error",
    }
    assert type(report["report_version"]) is int and report["report_version"] == 1
    assert report["sdk_version"] == __version__
    assert report["stage"] == stage.value and report["policy"] == policy
    assert report["options"] == {
        "connection_strings": "--connection-strings" in options,
        "phone_mode": ("formatted" if "--phone-mode" in options else "contiguous")
        if policy == "privacy"
        else None,
    }
    assert report["result"] == expected.diagnostics() and report["error"] is None
    assert stderr.endswith(b"\n") and len(stderr.splitlines()) == 1
    assert text.encode() not in stderr if text else True


@pytest.mark.parametrize("stage", [item.value for item in Stage])
@pytest.mark.parametrize(
    "policy,data,action,checked",
    [
        ("secrets", b"Opening hours: 9am to 5pm.", "allow", b"Opening hours: 9am to 5pm."),
        ("privacy", b"Contact demo@example.org", "redact", b"Contact [PII]"),
        ("privacy", ("ghp_" + "C" * 36).encode(), "block", b""),
    ],
)
def test_real_module_process(stage, policy, data, action, checked):
    completed = run(
        [
            "check",
            "--stdin",
            "--stage",
            stage,
            "--policy",
            policy,
            "--format",
            "json",
            "--output",
            "checked-text",
        ],
        data,
    )
    assert completed.returncode == (1 if action == "block" else 0)
    assert completed.stdout == checked
    assert json.loads(completed.stderr)["result"]["action"] == action


@pytest.mark.parametrize(
    "argv,code",
    [
        ([], "invalid_command"),
        (["scan", CANARY], "invalid_command"),
        (BASE + [CANARY], "invalid_command"),
        (BASE + ["--file", CANARY], "invalid_command"),
        (BASE + ["--stage", "tool"], "invalid_command"),
        (BASE + ["--stdin"], "invalid_command"),
        (BASE + ["--connection-strings", "--connection-strings"], "invalid_command"),
        (BASE + ["--fo", CANARY], "invalid_command"),
        (BASE[:-1], "invalid_command"),
        (BASE[:-1] + [CANARY], "invalid_configuration"),
        (["check", "--stdin", "--policy", "secrets"], "invalid_command"),
        (["check", "--stdin", "--stage", CANARY, "--policy", "secrets"], "invalid_configuration"),
        (["check", "--stdin", "--stage", "tool", "--policy", CANARY], "invalid_configuration"),
        (
            [
                "check",
                "--stdin",
                "--stage",
                "tool",
                "--policy",
                "secrets",
                "--phone-mode",
                "contiguous",
                "--format",
                "json",
            ],
            "invalid_configuration",
        ),
        (BASE + ["--output", CANARY], "invalid_configuration"),
        (BASE + ["--phone-mode", CANARY], "invalid_configuration"),
        (BASE + ["--stdin=true"], "invalid_command"),
        (BASE + ["--help"], "invalid_command"),
    ],
)
def test_static_configuration_errors_read_nothing(monkeypatch, argv, code):
    status, stdout, stderr, read, _ = capture(monkeypatch, argv, CANARY.encode())
    assert (status, stdout, stderr, read) == (2, b"", f"guardtrellis: {code}\n".encode(), 0)


@pytest.mark.parametrize(
    "argv", [["--help"], ["check", "-h"], ["--version"], ["check", "--version"]]
)
def test_help_version_need_no_source_and_do_not_read(monkeypatch, argv):
    status, stdout, stderr, read, _ = capture(monkeypatch, argv, CANARY.encode())
    assert status == 0 and stdout and not stderr and read == 0
    assert CANARY.encode() not in stdout


def test_equals_syntax_and_no_environment_policy(monkeypatch):
    monkeypatch.setenv("GUARDTRELLIS_POLICY", "secrets")
    argv = ["check", "--stdin", "--stage=tool", "--policy=privacy", "--format=json"]
    status, stdout, stderr, _, _ = capture(monkeypatch, argv, b"demo@example.org")
    assert status == 0 and not stderr
    assert json.loads(stdout)["result"]["action"] == "redact"


@pytest.mark.parametrize(
    "data", [b"", b"line1\r\nline2\n", "\ufeffcafé 雪\x00".encode(), b"\x1b[31mplain\x1b[0m"]
)
def test_file_and_stdin_preserve_exact_binary_utf8(tmp_path, data):
    source = tmp_path / "fixture with spaces 雪.txt"
    source.write_bytes(data)
    for selected in (["--stdin"], ["--file", str(source)]):
        completed = run(
            [
                "check",
                *selected,
                "--stage",
                "tool",
                "--policy",
                "secrets",
                "--output",
                "checked-text",
                "--format",
                "json",
            ],
            data,
        )
        assert completed.returncode == 0 and completed.stdout == data
        assert json.loads(completed.stderr)["result"]["action"] == "allow"
        assert source.read_bytes() == data


@pytest.mark.parametrize(
    "data,code",
    [
        (b"\xff" + CANARY.encode(), "invalid_encoding"),
        (b"\xed\xa0\x80", "invalid_encoding"),
        (b"x" * 100_001, "input_limit_exceeded"),
        (b"x" * 400_001, "input_limit_exceeded"),
    ],
    # Pytest puts node IDs in PYTEST_CURRENT_TEST. Literal payload IDs exceed
    # Windows' environment-variable limit and obscure the actual input tests.
    ids=["invalid-byte", "surrogate", "character-limit", "byte-limit"],
)
@pytest.mark.parametrize("checked", [False, True])
def test_ingress_errors_are_structured_and_private(monkeypatch, data, code, checked):
    argv = BASE + (["--output", "checked-text"] if checked else [])
    status, stdout, stderr, _, _ = capture(monkeypatch, argv, data)
    assert status == 2
    report = json.loads(stderr if checked else stdout)
    assert not (stdout if checked else stderr)
    assert report["result"] is None and report["error"] == {"code": code}
    assert CANARY.encode() not in stdout + stderr


def test_ingress_reads_at_most_byte_cap_plus_one():
    stream = io.BytesIO(b"x" * 500_000)
    with pytest.raises(_cli._Failure) as caught:
        _cli._read_bounded(stream)
    assert caught.value.code == "input_limit_exceeded" and stream.tell() == 400_001
    assert _cli._read_bounded(io.BytesIO("😀".encode() * 100_000)) == "😀" * 100_000
    assert _cli._read_bounded(io.BytesIO(b"x" * 100_000)) == "x" * 100_000


def test_input_errors_and_regular_file_checks(monkeypatch, tmp_path):
    for path, code in ((tmp_path, "invalid_source"), (tmp_path / CANARY, "input_io_error")):
        argv = ["check", "--file", str(path), *BASE[2:]]
        status, stdout, stderr, read, _ = capture(monkeypatch, argv)
        assert status == 2 and not stderr and read == 0
        assert json.loads(stdout)["error"] == {"code": code}
        assert CANARY.encode() not in stdout
    source = tmp_path / "file"
    source.write_bytes(b"Public")
    monkeypatch.setattr(_cli.os, "fstat", lambda _: SimpleNamespace(st_mode=0))
    status, stdout, _, _, _ = capture(monkeypatch, ["check", "--file", str(source), *BASE[2:]])
    assert status == 2 and json.loads(stdout)["error"]["code"] == "invalid_source"
    assert source.read_bytes() == b"Public"


@pytest.mark.skipif(os.name == "nt", reason="POSIX filesystem node API")
def test_fifo_rejected_without_open_or_blocking_and_regular_symlink_works(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    rejected = run(["check", "--file", str(fifo), *BASE[2:]])
    assert (
        rejected.returncode == 2
        and json.loads(rejected.stdout)["error"]["code"] == "invalid_source"
    )
    source = tmp_path / "regular"
    source.write_bytes(b"Public")
    link = tmp_path / "alias"
    link.symlink_to(source)
    assert run(["check", "--file", str(link), *BASE[2:]]).returncode == 0


def test_direct_tty_guards_run_before_read_even_for_empty_or_rejected_input(monkeypatch):
    for data in (b"", URI.encode(), b"Public"):
        install_streams(monkeypatch, data=data)
        sys.stdout.isatty = lambda: True
        assert _cli.main(BASE + ["--output", "checked-text"]) == 2
        assert sys.stdin.buffer.tell() == 0
        assert sys.stdout.buffer.getvalue() == b""
        assert sys.stderr.buffer.getvalue() == b"guardtrellis: invalid_configuration\n"
    install_streams(monkeypatch)
    sys.stdin.isatty = lambda: True
    assert _cli.main(BASE) == 2
    assert json.loads(sys.stdout.buffer.getvalue())["error"]["code"] == "invalid_source"
    assert sys.stdin.buffer.tell() == 0


def test_isatty_failure_is_output_error_before_input(monkeypatch):
    install_streams(monkeypatch)

    def broken():
        raise OSError(CANARY)

    sys.stdout.isatty = broken
    assert _cli.main(BASE + ["--output", "checked-text"]) == 3
    assert sys.stdin.buffer.tell() == 0
    assert sys.stderr.buffer.getvalue() == b"guardtrellis: output_io_error\n"


class Sink(io.BytesIO):
    def __init__(self, *, fail=None, chunk=None, events=None, name=""):
        super().__init__()
        self.fail = fail
        self.chunk = chunk
        self.events = [] if events is None else events
        self.name = name

    def write(self, data):
        self.events.append((self.name, "write"))
        if self.fail == "write":
            raise BrokenPipeError(CANARY)
        if self.fail == "interrupt":
            raise KeyboardInterrupt
        if self.fail == "zero":
            return 0
        return super().write(data[: self.chunk] if self.chunk else data)

    def flush(self):
        self.events.append((self.name, "flush"))
        if self.fail == "flush":
            raise OSError(CANARY)
        if self.fail == "interrupt_flush":
            raise KeyboardInterrupt
        super().flush()


def test_metadata_flush_precedes_payload_and_short_writes_do_not_duplicate(monkeypatch):
    events = []
    out, err = Sink(chunk=2, events=events, name="out"), Sink(chunk=7, events=events, name="err")
    status, stdout, stderr, _, failed = capture(
        monkeypatch, BASE + ["--output", "checked-text"], out=out, err=err
    )
    assert status == 0 and stdout == b"Public opening hours" and not failed
    assert json.loads(stderr)["result"]["action"] == "allow"
    assert events.index(("err", "flush")) < events.index(("out", "write"))
    assert events[-1] == ("out", "flush")


@pytest.mark.parametrize("failure", ["write", "flush", "zero", "interrupt", "interrupt_flush"])
@pytest.mark.parametrize("checked", [True, False])
def test_metadata_failure_withholds_payload_and_never_retries(monkeypatch, failure, checked):
    failed = Sink(fail=failure)
    kwargs = {"err" if checked else "out": failed}
    status, stdout, stderr, _, quarantined = capture(
        monkeypatch, BASE + (["--output", "checked-text"] if checked else []), **kwargs
    )
    assert status == (130 if failure.startswith("interrupt") else 3)
    assert quarantined == ["stderr" if checked else "stdout"]
    if checked:
        assert stdout == b"" and b"Public opening hours" not in stderr
        assert b"output_io_error" not in stderr
    elif failure.startswith("interrupt"):
        assert stderr == b""
    else:
        assert stderr == b"guardtrellis: output_io_error\n"
    assert CANARY.encode() not in stdout + stderr


@pytest.mark.parametrize("failure", ["write", "flush", "zero", "interrupt", "interrupt_flush"])
def test_payload_failure_does_not_append_second_metadata_record(monkeypatch, failure):
    status, stdout, stderr, _, quarantined = capture(
        monkeypatch, BASE + ["--output", "checked-text"], out=Sink(fail=failure)
    )
    assert status == (130 if failure.startswith("interrupt") else 3)
    assert json.loads(stderr)["result"]["action"] == "allow"
    assert len(stderr.splitlines()) == 1 and quarantined == ["stdout"]
    assert stdout == (b"Public opening hours" if "flush" in failure else b"")


def test_both_streams_broken_status_only_and_no_recursive_reporting(monkeypatch):
    out, err = Sink(fail="write"), Sink(fail="write")
    status, stdout, stderr, _, quarantined = capture(monkeypatch, out=out, err=err)
    assert (status, stdout, stderr) == (3, b"", b"")
    assert quarantined == ["stdout", "stderr"] and len(err.events) == 1


@pytest.mark.parametrize(
    "argv,data",
    [(["--help"], b""), ([], b""), (BASE, b"\xff"), (BASE, ("ghp_" + "D" * 36).encode())],
)
def test_output_failure_overrides_normal_help_config_ingress_or_block_status(
    monkeypatch, argv, data
):
    status, _, _, _, _ = capture(
        monkeypatch, argv, data, out=Sink(fail="write"), err=Sink(fail="write")
    )
    assert status == 3


def test_wrapper_runtime_interruption_sdk_error_and_limits_are_distinct(monkeypatch):
    def runtime(*_):
        raise RuntimeError(CANARY)

    monkeypatch.setattr(_cli, "_scan", runtime)
    status, stdout, stderr, _, _ = capture(monkeypatch)
    assert status == 3 and not stderr and json.loads(stdout)["error"] == {"code": "runtime_error"}

    def interrupt(*_):
        raise KeyboardInterrupt

    monkeypatch.setattr(_cli, "_scan", interrupt)
    for out in (None, Sink(fail="write")):
        status, stdout, stderr, _, _ = capture(monkeypatch, out=out)
        assert status == 130
        assert CANARY.encode() not in stdout + stderr
    monkeypatch.setattr(_cli, "_scan", lambda *_: Result(Action.ERROR, Stage.RETRIEVAL, None))
    status, stdout, _, _, _ = capture(monkeypatch)
    assert status == 3
    assert json.loads(stdout)["error"] is None and json.loads(stdout)["result"]["action"] == "error"
    monkeypatch.setattr(
        _cli, "_scan", lambda *_: Result(Action.ALLOW, Stage.RETRIEVAL, "x" * 100_001)
    )
    status, _, stderr, _, _ = capture(monkeypatch, BASE + ["--output", "checked-text"])
    assert status == 3 and json.loads(stderr)["error"] == {"code": "checked_output_limit_exceeded"}


def test_report_overflow_is_compact_error_not_truncated_findings(monkeypatch):
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", 400)
    status, stdout, stderr, _, _ = capture(monkeypatch, data=b"demo@example.org " * 20)
    assert status == 3 and not stderr and len(stdout) <= 400
    report = json.loads(stdout)
    assert report["result"] is None and report["error"] == {"code": "report_limit_exceeded"}


def test_report_limit_includes_final_lf_and_is_inclusive(monkeypatch):
    config = _cli._parse(BASE)
    result = _cli._scan(config, "Public")
    report = _cli._report(config, result, None)
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", len(report))
    assert _cli._report(config, result, None) == report
    monkeypatch.setattr(_cli, "MAX_REPORT_BYTES", len(report) - 1)
    with pytest.raises(_cli._Failure) as caught:
        _cli._report(config, result, None)
    assert caught.value.code == "report_limit_exceeded" and report.endswith(b"\n")


def test_real_maximum_utf8_bytes_roundtrip_and_one_extra_byte_rejects():
    argv = [
        "check",
        "--stdin",
        "--stage",
        "output",
        "--policy",
        "secrets",
        "--format",
        "json",
        "--output",
        "checked-text",
    ]
    data = "😀".encode() * 100_000
    completed = run(argv, data)
    assert completed.returncode == 0 and completed.stdout == data
    completed = run(argv, data + b"x")
    assert completed.returncode == 2 and completed.stdout == b""
    assert json.loads(completed.stderr)["error"] == {"code": "input_limit_exceeded"}


def test_human_output_is_only_static_metadata(monkeypatch):
    argv = BASE[:-2]
    status, stdout, stderr, _, _ = capture(monkeypatch, argv, b"Contact demo@example.org")
    assert status == 0 and not stderr
    assert stdout == b"stage=retrieval action=redact findings=1 codes=pii_email\n"
    status, stdout, _, _, _ = capture(monkeypatch, argv, b"\xff" + CANARY.encode())
    assert status == 2 and stdout == b"stage=retrieval error=invalid_encoding\n"


@pytest.mark.parametrize("checked", [False, True])
def test_uri_limits_are_sdk_error_not_ingress_error(monkeypatch, checked):
    status, stdout, stderr, _, _ = capture(
        monkeypatch,
        BASE + ["--connection-strings"] + (["--output", "checked-text"] if checked else []),
        ("postgresql://app:" + "X" * 8200 + "@db.invalid/x").encode(),
    )
    assert status == 3
    report = json.loads(stderr if checked else stdout)
    assert report["error"] is None and report["result"]["action"] == "error"
    assert not (stdout if checked else stderr)


def test_host_can_deadline_and_reap_stalled_stdin():
    process = subprocess.Popen(
        [sys.executable, "-m", "guardtrellis", *BASE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=0.6)
    finally:
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
    assert process.returncode is not None and stdout == stderr == b""


@pytest.mark.skipif(os.name == "nt", reason="POSIX terminal API; mocked TTY gates run everywhere")
def test_real_terminal_stdout_rejected_without_reading_stalled_input():
    import pty

    master, slave = pty.openpty()
    try:
        with subprocess.Popen(
            [sys.executable, "-m", "guardtrellis", *BASE, "--output", "checked-text"],
            stdin=subprocess.PIPE,
            stdout=slave,
            stderr=subprocess.PIPE,
        ) as process:
            assert process.wait(timeout=10) == 2
            assert process.stderr.read() == b"guardtrellis: invalid_configuration\n"
    finally:
        os.close(slave)
        os.close(master)


@pytest.mark.parametrize("channel", ["stdout", "stderr"])
def test_real_broken_descriptor_does_not_exit_120_or_print_shutdown_traceback(channel):
    # Close the reading end before the child writes; both code paths run on Windows too.
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    argv = BASE + (["--output", "checked-text"] if channel == "stderr" else [])
    with os.fdopen(write_fd, "wb") as broken:
        completed = subprocess.run(
            [sys.executable, "-m", "guardtrellis", *argv],
            input=b"Public",
            stdout=broken if channel == "stdout" else subprocess.PIPE,
            stderr=broken if channel == "stderr" else subprocess.PIPE,
            timeout=10,
        )
    assert completed.returncode == 3
    assert (completed.stderr if channel == "stdout" else completed.stdout) == (
        b"guardtrellis: output_io_error\n" if channel == "stdout" else b""
    )


@pytest.mark.parametrize("channel,descriptor", [("stdout", 1), ("stderr", 2)])
def test_closed_standard_descriptor_is_quarantined_for_shutdown(channel, descriptor):
    argv = BASE + (["--output", "checked-text"] if channel == "stderr" else [])
    code = (
        "import os; from guardtrellis._cli import main; "
        f"os.close({descriptor}); raise SystemExit(main())"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code, *argv], input=b"Public", capture_output=True, timeout=10
    )
    assert completed.returncode == 3 and not completed.stdout
    assert completed.stderr == (b"guardtrellis: output_io_error\n" if channel == "stdout" else b"")


def test_partial_metadata_failure_withholds_payload_and_partial_payload_has_one_report(monkeypatch):
    class Partial(Sink):
        def write(self, data):
            if self.tell():
                raise BrokenPipeError(CANARY)
            return super().write(data[:8])

    status, stdout, stderr, _, _ = capture(
        monkeypatch, BASE + ["--output", "checked-text"], err=Partial()
    )
    assert status == 3 and stdout == b"" and len(stderr) == 8
    status, stdout, stderr, _, _ = capture(
        monkeypatch, BASE + ["--output", "checked-text"], out=Partial()
    )
    assert status == 3 and stdout == b"Public o"
    assert json.loads(stderr)["result"]["action"] == "allow" and len(stderr.splitlines()) == 1


def test_input_io_and_preconfiguration_runtime_errors_are_sanitized(monkeypatch):
    install_streams(monkeypatch)

    def broken(*_):
        raise OSError(CANARY)

    monkeypatch.setattr(_cli, "_read_bounded", broken)
    assert _cli.main(BASE) == 2
    assert json.loads(sys.stdout.buffer.getvalue())["error"] == {"code": "input_io_error"}
    install_streams(monkeypatch)
    monkeypatch.setattr(_cli, "_parse", broken)
    assert _cli.main(BASE) == 3
    assert sys.stdout.buffer.getvalue() == b""
    assert sys.stderr.buffer.getvalue() == b"guardtrellis: runtime_error\n"


def test_bootstrap_import_failure_is_outside_cli_and_does_not_read_input(tmp_path):
    package = tmp_path / "guardtrellis"
    package.mkdir()
    (package / "__init__.py").write_text(
        'raise ImportError("Synthetic broken installation")\n', encoding="utf-8"
    )
    code = (
        "import sys, runpy; sys.path.insert(0, sys.argv[1]); "
        "runpy.run_module('guardtrellis', run_name='__main__')"
    )
    with subprocess.Popen(
        [sys.executable, "-I", "-c", code, str(tmp_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        assert process.wait(timeout=10) != 0  # Still-open stdin has no EOF or payload.
        stdout, stderr = process.communicate(timeout=10)
    assert not stdout and b"Synthetic broken installation" in stderr


def test_parent_redirection_can_truncate_source_before_cli_starts(tmp_path):
    source = tmp_path / "fixture.txt"
    source.write_bytes(CANARY.encode())
    # Simulate a shell opening the same file for stdout before starting the command.
    # The CLI has no opportunity to preserve the original bytes at this boundary.
    with source.open("wb") as destination:
        completed = subprocess.run(
            [sys.executable, "-m", "guardtrellis", "check", "--file", str(source), *BASE[2:]],
            stdout=destination,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    assert completed.returncode == 0 and not completed.stderr
    report = source.read_bytes()
    assert CANARY.encode() not in report and json.loads(report)["result"]["action"] == "allow"


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX SIGINT delivery; injected interruption runs everywhere"
)
def test_real_keyboard_interrupt_during_stdin_uses_structured_report_and_130():
    import signal

    code = (
        "import sys\n"
        "from guardtrellis import _cli\n"
        "read = _cli._read_bounded\n"
        "def ready_read(stream):\n"
        "    sys.stderr.buffer.write(b'READY')\n"
        "    sys.stderr.buffer.flush()\n"
        "    return read(stream)\n"
        "_cli._read_bounded = ready_read\n"
        "raise SystemExit(_cli.main())\n"
    )
    with subprocess.Popen(
        [sys.executable, "-c", code, *BASE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        # The marker comes from inside the validated input path, rather than before
        # main() where SIGINT legitimately has a static pre-configuration report.
        assert process.stderr.read(5) == b"READY"
        os.kill(process.pid, signal.SIGINT)
        stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 130 and not stderr
    assert json.loads(stdout)["error"] == {"code": "interrupted"}
