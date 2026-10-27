"""Bounded local policy checks. Reports deliberately never serialize checked text."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import BinaryIO, Literal, cast

from . import Action, Guard, PIIScanner, Result, SecretScanner, Stage, __version__

MAX_BYTES = 400_000
MAX_CHARS = 100_000
MAX_REPORT_BYTES = 128 * 1024
_HELP = b"""Usage: guardtrellis check (--file PATH | --stdin)
                         --stage STAGE --policy POLICY [OPTIONS]

Check one explicit UTF-8 source using local SDK scanners. No network or file rewriting.
  --stage input|output|retrieval|tool       Required text-scanning stage
  --policy secrets|privacy                Block secrets; privacy also redacts PII
  --connection-strings                    Opt in to supported credential URIs
  --phone-mode contiguous|formatted        Privacy only; default contiguous
  --format text|json                      Metadata format; default text
  --output metadata|checked-text           Default metadata; checked text requires a pipe/file
  --help, -h                              Show help without reading input
  --version                               Show SDK version without reading input

Example: guardtrellis check --stdin --stage retrieval --policy privacy --format json
Exit: 0 accepted/help/version, 1 blocked, 2 invalid configuration/input, 3 failure, 130 interrupted.
Consume checked stdout only after exit 0. Never redirect either stream to the input file.
"""


class _Failure(Exception):
    def __init__(self, code: str, status: int = 2):
        self.code = code
        self.status = status


class _OutputFailure(Exception):
    pass


@dataclass(frozen=True)
class _Config:
    file: str | None
    stage: Stage
    policy: str
    connection_strings: bool
    phone_mode: str | None
    format: str
    output: str


def _parse(argv: Sequence[str]) -> _Config | bytes:
    if list(argv) in (["--help"], ["-h"], ["check", "--help"], ["check", "-h"]):
        return _HELP
    if list(argv) in (["--version"], ["check", "--version"]):
        return f"guardtrellis {__version__}\n".encode("ascii")
    if not argv or argv[0] != "check":
        raise _Failure("invalid_command")
    flags = {"--stdin", "--connection-strings"}
    valued = {"--file", "--stage", "--policy", "--phone-mode", "--format", "--output"}
    options: dict[str, str | bool] = {}
    index = 1
    while index < len(argv):
        option = argv[index]
        # Support the conventional --name=value form without prefix matching.
        name, separator, value = option.partition("=")
        if name not in flags | valued or name in options or (separator and name in flags):
            raise _Failure("invalid_command")
        if name in flags:
            options[name] = True
        else:
            if not separator:
                index += 1
                if index >= len(argv) or argv[index].startswith("--"):
                    raise _Failure("invalid_command")
                value = argv[index]
            options[name] = value
        index += 1
    if ("--file" in options) == ("--stdin" in options) or not {
        "--stage",
        "--policy",
    } <= options.keys():
        raise _Failure("invalid_command")
    choices = {
        "--stage": {item.value for item in Stage},
        "--policy": {"secrets", "privacy"},
        "--phone-mode": {"contiguous", "formatted"},
        "--format": {"text", "json"},
        "--output": {"metadata", "checked-text"},
    }
    if any(name in options and options[name] not in values for name, values in choices.items()):
        raise _Failure("invalid_configuration")
    policy = str(options["--policy"])
    if policy == "secrets" and "--phone-mode" in options:
        raise _Failure("invalid_configuration")
    return _Config(
        cast(str | None, options.get("--file")),
        Stage(str(options["--stage"])),
        policy,
        "--connection-strings" in options,
        str(options.get("--phone-mode", "contiguous")) if policy == "privacy" else None,
        str(options.get("--format", "text")),
        str(options.get("--output", "metadata")),
    )


def _binary(channel: str) -> BinaryIO:
    return cast(BinaryIO, getattr(sys, channel).buffer)


def _quarantine(channel: str) -> None:
    """Keep a failed stdio buffer from flushing again at interpreter shutdown."""
    stream = getattr(sys, channel)
    try:
        descriptor = stream.fileno()
        if descriptor == {"stdout": 1, "stderr": 2}[channel]:
            sink = os.open(os.devnull, os.O_WRONLY)
            # If the standard descriptor was closed, open() may reuse that number.
            # Keep the replacement open in that case, including for __stdout__/__stderr__.
            if sink != descriptor:
                try:
                    os.dup2(sink, descriptor)
                finally:
                    os.close(sink)
    except Exception:
        pass
    # A substitute also handles replaced streams without a usable file descriptor.
    setattr(sys, channel, io.StringIO())


class _Output:
    def __init__(self) -> None:
        self.started: set[str] = set()
        self.failed: set[str] = set()

    def fail(self, channel: str) -> None:
        self.failed.add(channel)
        _quarantine(channel)

    def write(self, channel: str, payload: bytes) -> None:
        self.started.add(channel)
        try:
            stream = _binary(channel)
            offset = 0
            while offset < len(payload):
                count = stream.write(payload[offset:])
                if type(count) is not int or not 0 < count <= len(payload) - offset:
                    raise OSError
                offset += count
            stream.flush()
        except KeyboardInterrupt:
            self.fail(channel)
            raise
        except Exception:
            self.fail(channel)
            raise _OutputFailure from None

    def emit(self, report: bytes, payload: bytes | None, channel: str, status: int) -> int:
        try:
            self.write(channel, report)
            if payload is not None:
                self.write("stdout", payload)
        except KeyboardInterrupt:
            return 130
        except _OutputFailure:
            if "stderr" not in self.started and "stderr" not in self.failed:
                try:
                    self.write("stderr", b"guardtrellis: output_io_error\n")
                except KeyboardInterrupt:
                    return 130
                except _OutputFailure:
                    pass
            return 130 if status == 130 else 3
        return status


def _read_bounded(stream: BinaryIO) -> str:
    chunks: list[bytes] = []
    size = 0
    while size <= MAX_BYTES:
        chunk = stream.read(min(65_536, MAX_BYTES + 1 - size))
        if not isinstance(chunk, bytes):
            raise OSError
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    if size > MAX_BYTES:
        raise _Failure("input_limit_exceeded")
    try:
        text = b"".join(chunks).decode("utf-8", errors="strict")
    except UnicodeError:
        raise _Failure("invalid_encoding") from None
    if len(text) > MAX_CHARS:
        raise _Failure("input_limit_exceeded")
    return text


def _read(config: _Config) -> str:
    try:
        if config.file is None:
            if sys.stdin.isatty():
                raise _Failure("invalid_source")
            return _read_bounded(_binary("stdin"))
        if not stat.S_ISREG(os.stat(config.file).st_mode):
            raise _Failure("invalid_source")
        with open(config.file, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise _Failure("invalid_source")
            return _read_bounded(stream)
    except (OSError, ValueError, AttributeError):
        raise _Failure("input_io_error") from None


def _scan(config: _Config, text: str) -> Result:
    secret = SecretScanner(action=Action.BLOCK, connection_strings=config.connection_strings)
    scanners: list[SecretScanner | PIIScanner] = [secret]
    if config.policy == "privacy":
        scanners.append(
            PIIScanner(
                action=Action.REDACT,
                phone_mode=cast(Literal["contiguous", "formatted"], config.phone_mode),
            )
        )
    guard = Guard(
        max_chars=MAX_CHARS,
        input_scanners=scanners if config.stage == Stage.INPUT else (),
        output_scanners=scanners if config.stage == Stage.OUTPUT else (),
        retrieval_scanners=scanners if config.stage == Stage.RETRIEVAL else (),
        tool_scanners=scanners if config.stage == Stage.TOOL else (),
    )
    return guard.scan(text, stage=config.stage)


def _report(config: _Config, result: Result | None, error: str | None) -> bytes:
    if config.format == "json":
        body = {
            "report_version": 1,
            "sdk_version": __version__,
            "stage": config.stage.value,
            "policy": config.policy,
            "options": {
                "connection_strings": config.connection_strings,
                "phone_mode": config.phone_mode,
            },
            "result": result.diagnostics() if result is not None else None,
            "error": {"code": error} if error is not None else None,
        }
        report = (json.dumps(body, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
    elif result is not None:
        codes = ",".join(item.code for item in result.findings)
        report = (
            f"stage={config.stage.value} action={result.action.value} "
            f"findings={len(result.findings)} codes={codes}\n"
        ).encode()
    else:
        report = f"stage={config.stage.value} error={error}\n".encode("ascii")
    if len(report) > MAX_REPORT_BYTES:
        raise _Failure("report_limit_exceeded", 3)
    return report


def _prepare(config: _Config) -> tuple[bytes, bytes | None, int]:
    try:
        result = _scan(config, _read(config))
        payload = None
        if result.accepted and config.output == "checked-text":
            text = result.require_text()
            payload = text.encode("utf-8", errors="strict")
            if len(text) > MAX_CHARS or len(payload) > MAX_BYTES:
                raise _Failure("checked_output_limit_exceeded", 3)
        status = 3 if result.action == Action.ERROR else (0 if result.accepted else 1)
        return _report(config, result, None), payload, status
    except _Failure as error:
        code, status = error.code, error.status
    except KeyboardInterrupt:
        code, status = "interrupted", 130
    except Exception:
        code, status = "runtime_error", 3
    return _report(config, None, code), None, status


def main(argv: Sequence[str] | None = None) -> int:
    """Return a handled CLI status; both launchers use this entry boundary."""
    output = _Output()
    try:
        config = _parse(sys.argv[1:] if argv is None else argv)
        if isinstance(config, bytes):
            return output.emit(config, None, "stdout", 0)
        if config.output == "checked-text":
            try:
                terminal = sys.stdout.isatty()
            except KeyboardInterrupt:
                raise
            except Exception:
                output.fail("stdout")
                raise _Failure("output_io_error", 3) from None
            if terminal:
                raise _Failure("invalid_configuration")
    except _Failure as error:
        return output.emit(
            f"guardtrellis: {error.code}\n".encode("ascii"), None, "stderr", error.status
        )
    except KeyboardInterrupt:
        return output.emit(b"guardtrellis: interrupted\n", None, "stderr", 130)
    except Exception:
        return output.emit(b"guardtrellis: runtime_error\n", None, "stderr", 3)
    channel = "stderr" if config.output == "checked-text" else "stdout"
    try:
        report, payload, status = _prepare(config)
    except KeyboardInterrupt:
        return output.emit(b"guardtrellis: interrupted\n", None, channel, 130)
    except Exception:
        return output.emit(b"guardtrellis: runtime_error\n", None, channel, 3)
    return output.emit(report, payload, channel, status)
