"""Dependency-profile checks must fail closed rather than report the wrong versions."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import gemini_profiles as profiles


def test_minimum_profile_constrains_both_declared_direct_floors(tmp_path):
    constraints, expected = profiles.profile_constraints(tmp_path, "minimum")
    requirements = {
        line.split("==")[0]: line.split("==")[1]
        for line in constraints.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert requirements == expected == {"google-genai": "3.0.0", "httpx2": "2.12.0"}


def test_locked_profile_retains_the_exported_transitive_constraints(tmp_path, monkeypatch):
    exported = "google-genai==3.0.0\nhttpx2==2.16.0\ngoogle-auth==2.68.0\n"

    def export(command, *, cwd, check):
        assert cwd == profiles.ROOT and check
        assert "--frozen" in command and "--no-dev" in command
        assert command[command.index("--extra") + 1] == "gemini"
        Path(command[command.index("--output-file") + 1]).write_text(exported, encoding="utf-8")

    monkeypatch.setattr(profiles.subprocess, "run", export)
    constraints, expected = profiles.profile_constraints(tmp_path, "locked")
    assert constraints.read_text(encoding="utf-8") == exported
    assert expected == {"google-genai": "3.0.0", "httpx2": "2.16.0"}


@pytest.mark.parametrize(
    "exported",
    [
        "google-genai==3.0.0\n",
        "httpx2==2.16.0\n",
        "google-genai==3.0.0\nhttpx2==2.12.0\nhttpx2==2.16.0\n",
    ],
)
def test_incomplete_or_ambiguous_lock_cannot_claim_a_tested_profile(
    tmp_path, monkeypatch, exported
):
    def export(command, *, cwd, check):
        Path(command[command.index("--output-file") + 1]).write_text(exported, encoding="utf-8")

    monkeypatch.setattr(profiles.subprocess, "run", export)
    with pytest.raises(ValueError, match="select one direct package version"):
        profiles.profile_constraints(tmp_path, "locked")


def test_unknown_profile_cannot_fall_back_to_unconstrained_install(tmp_path):
    with pytest.raises(ValueError, match="Unknown Gemini"):
        profiles.profile_constraints(tmp_path, "other")
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize(
    "platform, executable", [("nt", "Scripts/python.exe"), ("posix", "bin/python")]
)
def test_fresh_profile_uses_native_python_path_with_spaces_and_unicode(
    tmp_path, monkeypatch, platform, executable
):
    work = tmp_path / "consumer environment 雪"
    work.mkdir()
    commands = []

    def create(command, *, check):
        assert check
        commands.append(command)

    # Replace this module's platform reference, not the process-wide os.name.
    monkeypatch.setattr(profiles, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(profiles.subprocess, "run", create)
    python = profiles.fresh_environment(work)
    assert python == work / "venv" / executable
    assert commands == [["uv", "venv", "--python", profiles.sys.executable, str(work / "venv")]]
