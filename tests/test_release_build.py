"""The candidate builder must use installed tooling, never resolve a backend."""

import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

UV = shutil.which("uv")
ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(UV is None, reason="uv is required for build integration tests")


@pytest.fixture
def build_project(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    # Use the public requirement, including versions newer than the installed backend.
    (source / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["hatchling>=1.27,<2"]\n'
        'build-backend = "hatchling.build"\n'
        '[project]\nname = "build_probe"\nversion = "1.0.0"\n'
    )
    package = source / "build_probe"
    package.mkdir()
    (package / "__init__.py").write_text('VALUE = "reviewed source"\n')
    return source


def build(source, python, cache):
    return subprocess.run(
        [
            UV,
            "build",
            "--offline",
            "--no-build-isolation",
            "--python",
            str(python),
            "--cache-dir",
            str(cache),
        ],
        cwd=source,
        # No index can satisfy the requirement, even if a newer backend exists upstream.
        env={**os.environ, "UV_INDEX_URL": "http://127.0.0.1:1/simple"},
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_offline_build_uses_preinstalled_backend_and_preserves_source(build_project, tmp_path):
    pytest.importorskip("hatchling")
    result = build(build_project, sys.executable, tmp_path / "empty-cache")
    assert result.returncode == 0, result.stderr
    expected = (build_project / "build_probe/__init__.py").read_bytes()
    with zipfile.ZipFile(next((build_project / "dist").glob("*.whl"))) as archive:
        assert archive.read("build_probe/__init__.py") == expected
    with tarfile.open(next((build_project / "dist").glob("*.tar.gz"))) as archive:
        member = archive.extractfile("build_probe-1.0.0/build_probe/__init__.py")
        assert member is not None and member.read() == expected


def test_missing_backend_fails_without_resolving_a_replacement(build_project, tmp_path):
    environment = tmp_path / "empty-venv"
    subprocess.run([UV, "venv", "--python", sys.executable, str(environment)], check=True)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    result = build(build_project, python, tmp_path / "empty-cache")
    assert result.returncode != 0
    assert "hatchling" in result.stderr
    assert not list((build_project / "dist").glob("*.whl"))
    assert not list((build_project / "dist").glob("*.tar.gz"))


def test_sdist_install_does_not_resolve_a_second_backend(build_project, tmp_path):
    pytest.importorskip("hatchling")
    result = build(build_project, sys.executable, tmp_path / "build-cache")
    assert result.returncode == 0, result.stderr
    environment = tmp_path / "consumer-venv"
    subprocess.run(
        [UV, "venv", "--python", sys.executable, str(environment)],
        check=True,
    )
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    requirements = tmp_path / "build-requirements.txt"
    subprocess.run(
        [
            UV,
            "export",
            "--locked",
            "--only-group",
            "build",
            "--no-emit-project",
            "--output-file",
            str(requirements),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=60,
    )
    # A nested venv's system-site-packages exposes the base interpreter, not the
    # outer test venv. Seed the consumer online, exactly as the production smoke
    # does: uv sync's locked downloads do not populate registry metadata for pip.
    subprocess.run(
        [
            UV,
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "--index-url",
            "https://pypi.org/simple",
            "--cache-dir",
            str(tmp_path / "bootstrap-cache"),
            "--requirements",
            str(requirements),
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    source = next((build_project / "dist").glob("*.tar.gz"))
    # The installed, hash-checked backend is available; the empty install cache
    # and offline mode prevent resolution of an isolated replacement.
    installed = subprocess.run(
        [
            UV,
            "pip",
            "install",
            "--python",
            str(python),
            "--offline",
            "--no-deps",
            "--no-build-isolation-package",
            "build-probe",
            "--cache-dir",
            str(tmp_path / "install-cache"),
            str(source),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert installed.returncode == 0, installed.stderr
    subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            'import build_probe; assert build_probe.VALUE == "reviewed source"',
        ],
        cwd=tmp_path,
        check=True,
    )


def test_build_bootstrap_rejects_incorrect_artifact_hashes(tmp_path):
    environment = tmp_path / "consumer-venv"
    subprocess.run([UV, "venv", "--python", sys.executable, str(environment)], check=True)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    requirements = tmp_path / "build-requirements.txt"
    subprocess.run(
        [
            UV,
            "export",
            "--locked",
            "--only-group",
            "build",
            "--no-emit-project",
            "--output-file",
            str(requirements),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=60,
    )
    original = requirements.read_text(encoding="utf-8")
    modified, hashes = re.subn(r"sha256:[a-f0-9]{64}", "sha256:" + "0" * 64, original)
    assert hashes > 0
    requirements.write_text(modified, encoding="utf-8")
    result = subprocess.run(
        [
            UV,
            "pip",
            "install",
            "--python",
            str(python),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "--index-url",
            "https://pypi.org/simple",
            "--cache-dir",
            str(tmp_path / "bootstrap-cache"),
            "--requirements",
            str(requirements),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "hash mismatch" in result.stderr.lower()
