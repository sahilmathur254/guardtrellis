"""The candidate builder must use installed tooling, never resolve a backend."""

import os
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest

UV = shutil.which("uv")
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
        [UV, "venv", "--python", sys.executable, "--system-site-packages", str(environment)],
        check=True,
    )
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    source = next((build_project / "dist").glob("*.tar.gz"))
    # Inherit only the test environment's installed backend, with no index or cache
    # available to resolve an isolated replacement during consumer installation.
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
