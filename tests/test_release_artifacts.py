"""Release integrity failures must stop promotion before package installation or upload."""

import hashlib
import io
import json
import tarfile
import tomllib
import urllib.error
import zipfile

import pytest

from scripts import release_artifacts as release

COMMIT = "a" * 40
RUN = "12345"


@pytest.fixture
def bundle(tmp_path):
    version = release.project_version()
    project = tomllib.loads((release.ROOT / "pyproject.toml").read_text())["project"]
    metadata = (
        f"Metadata-Version: 2.4\nName: guardtrellis\nVersion: {version}\n"
        "License-Expression: Apache-2.0\nRequires-Python: <3.15,>=3.11\n"
        + "".join(f"Project-URL: {name}, {url}\n" for name, url in project["urls"].items())
    ).encode()
    source = f"__version__ = {version!r}\n".encode()
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / ".gitignore").write_text("*")
    with zipfile.ZipFile(dist / f"guardtrellis-{version}-py3-none-any.whl", "w") as archive:
        archive.writestr(f"guardtrellis-{version}.dist-info/METADATA", metadata)
        archive.writestr("guardtrellis/__init__.py", source)
        archive.writestr("guardtrellis/py.typed", "")
        archive.writestr(f"guardtrellis-{version}.dist-info/licenses/LICENSE", "fixture")
    with tarfile.open(dist / f"guardtrellis-{version}.tar.gz", "w:gz") as archive:
        files = {
            "PKG-INFO": metadata,
            "src/guardtrellis/__init__.py": source,
            **dict.fromkeys(
                ("LICENSE", "CHANGELOG.md", "ROADMAP.md", "docs/releasing.md"), b"fixture"
            ),
        }
        for name, data in files.items():
            member = tarfile.TarInfo(f"guardtrellis-{version}/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    destination = tmp_path / "bundle"
    release.create(destination, dist, COMMIT, RUN)
    return destination


def test_matching_bundle_preserves_the_original_distributions(bundle):
    manifest = release.verify(bundle, COMMIT, RUN)
    assert manifest["version"] == release.project_version()
    for name, expected in manifest["sha256"].items():
        assert hashlib.sha256((bundle / "dist" / name).read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("commit,run_id", [("b" * 40, RUN), (COMMIT, "999"), ("main", RUN)])
def test_promotion_rejects_a_different_commit_or_run(bundle, commit, run_id):
    with pytest.raises(ValueError, match="manifest"):
        release.verify(bundle, commit, run_id)


def test_corrupted_artifact_is_rejected(bundle):
    next((bundle / "dist").glob("*.whl")).write_bytes(b"modified distribution")
    with pytest.raises(ValueError, match="integrity"):
        release.verify(bundle, COMMIT)


def test_packaged_module_version_must_match_metadata(bundle):
    wheel = next((bundle / "dist").glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files["guardtrellis/__init__.py"] = b"__version__ = '0.1.0a99'\n"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    with pytest.raises(ValueError, match="Packaged module version"):
        release.check_metadata(wheel, release.project_version())


def test_unreviewed_extra_distribution_is_rejected(bundle):
    (bundle / "dist" / "old-release.whl").write_bytes(b"old")
    with pytest.raises(ValueError, match="directory"):
        release.verify(bundle, COMMIT)


def test_publisher_checksum_list_must_match_the_manifest(bundle):
    (bundle / "SHA256SUMS").write_text("changed\n")
    with pytest.raises(ValueError, match="Checksum"):
        release.verify(bundle, COMMIT)


def test_index_downloads_are_verified_before_they_are_installed(bundle, tmp_path, monkeypatch):
    manifest = release.verify(bundle, COMMIT)
    files = [
        {
            "filename": name,
            "url": f"https://test-files.pythonhosted.org/{name}",
            "digests": {"sha256": sha},
        }
        for name, sha in manifest["sha256"].items()
    ]

    def read_url(url, limit):
        if url.endswith("/json"):
            return json.dumps({"urls": files}).encode()
        return (bundle / "dist" / url.rsplit("/", 1)[1]).read_bytes()

    monkeypatch.setattr(release, "read_url", read_url)
    destination = tmp_path / "downloaded"
    release.fetch(bundle, COMMIT, "testpypi", destination)
    for name, sha in manifest["sha256"].items():
        assert release.digest(destination / name) == sha


@pytest.mark.parametrize("defect", ["hash", "host", "yanked", "extra", "duplicate"])
def test_index_mismatches_fail_without_installation(bundle, monkeypatch, defect):
    manifest = release.verify(bundle, COMMIT)
    files = [
        {
            "filename": name,
            "url": f"https://files.pythonhosted.org/{name}",
            "digests": {"sha256": sha},
        }
        for name, sha in manifest["sha256"].items()
    ]
    if defect == "hash":
        files[0]["digests"]["sha256"] = "0" * 64
    elif defect == "host":
        files[0]["url"] = "https://unexpected.example/package.whl"
    elif defect == "yanked":
        files[0]["yanked"] = True
    elif defect == "extra":
        files.append({"filename": "other.whl"})
    else:
        files.append(files[0])
    monkeypatch.setattr(release, "read_url", lambda *_: json.dumps({"urls": files}).encode())
    with pytest.raises(ValueError):
        release.index_files("pypi", manifest["version"], manifest["sha256"])


def test_index_visibility_retries_are_bounded(monkeypatch):
    attempts = []

    def missing(url, limit):
        attempts.append(url)
        raise urllib.error.HTTPError(url, 404, "Not visible yet", {}, None)

    monkeypatch.setattr(release, "read_url", missing)
    monkeypatch.setattr(release.time, "sleep", lambda _: None)
    with pytest.raises(ValueError, match="did not appear"):
        release.index_files("testpypi", "0.1.0a1", {"file.whl": "0" * 64})
    assert len(attempts) == 6


def test_downloaded_bytes_must_match_the_index_and_manifest(bundle, tmp_path, monkeypatch):
    manifest = release.verify(bundle, COMMIT)
    files = [
        {
            "filename": name,
            "url": f"https://files.pythonhosted.org/{name}",
            "digests": {"sha256": sha},
        }
        for name, sha in manifest["sha256"].items()
    ]
    monkeypatch.setattr(release, "index_files", lambda *_: files)
    monkeypatch.setattr(release, "read_url", lambda *_: b"corrupt download")
    with pytest.raises(ValueError, match="Downloaded artifact"):
        release.fetch(bundle, COMMIT, "pypi", tmp_path / "downloaded")
