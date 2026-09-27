"""Release integrity failures must stop promotion before package installation or upload."""

import hashlib
import io
import json
import shutil
import tarfile
import tomllib
import urllib.error
import zipfile

import pytest

from scripts import release_artifacts as release

COMMIT = "a" * 40
RUN = "12345"


@pytest.fixture
def release_source(tmp_path, monkeypatch):
    root = tmp_path / "source"
    for name in (
        "pyproject.toml",
        "README.md",
        "uv.lock",
        "CHANGELOG.md",
        "src/guardtrellis/__init__.py",
    ):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(release.ROOT / name, target)
    monkeypatch.setattr(release, "ROOT", root)
    return root


def test_sync_preserves_surrounding_content_and_is_idempotent(release_source):
    project = release_source / "pyproject.toml"
    old = release.project_version()
    project.write_text(
        project.read_text(encoding="utf-8").replace(f'version = "{old}"', 'version = "0.2.0rc1"'),
        encoding="utf-8",
    )
    module = release_source / "src/guardtrellis/__init__.py"
    original = module.read_text(encoding="utf-8")
    readme = release_source / "README.md"
    start, end = release.readme_span(readme.read_text(encoding="utf-8"))
    before, after = (
        readme.read_text(encoding="utf-8")[:start],
        readme.read_text(encoding="utf-8")[end:],
    )
    assert release.sync() == "0.2.0rc1"
    assert module.read_text(encoding="utf-8") == original.replace(f'"{old}"', '"0.2.0rc1"')
    assert readme.read_text(encoding="utf-8").startswith(before)
    assert readme.read_text(encoding="utf-8").endswith(after)
    assert "guardtrellis==0.2.0rc1" in readme.read_text(encoding="utf-8")
    assert "guardtrellis[gemini]==0.2.0rc1" in readme.read_text(encoding="utf-8")
    first = (module.read_bytes(), readme.read_bytes())
    release.sync()
    assert first == (module.read_bytes(), readme.read_bytes())
    # Sync does not invent release notes or silently rewrite the dependency lock.
    with pytest.raises(ValueError, match="lockfile"):
        release.project_version()


@pytest.mark.parametrize("defect", ["missing", "duplicate", "reversed", "module"])
def test_sync_rejects_ambiguous_targets_without_partial_writes(release_source, defect):
    readme = release_source / "README.md"
    module = release_source / "src/guardtrellis/__init__.py"
    module.write_text(
        module.read_text(encoding="utf-8").replace(release.project_version(), "0.0.0"),
        encoding="utf-8",
    )
    if defect == "missing":
        readme.write_text(
            readme.read_text(encoding="utf-8").replace(release.README_END, ""), encoding="utf-8"
        )
    elif defect == "duplicate":
        readme.write_text(
            readme.read_text(encoding="utf-8") + release.README_START, encoding="utf-8"
        )
    elif defect == "reversed":
        readme.write_text(release.README_END + release.README_START, encoding="utf-8")
    else:
        module.write_text(
            module.read_text(encoding="utf-8") + '\n__version__ = "0.1.0a99"\n', encoding="utf-8"
        )
    before = (readme.read_bytes(), module.read_bytes())
    with pytest.raises(ValueError):
        release.sync()
    assert before == (readme.read_bytes(), module.read_bytes())


@pytest.mark.parametrize(
    "name,old,new,reason",
    [
        ("src/guardtrellis/__init__.py", "VERSION", "0.1.0a99", "module versions"),
        ("README.md", "**Version:", "**Candidate:", "release block"),
        ("uv.lock", "VERSION", "0.1.0a99", "lockfile"),
        ("CHANGELOG.md", "## VERSION", "## Unreleased", "changelog"),
    ],
)
def test_source_check_rejects_version_drift(release_source, name, old, new, reason):
    version = release.project_version()
    path = release_source / name
    path.write_text(
        path.read_text(encoding="utf-8").replace(old.replace("VERSION", version), new),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=reason):
        release.project_version()


def test_readme_install_pins_outside_the_generated_block_must_also_agree(release_source):
    readme = release_source / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8") + "\nInstall 'guardtrellis[gemini]==0.1.0a99'.\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="stale installation pin"):
        release.project_version()


def index_metadata(files):
    return {
        "info": {
            "name": "guardtrellis",
            "version": release.project_version(),
            "description": (release.ROOT / "README.md").read_text(encoding="utf-8"),
            "description_content_type": "text/markdown",
        },
        "urls": files,
    }


@pytest.fixture
def bundle(tmp_path):
    version = release.project_version()
    project = tomllib.loads((release.ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    metadata = (
        f"Metadata-Version: 2.4\nName: guardtrellis\nVersion: {version}\n"
        "License-Expression: Apache-2.0\nRequires-Python: <3.15,>=3.11\n"
        + "".join(f"Project-URL: {name}, {url}\n" for name, url in project["urls"].items())
        + "Description-Content-Type: text/markdown\n\n"
        + (release.ROOT / "README.md").read_text(encoding="utf-8")
    ).encode()
    source = f"__version__ = {version!r}\n".encode()
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / ".gitignore").write_text("*", encoding="utf-8")
    with zipfile.ZipFile(dist / f"guardtrellis-{version}-py3-none-any.whl", "w") as archive:
        archive.writestr(f"guardtrellis-{version}.dist-info/METADATA", metadata)
        archive.writestr("guardtrellis/__init__.py", source)
        archive.writestr("guardtrellis/py.typed", "")
        archive.writestr(f"guardtrellis-{version}.dist-info/licenses/LICENSE", "fixture")
    with tarfile.open(dist / f"guardtrellis-{version}.tar.gz", "w:gz") as archive:
        files = {
            "PKG-INFO": metadata,
            "src/guardtrellis/__init__.py": source,
            **{
                name: (release.ROOT / name).read_bytes()
                for name in ("README.md", "pyproject.toml", "uv.lock")
            },
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


@pytest.mark.parametrize(
    "member", ["METADATA", "PKG-INFO", "README.md", "pyproject.toml", "uv.lock"]
)
def test_stale_packaged_description_or_source_version_is_rejected(bundle, member):
    version = release.project_version()

    def stale(name, data):
        if name.endswith("/" + member):
            if member in ("METADATA", "PKG-INFO", "README.md"):
                # Leave distribution/module versions correct, reproducing the a2 defect.
                return data.replace(f"guardtrellis=={version}".encode(), b"guardtrellis==0.1.0a1")
            return data.replace(version.encode(), b"0.1.0a99")
        return data

    if member == "METADATA":
        file = next((bundle / "dist").glob("*.whl"))
        with zipfile.ZipFile(file) as archive:
            files = {name: stale(name, archive.read(name)) for name in archive.namelist()}
        with zipfile.ZipFile(file, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
    else:
        file = next((bundle / "dist").glob("*.tar.gz"))
        with tarfile.open(file) as archive:
            files = {
                m.name: stale(m.name, archive.extractfile(m).read()) for m in archive.getmembers()
            }
        with tarfile.open(file, "w:gz") as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
    with pytest.raises(ValueError, match="description|project metadata|lockfile"):
        release.check_metadata(file, version)


def test_unreviewed_extra_distribution_is_rejected(bundle):
    (bundle / "dist" / "old-release.whl").write_bytes(b"old")
    with pytest.raises(ValueError, match="directory"):
        release.verify(bundle, COMMIT)


def test_publisher_checksum_list_must_match_the_manifest(bundle):
    (bundle / "SHA256SUMS").write_text("changed\n", encoding="utf-8")
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
            return json.dumps(index_metadata(files)).encode()
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
    monkeypatch.setattr(release, "read_url", lambda *_: json.dumps(index_metadata(files)).encode())
    with pytest.raises(ValueError):
        release.index_files("pypi", manifest["version"], manifest["sha256"])


@pytest.mark.parametrize("field", ["name", "version", "description", "description_content_type"])
def test_index_metadata_must_match_even_when_artifact_hashes_agree(bundle, monkeypatch, field):
    manifest = release.verify(bundle, COMMIT)
    files = [
        {
            "filename": name,
            "url": f"https://files.pythonhosted.org/{name}",
            "digests": {"sha256": sha},
        }
        for name, sha in manifest["sha256"].items()
    ]
    metadata = index_metadata(files)
    metadata["info"][field] = "stale metadata"
    monkeypatch.setattr(release, "read_url", lambda *_: json.dumps(metadata).encode())
    with pytest.raises(ValueError, match="Index project|Release description"):
        release.index_files("pypi", manifest["version"], manifest["sha256"])


def test_description_comparison_accepts_windows_newlines_only():
    readme = (release.ROOT / "README.md").read_text(encoding="utf-8")
    release.check_description(readme.replace("\n", "\r\n") + "\r\n", "text/markdown")
    with pytest.raises(ValueError, match="description"):
        release.check_description(readme, "text/plain")


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
