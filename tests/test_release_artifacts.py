"""Release integrity failures must stop promotion before package installation or upload."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.error
import zipfile

import pytest
import yaml

from scripts import release_artifacts as release

COMMIT = "a" * 40
RUN = "12345"
ARTIFACT = "67890"
REPOSITORY = "sahilmathur254/guardtrellis"
REHEARSAL_JOBS = ("candidate", "smoke-candidate", "testpypi", "verify-testpypi", "retain-testpypi")


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


@pytest.fixture
def release_workflow():
    # YAML is a dev-only dependency; workflows are not shipped in the source archive.
    path = release.ROOT / ".github/workflows/release.yml"
    if not path.is_file():
        pytest.skip("Release workflow checks require the repository checkout")
    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]


def artifact_steps(job, action):
    return [
        step["with"]
        for step in job["steps"]
        if step.get("uses", "").startswith(f"actions/{action}-artifact@")
    ]


def job_needs(job):
    needs = job.get("needs", [])
    return {needs} if isinstance(needs, str) else set(needs)


def test_smokes_cannot_produce_authoritative_package_artifacts(release_workflow):
    jobs = release_workflow
    smoke_jobs = {
        name
        for name, job in jobs.items()
        if any("scripts/smoke_dist.py" in step.get("run", "") for step in job["steps"])
    }
    assert smoke_jobs == {"smoke-candidate", "verify-testpypi", "verify-pypi"}
    for name in smoke_jobs:
        job = jobs[name]
        assert job["runs-on"] == "ubuntu-latest"
        assert not artifact_steps(job, "upload")
        assert "environment" not in job
        assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}
    assert artifact_steps(jobs["candidate"], "upload")[0]["name"] == "candidate"
    assert jobs["smoke-candidate"]["needs"] == "candidate"
    assert set(jobs["testpypi"]["needs"]) == {"candidate", "smoke-candidate"}


@pytest.mark.parametrize(
    "producer,upload_id,name",
    [
        ("candidate", "upload-candidate", "candidate"),
        ("promote", "upload-pypi-candidate", "pypi-candidate"),
    ],
)
def test_producers_expose_only_the_original_upload_id(release_workflow, producer, upload_id, name):
    job = release_workflow[producer]
    assert job["outputs"] == {"artifact-id": f"${{{{ steps.{upload_id}.outputs.artifact-id }}}}"}
    upload = next(step for step in job["steps"] if step.get("id") == upload_id)
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"]["name"] == name
    assert upload["with"].get("overwrite", False) is False


@pytest.mark.parametrize(
    "consumer,producer",
    [
        ("smoke-candidate", "candidate"),
        ("testpypi", "candidate"),
        ("verify-testpypi", "candidate"),
        ("retain-testpypi", "candidate"),
        ("pypi", "promote"),
        ("verify-pypi", "promote"),
        ("retain-pypi", "promote"),
    ],
)
def test_same_run_consumers_pin_producer_id_even_if_artifact_names_are_replaced(
    release_workflow, consumer, producer
):
    job = release_workflow[consumer]
    assert producer in job_needs(job)  # Only direct needs expose a producer's outputs.
    [download] = artifact_steps(job, "download")
    assert (
        download["artifact-ids"]
        == f"${{{{ needs.{producer}.outputs.artifact-id || 'missing-producer-artifact-id' }}}}"
    )
    assert download["merge-multiple"] is True  # Keep the existing bundle directory layout.
    assert not {"name", "pattern", "run-id"}.intersection(download)


@pytest.mark.parametrize(
    "job_name,gate,producer,retained",
    [
        ("retain-testpypi", "verify-testpypi", "candidate", "testpypi-verified"),
        ("retain-pypi", "verify-pypi", "promote", "pypi-verified"),
    ],
)
def test_retention_uses_a_clean_runner_after_success(
    release_workflow, job_name, gate, producer, retained
):
    job = release_workflow[job_name]
    assert job_needs(job) == {producer, gate}
    assert "if" not in job  # Preserve the default success-only dependency gate.
    assert job["permissions"] == {}
    assert job["runs-on"] == "ubuntu-latest"
    assert len(job["steps"]) == 2
    download, upload = job["steps"]
    assert download["uses"].startswith("actions/download-artifact@")
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert (
        download["with"]["artifact-ids"]
        == f"${{{{ needs.{producer}.outputs.artifact-id || 'missing-producer-artifact-id' }}}}"
    )
    assert upload["with"]["name"] == retained
    assert download["with"]["path"].rstrip("/") == upload["with"]["path"].rstrip("/")


def test_promotion_uses_original_candidate_from_the_same_rehearsal(release_workflow):
    job = release_workflow["promote"]
    downloads = artifact_steps(job, "download")
    original, retained = downloads
    assert original["artifact-ids"] == "${{ inputs.rehearsal_artifact_id }}"
    assert "name" not in original
    assert original["merge-multiple"] is True
    assert retained["name"] == "testpypi-verified"
    for step in downloads:
        assert step["run-id"] == "${{ inputs.rehearsal_run_id }}"
        assert step["repository"] == "${{ github.repository }}"
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    compare = 'diff --recursive "$RUNNER_TEMP/candidate" "$RUNNER_TEMP/testpypi-verified"'
    verify = 'python scripts/release_artifacts.py verify --bundle "$RUNNER_TEMP/candidate"'
    assert commands.index(compare) < commands.index(verify)
    assert artifact_steps(job, "upload")[0]["path"].rstrip("/") == downloads[0]["path"]
    assert release_workflow["pypi"]["needs"] == "promote"
    assert job_needs(release_workflow["verify-testpypi"]) == {"candidate", "testpypi"}
    assert job_needs(release_workflow["verify-pypi"]) == {"promote", "pypi"}


def test_promotion_validates_manual_ids_before_any_download(release_workflow):
    steps = release_workflow["promote"]["steps"]
    preflight = next(
        step
        for step in steps
        if step.get("name") == "Require a successful rehearsal from the same main commit"
    )
    assert preflight["env"]["REHEARSAL_RUN_ID"] == "${{ inputs.rehearsal_run_id }}"
    assert preflight["env"]["REHEARSAL_ARTIFACT_ID"] == "${{ inputs.rehearsal_artifact_id }}"
    first_download = next(
        step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert steps.index(preflight) < steps.index(first_download)
    assert "${{ inputs." not in preflight["run"]


def test_release_preserves_manual_targets_and_limits_publishing_identity(release_workflow):
    definition = yaml.load(
        (release.ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert set(definition["on"]) == {"pull_request", "workflow_dispatch"}
    inputs = definition["on"]["workflow_dispatch"]["inputs"]
    assert inputs["target"]["options"] == ["validate", "testpypi", "pypi"]
    assert inputs["rehearsal_artifact_id"]["type"] == "string"
    assert inputs["rehearsal_artifact_id"]["required"] == "false"
    assert definition["permissions"] == {"contents": "read"}
    for name, job in release_workflow.items():
        permissions = job.get("permissions", {})
        assert permissions.get("actions") != "write"
        if name in {"testpypi", "pypi"}:
            assert permissions == {"id-token": "write"}
            assert job["environment"]["name"] == name
        else:
            assert "id-token" not in permissions


@pytest.fixture
def promotion_preflight(tmp_path, release_workflow):
    step = next(
        step
        for step in release_workflow["promote"]["steps"]
        if step.get("name") == "Require a successful rehearsal from the same main commit"
    )
    run_metadata = {
        "id": int(RUN),
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch",
        "path": ".github/workflows/release.yml",
        "head_branch": "main",
        "head_sha": COMMIT,
        "repository": {"id": 101, "full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }
    artifact_metadata = {
        "id": int(ARTIFACT),
        "name": "candidate",
        "expired": False,
        "workflow_run": {
            "id": int(RUN),
            "repository_id": 101,
            "head_repository_id": 101,
            "head_branch": "main",
            "head_sha": COMMIT,
        },
    }
    jobs_metadata = {
        "jobs": [
            {"name": name, "run_attempt": 1, "status": "completed", "conclusion": "success"}
            for name in REHEARSAL_JOBS
        ]
        + [
            {"name": name, "run_attempt": 1, "status": "completed", "conclusion": "skipped"}
            for name in ("promote", "pypi", "verify-pypi", "retain-pypi")
        ]
    }
    jobs_metadata["total_count"] = len(jobs_metadata["jobs"])
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "root = pathlib.Path(os.environ['PREFLIGHT_FIXTURES'])\n"
        "endpoint = sys.argv[2]\n"
        "with (root / 'calls').open('a') as calls:\n"
        "    calls.write(endpoint + '\\n')\n"
        f"prefix = 'repos/{REPOSITORY}/'\n"
        f"if endpoint == prefix + 'actions/runs/{RUN}':\n"
        "    print((root / 'run.json').read_text())\n"
        f"elif endpoint == prefix + 'actions/runs/{RUN}/jobs?filter=all&per_page=100':\n"
        "    print((root / 'jobs.json').read_text())\n"
        f"elif endpoint == prefix + 'actions/artifacts/{ARTIFACT}':\n"
        "    print((root / 'artifact.json').read_text())\n"
        "elif endpoint == prefix + 'environments/pypi':\n"
        "    print(json.dumps({'protection_rules': [{'type': 'required_reviewers', "
        "'reviewers': [{'id': 1}]}]}))\n"
        "else:\n"
        "    sys.exit('Unexpected API endpoint: ' + endpoint)\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)

    def invoke(*, run=None, artifact=None, jobs=None, **environment):
        (tmp_path / "run.json").write_text(
            json.dumps(run_metadata if run is None else run), encoding="utf-8"
        )
        (tmp_path / "artifact.json").write_text(
            json.dumps(artifact_metadata if artifact is None else artifact), encoding="utf-8"
        )
        (tmp_path / "jobs.json").write_text(
            json.dumps(jobs_metadata if jobs is None else jobs), encoding="utf-8"
        )
        calls = tmp_path / "calls"
        calls.unlink(missing_ok=True)
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
            env={
                **os.environ,
                "PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                "PREFLIGHT_FIXTURES": str(tmp_path),
                "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_SHA": COMMIT,
                "REHEARSAL_RUN_ID": RUN,
                "REHEARSAL_ARTIFACT_ID": ARTIFACT,
                **environment,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        return result, calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []

    return invoke, run_metadata, artifact_metadata


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
def test_promotion_accepts_only_the_exact_successful_rehearsal_candidate(promotion_preflight):
    invoke, _, _ = promotion_preflight
    result, calls = invoke()
    assert result.returncode == 0, result.stderr
    assert calls == [
        f"repos/{REPOSITORY}/actions/runs/{RUN}",
        f"repos/{REPOSITORY}/actions/runs/{RUN}/jobs?filter=all&per_page=100",
        f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT}",
        f"repos/{REPOSITORY}/environments/pypi",
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
@pytest.mark.parametrize("field", ["REHEARSAL_RUN_ID", "REHEARSAL_ARTIFACT_ID"])
@pytest.mark.parametrize("value", ["", "../1", "1,2", "1\n2", "$(exit 0)", "-1", "1.0", "１２"])
def test_promotion_rejects_nonnumeric_ids_before_calling_github(promotion_preflight, field, value):
    invoke, _, _ = promotion_preflight
    result, calls = invoke(**{field: value})
    assert result.returncode != 0
    assert not calls


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 999),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("event", "pull_request"),
        ("path", ".github/workflows/other.yml"),
        ("head_branch", "other"),
        ("head_sha", "b" * 40),
        ("repository", {"id": 101, "full_name": "other/repo"}),
        ("head_repository", {"full_name": "other/repo"}),
    ],
)
def test_promotion_rejects_untrusted_rehearsal_origins(promotion_preflight, field, value):
    invoke, run, _ = promotion_preflight
    run[field] = value
    result, calls = invoke(run=run)
    assert result.returncode != 0
    assert calls == [f"repos/{REPOSITORY}/actions/runs/{RUN}"]


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
@pytest.mark.parametrize(
    "field,value",
    [
        ("id", 999),
        ("name", "testpypi-verified"),
        ("expired", True),
        ("expired", None),
        ("workflow_run", None),
        ("workflow_run.id", 999),
        ("workflow_run.repository_id", 999),
        ("workflow_run.head_repository_id", 999),
        ("workflow_run.head_branch", "other"),
        ("workflow_run.head_sha", "b" * 40),
    ],
)
def test_promotion_rejects_a_different_or_expired_artifact(promotion_preflight, field, value):
    invoke, _, artifact = promotion_preflight
    if "." in field:
        parent, key = field.split(".")
        artifact[parent][key] = value
    else:
        artifact[field] = value
    result, calls = invoke(artifact=artifact)
    assert result.returncode != 0
    assert calls == [
        f"repos/{REPOSITORY}/actions/runs/{RUN}",
        f"repos/{REPOSITORY}/actions/runs/{RUN}/jobs?filter=all&per_page=100",
        f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT}",
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
@pytest.mark.parametrize("name", REHEARSAL_JOBS)
@pytest.mark.parametrize("defect", ["skipped", "failed", "missing", "incomplete", "duplicate"])
def test_promotion_requires_every_rehearsal_job_to_execute_successfully(
    promotion_preflight, name, defect
):
    invoke, _, _ = promotion_preflight
    jobs = [
        {"name": job, "run_attempt": 1, "status": "completed", "conclusion": "success"}
        for job in REHEARSAL_JOBS
    ]
    selected = next(job for job in jobs if job["name"] == name)
    if defect == "skipped":
        selected["conclusion"] = "skipped"
    elif defect == "failed":
        selected["conclusion"] = "failure"
    elif defect == "missing":
        jobs.remove(selected)
    elif defect == "incomplete":
        selected.update(status="in_progress", conclusion=None)
    else:
        jobs.append(selected.copy())
    result, calls = invoke(jobs={"total_count": len(jobs), "jobs": jobs})
    assert result.returncode != 0
    assert calls == [
        f"repos/{REPOSITORY}/actions/runs/{RUN}",
        f"repos/{REPOSITORY}/actions/runs/{RUN}/jobs?filter=all&per_page=100",
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
@pytest.mark.parametrize("defect", ["validation-only", "overflow", "incomplete-page"])
def test_promotion_rejects_validation_only_or_incomplete_job_evidence(promotion_preflight, defect):
    invoke, _, _ = promotion_preflight
    jobs = [
        {"name": name, "run_attempt": 1, "status": "completed", "conclusion": "success"}
        for name in REHEARSAL_JOBS
    ]
    if defect == "validation-only":
        for job in jobs:
            if job["name"] in {"testpypi", "verify-testpypi", "retain-testpypi"}:
                job["conclusion"] = "skipped"
        total_count = len(jobs)
    elif defect == "overflow":
        jobs.extend(
            {
                "name": f"extra-{index}",
                "run_attempt": 1,
                "status": "completed",
                "conclusion": "success",
            }
            for index in range(96)
        )
        total_count = len(jobs)
    else:
        total_count = len(jobs) + 1
    result, calls = invoke(jobs={"total_count": total_count, "jobs": jobs})
    assert result.returncode != 0
    assert calls == [
        f"repos/{REPOSITORY}/actions/runs/{RUN}",
        f"repos/{REPOSITORY}/actions/runs/{RUN}/jobs?filter=all&per_page=100",
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
@pytest.mark.parametrize("reverse_history", [False, True])
@pytest.mark.parametrize(
    "defect", [None, "latest-failed", "duplicate-latest", "missing-attempt", "nonnumeric-attempt"]
)
def test_promotion_uses_each_jobs_latest_attempt_after_verification_only_recovery(
    promotion_preflight, reverse_history, defect
):
    invoke, _, _ = promotion_preflight
    jobs = [
        {"name": name, "run_attempt": 1, "status": "completed", "conclusion": "success"}
        for name in REHEARSAL_JOBS
    ]
    failed_verification = next(job for job in jobs if job["name"] == "verify-testpypi")
    failed_verification["conclusion"] = "failure"
    next(job for job in jobs if job["name"] == "retain-testpypi")["conclusion"] = "skipped"
    for name in ("verify-testpypi", "retain-testpypi"):
        jobs.append(
            {"name": name, "run_attempt": 2, "status": "completed", "conclusion": "success"}
        )
    latest_verification = jobs[-2]
    if defect == "latest-failed":
        # An old success must never hide a newer failed verification.
        failed_verification["conclusion"] = "success"
        latest_verification["conclusion"] = "failure"
    elif defect == "duplicate-latest":
        jobs.append(latest_verification.copy())
    elif defect == "missing-attempt":
        failed_verification.pop("run_attempt")
    elif defect == "nonnumeric-attempt":
        failed_verification["run_attempt"] = "1"
    if reverse_history:
        jobs.reverse()
    result, calls = invoke(jobs={"total_count": len(jobs), "jobs": jobs})
    assert (result.returncode == 0) == (defect is None), result.stderr
    expected_calls = [
        f"repos/{REPOSITORY}/actions/runs/{RUN}",
        f"repos/{REPOSITORY}/actions/runs/{RUN}/jobs?filter=all&per_page=100",
    ]
    if defect is None:
        expected_calls.extend(
            [
                f"repos/{REPOSITORY}/actions/artifacts/{ARTIFACT}",
                f"repos/{REPOSITORY}/environments/pypi",
            ]
        )
    assert calls == expected_calls


@pytest.mark.skipif(sys.platform == "win32", reason="Executes an Ubuntu workflow shell command")
@pytest.mark.parametrize("change", [None, "package-and-manifest", "missing-retention"])
def test_promotion_compares_original_bytes_even_with_consistent_manifests(
    bundle, tmp_path, release_workflow, change
):
    original = tmp_path / "candidate"
    retained = tmp_path / "testpypi-verified"
    shutil.copytree(bundle, original)
    if change != "missing-retention":
        shutil.copytree(bundle, retained)
    if change == "package-and-manifest":
        wheel = next((retained / "dist").glob("*.whl"))
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("guardtrellis/extra_fixture.txt", "changed package contents")
        manifest = json.loads((retained / "release.json").read_text(encoding="utf-8"))
        manifest["sha256"][wheel.name] = release.digest(wheel)
        (retained / "release.json").write_text(json.dumps(manifest), encoding="utf-8")
        (retained / "SHA256SUMS").write_text(
            "".join(f"{sha}  dist/{name}\n" for name, sha in sorted(manifest["sha256"].items())),
            encoding="utf-8",
        )
        # The existing self-consistency check accepts these coordinated changes.
        release.verify(retained, COMMIT, RUN)
    step = next(
        step
        for step in release_workflow["promote"]["steps"]
        if step.get("run", "").startswith("diff --recursive ")
    )
    result = subprocess.run(
        ["bash", "-e", "-c", step["run"]],
        env={**os.environ, "RUNNER_TEMP": str(tmp_path)},
        capture_output=True,
        check=False,
    )
    assert (result.returncode == 0) == (change is None)
    release.verify(original, COMMIT, RUN)
