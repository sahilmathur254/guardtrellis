"""Record, verify, and download the exact distributions used for an alpha release.

This script never publishes. Index downloads use fixed PyPI endpoints and must match
the manifest from a trusted workflow run before the installation smoke can use them.
"""

import argparse
import ast
import hashlib
import json
import re
import shutil
import tarfile
import time
import tomllib
import urllib.error
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
INDEXES = {
    "testpypi": ("https://test.pypi.org", "test-files.pythonhosted.org"),
    "pypi": ("https://pypi.org", "files.pythonhosted.org"),
}


def module_version(source: str) -> str:
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise ValueError("Module version is missing")


def project_version() -> str:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    version = project["version"]
    if project["name"] != "guardtrellis" or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", version
    ):
        raise ValueError("Unexpected project name or release version")
    if module_version((ROOT / "src/guardtrellis/__init__.py").read_text()) != version:
        raise ValueError("Project and module versions differ")
    return version


def artifact_names(version: str) -> set[str]:
    return {f"guardtrellis-{version}-py3-none-any.whl", f"guardtrellis-{version}.tar.gz"}


def digest(file: Path) -> str:
    return hashlib.sha256(file.read_bytes()).hexdigest()


def check_metadata(file: Path, version: str) -> None:
    if file.suffix == ".whl":
        with zipfile.ZipFile(file) as archive:
            metadata = archive.read(f"guardtrellis-{version}.dist-info/METADATA")
            source = archive.read("guardtrellis/__init__.py")
            archive.read("guardtrellis/py.typed")
            archive.read(f"guardtrellis-{version}.dist-info/licenses/LICENSE")
    else:
        with tarfile.open(file) as archive:
            prefix = f"guardtrellis-{version}"

            def read(name: str) -> bytes:
                member = archive.extractfile(f"{prefix}/{name}")
                if member is None:
                    raise ValueError(f"Missing source archive file: {name}")
                return member.read()

            metadata = read("PKG-INFO")
            source = read("src/guardtrellis/__init__.py")
            for name in ("LICENSE", "CHANGELOG.md", "ROADMAP.md", "docs/releasing.md"):
                read(name)
    parsed = BytesParser().parsebytes(metadata)
    if (
        parsed["Name"] != "guardtrellis"
        or parsed["Version"] != version
        or parsed["Metadata-Version"] != "2.4"
    ):
        raise ValueError("Distribution metadata has the wrong name or version")
    if module_version(source.decode()) != version:
        raise ValueError("Packaged module version differs from distribution metadata")
    if parsed["License-Expression"] != "Apache-2.0" or set(
        parsed.get("Requires-Python", "").split(",")
    ) != {">=3.11", "<3.15"}:
        raise ValueError("Distribution license or Python requirement differs from the release")
    urls = dict(value.split(", ", 1) for value in parsed.get_all("Project-URL", []))
    expected_urls = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["urls"]
    if urls != expected_urls:
        raise ValueError("Distribution project URLs differ from the source metadata")


def verify(bundle: Path, commit: str, run_id: str | None = None) -> dict:
    manifest = json.loads((bundle / "release.json").read_text())
    version = project_version()
    if (
        manifest.get("schema") != 1
        or manifest.get("project") != "guardtrellis"
        or manifest.get("version") != version
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or manifest.get("commit") != commit
        or not re.fullmatch(r"[0-9]+", str(manifest.get("run_id", "")))
        or (run_id is not None and manifest["run_id"] != run_id)
    ):
        raise ValueError("Release manifest does not match the expected source/run/version")
    expected = artifact_names(version)
    if set(manifest["sha256"]) != expected:
        raise ValueError("Manifest must identify exactly the expected wheel and source archive")
    checksums = "".join(f"{sha}  dist/{name}\n" for name, sha in sorted(manifest["sha256"].items()))
    if (bundle / "SHA256SUMS").read_text() != checksums:
        raise ValueError("Checksum list differs from the release manifest")
    files = list((bundle / "dist").iterdir())
    if {file.name for file in files} != expected:
        raise ValueError("Distribution directory differs from the manifest")
    for file in files:
        if not file.is_file() or file.is_symlink() or digest(file) != manifest["sha256"][file.name]:
            raise ValueError(f"Artifact integrity check failed: {file.name}")
        check_metadata(file, version)
    return manifest


def create(bundle: Path, dist: Path, commit: str, run_id: str) -> dict:
    version = project_version()
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("Expected a full commit SHA and numeric workflow run ID")
    # uv creates this bookkeeping file alongside distributions; it is not a package file.
    files = [file for file in dist.iterdir() if file.name != ".gitignore"]
    if {file.name for file in files} != artifact_names(version):
        raise ValueError(
            "Build directory must contain exactly one current wheel and source archive"
        )
    for file in files:
        if file.is_symlink() or not file.is_file():
            raise ValueError("Distribution must be a regular file")
        check_metadata(file, version)
    bundle.mkdir(parents=True, exist_ok=False)
    (bundle / "dist").mkdir()
    for file in files:
        shutil.copyfile(file, bundle / "dist" / file.name)
    manifest = {
        "schema": 1,
        "project": "guardtrellis",
        "version": version,
        "commit": commit,
        "run_id": run_id,
        "sha256": {file.name: digest(file) for file in sorted(files)},
    }
    (bundle / "release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (bundle / "SHA256SUMS").write_text(
        "".join(f"{sha}  dist/{name}\n" for name, sha in manifest["sha256"].items())
    )
    return verify(bundle, commit, run_id)


def read_url(url: str, limit: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "GuardTrellis-release-check"})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Index response exceeded the release verification limit")
    return data


def index_files(index: str, version: str, expected: dict[str, str]) -> list[dict]:
    endpoint, file_host = INDEXES[index]
    # Newly uploaded files can take a short time to appear in the JSON index.
    for attempt in range(6):
        try:
            metadata = json.loads(
                read_url(f"{endpoint}/pypi/guardtrellis/{version}/json", 1_000_000)
            )
            files = metadata["urls"]
            names = [file["filename"] for file in files]
            if set(names) - set(expected) or len(names) != len(set(names)):
                raise ValueError("Index contains unexpected or duplicate release files")
            for file in files:
                url = urlsplit(file["url"])
                if (
                    file["digests"]["sha256"] != expected[file["filename"]]
                    or file.get("yanked", False)
                    or url.scheme != "https"
                    or url.netloc != file_host
                ):
                    raise ValueError("Index artifact hash, host, or release status does not match")
            if set(names) == set(expected):
                return files
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        if attempt < 5:
            time.sleep(5)
    raise ValueError("Release files did not appear on the selected index")


def fetch(bundle: Path, commit: str, index: str, destination: Path) -> None:
    manifest = verify(bundle, commit)
    files = index_files(index, manifest["version"], manifest["sha256"])
    destination.mkdir(parents=True, exist_ok=False)
    for file in files:
        data = read_url(file["url"], 20_000_000)
        if hashlib.sha256(data).hexdigest() != manifest["sha256"][file["filename"]]:
            raise ValueError("Downloaded artifact differs from the checked candidate")
        (destination / file["filename"]).write_bytes(data)
    print(f"Verified {index} downloads against release commit {commit}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify", "fetch"):
        subparser = subcommands.add_parser(command)
        subparser.add_argument("--bundle", type=Path, required=True)
        subparser.add_argument("--commit", required=True)
        if command in ("create", "verify"):
            subparser.add_argument("--run-id", required=command == "create")
        if command == "create":
            subparser.add_argument("--dist", type=Path, default=ROOT / "dist")
        if command == "fetch":
            subparser.add_argument("--index", choices=INDEXES, required=True)
            subparser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "create":
        print(json.dumps(create(args.bundle, args.dist, args.commit, args.run_id), indent=2))
    elif args.command == "verify":
        print(json.dumps(verify(args.bundle, args.commit, args.run_id), indent=2))
    else:
        fetch(args.bundle, args.commit, args.index, args.destination)


if __name__ == "__main__":
    main()
