"""Install each built distribution into a fresh environment outside the source tree.

Run `uv build --offline --no-build-isolation` with the locked build group first.
Dependencies must be cached when running with UV_OFFLINE=1.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_EXAMPLES = (
    "plain_callable.py",
    "retrieval_tools.py",
    "policy_operations.py",
    "decoded_query.py",
    "decoded_contact.py",
    "tool_result_handoff.py",
)
SMOKE = """
from pathlib import Path
import guardtrellis
from importlib.util import find_spec
from importlib.metadata import distributions
from guardtrellis import Action, Guard, JSONScanner, PIIScanner, SecretScanner, Stage, ToolGuard

assert 'site-packages' in str(Path(guardtrellis.__file__).resolve())
assert Path(guardtrellis.__file__).with_name('py.typed').is_file()
assert find_spec('fastapi') is None and find_spec('langgraph') is None
assert find_spec('openai') is None
assert find_spec('httpx') is None and find_spec('httpx2') is None
assert 'google-genai' not in {package.metadata['Name'] for package in distributions()}
assert Guard(input_scanners=[PIIScanner()]).scan('a@example.org').text == '[PII]'
invalid = Guard(output_scanners=[JSONScanner()]).scan('{invalid}', stage=Stage.OUTPUT)
assert invalid.action == Action.BLOCK
assert ToolGuard({'search': {'type':'object'}}).validate('search', '{}').accepted
calls = []
rejected = Guard(input_scanners=[JSONScanner()]).run('invalid JSON', calls.append)
assert not calls and rejected.text is None and rejected.action == Action.BLOCK
for uri in (
    'postgresql://db.example.invalid/demo?password=SyntheticPackage42',
    'mongodb+srv://app:SyntheticPackage43@cluster.example.invalid/demo',
):
    assert Guard(input_scanners=[SecretScanner()]).scan(uri).action == Action.ALLOW
    rejected = Guard(input_scanners=[SecretScanner(connection_strings=True)]).run(uri, calls.append)
    assert not calls and rejected.text is None and rejected.action == Action.BLOCK
    finding = rejected.input_result.findings[0]
    assert (finding.start, finding.end) == (0, len(uri))
print('Installed package smoke passed:', guardtrellis.__version__)
"""


OPENAI_SMOKE = """
from importlib.util import find_spec
from importlib.metadata import version

assert version('openai').split('.')[0] == '3'
assert find_spec('httpx2') is not None and find_spec('httpx') is None
assert find_spec('fastapi') is None and find_spec('langgraph') is None
print('OpenAI-only extra smoke passed')
"""


def smoke_cli(python: Path, work: Path) -> None:
    """Exercise real installed launchers with byte streams on every native CI OS."""
    console = python.with_name("guardtrellis.exe" if os.name == "nt" else "guardtrellis")
    source = work / "fixture with spaces 雪.txt"
    payload = "\ufeffOpening hours\r\n雪\x00\x1b[31m".encode("utf-8")
    source.write_bytes(payload)
    for command in ([str(console)], [str(python), "-I", "-m", "guardtrellis"]):
        version = subprocess.run(
            [*command, "--version"], capture_output=True, cwd=work, timeout=15, check=True
        )
        assert version.stdout.startswith(b"guardtrellis ") and not version.stderr
        for selection in (["--stdin"], ["--file", str(source)]):
            checked = subprocess.run(
                [
                    *command,
                    "check",
                    *selection,
                    "--stage",
                    "tool",
                    "--policy",
                    "secrets",
                    "--format",
                    "json",
                    "--output",
                    "checked-text",
                ],
                input=payload,
                capture_output=True,
                cwd=work,
                timeout=15,
                check=True,
            )
            assert checked.stdout == payload
            assert json.loads(checked.stderr)["result"]["action"] == "allow"
        for data, options, status, action in (
            (b"Contact demo@example.org", [], 0, "redact"),
            (
                b"postgresql://app:SyntheticInstall42@db.invalid/demo",
                ["--connection-strings"],
                1,
                "block",
            ),
        ):
            checked = subprocess.run(
                [
                    *command,
                    "check",
                    "--stdin",
                    "--stage",
                    "retrieval",
                    "--policy",
                    "privacy",
                    "--format",
                    "json",
                    "--output",
                    "checked-text",
                    *options,
                ],
                input=data,
                capture_output=True,
                cwd=work,
                timeout=15,
            )
            assert checked.returncode == status
            assert checked.stdout == (b"Contact [PII]" if status == 0 else b"")
            assert json.loads(checked.stderr)["result"]["action"] == action
    assert source.read_bytes() == payload
    example = work / "cli_ci.py"
    shutil.copyfile(ROOT / "examples" / "cli_ci.py", example)
    source.write_bytes(b"Opening hours: 9am to 5pm.")
    subprocess.run([str(python), "-I", str(example), str(source)], cwd=work, check=True, timeout=20)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    directory = args.dist_dir.resolve()
    wheels = list(directory.glob("*.whl"))
    sdists = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("Expected exactly one wheel and one source distribution in dist/")
    # Keep OpenAI isolated before other extras can mask its dependency requirements.
    stages = (
        ("", SMOKE, CORE_EXAMPLES),
        ("[openai]", OPENAI_SMOKE, ("openai_app.py", "azure_openai_app.py")),
        (
            "[fastapi,langgraph,openai,gemini]",
            None,
            (
                *CORE_EXAMPLES,
                "fastapi_app.py",
                "langgraph_app.py",
                "openai_app.py",
                "azure_openai_app.py",
                "gemini_app.py",
            ),
        ),
    )
    for artifact in wheels + sdists:
        with tempfile.TemporaryDirectory(prefix="guardtrellis-install-") as directory:
            work = Path(directory)
            environment = work / "venv"
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            subprocess.run(["uv", "venv", "--python", sys.executable, str(environment)], check=True)
            build_options = []
            if artifact.suffix != ".whl":
                # Seed disposable source-install environments with the reviewed backend,
                # rather than resolving another build backend during the smoke.
                requirements = work / "build-requirements.txt"
                subprocess.run(
                    [
                        "uv",
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
                )
                subprocess.run(
                    [
                        "uv",
                        "pip",
                        "install",
                        "--python",
                        str(python),
                        "--require-hashes",
                        "--only-binary",
                        ":all:",
                        "--requirements",
                        str(requirements),
                    ],
                    cwd=work,
                    check=True,
                )
                build_options = ["--no-build-isolation-package", "guardtrellis"]
            for extras, smoke, examples in stages:
                subprocess.run(
                    [
                        "uv",
                        "pip",
                        "install",
                        "--python",
                        str(python),
                        "--index-url",
                        "https://pypi.org/simple",
                        *build_options,
                        f"{artifact}{extras}",
                    ],
                    cwd=work,
                    check=True,
                )
                subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True)
                if smoke is not None:
                    subprocess.run([str(python), "-I", "-c", smoke], cwd=work, check=True)
                if extras == "":
                    smoke_cli(python, work)
                for filename in examples:
                    example = work / filename
                    shutil.copyfile(ROOT / "examples" / filename, example)
                    subprocess.run([str(python), "-I", str(example)], cwd=work, check=True)
            print(f"Verified {artifact.name}", flush=True)


if __name__ == "__main__":
    main()
