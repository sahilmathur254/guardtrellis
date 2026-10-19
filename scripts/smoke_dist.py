"""Install each built distribution into a fresh environment outside the source tree.

Run `uv build` first. Dependencies must be cached when running with UV_OFFLINE=1.
"""

import argparse
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
from guardtrellis import Action, Guard, JSONScanner, PIIScanner, Stage, ToolGuard

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
                        f"{artifact}{extras}",
                    ],
                    cwd=work,
                    check=True,
                )
                subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True)
                if smoke is not None:
                    subprocess.run([str(python), "-I", "-c", smoke], cwd=work, check=True)
                for filename in examples:
                    example = work / filename
                    shutil.copyfile(ROOT / "examples" / filename, example)
                    subprocess.run([str(python), "-I", str(example)], cwd=work, check=True)
            print(f"Verified {artifact.name}", flush=True)


if __name__ == "__main__":
    main()
