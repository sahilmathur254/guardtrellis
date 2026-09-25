"""Install each built distribution into a fresh environment outside the source tree.

Run `uv build` first. Dependencies must be cached when running with UV_OFFLINE=1.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = """
from pathlib import Path
import guardtrellis
from importlib.util import find_spec
from guardtrellis import Action, Guard, JSONScanner, PIIScanner, Stage, ToolGuard

assert 'site-packages' in str(Path(guardtrellis.__file__).resolve())
assert Path(guardtrellis.__file__).with_name('py.typed').is_file()
assert find_spec('fastapi') is None and find_spec('langgraph') is None
assert Guard(input_scanners=[PIIScanner()]).scan('a@example.org').text == '[PII]'
invalid = Guard(output_scanners=[JSONScanner()]).scan('{invalid}', stage=Stage.OUTPUT)
assert invalid.action == Action.BLOCK
assert ToolGuard({'search': {'type':'object'}}).validate('search', '{}').accepted
print('Installed package smoke passed:', guardtrellis.__version__)
"""


def main() -> None:
    wheels = list((ROOT / "dist").glob("*.whl"))
    sdists = list((ROOT / "dist").glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit("Expected exactly one wheel and one source distribution in dist/")
    for artifact in wheels + sdists:
        with tempfile.TemporaryDirectory(prefix="guardtrellis-install-") as directory:
            work = Path(directory)
            environment = work / "venv"
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            subprocess.run(["uv", "venv", "--python", sys.executable, str(environment)], check=True)
            subprocess.run(
                ["uv", "pip", "install", "--python", str(python), str(artifact)],
                cwd=work,
                check=True,
            )
            subprocess.run([str(python), "-I", "-c", SMOKE], cwd=work, check=True)
            example = work / "plain_callable.py"
            shutil.copyfile(ROOT / "examples/plain_callable.py", example)
            subprocess.run([str(python), "-I", str(example)], cwd=work, check=True)
            # Then exercise the optional integrations against the installed artifact too.
            subprocess.run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    str(python),
                    f"{artifact}[fastapi,langgraph]",
                ],
                cwd=work,
                check=True,
            )
            for filename in ("fastapi_app.py", "langgraph_app.py"):
                example = work / filename
                shutil.copyfile(ROOT / "examples" / filename, example)
                subprocess.run([str(python), "-I", str(example)], cwd=work, check=True)
            print(f"Verified {artifact.name}", flush=True)


if __name__ == "__main__":
    main()
