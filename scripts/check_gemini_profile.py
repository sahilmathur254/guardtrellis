"""Resolve a fresh Gemini-only environment and optionally run its focused regressions.

The minimum profile pins both declared direct floors. The locked profile constrains
the full Gemini closure to uv.lock. Neither profile reuses the all-extras environment.
"""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

from gemini_profiles import (
    PROFILES,
    ROOT,
    assert_gemini_profile,
    build_options,
    fresh_environment,
    profile_constraints,
    run_mocked_example,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--regressions", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix=f"guardtrellis-gemini-{args.profile}-") as directory:
        work = Path(directory)
        python = fresh_environment(work)
        constraints, expected = profile_constraints(work, args.profile)
        options = build_options(python, work, ROOT)
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(python),
                "--index-url",
                "https://pypi.org/simple",
                "--constraint",
                str(constraints),
                *options,
                f"{ROOT}[gemini]",
            ],
            cwd=work,
            check=True,
        )
        subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True)
        assert_gemini_profile(python, work, expected)
        run_mocked_example(python, work, expected)
        if args.regressions:
            # Consumer isolation was checked above. Add reviewed test tooling only to
            # this disposable regression environment, never to the distribution smoke.
            tooling = work / "test-tooling.txt"
            subprocess.run(
                [
                    "uv",
                    "export",
                    "--locked",
                    "--only-group",
                    "dev",
                    "--no-emit-project",
                    "--output-file",
                    str(tooling),
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
                    "--requirements",
                    str(tooling),
                ],
                cwd=work,
                check=True,
            )
            # Do not use uv run here: it could replace the minimum pins with the
            # project's locked all-extras environment before tests execute.
            subprocess.run(
                [str(python), "-m", "pytest", "-W", "error", "tests/test_gemini_example.py"],
                cwd=ROOT,
                check=True,
            )
            assert_gemini_profile(python, work, expected)


if __name__ == "__main__":
    main()
