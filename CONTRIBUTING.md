# Contributing to GuardTrellis

## Choose work

Start with the [roadmap](ROADMAP.md) and the public
[GitHub Project](https://github.com/users/sahilmathur254/projects/3). Its **Ready to contribute**
view contains scoped work that can start now. Issues labelled
[good first issue](https://github.com/sahilmathur254/guardtrellis/labels/good%20first%20issue)
have a small entry point; [help wanted](https://github.com/sahilmathur254/guardtrellis/labels/help%20wanted)
also includes more involved work.

Read the issue's acceptance criteria, dependencies, and existing discussion before starting.
Comment with your intended approach so the maintainer can coordinate overlapping work.
For a new substantial feature, open a proposal first. Documentation improvements, safe
reproductions, tests, and evaluation cases are useful contributions too.

Repository issues hold scope and completion evidence; the project holds status and priority.
Maintainers manage project status and assignments. You can contribute through a fork and
pull request without project or repository write access. No response-time commitment is made.

## Set up a contribution

Fork the repository on GitHub, replace `YOUR_USERNAME` below with your account, then run:

```sh
git clone https://github.com/YOUR_USERNAME/guardtrellis.git
cd guardtrellis
git remote add upstream https://github.com/sahilmathur254/guardtrellis.git
git switch -c describe-your-change
```

Use Python 3.11–3.14. The project uses a src layout, Hatchling, and uv's dependency lock.
The runtime depends only on jsonschema and referencing plus their dependencies. Keep
model providers, frameworks, network clients, and model downloads out of core dependencies.

```sh
uv sync --frozen --all-extras --group dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run python evaluation/run.py --report-dir /tmp/guardtrellis-eval
uv build
uv run python scripts/smoke_dist.py
```

If the default uv cache is unavailable, set `UV_CACHE_DIR` to a writable local directory.
On machines whose Python trust store is incomplete, use a verified system CA bundle via
`SSL_CERT_FILE`; never disable certificate verification. uv must be installed separately.

## Keep changes reviewable

Implement one scoped issue per pull request where practical. Follow the existing API and
dependency patterns. Add behavior-focused regression coverage when changing runtime behavior;
check links and examples for documentation changes. State which checks actually ran and any
remaining limitations. CI runs the full checks against submitted code.

Open a pull request from your fork to `main`, link the issue, explain the user-visible change,
and include validation evidence. Use `Fixes #NUMBER` when the PR completes the issue; use
`Refs #NUMBER` for partial work. Address review feedback before merge. Do not mark a roadmap
item complete until its acceptance criteria are met and its completion evidence is linked.

The current API is alpha and may change. Discuss public API or dependency changes before
implementation and include migration notes when compatibility is affected.

Test behavior and failure boundaries: rejected content must not reach callbacks or normal
results; scanner/callback failures must be explicit errors; no raw input belongs in logs,
reprs, generic exceptions, or diagnostics. Preserve meaningful offsets through redaction.
New checks need supported-format documentation, benign challenges, and bounded processing.
Do not add broad automatic injection-blocking phrases without evidence and explicit policy.

Use fabricated data in issues, examples, fixtures, and reports. Remove credentials and personal
data from logs and reproductions. Describe tooling or AI assistance when it affects attribution,
verification, or a reviewer's ability to reproduce the change; contributors remain responsible
for understanding and validating submitted code.

Tests run against the installed editable package. Optional example tests skip when extras
are absent; the CI matrix installs all extras, so those tests must run there. Distribution
smokes install the wheel and source archive in fresh temporary environments outside this
directory, verify core installs exclude frameworks and provider SDKs, then install extras and
execute all six examples against each installed artifact. The OpenAI, Azure, and Gemini examples use
in-memory HTTP mocks, including when credentials exist in the environment. See the
[OpenAI](docs/openai.md), [Azure](docs/azure_openai.md), and [Gemini](docs/gemini.md) guides
for separately opted-in live smokes;
normal pytest and CI never make live provider calls. Build the sdist
and wheel after updating packaged documentation or evaluation results.

The CI matrix covers these combinations:

| Runner | Architecture | Python |
| --- | --- | --- |
| Linux (`ubuntu-latest`) | x64 | 3.11, 3.12, 3.13, 3.14 |
| macOS 15 (`macos-15`) | ARM64 | 3.12 |
| Windows Server 2025 (`windows-2025`) | x64 | 3.12 |

Every combination runs the full tests with extras, lint/format/type checks, the synthetic
evaluation, and fresh wheel/sdist installation checks with all six examples. Each job has
a 15-minute limit; failures do not cancel the other matrix jobs. Bash runs workflow commands
on all runners so a failed command stops its step; Python and its subprocesses run natively
on each OS. The macOS and Windows jobs initially cover one Python version each.

Check the run for the commit under review, including its runner image details; local success
does not establish remote CI success. Synthetic evaluation limitations and reported false
positives/misses are part of the deliverable, not tests to tune away.
Do not include real credentials or personal data in tests, fixtures, or reports.

For changes to resource limits or cancellation, use the separate
[bounded measurement harness](docs/resource_limits.md). It runs fixed scenarios in child
processes with external deadlines and records incomplete work honestly. Tests check
containment and outcomes without asserting performance thresholds. Keep exploratory
reports outside the checkout; update the reviewed resource baseline only intentionally.

## Releases and licensing

Package publication is maintainer work and follows the [release checklist](docs/releasing.md).
The first alpha, [0.1.0a1](https://pypi.org/project/guardtrellis/0.1.0a1/), is available on PyPI;
install it with `python -m pip install 'guardtrellis==0.1.0a1'` to evaluate the published version.
A merged contribution does not itself trigger publication.
The project is Apache-2.0 licensed; preserve applicable notices when adding third-party material.
