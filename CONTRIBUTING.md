# Contributing locally

Use Python 3.11–3.14. The project uses a src layout, Hatchling, and uv's dependency lock.
The runtime depends only on jsonschema and referencing plus their dependencies. Keep
model providers, frameworks, network clients, and model downloads out of core dependencies.

```sh
uv sync --frozen --all-extras --group dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run python evaluation/run.py
uv build
uv run python scripts/smoke_dist.py
```

If the default uv cache is unavailable, set `UV_CACHE_DIR` to a writable local directory.
On machines whose Python trust store is incomplete, use a verified system CA bundle via
`SSL_CERT_FILE`; never disable certificate verification. uv must be installed separately.

Test behavior and failure boundaries: rejected content must not reach callbacks or normal
results; scanner/callback failures must be explicit errors; no raw input belongs in logs,
reprs, generic exceptions, or diagnostics. Preserve meaningful offsets through redaction.
New checks need supported-format documentation, benign challenges, and bounded processing.
Do not add broad automatic injection-blocking phrases without evidence and explicit policy.

Tests run against the installed editable package. Optional example tests skip when extras
are absent; the CI matrix installs all extras, so those tests must run there. Distribution
smokes install the wheel and source archive in fresh temporary environments outside this
directory, verify core installs exclude frameworks, then install extras and execute all
three examples against each installed artifact. Build the sdist
and wheel after updating packaged documentation or evaluation results.

The workflow checks Python 3.11, 3.12, 3.13, and 3.14 on Linux. Check the run for the commit
under review; local success does not establish remote CI success. Synthetic evaluation limitations
and reported false positives/misses are part of the deliverable, not tests to tune away.
Do not include real credentials or personal data in tests, fixtures, or reports.

Use GitHub issues to discuss substantial changes and submit focused pull requests with
relevant validation. Package publication and deployments are separate from source contributions;
no PyPI release is available yet. The project is Apache-2.0 licensed; preserve applicable
notices when adding third-party material.
