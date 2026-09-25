# Releasing GuardTrellis

Version `0.1.0a1` was published on 2026-09-25 to
[PyPI](https://pypi.org/project/guardtrellis/0.1.0a1/). Its
[GitHub prerelease](https://github.com/sahilmathur254/guardtrellis/releases/tag/v0.1.0a1) and
[#4](https://github.com/sahilmathur254/guardtrellis/issues/4) retain the release evidence.
The instructions below describe the process for future releases; use the new candidate's
version and rehearsal run rather than rerunning the completed alpha upload. The release workflow is
`.github/workflows/release.yml`. It validates on pull requests and offers three manual
targets: `validate`, `testpypi`, and `pypi`. It never publishes on a push, pull request, or tag.

## What the workflow does

1. **Validate:** build one wheel and one source archive, run strict Twine metadata checks,
   and install both outside the checkout with core and optional example smokes. Record
   their SHA-256 hashes, package version, source commit, and workflow run ID in `release.json`.
2. **TestPyPI:** on an explicit dispatch from this repository's `main`, require successful
   push CI for that commit and a reviewer-protected `testpypi` environment. Build/validate
   the candidate, await environment approval, and upload with Trusted Publishing. Download
   the actual index files, match both hashes, and smoke-test those downloads. Only then
   retain the unchanged files as the `testpypi-verified` workflow artifact.
3. **PyPI:** on a separate dispatch, require a successful TestPyPI run from this same
   `main` commit. Retrieve its `testpypi-verified` artifact, check the recorded run/commit,
   versions, metadata, and hashes, and await the `pypi` environment approval. Upload those
   same files without rebuilding. Verify their public PyPI hashes and fresh installations.

Publishing jobs only download the candidate, check its hashes, and invoke the pinned PyPA
action. They have `id-token: write`; build/install/verification jobs do not. No long-lived
PyPI token is required. Dependencies for installation smokes come from ordinary PyPI;
the candidate itself is the exact file downloaded from the selected index, so TestPyPI
does not participate in dependency resolution. Both index verification paths are bounded
and fail if files are missing, changed, yanked, or unexpected.

GitHub artifacts are retained for 30 days. Keep the workflow run links and download the
verified bundle for the release record. Promotion requires the source commit to remain
unchanged between rehearsal and production dispatch; coordinate merges during that interval.
The workflow does not create a GitHub release or tag automatically.

## Prepare and review

The alpha can ship after these release checks pass; later feature-roadmap items need not
be complete. A stable `0.1.0` requires a later compatibility/support decision informed by
adopter feedback and broader validation. Synthetic results do not establish production safety.

```sh
uv sync --frozen --all-extras --group dev --group release
uv run --frozen pytest -W error
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy
uv run --frozen python evaluation/run.py --report-dir /tmp/guardtrellis-release-eval
uv build
uv run --frozen --group release python -m twine check --strict dist/*
uv run --frozen python scripts/smoke_dist.py
```

Use a clean checkout and a build directory containing only this candidate's wheel/sdist.
Keep versions in `pyproject.toml` and `src/guardtrellis/__init__.py` consistent. Inspect the
packaged README, URLs, license, and [changelog](../CHANGELOG.md). The manifest validator also
checks the package versions and expected metadata inside both distributions. Review passing
Python 3.11–3.14 CI on the exact commit; a local pass alone does not establish that.
Both build targets explicitly use Core Metadata 2.4 for compatibility. Twine 7 is locked in
the separate `release` dependency group and is not a runtime dependency.

Pull requests run the publication-free candidate path. After merging the reviewed workflow,
a maintainer can perform the same dry run from the default branch:

```sh
gh workflow run release.yml --ref main -f target=validate
```

The `candidate` artifact contains `dist/`, `release.json`, and `SHA256SUMS`. The manifest also
appears in the workflow summary. No accounts or publishing credentials are needed for validation.

## One-time account and environment setup

This configuration is a maintainer action and is not performed by committing the workflow.
Get explicit approval before changing trust/permissions or uploading a package.

Create the GitHub environments `testpypi` and `pypi` in this repository. For each:

- Require a reviewer, initially `sahilmathur254`, and restrict deployment branches to `main`.
- Disable administrator bypass. If the owner is the only reviewer and dispatches the release,
  allow that owner to approve their own deployment; otherwise a second reviewer is needed.
- Keep approvals separate between the rehearsal and the production release.

The workflow checks that required reviewers are configured before it schedules publication;
a missing environment fails the preflight instead of silently relying on an unprotected one.

Register separate pending GitHub Trusted Publishers on the two indexes using these exact values:

| Field | TestPyPI | PyPI |
| --- | --- | --- |
| Project name | `guardtrellis` | `guardtrellis` |
| GitHub owner | `sahilmathur254` | `sahilmathur254` |
| Repository | `guardtrellis` | `guardtrellis` |
| Workflow filename | `release.yml` | `release.yml` |
| Environment | `testpypi` | `pypi` |

Use the account's Publishing page on [TestPyPI](https://test.pypi.org/manage/account/publishing/)
and [PyPI](https://pypi.org/manage/account/publishing/). TestPyPI has a separate account/database.
The field takes `release.yml`, not its repository directory path. A profile or pending publisher
does not reserve a package name; recheck availability before publishing. Follow
[PyPI's pending-publisher instructions](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
and [GitHub environment guidance](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

## Rehearse, then promote

After the maintainer approves the candidate and TestPyPI upload, and the exact `main` commit's
push CI has succeeded:

```sh
gh workflow run release.yml --ref main -f target=testpypi
```

Approve the `testpypi` deployment in Actions. Inspect the completed run's logs, package
description on TestPyPI, and `testpypi-verified` artifact. Record the numeric run ID and
review both downloaded-artifact installation results before deciding to publish to PyPI.

After a separate production release approval, replace `REHEARSAL_RUN_ID` below with that
successful run ID. Do not advance `main` between these two dispatches:

```sh
gh workflow run release.yml --ref main -f target=pypi -f rehearsal_run_id=REHEARSAL_RUN_ID
```

Approve the `pypi` deployment only after reviewing the candidate manifest. Success includes
verification of the public PyPI files and both installations, not just a successful upload.
The resulting `pypi-verified` artifact retains the original TestPyPI candidate manifest/hashes.

Then create tag `v0.1.0a1` and a GitHub **prerelease** at the manifest's exact commit. Confirm
the tag's version matches the packaged version and that it resolves to that commit. Include
the changelog, retained limitations, both workflow runs, and artifact hashes in the release notes.
The tag is a record of the reviewed release; pushing it does not trigger another upload.

Only after availability is verified, document the public installation command
`python -m pip install 'guardtrellis==0.1.0a1'`, update source-only status in the roadmap and
contributor guide, and close the release issue with the verified package URL. An explicit
prerelease version or `--pre` opts users into a prerelease; see
[pip's documented behavior](https://pip.pypa.io/en/stable/cli/pip_install/#pre-release-versions).

## Failure and recovery

- A failed build, metadata/hash check, or installation cannot reach a publishing job. Fix
  the cause, review the new commit, and revalidate. Before any upload, workflow changes can
  be reverted without changing index state.
- If upload succeeded but index verification failed, inspect the recorded hashes and index
  state, then rerun only the failed verification job. Do not repeat a completed upload or
  a completed workflow; artifact names and uploaded filenames are deliberately not overwritten.
- If an upload only partially succeeded, inspect the exact files before deciding on recovery.
  The workflow does not use `skip-existing` to hide mismatches. A new corrected alpha version
  is the simple recovery path when the published candidate cannot be completed unchanged.
- If the commit changes or the verified GitHub artifact expires, automatic promotion stops.
  Do not substitute a rebuild for the verified files; prepare a new candidate/version or
  obtain a separately reviewed recovery plan.
- For a defective PyPI release, document the problem and publish a corrected version. A
  maintainer can consider [yanking](https://docs.pypi.org/project-management/yanking/) the
  affected release; deletion or overwriting is not a rollback strategy.

Primary references: [Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/),
[PyPA publishing action](https://github.com/pypa/gh-action-pypi-publish), and
[TestPyPI](https://packaging.python.org/en/latest/guides/using-testpypi/).
