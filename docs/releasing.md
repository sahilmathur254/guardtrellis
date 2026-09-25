# Releasing GuardTrellis

The repository contains version `0.1.0a1`; no package release has been verified on PyPI.
This is the maintainer checklist for the first alpha, not an upload workflow or a record
that the steps below have happened. Track the work in the [roadmap](../ROADMAP.md).

## Release timing

Publish the alpha once the metadata/release notes and publishing workflow are reviewed,
a TestPyPI rehearsal passes, and the maintainer approves the exact release. The remaining
feature roadmap need not be complete. Early users should see an explicit experimental
version, the supported formats, and the current evaluation limitations.

A stable `0.1.0` is a later compatibility and support decision informed by adopter feedback,
broader validation, and unresolved defects. Passing a synthetic corpus does not establish
production safety. Source installation from the public repository is available now.

## Prepare the candidate

- [ ] Confirm the chosen version is available and agrees in `pyproject.toml` and
  `src/guardtrellis/__init__.py`; update the lockfile if project metadata requires it.
- [ ] Add verified project URLs and release notes; inspect README rendering and links
  outside GitHub. Keep the Apache-2.0 license and alpha classifier in the artifacts.
- [ ] Review the exact commit and its passing CI on all supported Python versions.
- [ ] Build wheel and sdist from that commit, validate their metadata with
  `python -m twine check --strict dist/*` in a release-validation environment, and run
  `scripts/smoke_dist.py` against the freshly built files.
- [ ] Record source commit, artifact SHA-256 hashes, validation commands, and results.
  Carry those checked artifacts into publication; rebuilding produces a new candidate
  that must be validated again.

## Configure publishing

Prefer [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/), which exchanges
the workflow's OIDC identity for short-lived publishing credentials. It avoids storing
a long-lived PyPI API token in the repository or GitHub secrets.

The workflow and account configuration still need to be implemented and approved. Record
the exact repository owner (`sahilmathur254`), repository (`guardtrellis`), workflow filename,
and environment name before configuring trust. Limit publish permissions to the jobs that
need them; separate TestPyPI from production and require a maintainer release decision.
Normal pushes and pull requests must not upload packages.

For a new package, a
[pending publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
can create the project on its first successful upload. A PyPI profile or pending publisher
does not reserve the package name. Configure TestPyPI and PyPI separately; they are separate
services with separate accounts. Recheck name availability when preparing the release.

## Rehearse on TestPyPI

- [ ] Obtain approval for the rehearsal and its publisher/environment configuration.
- [ ] Upload the checked artifacts to TestPyPI through the reviewed workflow.
- [ ] Install the candidate in a fresh environment outside the checkout. TestPyPI may not
  contain runtime dependencies: install those from regular PyPI, then install the candidate
  from TestPyPI with `--no-deps`, and run `pip check`.
- [ ] Verify the installed version, core API, privacy/failure behavior, and optional examples.
  Exercise both wheel and sdist installation; document which index supplied each artifact.
- [ ] Inspect the package description, links, dependency metadata, and license on TestPyPI.
  Keep hashes and results with the release evidence.

Follow the [TestPyPI guide](https://packaging.python.org/en/latest/guides/using-testpypi/)
for index-specific behavior. Do not mix TestPyPI into normal dependency resolution using
an extra index for this rehearsal. TestPyPI content is temporary and is not the user-facing
distribution channel.

## Publish and verify

- [ ] Review rehearsal evidence and obtain the maintainer's explicit PyPI release approval.
- [ ] Publish the approved wheel and sdist to PyPI; retain their hashes and workflow run.
- [ ] Download from PyPI into a fresh environment and verify hashes, metadata, installed
  version, a core smoke call, and the intended optional installs.
- [ ] Create a matching Git tag and GitHub prerelease pointing to the reviewed commit,
  with release notes, limitations, and verification evidence.
- [ ] Replace source-only wording after availability is verified and link the actual package.
  For the proposed first alpha, document `python -m pip install 'guardtrellis==0.1.0a1'`
  only once that version exists. An explicit prerelease version or `--pre` opts users into
  prerelease installation; see [pip's prerelease behavior](https://pip.pypa.io/en/stable/cli/pip_install/#pre-release-versions).
- [ ] Close the release issue and update the roadmap status using the verified package URL.

If rehearsal fails, fix and revalidate the candidate before production publication. If a
published version is defective, document the problem and prepare a corrected version; do
not assume an uploaded filename can be overwritten. A maintainer may consider yanking a
broken release under [PyPI's documented behavior](https://docs.pypi.org/project-management/yanking/).
