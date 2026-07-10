# PyPI Release Runbook

This runbook covers the Python package upload path for `agent-assure` v0.4.3.
The default path is GitHub Trusted Publishing with OIDC. Local `twine upload`
is a fallback only when Trusted Publishing is unavailable.

## Release Shape

The signed GitHub release bundle remains the source of release evidence,
digests, SBOM, GitHub release assets, and final PyPI package files. Final PyPI
publishing happens inside `.github/workflows/release.yml` after the release
bundle is built, checked, signed, verified, and uploaded as a workflow
artifact. The PyPI job downloads that release bundle artifact and publishes
the wheel and source distribution from `.tmp/release/dist/`; it does not rebuild
package files or upload signature sidecars.

The workflows have distinct roles:

- `.github/workflows/release.yml` builds the signed GitHub release bundle and
  uploads GitHub release assets. On release tags, it also publishes the package
  files from that same release bundle to PyPI. The PyPI job verifies the
  downloaded release bundle signatures against the release workflow identity,
  replays the downloaded release bundle digests, and rechecks the staged
  wheel/source distribution immediately before upload.
- `.github/workflows/publish-testpypi.yml` manually publishes a separately
  built TestPyPI candidate from the selected ref. Use a unique package version
  for each TestPyPI candidate. The workflow validates the requested version
  through a strict release-version parser before building or uploading.

Release, evidence, and TestPyPI workflows use Python 3.14, matching the
checked-in `requirements.lock` generator version. The tag validator checks the
package version, exported schema version constants, and matching frozen schema
directory before package upload. For the v0.4.3 package release, the active
schema is `0.4.3` and the frozen schema directory is `schemas/v0.4.3`.

## Owner Setup

Complete this setup before the first TestPyPI publish attempt:

1. Create or claim `agent-assure` on TestPyPI and PyPI.
2. Configure the TestPyPI Trusted Publisher for this repository and
   `.github/workflows/publish-testpypi.yml`.
3. Configure the PyPI Trusted Publisher for this repository and
   `.github/workflows/release.yml`.
4. Configure GitHub environments named `testpypi` and `pypi`.
5. Protect the `pypi` environment with manual approval.
6. Do not store PyPI API tokens unless Trusted Publishing is unavailable.

## Credential Timing

1. Complete account creation, 2FA setup, Trusted Publisher configuration, and
   GitHub environment setup during Sprint 1 owner setup.
2. Use Trusted Publishing/OIDC as the default release path. In that path, do
   not create, paste, store, or commit a PyPI API token, and do not run local
   `twine upload`.
3. Use a PyPI API token only as a high-alert manual fallback if Trusted
   Publishing is unavailable. Create the token immediately before the manual
   upload step, after the relevant release checks have passed and the package
   files are present.
4. For a first manual upload to an unregistered package name, an account-scoped
   token may be required because the project does not exist yet. After the
   package exists, replace that with project-scoped tokens for future uploads.
   TestPyPI and PyPI use separate accounts, projects, and tokens.
5. Manual fallback upload creates or registers the package on the first
   successful upload. Use `python -m twine upload --repository testpypi dist/*`
   for a TestPyPI candidate built from the candidate ref. For the final PyPI
   release, use Trusted Publishing from `.github/workflows/release.yml`; if a
   manual fallback is unavoidable, upload the package files from the release
   bundle directory, for example `.tmp/release/dist/*.whl` and
   `.tmp/release/dist/*.tar.gz`. Username is `__token__`; password is the copied
   token value, including the `pypi-` prefix.
6. A final manual PyPI upload must not bypass the release evidence ledger. Build
   the release bundle first, verify its digest replay, and attach the release
   manifest, SBOM, evidence packet, digest replay file, distributions, and
   signature bundles to the GitHub release before or alongside the manual
   upload. Record the manual-upload reason in the release notes.
7. Never add PyPI tokens to repository files, GitHub workflow YAML, shell
   history snippets, logs, release notes, or docs examples with real values.

## Local Verification

From a clean checkout:

```bash
git checkout main
git pull
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
schema_review_dir="$(mktemp -d)"
agent-assure schema export --out "${schema_review_dir}/v0.4.3"
git diff --no-index -- schemas/v0.4.3 "${schema_review_dir}/v0.4.3"
make schema-check
make release-check
python scripts/check_version_matches_tag.py v0.4.3
rm -rf "${schema_review_dir}"
```

PowerShell equivalent:

```powershell
git checkout main
git pull
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
$SchemaReviewRoot = Join-Path $env:TEMP "agent-assure-schema-review"
Remove-Item -LiteralPath $SchemaReviewRoot -Recurse -Force -ErrorAction SilentlyContinue
$SchemaReview = Join-Path $SchemaReviewRoot "v0.4.3"
agent-assure schema export --out $SchemaReview
git diff --no-index -- schemas/v0.4.3 $SchemaReview
make schema-check
make release-check
python scripts/check_version_matches_tag.py v0.4.3
Remove-Item -LiteralPath $SchemaReviewRoot -Recurse -Force
```

If the schema review diff is intentional, run `make schemas`, review
`git diff -- schemas/v0.4.3`, run `make schema-force-includes`, then rerun
`make schema-check` before continuing.

## Temporary Virtual Environments

Use POSIX snippets like this only in CI, WSL, or Git Bash:

```bash
python -m venv /tmp/agent-assure-release
source /tmp/agent-assure-release/bin/activate
python -m pip install --upgrade pip
rm -rf /tmp/agent-assure-release
```

Use PowerShell on Windows:

```powershell
$ReleaseTemp = Join-Path $env:TEMP "agent-assure-release"
python -m venv $ReleaseTemp
& (Join-Path $ReleaseTemp "Scripts\Activate.ps1")
python -m pip install --upgrade pip
deactivate
Remove-Item -LiteralPath $ReleaseTemp -Recurse -Force
```

## TestPyPI Candidate

TestPyPI package versions are immutable. A second upload of the same version
will fail, so each release candidate needs a unique version such as
`0.4.3rc1`, then `0.4.3rc2` if another candidate is needed.

1. Create a candidate ref whose package metadata already contains the unique
   candidate version, for example `project.version = "0.4.3rc1"` and
   `agent_assure.__version__ = "0.4.3rc1"`.
2. Build and verify locally with `make release-check`.
3. Run the `Publish to TestPyPI` workflow manually from that ref and set
   `expected-version` explicitly to the same value, for example `0.4.3rc1`.
   The workflow intentionally has no default version because the selected ref
   must already contain matching package metadata.
4. Install the release candidate from a clean environment.

After the TestPyPI candidate passes install checks, restore the final package
version to `0.4.3` before creating the final `v0.4.3` tag.

CI, WSL, or Git Bash:

```bash
python -m venv /tmp/agent-assure-testpypi
source /tmp/agent-assure-testpypi/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps \
  --index-url https://test.pypi.org/simple/ \
  agent-assure==0.4.3rc1
python -m pip check
agent-assure --version
agent-assure schema export --out /tmp/agent-assure-testpypi-schemas
agent-assure demo flagship --out /tmp/agent-assure-testpypi-flagship --clean
deactivate
rm -rf \
  /tmp/agent-assure-testpypi \
  /tmp/agent-assure-testpypi-schemas \
  /tmp/agent-assure-testpypi-flagship
```

PowerShell:

```powershell
$InstallTemp = Join-Path $env:TEMP "agent-assure-testpypi"
$SchemaTemp = Join-Path $env:TEMP "agent-assure-testpypi-schemas"
$FlagshipOut = Join-Path $env:TEMP "agent-assure-testpypi-flagship"
python -m venv $InstallTemp
& (Join-Path $InstallTemp "Scripts\Activate.ps1")
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps `
  --index-url https://test.pypi.org/simple/ `
  agent-assure==0.4.3rc1
python -m pip check
agent-assure --version
agent-assure schema export --out $SchemaTemp
agent-assure demo flagship --out $FlagshipOut --clean
deactivate
Remove-Item -LiteralPath $InstallTemp -Recurse -Force
Remove-Item -LiteralPath $SchemaTemp -Recurse -Force
Remove-Item -LiteralPath $FlagshipOut -Recurse -Force
```

The expense demo remains a repository example unless its fixture supports the
same decision-field/process-regression shape without slowing the flagship
release path.

If the expense demo is included in the release candidate, also run:

```bash
agent-assure demo expense --out /tmp/agent-assure-testpypi-expense --clean
```

PowerShell:

```powershell
$ExpenseOut = Join-Path $env:TEMP "agent-assure-testpypi-expense"
agent-assure demo expense --out $ExpenseOut --clean
```

## Final PyPI Release

Create and push the final release tag only after TestPyPI install checks pass:

```bash
git checkout main
git pull
make schema-check
make release-check
python scripts/check_version_matches_tag.py v0.4.3
git tag v0.4.3
git push origin v0.4.3
```

The PyPI publish job in `.github/workflows/release.yml` runs only on matching
tags. It blocks if `v0.4.3` does not match `project.version = "0.4.3"` and
`agent_assure.__version__ = "0.4.3"`, if the active schema constants do not
match the release schema version `0.4.3`, or if `schemas/v0.4.3` is
missing. It publishes package files
from the release bundle artifact produced by the release build; it does not run
a second package build. Before upload, it verifies the downloaded release
bundle with cosign against `.github/workflows/release.yml`, verifies the same
bundle with `agent-assure release replay`, stages only `.whl` and `.tar.gz`
files, then runs `twine check`, wheel-content verification, and the clean wheel
smoke install on the staged upload directory.

PyPI receives only the wheel and source distribution. The release packet,
manifest, SBOM, digest replay file, and signature bundles live on the GitHub
release and are the cryptographic provenance chain for the package files.

If the PyPI publish job fails after the release build succeeds, rerun the failed
job from the same workflow run so it reuses the uploaded release bundle
artifact. Do not push a replacement tag or start a fresh build for the same
version unless the release is being deliberately re-cut before any package file
has been accepted by PyPI.

After the workflow publishes to PyPI, validate the final package from a clean
environment.

CI, WSL, or Git Bash:

```bash
python -m venv /tmp/agent-assure-pypi
source /tmp/agent-assure-pypi/bin/activate
python -m pip install --upgrade pip
python -m pip install agent-assure==0.4.3
agent-assure --version
agent-assure demo flagship --out /tmp/agent-assure-pypi-flagship --clean
deactivate
rm -rf /tmp/agent-assure-pypi /tmp/agent-assure-pypi-flagship
```

PowerShell:

```powershell
$InstallTemp = Join-Path $env:TEMP "agent-assure-pypi"
$FlagshipOut = Join-Path $env:TEMP "agent-assure-pypi-flagship"
python -m venv $InstallTemp
& (Join-Path $InstallTemp "Scripts\Activate.ps1")
python -m pip install --upgrade pip
python -m pip install agent-assure==0.4.3
agent-assure --version
agent-assure demo flagship --out $FlagshipOut --clean
deactivate
Remove-Item -LiteralPath $InstallTemp -Recurse -Force
Remove-Item -LiteralPath $FlagshipOut -Recurse -Force
```
