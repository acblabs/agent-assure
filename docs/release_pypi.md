# PyPI Release Runbook

This runbook covers the Python package upload path for `agent-assure` v0.6.0.
The default path is GitHub Trusted Publishing with OIDC. Local `twine upload`
is a fallback only when Trusted Publishing is unavailable.

## Release Shape

The signed GitHub release bundle remains the source of release evidence,
digests, SBOM, GitHub release assets, and final PyPI package files. An
unprivileged job builds and tests the bundle. A second fresh job rebuilds it,
hashes the actual bytes of every future signing input from both copies, and
fails on any mismatch without trusting manifest-declared hashes. It then
promotes under a new artifact ID only the signing allowlist rebuilt in that
fresh job and byte-matched to the downloaded inputs. This is a same-toolchain
fresh-job reproducibility check, not reproduction by an independent
implementation or diverse toolchain. A minimal OIDC job downloads only that
promoted artifact and signs the fixed file set; it cannot access the original
build artifact through its job dependencies and does not check out or execute
package code. A separate
non-OIDC job verifies every signature and promotes the signed bundle and an
exact wheel-plus-sdist artifact. The PyPI job has only two steps: download that
exact verified distribution artifact ID and invoke Trusted Publishing. It does
not check out, rebuild, import, or smoke-test package code.

The workflows have distinct roles:

- `.github/workflows/release.yml` separates unprivileged build, fresh-job
  reproduction, minimal OIDC signing, non-OIDC verification/staging, GitHub
  release creation, and PyPI publication. GitHub releases are created once;
  existing releases and assets are never replaced by the workflow.
- `.github/workflows/publish-testpypi.yml` manually publishes a separately
  built TestPyPI candidate from the selected ref. Use a unique package version
  for each TestPyPI candidate. The workflow validates the requested version
  through a strict release-version parser before building or uploading.

Release, evidence, and TestPyPI workflows use the exact Python 3.14.6 canonical
producer, matching the checked-in `requirements.lock` generator version. The
compatibility CI matrix remains minor-version based. The tag validator checks the
package version, exported schema version constants, and matching frozen schema
directory before package upload. For the v0.6.0 package release, the active
schema is `0.6.0` and the candidate schema directory is `schemas/v0.6.0` until
the matching tag freezes it.

## Owner Setup

Complete this setup before the first TestPyPI publish attempt:

1. Create or claim `agent-assure` on TestPyPI and PyPI.
2. Configure the TestPyPI Trusted Publisher for this repository and
   `.github/workflows/publish-testpypi.yml`.
3. Configure the PyPI Trusted Publisher for this repository and
   `.github/workflows/release.yml`.
4. Configure GitHub environments named `signing`, `testpypi`, `pypi`, and
   `github-release`.
5. Protect all four privileged environments with required reviewers. Enforce
   immutable `v*` tag rules and require release tags to point to commits on the
   default branch. The release job independently re-reads and peels the remote
   tag immediately before creation and requires the resulting commit to equal
   the signed workflow SHA; tag rules remain defense in depth against the
   unavoidable interval between that check and GitHub's release-create API.
6. Restrict environment deployment branches/tags to the intended release refs.
7. Do not store PyPI API tokens unless Trusted Publishing is unavailable.

## Credential Timing

1. Complete account creation, 2FA setup, Trusted Publisher configuration, and
   GitHub environment setup during release-owner onboarding.
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
agent-assure schema export --out "${schema_review_dir}/v0.6.0"
git diff --no-index -- schemas/v0.6.0 "${schema_review_dir}/v0.6.0"
make schema-check
make release-check
python scripts/check_version_matches_tag.py v0.6.0
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
$SchemaReview = Join-Path $SchemaReviewRoot "v0.6.0"
agent-assure schema export --out $SchemaReview
git diff --no-index -- schemas/v0.6.0 $SchemaReview
make schema-check
make release-check
python scripts/check_version_matches_tag.py v0.6.0
Remove-Item -LiteralPath $SchemaReviewRoot -Recurse -Force
```

If the schema review diff is intentional, run `make schemas`, review
`git diff -- schemas/v0.6.0`, run `make schema-force-includes`, then rerun
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

Before creating a candidate, every built-in mutation operator must have an
immutable `introduced_at_commit`. The implementation must be committed first;
only then may a follow-up provenance commit replace `git:uncommitted` with that
implementation commit. Do not stamp the working tree or an arbitrary later
commit. Before stamping, freeze the catalog and transformation binding digests
in the operator's authored `introduction_components` snapshot and the canonical
`agent_assure/mutation/introduction_snapshots.json` document. `make
release-check` reads that document from the claimed commit, requires the carried
snapshot to match it, and then replays its component digests and the
target-control creation snapshot. Local and CI release validation therefore
require full Git history. The complete current `implementation_components`
manifest still determines the implementation identity being released, but its
bytes are not compared with a historical commit; later maintenance is therefore
allowed to change current identity without rewriting introduction history. The
guard additionally requires
`introduced_in_release` not to be newer than the expected package/tag version,
using release-candidate-aware SemVer precedence; historical operators therefore
remain valid in later releases while future-dated declarations fail. It also
requires the introduction commit to be in the release commit's ancestry and
each target control's `first_seen_commit` to precede the operator introduction.
A remaining `git:uncommitted` value is an intentional hard release blocker. An
operator intended for an RC must truthfully name that RC or an earlier version;
a stable `0.6.0` introduction is correctly considered newer than `0.6.0rc2`.

TestPyPI package versions are immutable. A second upload of the same version
will fail, so each release candidate needs a unique version such as
`0.6.0rc1`, then `0.6.0rc2` if another candidate is needed.

1. Create a candidate ref whose package metadata already contains the unique
   candidate version, for example `project.version = "0.6.0rc1"` and
   `agent_assure.__version__ = "0.6.0rc1"`.
2. Build and verify locally with `make release-check`.
3. Run the `Publish to TestPyPI` workflow manually from that ref and set
   `expected-version` explicitly to the same value, for example `0.6.0rc1`.
   The workflow intentionally has no default version because the selected ref
   must already contain matching package metadata.
4. Install the release candidate from a clean environment.

After the TestPyPI candidate passes install checks, restore the final package
version to `0.6.0` before creating the final `v0.6.0` tag.

CI, WSL, or Git Bash:

```bash
python -m venv /tmp/agent-assure-testpypi
source /tmp/agent-assure-testpypi/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps \
  --index-url https://test.pypi.org/simple/ \
  agent-assure==0.6.0rc1
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
  agent-assure==0.6.0rc1
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
python scripts/check_version_matches_tag.py v0.6.0
git tag v0.6.0
git push origin v0.6.0
```

The release workflow runs only its privileged jobs on matching tags. It blocks
if `v0.6.0` does not match `project.version = "0.6.0"` and
`agent_assure.__version__ = "0.6.0"`, if the active schema constants do not
match the mapped release schema version `0.6.0`, or if `schemas/v0.6.0` is
missing. The tag must resolve to `GITHUB_SHA`, be an ancestor of the default
branch, have matching release notes, and start and finish generation with a
clean source tree. A fresh job rebuilds the complete signing allowlist, compares
the actual bytes of the downloaded packet JSON, packet Markdown, manifest,
replay, release notes, SBOM, wheel, and source distribution against that
rebuild, and replays the digests from the fresh-job rebuild. It stages only
byte-matched files from that rebuild under a new artifact ID. Manifest claims
alone cannot satisfy this gate.

After keyless signing, a non-OIDC verification job checks the exact workflow
identity, rejects modified-blob verification, validates the signed distribution
directory, and promotes both the complete verified signed bundle and a staged
`.whl`/`.tar.gz` pair. GitHub Release consumes the verifier-promoted full-bundle
ID; the PyPI publisher consumes the verifier-promoted distribution ID and
invokes the pinned publication action. Neither publisher executes project code.

PyPI receives only the wheel and source distribution. The release packet,
manifest, SBOM, digest replay file, and signature bundles live on the GitHub
release and are the cryptographic provenance chain for the package files.

If publication fails after verification succeeds, rerun the failed publisher
job from the same workflow run so it downloads the same content-addressed
distribution artifact. The GitHub release job intentionally refuses to replace
an existing release or asset. Do not push a replacement tag or create a fresh
build for the same version.

After the workflow publishes to PyPI, validate the final package from a clean
environment.

CI, WSL, or Git Bash:

```bash
python -m venv /tmp/agent-assure-pypi
source /tmp/agent-assure-pypi/bin/activate
python -m pip install --upgrade pip
python -m pip install agent-assure==0.5.0
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
python -m pip install agent-assure==0.5.0
agent-assure --version
agent-assure demo flagship --out $FlagshipOut --clean
deactivate
Remove-Item -LiteralPath $InstallTemp -Recurse -Force
Remove-Item -LiteralPath $FlagshipOut -Recurse -Force
```
