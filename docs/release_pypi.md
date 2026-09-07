# PyPI Release Runbook

This runbook covers the conditional Python package upload path for
`agent-assure` v0.6.6.
The default path is GitHub Trusted Publishing with OIDC. Local `twine upload`
is a fallback only when Trusted Publishing is unavailable.

> **Release status:** v0.6.6 is currently untagged and unpublished. Every step
> below remains conditional on all empirical and release gates passing and on
> explicit human approval. This runbook does not imply that v0.6.6 has shipped.

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
package code. A separate non-OIDC job verifies every signature, rejects any
missing, extra, linked, reparse, or non-regular full-tree entry, and promotes the
signed bundle and an exact wheel-plus-sdist artifact. After those uploads, a new
unprivileged job downloads the exact immutable IDs, repeats signature and
coherent-binding verification from a captured private snapshot, and requires
the separate two-file distribution artifact to byte-match the wheel and sdist in
the full bundle. It exposes those same IDs only after success and does not
reupload them. The PyPI job has only two steps: download that exact verified
distribution artifact ID and invoke Trusted Publishing. It does not check out,
rebuild, import, or smoke-test package code.

The workflows have distinct roles:

- `.github/workflows/release.yml` separates unprivileged build, fresh-job
  reproduction, minimal OIDC signing, non-OIDC verification/staging, GitHub
  release creation, and PyPI publication. GitHub releases are created once;
  existing releases and assets are never replaced by the workflow. Its tagged
  production path accepts only stable `vX.Y.Z` versions and rejects release
  candidate tags. Its protected `prepare-tag` operation first checks out an
  exact default-branch commit SHA, runs the empirical and release gates, and
  reproduces the release bytes before it creates the immutable annotated tag.
- `.github/workflows/publish-testpypi.yml` manually publishes a separately
  built TestPyPI candidate from the selected ref. Use a unique package version
  for each TestPyPI candidate. The workflow validates the requested version
  through a strict release-version parser before building or uploading.

Release, evidence, and TestPyPI workflows use the exact Python 3.14.6 canonical
producer, matching the checked-in `requirements.lock` generator version. The
compatibility CI matrix remains minor-version based. The tag validator checks the
package version, exported schema version constants, and matching frozen schema
directory before package upload. For the v0.6.6 package release, the active
schema is `0.6.6` and the candidate schema directory is `schemas/v0.6.6` until
the matching tag freezes it.

## Owner Setup

Complete this setup before the first TestPyPI publish attempt:

1. Create or claim `agent-assure` on TestPyPI and PyPI.
2. Configure the TestPyPI Trusted Publisher for this repository and
   `.github/workflows/publish-testpypi.yml`.
3. Configure the PyPI Trusted Publisher for this repository and
   `.github/workflows/release.yml`.
4. Configure GitHub environments named `release-tag`, `signing`, `testpypi`,
   `pypi`, and `github-release`.
5. Protect all five privileged environments with required reviewers. Enforce
   immutable `v*` tag rules and require release tags to point to commits on the
   default branch. Permit tag creation only through the protected `release-tag`
   environment. The release job independently re-reads and peels the remote tag
   immediately before GitHub Release creation and requires the resulting commit
   to equal the signed workflow SHA; tag rules remain defense in depth against
   the unavoidable interval between that check and GitHub's release-create API.
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
   manifest, assurance evidence graph, SBOM, evidence packet, digest replay
   file, distributions, and signature bundles to the GitHub release before or
   alongside the manual upload. Record the manual-upload reason in the release
   notes.
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
agent-assure schema export --out "${schema_review_dir}/v0.6.6"
git diff --no-index -- schemas/v0.6.6 "${schema_review_dir}/v0.6.6"
make schema-check
make release-check
python scripts/check_version_matches_tag.py v0.6.6
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
$SchemaReview = Join-Path $SchemaReviewRoot "v0.6.6"
agent-assure schema export --out $SchemaReview
git diff --no-index -- schemas/v0.6.6 $SchemaReview
make schema-check
make release-check
python scripts/check_version_matches_tag.py v0.6.6
Remove-Item -LiteralPath $SchemaReviewRoot -Recurse -Force
```

If the schema review diff is intentional, run `make schemas`, review
`git diff -- schemas/v0.6.6`, run `make schema-force-includes`, then rerun
`make schema-check` before continuing.

`make release-check` is the repeatable engineering gate used by ordinary CI;
it intentionally remains runnable while empirical work is incomplete. It does
not authorize publication. Every TestPyPI or tagged-release path must instead
run the ordered publish gate:

```bash
make release-publish-check EXPECTED_RELEASE=0.6.6rc1 EMPIRICAL_STUDY_BUNDLE_ROOT=evidence/empirical/real-model-study EXTERNAL_PILOT_BUNDLE_ROOT=evidence/empirical/external-pilot EXTERNAL_PILOT_EVIDENCE=external-pilot-evidence.json EXTERNAL_PILOT_REVIEW_RECEIPT=external-pilot-independence-review.json
```

That target validates the exact self-digested study report, the pilot evidence
descriptor, a separately persisted human independence-review receipt, every
referenced pilot artifact byte, and the fixed
committed Process-Equivalence Benchmark v0.2. The Make target does not expose a
benchmark override: the checker loads the top-level canonical artifact and its
packaged mirror, requires byte-for-byte mirror parity, then requires the study
manifest's benchmark ID, version, digest, and disjoint exhaustive case frame to
match. It also requires an eligible all-`real_provider` study report, a
genuinely external independently controlled CI attempt for implementation
`agent-assure`, a pilot implementation version on the `EXPECTED_RELEASE` base
line, and captured pilot learning. An RC such as `0.6.6rc1` and stable `0.6.6`
share base line `0.6.6`; a different base version fails closed with a distinct
reason.

The checker pins one closed, link-free pilot bundle, enforces per-file and
aggregate bounds, verifies every byte digest, validates the wheel
name/version/metadata/RECORD and supported declared JSON contracts, privacy
scans a closed inventory of wheel members, rejects credential-shaped names and
unknown or undecodable binary members, and requires the review receipt to bind
the exact inventory, environment-control evidence, expected release line, and
a post-evidence review time. Missing, extra, invalid, misbound, or unreadable
evidence fails closed. The underlying readiness API also requires the
factory-only verified-bundle result; it does not accept a bare parsed pilot
descriptor as an alternate path around byte and receipt verification.

The origin and human-independence fields remain declared, digest-bound claims.
The receipt explicitly records `human_operator_attestation` and
`out_of_band_not_machine_verified`: the checker does not infer provider use
from names or authenticate provider dispatch, repository control, reviewer
identity, or human provenance. Repository review and release-environment
approval remain the manual trust root. The checker emits the canonical
benchmark, study, pilot, receipt, and artifact-manifest digests and only then
invokes `release-check`. The pilot's exact `source_revision` and
distribution binding continue to identify the tested pre-candidate rather
than release HEAD. The empirical checkpoint is necessary but not sufficient;
it does not turn that record into exact-candidate, clean-reproduction, or
CI-integration evidence, and all three later eligibility flags remain false.

`make release-check` also verifies the committed process-equivalence
reproduction index in check mode and requires its public and packaged copies to
match exactly. The distribution verifier rejects non-portable paths, duplicate
or colliding names, links and special files, expansion-limit violations,
missing source or packaged resources, wheel `RECORD` mismatches, and any
filename, archive-layout, or metadata identity/version disagreement between the
wheel and sdist. Every non-`.dist-info` wheel payload path and byte must match
its intended sdist source (`src/agent_assure`, `mappings`, or a frozen schema),
so wheel-only `.pth`/`.data` payloads, missing sources, and build byte drift are
release blockers. It also privacy-scans every final wheel and sdist member under
bounded byte/line/token budgets. Installable Python is parsed for literal
credential assignments while credential-handling vocabulary remains valid;
intentional detector-test vectors require exact reviewed file digests. Unknown
types, undecodable text, raw-output paths, and modified/unapproved binary assets
are release blockers. Before any package code runs, the smoke phase creates and
pins every artifact, cache, build, and environment root; installs the
hash-locked dependencies separately; builds the exact sdist offline; and
requires the resulting wheel's complete payload and metadata to reproduce the
published wheel. Both verified wheels are then installed into separate clean
environments with `--no-deps --no-compile`. Each whole-environment delta must
match the wheel payload, declared console scripts, deterministic pip metadata,
and installed `RECORD` exactly. Unexpected `.pth`, bytecode, packages, modules,
metadata, scripts, links, reparse points, special files, or dependency changes
are release blockers, and pip cannot fetch a direct or transitive dependency
from project metadata during either project install.

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
target-control creation snapshot. The catalog method-component hash normalizes
the administrative introduction stamps and the pending
`evidence_provenance_identity` first-seen value so a follow-up provenance-only
stamp does not change normalized method identity. That normalization is not
provenance verification. The release guard uses the unnormalized declarations,
loads each mapped control source at its declared `first_seen_commit`, parses it
as Python, locates the control's explicitly mapped top-level implementation
function, and requires an exact
`ControlResult(control_id="<declared ID>", ...)` keyword literal outside a
statically false conditional branch and before an unconditional terminal
statement in its sequential block. Unavailable or unparseable source, a missing
or ambiguous mapped function, or a function without that exact literal fails
closed. This proves only that the literal occurs in the mapped function under
the bounded static filter; it does not prove that the function is invoked or
that the call is executable for a particular runtime input. Local and CI release
validation therefore require full Git history. The complete current
`implementation_components` manifest still
determines the implementation identity being released, but its bytes are not
compared with a historical commit; later maintenance is therefore allowed to
change current identity without rewriting introduction history. The guard
additionally requires
`introduced_in_release` not to be newer than the expected package/tag version,
using release-candidate-aware SemVer precedence; historical operators therefore
remain valid in later releases while future-dated declarations fail. It also
requires the introduction commit to be in the release commit's ancestry and
each target control's `first_seen_commit` to precede the operator introduction.
A remaining `git:uncommitted` value is an intentional hard release blocker. An
operator intended for an RC must truthfully name that RC or an earlier version;
a stable `0.6.6` introduction is correctly considered newer than `0.6.6rc2`.

TestPyPI package versions are immutable. A second upload of the same version
will fail, so each release candidate needs a unique version such as
`0.6.6rc1`, then `0.6.6rc2` if another candidate is needed.

1. Create a candidate ref whose package metadata already contains the unique
   candidate version, for example `project.version = "0.6.6rc1"` and
   `agent_assure.__version__ = "0.6.6rc1"`.
2. Regenerate the version-bound deterministic goldens with
   `python scripts/update_golden.py --update-golden`. The evidence-sensitivity
   reports carry `producer_version`, so changing to an RC intentionally changes
   their bytes and self-digests. Review the complete golden diff, then commit
   the regenerated RC goldens on the candidate ref; do not leave them as
   uncommitted local changes.
3. From the committed candidate ref, run `python scripts/update_golden.py` in
   check mode and then build and verify with `make release-publish-check`.
   The TestPyPI workflow repeats the empirical gate, version-bound golden check,
   and release checks and rejects stale or uncommitted candidate evidence.
4. Run the `Publish to TestPyPI` workflow manually from that ref and set
   `expected-version` explicitly to the same value, for example `0.6.6rc1`.
   The workflow intentionally has no default version because the selected ref
   must already contain matching package metadata. Dispatch it from the
   candidate branch or commit; do not create or push a `v0.6.6rcN` tag.
5. Install the release candidate from a clean environment.

After the TestPyPI candidate passes install checks, restore the final package
version to `0.6.6`, run `python scripts/update_golden.py --update-golden` again,
review and commit the stable-version golden regeneration, then run
`python scripts/update_golden.py` and `make release-publish-check` from the
clean final commit before dispatching the protected `prepare-tag` operation.
RC-generated sensitivity goldens must not remain on the final tag.

CI, WSL, or Git Bash:

```bash
python -m venv /tmp/agent-assure-testpypi
source /tmp/agent-assure-testpypi/bin/activate
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps \
  --index-url https://test.pypi.org/simple/ \
  agent-assure==0.6.6rc1
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
  agent-assure==0.6.6rc1
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

Before selecting the final tag target, prepare and review one release commit
that:

1. moves the release entries from `Unreleased` under a dated `## 0.6.6`
   changelog heading;
2. creates `docs/release_notes/v0.6.6.md` and adds it to `mkdocs.yml`;
3. updates `CITATION.cff`, README package/action pins and maturity wording, and
   the released-schema wording in `docs/for_engineers.md` and
   `docs/schema_evolution.md`;
4. records separately authorized remediation in the approved private governance
   record without exposing internal planning metadata in public files; and
5. passes docs alignment, schema parity, release checks, and a clean-worktree
   check from the exact commit that will receive the tag.

Do not tag an implementation checkpoint that lacks this collateral. After the
release commit is reviewed and the TestPyPI install checks pass, record its
exact SHA and dispatch the protected pre-tag operation from the default-branch
workflow definition:

```bash
git checkout main
git pull
make schema-check
make release-publish-check
python scripts/check_version_matches_tag.py v0.6.6
release_sha="$(git rev-parse HEAD)"
test "${release_sha}" = "$(git rev-parse origin/main)"
gh workflow run release.yml --ref main \
  -f operation=prepare-tag \
  -f source-sha="${release_sha}" \
  -f expected-version=0.6.6
```

Do not create or push `v0.6.6` manually. The pre-tag run checks that the SHA is
a full commit ID on the default branch, the stable version and collateral match,
the tag does not already exist, the worktree is clean, the empirical checkpoint
passes, and a fresh job reproduces every future signing input. Only then does
the separately protected `release-tag` job create one annotated tag bound to
that SHA. Because tag creation with `GITHUB_TOKEN` does not recursively trigger
a push workflow, the job explicitly dispatches `release.yml` at the new tag.
That tag-bound run repeats the gates before any OIDC signing or publication.
The internal dispatch also passes the exact protected run ID and attempt. A
separate unprivileged provenance job re-resolves the annotated tag and its
referenced preparation attempt through the GitHub API, verifies the successful
build, reproduction, and tag-create steps, and requires the dispatch to have
come from either that successful protected preparation or a successful
protected `resume-tag` attempt. Signing depends on this job. Consequently, a
manual tag push or manually dispatched `standard` operation without the exact
matching protected authorization cannot reach OIDC signing even if repository
tag rules are missing or later weakened; those rules remain defense in depth.
Operators must not populate the internal `authorization-run-*` inputs
themselves.

If the protected job creates the annotated tag but its final workflow dispatch
fails or times out, do not move, replace, or recreate the tag. Re-run the
workflow from that immutable tag with the exact same SHA and version using the
explicit recovery operation:

```bash
release_tag="v0.6.6"
gh workflow run release.yml --ref "${release_tag}" \
  -f operation=resume-tag \
  -f source-sha="${release_sha}" \
  -f expected-version=0.6.6
```

`resume-tag` repeats the empirical, release, and independent-reproduction gates,
then requires its own workflow ref, GitHub run SHA, checked-out commit, and
peeled annotated-tag commit to equal the requested release identity. It verifies
through the GitHub API that the existing ref's name and annotation contract also
match. It never writes tag content. Before dispatching, it performs a bounded
query for an active or successful tag-bound release run and exits successfully
without creating a duplicate when one exists. A mismatched tag, an unbounded
run history, or any unverifiable response fails closed. The shared release
concurrency group uses the bounded `queue: max` mode so an authorized pending
publication run is not replaced by a later recovery dispatch. The resumed
tag-bound run verifies both the original successful tag-create step named by
the immutable annotation and the exact successful protected resume attempt
before signing, preserving recovery without treating an arbitrary existing tag
as authorization.

The release workflow runs its signing and publishing jobs only on matching,
protected-provenance tags. It blocks
if `v0.6.6` does not match `project.version = "0.6.6"` and
`agent_assure.__version__ = "0.6.6"`, if the active schema constants do not
match the mapped release schema version `0.6.6`, or if `schemas/v0.6.6` is
missing. The tag must resolve to `GITHUB_SHA`, be an ancestor of the default
branch, have matching release notes, and start and finish generation with a
clean source tree. A fresh job rebuilds the complete signing allowlist, compares
the actual bytes of the downloaded evaluation summary, comparison summary,
assurance evidence graph, packet JSON, packet Markdown, manifest, replay,
release notes, SBOM, wheel, and source distribution against that rebuild, and
replays the digests from the fresh-job rebuild. It stages the byte-matched
signing allowlist plus normalized, confined manifest/replay support files whose
raw digests are verified before and after copy. Those support files remain
outside the signing and GitHub Release allowlists. Manifest claims alone cannot
satisfy this gate.

After keyless signing, a non-OIDC verification job checks the exact workflow
identity, rejects modified-blob verification, validates the signed distribution
directory, verifies a confined descriptor-backed private snapshot, and atomically
promotes both the complete verified signed bundle and an exact
`.whl`/`.tar.gz` pair. A fresh post-upload job then downloads both immutable
artifact IDs, repeats full signature and binding verification, and proves that
the separate two-file distribution view is byte-identical by filename to the
full bundle's distributions. GitHub Release and PyPI consume those same IDs only
after this job succeeds; no new artifact is uploaded after the final check.
Neither publisher reads the mutable verifier input or executes project code.

PyPI receives only the wheel and source distribution. The packet-bound
evaluation and comparison summaries, assurance evidence graph, release packet,
manifest, SBOM, digest replay file, and signature bundles live on the GitHub
release and are the cryptographic provenance chain for the package files.

If publication fails after verification succeeds, rerun the failed publisher
job from the same workflow run so it downloads the same content-addressed
distribution artifact. The GitHub release job intentionally refuses to replace
an existing release or asset. Do not push a replacement tag or create a fresh
build for the same version.

If a publisher cannot be rerun because the immutable tagged workflow itself
contains a publisher-only defect, use only the exact, repository-declared
recovery operation for that failed run. The v0.6.0 recovery is fixed to the
original run, attempt, commit, artifact IDs, artifact digests, tag, workflow
identity, and a separately protected recovery ref. Its unprivileged verifier
rechecks GitHub metadata, keyless signatures, exact bytes, and unpublished
state, then promotes new content-addressed artifacts for the minimal
GitHub-release and PyPI jobs. GitHub denies `GITHUB_TOKEN` release creation in
some cases when the tagged commit's workflow differs from the default branch.
For this exception, the release owner downloads the verifier-promoted artifact
and creates the exact draft with a workflow-authorized credential. The
read-only GitHub-release job then requires the owner identity, exact notes,
exact 16-asset name set, and a byte-for-byte download match before PyPI can
proceed. Never move or recreate `v0.6.0`, broaden the recovery inputs, or
rebuild its distributions.

After the workflow publishes to PyPI, validate the final package from a clean
environment.

CI, WSL, or Git Bash:

```bash
python -m venv /tmp/agent-assure-pypi
source /tmp/agent-assure-pypi/bin/activate
python -m pip install --upgrade pip
python -m pip install agent-assure==0.6.6
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
python -m pip install agent-assure==0.6.6
agent-assure --version
agent-assure demo flagship --out $FlagshipOut --clean
deactivate
Remove-Item -LiteralPath $InstallTemp -Recurse -Force
Remove-Item -LiteralPath $FlagshipOut -Recurse -Force
```
