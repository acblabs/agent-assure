# Release Evidence

Release evidence consists of the flagship fixture-mode outputs, an evidence
packet, its assurance evidence graph, a release artifact manifest, a digest
replay file, an SBOM, Python distribution artifacts, and optional keyless
cosign bundles created by GitHub Actions workflows.

The digest replay file records raw SHA-256 file digests for replay-stable
source artifacts, such as the compiled suite and fixture manifest. For
environment-bearing review artifacts, such as the evidence packet and release
artifact manifest, it records a stable JSON projection digest that excludes
volatile local environment fields while keeping deterministic verdict content.
It is a reproducibility check, not a signature. When replay verifies the release
artifact manifest, it also cross-checks each manifest-listed `sha256` against
the available artifact bytes, including SBOM and Python distribution entries.
For environment-bearing child artifacts, replay still uses stable child
projections when computing the release-manifest replay digest. The top-level
packet, evidence-graph, manifest, and replay-file blobs are still exact release
artifacts and must be verified with their matching cosign bundles when
cryptographic workflow identity is required. Evidence-graph stable replay
retains semantic payloads, states, identities, and edges while excluding only
graph/payload digests and evaluation/comparison source digests transitively
affected by volatile environment metadata. Raw graph bytes remain independently
SHA-256 checked.

## Build a Release Bundle

From a clean checkout:

```bash
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
python scripts/build_release_bundle.py --expected-release 0.6.3 --out .tmp/release --write-digests .tmp/release/release-digest-replay.json
agent-assure release replay .tmp/release/release-digest-replay.json --artifact-root . --require-current-commit
```

The bundle directory contains the evidence packet, Markdown packet, assurance
evidence graph, release artifact manifest, digest replay file, SBOM, Python
source distribution, wheel, run sets, reports, fixture manifest, dependency
inventory, and per-step command logs under `logs/`.

## Reproduce From a Tag

After the target tag exists, reproduce from a clean checkout of the tagged
commit and the downloaded release bundle:

```bash
TAG=v0.6.3
RELEASE="${TAG#v}"
git checkout "${TAG}"
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps --no-build-isolation -e .
python scripts/build_release_bundle.py --expected-release "${RELEASE}" --out .tmp/release --write-digests .tmp/release/release-digest-replay.actual.json --source-ref "refs/tags/${TAG}"
agent-assure release replay path/to/downloaded/release-digest-replay.json --artifact-root . --expect-ref "refs/tags/${TAG}" --require-current-commit
```

The script reruns the flagship suite and rebuilds local release artifacts. The
replay command checks the published digest replay against regenerated local
files. It fails if the checkout commit differs from the commit recorded in the
replay file, a required release artifact is missing, or any regenerated replay
digest differs. If the current git commit cannot be determined, commit-bound
replay fails closed.

Core completeness follows the loaded replay schema version. Frozen replay
schemas through v0.6.2 require the historical compiled-suite, fixture-manifest,
evidence-packet, and release-artifact-manifest roles. The v0.6.3 writer also
requires assurance-evidence-graph. Unknown version policies fail closed;
explicit `--require-role` options add requirements without replacing that
versioned core set.

For an already generated artifact directory:

```bash
agent-assure release replay release-digest-replay.json --artifact-root . --require-current-commit
```

Standalone replay follows the artifact paths inside the release artifact
manifest projection and enforces the manifest's recorded child digests. Keep the
full generated artifact tree available under `--artifact-root`, including run
sets, summaries, dependency inventory, SBOM, wheel, and source distribution; a
reports-only directory is not sufficient.

The evidence workflow also compares published and rebuilt distribution entries
before replay. If a wheel or source distribution stops being byte-reproducible,
that check reports the specific distribution filename and digest pair before
the broader release-manifest replay check runs.

Release bundle scripts pin waiver-sensitive CI evaluation to `2026-07-03` and
default subprocesses to `SOURCE_DATE_EPOCH=1783036800` unless the environment
already sets a value. Those values were established for v0.6.0 replay,
deliberately retained for v0.6.1, v0.6.2, and v0.6.3. Keep them fixed when
replaying these release lines.

Replay artifact paths must be relative to `--artifact-root` and cannot include
parent-directory segments. `--expect-commit` validates the replay file's
`source_commit`; `--expect-ref` validates the replay file's `source_ref`.
`--require-current-commit` separately checks the current checkout against the
replay file's `source_commit`.

Commands keep source provenance separate from artifact path rooting. Git commit
and lockfile metadata are collected from the source project root, while release
manifest paths are made relative to an artifact root that can also cover an
external report directory. Artifact paths still fail closed if they cannot share
a common filesystem root. The bundled release scripts require `--suite`,
`--baseline-variant`, and `--candidate-variant` inputs to stay under the
repository root; copy external release inputs into the repository before
building a release bundle.

Fixture release artifacts are the deterministic release path. Live RunSets and
live reports can carry host timestamps, latency measurements, scheduling
jitter, provider metadata, and emergency-record timing from real execution.
Treat live artifacts as time-bound operational evidence with raw artifact
digests, not byte-replay-stable fixture evidence.

## Sign Blobs

Only after a fresh job rebuilds the complete signing set and compares every
downloaded signing input by its actual SHA-256 bytes does a minimal GitHub
Actions OIDC job sign the reviewed blob set. The comparison covers packet JSON,
packet Markdown, manifest, replay, SBOM, wheel, source distribution, and release
notes when present; it never treats manifest-declared hashes as proof of the
downloaded bytes. The reproduction job stages under a new artifact ID only
files rebuilt in that fresh job and byte-matched to the downloaded inputs. This
establishes same-toolchain fresh-job reproducibility, not reproduction by an
independent implementation or diverse toolchain. The signer downloads only
that ID and has no checkout, Python setup, dependency installation, package
import, or package execution. It is tag-only and protected by the `signing`
environment. A separate job without OIDC verifies the exact workflow identity
and promotes the verified signed bundle. Signed blobs include:

Both signing workflows require a `v*` tag. The evidence workflow also checks
that the tag resolves to the workflow commit, matches the package version, and
is reachable from the repository's default branch before its OIDC job can run.

```bash
cosign sign-blob --yes --bundle evidence-packet.json.bundle evidence-packet.json
cosign sign-blob --yes --bundle evidence-packet.md.bundle evidence-packet.md
cosign sign-blob --yes --bundle assurance-evidence-graph.json.bundle assurance-evidence-graph.json
cosign sign-blob --yes --bundle release-artifact-manifest.json.bundle release-artifact-manifest.json
cosign sign-blob --yes --bundle release-digest-replay.json.bundle release-digest-replay.json
cosign sign-blob --yes --bundle sbom.cdx.json.bundle sbom.cdx.json
cosign sign-blob --yes --bundle agent_assure-0.6.3-py3-none-any.whl.bundle agent_assure-0.6.3-py3-none-any.whl
cosign sign-blob --yes --bundle agent_assure-0.6.3.tar.gz.bundle agent_assure-0.6.3.tar.gz
```

The tag release workflow also signs its reviewed `release-notes.md`. The
human-readable evidence packet and release notes are signed exact-byte
derivatives; they are not included in the release manifest because doing so
would create a circular digest relationship with the packet they render.

The repository workflow pins the cosign binary to `v3.0.6` through the
`cosign-release` installer input.

## Verify Workflow Identity

Use the exact repository, workflow name, tag ref, release commit, and trigger
that produced the signed release bundle:

```bash
REPO=acblabs/agent-assure
TAG=v0.6.3
SHA=<release-commit-sha>
ISSUER="https://token.actions.githubusercontent.com"
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"

cosign verify-blob evidence-packet.json \
  --bundle evidence-packet.json.bundle \
  --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-github-workflow-name "release" \
  --certificate-github-workflow-repository "${REPO}" \
  --certificate-github-workflow-ref "refs/tags/${TAG}" \
  --certificate-github-workflow-sha "${SHA}" \
  --certificate-github-workflow-trigger "push"
```

Repeat the same verification command for `evidence-packet.md`,
`assurance-evidence-graph.json`, `release-artifact-manifest.json`,
`release-digest-replay.json`, `sbom.cdx.json`, the wheel, and the source
distribution with their matching `.bundle` files. The evidence workflow may
also produce signed evidence blobs; for those artifacts, use workflow name
`evidence`. Cosign verification is byte-exact: changing a signed file
invalidates the signature. This is separate from digest replay, which uses
stable projections for environment-bearing JSON artifacts.

Sigstore documents keyless blob signing and GitHub Actions OIDC signing at
https://docs.sigstore.dev/cosign/signing/signing_with_blobs/ and
https://docs.sigstore.dev/quickstart/quickstart-ci/.

An unprivileged prerequisite job performs workflow-identity verification and
stages an exact two-file distribution artifact. The PyPI publisher downloads
that verified artifact by immutable artifact ID and performs no checkout or
project-code execution.

## Limits

Signed release evidence says that a specific workflow identity signed exact
bytes. The SBOM records the local release build environment and distribution
file hashes; it is not a vulnerability assessment or supply-chain attestation.
Replay cross-checks manifest-listed digests when the files are available under
the artifact root, but it is still not a signature and does not replace cosign
verification. Signed release evidence does not establish safety assurance,
compliance status, clinical validity, live model quality, or OpenTelemetry
adoption.
