# Release Evidence

Release evidence consists of the flagship fixture-mode outputs, an evidence
packet, a release artifact manifest, a digest replay file, an SBOM, Python
distribution artifacts, and optional keyless cosign bundles created by GitHub
Actions workflows.

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
packet, manifest, and replay-file blobs are still exact release artifacts and
must be verified with their matching cosign bundles when cryptographic workflow
identity is required.

## Build a Release Bundle

From a clean checkout:

```bash
pip install -e ".[dev]"
python scripts/build_release_bundle.py --out .tmp/release --write-digests .tmp/release/release-digest-replay.json
agent-assure release replay .tmp/release/release-digest-replay.json --artifact-root . --require-current-commit
```

The bundle directory contains the evidence packet, Markdown packet, release
artifact manifest, digest replay file, SBOM, Python source distribution, wheel,
run sets, reports, fixture manifest, and dependency inventory.

## Reproduce From a Tag

After the target tag exists, reproduce from a clean checkout of the tagged
commit and the downloaded release bundle:

```bash
git checkout v0.2.0
pip install -e ".[dev]"
python scripts/build_release_bundle.py --out .tmp/release --write-digests .tmp/release/release-digest-replay.actual.json --source-ref refs/tags/v0.2.0
agent-assure release replay path/to/downloaded/release-digest-replay.json --artifact-root . --expect-ref refs/tags/v0.2.0 --require-current-commit
```

The script reruns the flagship suite and rebuilds local release artifacts. The
replay command checks the published digest replay against regenerated local
files. It fails if the checkout commit differs from the commit recorded in the
replay file, a required release artifact is missing, or any regenerated replay
digest differs. If the current git commit cannot be determined, commit-bound
replay fails closed.

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

Replay artifact paths must be relative to `--artifact-root` and cannot include
parent-directory segments. `--expect-commit` validates the replay file's
`source_commit`; `--expect-ref` validates the replay file's `source_ref`.
`--require-current-commit` separately checks the current checkout against the
replay file's `source_commit`.

## Sign Blobs

The evidence workflow signs these blobs with GitHub Actions OIDC identity:

```bash
cosign sign-blob --yes --bundle evidence-packet.json.bundle evidence-packet.json
cosign sign-blob --yes --bundle release-artifact-manifest.json.bundle release-artifact-manifest.json
cosign sign-blob --yes --bundle release-digest-replay.json.bundle release-digest-replay.json
cosign sign-blob --yes --bundle sbom.cdx.json.bundle sbom.cdx.json
cosign sign-blob --yes --bundle agent_assure-0.2.0-py3-none-any.whl.bundle agent_assure-0.2.0-py3-none-any.whl
cosign sign-blob --yes --bundle agent_assure-0.2.0.tar.gz.bundle agent_assure-0.2.0.tar.gz
```

The repository workflow pins the cosign binary to `v3.0.6` through the
`cosign-release` installer input.

## Verify Workflow Identity

Use the exact repository, workflow name, tag ref, release commit, and trigger
that produced the signed release bundle:

```bash
REPO=acblabs/agent-assure
TAG=v0.2.0
SHA=<release-commit-sha>
ISSUER="https://token.actions.githubusercontent.com"

cosign verify-blob evidence-packet.json \
  --bundle evidence-packet.json.bundle \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer "${ISSUER}" \
  --certificate-github-workflow-name "release" \
  --certificate-github-workflow-repository "${REPO}" \
  --certificate-github-workflow-ref "refs/tags/${TAG}" \
  --certificate-github-workflow-sha "${SHA}" \
  --certificate-github-workflow-trigger "push"
```

Repeat the same verification command for `release-artifact-manifest.json`,
`release-digest-replay.json`, `sbom.cdx.json`, the wheel, and the source
distribution with their matching `.bundle` files. The evidence workflow may
also produce signed evidence blobs; for those artifacts, use workflow name
`evidence`. Cosign verification is byte-exact: changing a signed file
invalidates the signature. This is separate from digest replay, which uses
stable projections for environment-bearing JSON artifacts.

Sigstore documents keyless blob signing and GitHub Actions OIDC signing at
https://docs.sigstore.dev/cosign/signing/signing_with_blobs/ and
https://docs.sigstore.dev/quickstart/quickstart-ci/.

## Limits

Signed release evidence says that a specific workflow identity signed exact
bytes. The SBOM records the local release build environment and distribution
file hashes; it is not a vulnerability assessment or supply-chain attestation.
Replay cross-checks manifest-listed digests when the files are available under
the artifact root, but it is still not a signature and does not replace cosign
verification. Signed release evidence does not establish safety assurance,
compliance status, clinical validity, live model quality, or OpenTelemetry
adoption.
