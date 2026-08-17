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
packet Markdown, packet-bound evaluation and comparison summaries, assurance
evidence graph, manifest, replay, SBOM, wheel, source distribution, and release
notes when present; it never treats manifest-declared hashes as proof of the
downloaded bytes. The reproduction job stages under a new artifact ID only files
rebuilt in that fresh job: byte-matched signing inputs plus normalized,
confined manifest/replay dependencies whose raw digests are checked before and
after staging. The support files let the later verifier replay the complete
manifest; they are not added to the signing or public-release allowlists. This
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
cosign sign-blob --yes --bundle evaluation-summary.json.bundle evaluation-summary.json
cosign sign-blob --yes --bundle comparison-summary.json.bundle comparison-summary.json
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
would create a circular digest relationship with the packet they render. The
unprivileged verifier reconstructs packet Markdown from the validated packet
model and reads release notes from the immutable release-commit Git blob, then
requires exact byte equality.

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
`evaluation-summary.json`, `comparison-summary.json`,
`assurance-evidence-graph.json`, `release-artifact-manifest.json`,
`release-digest-replay.json`, `sbom.cdx.json`, the wheel, and the source
distribution with their matching `.bundle` files. After every exact-blob
signature passes, the repository verifier requires the signed top-level
manifest to equal the manifest nested in the packet. It then reopens the signed
evaluation summary, comparison summary, and graph through the trusted artifact
root, checks their exact manifest digests and nested packet models, and
reconstructs the graph from the packet evidence. The verifier also hashes every
manifest-listed file, requires the manifest's SBOM, wheel, and source-distribution
roles to identify the signed runtime-discovered files, and checks the complete
versioned replay role set against the trusted workflow SHA and ref. Replay roles
for the graph, packet, and manifest must identify those same signed files. Packet
Markdown must exactly match deterministic rendering of the signed packet, while
tag release notes must exactly match `docs/release_notes/<tag>.md` at the signed
Git commit. These bindings connect every fixed and runtime-discovered release
asset, so a mixed set from distinct otherwise valid builds fails before
promotion even when every file has a valid signature for the same workflow
identity. The workflow verifier copies the confined allowlist through validated
file descriptors into a private snapshot, verifies that snapshot, rejects every
missing or extra file or directory and every link, reparse point, or non-regular
entry, rechecks the exact inventory and bytes, and atomically promotes separate
full-release and wheel-plus-sdist views.

Promotion is not the publication trust boundary because the promoted workspace
remains writable until upload completes. The verifier therefore uploads both
views, then a new unprivileged job downloads those exact immutable artifact IDs.
That fresh job repeats full-tree signature and coherent-binding verification
from a private captured snapshot and requires the independently uploaded
distribution view to contain exactly the same wheel and source-distribution
bytes as the full bundle. Only after that check succeeds does it expose the
same IDs to the GitHub Release and PyPI jobs; it does not upload another copy.
The evidence workflow applies the same post-upload full-bundle verification to
its immutable artifact ID. Publisher jobs never read a mutable verifier tree.
Verification reads and validates data only; it does not import from or execute
the wheel or source distribution. The evidence workflow may also produce
signed evidence blobs; for those artifacts, use workflow name `evidence`. Cosign
verification is byte-exact: changing a signed file invalidates the signature.
This is separate from digest replay, which uses stable projections for
environment-bearing JSON artifacts.

Sigstore documents keyless blob signing and GitHub Actions OIDC signing at
https://docs.sigstore.dev/cosign/signing/signing_with_blobs/ and
https://docs.sigstore.dev/quickstart/quickstart-ci/.

An unprivileged prerequisite job performs workflow-identity verification and
stages an exact two-file distribution artifact. A second fresh job re-downloads
and verifies the uploaded full and distribution artifact IDs. The PyPI publisher
downloads that same verified distribution ID and performs no checkout or
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
