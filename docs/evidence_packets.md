# Evidence Packets

Evidence packets summarize deterministic fixture-mode evidence for CI and
release review. A packet contains an evaluation summary, an optional comparison
summary, a machine-readable interpretation section, local environment metadata,
deterministic SHA-256 digests of the summary files used to build it, a
dependency-inventory digest, a release artifact manifest, and explicit
limitations.

```bash
agent-assure packet build \
  .tmp/showcase/evidence-report/evaluation-summary.json \
  --comparison .tmp/showcase/comparison-report/comparison-summary.json \
  --out .tmp/showcase/evidence-packet.json
agent-assure ci gate .tmp/showcase/evidence-packet.json
```

`packet build` also writes `evidence-packet.md`,
`dependency-inventory.json`, and `release-artifact-manifest.json` beside the
JSON packet unless explicit output paths are provided. For a known failing
candidate, the CI gate is expected to exit `1` after reading the packet.

The dependency inventory is a best-effort runtime package listing generated
from the active Python environment. Release bundles additionally write an SBOM
that records package URLs for installed packages and SHA-256 hashes for the
built wheel and source distribution. Neither artifact is a vulnerability
assessment or supply-chain attestation.

Release replay cross-checks manifest-listed artifact digests when the referenced
files are available under the replay artifact root. That reproducibility check
is separate from cosign verification of exact workflow-signed blobs.

Packet artifact digests, dependency-inventory digests, and release-manifest
digests are raw SHA-256 hashes over the LF-normalized JSON files that were
written locally. They are environment-bound exact-artifact anchors, not the
cross-platform-stable JCS content digests used for suites, fixture manifests,
and runset provenance. `packet_id` is derived from the redacted summaries after
local environment metadata is excluded, plus interpretation text and
limitations; it intentionally excludes exact-file digests and the release
manifest.

Release evidence can attach keyless cosign bundles to the packet, release
artifact manifest, digest replay file, SBOM, wheel, and source distribution.
Those signatures verify the exact bytes and workflow identity that signed them;
they do not turn packet contents into safety, compliance, clinical-validation,
live model-quality, or standards adoption evidence. See
`docs/release_evidence.md` for exact verification commands.
