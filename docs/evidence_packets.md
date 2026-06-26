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
from the active Python environment. It is not a CycloneDX-conformant SBOM and
does not include package URLs, wheel hashes, licenses, or a dependency graph.

Packet artifact digests, dependency-inventory digests, and release-manifest
digests are raw SHA-256 hashes over the LF-normalized JSON files that were
written locally. They are environment-bound exact-artifact anchors, not the
cross-platform-stable JCS content digests used for suites, fixture manifests,
and runset provenance. `packet_id` is derived from the redacted summaries after
local environment metadata is excluded, plus interpretation text and
limitations; it intentionally excludes exact-file digests and the release
manifest. Cryptographically signed attestations remain outside the current claim
boundary.
