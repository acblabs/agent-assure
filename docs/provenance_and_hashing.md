# Provenance And Hashing

Hashes answer which material participated in a run. They do not decide whether a
behavior is correct.

Current digest behavior:

- values are projected through `digest_projection`;
- digest-relevant configuration decimals are quantized to six places and
  represented as JSON strings in digest projections;
- strings must be NFC-normalized;
- RFC 8785 JCS bytes are produced by one implementation path;
- SHA-256 is used for content digests;
- fixture manifests hash file bytes and use canonical digests for the manifest
  artifact;
- HMAC-SHA256 is used for sensitive low-entropy correlations.
