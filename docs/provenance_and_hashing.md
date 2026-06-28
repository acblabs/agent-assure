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

The current schema keeps fixture-mode provenance narrow while allowing live
records to carry optional operational metadata such as timestamps, token counts,
latency, and estimated cost as schema-normalized strings and integers. RunSet
digests are exact artifact digests over persisted fields, not a separate
observed-value-free provenance projection. Release replay is the place where
environment-bearing review artifacts use explicit stable projections.
