# Provenance And Hashing

Hashes answer which material participated in a run. They do not decide whether a
behavior is correct.

Current digest behavior:

- values are projected through `digest_projection`;
- decimals are represented as JSON strings in digest projections;
- strings must be NFC-normalized;
- RFC 8785 JCS bytes are produced by one implementation path;
- SHA-256 is used for content digests;
- HMAC-SHA256 is used for sensitive low-entropy correlations.
