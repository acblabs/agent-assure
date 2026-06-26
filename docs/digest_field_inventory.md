# Digest Field Inventory

Normative digest path:

1. Typed value.
2. `digest_projection`.
3. `canonical_bytes`.
4. SHA-256 or HMAC-SHA256.

Digest-relevant fields include suite authoring content, compiled suite
artifacts, expectation digests, RunSet `suite_digest` and
`fixture_manifest_digest` bindings, fixture manifest entries, run records, span
plans, and manifest paths.

Configuration decimals use fixed six-place strings, for example `0.700000`.
