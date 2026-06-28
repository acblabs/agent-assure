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

The persisted run schema is intentionally lean for deterministic fixture mode
and adds optional live operational fields for protocol-bound observations. It
does not persist raw model-call payloads, raw tool arguments, retrieval records,
risk tags, or capability inventories. Persisted numeric operational values use
strings or integers rather than Python Decimal, float, or datetime objects.

RunSet `runset_digest` is an exact artifact digest used for waiver scoping and
local reproducibility. Release replay uses role-specific stable projections for
environment-bearing reports, packets, and manifests, and excludes only the
defined environment fields for each role.
