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

The v0.1 persisted run schema is intentionally lean for deterministic fixture
mode. It does not persist live timestamps, status transitions, model-call or
tool-call records, retrieval records, observed metrics, risk tags, variants, or
capability inventories. No current persisted model carries a Decimal, float, or
timestamp field; decimal normalization is unit-tested support for future
digest-relevant configuration rather than an exercised integration path.

RunSet `runset_digest` is an exact artifact digest used for waiver scoping and
local reproducibility. Release replay uses role-specific stable projections for
environment-bearing reports, packets, and manifests, and excludes only the
defined environment fields for each role.
