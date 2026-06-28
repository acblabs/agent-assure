# Digest Field Inventory

Normative digest path:

1. Typed value.
2. `digest_projection`.
3. `canonical_bytes`.
4. SHA-256 or HMAC-SHA256.

The generic `digest_projection` path preserves explicit `None` values as
identity data. That is correct for typed artifact identity digests, including
frozen live protocol records. Digest roles that need missing optional fields
and explicit null fields to be equivalent must define a role-specific
projection that removes those fields before canonicalization.

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
Optional live advanced-analysis endpoint plans are part of
`live-protocol-record` and therefore change the protocol digest. Derived
statistical-invariant results, rare-event bounds, observed cluster-correlation
summaries, and paired randomization test outputs are persisted report fields;
they are review evidence bound to the protocol digest rather than independent
provenance roots.

Optional live drift-monitoring plans are also part of `live-protocol-record`
and therefore change the protocol digest. Derived `live-drift-report`
artifacts carry comparability results, ordered-window summaries, trend,
adjacent-step, serial-dependence, AR(1), and EWMA monitoring diagnostics when
their declared window-count prerequisites are met. These diagnostics are review
evidence derived from protocol-bound live evaluation reports; they are not
independent provenance roots and are not release-verdict shortcuts.

Optional live trajectory-analysis plans are part of `live-protocol-record` and
therefore change the protocol digest. Derived `live-trajectory-report`
artifacts carry privacy-filtered path summaries, transition summaries,
sequence-invariant results, history-dependent checks, and operational
event-process summaries. They are review evidence derived from structured
protocol-bound live artifacts; they do not persist raw prompts, raw outputs,
tool arguments, sensitive identifiers, or unredacted summaries, and they are
not independent provenance roots or release-verdict shortcuts.

RunSet `runset_digest` is an exact artifact digest used for waiver scoping and
local reproducibility. Release replay uses role-specific stable projections for
environment-bearing reports, packets, and manifests, and excludes only the
defined environment fields for each role.

For the v0.2 release surface, digest-bearing additions are covered through the
`live-protocol-record` digest, live RunSet protocol bindings, JSON Schema
parity fixtures, and schema export drift checks. Release replay still verifies
the deterministic release bundle and manifest-listed artifact bytes; it does
not turn arbitrary later live workspaces into signed release evidence unless
those artifacts are explicitly included in a future release bundle manifest.
