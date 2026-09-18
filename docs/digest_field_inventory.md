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

`provider_response_payload_sha256` is a deliberate raw-byte commitment rather
than a typed canonical-artifact digest. A built-in live adapter applies SHA-256
directly to the exact bounded response byte sequence before decoding,
normalization, or parsing. Its required `provider_response_payload_scope`
identifies whether those bytes are a complete HTTP response body, complete
external-script stdout, one complete static JSONL record, or bytes declared by
an unregistered adapter. The successful-attempt journal repeats the same pair.
Study provenance canonically hashes the sorted `(arm_id, run_id, scope,
payload_sha256)` tuples into a separate aggregate set digest; confirmatory
real-provider eligibility requires one complete-HTTP-body commitment per run.
Neither digest is provider authentication, a signature, confidentiality, or
proof that a transport supplied every upstream byte.

`StudyStatisticalMethodReviewReceipt.registration_review_receipt_digest` is a
logical backlink to the exact self-digested registration-review receipt that
the method-review command revalidated against the raw registration record. It
orders and binds the two human attestations; it is not a second hash of the raw
record and does not authenticate either reviewer. Validation requires the
method-review timestamp to be strictly later than the bound registration
review.

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

The canonical RunSet digest is SHA-256 over RFC 8785 canonical bytes of the
version-aware schema-validated, current `RunSet` model JSON projection. The
projection retains the accepted `schema_version` and materializes
schema-permitted omitted defaults. Mutation campaigns, nested results,
evidence subjects, and evaluator reports use this same identity for source
content, while transformed-result and candidate-report digests share the
corresponding candidate projection. The digest is used for waiver scoping and
local reproducibility; v0.6 evaluation reports persist it as `runset_digest`.
Release replay uses role-specific stable projections for environment-bearing
reports, packets, and manifests, and excludes only the defined environment
fields for each role.

A campaign creates this source identity only after three ordered preflight
checks: strict JSON values, successful RunSet validation/model projection, and
bound-profile privacy scans of both the copied input and projection. Failure at
any stage is a campaign-level rejection before hashing or artifact creation;
the canonical-JSON, projection, and privacy classes have separate fixed
messages. Single-operator schema and source-privacy failures remain
`invalid_subject` results rather than campaign artifacts.

For the v0.2 release surface, digest-bearing additions are covered through the
`live-protocol-record` digest, live RunSet protocol bindings, JSON Schema
parity fixtures, and schema export drift checks. Release replay still verifies
the deterministic release bundle and manifest-listed artifact bytes; it does
not turn arbitrary later live workspaces into signed release evidence unless
those artifacts are explicitly included in a future release bundle manifest.
