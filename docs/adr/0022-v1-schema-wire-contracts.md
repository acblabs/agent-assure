# ADR 0022: Writer compatibility, wire contracts and digest dependencies

- Identifier: `ADR-V1-SCHEMA`
- Ticket: `V1-BASE-09`
- Status: `proposed_for_development`
- Target profile: `stable-core/v1`
- Owner responsibility: `technical_lead`
- Reviewer responsibility: `repository_maintainer`
- Required reviewer competence: `schema_compatibility`
- Approval mode proposed: `maintainer_development`
- Review limitation: `NO_INDEPENDENT_REVIEW`
- Start receipt: `drafting_authorization`; completion receipt: `development_design_acceptance`
- Dependencies: exact accepted `V1-BOOT-01` and `V1-BASE-01` development receipts

This draft proposes the compatibility and schema-first contract. It neither
publishes a new writer nor accepts one. The existing roster records only S1
competence; it does not record `schema_compatibility`. The role name, control of
a signing key, or this draft cannot supply that missing competence declaration.
Human assignment/competence review and the exact signed ADR acceptance remain
pending. Successor S1 acceptance and the approved dispatch scope remain gates.

## Actual repository boundary

The current package is `0.7.0` and the current persisted writer is `0.6.6`, as
declared independently in `pyproject.toml`, `agent_assure/__init__.py`, and
`schema/base.py`. These are different identities by design. `PersistedArtifact`
enforces strict/frozen models and the RFC 8785 safe-integer range. Exported
persisted roots explicitly require their identity fields even when a Python
constructor has defaults. Production loading must inspect raw identity fields
before parsing so defaults cannot manufacture a missing wire identity.

The existing compatibility registry is `FROZEN_ROOT_VALIDATION_POLICY` in
`schema/validation.py`, keyed by exact `(artifact_kind, schema_version)` pairs.
Its current implementation distinguishes current semantics, version-specific
semantic replay, and archival-only roots; unknown pairs fail. Frozen-schema
loading verifies exact schema dispatch and rejects remote schema references.
Source-checkout discovery is an existing convenience; installed-wheel discovery
uses `importlib.resources` and the immutable `agent_assure.schema_resources`
package. Do not invent a second registry in a nonexistent `schema/registry.py`.

The verified generation path is source models -> `schema/export.py` ->
development `schemas/unreleased/` -> reviewed new frozen `schemas/v*` snapshot
and packaged resource mapping. `scripts/schema_versions.py` reads the active
writer identity from the model source. `scripts/sync_schema_force_includes.py`
reconciles frozen resources with wheel packaging. `make schema-staging` exports
development resources; `make schema-check` checks the approved generated
resources and include mapping. S2 does not edit frozen snapshots or bump the
package/writer version to make a planning example appear implemented.

## Compatibility matrix and offline registry

The new matrix is an immutable, versioned package resource. Every cell has the
exact tuple `(producer_package_version, writer_schema_version, artifact_kind,
reader_package_version)` and a disposition, minimum reader, schema-resource
digest, semantic-replay identity, migration identity or explicit `null`, losses,
and authorization restrictions. Ranges may be represented only as an explicitly
expanded, tested set in the published registry. No missing cell is a wildcard.

| Condition | Reader disposition | Meaning |
| --- | --- | --- |
| Exact registered cell with complete version-specific replay and all policy/admission prerequisites | `semantic_replay_and_authorization_eligible` | Schema/semantic compatibility permits consideration; actual authority still requires the manifest, eligible evidence, qualification and current context. |
| Exact registered archival/limited-replay cell | `shape_and_integrity_only` | Validate original shape and hashes for inspection; no v1 authorization support. |
| Missing cell, unavailable immutable resource, unmet minimum reader, unknown contract or unsupported migration | `unsupported` | Fail closed with an explicit compatibility reason; do not parse with the nearest model. |

Current baseline cells remain derived from the exact existing frozen-root policy
and its tests. Current semantic replay does not imply that historical process
facts are sufficient for a new v1 claim. In particular, no `0.7.0`/`0.6.6` cell
currently establishes v1 action-consumption, closure or deployment authorization.
All prospective v1 cells remain unsupported until `SCHEMA-01A` implements and
reviews the explicit matrix. The `1.0.0` version strings and
`authorization-evidence-packet` label in `SCHEMA-001` are seed inputs, not a
reservation of the production writer or a new canonical artifact ontology.
`V1-SCHEMA-01` must select the new writer identity through reviewed source models
and preserve the existing `EvidencePacket` extension boundary.

An installed wheel must resolve the registry and every referenced schema offline,
outside the checkout, with user-site and source fallbacks disabled. Its resource
digest must equal the candidate-bound schema inventory. An absent or malformed
resource is unsupported; downloading a schema or silently consulting a checkout
is forbidden on this verification path. A schema file at the expected name is
not sufficient: its exact root discriminator/version vocabulary must admit the
declared pair. The minimum-reader check runs before semantic projection.

## Ordering migration and retained source identity

Replace the ambiguous use of one sequence field in new writers with an explicit
ordering-basis discriminator. Values distinguish authoritative global order,
authoritative producer-local order, transport-only order and no order. A required
storage ordinal supports deterministic storage only. A qualified source sequence,
when present, binds scope, producer, epoch, sequence value and authority-contract
identity. Explicit happens-before facts bind their basis and provenance.

Migrations preserve original bytes and exact-file digest. A derived artifact
binds source identity/digest, migration ID/version, applied defaults, all losses,
target schema and reader disposition. It must not invent causality, terminal
closure, approval consumption, eligibility, authority or a successful conclusion
from a historical boolean, transport position, timestamp, span parent or pass.
Qualified producer terminal-count closure requires the authenticated channel and
epoch, exact half-open contiguous range, count and digest; a gap is not complete.

Migration never mutates the source. A lossless syntactic migration cannot promote
evidence authority. A lossy downgrade of an authorization-bearing artifact is
rejected rather than relabeled as compatible. An inspection-only export may
describe its losses and retain its nonauthorizing disposition; it must not keep
an eligible authorization flag or signature over changed semantics.

## Closed production inventory and shared field rules

The companion [wire-contract inventory](../governance/v1/sprint2/wire-contract-inventory.json)
is a proposed design input, not a production schema registry. It enumerates the
exact 42 `SCHEMA-01D` contracts, current-subject digest dependencies, historical
bindings, and schema-first receipt edges. The shorter compatibility summary is
not a competing inventory. In particular,
`product-gate-producer-consumer-binding/v1` is included. Method-local records
outside this closed slice, such as activation preview or family-state projection,
retain their owning ticket's schema-first obligations; absence from this scoped
set does not exempt their first writer.

Every production object is closed (`additionalProperties=false` at every object
boundary) with constant contract discriminator, explicit required properties,
explicit nullable unions, bounded strings/collections/depth, and exact semantic
revalidation. An absent property is not equivalent to `null`; absence cannot
mean permission, zero cost, no adverse finding, complete coverage or successful
execution. Arrays that form sets have canonical order and explicit uniqueness;
arrays whose order is semantic retain that order. Identifiers and hashes are
bounded before arithmetic or allocations. Booleans are not integers. Decision
numbers obey `ADR-V1-NUM-STAT`; strings never smuggle nonfinite floats or
unbounded integer work into the validator.

Unless a specific contract below overrides it, its production resource must
require explicit `contract_id`, root `artifact_kind`, `schema_version`, exact
subject/scope identity, and its declared digest field. The accepted schema map
freezes each literal and all field names before a writer is merged. Optional
baseline, endpoint or obligation identities are required properties with a
declared `null` branch only when the contract permits nonapplicability. A missing
required dependency never becomes `null` merely to pass validation. Signatures
are separate from the canonical subject and are required for eligible use at
the authority boundary stated by the owning contract, even if an unsigned draft
can be structurally inspected.

The following table fixes required semantic payloads and the allowed
nonapplicability boundaries. The S3 field-level models and schemas must encode
all of them; adding or omitting conclusion-bearing semantics requires a new ADR
acceptance, not a permissive `Any` or free-form object field.

| Contracts | Required payload and nullability contract |
| --- | --- |
| `source-event-identity/v1` | Exactly `identity_contract_id`, `run_id`, `producer_id`, `producer_epoch`, `event_id`; the first is the literal contract ID, the other four are nonempty strings of at most 512 characters. No extra envelope fields, normalization or delimiter-concatenated identity. |
| `model-identity/v1` | Tier/identity class, actual serving revision or explicit unavailable value, configuration/runtime/tool/isolation/cache/window envelope, attestation authority and chain, claim-local eligibility and limitations. Tier 3 cannot populate a fabricated immutable revision; its unavailable attestation is explicit and nonauthorizing for stable B1/D1. |
| `signature-envelope/v1` | Cryptographic profile, exact subject digest/projection identity, domain, signer/key snapshot, role/scope/tenant, signature bytes and verification context. Required revocation/time/replay facts cannot be omitted. A detached envelope is not included in its signed subject. |
| `approval-receipt/v1` | Approval ID/generation, authority, source identity, candidate/run/tenant scope, action ID and action-version/content digest, validity, capacity/use policy, revocation context and exact signature binding. Unbounded validity is an explicitly typed endpoint, never missing expiry by accident. |
| `approval-allocation-proof-bundle/v1` | Method/domain/order/certificate identities, accepted-facts digest, fixed canonical vertex sets and complete pair-universe digest, must/may graph digests, classification basis and canonical certificate. Mixed fallback includes canonical direct history projections, digests and candidate-set digest. Raw-ID diagnostic arrays and `completion_oracle_conclusion` are forbidden. |
| `required-claim-manifest/v1` | Nonempty unique requirement rows with exact claim/obligation/evidence-mode/quantifier, subject/scope/digest, consumer, combination group/rule, authority, admission, qualification and exposure. Explicit scope disjointness proof or universal-veto dominance is required when relevant; a different scope digest is not a proof. |
| `veto-record/v1` | Registered veto kind, applicability and exact scope, admitted validation mechanism, trusted authority/validity, validated result digest, source and reason. Advisory or unvalidated findings cannot masquerade as admitted vetoes. |
| `authorization-capability-preflight/v1` | Exact manifest/policy/adapter/profile/model-identity bindings, per-claim reachability and unmet prerequisites, explicit nonauthorization, no execution, no index allocation and no alpha spend. |
| `authorization-artifact/v1` | Exact candidate/packet/policy/manifest/profile/context/head bindings, verifier freshness, unique requirement-to-evidence matches, conclusions/status/applicability/exposure/qualification/reasons, required evidence-drain completion and final boolean. Invalid input emits no eligible artifact. |
| `statistical-registration/v1` | Complete frozen decision-bundle identity, family/reservation/index lifecycle, population/sampling, endpoint vector/roles, margins/bounds/methods, both alpha allocations, cluster/reducer/missingness/protocol/identity, predictable schedule, stopping/drain policy and qualification envelope. Index is explicitly null only while reserved and unallocated. |
| `statistical-checkpoint/v1` | Registration/index/lifecycle, ordered source ledger and consumed cluster identities, batch/filtration protocol, replay-sufficient state, current conservative evidence, historical crossings, preceding checkpoint, stop and policy context. A first checkpoint has explicit null predecessor; moments-only state is insufficient for historical crossing replay. |
| `statistical-bundle-close-receipt/v1` | Exact registration, endpoint and bundle prefixes, terminal reason, endpoint vector, atomic close/predecessor identity and already launched observation set. Unresolved horizon is explicit and cannot be called PASS. |
| `evidence-consumer-disposition/v1` | Position/source identity and unique compiler-derived consumer instance; terminal execution/conclusion/applicability and source binding. Endpoint/obligation may be explicit null only when the consumer-instance type permits it. A nonapplicable cell needs its independent proof. |
| `evidence-consumer-drain-completion/v1` | Compiler-derived consumer registry, complete launched-position matrix, exact unique latest disposition set, nonapplicability proofs and digest/count equality. Missing, pending, cancelled, timed-out or duplicate cells cannot represent completed drain. |
| `release-candidate-manifest/v1` | Candidate/version, clean source commit/tree, build recipe/toolchain/environment/locks, exact staged wheel/sdist inventory, SBOM/provenance, schema matrix, methods/mappings/adapters/privacy/profiles/work limits and qualification policy. No rebuild or mutable alias replaces staged bytes. |
| `candidate-install-verification/v1` | Candidate and wheel digests, isolated environment and exact commands, interpreter/platform, wheelhouse/locks, installed version/location/RECORD/direct-url proof, CLI agreement, `pip check` and outcome. A failed check never yields integrity acceptance. |
| `candidate-equivalence-transfer/v1` | Exact source/target candidates, full transitive impact closure and per-control disposition/evidence, residual reruns, invalidators, issue/expiry and independent proof signature. Unresolved impact requires full rerun. |
| `qualification-bundle/v1` | Exact candidate/method/profile/platform subject, execution authorization, independently reviewed goldens, commands/results/resources and reviewer competence/independence receipts. Unavailable qualification is pending, never an empty passing list. |
| `pilot-readiness/v1` | Exact candidate/environment, readiness disposition, scoped execution authorization, protocol/identity/rollback/stop/data/resource controls and required qualification evidence. Only current READY starts a pilot. |
| `pilot-bundle/v1` | Readiness/candidate bindings, independent operator, four distinct scenario receipts (valid, substantive violation, observation gap, tamper-invalid), source/configuration/environment, outputs and byte-bound review. Tamper-invalid is not a process violation. |
| `profile-lifecycle-transition/v1` | Exact profile/version/candidate or release range, signed predecessor, state/replacement/reason/effective boundary, policy owner and support deadline. Replacement is explicit null only when absent; deprecated without a valid deadline is nonauthorizing. |
| `channel-artifact-manifest/v1` | Verifier-owned target identity/namespace and canonical unique expected `(path,kind,size,sha256)` inventory/count/set digest. Channel inventories differ legitimately; shared wheel/sdist bytes must agree. |
| `channel-publication-receipt/v1` | Candidate/target manifest, expected and independently read-back inventories, equality, terminal state, credential-free distinct verifier, capability and trusted read-back time. Partial/conflicting publication is not completion. |
| `preview-publication/v1` | Trusted release entry and exact nonempty source-ticket/accepted-receipt rows, source/tree/version, both channel manifests/read-backs, publisher authorization, installed-wheel verification, provenance/locks/SBOM/capability, independent verifier and `authorization_effect=none`. |
| `product-threshold-definition/v1` | Gate purpose/scope, exact metrics and numerical ceilings/floors, required segments, observation window, exposure and censoring rules, producer/authority separation, immutable issue/signature and change-control identity. Later thresholds cannot relabel old evidence. |
| `product-evidence-snapshot/v1` | Threshold/basis/candidate/scope, exact source ledgers/observations/counts, cutoff, window/exposure/assumptions, producer and nonauthorizing effect. Pilot-start evidence does not claim post-pilot adoption. |
| `product-exposure-floor-evaluation/v1` | Exact snapshot and threshold, per-segment denominator/exposure and elapsed-time checks, deterministic result/reasons; unavailable or zero denominator is not a passing rate. |
| `optional-train-start-threshold-evaluation/v1` | Exact optional profile/train and predecessor basis, snapshot/threshold/floor bindings, both demand comparisons when required, deterministic proceed/defer/reorder eligibility with no work-start authority of its own. |
| `product-gate-producer-consumer-binding/v1` | Exact producing/consuming ticket/work package/sprint/train, gate purpose, basis and authority profile, distinct evidence-producer and decision-signer identities. Unknown or cross-purpose consumers fail. |
| `product-gate-record/v1` | Exact evidence, purpose, producer/consumer binding, threshold/floor/time-order, candidate/predecessor basis, generation/validity and authorized decision. Acceptance does not imply `decision=proceed`. |
| `product-gate-generation/v1` | Series identity, generation number, parent or explicit generation-zero null, complete recomputed gate/evidence bindings, accepted status and supersession. A child cannot reuse stale values without recomputation. |
| `product-gate-series-controller/v1` | Series, authoritative unique live generation, expected predecessor and atomic update identity; trusted controller authority and scope. No two independently live generations. |
| `product-gate-sequence-head/v1` | Authenticated projection of the controller's exact accepted generation and monotonic sequence, not a competing source of authority. |
| `product-gate-trusted-time-order/v1` | Trusted threshold signature and predecessor commit/read-back observations, later-of start, cutoff, minimum duration, validity and clock/proof identity. Unattested producer timestamps cannot prove required freshness. |
| `assurance-registry-descriptor/v1` | Trusted discovery source, protected repository/ref namespace, sole writer, authentication/trust snapshots, CAS/read-back/freshness and fork/outage/rollback policies. Candidate-supplied discovery cannot choose policy. |
| `assurance-release-head/v1` | Exact candidate/artifact set, profile transitions, scoped approvals/qualification/pilot/product gates as selected, three independently verified GA channel receipts, expected predecessor, monotonic index and registry identity. No post-CAS commit proof is reachable from this head. |
| `assurance-head-commit-proof/v1` | Exact signed head and registry, expected predecessor, winning CAS commit, authenticated remote read-back, monotonic lineage and trusted verification time. It is issued after CAS and is never a head input. |
| `exceptional-deployment-authorization/v1` | Typed last-known-good rollback capsule: exact source/target/prior normal authorization/statistical projection/allocation/head/registry/context, outage predicate, nonce-store descriptor, monitoring/reconciliation, validity and distinct policy/security signatures. It never sets normal `authorized=true` or references its future consumption. |
| `rollback-nonce-state/v1` | Exact capsule/nonce, authoritative store descriptor/version, state, expected predecessor and idempotent command identity. Only `ISSUED -> CONSUMED`; initial predecessor is explicit null. No future receipt digest. |
| `rollback-consumption-receipt/v1` | Capsule/nonce, expected and winning store states/CAS, exact committed idempotent rollback command and verifier. Concurrent replay returns the winning command/receipt; it does not authorize another action. |
| `dispatch-context/v1` | Exact occurrence/source offsets/digests, scoped normative slices, required receipts, file allowlist, commands/limits/stop rules and lazy-retrieval manifest. Missing or oversized material fails dispatch rather than truncating it. |
| `structural-exploratory-topology-report/v1` | Exact exploratory source/transition/cluster definitions, protected-state/pooling policy, topology estimates/uncertainty/resources and advisory limitations. It cannot silently pool confirmatory state or support equivalence from nonsignificance. |

## Canonical projections and the acyclic artifact graph

For contract `c` the production schema freezes one projection `P_c`; its semantic
digest is `sha256:` plus lowercase SHA-256 of
`ASCII("agent-assure:" + c) || 0x00 || UTF8(RFC8785(P_c))`, except where an
already specified contract freezes a more specific domain/projection. Domain
identity is explicit in the production schema; the generic rule cannot override
the frozen matching-graph, pair-universe or witness projections. Exact-file
hashes remain separately named values over original bytes.

`P_c` excludes the object's declared self-digest property and detachable
signature envelope, using the exact field names frozen in its schema. There is
no recursive stripping of arbitrarily named nested fields. The signature
envelope covers the finalized exact subject/projection and domain-separated
claim. The subject cannot bind its own future envelope. Verification binds
authority, tenant/scope, key snapshot, revocation, time and replay context; a
valid signature does not establish truth, coverage or method admission.

The inventory's edge direction is **artifact binds dependency**. Edges are
allowed current-subject references, not a requirement to run every optional
profile. The selected manifest/profile independently determines mandatory
references and cardinality. A required reference cannot be silently dropped.
The resulting payload dependency graph is acyclic. In particular:

- Candidate bytes and immutable schema/method/policy inputs precede qualification,
  installed-wheel checks, pilots and channel receipts.
- Per-channel expected manifests precede independent read-back receipts. A GA
  head binds exactly private storage, GitHub and production PyPI receipts and
  its scoped release approvals. Public visibility does not activate assurance.
- The signed release head precedes registry CAS and remote read-back; the
  external commit proof follows those operations. The head never binds that
  proof, and none of its transitive inputs may refer to it.
- Current deployment authorization binds the committed head and its external
  proof; it is not an input to the head it authorizes against.
- A rollback capsule follows its prior normal authorization and provisions a
  store nonce. Nonce consumption and its receipt follow issuance. The capsule
  binds a store descriptor, never its future state/consumption receipt.

Contract *types* alone are insufficient to prove an artifact-instance DAG:
checkpoints, profile states, gate controllers and release heads have predecessor
links of the same type. The inventory therefore separates
`contract_dependencies` from `historical_bindings`. Each historical binding
requires a different immutable instance, strictly earlier generation/index,
authenticated ancestry and the correct series/family/registry scope. Product
evidence may bind an already committed predecessor head; it cannot bind the
future head that will consume its gate. A source candidate for equivalence
transfer is a distinct already frozen source instance, not the target itself.

Before acceptance, `SCHEMA-01D` must expand the allowed type graph into the exact
instance/projection graph, include external policy/trust/schema/build/method and
source-ledger nodes, validate every reference and perform a topological check.
Unknown edges, cycles, a non-decreasing predecessor, a dangling reference, or a
post-CAS proof reachable from its own head block the writer. A digest-only
summary with unchecked opaque references is insufficient.

## Schema-first receipts and work-package gates

`SCHEMA-01A` owns the immutable writer/reader registry and compatibility matrix;
`SCHEMA-01D` owns the closed production resource set and acyclic digest DAG. Each
emits exactly one `implementation_acceptance` for its exact work-package
subject, evidence/schema-set digest and assigned `repository_maintainer` issuer
whose roster includes `schema_compatibility`. Ticket-level design acceptance,
planning-governance schemas and Appendix G metadata cannot replace either.

Each first writer must consume the exact accepted receipt for its own contract
and dependency projections before it starts implementation, merges or closes.
The receipt binds contract IDs/versions, schema bytes, canonical projection/DAG,
field/nullability bounds, compatibility matrix identity, reviewer and evidence.
One `SCHEMA-01D` receipt may cover the declared closed set, but each writer must
verify that its exact contract is included; a count or generic schema label is
not coverage. Later schema/projection changes invalidate affected writer gates.

The explicit schema-first edges include `CUT-01A`, `DIST-01A`, `DIST-01B`,
`EVID-03A`, `NUM-01A`, `QUAL-01C`, `REL-01G`, `TEMP-01A` and `TRUST-01A` consuming
`SCHEMA-01D`; `TEMP-01A` also consumes `SCHEMA-01A`. `DIST-01B` additionally waits
for `QUAL-01C`. These are start/completion/merge gates, not advisory ordering.
The full occurrence-expectation contract remains independently authored under
`BASE-06D`; the schema inventory is not a second mutable release train.

`SCHEMA-01B` implements ordering/terminal-count migration, and `SCHEMA-01C`
qualifies historical migration/downgrade behavior after the registry/resource
gates. No S3 AST/compiler serialization may land before the relevant A/D receipts.

## Seed dispositions and verification

`SCHEMA-001` retains fresh-wheel, offline immutable-resource discovery and the
exact registered reader disposition; its absent-cell subprobe is unsupported
with `SCHEMA_COMPATIBILITY_CELL_ABSENT`, never best effort. `SCHEMA-002` retains
original source digest/transport ordinal and forbids invented causality,
authority or closure; attempted semantic promotion is refused with
`MIGRATION_INVENTED_SEMANTICS_REJECTED`. Both seeds remain assigned to
`V1-SCHEMA-01` for reviewed production-schema conversion. These are design
dispositions, not evidence that a new wheel or writer exists.

Read-only inspection used source reads of `schema/base.py`, `schema/stream.py`,
`schema/export.py`, `schema/validation.py`, `schema_resources/__init__.py`,
`scripts/schema_versions.py`, `scripts/check_schema_staging.py`,
`docs/schema_evolution.md`, ADR 0016 and the schema ticket/seed contracts.
The companion inventory is checked for exact 42-ID set equality, dependency
closure and acyclicity; such design validation is not runtime qualification.

S3 acceptance must run `make check schema-check` and the targeted raw-identity,
Pydantic/JSON-Schema parity, exact projection, immutable-snapshot, installed-wheel
offline discovery, missing-cell/minimum-reader, migration-loss/downgrade,
producer-epoch/order/terminal-count, digest-cycle and first-writer receipt tests.
Golden outputs need separate review; forged receipts, wrong competence, duplicate
contracts, altered schema bytes, cyclic historical references and future-proof
edges must fail. Candidate installed-wheel qualification subsequently binds the
exact staged bytes; a source-checkout pass is insufficient.

This draft closes only when its exact signed `development_design_acceptance`
records the qualified scope of the human review and remaining admissions. It
does not qualify a reader, implementation, mathematical method, release or
deployment, and it cannot cure the missing successor S1 acceptance.
