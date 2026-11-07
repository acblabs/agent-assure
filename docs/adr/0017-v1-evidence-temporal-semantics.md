# ADR 0017: V1 evidence, temporal semantics, and approval allocation

- Identifier: `ADR-V1-EVIDENCE`
- Ticket: `V1-BASE-02`
- Status: `proposed_for_development`
- Target: `stable-core/v1`; Sprint 2, governance release `1.0.0a2`
- Draft owner responsibility: `assurance_lead`; human assignment pending
- Declared reviewer responsibility: `telemetry_security_reviewer`; assignment pending
- Drafting basis: the user's instruction to implement the prerequisites and
  Sprint 2; this document does not assert a signed drafting receipt
- Author: LLM implementation agent; independent review: `NO_INDEPENDENT_REVIEW`
- Required completion receipt: `development_design_acceptance`, bound to this
  file's exact externally computed digest; receipt and signature pending
- Authority effect: none; no source, method, profile, or release is admitted here

This is a concrete development proposal. The signed Sprint 1 successor closure,
current forecast, approved file scopes, staffing/competence records, and scoped
acceptance remain prerequisites to dispatch under the governed train. Preparing
this reviewable draft does not establish those facts or change existing package
behavior. The private Revision 6.5 specification, sections 1.3, 4, and 6, supplies
the requirements; accepted ADRs 0011–0014 continue to control claim boundaries.

## Existing contracts and migration boundary

Reuse `AgentRunRecord` and `StructuredFieldOrigin` in `schema/run.py`,
`FrameworkObservation` in `adapters/base.py`, `StreamSequenceContract`,
`StreamEventRecord`, and `StreamRunRecord` in `schema/stream.py`, and
`AssuranceEvidenceDescriptor` in `schema/mutation.py`. Keep the current writer
`0.6.6` and released schema snapshots unchanged in Sprint 2. `ADR-V1-SCHEMA`
defines the later production writer and compatibility receipt.

Execution outcome, logical evidence conclusion, applicability/exposure, and
authorization are distinct dimensions. A completed analysis can be inconclusive;
an invalid input is not proof of a process violation. The future semantic
vocabulary is `supported`, `violated`, `inconclusive`, `not_evaluated`.
`invalid` classifies processing/integrity rather than becoming a fifth logical
conclusion. The four semantic conclusion strings already exist in
`EvidenceState`; preserve their spelling and historical meaning:

| V1 condition | Existing descriptor state and restriction |
| --- | --- |
| Supported / violated / inconclusive / not evaluated after valid processing | `supported` / `violated` / `inconclusive` / `not_evaluated`, respectively; retain separate qualification, execution, and exposure fields |
| Malformed, inconsistent, or untrusted input | `error`, `verdict_bearing=false`; explicit processing status `invalid`, not a fabricated violation |
| Unmet eligibility, authority, or other prerequisite | `prerequisites_unmet`, `verdict_bearing=false`; no supported/violated conclusion may bypass that prerequisite |

Existing `contradicted`, `out_of_scope`, `expired`, `invalidated`, `waived`, and
other legacy states keep their contract-specific meanings; they are not aliases
for the four conclusions. CI `GateOutcome` values also remain unchanged. The
new schema adapter must carry the independent dimensions without reinterpreting
a legacy `pass` as v1 support. The current stochastic/human-reviewed descriptor
sufficiency restriction still applies until its typed supporting artifacts are
implemented and accepted. Until the relevant new schema/adapter receipt exists,
new v1 wire serialization is unsupported, never a lossy legacy projection.

`V1-TEMP-02` replaces the current approval-order authority in
`live/trajectory.py` for v1 consumers. Preserve archival rendering while routing
v1 decisions through one monitor. `human_review_performed=true` alone supplies
neither action correlation nor order; synthesized legacy paths remain advisory.

## Observations, origin, and eligibility

Preserve source origin as immutable history. A verified signature on
`model_self_report` leaves that origin unchanged; there is no
`resulting_origin_class` or policy-created `independent_observer` origin.
Persist separate facts for source declaration, observation mechanism, verified
signature and byte scope, authority, candidate-relative independence, and
predicate-specific eligibility. The latter three are verifier conclusions bound
to policy, source contract, trust snapshot, scope, and supporting records.
Producer booleans such as `authenticated=true` and a service name are not proof.

Initially the closed claim-scope registry covers observed approval, observed
execution, action identity/version, order, coverage, and declared terminal
state. Approval authority does not automatically confer execution-observer
authority. Bind tenant/run, source/epoch, allowed purpose, key validity and
revocation, and replay domain. Offline verification uses a supplied trusted
snapshot; untrusted URLs never discover verification keys.

Privacy filtering precedes persistent identity and hashing. Preserve a material
event whose value was removed and mark the affected predicate unavailable.
Hashing predictable sensitive values is not anonymization; use contract-approved
opaque identities or commitments where required.

## Coverage, closure, causality, and admissible histories

Maintain independent fields for lifecycle (`open`, `normal_terminal`, `aborted`,
`unknown`), per-channel observation coverage, qualified closure, and proven
happens-before. Normal termination can coexist with lost telemetry; an aborted
run can be fully observed. EOF, a terminal model answer, and maximum observed
timestamp establish none of these coverage guarantees.

A coverage contract names the complete expected producer set, or a trusted
discovery-and-closure procedure, plus channels/event classes, epochs, sequence
semantics, loss/sampling rules, and predicate scope. Unknown producer completeness
prevents a global absence claim. A watermark binds producer/epoch/channel/class,
qualified sequence or event-time basis, boundary convention, known gaps,
provenance, and the authoritative exclusion of earlier events. An epoch restart
starts a new coverage domain. Later heartbeats cannot erase known loss.

The stable closure profile is `producer-terminal-count/v1`. An authenticated
terminal marker binds the epoch and channel, first index, final exclusive index,
expected count, and ordered-identity digest. Closure requires a qualified local
sequence, exactly one accepted record at every index in that half-open range,
matching count and digest, and no remaining gap. Early arrival of the marker is
pending closure. This proves neither omitted-producer discovery nor cross-source
order.

For validated observations O, let A(O) contain all executions consistent with
eligible facts, qualified source/coverage contracts, time uncertainty, and order.
Contradictory facts produce invalid evidence; never quantify vacuously over an
empty A(O). For a contract phi:

| Evidence conclusion | Semantic condition and method boundary |
| --- | --- |
| `supported` | A(O) is nonempty and every H in A(O) satisfies phi |
| `violated` | A(O) is nonempty and every H in A(O) violates phi |
| `inconclusive` | Proven mixed semantics has both satisfying and violating histories; a bounded method that cannot establish either one-sided conclusion also returns this nonauthorizing state, with method completeness explicitly incomplete |

Distinguish proven mixed semantics from incomplete method reasoning in the last
row. A complete finite trace varies only in admissible linearizations; a complete
prefix varies in suffixes; missing history additionally permits insertion of
earlier/intermediate events. A cut is downward closed under proven causality and
complete for the predicate's required channels through its boundary. Buffer or
spill later observations without claiming they belong to the cut.

An eligible monotone forbidden-action witness may settle a violation before
unrelated channels close. By contrast, absence of a qualifying approval requires
closure of the relevant history or another witness ruling it out in every
completion. Late events behind an accepted watermark, conflicting duplicates,
or causal cycles invalidate affected decisions and require recomputation. Keep
old artifacts immutable and attach new invalidation context externally.

Only qualified global/local sequencing, workflow transitions, communication, or
lifecycle facts establish edges. Canonical storage sorting and uncertain wall
clocks do not create causality. Deduplicate stable source identity inside
run/producer/epoch, never content: exact redelivery is idempotent; conflicting
content at the same identity is invalid. Legitimate repeated equal actions stay
distinct. Missing identity requires an explicit, limited batch-position contract.

## Typed temporal language and action binding

The stable authoring surface is the typed macros `strict_prior`, `fresh_prior`,
`absence`, `response`, `within`, and explicitly scoped `eventually`. Compile
source to validated AST, canonical monitor IR, and deterministic executable
monitor; bind all source/AST/IR/macro/compiler and observation-policy digests.
Unknown operators/predicates fail validation; no Python evaluation or LLM
translation may supply semantics.

The internal IR also has Boolean connectives, implication, strong/weak next,
eventually, always, strong/weak until. Raw next/until and arbitrary compositions
require a declared and established complete total order. Every contract records
required and supported order models. Partial-order evidence invokes only its
admitted reachability/closure/matching/interval macro evaluator; otherwise emit
`TEMPORAL_ORDER_MODEL_UNSUPPORTED`, never a favorable selected linearization.

On a nonempty word evaluate at position zero. Strong next is false at the last
position; weak next is true there. Strong until requires its right-hand witness
and its left operand at every preceding position; weak until adds the case where
the left operand holds throughout. The versioned empty-word convention is:
atom=false, Boolean constants unchanged, Boolean connectives recursive,
X=false, Xw=true, F=false, G=true, U=false, W=true. An empty artifact needs trusted
closure and applicability before it can represent an eligible empty execution.

`response(A,B)` permits B at A's abstract position; `strict_prior(A,B)` does not.
`first_precedence(A,B) = not B W A` remains internal/legacy and does not authorize
an action. Correlate approvals using action ID, approved action-version/content
digest, candidate/run/tenant scope, eligible authority, use policy, and validity.
Action ID alone or model-written approval prose is insufficient. Each execution
attempt, including a retry, consumes one approval by default. Reuse requires an
explicit versioned capacity/scope contract.

| `approval_use_semantics` | Claim and accepted evidence |
| --- | --- |
| `observed_consumption` | Default: validate eligible execution/attempt events and their `consumed_approval_id`; never swap in a favorable unused grant |
| `declared_allocator` | Replay an exact policy/version over complete eligible inputs; runtime-use claims additionally bind actual consumption to that allocator execution |
| `allocation_feasibility` | Opt-in: prove an assignment exists; this does not establish actual consumption |

Unknown consumption IDs prevent support. A reference to a missing approval is
conclusive failure only with relevant approval-history closure or another
conclusive contradiction. Double consumption, wrong action/version, and definite
expiry/order violations can be conclusive when their relevant facts are eligible.
A universal conjunction with a definite violation is violated even if other
obligations remain unresolved; retain those obligations in the report.

For simple qualified validity intervals both endpoints are inclusive unless a
new contract versions that convention; issue must strictly precede execution.
Revocation is separate and needs explicit effective-order/time semantics.
For qualified time enclosures A=[a_lo,a_hi], B=[b_lo,b_hi], elapsed time belongs
to [b_lo-a_hi,b_hi-a_lo], intersected with independent causal constraints. Support
requires the entire witness interval inside the allowed closed interval.
Straddling is inconclusive. An unwitnessed response becomes late only after its
entire possible on-time region closes. Aborted runs are included unless an
explicit contract excludes them with exposure and exclusion basis reported.

For `declared_allocator`, this development proposal selects
`earliest_expiry_first/v1` only in its restricted unit-capacity, interchangeable same-action/version/scope,
qualified-total-order, contiguous-interval domain. Choose earliest expiry among
available unused grants; ties use issue order then canonical approval identity;
unbounded expiry sorts last. The exchange argument replaces a chosen later
expiry with the available earlier expiry: any later execution covered by the
earlier grant remains coverable by the later one. Added capability constraints
or capacities invalidate that argument and require another method identity.

Mandatory discriminator: grants a1:[0,100], a2:[1,5] issued at 0 and 1 and
executions at 2 and 50 admit assignment a2,a1. Recorded use a1,a2 violates actual
consumption; absent consumption stays inconclusive even though feasibility holds.

## Partial-order allocation theorem and method completeness

For unit-capacity `allocation_feasibility`, let P(G) mean that bipartite graph G
has a matching saturating every action vertex. Before applying
`edge-monotone-box/v1`, prove a nonempty completion domain, fixed canonical
approval/action sets, and E_must subset E(H) subset E_may for every admissible H.
Here subset permits equality. A cyclic/contradictory domain is invalid; unproved
guards yield nonauthorizing method-incomplete evidence.

Evaluate in this order:

1. If P(G_must), support with its canonical saturating matching. Adding edges
   preserves that same matching in every admissible graph. Realizability of the
   all-must graph is unnecessary.
2. Otherwise, if not P(G_may), violate with its canonical Hall-deficiency
   certificate. Removing edges cannot repair Hall deficiency. Realizability of
   the all-may graph is unnecessary.
3. Otherwise report inconclusive. Mark `mixed_exact` only after validating one
   passing and one failing admissible completion. If either class lacks a
   witness, set `method_completeness=incomplete` with
   `PARTIAL_MATCHING_DOMAIN_UNSUPPORTED`. The union of all possible edges need
   not itself be a possible history.

The quantification is “for every admissible history there exists an assignment,”
not one favorable history/assignment. These rules neither evaluate actual
consumption nor authorize replacing a frozen allocator.

For `strict-precedence-only/v1`, the domain must be exactly all linear extensions
of one accepted DAG O. Vertex membership, capacity, validity, identity, scope,
and authority are fixed. A verifier-derived complete pair universe C records
every fixed-non-order-compatible pair; every omitted pair must be proved
fixed-ineligible. Eligibility of (a,x) in C then means precisely a before x.
Thus E_must contains pairs entailed a<x, and E_may contains pairs not entailed
x<a. A hidden completion filter or unknown pair invalidates this recognizer.

Let U=E_may minus E_must. The may extremum exists exactly when O augmented with
all a->x for U is acyclic. The must extremum exists exactly when O augmented
with all x->a for U is acyclic. Necessity follows because a realizing total order
contains every added relation; sufficiency follows from a topological order of
the augmented DAG and the fixed-predicate assumptions. This equivalence is not
extended to correlated time, authority, capacity, or variable vertex existence.

## Deterministic certificates and bytes

`approval-allocation-proof-bundle/v1` freezes one certificate convention. Future
production schemas are closed objects and exclude reference-only
`completion_oracle_conclusion`. Identities are `source-event-identity/v1` objects
with exactly `identity_contract_id`, `run_id`, `producer_id`, `producer_epoch`,
and `event_id`; the discriminator is constant and the other values are nonempty
strings of at most 512 characters copied exactly from accepted records. Do not
concatenate delimiters, normalize Unicode, or case fold.

A vertex key is `[vertex_kind, canonical_event_identity]`, where kind is exactly
`action` or `approval`. Compare unsigned UTF-8 bytes of its RFC 8785 encoding.
All ready `action` keys precede ready `approval` keys; raw identifier ordering is
equivalent only within the same kind. Duplicate key bytes are invalid.

- `lexicographic-kahn/v1` repeatedly selects the minimum ready vertex key.
- `ordered-dfs-cycle/v1` orders start vertices and adjacency by that comparator,
  selects the first gray-edge stack suffix closed by the gray target, and rotates
  the directed closed cycle to its least key rotation. When both augmented DAGs
  fail, emit the must cycle before the may cycle.
- Canonical maximum matching maximizes cardinality, then minimizes the
  action-indexed approval vector lexicographically, with UNMATCHED after all
  approvals. Residual-feasibility checks realize that canonicalization in
  bounded polynomial work.
- For deficiency, orient unmatched edges action-to-approval and matched edges
  approval-to-action; reach from all unmatched actions. Emit sorted reachable
  actions S, their exact sorted neighbors N(S), and positive |S|-|N(S)|.

Vertex arrays use vertex-byte order; edge/pair rows contain
`[approval_vertex_key, action_vertex_key]` and sort by action key then approval
key. Define D(domain,p)=`sha256:` plus lowercase SHA-256 of ASCII(domain), NUL,
and UTF8(RFC8785(p)). Freeze these projections:

| Artifact/domain suffix after `agent-assure:` | Exact projection fields |
| --- | --- |
| `complete-pair-universe/v1` | `contract_id`, `approval_use_semantics`, `edge_uncertainty_contract_id`, `vertex_identity_contract_id`, `approval_vertex_keys`, `action_vertex_keys`, `fixed_non_order_eligible_pairs`, `omitted_pairs_semantics`, `fixed_pair_universe_complete` |
| `matching-graph/v1` | `contract_id`, `graph_role`, `accepted_facts_digest`, `fixed_pair_universe_digest`, `approval_vertex_keys`, `action_vertex_keys`, `edges` |
| `matching-history-witness/v1` | `contract_id`, `completion_domain_id`, `accepted_facts_digest`, `fixed_pair_universe_digest`, `ordered_vertex_keys` |
| `matching-witness-candidate-set/v1` | `contract_id`, `completion_domain_id`, `accepted_facts_digest`, `fixed_pair_universe_digest`, `candidates` |

The pair universe fixes `approval_use_semantics=allocation_feasibility`,
`omitted_pairs_semantics=fixed_ineligible`, and
`fixed_pair_universe_complete=true`. Graph role is `must` or `may`. The history
projection's discriminator is `matching-history-projection/v1`; each history
contains every vertex exactly once. Missing eligibility proofs, duplicates,
unknown vertices, noncanonical derived bytes, or digest mismatch make the
recognizer unavailable, never a reduced may graph.

Middle-case bundles bind the canonical must deficiency, may saturating matching,
unresolved edges, and per-class witnesses or extremal impossibility cycles.
Use the canonical Kahn order of each realizable extremum for its class. Only an
unrealizable class uses the authenticated candidate-set fallback. Each candidate
has exactly `witness_class`, `history_projection`, `history_digest`; validate
admissibility and recompute pass/fail. Sort unique rows by ASCII class then
unsigned (raw 32-byte history digest, history bytes); choose the minimum such
tuple independently per required fallback class and bind the candidate-set
digest. No valid fallback in a required class leaves the method incomplete.

The bundle binds method/domain/order/certificate algorithm identities, accepted
facts, canonical vertices, pair universe and both graph digests, classification
basis, and certificates. Hash all bundle fields except `proof_bundle_digest`
and detachable signature under `agent-assure:approval-allocation-proof-bundle/v1`.
Sign finalized bytes under the separate approved signature profile. This creates
no digest self-reference and permits no alternate matching/cycle/witness choice
under the same identity. The ASCII-only tiny reference identity specialization
is not the production source identity contract.

Classification requires at most two matching problems; ordered certificate
construction has separately bounded polynomial cost. Only augmented-DAG
acyclicity is linear after reachability and U construction. Independent tiny
oracles enumerate linear extensions and assignments within an explicitly frozen
domain; no all-posets or production-scale exhaustive claim follows.

## Inconclusive-obligation product contract

Freeze `inconclusive-obligation-rate/v1` at the grain of one deduplicated
applicable required-obligation evaluation attempted under an exact candidate,
required-claim manifest, and scope. Its numerator counts those evaluations
ending inconclusive after valid processing. Its denominator includes every
applicable attempt, including timeout, insufficient evidence, invalid,
not-evaluated, unsupported, or policy-excluded outcomes unless independently
proved not applicable. Report those outcome categories separately; they cannot
disappear from the exposure ledger to improve the rate. Invalid processing never
becomes an inconclusive numerator entry merely to normalize presentation.

The ledger freezes obligation/attempt identity, retry deduplication, applicability
proof, outcome, censoring, candidate/manifest/scope, adapter, model-identity tier,
partner/context, coverage source, predicate, and missing-fact reason. Exact
transport redelivery and duplicate submission of the same logical invocation do
not create extra exposure. A new execution attempt after a failed invocation has
its own preregistered attempt identity and cannot replace that failure; retain
both attempted evaluations. Append-only status progression may complete a
pending attempt, but a terminal outcome is immutable, with corrections recorded
as invalidation rather than favorable overwrite. Report unresolved censored
attempts and their times. Bind the ledger digest, metric-definition digest, and change-control
digest. Changed definition, threshold, denominator, scope, or segmentation needs
a new version and prospective evidence; do not relabel earlier observations.

The following is a concrete proposed development choice, not a roadmap-supplied
number, empirical result, confidence statement, or accepted product threshold:

```json
{
  "decision_item_id": "PRODUCT-INCONCLUSIVE-01",
  "contract_id": "inconclusive-obligation-rate/v1",
  "status": "proposed_for_development",
  "minimum_applicable_obligation_attempts": 30,
  "maximum_inconclusive_rate": {"numerator": 1, "denominator": 10},
  "threshold_comparison": "less_than_or_equal",
  "policy_owner_acceptance": "pending",
  "authorization_effect": "none"
}
```

The exact count floor applies to the bound decision scope, with the declared
segments reported separately; a future policy may impose stricter segment
floors prospectively. The product/release-policy owner must accept the exact
scope, floor, ceiling, and ledger rules before an eligible threshold observation
window opens. Until then no threshold evaluation may report acceptance or satisfy
pilot/GA readiness. Thirty attempts and a 10% ceiling provide a concrete review
proposal only; statistical precision or suitability requires separately justified
design. The metric does not replace correctness, privacy, power, exposure,
integration-failure, or independent-review gates.

## Seed dispositions, acceptance, and remaining qualification

| Semantic seed | Design disposition | Downstream production-fixture owner |
| --- | --- | --- |
| `AUTH-003` | Missing required support never authorizes, even with valid bindings and no other error | `V1-AUTH-01` |
| `TEMP-006` | Referenced approval may still exist in unclosed history: inconclusive, not an absence violation | `V1-EVID-02`, with monitor coverage in `V1-TEMP-02` |
| `TRUST-001` | Signed self-report stays self-report and cannot establish independent approval | `V1-TRUST-01`, eligibility follow-through in `V1-TRUST-02` |
| `STAT-010` | Moments alone cannot reconstruct historical exclusion/crossing; invalid replay state | `V1-STAT-01` |
| `IO-001` | Missing manifest chunk is invalid input, not a smaller complete trace | `V1-IO-01` |

These dispositions review seed meanings; they are not production-schema
fixtures or completed qualification. `V1-EVID-03` owns the independent oracle;
`V1-TEMP-01/02` own compilation/monitor conversion; `V1-SCHEMA-01` owns the strict
writer and proof projections. Freeze `MATCH-009` byte vectors and mixed-kind
ready-set, shuffled-input, incomparable-extremum, and fallback cases. Tests must
show both decisive one-sided rules when their corresponding extremum is
unrealizable and distinguish mixed-exact from incomplete middle cases.

Stage completion requires exact-digest design review, cross-ADR consistency,
all required seed dispositions, explicit assignments/scopes/work ceilings, and
recorded unresolved admissions. No future implementation test is a prerequisite
to this drafting receipt. Later implementation must test complete/partial
coverage, epoch gaps and late invalidation, empty/terminal semantics,
consumption-vs-feasibility counterexamples, timing straddles, canonical proofs,
privacy, resource exhaustion, and archival compatibility. Qualification adds
independent oracle review, approved source contracts, measured budgets, and
candidate-bound independent admission. None has been performed by this draft.

Alternatives rejected: timestamp sorting as causality; treating EOF as closure;
signature-based origin promotion; feasibility substituted for consumption;
requiring extremal realizability for decisive monotone certificates; favorable
linearization selection; and denominator changes chosen after seeing outcomes.
