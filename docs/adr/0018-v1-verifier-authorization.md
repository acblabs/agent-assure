# ADR 0018: V1 verifier authority and complete authorization

- Identifier: `ADR-V1-AUTH`
- Ticket: `V1-BASE-03`
- Status: `proposed_for_development`
- Target: `stable-core/v1`; Sprint 2, governance release `1.0.0a2`
- Draft owner responsibility: `release_policy_owner`; human assignment pending
- Declared reviewer responsibility: `security_reviewer`; assignment pending
- Drafting basis: the user's instruction to implement the prerequisites and
  Sprint 2; this document does not assert a signed drafting receipt
- Author: LLM implementation agent; independent review: `NO_INDEPENDENT_REVIEW`
- Required completion receipt: `development_design_acceptance`, bound to this
  file's exact externally computed digest; receipt and signature pending
- Authority effect: none; no method, deployment, or release is approved here

The proposal derives from the private Revision 6.5 requirements, sections 3 and
13, and preserves accepted ADRs 0011–0014. The signed Sprint 1 successor,
current forecast, staffing/competence and exact scoped authorizations still gate
governed dispatch. A prepared design is not acceptance evidence. Sprint 2 leaves
the package at `0.7.0`, writer at `0.6.6`, historical schemas, existing CLI
commands, and runtime behavior unchanged.

## Existing contracts and authority separation

Extend `AssuranceEvidenceDescriptor` in `schema/mutation.py`, `EvidencePacket`
in `schema/packet.py`, policy contracts in `policies/`, and `GateDecision` /
`GateOutcome` and `gate_*` in `ci.py`. Publish future contracts only after
`ADR-V1-SCHEMA` and the matching first-writer schema/DAG receipt. Do not invent
`RunRecordV04` or treat the present evidence descriptor as an already-qualified
v1 authorization schema.

Keep conclusion (`supported`, `violated`, `inconclusive`, `not_evaluated`),
processing status, applicability/exposure, and authorization separate. Invalid
input does not demonstrate an obligation violation; a nonblocking legacy exit
does not establish v1 support. Existing `EvidenceState` and `GateOutcome`
enums keep their historical definitions. The four conclusion labels map to the
same-named existing `EvidenceState` members, while invalid processing maps to
non-verdict `error` with explicit invalid processing status and missing
prerequisites retain non-verdict `prerequisites_unmet`. The complete mapping is
in [ADR 0017](0017-v1-evidence-temporal-semantics.md). Existing `contradicted`
is not renamed to `violated`. Their adapter into new typed fields is explicit
and versioned; unsupported new dimensions cannot be silently squeezed into old
enum values. Preserve raw evidence when authorization is withheld.

## Verifier-owned manifest and policy

Load requirements, policy, acceptance oracles, trust, and admissions from a
separately pinned trusted ref or a supplied authenticated policy bundle. Candidate
or telemetry bytes may carry copies/digests for replay but cannot select, replace,
or weaken them. A protected filename or CODEOWNERS file without enforced review
and workflow permissions is insufficient. Never execute candidate-controlled
code with policy, deployment, signing, or publication credentials.

`required-claim-manifest/v1` is a closed, signed, canonically digested contract.
Release profiles reject an empty requirement set, unknown requirements,
duplicate requirement or claim identities, unresolved matches, and conflicting
evidence. A versioned combination rule is required for every allowed multi-input
match. Each row binds:

- `requirement_id`, `claim_id`, `source_obligation_id`, `evidence_mode_id`,
  `quantifier_id`, `consumer_id`, `combination_group_id`, `combination_rule_id`;
- exact contract, subject/candidate and baseline where relevant; scope selector
  and digest; minimum exposure; coverage and eligibility policies;
- required approval-use semantics, authority/admission, admitted method/version,
  qualification identity, and statistical policy/allocation where applicable.

Materiality, margins, and alpha come from preregistered verifier policy. Opaque
nonempty receipt strings are not resolved proof; resolve each required identity
and digest to an authenticated, correctly scoped object.

| Evidence mode | Quantifier and effect |
| --- | --- |
| `universal-per-run/v1` | Every eligible observed run in the exact scope must satisfy the obligation; one eligible violation defeats that requirement |
| `population-rate/v1` | Per-run outcomes feed the admitted reducer; individual substantive failures have no independent veto effect |
| `both-explicit-scopes/v1` | Authoring syntax only; compile before signing into separate universal and population rows with distinct claim identities and explicit scopes |

Overlapping universal/population scopes require
`universal-veto-dominates/v1`. Otherwise supply an independently verifiable
`scope-disjointness-proof/v1` binding both selectors/digests, basis, verifier, and
proof digest. Different digests alone do not establish disjointness. Unresolved
overlap yields `CLAIM_COMBINATION_AMBIGUOUS` before execution. Shared observations
can feed several registered consumers but do not become independent corroboration
or multiple votes. A rate-tolerant research population and zero-tolerance pilot
may coexist only with these explicit scopes and composition rules.

## Complete normal authorization predicate

For an exact deployment request, normal authorization is the conjunction:

```text
authenticated_current_verifier_policy_and_manifest
and exact_subject_contract_method_bindings
and existing_required_gates_satisfied_or_exactly_allowed
and every_required_v1_claim_qualified_supported_and_sufficiently_exposed
and every_required_launched_evidence_drain_complete
and no_blocking_input_integrity_or_execution_error
and no_applicable_admitted_typed_veto
and current_decision_context_for_the_requested_deployment
```

Qualification entails eligible observations, satisfied prerequisites, approved
exact/enclosed decision computation, stable admitted method, and verified
qualification identity. `accepted_for_development`, self-review, or
`NO_INDEPENDENT_REVIEW` cannot satisfy an independent-qualification requirement.
An allocation-feasibility claim cannot match observed consumption. Logical
vacuous support does not meet a positive exposure floor. Missing, unqualified,
unsupported, ineligible, or inconclusive required evidence withholds authority,
retains its raw state, and reports `REQUIRED_CLAIM_UNRESOLVED` or the more specific
typed cause.

Legacy exact waivers remain restricted to their existing eligible failures.
Default v1 required claims are non-waivable. A separate exceptional deployment
artifact can express a specifically governed exception; it cannot be labeled a
normal stable-core pass. No waiver changes an observation into support or creates
missing coverage/statistical prerequisites.

Favorable experimental evidence remains advisory and cannot fill a stable claim.
Deny-only effect requires an explicit verifier rule, validated scope, approved
validation mechanism, trusted authority signature, finite validity, and exact
validated-result digest. An unvalidated abstract counterexample is review
evidence rather than an automatic veto. Invalid optional input that the selected
profile requires must block processing; its producer cannot remove the failed
descriptor and continue. Unrelated optional analyses need not execute and cannot
silently change profile semantics. LLM judgments are permanently advisory under
ADR 0014, including when a human approves their presentation.

## Typed vetoes and applicability

`veto-record/v1` admits exactly `universal-obligation-violation/v1`,
`allocated-statistical-fail/v1`, and `admitted-deny-only/v1`. Each binds claim,
source obligation, scope, result/evidence digests, policy rule, issuer/admission,
unique decision path, and the exact manifest, policy, and packet. The verifier
derives applicability from a signed `scope-applicability-proof/v1` and these
bindings; a caller's `applicable=true` cannot make a veto apply.

Resolve exactly one signed and time-valid `veto-admission-receipt/v1` in a trusted
admission index. Recompute its domain-separated digest over kind, claim,
obligation, scope, evidence mode, rule, issuer, method/version, trust snapshot,
and validity. A deny-only admission additionally binds its approved validation
mechanism and validated result. Kind and evidence mode must agree: universal
violation uses universal mode; statistical FAIL uses population-rate mode;
deny-only uses its exact admitted profile.

Statistical vetoes bind family root, registration, endpoint, both positive
allocation weights u_j and w_k, effective alpha_FAIL, and authenticated allocation
and crossing receipts. Reject duplicate receipt keys; require family and effective
alphas strictly between zero and one and positive u_j,w_k no greater than one.
Resolve the allocation policy, enforce its directional endpoint-weight sums at
most one and exact registered w_k, then recompute
effective_alpha=alpha_family*u_j*w_k and match claim/scope authority. Missing or mismatched resolution yields
`STATISTICAL_VETO_ALLOCATION_INVALID`. A rate-only individual failure cannot
manufacture a universal veto. Universal-veto provenance explains the already
failed required claim; it is not a second vote. Integrity/execution errors remain
separate blockers and are never relabeled as substantive vetoes.

## Launched evidence cannot disappear at statistical stopping

The compiler derives a unique registry of consumer instances, each exactly bound
to `{consumer_id, requirement_id, claim_id, endpoint_id|null, obligation_id|null}`.
Duplicate projections or ambiguous ownership are invalid. The verifier derives
the full Cartesian matrix of already launched position/cluster identities and
compiler-required consumer instances. Each cell needs one terminal latest
source-bound `evidence-consumer-disposition/v1`; an admitted nonapplicability
proof is required to exclude a cell.

A signed `evidence-consumer-drain-completion/v1` binds that exact matrix,
uniqueness, source identities, terminal results, and all required proofs. A
statistical PASS at its stopped prefix is a component decision, not permission
to omit a later launched observation that violates a universal rule or integrity.
Pending, cancelled, missing, timed-out, duplicate, or invalid cells prevent
positive authorization with `LAUNCHED_EVIDENCE_DRAIN_PENDING` or an integrity
failure. A veto or integrity finding may stop deployment immediately, but the
final audit packet still drains. No intermediate signed artifact may say
`authorized=true` before drain completion.

## Claim-local capability preflight

`authorization-capability-preflight/v1` deterministically checks the authenticated
manifest, profile admissions, adapter capability, declared model-identity
requirements, and authenticated identity receipt before activation or provider
spend. Recompute policy-authority signatures, canonical digests, and the closed
compiler-owned claim classifications. Never trust caller-supplied tier labels,
release-bearing booleans, or requirement omissions.

Report each claim's mode, quantifier, scope, authority, identity tier,
release-bearing eligibility, expected effect, and blocking cause, plus whole
manifest reachability. An absent claim family is `not_required`. Preflight always
has `alpha_spent=false` and `draw_launched=false`; potential
`activation_eligible` and `draw_launch_eligible_after_activation` describe future
transitions, not executed ones. Runtime authorization rechecks all bindings.

Tier-3 hosted identity can leave qualified deterministic temporal claims eligible
while making required stable B1/D1 claims advisory and the whole manifest
unreachable. Wrapper signing, canaries, fingerprints, or a stationarity assertion
cannot promote that identity. Remedies for
`PROVIDER_IDENTITY_NOT_RELEASE_BEARING` are an admitted immutable local subject,
an actually admitted provider-attested immutable serving identity, or a
prospectively explicit advisory objective. Advisory acknowledgement never spends
authorization alpha or silently weakens a signed manifest.

## Runtime signatures and public distribution provenance

`signature-envelope/v1` is the stable runtime profile: DSSE v1 over
artifact-specific RFC 8785 payload bytes, with a closed payload type and domain
separator and Ed25519 authority from a verifier-owned offline trust snapshot.
HMAC is reference/test-only across principals; successful HMAC validation cannot
establish external authority. Signature verification authenticates exact signed
bytes under policy, not their correctness, coverage, independence, or sufficiency.

The signed claim/envelope binds algorithm/profile, payload type/digest, key ID,
signature, signer/issuer, role/scope, tenant, candidate/subject,
environment/replay domain, sequence or nonce where applicable, trusted decision
time, and trust-snapshot digest. The snapshot binds public key, permitted
roles/scopes/tenants, validity, and revocation effective time. Evaluate key scope,
validity, and revocation at the policy-defined trusted decision time and any
additionally required authenticated event time. Signature bytes alone do not
establish when signing occurred; absent required time or unresolved revocation
fails closed. Separate observation, approval, candidate,
qualification, pilot, channel, aggregate-approval, and release-head domains.
No signed payload includes its signature; canonical projections and the acyclic
digest graph are frozen by `ADR-V1-SCHEMA`. No key discovery from telemetry URLs,
unregistered algorithm fallback, or cryptographic-profile substitution is allowed.

`sigstore-release/v1` is separate public-distribution provenance: keyless
cosign/Sigstore bundle, exact artifact SHA-256, pinned issuer/workflow/ref/SHA
policy, inclusion evidence, and offline-verifiable roots/snapshot. It does not
authenticate runtime observations or human approvals. Algorithm changes need a
new profile and migration/compatibility decision. The S1 planning OpenSSH SSHSIG
profile remains historical planning governance and cannot substitute for either
runtime DSSE or public distribution provenance.

## CLI, artifact, and deployment contract

| Surface | Authority |
| --- | --- |
| `agent-assure ci gate --release-profile` | Existing 1.x evidence/efficacy gate; preserves its legacy envelope and exits; cannot emit deployment authorization |
| `agent-assure authorize preflight` | Non-authorizing reachability projection; no draw, index, or alpha allocation |
| `agent-assure authorize` | Sole v1 command permitted to emit current signed `authorized=true` |
| `agent-assure authorize explain` | Deterministic rendering of an existing decision; no fresh authority |
| `agent-assure release ...` | Existing release replay and pilot-evidence finalization |
| `agent-assure test activate` | Statistical family/index CAS after a valid preview; no deployment authority |

The future `authorize` exit mapping is 0 for a valid current positive artifact;
1 for valid nonauthorization (including stale context, unresolved evidence,
resource limits, or an unadmitted requested profile); 2 for malformed input,
invalid manifest, or integrity failure without an eligible artifact; 4 for bounded
internal failure without an eligible artifact. No other exit authorizes. Preserve
the existing command-specific mappings; do not globally reinterpret legacy exits.
Older clients without `authorize` cannot authorize v1, and authorization-bearing
artifacts cannot be downgraded to a reader unable to preserve their meaning.

The input set is evidence packet, trusted required-claim manifest and policy,
current deployment context, profile admissions, and explicit output destination.
The authorization artifact binds candidate-manifest, policy, requirements,
packet, profile-admission and current-context digests; verifier/freshness;
deterministic evidence match for every requirement; conclusion/status,
applicability/exposure, qualification, typed reasons and unresolved explanations;
and the final Boolean. Sign finalized bytes. Reuse rooted, lock-coordinated,
no-clobber publication: identical existing bytes are idempotent; different bytes
at the destination fail. A process exit is never a substitute for the artifact.

Trusted CI recomputes the decision. The deployment consumer independently checks
exact candidate, current context/policy, signatures, reader disposition, and the
committed assurance head via the authenticated registry and read-back protocol in
`ADR-V1-RELEASE-REGISTRY`. Package availability, a GitHub release, and legacy gate
success do not establish deployment authority. Missing/crashed/timed-out/stale
verification, unsupported schemas, an absent committed head, or
`explanation_complete=false` cannot authorize.

Preflight, decision, and explanation share a canonical claim matrix: mode,
quantifier, scope, overlap/composition, identity/reachability, endpoint-local and
registration state/prefix, launched-drain status/missing keys, and exact blocking
claim/observation. Explain when a population endpoint passed but an overlapping
universal claim vetoed. Explanations are deterministic bounded inclusion-minimal
missing/conflicting-fact sets; exhaustion marks them incomplete, not authoritative
LLM prose.

`test activate` and all internal/API aliases require signed, unexpired
`activation-preview/v1` bound to exact family head, prospective index,
registration/design, qualification envelope, and acknowledgement. No force flag,
environment/configuration, alias, or direct-function bypass exists. Invalid,
expired, replayed, wrong-subject or wrong-head previews leave index/head/alpha
unchanged. Activation remains separate from deployment authorization.

## Governed last-known-good rollback

The sole outage exception is `exceptional-deployment-authorization/v1`, subtype
`last-known-good-rollback/v1`; it never sets normal `authorized=true`. Pre-issue
under normal registry availability following a successful ordinary release.
Bind explicit capsule/version, source/target candidates, prior normal and
statistical decisions, registration projection and alpha allocation, last verified
head/time and registry descriptor, deployment scope, admitted outage predicate,
issue/expiry/maximum age, nonce/store descriptor, monitoring/stop and reconciliation
policy/deadline. Require distinct assigned release-policy and independent-security
signatures. Supersession revokes older unused capsules.

Provision one ISSUED nonce outside the registry failure domain. The sole
authorizer recomputes every comparison and atomically commits ISSUED->CONSUMED
with the exact rollback command against the expected store version before any
action is emitted/enqueued. One request wins. Replays/concurrent losers return
the already committed command/receipt as a nonauthorizing replay, never a second
authorization. Unavailable store, unknown winner after conflict, invalid capsule,
wrong subject/scope, expiry, or false outage predicate fails closed. Consumption
never resets. Permit rollback only: no forward deployment, continued rollout,
new PASS, evidence substitution, or ref rewind. Recovery creates a forward head
and authenticated reconciliation. S2 freezes this contract without implementing
or admitting a rollback controller.

## Seed dispositions and stage-specific acceptance

| Semantic seed | Required interpretation | Production-fixture owner |
| --- | --- | --- |
| `AUTH-003` | Supported required evidence is missing: no authorization despite all unrelated predicates passing | `V1-AUTH-01`, integration in `V1-AUTH-02/03` |
| `TEMP-006` | Open approval history leaves the default consumption claim inconclusive and nonauthorizing | `V1-EVID-02`, monitor in `V1-TEMP-02` |
| `TRUST-001` | Signature verification preserves self-report origin and cannot establish independent approval | `V1-TRUST-01/02` |
| `STAT-010` | Moments-only restart cannot support historical crossing/exclusion; invalid replay state | `V1-STAT-01` |
| `IO-001` | Missing declared chunk invalidates evidence; no partial packet may authorize | `V1-IO-01/02` |

S2 completes with scoped exact-digest design acceptance, reviewed seed meanings,
cross-ADR agreement, exact allowed files and bounded work, and declared remaining
admissions. It does not require unbuilt production tests or imply release
qualification. Implementation tickets must introduce strict schemas first and
test the complete vertical slice early: preflight/decision/explain, packet/head
binding, every predicate omitted independently, empty/duplicate manifest,
overlap ambiguity, forged/unallocated/duplicate veto, pending drain,
missing-consumption/closure, tamper, no-clobber, legacy nonauthority,
unsupported-reader and exact-subject mismatch. Add offline trust expiry,
revocation/domain-replay, hostile policy replacement, and rollback CAS races.

Independent qualification must bind a frozen adversarial corpus, bounded
semantic-oracle domain, exact candidate, source/observer contracts, trusted
policy/oracles, cryptographic profiles, resource envelope, commands and outputs,
and declared independence. A green unit test or a signature cannot substitute
for this evidence. No qualified receipt, admitted method, hosted-CI result, or
human signature is claimed by this draft.

Alternatives rejected: candidate-owned policy; legacy exits as deployment
authority; a favorable statistical component bypassing other required consumers;
Boolean vetoes; signing as evidence-origin promotion; LLM verdicts; ambiguous
scope composition; and mutable or self-referential release-head proofs.
