# Schema Reference

Current development writer schema version: `0.6.6`.
Current development writer schema snapshot: `schemas/v0.6.6/`.
Latest published release schema snapshot: `schemas/v0.6.5/`.

The `0.6.6` writer is an untagged development surface, not a published
release. The `schemas/v0.6.5/` snapshot remains immutable.

Persisted artifacts include `schema_version` and `artifact_kind`. Current
models emit `schema_version: 0.6.6` and continue to accept legacy
`schema_version: 0.2.0`, `schema_version: 0.3.1`, `schema_version: 0.4.3`,
`schema_version: 0.5.0`, `schema_version: 0.6.0`,
`schema_version: 0.6.1`, `schema_version: 0.6.2`,
`schema_version: 0.6.3`, `schema_version: 0.6.4`, and
`schema_version: 0.6.5` artifacts where their
compatibility contracts permit those labels. Historical artifacts validate
against their frozen schema snapshots. The v0.6.0, v0.6.1, v0.6.2, v0.6.3,
v0.6.4, and v0.6.5 snapshots remain immutable; current v0.6 relational checks
continue to apply after validated legacy projection, including each
evidence-carrying root's
self-digest. The v0.6.6 schemas are current development writer contracts: every
root and nested persisted model pins
`schema_version` to that model's emitted default. Thus nested current mutation
operators, expected-detection contracts, and results use `0.6.6`, while the
independently versioned usage models continue to emit `0.4.3`. Compatibility
projection of a frozen artifact does not widen the current wire schema.
Importable models and their direct `model_json_schema()` output retain declared
legacy read compatibility; checked-in schemas and current artifact validation
use the separately pinned writer-schema projection.

Since v0.6.1 the run-set evidence-link identifiers use the same exact ASCII
machine-identifier grammar in runtime and JSON Schema. This covers `EvidenceRef.ref_id`,
`EvidenceRef.source_id`, `EvidenceRef.claim_ids`, `EvidenceItem.ref_id`,
`EvidenceItem.source_id`, `ClaimRecord.claim_id`,
`ClaimEvidenceLink.claim_id`, `ClaimEvidenceLink.evidence_ref_id`,
`Expectation.required_evidence_refs`, and `Expectation.material_claim_ids`:
`[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}`. They are therefore nonempty, limited to
256 characters, and cannot carry whitespace, controls, format characters,
private-use characters, unassigned code points, or other Unicode text. These
producer constraints do not retroactively invalidate identifier strings
admitted by the immutable v0.6.0 schema.

A current `AgentRunRecord` also requires its evidence references, evidence
items, claims, and claim-evidence links to carry the current schema version. A
current `CompiledSuite` likewise requires current resolved expectations. These
targeted coherence checks match the v0.6.6 writer schemas without applying
parent-version equality to independently versioned components such as usage
records. Matching legacy parent/member projections remain supported through
their frozen schemas.

A current `EvidencePacket` likewise requires each nested persisted artifact
covered by its writer schema to use the packet schema version, while nested
`UsageSummary` and `UsageSummaryDelta` retain their independently emitted
version. The same exact relationship is enforced for coherent v0.6.1 and
v0.6.2 packet projection. Packet persistence validates the post-redaction
payload against the root-version-selected current writer or legacy frozen
schema before writing bytes, so a current packet cannot embed a legacy
evaluation or comparison summary.

A current evidence packet also binds exactly one `evaluation-summary` digest.
It binds exactly one `comparison-summary` digest when, and only when, a nested
comparison is present. Runtime model validation, packet construction, and CI
gating enforce this cardinality so a missing or duplicate digest cannot make the
packet ambiguous. Packet construction obtains the parsed summary, raw SHA-256,
and release-manifest path from one bounded file snapshot. Trusted packet gating
reopens that confined source file and requires both its exact raw digest and its
fully parsed model to match the packet; privacy redaction is not an integrity
comparison.

A current packet may bind an evidence graph by carrying both
`evidence_graph_digest`, the graph's semantic RFC 8785 digest, and exactly one
`assurance-evidence-graph` artifact digest, the raw SHA-256 of the transported
JSON file. When a release manifest is nested, it must contain the same exact
artifact digest. The two bindings are all-or-none, but graph binding remains
optional in the packet schema for compatible third-party producers. The graph
does not contain packet identity or packet-file digests, so this relationship
does not create a digest cycle. Current first-party packet and CI producers emit
the graph, privacy-filter its sources before projection, and verify the exact
file plus a fresh semantic reconstruction before publishing the packet.

A current packet may also carry one `evidence-sensitivity-report`. Its
counterfactual RunSet ID and digest must equal the packet evaluation's
authenticated subject; when comparison evidence is present, both report arm
identities must equal the comparison pair. The nested report and exactly one
raw `evidence-sensitivity-report` digest in both the packet and release manifest
are all-or-none. First-party graph projection preserves the report's typed
status and limitations without adding node or edge kinds.

A packet may additionally carry the repeated-study
`statistical-sufficiency-report` and
`stochastic-evidence-sensitivity-report` together. A verdict-bearing pair
requires the packet evaluation's RunSet ID and digest to equal the exact
counterfactual source dependency and requires both source RunSet
execution-configuration digests to equal their protocol-arm configurations. If
comparison evidence is present, both its baseline and candidate RunSet IDs and
digests must equal the exact source arms. The graph projection preserves the
same candidate RunSet/configuration binding.

Whenever either repeated-study field is present, packet artifact digests also
require exactly one `stochastic-baseline-source-runset` and one
`stochastic-counterfactual-source-runset` role; the pair is atomic. A release
manifest, when present, requires the same two roles and exact digests. The
RunSets remain separate files rather than nested statistical-report fields.
Verification parses both files, recomputes their canonical RunSet and
per-record digests into the two `source_runsets` dependency objects, requires
exact equality, reruns the canonical paired observation assembler, and requires
the entire ordered result to equal the persisted sufficiency observations.
Recommendation, outcome, disposition, cluster, endpoint, and source-record
semantics are therefore source-derived rather than merely membership-checked.
The nested reports without the confined release-manifest artifact root or an
explicit exact source-RunSet pair are insufficient for stochastic packet
verification and make the packet invalid.

At schema versions `0.6.0`, `0.6.1`, `0.6.2`, `0.6.3`, `0.6.4`,
`0.6.5`, and `0.6.6`,
`evaluation-report` requires
`runset_digest`: SHA-256 over the RFC 8785 canonical bytes of the version-aware
schema-validated, current `RunSet` model JSON projection. The projection
retains the accepted `schema_version` and materializes schema-permitted omitted
defaults before hashing; it is not a digest of raw input bytes. The report also
requires an explicit `waiver_dispositions` array. The latter records one
privacy-minimized matched, unmatched, or expired disposition per supplied
waiver without changing the gate rollup. Mutation execution checks the RunSet
binding for both source and candidate reports so equal `runset_id` labels
cannot make stale report content admissible. Campaign source, nested mutation
result, evidence subject, and source evaluator digests use this same
projection; transformed-result and candidate evaluator digests do likewise.

Since v0.6.3, the `evaluation-summary` writer admits an optional `runset_digest`
with the same canonical projection. The built-in evaluator always copies its
authenticated report digest into the summary, and a first-party packet graph
uses that value as its primary subject digest. A present summary digest must
match its enclosing evaluation report and the graph's primary subject; any
conflict with mutation or control-efficacy source digests fails closed. The
field is optional for current independent producers, while frozen summary
schemas through v0.6.2 omit it. Graph projection never infers the missing join
for those summaries.

The v0.6.4 `comparison-summary` writer similarly requires
`baseline_runset_digest` and `candidate_runset_digest`, each computed from the
same version-aware canonical RunSet projection. The import model keeps the pair
optional so validated frozen summaries through v0.6.3 can be projected without
inventing historical identities, but rejects a partial pair. First-party normal
and invalid-comparison writers always emit both digests. Sensitivity packet and
graph binding verifies them against the exact RunSets embedded in the detector
report before comparing the remaining canonical comparison semantics.
Comparison reports and evidence packets always require the comparison's
candidate RunSet ID to match the corresponding evaluation; when both sides
carry RunSet digests, those authenticated identities must also match. The same
rule is rechecked by CI so an unvalidated in-memory copy cannot bypass it. A
missing optional evaluation digest remains explicitly unbound rather than being
inferred from the comparison. Comparison JSON publication validates the
privacy-filtered report and summary against the active writer schemas before
creating either output file.

Current `agent-run-record` writers can attach one `structured_field_origins`
object covering recommendation, outcome, summary, tools, evidence references
and items, claims and links, policy results, and human-review flags. The origin
vocabulary is `fixture`, `instrumented_adapter`, `model_self_report`,
`runner_observed`, and `legacy_unspecified`. Current first-party runners always
emit the object. For compatible older artifacts, omission is projected as
`fixture` only when `execution_mode=fixture`; omission on a live record remains
`legacy_unspecified`.

Control eligibility is source-aware. Fixture and instrumented-adapter fields
can satisfy declared controls within their documented producer trust boundary;
model-self-reported and legacy-unspecified process fields cannot. Direct
OpenAI-compatible calls use a strict, decision-only response contract, so the
model cannot populate process fields. Runner-observed provenance is valid only
for the runner's excluded runtime-error record shape. Untrusted positive policy
results are ignored, while negative policy states, forbidden-tool reports, and
evidence contradictions remain verdict-bearing.

Every v0.6 live `agent-run-record` also requires
`cost_budget_committed_usd`, `generated_token_budget_committed`, and
`total_token_budget_committed`. These fields record conservative amounts
charged against local dispatch ceilings, including retained reservations for
network attempts whose billing or generation outcome is ambiguous; they are
distinct from provider-reported usage and estimated invoice cost.

Exported roots:

- `assurance-evidence-descriptor`
- `assurance-evidence-graph`
- `assurance-mutation-campaign`
- `assurance-mutation-catalog`
- `assurance-mutation-operator`
- `assurance-mutation-result`
- `agent-run-record`
- `process-equivalence-benchmark`
- `process-equivalence-reproduction-index`
- `real-model-study-manifest`
- `real-model-study-execution-review`
- `real-model-study-registration-review`
- `real-model-study-statistical-method-review`
- `real-model-study-report`
- `repeated-evidence-sensitivity-protocol`
- `compiled-suite`
- `comparison-report`
- `comparison-summary`
- `control-coverage-report`
- `control-efficacy-report`
- `external-pilot-evidence`
- `external-pilot-input-manifest`
- `external-pilot-independence-review`
- `evaluation-report`
- `evaluation-summary`
- `emergency-process-record`
- `environment-info`
- `evidence-packet`
- `evidence-sensitivity-protocol`
- `evidence-sensitivity-report`
- `expectation`
- `expectation-change-record`
- `expected-detection-contract`
- `fixture-manifest`
- `live-comparison-report`
- `live-drift-report`
- `live-evaluation-report`
- `live-protocol-record`
- `live-trajectory-report`
- `release-artifact-manifest`
- `release-digest-replay`
- `rag-sensitivity-corpus-manifest`
- `rag-sensitivity-corpus-snapshot`
- `rag-sensitivity-knowledge-contract`
- `rag-sensitivity-synthetic-data-attestation`
- `run-set`
- `span-plan`
- `statistical-sufficiency-report`
- `stochastic-evidence-sensitivity-report`
- `stream-event-record`
- `stream-ingestion-diagnostics`
- `stream-run`
- `threat-applicability-manifest`
- `usage-ledger`
- `usage-pricing-snapshot`
- `usage-segment`
- `usage-summary`
- `usage-summary-delta`

`controls-mutation-onboarding-config` is intentionally absent from this list.
It is a package-bound authored workflow input, not an exported evidence root.
Although it carries `artifact_kind` and `schema_version` for strict parsing,
the project does not publish a frozen JSON Schema or cross-version replay
contract for it. The exact authored file may still be digest-bound under the
packet role `control-efficacy-onboarding-config`.

Current evidence-carrying writer roots use persisted
`schema_version: 0.6.6` and a separate semantic contract identity. Roots
introduced before v0.6.2 also accept their compatible frozen v0.6.0, v0.6.1,
v0.6.2, and v0.6.3 shapes, while roots introduced in v0.6.2 accept their
compatible frozen shapes:

- `assurance-evidence-descriptor` is `AssuranceEvidenceDescriptor/v1` and has
  an `evidence_digest` computed without its own digest field;
- `assurance-mutation-catalog` is `AssuranceMutationCatalog/v1` and has a
  `catalog_digest` computed without its own digest field;
- `assurance-mutation-campaign` is `AssuranceMutationCampaign/v1` and has a
  `campaign_digest` computed without its own digest field;
- `assurance-mutation-operator` is `AssuranceMutationOperator/v1` and has an
  `operator_digest` computed without its own digest field;
- `expected-detection-contract` is `ExpectedDetectionContract/v1` and has a
  `contract_digest` computed without its own digest field; and
- `assurance-mutation-result` is `AssuranceMutationResult/v1` and has a
  `result_digest` computed without its own digest field.

Each root carries `contract_version: 1.0.0`. Contract version identifies the
method semantics, while persisted schema version identifies JSON shape.

Two persisted roots are introduced in v0.6.2:

- `threat-applicability-manifest` is
  `ThreatApplicabilityManifest/v1`. Its `manifest_digest` is computed over the
  full RFC 8785 projection except that digest field. It binds a named and
  versioned threat source, canonically ordered present-control IDs, canonically
  ordered threat items, and limitations. Each item records applicability,
  criticality, and review date; `not_applicable` requires both owner and
  rationale. The authoring loader accepts either the exact persisted form or an
  exact minimal YAML form and rejects mixed or extension-bearing documents.
- `control-efficacy-report` is `ControlEfficacyReport/v1`. Its `report_digest`
  is computed over every persisted field except that digest. It binds campaign,
  source, suite, catalog, and threat-manifest digests; canonical, selected, and
  pending operator orders; per-operator outcomes; complete state counts;
  exact catalog, family, independence, and threat ratios; required and critical
  survivor IDs; threat coverage; semantic states; and limitations.

One persisted root is introduced on the v0.6.3 writer surface:

- `assurance-evidence-graph` is `AssuranceEvidenceGraph/v1`. Its
  `graph_digest` covers the RFC 8785 canonical artifact except that digest
  field, while each node separately binds its typed payload digest. The closed
  node vocabulary is `subject`, `requirement`, `evidence`, and `finding`; the
  relationship edge vocabulary is `supports`, `contradicts`, `targets`,
  `derived_from`, and `scoped_to`. The v0.6.5 shape additionally admits
  `depends_on` only from stochastic sensitivity evidence to its exact
  statistical-sufficiency evidence. Validation rejects duplicate node IDs or
  edges, node IDs that do not match their schema-owned typed projection,
  dangling or self edges, endpoint-kind mismatches, noncanonical ordering,
  invalid digests, incoherent evidence/finding states, invalid typed reference
  values, empty source identifiers, and undeclared graph reason codes. A
  complete compatibility manifest
  accounts for every legacy evidence-packet field and rejects an unsupported
  verdict-bearing projection. See
  [Minimal Assurance Evidence Graph](evidence_graph.md).

Seven persisted roots are introduced on the v0.6.4 writer surface:

- `rag-sensitivity-corpus-manifest` is
  `RAGSensitivityCorpusManifest/v1`. Its semantic corpus digest covers its exact,
  canonically ordered document descriptors, whose content digests bind the raw
  committed document bytes.
- `rag-sensitivity-corpus-snapshot` is `RAGSensitivityCorpusSnapshot/v1`. It
  self-digests the exact raw manifest and document UTF-8 together with decoded
  typed payloads, enforces aggregate byte limits, and makes the report's corpus
  and privacy claims independently replayable.
- `rag-sensitivity-knowledge-contract` is
  `RAGSensitivityKnowledgeAuthority/v1`. It binds exactly two corpus digests to
  one authority-scoped logical evidence/claim target, exact governing content
  digests, and coherent expected recommendation/outcome tuples.
- `rag-sensitivity-synthetic-data-attestation` is
  `RAGSensitivitySyntheticDataAttestation/v1`. For custom inputs, its
  `attestation_digest` binds the exact compiled-suite, fixture-manifest,
  knowledge-contract, semantic corpus, and raw corpus-snapshot digests together
  with the artifact author's synthetic-data and raw-persistence assertions.
  It is an operator assertion, not independent semantic verification or a
  signature.
- `evidence-sensitivity-protocol` is `RAGSensitivityProtocol/v1`. It binds the
  full controlled identity set and derives a closed difference manifest; only
  corpus and governing-evidence digests may differ. It embeds the exact fixture
  manifest plus manifest-bound raw request, subject, and tool snapshots, and
  requires their role paths to derive from the selected fixture identity.
- `evidence-sensitivity-report` is `RAGSensitivityReport/v1`. It recomputes the
  observed relation, corpus controls, exact ranked retrieval, subject-mode
  output, authority bindings, evidence links, prerequisite states, endpoint,
  verdict role, gate effect, reasons, and decision-inertia finding from its
  nested evidence. It embeds the exact compiled suite, both complete RunSets,
  and both evaluation summaries, verifies their identities and projections,
  and freshly re-evaluates each arm so packet and graph consumers retain the
  complete authenticated execution chain.
- `process-equivalence-reproduction-index` is
  `ProcessEquivalenceReproductionIndex/v1`. Its
  `reproduction_index_digest` binds a synthetic reproduction index that
  requires both the `same_output_different_process` and
  `evidence_insensitivity` strata and explicitly disallows leaderboard,
  prevalence, and real-model claims. Source roots are canonical portable paths;
  repository-specific stratum mappings remain updater policy rather than frozen
  contract semantics.

All seven roots use self-digested or exact source-artifact identities as
applicable. The evidence-sensitivity contracts are documented in
[Controlled RAG Evidence Sensitivity](evidence_sensitivity.md).

Three persisted roots are introduced on the v0.6.5 writer surface:

- `repeated-evidence-sensitivity-protocol` is
  `RepeatedEvidenceSensitivityProtocol/v1`. It prebinds the only supported
  endpoint, `expected_decision_response`, to exact baseline and counterfactual
  arm configurations, corpus and manifest digests, provider/model identities,
  adapter, pipeline, tool schema, policy bundle, case/repetition pair manifest,
  frozen case-to-cluster map, sequential arm order, cluster identities,
  multiplicity family, exclusions, coupling descriptor, and exact binary
  cluster power plan. The v1 plan requires balanced planned cluster composition
  and exactly `planned_inferential_clusters` frozen cluster identities.
  `null_response_rate`, `alternative_response_rate`, and the eventual estimate
  all describe one fixed planned-frame composite endpoint. A non-analyzable
  cluster is scored as zero for inference, while observed/analyzable counts are
  retained separately. `maximum_exclusion_rate` is an audit cap, not
  denominator or sample-size inflation. Fixed-N validation recomputes the
  integer critical value, type-I error, and power at that exact N because
  discrete exact-test feasibility is not monotone. Only the governing corpus is
  an intentional arm difference; other differences reject the confirmatory
  protocol. A separate design commitment is carried into both source RunSets
  before execution.
- `statistical-sufficiency-report` is `StatisticalSufficiencyReport/v1`. It
  retains every planned pair with a typed included, missing, excluded, identity
  mismatch, or undeclared-difference disposition; recomputes planned, actual,
  included, complete-cluster, and exclusion counts; binds the exact baseline
  and counterfactual source RunSets plus canonical record-membership
  commitments without nesting the full RunSets; computes descriptive
  complete/analyzable cluster counts
  separately from the fixed planned inferential frame; and derives `satisfied`,
  `prerequisites_unmet`, or `inconclusive` from canonical prerequisite checks.
  Missing pairs, incomplete source execution, and exclusions above the audit cap
  remain non-verdict conditions even though an all-planned-cluster analysis may
  be retained with non-analyzable clusters scored as zero. Deterministic
  fixtures bypass inference, and only a satisfied confirmatory stochastic
  report permits a population statement.
- `stochastic-evidence-sensitivity-report` is
  `StochasticEvidenceSensitivityReport/v1`. It keeps observed response and
  counterexample counts separate from the estimated response rate and derives
  its state from the embedded sufficiency report. A verdict-bearing `pass` or
  `block` requires an exact `depends_on` dependency on that satisfied report;
  non-verdict states cannot manufacture the dependency.

The coupling descriptor derives `fully_coupled`, `partially_coupled`,
`nominally_paired`, `unpaired`, or `unknown` from disjoint declared dimensions.
A requested provider seed alone cannot establish shared randomness, and
sequential `baseline_then_counterfactual` execution cannot share temporal
order. The inferential vector contains exactly one bit for every frozen planned
cluster. It is one only when every planned pair in that cluster is present,
included, and exhibits the expected response; otherwise it is zero. Planning,
estimation, and gating therefore share the same fixed denominator and exact
one-sided binomial upper-tail calculation over independent, exchangeable
composite cluster endpoints. An optional SHA-256-seeded Monte Carlo estimate of
that same null tail is diagnostic only and cannot alter the verdict. The
analysis persists a compact lossless `exact_p_value_expression` and a separate
six-place conservative upper bound for display. The gate does not consume the
rounded bound: it recomputes the exact integer rejection decision from the
frozen null probability, planned denominator, observed count, and critical
threshold. See
[Repeated Paired Evidence Sensitivity](repeated_evidence_sensitivity.md) for
planning equations, execution and privacy boundaries, and limitations.

Six persisted roots are introduced on the v0.6.6 development writer surface:

- `process-equivalence-benchmark` is
  `ProcessEquivalenceBenchmark/v1`. Its `benchmark_digest` binds the
  canonically ordered Process-Equivalence Benchmark v0.2 case identities and
  raw source/input digests. It contains no model outputs, observations, or
  scores. Exact `input_digest` values must be globally unique to reject
  byte-identical pseudo-replicates; this does not detect semantic duplicates or
  prove independence.
- `real-model-study-manifest` is `RealModelStudyManifest/v1`. Its
  `manifest_digest` binds the declared external registration-record locator
  and digest, execution window, benchmark, per-condition `execution_origin`, exact condition
  protocols/configurations/model identities, authority contract, budget,
  publication policy, and complete prespecified decision rule. The protocol-set
  and decision-rule digests are independently derived within the manifest.
  `execution_origin` is the enum `real_provider | synthetic_fixture` and
  defaults to the fail-closed synthetic value. Real-provider readiness also
  requires a derived provenance sidecar bound to both exact source RunSets and
  complete dispatch metadata; this is not cryptographic provider
  authentication.
- `real-model-study-registration-review` is
  `StudyRegistrationReviewReceipt/v1`. Its `review_receipt_digest` binds the
  study/manifest, registration method/reference, exact record SHA-256,
  registration/review timestamps, pseudonymous reviewer, and mandatory
  reference-resolution, digest-match, immutability, coverage, and
  pre-observation attestations. Reviewer identity authentication remains
  explicitly out of band.
- `real-model-study-execution-review` is
  `StudyExecutionReviewReceipt/v1`. Its self-digest binds the exact study,
  manifest/report logical and byte digests, every condition's source RunSet IDs
  and byte digests, observed-provenance digest, provider-response-ID-set digest,
  post-window review time, distinct reviewer rationale, and mandatory
  provider-log/account checks. Those checks are human attestations; reviewer
  and provider identities remain authenticated out of band.
- `real-model-study-statistical-method-review` is
  `StudyStatisticalMethodReviewReceipt/v1`. Its self-digest binds an approval
  by a qualified reviewer independent of study design, execution, and analysis
  to the exact manifest and benchmark bytes, registered protocol bytes and
  design commitments, cluster counts and roles, preregistered provider-attempt
  identities, multiplicity method, interval method, decision boundaries, and
  negative-control design. Validation requires the review after registration
  and before execution. Qualifications, independence, and review conclusions
  remain human attestations authenticated out of band.
- `real-model-study-report` is `RealModelStudyReport/v1`. Its
  `report_digest` binds the frozen manifest, every condition result,
  missing/excluded/invalid pair partitions, sufficiency and operational
  summaries, direct same-decision inertia partitions, invariant-control
  results, exact one-sided Clopper-Pearson intervals when applicable,
  limitations, drift boundary, and hypothesis classification. Statistical
  fields are omitted for `underpowered`, `invalidated`, and `not_executed`
  conditions; `control_failed` retains its unexpected-change statistics but
  blocks classification. A standalone report cannot authenticate separate
  registration evidence and therefore keeps publication permission false.
- `external-pilot-evidence` is `ExternalPilotEvidence/v1`. Its
  `pilot_evidence_digest` binds pseudonymous subject, distribution,
  environment-control classification and evidence, input origin, exact
  commands, privacy-filtered artifacts, friction/remediation, consent, and
  privacy boundaries. Only an external attempted/completed record with
  independently controlled non-maintainer CI and non-bundled input qualifies
  as an external attempt. Its pre-candidate learning classification makes every
  later exact-candidate gate-eligibility field permanently false.
- `external-pilot-input-manifest` is `PilotInputManifest/v1`. It binds each
  input-bearing workflow option to an exact privacy-safe argument, concrete
  bundled or non-bundled origin, content SHA-256, and output-bindable semantic
  identity digest, then derives separate configuration and data set digests.
- `external-pilot-independence-review` is
  `ExternalPilotIndependenceReviewReceipt/v1`. Its
  `review_receipt_digest` binds the exact pilot logical/raw evidence,
  canonical full artifact manifest, environment-control and consent artifacts,
  derived friction category and remediation state (including applied source and
  prior-candidate bindings), expected release line, exact attempt-specific
  Actions run URLs, attempts, and heads, trusted workflow revision and byte
  hashes, the execution-source SHA embedded in those bytes, complete public
  dispatch inputs and their canonical checksums, distinct reviewer, completed
  human review checklist, and review time. It is explicitly operator-attested with reviewer identity
  authenticated out of band rather than by this JSON contract.

The real-model study and external-pilot contracts are documented in
[Preregistered Real-Model Study](real_model_study.md) and
[External CI Pilot Evidence](external_pilot.md).

An `ExactRate` persists `numerator`, `denominator`, and either `defined` or
`undefined_zero_denominator`. The numerator cannot exceed the denominator, and
the state must match whether the denominator is zero. Catalog and stratum kill
rates use `caught / (caught + survived)`. `inapplicable`, `invalid_operator`,
`invalid_subject`, and `execution_error` remain separate and cannot enter that
denominator. The writer JSON Schema enforces the denominator/state relationship
and requires a zero numerator when the denominator is zero. The general
`numerator <= denominator` comparison for nonzero denominators remains a
runtime-model relational check because JSON Schema Draft 2020-12 has no
standard cross-property numeric comparison keyword.

All five `IndependenceClass` values must appear in canonical order in every
efficacy report. The fixed independent-challenge policy admits only
`external_preexisting`, `third_party_contributed`, and
`first_party_precontrol`; `first_party_postcontrol` and `unknown` are retained
but ineligible. Threat challenge coverage requires an applicable manifest
item, a completed referring operator, and at least one target control declared
present. Challenge coverage and detector outcome are independent projections:
a survived completed operator can challenge a threat without being caught.

`ControlEfficacyGateProfile` and `ControlEfficacyGateDecision` are strict nested
models rather than separately exported roots. The profile maps report facts to
effects without changing `semantic_state` or `threat_scope_state`; the decision
binds `report_digest` and records stable reason codes. The
`unscoped_catalog_references` threat-scope state is distinct from the ordinary
`gap_observed` state for declared but unchallenged threats, and its exact
residual IDs produce the configurable
`UNSCOPED_CATALOG_THREAT_REFERENCE` finding (`review` by default). Critical
operator survivors derive from applicable, critical manifest threats
referenced by the operator rather than from a separate editable critical-operator
field. Applicable critical threats without a completed challenge produce
`CRITICAL_THREAT_UNCOVERED`, also `review` by default. The profile and decision
must be supplied together to a decision-bearing writer, which freshly derives
the expected decision and requires exact equality rather than trusting a
matching report digest.

An `evidence-packet` may carry efficacy only as a complete triple:
`control_efficacy`, `control_efficacy_gate_profile`, and
`control_efficacy_gate`. Validation derives a fresh decision from the nested
report/profile pair and requires exact equality, not only a matching report
digest. `artifact_digests` must contain exactly one
`control-efficacy-report` role and exactly one typed configuration role:
`control-efficacy-onboarding-config` for authored workflow YAML or
`control-efficacy-gate-profile` for a bare profile JSON file. The generic
`control-efficacy-config` role is rejected. A packet without a nested report
rejects every efficacy artifact role. These relations keep catalog-relative
control challenge scope distinct from the required candidate evaluation
summary.

The catalog uses `core/v1` identity and
`operator-id-lexicographic/v1` ordering. Its digest covers the full canonical
projection except the digest itself, including operator and detector
identities, implementation components, provenance, independence, invariant
families, threat-source references, stable markers, ordering semantics, and
limitations. The campaign binds the source and suite digests, catalog ID and
digest, producer version, mode, seed, canonical/selected/executed/pending
operator order, embedded per-operator expected contracts and results,
applicability, prohibited-substitute finding IDs, completion, and limitations.
Every operator runs against the same immutable source; v1 does not compose or
chain mutations.

No campaign root exists until the source passes three ordered preflight
classes: strict canonical-JSON runtime values, version-aware RunSet validation
and current-model projection, then bound-profile privacy scans of both the
copied input and projected model. Canonical-identity, projection, and privacy
failures use separate fixed campaign-level messages and occur before source
hashing or artifact creation. Without a catalog, schema and source-privacy
failures remain per-operator `invalid_subject` results.

The individual result binds source and transformed digests, operator identity
and implementation digest, evaluator method ID/version/implementation digest,
gate-profile ID and canonical digest, order-independent waiver-set digest,
evaluation date, seed, exact changed paths, expected-detection contract digest,
selected finding-target digest, observed findings with target digests,
provenance, independence class, semantic state, and limitations. Evaluator
implementation identity is non-zero except that the all-zero unavailable
sentinel is permitted only for `execution_error` with
`catalog_integrity_error`, before evaluator identity can be established. A
matched finding must carry the selected target digest. Permitted operator paths
expose single-segment wildcard-template syntax in JSON Schema, while result
paths are exact JSON Pointers. See `docs/evidence_carrying_releases.md` for
field semantics and `docs/mutation_catalog.md` for the exact seven-operator
catalog.

An `llm_advisory` mutation evaluator cannot produce `caught` or `survived`;
execution returns typed, non-verdict evidence before invoking that evaluator.

Known-operator provenance carries two canonically ordered component sets. The
complete current `implementation_components` manifest derives the current
implementation digest. The authored `introduction_components` snapshot freezes
the catalog and transformation bindings from first introduction. The release
guard first matches that carried snapshot to the snapshot document stored in
the immutable introduction commit, then replays only those historical bindings,
plus the authored target-control creation digest, against LF-normalized Git
blobs. Current implementation bytes are not required to equal their historical
versions. Unknown-operator results keep both component sets,
introduction facts, and target-control provenance explicitly unknown rather than
inventing those facts.

`AgentRunRecord` intentionally has no persisted `otel_attributes` field. OTel
attributes are derived from structured fields during span-plan projection.

`control-coverage-report` records a framework evidence mapping from an
evidence packet to selected framework concepts. It carries the framework and
mapping versions, mapping digest, evidence-packet digest, per-item coverage
states, conditional rule evaluations, evidence references with optional
`evidence_digest` values, optional MITRE ATLAS mapping strength and
tactic/technique IDs, and explicit limitations. Coverage
states are review labels such as `observed`, `partially_observed`,
`conditionally_observed`, `contradictory_evidence_observed`, `not_observed`,
`not_evaluated`, `not_applicable`, and `out_of_scope`; they are not grades.
Control-specific evaluation signals are based on packet-resident finding
evidence or explicit mapping scope boundaries, not on an evaluation-summary
rollup alone.

`AgentRunRecord` and `RunSet` remain lean in fixture mode. They persist
deterministic case identity, summaries, outcomes, evidence references,
claim-evidence links, provider/model labels, tool names, and
fixture/provenance bindings. Current RunSets also require a
`privacy_profile_id` and canonical `privacy_profile_digest` identifying the
detector semantics applied by persistence and evaluation. Evaluation and
comparison summaries carry the same pair, and packet/report assembly rejects
incoherent profile bindings. Accepted pre-v0.5.0 artifacts omit the pair and
remain serializable against their frozen schemas. Live records may additionally persist
observation IDs, repetition and schedule indexes, cluster/source-group IDs,
adapter IDs, provider response IDs, resolved provider-version fields,
request/completion timestamps, trace context, attempt/retry/rate-limit
counters, inclusion or exclusion state, latency, token counts, and estimated
cost. Live RunSets bind to a protocol ID and digest, can mark incomplete
execution with stop reasons, and may include emergency process records for
external-script subprocess failures. They still do not persist raw prompts,
raw provider outputs, tool arguments, retrieval records, risk tags, or
capability inventories.

The v0.6.6 RunSet root and record provenance also admit an optional
`study_manifest_digest`. Absence remains coherent for ordinary runs. When a
RunSet carries the field, every record must carry the same exact value; a
partial or conflicting backlink fails validation. Real-model study analysis
requires the exact frozen manifest digest on both source RunSets and every
record, so a non-study or differently registered execution cannot be
substituted into the confirmatory replay.

The implemented live adapter IDs include `static-jsonl`,
`openai-chat-completions`, and `external-script`. The OpenAI-compatible adapter
is configured through the live adapter schema, requires explicit network opt-in
and HTTPS endpoint allowlisting, and is implemented through Python
standard-library HTTP support rather than a provider SDK dependency.

Live-specific root artifacts:

- `live-protocol-record` records the declared protocol identity, suite digest,
  baseline mode, hypothesis family, primary endpoint, analysis method, frozen
  group IDs and margin, confidence level, cluster definition, sample-size
  arithmetic, assumed intraclass correlation, design effect, effective sample
  size, planned repetitions, randomization blocking, retry policy, exclusion
  policy, rate-limit caps, provider-version capture plan, request/token/cost
  limits, stopping rules, tool-schema digest, policy-bundle digest, analysis
  digest, optional advanced statistical endpoint plan, optional drift
  monitoring plan, optional trajectory analysis plan, approved data boundary,
  and safety limits. Advanced endpoint plans declare endpoint IDs, roles,
  confirmatory or exploratory interpretation, prerequisite counts, reason-code
  families, rare-event exposure units, exchangeability assumptions, and
  Bonferroni multiplicity controls. Drift monitoring plans declare ordered-window metrics,
  comparability mode, exploratory or confirmatory interpretation, prerequisite
  window and observation counts, dependence and state-summary minimum window
  counts, review thresholds, and EWMA smoothing factors. Trajectory analysis
  plans declare observable transition and event methods, observation and
  transition support thresholds, event-count and exposure thresholds,
  burst-window settings, and explicit sequence invariants.
- `live-evaluation-report` records per-observation expectation results,
  inclusion/exclusion accounting, aggregate pass rates, outcome rates,
  reason-code rates, pooled and cluster-mean rates, cluster counts, design
  effects, effective sample sizes, largest-cluster sensitivity values,
  confidence interval center metadata, estimated-cost source metadata,
  per-observation tool-schema and policy-bundle provenance digests, completion
  status, stop reasons, budget-exhaustion status, provider/model group
  summaries, suite and execution-configuration digests, a top-level exploratory
  flag, latency distributions, estimated-cost distributions, optional
  statistical-invariant results, and interpretation limitations. Statistical
  invariant results can include rare-event Poisson upper bounds and observed
  cluster-correlation summaries with bootstrap uncertainty; zero observed
  critical events are represented as bounded evidence, not absence proofs.
  A rare-event bound's `confidence_level` is the effective level used to
  calculate that bound. For a confirmatory endpoint under Bonferroni control,
  it equals `1 - adjusted_alpha`.
  Degenerate per-arm cluster intervals are labeled as boundary heuristics rather
  than ordinary cluster t intervals.
- `live-comparison-report` records a baseline-to-candidate live report
  comparison with protocol binding, baseline mode, cluster-level analysis
  method, pass-rate difference, paired cluster t or percentile bootstrap
  interval when declared, fixed-reference interval when declared, margin,
  compared-cluster count, effective sample size, exploratory status, latency
  delta, cost delta, optional paired randomization test results, and
  limitations. Paired randomization tests are emitted only for protocol-declared
  concurrent paired designs and report prerequisite status, p-value,
  adjusted p-value, exact or Monte Carlo resampling count, and exchangeability
  assumption. Monte Carlo seeds are deterministic integers derived from
  protocol-bound seed material; the report cannot prove exchangeability beyond
  the declared assumption and structural pairing checks. Paired sign-flip
  randomization requires a zero non-inferiority margin. Equality at that zero
  margin is inconclusive and produces `not_evaluated`; a negative observed
  difference remains a fail-closed boundary breach but is not proof of
  regression.
  For Bonferroni outputs, consumers must treat `adjusted_alpha` and
  `adjusted_p_value` as alternative correction encodings: compare a raw
  p-value to `adjusted_alpha`, or compare `adjusted_p_value` to the protocol
  `familywise_alpha`; never compare an adjusted p-value to an adjusted alpha.
- `live-drift-report` records ordered cross-window monitoring over live
  evaluation reports. It includes a comparability result for suite identity,
  baseline mode, analysis method, protocol digest, material field match,
  tool-schema digest, policy-bundle digest, and timestamp-order validity;
  per-window observation counts, provider-version metadata availability,
  observation-window timestamps when available, and metric values; and
  per-metric diagnostics for trend, adjacent-window step changes, separate
  dependence signals from lag-1 autocorrelation and optional AR(1) summaries,
  and EWMA governance-health or control-reliability state estimates when their
  declared window thresholds are met. Dependence thresholds have an eight-window
  floor and EWMA state thresholds have a six-window floor. Drift reports are
  exploratory by default, use `not_evaluated` gate state, and keep drift signals separate from
  release-verdict evidence unless a reviewed protocol separately predeclares a
  stronger interpretation. Irregular timestamps are used for ordering and
  comparability checks only; lag-1, AR(1), trend, and EWMA diagnostics operate
  over ordered window positions and do not time-weight unequal gaps.
- `live-trajectory-report` records derived observable governance trajectories
  from a protocol-bound RunSet and its live evaluation report. It includes
  privacy-filtered path summaries over generic states such as request assembly,
  provider call, tool call, evidence check, policy check, redaction check,
  human review, verdict, exclusion, and emergency; observable transition
  profile frequencies with declared support status; sequence-invariant results that
  separate governance-control failures from operational reliability warnings;
  explicit history-dependent checks for conditions that depend on run history; and operational
  event-process summaries for retries, rate limits, exclusions, malformed
  outputs, runtime failures, emergency records, and budget stops. Event-process
  summaries report exposure-normalized rates, timestamp coverage, interarrival
  summaries when available, and exploratory burst signals. The report uses
  `not_evaluated` gate state, does not persist raw prompts, raw outputs, tool
  arguments, sensitive identifiers, or unredacted summaries, and treats path
  coverage as sampled review evidence rather than proof that unsafe paths are
  impossible.
  Transition profiles are adjacent-state summaries over observable structured
  artifacts, while history-dependent checks capture non-Markov sequence
  conditions. Burst-window event-process outputs are reliability review signals,
  not fitted Hawkes intensity estimates.
- `emergency-process-record` records redacted subprocess failure metadata for
  configured external scripts, including failure kind, command digest,
  executable/script names, working-directory digest, observation/run/case
  linkage, duration, timeout, exit code, stdout/stderr byte counts, redacted
  stderr summary, safe error metadata, and trace context. It does not persist
  raw prompts, raw provider outputs, raw stdout, raw stderr, or script
  arguments.

Streaming root artifacts:

- `stream-event-record` records one privacy-filtered streaming event with a
  run ID, event ID, sequence number, optional case and producer dimensions,
  optional framework observation, optional usage segment, optional span context,
  privacy-filtered attributes, and a canonical payload digest. It does not
  persist raw prompts, raw token chunks, raw tool arguments, or unredacted model
  output.
  The stream payload digest is computed by `agent-assure stream ingest`;
  producers may omit it. When a producer declares `digest`, ingestion verifies
  it against this projection:
  remove `digest`, `event_id`, `artifact_kind`, and `schema_version` fields at
  any object depth; remove object fields whose value is JSON null; remove object
  fields whose projected value is an empty object or empty list; remove
  `currency: "USD"` fields because that is the usage schema default; recurse
  through nested objects and arrays; then hash the canonical JSON projection
  with SHA-256. Arrays preserve their non-null projected elements. Producers
  that rely on idempotent redelivery should keep timestamps and
  privacy-filtered payload fields stable for the same logical event. Global
  timestamps are optional; any timestamp that is present must use strict RFC
  3339 date-time syntax with an uppercase `T` and either `Z` or a numeric UTC
  offset. Producer-local streams require a timestamp on every event.
- `stream-ingestion-diagnostics` records the declared sequencing contract,
  source event count, accepted event count, duplicate count, run IDs, duplicate
  summaries, and ingestion diagnostics. Duplicate summaries are emitted only
  when a duplicate composite key has the same event ID and digest.
- `stream-run` records a deterministic ordered stream event set after
  validation and deduplication. Its sequencing contract is either global
  run-level sequence numbers or producer-local sequence numbers using a
  declared producer field. It carries aggregate usage evidence and is projected
  by `agent-assure stream evaluate` into normal fixture-mode RunSets and
  ordered span plans.

`SpanPlan` may include W3C trace context so optional OpenTelemetry SDK export
can link emitted spans to the live runtime context. Span plans remain derived
from structured fields and do not duplicate an `otel_attributes` dictionary on
run records. In v0.5.0, stream span plans are flat per-run plans: stream events
carry `agent_assure.stream.span_id` and
`agent_assure.stream.parent_span_id` as event attributes when present, but the
schema does not yet model a hierarchy of child `SpanPlan` records.

Observed `LiveRate` values are emitted only for a positive observation
denominator. If no observation remains for a rate, evaluation fails closed
rather than serializing a fabricated `0.000000` estimate or `[0, 0]` interval.
A declared fixed reference is not an observed rate and may still carry its
configured point value with a zero observation denominator. Current-model
validation distinguishes that exact fixed-reference representation from an
observed rate. Otherwise `LiveRate.rate` is the pooled observation rate and
`LiveRate.cluster_mean_rate` is the unweighted mean across declared clusters.
When the interval center is `cluster_mean_rate`, `ci_lower` and `ci_upper`
describe that cluster-centered estimate and are not required to bracket the
pooled rate under unequal cluster sizes.

External `AgentRunRecord` producers must also follow
`agent-run-record-producer-contract/v2`, documented in
`docs/schema_evolution.md`. In particular, material claim coverage is satisfied
only by explicit `claim_evidence_links` that point to present evidence
references, and process-control eligibility depends on declared field origin.

Usage schema roots started as an additive v0.3.1 release surface and are
extended in v0.4.3 for declared pricing snapshots and basis-point deltas.
`UsageSegment` records measured token, tool-call, retry, latency, and declared
estimated cost fields for a case, run, span, or future stream event range.
Persisted money uses `estimated_cost_microusd` integers; the schema does not
use floats for cost. Micro-USD cost evidence is USD-only by design in v0.4.3;
the pattern-validated `currency` field remains for schema continuity and
non-cost usage summaries, but cost-bearing artifacts must use `USD`. v0.4.3
producers emit usage roots with `schema_version: "0.4.3"`; replay still
accepts v0.3.1 usage roots, while v0.4.3-only fields cannot be labeled as
v0.3.1. Usage-bearing containers use `schema_version: "0.3.1"` or later when
usage evidence is present; `schema_version: "0.2.0"` containers reject direct
and nested usage fields.
Cost-bearing usage segments require explicit limitations, and this requirement
is encoded in the exported JSON Schema. Segment metadata labels such as
`provider`, `model`, `operation`, `cost_basis`, `pricing_snapshot_id`, and
`pricing_snapshot_digest` are caller-controlled review metadata; producers
should not put sensitive identifiers in them.
Segment-level `pricing_snapshot_digest` is a v0.4.3-only provenance field and
is rejected on `schema_version: "0.3.1"` usage segments.
`usage-pricing-snapshot` records explicit versioned demo or caller-declared
token prices with integer micro-USD input and output rates, optional cached
input and reasoning-token rates, and explicit limitations. Pricing snapshots
are USD-only while the persisted cost field remains `estimated_cost_microusd`.
The bundled pricing helper refuses total-token-only segments; callers must
provide `prompt_tokens` and `completion_tokens`, and must declare cached-input
or reasoning-token rates when those token classes are present.
The bundled `examples/usage/local-demo-pricing-v1.json` and
`examples/usage/langgraph-expense-demo-pricing-v1.json` snapshots are marked as
demo fixtures and are not live provider pricing.
`UsageLedger` keeps the contributing segments, the deterministic
`sum_known_fields_v1` aggregation method, and missingness counts. JSON Schema
validates the shape of those counts; Pydantic validation verifies that the
counts exactly match the contributing segments. `UsageSummary` contains summed
known fields, cost-basis labels, pricing snapshot IDs and digests, optional
`cost_observation_count`, and limitations, and must match the ledger-derived
summary when both are present. `total_latency_ms` is the sum of known segment
latency fields under `sum_known_fields_v1`, not necessarily wall-clock elapsed
time for parallel runs. Cost aggregation and comparison require homogeneous
cost basis plus matching explicit pricing snapshot IDs and content digests; raw
cost numbers without that provenance remain review facts but are not diffed as
comparable declared estimated cost evidence. `cost_observation_count` is derived
from distinct `run_id` values when available, otherwise from distinct `case_id`
values with a limitation; multiple unlabeled cost-bearing segments omit the
per-observation denominator rather than guessing. `UsageSummaryDelta` records
baseline-to-candidate usage deltas when usage is observed, including integer
basis-point fields such as `total_tokens_delta_bps` where a nonzero baseline
exists. Missing usage is represented as `not_observed`, not as a failing gate.
Partial missingness is retained in limitations so known-field totals are not
presented as complete observations. These fields are measured usage and
declared estimated cost evidence only, not business impact claims.
