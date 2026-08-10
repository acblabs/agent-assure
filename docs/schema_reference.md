# Schema Reference

Current schema version: `0.6.2`.

Persisted artifacts include `schema_version` and `artifact_kind`. Current
models emit `schema_version: 0.6.2` and continue to accept legacy
`schema_version: 0.2.0`, `schema_version: 0.3.1`, `schema_version: 0.4.3`,
`schema_version: 0.5.0`, `schema_version: 0.6.0`, and
`schema_version: 0.6.1` artifacts where their compatibility contracts permit
those labels. Historical artifacts validate against their frozen schema
snapshots. The v0.6.0 and v0.6.1 snapshots remain immutable; current v0.6
relational checks continue to apply after validated legacy projection,
including each evidence-carrying root's self-digest. Published v0.6.2 schemas
are writer contracts: every root and nested persisted model pins
`schema_version` to that model's emitted default. Thus nested current mutation
operators, expected-detection contracts, and results use `0.6.2`, while the
independently versioned usage models continue to emit `0.4.3`. Compatibility
projection of a frozen artifact does not widen the current wire schema.
Importable models and their direct `model_json_schema()` output retain declared
legacy read compatibility; checked-in schemas and current artifact validation
use the separately pinned writer-schema projection.

In v0.6.1 the evidence graph uses the same exact ASCII machine-identifier
grammar in runtime and JSON Schema. This covers `EvidenceRef.ref_id`,
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
targeted coherence checks match the v0.6.2 writer schemas without applying
parent-version equality to independently versioned components such as usage
records. Matching legacy parent/member projections remain supported through
their frozen schemas.

A current `EvidencePacket` likewise requires each nested persisted artifact
covered by its writer schema to use the packet schema version, while nested
`UsageSummary` and `UsageSummaryDelta` retain their independently emitted
version. The same exact relationship is enforced for coherent v0.6.1 packet
projection. Packet persistence validates the post-redaction payload against
the root-version-selected current writer or legacy frozen schema before writing
bytes, so a current packet cannot embed a legacy evaluation or comparison
summary.

At schema versions `0.6.0`, `0.6.1`, and `0.6.2`, `evaluation-report` requires
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

Every v0.6 live `agent-run-record` also requires
`cost_budget_committed_usd`, `generated_token_budget_committed`, and
`total_token_budget_committed`. These fields record conservative amounts
charged against local dispatch ceilings, including retained reservations for
network attempts whose billing or generation outcome is ambiguous; they are
distinct from provider-reported usage and estimated invoice cost.

Exported roots:

- `assurance-evidence-descriptor`
- `assurance-mutation-campaign`
- `assurance-mutation-catalog`
- `assurance-mutation-operator`
- `assurance-mutation-result`
- `agent-run-record`
- `compiled-suite`
- `comparison-report`
- `comparison-summary`
- `control-coverage-report`
- `control-efficacy-report`
- `evaluation-report`
- `evaluation-summary`
- `emergency-process-record`
- `environment-info`
- `evidence-packet`
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
- `run-set`
- `span-plan`
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

Current evidence-carrying release roots use persisted
`schema_version: 0.6.2` and a separate semantic contract identity. The roots
introduced before v0.6.2 also accept their compatible frozen v0.6.0 and v0.6.1
shapes:

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

`LiveRate.rate` is the pooled observation rate. `LiveRate.cluster_mean_rate` is
the unweighted mean across declared clusters. When the interval center is
`cluster_mean_rate`, `ci_lower` and `ci_upper` describe that cluster-centered
estimate and are not required to bracket the pooled rate under unequal
cluster sizes.

External `AgentRunRecord` producers must also follow
`agent-run-record-producer-contract/v1`, documented in
`docs/schema_evolution.md`. In particular, material claim coverage is satisfied
only by explicit `claim_evidence_links` that point to present evidence
references.

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
