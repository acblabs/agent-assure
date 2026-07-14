# Schema Reference

Schema version: `0.5.0`.

Persisted artifacts include `schema_version` and `artifact_kind`. The current
models emit `schema_version: 0.5.0` and continue to accept legacy
`schema_version: 0.2.0`, `schema_version: 0.3.1`, and
`schema_version: 0.4.3` artifacts for replay. Usage roots still emit their
own v0.4.3 usage schema label because sprint 13 reuses that shape.

Exported roots:

- `agent-run-record`
- `compiled-suite`
- `comparison-report`
- `comparison-summary`
- `control-coverage-report`
- `evaluation-report`
- `evaluation-summary`
- `emergency-process-record`
- `environment-info`
- `evidence-packet`
- `expectation`
- `expectation-change-record`
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
- `usage-ledger`
- `usage-pricing-snapshot`
- `usage-segment`
- `usage-summary`
- `usage-summary-delta`

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
fixture/provenance bindings. Live records may additionally persist
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
  summaries, latency distributions, estimated-cost distributions, optional
  statistical-invariant results, and interpretation limitations. Statistical
  invariant results can include rare-event Poisson upper bounds and observed
  cluster-correlation summaries with bootstrap uncertainty; zero observed
  critical events are represented as bounded evidence, not absence proofs.
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
  the declared assumption and structural pairing checks.
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
  privacy-filtered payload fields stable for the same logical event.
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
