# Schema Reference

Schema version: `0.2.0`.

Persisted artifacts include `schema_version` and `artifact_kind`.

Exported roots:

- `agent-run-record`
- `compiled-suite`
- `comparison-report`
- `comparison-summary`
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

`AgentRunRecord` intentionally has no persisted `otel_attributes` field. OTel
attributes are derived from structured fields during span-plan projection.

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

`SpanPlan` may include W3C trace context so optional OpenTelemetry SDK export
can link emitted spans to the live runtime context. Span plans remain derived
from structured fields and do not duplicate an `otel_attributes` dictionary on
run records.

`LiveRate.rate` is the pooled observation rate. `LiveRate.cluster_mean_rate` is
the unweighted mean across declared clusters. When the interval center is
`cluster_mean_rate`, `ci_lower` and `ci_upper` describe that cluster-centered
estimate and are not guaranteed to bracket the pooled rate under unequal
cluster sizes.

External `AgentRunRecord` producers must also follow
`agent-run-record-producer-contract/v1`, documented in
`docs/schema_evolution.md`. In particular, material claim coverage is satisfied
only by explicit `claim_evidence_links` that point to present evidence
references.
