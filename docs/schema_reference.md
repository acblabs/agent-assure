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
- `live-evaluation-report`
- `live-protocol-record`
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

Live-specific root artifacts:

- `live-protocol-record` records the declared protocol identity, suite digest,
  baseline mode, hypothesis family, primary endpoint, analysis method, frozen
  group IDs and margin, confidence level, cluster definition, sample-size
  arithmetic, assumed intraclass correlation, design effect, effective sample
  size, planned repetitions, randomization blocking, retry policy, exclusion
  policy, rate-limit caps, provider-version capture plan, request/token/cost
  limits, stopping rules, tool-schema digest, policy-bundle digest, analysis
  digest, approved data boundary, and safety limits.
- `live-evaluation-report` records per-observation expectation results,
  inclusion/exclusion accounting, aggregate pass rates, outcome rates,
  reason-code rates, pooled and cluster-mean rates, cluster counts, design
  effects, effective sample sizes, largest-cluster sensitivity values,
  confidence interval center metadata, estimated-cost source metadata,
  per-observation tool-schema and policy-bundle provenance digests, completion
  status, stop reasons, budget-exhaustion status, provider/model group
  summaries, latency distributions, estimated-cost distributions, and
  interpretation limitations.
- `live-comparison-report` records a baseline-to-candidate live report
  comparison with protocol binding, baseline mode, cluster-level analysis
  method, pass-rate difference, paired cluster t or percentile bootstrap
  interval when declared, fixed-reference interval when declared, margin,
  compared-cluster count, effective sample size, exploratory status, latency
  delta, cost delta, and limitations.
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
