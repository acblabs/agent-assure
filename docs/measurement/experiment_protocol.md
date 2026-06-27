# Experiment Protocol

Protocol status: live statistical protocol. This document defines the minimum
statistical, operational, and safety controls required before interpreting a
live stochastic evaluation. It does not authorize broad model-quality,
safety-assurance, compliance, or clinical-validity claims. Runtime isolation,
OpenTelemetry SDK spans, runtime context propagation, and OTLP export remain
future implementation work.

The protocol is intentionally conservative. A live result must be interpreted
as time-bound evidence about a declared provider/model/configuration/date
window, not as a general safety, compliance, clinical, or provider-quality
claim.

## Scope

The live evaluation scope is limited to governed agent pipelines whose behavior
can already be evaluated in fixture mode. A candidate must first pass or
explain deterministic fixture-mode findings before a live stochastic protocol
instance can be approved.

A protocol instance must be frozen before execution and must identify:

- suite digest, fixture digest, and expectation set;
- provider, model, adapter, tool-schema, prompt-template, and policy digests;
- baseline handling mode and reference source;
- hypotheses, endpoints, non-inferiority or superiority margins, and analysis
  method;
- planned sample size, repetition count, randomization seed, and stopping
  rules;
- retry, exclusion, rate-limit, budget, data-handling, and safety controls.

The same live results cannot be reused for a different claim unless that reuse
was declared before execution.

## Experimental Unit

The primary observational unit is:

```text
case_id x variant_id x provider_id x model_id x repetition_index
```

Repeated calls for the same case are correlated. Analysis must preserve that
nesting and must not treat repeated provider calls as fully independent
population samples. Execution order should be randomized within balanced case
blocks, with the random seed recorded in the run manifest.

If multiple cases share the same source document, retrieval corpus shard,
conversation seed, or other upstream stochastic dependency, the independence
cluster is the shared source group rather than the individual case. Sampling,
bootstrap resampling, and effective sample-size calculations must use the
largest declared correlation cluster.

## Baseline Handling

The default design is concurrent paired re-evaluation. The approved baseline
configuration is frozen before execution, then baseline and candidate arms are
run in the same protocol instance over the same declared cases, provider/model
set, repetition schedule, randomization blocks, and date window. In this mode,
`baseline_pass_rate` is the observed concurrent baseline rate, and paired
case-level or cluster-level differences are valid analysis inputs.

A protocol instance may instead use fixed-reference threshold mode. In that
mode, the reference is a frozen historical value or externally approved
threshold, not a concurrently observed baseline arm. Fixed-reference analyses
must use a one-sample method against the declared constant and must not use
paired bootstrap, paired t-intervals, or paired regression language. Reports
must label the mode as fixed-reference and state that provider drift between
the historical reference and current candidate is not controlled by pairing.

## Hypotheses

Each live run must declare one primary hypothesis family before execution.
Allowed primary families are:

- governance-control non-inferiority: the candidate expectation-pass rate is
  not materially worse than the concurrently re-evaluated approved baseline, or
  a fixed reference threshold when that mode is explicitly declared, by more
  than the declared margin;
- provider/model comparison: two declared provider/model configurations differ
  in expectation-pass rate, refusal rate, latency, or cost under a declared
  endpoint;
- regression detection: the candidate has a higher rate of a declared
  reason-code family than the approved baseline.

For governance-control non-inferiority, the default null hypothesis is:

```text
H0: candidate_pass_rate - baseline_pass_rate <= -delta
H1: candidate_pass_rate - baseline_pass_rate > -delta
```

The default `delta` is five percentage points unless a narrower domain-specific
margin is frozen before execution. This default is an upper bound for low- or
medium-severity aggregate expectation-pass endpoints; high-severity governance
controls should use a narrower margin, including zero tolerance when
appropriate. Any hard policy violation, sensitive-content leak, forbidden
provider/tool use, or unapproved human-review bypass remains verdict-bearing
regardless of aggregate statistical performance.

Exploratory analyses are allowed only when labeled as exploratory. They must
not be reported as confirmatory evidence.

## Endpoints

The default primary endpoint is the expectation-pass indicator for each
case-level live observation. Secondary endpoints may include:

- reason-code rates by configured family;
- refusal or incomplete-run rates;
- cost per successful eligible observation;
- latency median and tail quantiles;
- provider or adapter reliability events.

Cost and latency are operational measurements. They are not evidence of model
quality unless a protocol instance explicitly defines and justifies such a
claim.

## Sample-Size Plan

A protocol instance must include a sample-size calculation before execution.
The calculation must state the target margin, desired confidence level, desired
power when hypothesis testing is planned, expected baseline rate, expected
candidate rate, planned observations per cluster, and assumed intraclass
correlation.

Cluster adjustment must use the design-effect formula:

```text
DEFF = 1 + (m - 1) * rho
effective_n = planned_observations / DEFF
```

`m` is the planned number of observations per independence cluster and `rho` is
the assumed intraclass correlation. When no pilot estimate exists, use
`rho = 0.20` as the default conservative planning value and include sensitivity
calculations at `rho = 0.05` and `rho = 0.40`. If shared-source grouping makes
clusters unequal, use the mean cluster size for planning and report a
sensitivity calculation using the largest cluster size.

Minimum planning rules:

- fewer than 30 distinct cases is exploratory only;
- repeated calls must be adjusted for clustering by case;
- shared-source or shared-corpus groups must be adjusted at the shared-source
  cluster level rather than the case level;
- benchmark-style rate claims should target a 95 percent confidence interval
  half-width of at most five percentage points for the primary endpoint;
- non-inferiority claims should target at least 80 percent power at the
  declared margin after applying the clustering adjustment;
- budget-constrained runs that cannot meet the planned sample size must be
  marked incomplete or exploratory before results are interpreted.

The frozen protocol must show the arithmetic used to derive planned sample
size and effective sample size. The analysis report must include the planned
and observed effective sample size after clustering.

## Confidence-Interval Method

Primary binary endpoints must report 95 percent confidence intervals. The
v0.1 implementation accepts only `confidence_level = 0.950000`; protocols that
need 90 percent or 99 percent intervals require a schema and critical-value
update before execution. For the default concurrent paired design, use paired
cluster-level inference. The
preferred large-sample method is a paired, cluster-stratified bootstrap that
resamples independence clusters and keeps all planned baseline/candidate
observations for each sampled cluster. For fixed-reference threshold mode, use a
one-sample interval or test against the declared constant; paired methods are
not valid in that mode. Per-arm descriptive rates must use cluster-aware
metadata and must not treat repeated observations as independent.

Percentile cluster bootstrap intervals are acceptable only with at least 50
independent clusters. With 30 to 49 independent clusters, the confirmatory
interval must be a t-interval over cluster-level paired differences or a
predeclared BCa bootstrap with a small-cluster caveat. Fewer than 30
independent clusters is exploratory only unless an external statistical review
approves a different exact or randomization method before execution.

Per-arm descriptive rates may report a pooled observation rate together with a
cluster-mean rate. When cluster sizes are unequal, the pooled rate and the
cluster-centered confidence interval can have different centers; reports must
show enough metadata for reviewers to see that distinction.

For rare critical events, including sensitive-content leaks or forbidden
tool/provider use, an observed count of zero must be reported with an upper
confidence bound, not as proof of absence. The rule-of-three approximation is
acceptable for a quick upper bound; exact binomial intervals are preferred in
final reports.

Latency and cost summaries should use bootstrap intervals for medians and tail
quantiles. Normal approximations are not acceptable for skewed operational
metrics unless justified by diagnostics.

If multiple confirmatory endpoints, reason-code families, provider/model
comparisons, or subgroup claims are run, adjust p-values or confidence
decisions with a declared family-wise method such as Holm-Bonferroni, or
declare a hierarchy that controls which findings are confirmatory.
Exploratory comparisons must remain labeled exploratory.

## Interim Looks and Stopping Rules

Interim looks are operational by default. They may inspect spend, rate-limit
events, retry exhaustion, sensitive-content handling, adapter failures, and
other safety or reliability signals, but they must not inspect comparative
effect estimates used for the confirmatory test.

If a protocol instance will inspect interim comparative results or stop early
for efficacy or futility, it must declare a group-sequential design before
execution, including the number and timing of looks, alpha-spending rule, and
final inference method. Acceptable examples include O'Brien-Fleming or Pocock
style boundaries. Without a predeclared sequential design, early stopping can
only make the run incomplete, inconclusive, or failed for operational/safety
reasons.

## Retry and Exclusion Rules

Retries must never be used to improve a model answer. A retry is allowed only
when no usable provider response was accepted, such as a transient transport
failure, timeout before response receipt, or provider-side 5xx error. The
default maximum is two retries with exponential backoff. Production protocols
may add jitter; deterministic review fixtures may declare jitter-free backoff
so replay timing remains predictable.

The following outcomes are included rather than excluded:

- provider refusals;
- content-policy blocks returned by the provider;
- malformed structured outputs;
- tool-call schema violations;
- timeouts after the declared retry budget;
- rate-limit failures after the declared backoff budget.

Exclusions are allowed only for predeclared reasons that prevent an observation
from being interpretable, such as a local configuration error discovered before
provider processing or a provider incident that prevents request acceptance.
Every exclusion must have a reason, timestamp, attempt count, and redacted
diagnostic entry. Exclusion rates must be reported next to primary results.

## Provider-Version Capture

Each live observation must capture enough provenance to make the result
time-bound and reviewable without persisting raw prompts, tool arguments,
outputs, or sensitive identifiers. Required fields include:

- provider name and endpoint family;
- requested model identifier;
- provider-returned resolved model identifier or version, when available;
- API version, SDK package name and version, and adapter version;
- region or deployment label, when applicable and non-sensitive;
- request start and completion timestamps in UTC;
- prompt-template digest, tool-schema digest, policy-bundle digest, suite
  digest, and run-configuration digest;
- response metadata needed for rate-limit, cost, latency, and retry accounting,
  after privacy filtering.

If the provider does not expose a resolved version, the report must state that
the resolved provider version is unknown. Unknown provider versions prevent
version-specific claims.

## Rate-Limit Handling

Live execution must comply with provider terms and configured quotas. The run
configuration must declare per-provider concurrency, requests-per-minute caps,
tokens-per-minute caps when available, and maximum backoff duration.

The runner must honor `Retry-After` or equivalent provider guidance when it is
available. It must not use parallelism, account rotation, or region rotation to
bypass limits. If rate-limit failures exceed the predeclared threshold, the run
must stop cleanly and be marked incomplete or inconclusive.

When a tokens-per-minute cap is declared, the live configuration must provide a
maximum generated-token reservation. The runner paces requests using the prompt
character count plus that reservation before each provider call, then reconciles
the window with observed token usage when the provider reports it.

Rate-limit events are operational findings. They must be reported with redacted
metadata and included in reliability summaries.

## Cost Budgets

Every live protocol instance must define hard budgets before execution:

- maximum total spend;
- maximum spend by provider/model pair;
- maximum requests and maximum generated tokens;
- warning threshold and stop threshold;
- policy for incomplete analysis when the budget is exhausted.

Budget thresholds must be enforced mechanically. A run must stop before
exceeding the hard budget, and budget increases are not allowed after any
operational telemetry or interim analysis is reviewed. Reports must separate
estimated cost, provider-reported cost, and cost inferred from token pricing
tables.

Cost measurements are time-bound to the provider pricing information recorded
with the run. They are not production cost projections unless a separate
production workload model is declared.

## Live-Run Ethics and Safety Limits

Live runs must use synthetic, public, or explicitly authorized data only. Raw
PHI, PII, secrets, credentials, customer data, and employer-confidential data
are prohibited unless a separate reviewed data-handling protocol exists outside
this repository.

The prompt and tool surface must not request illegal activity, real-world
autonomous actions, credential disclosure, malware, self-harm assistance, or
other disallowed content. External tools must be read-only or side-effect-free
unless separately reviewed. Network access must be limited to declared provider
endpoints and required package infrastructure.

Stop the run immediately if any of the following occurs:

- raw sensitive content is persisted;
- credentials or secrets appear in logs, reports, packets, or telemetry;
- a provider returns unexpected high-risk content under the configured safety
  taxonomy;
- budget or rate-limit controls fail closed incorrectly;
- an adapter sends data to an undeclared provider, endpoint, or tool.

The final report must document provider data-retention settings when they are
available, including whether prompts or outputs may be retained or used for
training by the provider. Absence of provider retention metadata must be
reported as an unresolved limitation.

## Machine-Readable Protocol Record

This prose protocol is paired with a strict JSON `live-protocol-record`
artifact. The record has its own artifact kind, schema version, canonical
digest path, and schema evolution path. A live evaluation report can reference
that digest so reviewers can verify that the run was executed under the
declared hypotheses, baseline mode, sample-size plan, retry/exclusion policy,
rate-limit policy, cost budget, provider-version capture plan, and safety
limits.

The machine-readable protocol record must include the tool-schema digest and
policy-bundle digest. Each live observation's provenance must carry matching
digests; mismatches make the RunSet invalid for live evaluation.

The live protocol record is necessary but not sufficient for interpretation.
Reports must still show whether the executed RunSet matched the approved
configuration, whether exclusions and retries were handled as declared, and
whether any budget, rate-limit, privacy, or safety stop condition was reached.

## Required Artifacts Before Execution

Before a live run begins, the repository or run workspace must contain:

- frozen machine-readable protocol record and matching human-readable review
  note;
- suite and run-configuration digests;
- baseline handling mode and reference configuration;
- provider-version capture plan;
- randomization manifest;
- sample-size calculation;
- retry, exclusion, and rate-limit policy;
- cost budget ledger;
- safety and data-handling review note;
- analysis script or notebook digest;
- report template with claim boundaries.

After execution, publish an evidence packet only if raw sensitive payloads are
absent, exclusions are accounted for, budgets were enforced, and the analysis
report marks unsupported or inconclusive capabilities as `not_evaluated`.

## Interpretation Boundary

A statistically acceptable live result would support only the declared,
time-bound claim for the declared suite, provider/model set, configuration, and
date window. It would not establish safety assurance, regulatory compliance,
clinical validity, provider superiority in general, or standards acceptance.
