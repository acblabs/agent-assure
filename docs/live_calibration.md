# Live Calibration and Test Summary

This document summarizes the synthetic evidence used to check the v0.2 live
statistical, drift-monitoring, trajectory, and operational event-process paths.
Here, calibration means deterministic synthetic fixtures that exercise expected
null behavior, boundary behavior, prerequisite failures, and report labeling. It
is not external empirical validation of a provider, model, or production
workflow.

## Synthetic Inputs

Live tests use strict `live-protocol-record` artifacts, synthetic
`AgentRunRecord` values, and the offline `static-jsonl` adapter. The helper
protocols declare suite digest, protocol digest, cluster counts, repetition
counts, randomization seed, analysis method, policy-bundle digest,
tool-schema digest, budget rules, and approved synthetic data boundary before
reports are built.

The static adapter and unit fixtures keep provider outputs fixed, so tests can
check report semantics without network access, token spend, provider drift, or
undocumented model changes.

## Statistical Checks

`tests/unit/evaluation/test_live_statistics.py` covers pooled and cluster-mean
rates, design-effect and effective-sample calculations, largest-cluster
sensitivity, boundary intervals, paired t intervals, bootstrap path selection,
fixed-reference comparisons, incomplete stops, exclusions, and budget-stop
status.

Advanced endpoint tests cover bounded-work binomial rare-event bounds (exact
Clopper--Pearson, exact zero-event closed form, and conservative large-n
one-sided Bernoulli KL-Chernoff inversion with rational logarithm enclosures and
outward rounding), one-sidedness labeling, zero-event interpretation, observed
cluster-correlation summaries with uncertainty, Bonferroni rejection of
unadjusted multiple confirmatory endpoints, deterministic SHA-256-derived
resampling seeds, and exact paired-permutation null behavior. The scalable
branches have work bounded independently of cluster count. Tests also assert
that the KL-Chernoff branch remains explicitly non-exact. Low-cluster,
mismatched-pairing, unsupported-confidence, inconsistent-design-effect, and
incompatible primary endpoint cases fail closed or remain exploratory.

Adversarial persistence tests mutate otherwise valid current reports and prove
that deserialization rejects forged top-level gate states, count/rate and
zero-event contradictions, altered intervals and p-values, nested
schema-version downgrades, paired-arm denominator or fixed-reference count
contradictions, and comparison rates or differences that disagree with their
paired clusters. The comparison verifier reconstructs both complete arm-rate
objects from per-cluster integer counts and recomputes inference from the
unrounded count ratios. This avoids a second display-precision rounding step at
sign and non-inferiority boundaries. The
evaluation verifier recomputes decision-bearing projections from bounded
embedded sufficient statistics. Before any evaluation kernel runs, one
aggregate plan charges every nondegenerate exclusion, pass, outcome, and reason
rate for both the overall summary and every group together with every eligible
ICC bootstrap. Exact Clopper--Pearson items are also collected and checked as
one batch before the first exact-tail inversion. The shared resampling ceiling
is 4,096,000 primitive sample/sign units: one 1,000-draw ICC bootstrap over the
4,096-cluster storage ceiling. Exact paired permutation is capped at 17
clusters; bootstrap and Monte Carlo protocols are
rejected during protocol validation when planned clusters exceed the budget.
T-based and descriptive methods retain the full persisted-observation limit.
Source digests still require comparison with separately trusted RunSet or
evaluation-report bytes. Resolving both comparison source-evaluation digests
against separately trusted evaluation reports establishes source consistency,
not provider-side truth. Latency and cost absolutes remain source-declarative,
their delta arithmetic is replayed, and the operational fields remain
non-decision-bearing. The tests do not turn producer-attested observations into
remote attestation.

Current evaluation-report loading now checks every execution obligation that is
recoverable from its bounded observation projection before resampling or
interval work: planned grid and blocks, cluster derivation, prompt/source-group
stability, homogeneous arm metadata, exclusions, retry/rate-limit ceilings,
declared provider capture, tool/policy digests, and exact per-observation and
total costs. The loader reads one bounded byte snapshot, applies writer or
frozen JSON Schema validation, and reuses the same single Pydantic projection
for semantic verification and its return value; it does not rerun statistical
derivation after validation. The projection deliberately omits token usage, committed
cost/token budgets, per-run configuration/model provenance, and the full frozen
suite/prompt manifest. Those properties remain verifiable only against the
separately trusted source RunSet identified by `source_runset_digest`.

## Drift Checks

Drift tests build ordered synthetic live evaluation windows and verify
comparability checks, timestamp-order checks, ordered trend diagnostics,
adjacent-step diagnostics, lag-1 autocorrelation, AR(1) summaries, and EWMA
governance-health or control-reliability summaries. Window-count thresholds are
exercised so dependence and state summaries remain invalid or exploratory when
their prerequisites are not met.

## Trajectory and Event-Process Checks

Trajectory tests derive observable state paths from structured live RunSets and
evaluation reports. They verify transition summaries, required-review and
claim-evidence sequence invariants, explicit history-dependent checks,
separation of governance-control findings from operational reliability
warnings, retry burst detection, missing-timestamp labeling, and counted-event
handling that does not invent timestamps.

These checks cover Markov-style adjacent-state summaries,
history-dependent/non-Markov sequence conditions, and burst-window reliability
signals. They do not calibrate a fitted Hawkes or other point-process intensity
model.

The frozen plan's method set is authoritative. Drift metrics require their
descriptive-trend basis and optional dependence/state outputs are conditional
on declaration. A missing metric value in any declared drift window is never
silently removed to join the values on either side: adjacency, dependence, and
EWMA outputs are suppressed across that gap, and a confirmatory metric receives
an invalid prerequisite and monitoring status. Trajectory sequence and event-process families are omitted
when undeclared; confirmatory trajectory analysis requires the complete
supported set and at least one confirmatory invariant target. Exploratory plans
reject confirmatory invariants, and a targetless result cannot receive
`trajectory_status: valid`. Each invariant's `evaluated_observations` is its
applicable exposure, not the report-wide path count: all paths for forbidden
states, included approval paths requiring review for the review invariant,
observable included approval paths for claim evidence, and included paths
carrying both attempt and retry counters for counter consistency. For the
claim-evidence invariant, control-ineligible included approvals are counted
separately in `unobservable_observations`; excluded observations contribute to
neither population. Path status makes that boundary explicit: excluded paths
are `not_evaluated`, included non-approvals are `not_applicable`, and only
included approvals may be `complete`, `incomplete`, or `unobservable`. Zero
applicable exposure invalidates a confirmatory invariant. The currently
observable review contract supports only
`required_state: human_review`. A zero-count process with adequate exposure is a
met observed zero rate, while positive under-threshold or incompletely
timestamped processes cannot emit a no-burst signal.

`tests/integration/test_live_cli.py` exercises the CLI path end to end with the
static adapter: live run, live evaluate, live drift, and live trajectory all
write schema-valid JSON and Markdown reports from synthetic local inputs.

## Reproduction Commands

```bash
pytest tests/unit/evaluation/test_live_statistics.py
pytest tests/integration/test_live_cli.py
pytest tests/integration/test_schema_parity.py
```

These checks support the claim that the implementation labels advanced
statistical, drift, trajectory, and event-process outputs as confirmatory,
exploratory, invalid, or `not_evaluated` according to the frozen protocol and
declared prerequisites. They do not establish safety assurance, prove
regulatory compliance, validate clinical use, show provider superiority, or
claim OpenTelemetry adoption.
