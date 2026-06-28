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

Advanced endpoint tests cover rare-event Poisson upper bounds, one-sided
sidedness labeling, zero-event interpretation, observed cluster-correlation
summaries with uncertainty, Bonferroni rejection of unadjusted multiple
confirmatory endpoints, deterministic SHA-256-derived resampling seeds, and
exact paired-permutation null behavior. Low-cluster, mismatched-pairing,
unsupported-confidence, inconsistent-design-effect, and incompatible primary
endpoint cases fail closed or remain exploratory.

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
