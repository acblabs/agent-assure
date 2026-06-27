# Live Mode Roadmap

`live` is recognized in schemas so future artifacts can evolve deliberately.
Commands that would imply live execution reject it in v0.1. Live stochastic
evaluation is planned only after a statistical protocol is committed.

The pre-live statistical protocol is documented in
`docs/measurement/experiment_protocol.md`. It covers hypotheses, sample-size
planning, confidence intervals, baseline handling modes, retry and exclusion
rules, provider-version capture, rate-limit handling, cost budgets, live-run
ethics and safety limits, and the need for a machine-readable protocol record
before live execution.

The next implementation phase still needs live provider adapters, repeated
RunSets, stochastic outcome-rate evaluation, provider/model comparisons,
cost/latency distributions, runtime isolation, and actual OpenTelemetry SDK
emission. Until those capabilities exist, live execution remains
command-rejected and unsupported by the current CLI.
