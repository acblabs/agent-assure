# Live Mode Roadmap

`live` is recognized in schemas and now has an explicit command namespace for
adapter-based execution and stochastic reports. Fixture commands remain
deterministic and keep their original behavior; live execution is invoked only
through `agent-assure live ...` with a live run configuration and frozen
`live-protocol-record`.

The statistical protocol is documented in
`docs/measurement/experiment_protocol.md`. It covers hypotheses, sample-size
planning, confidence intervals, baseline handling modes, retry and exclusion
rules, provider-version capture, rate-limit handling, cost budgets, live-run
ethics and safety limits, and the machine-readable `live-protocol-record`
artifact used to bind live reports to a reviewed protocol.

Implemented live-mode pieces include:

- explicit provider adapters, including offline static JSONL and
  OpenAI-compatible chat-completions adapters;
- protocol-bound repeated live RunSets with observation, cluster, attempt,
  exclusion, incomplete-stop, budget, tool-schema, policy-bundle, and
  provider-version metadata;
- cluster-aware expectation-pass, outcome, reason-code, and exclusion rates
  with pooled rate, cluster-mean rate, design-effect, and
  effective-sample-size reporting, including largest-cluster sensitivity;
- protocol-declared paired-cluster and fixed-reference live comparison reports
  with exploratory guardrails for low cluster counts;
- latency and estimated-cost distributions.

Remaining future work includes external subprocess isolation, emergency
process records, actual OpenTelemetry SDK spans, runtime context propagation,
and OTLP export. Live reports remain time-bound operational evidence and are
not safety, compliance, clinical-validity, or general provider-quality
evidence.
