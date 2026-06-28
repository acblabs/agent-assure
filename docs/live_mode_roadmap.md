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
  OpenAI-compatible chat-completions adapters; the OpenAI-compatible adapter
  uses Python's standard-library `urllib.request` HTTP client rather than an
  additional provider SDK dependency;
- an external-script adapter that invokes configured scripts through a no-shell
  subprocess harness with timeout handling and explicit environment allowlists
  and overlays;
- protocol-bound repeated live RunSets with observation, cluster, attempt,
  exclusion, incomplete-stop, budget, tool-schema, policy-bundle, and
  provider-version metadata;
- redacted `emergency-process-record` artifacts for subprocess spawn failures,
  timeouts, nonzero exits, and invalid structured output;
- W3C `traceparent` propagation into live adapters, HTTP requests, external
  script environment variables, external script request JSON, RunSet records,
  and derived span plans;
- cluster-aware expectation-pass, outcome, reason-code, and exclusion rates
  with pooled rate, cluster-mean rate, planned intraclass correlation,
  design-effect, effective-sample-size reporting, interval-center metadata,
  and largest-cluster sensitivity;
- optional advanced statistical endpoint plans bound into the live protocol
  digest, with confirmatory/exploratory endpoint labels, rare-event Poisson
  upper bounds, observed cluster-correlation summaries with uncertainty,
  Bonferroni multiplicity controls, and paired exact or Monte Carlo
  randomization tests with structural pairing checks and deterministic integer
  resampling seeds when exchangeability is predeclared;
- protocol-declared paired-cluster and fixed-reference live comparison reports
  with exploratory guardrails for low cluster counts;
- protocol-bound cross-window drift monitoring reports with suite/protocol,
  tool-schema, policy-bundle, baseline-mode, and analysis-method
  comparability checks; timestamp-order validation; ordered trend,
  adjacent-step, separate lag-1 autocorrelation and AR(1) dependence
  diagnostics, and EWMA governance-health or control-reliability summaries with
  method-specific minimum-window gates and exploratory review-signal labeling
  by default;
- derived live trajectory reports with privacy-filtered observable state paths,
  observable transition profiles, explicit history-dependent checks,
  sequence invariants that separate governance-control failures from
  operational reliability warnings, and event-process summaries for retries,
  rate limits, exclusions, malformed outputs, runtime failures, emergency
  records, and budget stops. The transition profiles are analogous to
  Markov-style observable state summaries, while the history-dependent checks
  represent non-Markov conditions such as required review before approval or
  complete claim-evidence history across retries;
- burst-window operational event-process screens for retry cascades,
  rate-limit storms, malformed outputs, runtime failures, and emergency
  records. These are exploratory reliability diagnostics; the current release
  does not fit or claim a Hawkes intensity model;
- latency and estimated-cost distributions;
- optional OpenTelemetry SDK span emission and OTLP HTTP export from
  privacy-filtered span plans when `agent-assure[otel]` is installed.

Remaining future work includes hardening the external-runner extension surface,
adding more provider-specific adapter ergonomics, and collecting enough exported
span evidence to reassess whether any upstream OpenTelemetry guidance gap
remains. Live reports remain time-bound operational evidence and are not safety,
compliance, clinical-validity, or general provider-quality evidence.
