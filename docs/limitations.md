# Limitations

The current implementation is deliberately bounded. Its fixture path evaluates
deterministic local artifacts so governance-pipeline changes can be reproduced
and reviewed without live provider drift, network access, token spend, or
stochastic sampling noise. Its live path is explicit, protocol-bound,
cluster-aware, and reports repeated observations as time-bound operational
evidence.

## Deliberate Scope

The fixture path focuses on assurance for governance controls: expectations,
evidence links, provider/tool boundaries, redaction, escalation, human review,
runtime failures, fixture equivalence, provenance diffing, and CI/report gates.

`required_human_review` checks that a run preserved the declared route to human
review. The `human_review_performed` field is observational metadata unless a
live trajectory invariant or downstream policy explicitly gates on performed
review; setting it alone does not satisfy or fail the deterministic review-route
control.

This scope does not establish safety assurance, prove regulatory compliance,
validate clinical workflows, assess provider quality, or provide production
PHI de-identification.

Live stochastic work requires an explicit run configuration and a matching
machine-readable protocol record. Reports support declared pass-rate,
outcome-rate, reason-code, exclusion-rate, cost, and latency analyses with
cluster/effective-sample metadata, completion status, stop reasons, and
tool-schema/policy-bundle provenance checks; they are not general model-quality
claims.

## Measurement Boundary

The result tables in the measurement and technical-report documents are
empirical only in the fixture-bound sense. They count deterministic cases,
findings, and reason codes produced by reproducible repository artifacts. They
do not provide confidence intervals, latency distributions, cost distributions,
or stochastic performance claims. Live reports do provide confidence intervals
and operational distributions, but only for their declared live observation
window. Per-arm live rates report both pooled observation rates and cluster
mean rates because unequal cluster sizes can make the confidence-interval
center differ from the pooled point estimate. Reports label the interval center
explicitly. Low-cluster analyses are marked exploratory by protocol guardrails,
and boundary rates near 0 or 1 should be read with the small-sample caveats in
the live protocol. Design-effect and effective-sample-size fields are planning
and sensitivity metadata; the reported cluster intervals are computed from
empirical cluster-rate values, not from `effective_n`. Paired-difference
intervals with zero between-cluster variance can collapse to zero width and are
labeled as degenerate descriptive intervals. Per-arm rates with identical
cluster values use a labeled degenerate-boundary heuristic; that heuristic is a
conservative display aid, not an ordinary t interval or an observation-level
Wilson analysis.

Advanced live endpoint plans add rare-event upper bounds, observed
cluster-correlation summaries, and paired randomization tests only when those
analyses are declared in the frozen protocol. Zero observed critical events are
reported with a one-sided upper confidence bound rather than as proof that the
event cannot occur. Rare-event bound artifacts expose `interval_sidedness` so
reviewers do not read them as the two-sided intervals used for live rate
summaries. Observed intraclass correlation is descriptive unless the
protocol predeclares a large-cluster threshold or external statistical-review
allowance; low-cluster observed ICC estimates do not narrow confirmatory
interpretation below the planned-ICC analysis. Paired randomization tests check
that included clusters and included case/repetition sets match, but the
exchangeability assumption remains a reviewed design assumption rather than a
property the tool can prove.

Cross-window live drift reports are monitoring artifacts. They compare ordered
live evaluation windows only after a comparability check over suite identity,
baseline mode, analysis method, protocol digest, tool-schema digest, and
policy-bundle digest, and they reject nonmonotonic timestamp order when window
timestamps are available. Trend and adjacent-step diagnostics are separate from
serial-dependence diagnostics such as lag-1 autocorrelation and AR(1).
Autocorrelation, AR(1), and EWMA state summaries are suppressed until their
declared ordered-window thresholds are met; dependence and AR(1) summaries
require at least eight ordered windows, and EWMA state summaries require at
least six. All of these outputs are exploratory by default and are review
signals, not release verdicts. The default autocorrelation and AR(1) review
thresholds are governance heuristics rather than calibrated null false-positive
rates. EWMA state labels such as governance health, control reliability, and drift state refer
only to observable governance records; they are not claims about model intent,
reasoning, consciousness, or hidden mental state.

Live trajectory reports are also review artifacts. They derive observable path
summaries from structured run, evaluation, and emergency-process records, then
report canonical state-transition profiles, sequence invariants, history-dependent
checks, and operational event-process summaries. They do not persist raw
prompts, raw outputs, tool arguments, sensitive identifiers, raw stdout/stderr,
or unredacted summaries. A trajectory invariant can identify a governance
control review finding, and an event-process burst can identify an operational
reliability warning, but the report itself uses `not_evaluated` gate state and
does not replace expectation, policy, invariant, or configured comparison
gates. Low observation counts, low event counts, missing timestamps, missing
ordering metadata, or weak transition support make trajectory and event-process
outputs exploratory or invalid. Observed path coverage is sampled evidence over
the declared run, not proof that unsafe paths are impossible.

Statistical, state-space, and event-process language in this repository refers
to bounded analyses over observable artifacts. Markov-style transition
summaries describe adjacent structured states; history-dependent checks cover
non-Markov sequence conditions; burst-window event-process screens identify
operational reliability review signals. The current implementation does not fit
a Hawkes intensity model, infer hidden model state, or make literal physics
path-integral claims.

Unsupported capabilities are reported as `not_evaluated`. They are not silently
treated as passing.

Framework adapters are experimental trusted translators. The LangGraph adapter
reads allowlisted `agent_assure` metadata from framework events and deliberately
ignores raw event `input`, `output`, message, completion, and tool-argument
payloads. It rejects raw-payload key names and free-text privacy attribute
values, and applies the same compact-token rule to adapter-controlled
top-level labels and usage labels such as `review_route`, `operation`, and
`cost_basis`. It does not semantically prove that a compact producer-supplied
label is fully scrubbed. The current projection helper emits fixture-mode
review artifacts only; protocol-bound live evidence must still use the live
runner. Framework adapter output can show whether declared process evidence
survived a framework run, but it does not attest LangGraph application code,
hidden model behavior, or production trace completeness.

## Comparison Boundary

Comparison reports require fixture equivalence before interpreting
baseline-to-candidate changes. If fixture material differs, the comparison is
invalid rather than a behavioral regression.

Provenance differences are reported for review and reproduction. Hashes and
digest changes are not verdict-bearing shortcuts.

## Runtime Boundary

In-process fixture runs capture ordinary Python exceptions and produce failure
records. Live adapters capture accepted provider metadata when available and
record retry/rate-limit/exclusion counters. Configured external scripts run
through a no-shell subprocess harness that records redacted emergency process
metadata for spawn failures, timeouts, nonzero exits, invalid stdout, and
oversized output.

This boundary is not a hardened sandbox against malicious local scripts. The
external-script adapter sends the full live request payload, including the
original prompt text, to the configured script. Script executable, argv, and
working-directory resolution happen in the calling process; compromise of the
configured script or its allowed environment can affect the host. Scripts do
not inherit the full parent environment by default, but any variable named in
`script_env_allowlist` or supplied through `script_env` is intentionally passed
through. Prompt, JSONL response, script, and script working-directory paths are
confined to the live config directory; this prevents accidental path escape but
does not make the script itself trustworthy. Non-interactive live execution
must pass `--trust-config` plus the specific risk flags for external-script
execution, network egress, or host environment propagation; these flags are an
operator acknowledgement, not isolation.

Live adapters are trusted record producers. A static JSONL file, external
script, or network provider controls the structured observation it returns,
including recommendations, outcomes, evidence links, claims, tool names, review
flags, and summaries. Live producer-supplied failing policy results are
verdict-bearing, but agent-assure does not attest adapter code or provider
responses. The OpenAI-compatible adapter requires HTTPS and an allowlisted
endpoint host; non-default gateways must be listed explicitly. CI live network
runs fail closed when endpoint DNS safety screening cannot resolve the host,
and OpenAI-compatible requests repeat DNS screening immediately before
dispatch. This reduces but does not eliminate DNS rebinding risk because the
HTTP stack is not pinned to a screened address.

Optional OpenTelemetry export is a projection from persisted, privacy-filtered
span plans. OTLP HTTP export requires an explicit HTTPS endpoint and an explicit
allowed endpoint host; ambient SDK endpoint defaults are not used, and DNS
safety screening fails closed by default. It is useful for correlation, but it
is not live SDK instrumentation of adapter HTTP calls or external subprocess
execution.
Catastrophic host termination, production workload isolation, and distributed
tracing beyond the local W3C context propagated by the live runner remain out
of scope.

## Release-Evidence Boundary

Digest replay checks reproducibility. Keyless cosign verification can verify
exact signed blob bytes and GitHub Actions workflow identity. Neither digest
replay nor signature verification establishes safety, legal or regulatory
status, clinical validity, live model quality, or standards acceptance.
