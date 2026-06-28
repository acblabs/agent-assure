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

This scope does not establish safety assurance, prove regulatory compliance,
validate clinical workflows, certify provider quality, or provide production
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
labeled as degenerate descriptive intervals.

Unsupported capabilities are reported as `not_evaluated`. They are not silently
treated as passing.

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
metadata for spawn failures, timeouts, nonzero exits, and invalid stdout.

This boundary is not a hardened sandbox against malicious local scripts. The
external-script adapter sends the full live request payload, including the
original prompt text, to the configured script. Script executable, argv, and
working-directory resolution happen in the calling process; compromise of the
configured script or its allowed environment can affect the host. Scripts do
not inherit the full parent environment by default, but any variable named in
`script_env_allowlist` or supplied through `script_env` is intentionally passed
through.

Optional OpenTelemetry export is a projection from persisted, privacy-filtered
span plans. It is useful for correlation, but it is not live SDK
instrumentation of adapter HTTP calls or external subprocess execution.
Catastrophic host termination, production workload isolation, and distributed
tracing beyond the local W3C context propagated by the live runner remain out
of scope.

## Release-Evidence Boundary

Digest replay checks reproducibility. Keyless cosign verification can verify
exact signed blob bytes and GitHub Actions workflow identity. Neither digest
replay nor signature verification establishes safety, legal or regulatory
status, clinical validity, live model quality, or standards acceptance.
