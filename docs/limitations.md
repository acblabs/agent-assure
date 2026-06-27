# Limitations

The current implementation is deliberately bounded. It evaluates deterministic
local fixtures so that governance-pipeline changes can be reproduced and
reviewed without live provider drift, network access, token spend, or stochastic
sampling noise.

## Deliberate Scope

`agent-assure` v0.1 focuses on fixture-mode assurance for governance controls:
expectations, evidence links, provider/tool boundaries, redaction, escalation,
human review, runtime failures, fixture equivalence, provenance diffing, and
CI/report gates.

This scope does not evaluate live models, compare stochastic providers, estimate
model-quality rates, establish safety assurance, prove regulatory compliance,
validate clinical workflows, or provide production PHI de-identification.

A pre-live statistical protocol now exists for future stochastic work. It is a
planning and review boundary, not evidence that live evaluation has been
implemented.

## Measurement Boundary

The result tables in the measurement and technical-report documents are
empirical only in the fixture-bound sense. They count deterministic cases,
findings, and reason codes produced by reproducible repository artifacts. They
do not provide confidence intervals, latency distributions, cost distributions,
or stochastic performance claims.

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
records. Catastrophic process termination, external subprocess isolation, live
provider version drift, rate limits, production runtime isolation, and
distributed tracing are future scope.

## Release-Evidence Boundary

Digest replay checks reproducibility. Keyless cosign verification can verify
exact signed blob bytes and GitHub Actions workflow identity. Neither digest
replay nor signature verification establishes safety, legal or regulatory
status, clinical validity, live model quality, or standards acceptance.
