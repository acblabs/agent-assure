# Limitations

The current implementation evaluates deterministic local fixtures. It does not
evaluate live models, compare stochastic providers, estimate model-quality
rates, certify safety, prove regulatory compliance, or validate clinical
workflows.

Comparison reports require fixture equivalence before interpreting
baseline-to-candidate changes. If fixture material differs, the comparison is
invalid rather than a behavioral regression. Provenance differences are reported
for review and reproduction, but hashes and digest changes are not treated as
verdict-bearing shortcuts.

The result tables in the measurement and technical-report drafts are empirical
only in the fixture-bound sense: they count deterministic cases, findings, and
reason codes produced by reproducible repository artifacts. They do not provide
confidence intervals, latency distributions, cost distributions, or stochastic
performance claims.

In-process fixture runs capture ordinary Python exceptions; catastrophic process
termination remains outside the current runtime boundary.
