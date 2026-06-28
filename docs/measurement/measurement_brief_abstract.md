# Measurement Brief Abstract

Agentic AI systems increasingly depend on governance pipelines that assemble
evidence, enforce provider and tool policies, redact sensitive content, and
route uncertain cases for review. This brief frames a local measurement method
for those pipelines: hold model and tool fixtures fixed when determinism is
needed, freeze live protocols when stochastic behavior is measured, resolve
labeled expectations, evaluate candidates against explicit invariants and
controls, and treat baseline comparison as secondary context. The current
implementation demonstrates the method with reproducible fixture suites, strict
JSON schemas, lexeme-preserving YAML compilation, canonical digest projection,
privacy-filtered reports, CI gates, evidence packets, release replay artifacts,
OpenTelemetry-aligned span-plan previews, and protocol-bound live reports.
The live path includes cluster-aware rates, design-effect/effective-sample
metadata, rare-event Poisson upper bounds, observed intraclass-correlation
summaries, Bonferroni-controlled endpoint families, paired exact or Monte Carlo
randomization tests, trajectory-state summaries, drift signals, and operational
event-process review outputs. The flagship fixture result shows a candidate
that preserves the visible answer for a shared-source multi-claim case while
losing a fixture-declared material evidence link; the report fails the
candidate with `MATERIAL_CLAIM_MISSING_EVIDENCE` under equivalent fixtures. The
contribution is not a general live model-quality benchmark. It is a bounded
assurance pattern for governance-pipeline change review, where unsupported
capabilities remain `not_evaluated`, statistical claims remain protocol-bound,
and provenance digests are separated from behavioral verdicts. The result does
not establish safety assurance, validate clinical workflows, prove regulatory
compliance, or claim standards adoption.
