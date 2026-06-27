# Measurement Brief Abstract

Agentic AI systems increasingly depend on governance pipelines that assemble
evidence, enforce provider and tool policies, redact sensitive content, and
route uncertain cases for review. This brief frames a deterministic measurement
method for those pipelines: hold model and tool fixtures fixed, resolve labeled
expectations, evaluate the candidate against explicit invariants and controls,
and treat baseline comparison as secondary context. The current implementation
demonstrates the method with reproducible fixture suites, strict JSON schemas,
lexeme-preserving YAML compilation, canonical digest projection, privacy-filtered
reports, CI gates, evidence packets, and OpenTelemetry-aligned span-plan
previews. The flagship result shows a candidate that preserves the visible
answer for a shared-source multi-claim case while losing a fixture-declared
material evidence link; the report fails the candidate with
`MATERIAL_CLAIM_MISSING_EVIDENCE` under equivalent fixtures. The contribution is
not a live model-quality benchmark. It is a bounded assurance pattern for
deterministic governance-pipeline change review, where unsupported capabilities
remain `not_evaluated` and provenance digests are separated from behavioral
verdicts. The fixture-mode result does not compare stochastic providers,
establish safety assurance, validate clinical workflows, prove regulatory
compliance, or claim standards adoption.
