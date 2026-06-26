# Executive One Pager

`agent-assure` is a reproducible assurance substrate for deterministic AI agent
governance pipelines. It treats expectations as the oracle, separates provenance
changes from behavioral verdicts, and keeps model and tool fixtures fixed.

The current implementation delivers strict schemas, JSON Schema parity, YAML
suite compilation, canonical digests, redaction utilities, deterministic fixture
runs, expectation evaluation, comparison reports, and an OpenTelemetry-aligned
span-plan preview. It does not make safety, compliance, clinical validation,
endorsement, or live model-quality claims.

Current deterministic result tables show passing baselines, an evidence-linking
regression isolated to the shared-source multi-claim case, provider-boundary
control failures, and a neutral expense-approval example. Provenance changes are
reported separately from verdicts.

The flagship showcase can be reproduced locally in about five minutes from the
README commands. It compares a passing baseline with an evidence-normalization
candidate under equivalent fixtures. The visible answer remains
`recommendation=approve; outcome=approve` for the affected case, while the
candidate loses the material `claim-duration` evidence link and receives
`MATERIAL_CLAIM_MISSING_EVIDENCE`.

Adoption path: start with fixture-mode authoring, add organization-specific
expectations and controls, use comparison reports for deterministic change
review, then publish evidence packets only after release artifacts have been
reviewed.
