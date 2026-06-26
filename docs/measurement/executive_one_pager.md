# Executive One Pager

`agent-assure` is a reproducible assurance substrate for deterministic AI agent
governance pipelines. It treats expectations as the oracle, separates provenance
changes from behavioral verdicts, and keeps model and tool fixtures fixed.

The current implementation delivers the trust core: strict schemas, JSON Schema
parity, YAML suite compilation, canonical digests, redaction utilities, and an
OpenTelemetry-aligned span-plan preview. It does not make safety, compliance,
clinical validation, endorsement, or live model-quality claims.

Adoption path: start with fixture-mode authoring, add deterministic runner and
policies in future releases, then publish evidence packets only after the
flagship suite and documentation have been reviewed.
