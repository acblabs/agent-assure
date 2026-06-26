# Abstract

AI agent governance pipelines can regress in ways that are not visible through
raw answer comparison alone. This report proposes invariant-based change control
for deterministic governance-pipeline evaluation: hold fixtures fixed, resolve
labeled expectations, separate provenance changes from behavioral verdicts, and
produce reproducible artifacts for review. The current implementation provides
the supporting substrate: strict persisted schemas, JSON Schema parity,
lexeme-preserving YAML authoring, RFC 8785 digest projection, HMAC-sensitive correlation tokens,
privacy-filtered summaries, and an OpenTelemetry-aligned span-plan preview. The
work is deliberately scoped to deterministic fixture-mode assurance and does not
claim live model-quality evaluation, safety certification, regulatory
compliance, clinical validation, or standards adoption.
