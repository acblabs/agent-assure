# Features

## Implemented

- Offline package and CLI skeleton.
- Strict immutable persisted schemas for suites, expectations, run records,
  evaluation summaries, comparisons, packets, and span plans.
- Deterministic JSON Schema export and runtime/JSON Schema parity tests.
- Safe YAML authoring loader that preserves semantic string lexemes.
- Suite lint and compile commands with resolved expectations.
- Canonical digest projection through a single JCS path.
- SHA-256 content digests and HMAC-SHA256 sensitive correlation tokens.
- Redacted summaries and safe errors for persisted and displayed artifacts.
- OpenTelemetry-aligned span-plan preview from structured run records.
- Documentation-alignment checks for conservative public claims.

## Planned

- Deterministic fixture runner, fixture manifests, evaluator, reports, evidence
  packets, CI gates, signed release evidence, and full example suites.
- Live stochastic evaluation, provider comparisons, confidence intervals, cost
  distributions, and OpenTelemetry SDK export in a future release.

## Explicitly unsupported in v0.1

- Safety certification.
- Regulatory compliance certification.
- Clinical validation.
- NIST endorsement.
- OpenTelemetry adoption or standards compliance.
- Live model-quality regression detection.
