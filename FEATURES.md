# Features

## Implemented

- Offline package and CLI skeleton.
- Strict immutable persisted schemas for suites, expectations, run records,
  evaluation summaries, comparisons, packets, and span plans.
- Deterministic JSON Schema export and runtime/JSON Schema parity tests.
- Safe YAML authoring loader that preserves semantic string lexemes.
- Suite lint and compile commands with resolved expectations and fixture manifests.
- Canonical digest projection through a single JCS path.
- SHA-256 content digests and HMAC-SHA256 sensitive correlation tokens.
- Redacted summaries and safe errors for persisted and displayed artifacts.
- Deterministic offline fixture runner with fixed IDs, typed variant configs,
  safe multi-root fixture resolution, source/manifest verification, registered
  runners, and in-process failure records.
- Prior-authorization synthetic example with shared fixtures, ten fixed cases,
  and baseline, evidence-normalization, provider-policy, fake-PHI redaction, and
  smoke variants.
- Minimal expense-approval example with independent fixtures, a passing
  baseline, and a deterministic provider-control candidate.
- Bundled example modules included for reproducible local demos, with public API
  boundaries documented separately.
- Socket-disabled pytest configuration for offline fixture-mode tests.
- OpenTelemetry-aligned span-plan preview from structured run records.
- Documentation-alignment checks for conservative public claims.

## Planned

- Evaluator, reports, evidence packets, CI gates, and signed release evidence.
- Live stochastic evaluation, provider comparisons, confidence intervals, cost
  distributions, and OpenTelemetry SDK export in a future release.

## Explicitly unsupported in v0.1

- Safety certification.
- Regulatory compliance certification.
- Clinical validation.
- NIST endorsement.
- OpenTelemetry adoption or standards compliance.
- Live model-quality regression detection.
