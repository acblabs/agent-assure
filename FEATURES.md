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
  runners, suite/run digest binding, and in-process failure records.
- Prior-authorization synthetic example with shared fixtures, ten fixed cases,
  and baseline, evidence-normalization, provider-policy, fake-PHI redaction, and
  smoke variants.
- Minimal expense-approval example with independent fixtures, a passing
  baseline, and a deterministic provider-control candidate.
- Expectation-driven RunSet evaluator with built-in deterministic controls for
  runtime success, structured output fields, evidence coverage, explicit
  claim-evidence links, configured tool allowlists, provider review boundaries,
  human review routing, redaction checks, prompt-boundary cases, gate profiles, and
  per-finding time-bounded waivers.
- JSON, Markdown, and Rich console evaluation reports that lead with candidate
  vs expectations and keep unsupported capabilities marked `not_evaluated`.
- RunSet comparison reports with fixture-equivalence checks, candidate-first
  verdict explanations, baseline context, and provenance-only change reporting.
- Evidence packets that bundle evaluation and comparison summaries with
  interpretation guidance, environment metadata, deterministic input artifact
  digests, dependency-inventory digest, and release artifact manifest.
- Release digest replay with stable projections for environment-bearing review
  artifacts, manifest-listed digest cross-checks, release-bundle SBOM
  generation, hash-pinned release dependency installation, and keyless cosign
  workflow signing for exact packet, manifest, replay-file, SBOM, wheel, and
  source distribution verification by GitHub Actions workflow identity.
- CI gates for candidate RunSets, optional baseline comparisons, evaluation
  summaries, comparison summaries, and evidence packets with full/fail-fast
  report modes and stable pass, fail, and invalid-comparison exit codes.
- Reproducible flagship showcase commands that demonstrate a stable visible
  answer with a failing material evidence-link invariant under equivalent
  fixtures.
- Publishable measurement, executive, technical-report, standards, and
  reproducibility documents with traceability to deterministic fixture evidence
  and explicit limitation boundaries.
- Bundled example modules included for reproducible local demos, with public API
  boundaries documented separately.
- Socket-disabled pytest configuration for offline fixture-mode tests.
- OpenTelemetry-aligned span-plan preview from structured run records.
- Documentation-alignment checks for conservative public claims.

## Planned

- Live stochastic evaluation, provider comparisons, confidence intervals, cost
  distributions, and OpenTelemetry SDK export in a future release.

## Explicitly unsupported in v0.1

- Safety certification.
- Regulatory compliance certification.
- Clinical validation.
- NIST endorsement.
- OpenTelemetry adoption or standards compliance.
- Live model-quality regression detection.
