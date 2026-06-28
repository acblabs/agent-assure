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
- Statistical protocol for live stochastic evaluation, covering
  baseline handling modes, hypotheses, sample-size planning, confidence
  intervals, interim-look rules, retry/exclusion rules, provider-version
  capture, rate-limit handling, cost budgets, live-run ethics and safety
  limits, and machine-readable protocol records.
- Live protocol, live-evaluation, and live-comparison persisted schemas;
  explicit live provider adapters including a static JSONL adapter for offline
  tests, an external-script subprocess adapter, and an OpenAI-compatible
  chat-completions adapter requiring network opt-in; protocol-bound repeated
  live RunSets; cluster-aware
  expectation-pass, outcome, reason-code, and exclusion rates; pooled and
  cluster-mean rate reporting with explicit confidence-interval center
  metadata; design-effect and effective-sample-size reporting with
  largest-cluster sensitivity; paired cluster comparisons for concurrent
  baselines; fixed-reference comparisons for threshold protocols;
  optional advanced statistical endpoint plans with rare-event upper bounds,
  observed cluster-correlation summaries, Bonferroni endpoint multiplicity controls,
  and paired exact or Monte Carlo randomization tests with structural pairing
  checks and stable integer seeds; low-cluster exploratory
  guardrails; provider-version and tool/policy
  provenance checks;
  cross-window drift monitoring reports with comparability checks, ordered
  trend, adjacent-step, separate lag-1 autocorrelation and AR(1) dependence
  diagnostics, EWMA governance-health/control-reliability summaries, timestamp
  order checks, and method-specific minimum-window gates labeled as review
  signals by default;
  derived trajectory reports with privacy-filtered observable state paths,
  canonical transition profiles, explicit history-dependent checks, sequence invariants
  that separate governance-control findings from operational reliability
  warnings, and event-process summaries for retries, rate limits, exclusions,
  malformed outputs, runtime failures, emergency records, and budget stops;
  retry/rate-limit/token-pacing/budget enforcement fields; incomplete-run
  status; provider/model group summaries; and cost/latency distributions.
- Runtime isolation for configured external scripts through a no-shell
  subprocess harness with timeout handling, declared environment allowlists,
  redacted emergency process records, structured-output validation, and
  trace-context propagation through environment variables and request JSON.
- Bundled example modules included for reproducible local demos, with public API
  boundaries documented separately.
- Socket-disabled pytest configuration for offline fixture-mode tests.
- OpenTelemetry-aligned span-plan preview from structured run records, plus
  optional OpenTelemetry SDK span emission and OTLP HTTP export when
  `agent-assure[otel]` is installed.
- Documentation-alignment checks for conservative public claims.

## Planned

- Hardened external-runner extension APIs and broader live provider adapter
  ergonomics.

## Explicitly unsupported

- Safety certification.
- Regulatory compliance certification.
- Clinical validation.
- NIST endorsement.
- OpenTelemetry adoption or standards compliance.
- General live model-quality regression detection beyond declared,
  time-bound live protocol analyses.
