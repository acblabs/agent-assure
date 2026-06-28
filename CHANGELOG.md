# Changelog

## Unreleased

- Added runtime isolation and OpenTelemetry export support for live execution:
  an `external-script` live adapter backed by a no-shell subprocess harness,
  redacted `emergency-process-record` artifacts for subprocess crashes,
  timeouts, nonzero exits, and invalid output, W3C trace-context propagation
  into live adapters and external scripts, trace-bearing span plans, and
  optional `agent-assure[otel]` SDK/OTLP export via `agent-assure otel export`.
- Added initial live evaluation support: strict live protocol/report schemas,
  explicit live provider adapters, protocol-bound repeated live RunSets,
  cluster-aware expectation-pass/outcome/reason-code/exclusion rates,
  pooled and cluster-mean rate reporting, design-effect and
  effective-sample-size reporting with largest-cluster sensitivity,
  protocol-declared paired-cluster t or bootstrap and fixed-reference live
  comparison reports with exploratory cluster-count guardrails, provider-version
  and tool/policy provenance checks, retry/rate-limit/token-pacing/budget
  metadata, incomplete-run status, cost/latency distributions, and
  `agent-assure live` CLI commands. The static JSONL adapter keeps the live
  path testable without sockets; the OpenAI-compatible adapter requires
  explicit network opt-in.
- Bumped persisted artifact and package version metadata to `0.2.0`, exported
  current JSON Schemas under `schemas/v0.2.0`, and retained the v0.1 release
  schema set for historical replay.
- Hardened live statistical reporting by sharing one t-critical/interval
  implementation across evaluation and comparison paths, labeling per-arm
  confidence-interval centers explicitly, avoiding spuriously exact zero-width
  boundary intervals, using the declared cluster bootstrap method for
  descriptive per-arm rates when applicable, and rejecting paired comparisons
  whose included cluster sets do not match.
- Hardened live response handling with a strict structured-output contract,
  malformed-output emergency records, post-response budget-stop records,
  estimated-cost source metadata, redacted live summaries before record
  construction, and explicit tests for malformed JSON, budget exhaustion,
  cluster-edge cases, paired-cluster mismatches, and subprocess environment
  isolation.
- Narrowed the external-script adapter environment boundary so scripts receive
  only declared allowlisted variables, explicit config overlays, and
  runner-injected trace/request variables rather than the full parent
  environment.
- Added and tightened a statistical protocol for live stochastic
  evaluation, covering baseline handling modes, hypotheses, reproducible
  sample-size planning, confidence intervals, interim-look rules, retry and
  exclusion rules, provider-version capture, rate-limit handling, cost budgets,
  live-run ethics and safety limits, and the machine-readable protocol
  record requirement.
- Documented `agent-run-record-producer-contract/v1` so external
  `AgentRunRecord` producers have a versioned contract for explicit material
  claim-evidence links.
- Hardened documentation-alignment checks so required Markdown sections ignore
  fenced-code headings, missing protocol sections are covered by tests, and
  conservative public-claim wording conventions are documented.
- Hardened release replay so release manifests cross-check recorded artifact
  digests against regenerated files, including manifest-listed SBOM and
  distribution bytes, instead of treating manifest `sha256` values as
  informational.
- Moved the fixture-evaluation operation name out of `gen_ai.operation.name`
  and into the project namespace; `gen_ai.operation.name` is now documented as
  intentionally not emitted.
- Tightened material-claim evidence evaluation so only explicit
  `ClaimEvidenceLink` records pointing to present evidence satisfy the
  invariant.
- Added hash-pinned release dependency installation via `requirements.lock`,
  plus documentation for the lean persisted schema and release replay boundary.
- Added an explicit distribution reproducibility check for the evidence
  reproduce job and documented the claim-evidence-link contract for external
  `AgentRunRecord` producers.

## 0.1.0 - 2026-06-27

- Finalized the v0.1.0 release bundle workflow with release tag validation,
  documentation alignment, test/schema gates, SBOM generation, Python source
  distribution and wheel assets, replay verification, keyless cosign signing,
  and GitHub release asset upload. Hardened bundle assembly to use one
  environment snapshot for the manifest and SBOM, normalized project package
  names in SBOM component filtering, and documented that manifest-listed SBOM
  and distribution bytes are cross-checked during replay while exact release
  blobs remain cosign-verifiable workflow-signed artifacts.
- Hardened release digest replay by separating replay source-commit/source-ref
  validation from current-checkout validation, centralizing role digest-mode
  policy, rejecting artifact paths that escape the replay root, and adding CI
  schema-export drift checks. Replay findings now report generic `expected` and
  `actual` values because findings may compare digests, commits, refs, or path
  state.
- Expanded public review artifacts: measurement use-case brief,
  executive one-pager, citable abstracts, technical report, reproducibility
  appendix, OpenTelemetry gap analysis, deferred contribution candidate,
  standards freshness checklist, and traceability coverage for those public
  claims.
- Added CI orchestration over candidate RunSets with optional baseline
  comparison, full/fail-fast report modes, structured diagnostics, evidence
  packet generation, Markdown packets, environment provenance, local dependency
  inventory generation, release artifact manifests, replay-stable release
  digest checks, and keyless cosign signing/verification workflow support for
  exact release evidence blobs.
- Hardened post-review contracts: RunSets now bind suite version/digest and
  fixture manifest digest, evidence records include explicit claim-evidence
  links, provider expectation failures emit `FORBIDDEN_PROVIDER`, comparison
  diffs use stable finding identity instead of message text, decimal digest
  projection uses fixed six-place strings, SafeError carries non-leaking debug
  metadata, runset writes redact summaries before persistence, and report/span
  output is privacy-filtered before display.
- Added the initial implementation: package skeleton, strict schemas, schema
  export, validator parity, YAML compilation, canonical digests, privacy
  utilities, HMAC tokens, and OpenTelemetry-aligned span-plan preview.
- Added fixture manifests, safe fixture path resolution, compiled-suite loading,
  golden drift checks, deterministic fixture runs, and the synthetic prior
  authorization example variants.
- Hardened fixture runs with typed variant configs, explicit case-to-expectation
  links, multi-root fixture validation, source digest checks, and catalog-based
  prior authorization evidence assembly.
- Reworked the prior authorization evidence regression to arise from duplicate
  source/content associations during catalog reconstruction, modeled provider
  selection as layered configuration precedence, added a fake-PHI redaction
  fixture case, and enabled socket-disabled pytest runs.
- Expanded the prior authorization evidence fixtures to cover nine ordinary
  one-source/one-claim cases plus the shared-source edge case, added a
  blind-review release-evidence rubric, and added a minimal expense-approval
  example with baseline and provider-control candidate variants.
- Moved bundled example subject logic under an explicit package examples
  namespace, merged duplicate evidence references before persistence, and
  removed unused split-case YAML placeholders.
- Kept bundled example modules installable for reproducibility while documenting
  that they are not a stable public extension API, and moved the intentionally
  lossy evidence assembly behavior out of shared framework evidence helpers.
- Added deterministic RunSet evaluation with expectation resolution, material
  evidence-link invariants, structured output and configured tool controls,
  provider review-boundary and human-review controls, gate profiles, disjoint
  case metrics, per-finding time-bounded waivers, not-evaluated capability
  reporting, and JSON/Markdown/Rich evaluation reports.
- Added RunSet comparison with fixture-equivalence gating, final comparison
  classifications, provenance-only diffing, candidate-first JSON/Markdown/Rich
  reports, and invalid-comparison exit behavior.
- Added a public flagship showcase with exact local commands, expected
  pass/fail output fields, baseline-to-candidate comparison story, GitHub
  Actions usage snippet, and reproducibility digest summary.
