# Architecture

`agent-assure` is an Agent Release Assurance Compiler for Evidence-Carrying
Agent Releases. It compiles declared controls and privacy-filtered observations
into versioned evidence artifacts for local review; it is not a telemetry
backend or hosted system of record.

The current implementation establishes the trust core:

- strict schemas in `src/agent_assure/schema`;
- YAML authoring and compilation in `src/agent_assure/authoring`;
- digest projection and RFC 8785 canonical bytes in `src/agent_assure/canonical`;
- fixture resolution, manifests, and deterministic local runs in
  `src/agent_assure/fixtures` and `src/agent_assure/runner`;
- privacy filters in `src/agent_assure/privacy`;
- expectation resolution, deterministic controls, gate profiles, and waivers in
  `src/agent_assure/evaluation` and `src/agent_assure/policies`;
- JSON, Markdown, and Rich console reports in `src/agent_assure/reporting`;
- live adapters, repeated RunSet execution, stochastic summaries, and live
  comparisons in `src/agent_assure/live`;
- subprocess isolation and emergency process records in
  `src/agent_assure/runner/subprocess_harness.py` and
  `src/agent_assure/schema/runtime.py`;
- OpenTelemetry-aligned span-plan preview, trace-context helpers, and optional
  SDK/OTLP export in `src/agent_assure/telemetry`;
- evidence packets, environment/dependency-inventory capture, release manifests, and CI gates
  in `src/agent_assure/reporting/packet.py`,
  `src/agent_assure/reporting/environment.py`, and `src/agent_assure/ci.py`.
- versioned assurance evidence descriptors, mutation-operator contracts,
  expected-detection contracts, and single-operator mutation results under the
  schema and control layers. These contracts reuse the canonical digest,
  bounded-input, evaluator, and privacy boundaries rather than introducing a
  parallel execution stack.

Bundled deterministic subjects live under `src/agent_assure/examples` so the
example suites can run from an installed wheel. They are reproducibility
fixtures, not the stable public extension API; see `docs/api_surface.md`.

Future releases can harden external-runner extension surfaces and expand
provider-specific live adapter ergonomics.

See `docs/evidence_carrying_releases.md` for the evidence and mutation contract
set and `docs/adr/0010-assurance-compiler-boundary.md` for the product boundary.
