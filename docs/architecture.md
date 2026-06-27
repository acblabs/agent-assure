# Architecture

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
- OpenTelemetry-aligned span-plan preview in `src/agent_assure/telemetry`;
- evidence packets, environment/dependency-inventory capture, release manifests, and CI gates
  in `src/agent_assure/reporting/packet.py`,
  `src/agent_assure/reporting/environment.py`, and `src/agent_assure/ci.py`.

Bundled deterministic subjects live under `src/agent_assure/examples` so the
example suites can run from an installed wheel. They are reproducibility
fixtures, not the stable public extension API; see `docs/api_surface.md`.

Future releases add runtime isolation, SDK telemetry export, and hardened
external-runner extension surfaces.
