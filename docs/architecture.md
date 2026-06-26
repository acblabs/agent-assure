# Architecture

The current implementation establishes the trust core:

- strict schemas in `src/agent_assure/schema`;
- YAML authoring and compilation in `src/agent_assure/authoring`;
- digest projection and RFC 8785 canonical bytes in `src/agent_assure/canonical`;
- fixture resolution, manifests, and deterministic local runs in
  `src/agent_assure/fixtures` and `src/agent_assure/runner`;
- privacy filters in `src/agent_assure/privacy`;
- OpenTelemetry-aligned span-plan preview in `src/agent_assure/telemetry`.

Bundled deterministic subjects live under `src/agent_assure/examples` so the
example suites can run from an installed wheel. They are reproducibility
fixtures, not the stable public extension API; see `docs/api_surface.md`.

Future releases add full evaluation, reporting, comparison, and release evidence
workflows.
