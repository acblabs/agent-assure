# API Surface

The current stable public surface is intentionally narrow:

- the `agent-assure` CLI;
- the v0.3.1 frozen release schema snapshot under `schemas/v0.3.1`, which
  remains the active persisted artifact schema for the v0.4.2 package release,
  with earlier release schema sets retained under `schemas/v0.1.0`,
  `schemas/v0.2.0`, and `schemas/v0.3.0`;
- importable schema models under `agent_assure.schema`;
- fixture-mode helpers used by the bundled examples.
- experimental live-adapter configuration and reporting commands under
  `agent-assure live`.
- experimental runtime isolation and telemetry commands for external-script
  live adapters and OpenTelemetry export.
- experimental framework adapters under `agent_assure.adapters`, currently
  including a LangGraph translator.

The wheel also includes `agent_assure.examples.*` modules so the offline example
suites remain reproducible after installation. These modules are bundled
demonstration subjects, not a stable extension API. Their runner identifiers are
registered for the repository's fixed examples and may change before a public
adapter API is introduced.

External projects should treat persisted artifacts and CLI behavior as the
primary integration points. Live adapter internals, external-script request
JSON, framework-adapter internals, and telemetry exporter helpers are useful
for development but are not yet a stable plugin API.

External producers of `AgentRunRecord` artifacts should also treat
`agent-run-record-producer-contract/v1` as part of the integration surface. The
contract is documented in `docs/schema_evolution.md` and
`docs/expectation_authoring.md`; it requires explicit material
claim-evidence links that point to present evidence references.
