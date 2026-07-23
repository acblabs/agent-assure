# API Surface

The current public surface is intentionally narrow and status-qualified.
The stable released v0.5.0 surface consists of:

- the `agent-assure` CLI;
- package release v0.5.0, which uses the v0.5.0 frozen release schema snapshot
  under `schemas/v0.5.0`, with
  earlier release schema sets retained under `schemas/v0.1.0`,
  `schemas/v0.2.0`, `schemas/v0.3.0`, `schemas/v0.3.1`, and
  `schemas/v0.4.3`;
- importable schema models under `agent_assure.schema`;
- fixture-mode helpers used by the bundled examples.
- framework evidence mapping through `agent-assure controls map`.

The development package additionally exposes non-stable surfaces:

- experimental live-adapter configuration and reporting commands under
  `agent-assure live`;
- experimental runtime isolation and telemetry commands for external-script
  live adapters and OpenTelemetry export;
- experimental framework adapters under `agent_assure.adapters`, currently
  including LangGraph and Google ADK translators;
- experimental stream ingestion and stream evaluation commands under
  `agent-assure stream`;
- development-RFC single-operator assurance mutation through
  `agent-assure controls mutate`; and
- development-RFC `AssuranceEvidenceDescriptor/v1`,
  `AssuranceMutationOperator/v1`, `ExpectedDetectionContract/v1`, and
  `AssuranceMutationResult/v1` persisted contracts.

The `/v1` suffix identifies the proposed method-contract generation; it does
not make an RFC surface a stable compatibility commitment before release.

The wheel also includes `agent_assure.examples.*` modules so the offline example
suites remain reproducible after installation. These modules are bundled
demonstration subjects, not a stable extension API. Their runner identifiers are
registered for the repository's fixed examples and may change before a public
adapter API is introduced.

External projects should treat persisted artifacts and CLI behavior as the
primary integration points. Live adapter internals, external-script request
JSON, framework-adapter internals, and telemetry exporter helpers are useful
for development but are not yet a stable plugin API.

The mutation surface is deliberately closed over the built-in operator
registry. It is not a public executable-plugin API. Contract consumers should
use the persisted artifact kinds and documented CLI rather than importing
operator implementation internals.

External producers of `AgentRunRecord` artifacts should also treat
`agent-run-record-producer-contract/v1` as part of the integration surface. The
contract is documented in `docs/schema_evolution.md` and
`docs/expectation_authoring.md`; it requires explicit material
claim-evidence links that point to present evidence items.

The evidence-carrying release contracts and their compatibility boundaries are
documented in `docs/evidence_carrying_releases.md`.
