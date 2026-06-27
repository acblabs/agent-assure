# OpenTelemetry Alignment

The current implementation produces an OpenTelemetry-aligned span-plan preview.
It does not emit runtime SDK spans, export OTLP data, propagate runtime context,
or claim adoption by the OpenTelemetry project.

The preview is derived from structured `AgentRunRecord` fields. Run records do
not persist an `otel_attributes` dictionary.

Mapped preview attributes include:

- `gen_ai.provider.name`
- `gen_ai.request.model`
- `gen_ai.tool.name` on local tool-call preview events
- `agent_assure.operation.name`
- `agent_assure.run_id`
- `agent_assure.case_id`
- `agent_assure.pipeline_id`
- `agent_assure.execution_mode`

The preview intentionally does not emit `gen_ai.operation.name`,
`gen_ai.response.tokens`, or `rpc.method`. The local fixture evaluation
operation is project-specific and remains under the `agent_assure.*` namespace.

Project-specific provenance remains under the `agent_assure.*` namespace. The
current gap assessment and contribution stance are documented in
`docs/standards/otel_genai_gap_analysis.md`,
`docs/standards/otel_contribution_candidate.md`, and
`docs/standards/freshness_checklist.md`.
