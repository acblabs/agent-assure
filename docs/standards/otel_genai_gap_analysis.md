# OTel GenAI Gap Analysis

The current implementation creates an OpenTelemetry-aligned span-plan preview
from structured run records. The project does not invent vendor-neutral GenAI
attributes beyond the pinned snapshot. Project-specific attributes use the
`agent_assure.*` namespace.

Known mapping decisions:

- include `gen_ai.operation.name`;
- include `gen_ai.system` when a provider is present;
- include `gen_ai.request.model` when a model is present;
- include `agent_assure.run_id` and related local provenance fields;
- do not emit `gen_ai.response.tokens`;
- do not emit `rpc.method` for generic tool calls.

Any upstream contribution candidate remains provisional until implementation
evidence exists and current OpenTelemetry discussions are reviewed.
