# OpenTelemetry Alignment

The current implementation produces an OpenTelemetry-aligned span-plan preview.
It does not emit runtime SDK spans and does not claim adoption by the
OpenTelemetry project.

Mapped attributes include:

- `gen_ai.operation.name`
- `gen_ai.system`
- `gen_ai.request.model`
- `agent_assure.run_id`
- `agent_assure.case_id`

The preview intentionally does not emit `gen_ai.response.tokens`. Generic tool
call events use `agent_assure.tool.name` and do not emit `rpc.method`.
