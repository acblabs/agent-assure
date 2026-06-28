# OpenTelemetry Alignment

The current implementation produces an OpenTelemetry-aligned span-plan preview.
It can also emit OpenTelemetry SDK spans and export OTLP HTTP data when the
optional `agent-assure[otel]` dependencies are installed. This remains an
implementation feature, not a claim of adoption by the OpenTelemetry project.

The implemented trace path is intentionally narrow and auditable:

- live runs create or accept W3C `traceparent` context;
- the static JSONL, external-script, and OpenAI-compatible adapters receive
  that context through their declared request surfaces;
- the OpenAI-compatible adapter forwards `traceparent` and `tracestate` on the
  standard-library `urllib.request` HTTP request when present;
- external scripts receive trace context in request JSON and runner-injected
  environment variables;
- persisted run records and span plans carry the filtered context needed to
  correlate artifacts without storing raw prompts, raw outputs, or an OTel
  attribute bag.

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
- `agent_assure.observation_id` for live observations
- `agent_assure.adapter_id` for live observations
- `agent_assure.latency_ms` for live observations

The preview intentionally does not emit `gen_ai.operation.name`,
`gen_ai.response.tokens`, or `rpc.method`. The local fixture evaluation
operation is project-specific and remains under the `agent_assure.*` namespace.

Span plans may include W3C `traceparent` context. Live execution propagates that
context to adapters and external scripts, and `agent-assure otel export` extracts
it as the parent context for emitted SDK spans. The exporter accepts an
`agent-run-record`, a `run-set`, or a precomputed `span-plan` artifact and emits
only privacy-filtered attributes and events derived from the span plan.

This is projection from persisted artifacts, not live instrumentation of the
adapter HTTP request or external subprocess lifecycle. Span timing and latency
attributes therefore reflect recorded run metadata rather than SDK spans opened
around provider calls or child processes.

For this reason, public documentation should describe the project as
OpenTelemetry-aligned, with optional SDK/OTLP export, rather than
OpenTelemetry adoption, conformance, or standards acceptance.

Project-specific provenance remains under the `agent_assure.*` namespace. The
current gap assessment and contribution stance are documented in
`docs/standards/otel_genai_gap_analysis.md`,
`docs/standards/otel_contribution_candidate.md`, and
`docs/standards/freshness_checklist.md`.
