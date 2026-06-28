# OTel GenAI Gap Analysis

This analysis describes how the current `agent-assure` span-plan preview and
optional SDK/OTLP export path map to OpenTelemetry GenAI semantic-convention
concepts. It is a compatibility and freshness review, not an OpenTelemetry
adoption, conformance, or acceptance claim.

## Review Status

Freshness status: complete for the current documentation set.

Reviewed on: 2026-06-27.

Reviewed sources:

- OpenTelemetry GenAI semantic conventions:
  https://opentelemetry.io/docs/specs/semconv/gen-ai/
- OpenTelemetry semantic-conventions-genai repository:
  https://github.com/open-telemetry/semantic-conventions-genai
- Local compatibility lock:
  `compat/otel_genai_semconv.lock`
- Local mapping matrix:
  `compat/otel_mapping_matrix.yaml`

The local lock remains a compatibility snapshot. The external
OpenTelemetry GenAI conventions are maintained outside this repository and may
change after this review. Recheck the sources above before opening an upstream
issue or making a stronger interoperability claim.

## Local Scope

The current implementation creates a span-plan preview from structured
`AgentRunRecord` data. When optional OpenTelemetry dependencies are installed,
the same span plans can be emitted through the OpenTelemetry SDK and OTLP HTTP
exporter. Live execution propagates W3C trace context into adapters and
external scripts. The preview exists so reviewers can inspect what attributes
are derived from structured fields without persisting an `otel_attributes`
dictionary on run records.

The mapping is generated from structured fields and the local compatibility
matrix. Project-specific fields use the `agent_assure.*` namespace.

## Current Mapping Decisions

| Structured source | Emitted preview attribute | Decision |
| --- | --- | --- |
| fixed local operation value | `agent_assure.operation.name` | Keep the fixture-evaluation operation project-local. |
| `AgentRunRecord.provider` | `gen_ai.provider.name` | Emit only when the run record has a provider. |
| `AgentRunRecord.model` | `gen_ai.request.model` | Emit only when the run record has a model. |
| `AgentRunRecord.tools` | `gen_ai.tool.name` | Emit on local tool-call preview events. |
| `AgentRunRecord.run_id` | `agent_assure.run_id` | Keep project-local provenance under the project namespace. |
| `AgentRunRecord.case_id` | `agent_assure.case_id` | Keep fixture case identity project-local. |
| `AgentRunRecord.pipeline_id` | `agent_assure.pipeline_id` | Keep pipeline identity project-local. |
| `AgentRunRecord.execution_mode` | `agent_assure.execution_mode` | Keep fixture/live mode project-local. |
| `AgentRunRecord.observation_id` | `agent_assure.observation_id` | Keep live observation identity project-local. |
| `AgentRunRecord.adapter_id` | `agent_assure.adapter_id` | Keep adapter identity project-local. |
| `AgentRunRecord.latency_ms` | `agent_assure.latency_ms` | Keep observed live latency project-local. |
| `AgentRunRecord.traceparent` | span parent context | Propagate W3C context without storing an OTel attribute bag. |

The preview deliberately does not emit:

- `gen_ai.response.tokens`, because the local mapping matrix does not include
  that attribute and the exporter keeps token accounting in project-local
  records and reports;
- `gen_ai.operation.name`, because the current implementation has no upstream
  GenAI operation value for its fixture and live assurance operations and does
  not put project-specific values in standard attributes;
- `rpc.method` for generic tool calls, because fixture-mode tool outputs are
  local artifacts rather than RPC invocations;
- raw prompts, raw outputs, tool arguments, sensitive identifiers, or
  unredacted summaries.

## Gap Assessment

No standards contribution is justified solely from the current implementation.
The project now has local SDK/OTLP export evidence in addition to deterministic
fixture-mode evaluation, live protocol artifacts, local provenance, and review
artifacts. However, project-local attributes are still sufficient for the
implemented behavior, and no specific upstream semantic-convention gap has been
confirmed.

The only plausible future gap is representational guidance for offline
evaluation and release-evidence artifacts associated with agent runs. That gap
is not yet confirmed. Current upstream GenAI semantic conventions continue to
evolve, and any upstream discussion should use exported span examples to ask
for guidance before proposing new attributes.

## Contribution Readiness

Current readiness: defer upstream contribution.

The narrowest future contribution would be a discussion issue, not an attribute
proposal, asking whether existing GenAI semantic conventions intend to cover
offline deterministic evaluation artifacts such as fixture equivalence, evidence
packets, and evaluation summaries. If maintainers indicate that existing
conventions already cover the use case, no spec change should be pursued. If a
real gap remains after exported span examples are reviewed, the first
contribution should be non-normative examples or guidance before any new
attribute is proposed.

## Traceability

Implementation evidence:

- mapping matrix: `compat/otel_mapping_matrix.yaml`;
- snapshot lock: `compat/otel_genai_semconv.lock`;
- mapping code: `src/agent_assure/telemetry/otel_mapping.py`;
- SDK exporter: `src/agent_assure/telemetry/otel_sdk.py`;
- trace context helpers: `src/agent_assure/telemetry/context.py`;
- privacy filter: `src/agent_assure/telemetry/privacy_filter.py`;
- span-plan and SDK tests: `tests/unit/telemetry/test_span_plan.py`,
  `tests/unit/telemetry/test_otel_sdk.py`;
- CLI preview/export: `agent-assure otel preview`, `agent-assure otel export`.

Public boundary:

- use "OpenTelemetry-aligned" for the current release surface;
- do not claim OpenTelemetry adoption, conformance, or acceptance;
- do not invent vendor-neutral GenAI attributes in this repository;
- keep `agent_assure.*` fields project-local unless an upstream process later
  establishes a different recommendation.
