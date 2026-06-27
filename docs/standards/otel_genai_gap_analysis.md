# OTel GenAI Gap Analysis

This analysis describes how the current `agent-assure` span-plan preview maps to
OpenTelemetry GenAI semantic-convention concepts. It is a compatibility and
freshness review, not an OpenTelemetry adoption, conformance, or acceptance
claim.

## Review Status

Freshness status: complete for the current v0.1 documentation set.

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

The local lock remains a v0.1 compatibility snapshot. The external
OpenTelemetry GenAI conventions are maintained outside this repository and may
change after this review. Recheck the sources above before opening an upstream
issue or making a stronger interoperability claim.

## Local Scope

The current implementation creates a span-plan preview from structured
`AgentRunRecord` data. It does not instantiate the OpenTelemetry SDK, export
OTLP data, propagate runtime context, or emit live spans. The preview exists so
reviewers can inspect what attributes would be derived from structured fields
without persisting an `otel_attributes` dictionary on run records.

The mapping is generated from structured fields and the local compatibility
matrix. Project-specific fields use the `agent_assure.*` namespace.

## Current Mapping Decisions

| Structured source | Emitted preview attribute | Decision |
| --- | --- | --- |
| fixed operation value | `gen_ai.operation.name` | Use the pinned GenAI operation attribute for the preview span. |
| `AgentRunRecord.provider` | `gen_ai.provider.name` | Emit only when the run record has a provider. |
| `AgentRunRecord.model` | `gen_ai.request.model` | Emit only when the run record has a model. |
| `AgentRunRecord.tools` | `gen_ai.tool.name` | Emit on local tool-call preview events. |
| `AgentRunRecord.run_id` | `agent_assure.run_id` | Keep project-local provenance under the project namespace. |
| `AgentRunRecord.case_id` | `agent_assure.case_id` | Keep fixture case identity project-local. |
| `AgentRunRecord.pipeline_id` | `agent_assure.pipeline_id` | Keep pipeline identity project-local. |
| `AgentRunRecord.execution_mode` | `agent_assure.execution_mode` | Keep fixture/live mode project-local. |

The preview deliberately does not emit:

- `gen_ai.response.tokens`, because the local mapping matrix does not include
  that attribute and the v0.1 fixture runner does not measure token usage;
- `rpc.method` for generic tool calls, because fixture-mode tool outputs are
  local artifacts rather than RPC invocations;
- raw prompts, raw outputs, tool arguments, sensitive identifiers, or
  unredacted summaries.

## Gap Assessment

No standards contribution is justified for v0.1 solely from the current
implementation. The project has evidence for deterministic fixture-mode
evaluation, local provenance, and review artifacts, but it does not yet produce
runtime OpenTelemetry spans. A standards change should not be proposed from a
preview-only implementation when project-local attributes are sufficient.

The only plausible future gap is representational guidance for offline
evaluation and release-evidence artifacts associated with agent runs. That gap
is not yet confirmed. Current upstream GenAI semantic conventions continue to
evolve, and the future v0.2 SDK/export work should be implemented first so any
discussion is backed by real span data rather than a preview.

## Contribution Readiness

Current readiness: defer upstream contribution.

The narrowest future contribution would be a discussion issue, not an attribute
proposal, asking whether existing GenAI semantic conventions intend to cover
offline deterministic evaluation artifacts such as fixture equivalence, evidence
packets, and evaluation summaries. If maintainers indicate that existing
conventions already cover the use case, no spec change should be pursued. If a
real gap remains after v0.2 SDK spans exist, the first contribution should be
non-normative examples or guidance before any new attribute is proposed.

## Traceability

Implementation evidence:

- mapping matrix: `compat/otel_mapping_matrix.yaml`;
- snapshot lock: `compat/otel_genai_semconv.lock`;
- mapping code: `src/agent_assure/telemetry/otel_mapping.py`;
- privacy filter: `src/agent_assure/telemetry/privacy_filter.py`;
- span-plan tests: `tests/unit/telemetry/test_span_plan.py`;
- CLI preview: `agent-assure otel preview`.

Public boundary:

- use "OpenTelemetry-aligned" for v0.1;
- do not claim OpenTelemetry adoption, conformance, or acceptance;
- do not invent vendor-neutral GenAI attributes in this repository;
- keep `agent_assure.*` fields project-local unless an upstream process later
  establishes a different recommendation.
