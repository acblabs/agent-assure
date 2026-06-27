from __future__ import annotations

from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.telemetry import SpanAttribute, SpanEvent, SpanPlan
from agent_assure.telemetry.privacy_filter import safe_attribute
from agent_assure.telemetry.semconv_lock import SEMCONV_CHECKSUM, SEMCONV_COMMIT


def run_record_to_span_plan(record: AgentRunRecord) -> SpanPlan:
    attributes: dict[str, str | int | bool] = {
        "agent_assure.schema_version": record.schema_version,
        "agent_assure.operation.name": "fixture_evaluation",
        "agent_assure.run_id": record.run_id,
        "agent_assure.case_id": record.case_id,
        "agent_assure.pipeline_id": record.pipeline_id,
        "agent_assure.execution_mode": record.execution_mode.value,
        "agent_assure.recommendation": safe_attribute(record.recommendation),
        "agent_assure.outcome": safe_attribute(record.outcome),
        "agent_assure.input_summary": safe_attribute(record.input_summary),
        "agent_assure.output_summary": safe_attribute(record.output_summary),
        "agent_assure.human_review_required": record.human_review_required,
        "agent_assure.human_review_performed": record.human_review_performed,
    }
    if record.provider is not None:
        attributes["gen_ai.provider.name"] = safe_attribute(record.provider)
    if record.model is not None:
        attributes["gen_ai.request.model"] = safe_attribute(record.model)
    events = tuple(
        SpanEvent(
            name="agent_assure.tool_call",
            attributes=(_attribute("gen_ai.tool.name", safe_attribute(tool_name)),),
        )
        for tool_name in record.tools
    )
    return SpanPlan(
        span_name="agent_assure.run",
        attributes=tuple(_attribute(key, attributes[key]) for key in sorted(attributes)),
        events=events,
        semconv_commit=SEMCONV_COMMIT,
        semconv_checksum=SEMCONV_CHECKSUM,
    )


def _attribute(key: str, value: str | int | bool) -> SpanAttribute:
    return SpanAttribute(artifact_kind="span-attribute", key=key, value=value)
