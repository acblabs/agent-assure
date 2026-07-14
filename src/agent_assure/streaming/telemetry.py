from __future__ import annotations

from collections import defaultdict

from agent_assure.schema.stream import StreamEventRecord, StreamRunRecord
from agent_assure.schema.telemetry import SpanAttribute, SpanEvent, SpanPlan
from agent_assure.telemetry.context import RuntimeTraceContext, trace_context_for_seed
from agent_assure.telemetry.privacy_filter import safe_attribute
from agent_assure.telemetry.semconv_lock import SEMCONV_CHECKSUM, SEMCONV_COMMIT


def stream_run_to_span_plans(stream_run: StreamRunRecord) -> tuple[SpanPlan, ...]:
    grouped: dict[str, list[StreamEventRecord]] = defaultdict(list)
    for event in stream_run.events:
        grouped[event.run_id].append(event)
    return tuple(
        _span_plan_for_run(stream_run, run_id, tuple(events))
        for run_id, events in sorted(grouped.items())
    )


def _span_plan_for_run(
    stream_run: StreamRunRecord,
    run_id: str,
    events: tuple[StreamEventRecord, ...],
) -> SpanPlan:
    attrs: dict[str, str | int | bool] = {
        "agent_assure.operation.name": "stream_ingestion",
        "agent_assure.schema_version": stream_run.schema_version,
        "agent_assure.stream.id": stream_run.stream_id,
        "agent_assure.stream.run_id": run_id,
        "agent_assure.stream.event_count": len(events),
        "agent_assure.stream.sequence_scope": stream_run.sequence_contract.scope,
        "agent_assure.stream.duplicate_event_count": stream_run.duplicate_event_count,
    }
    if stream_run.sequence_contract.producer_field is not None:
        attrs["agent_assure.stream.producer_field"] = stream_run.sequence_contract.producer_field
    trace_context = _trace_context(run_id, events)
    return SpanPlan(
        artifact_kind="span-plan",
        span_name="agent_assure.stream.run",
        traceparent=trace_context.traceparent,
        tracestate=trace_context.tracestate,
        attributes=tuple(_attribute(key, attrs[key]) for key in sorted(attrs)),
        events=tuple(_event_to_span_event(event) for event in events),
        semconv_commit=SEMCONV_COMMIT,
        semconv_checksum=SEMCONV_CHECKSUM,
    )


def _event_to_span_event(event: StreamEventRecord) -> SpanEvent:
    attrs: dict[str, str | int | bool] = {
        "agent_assure.stream.event_id": safe_attribute(event.event_id),
        "agent_assure.stream.event_type": safe_attribute(event.event_type),
        "agent_assure.stream.sequence_number": event.sequence_number,
        "agent_assure.stream.event_digest": event.digest,
    }
    _set_attr(attrs, "agent_assure.stream.case_id", event.case_id)
    _set_attr(attrs, "agent_assure.stream.producer_id", event.producer_id)
    _set_attr(attrs, "agent_assure.stream.node_id", event.node_id)
    _set_attr(attrs, "agent_assure.stream.span_id", event.span_id)
    _set_attr(attrs, "agent_assure.stream.parent_span_id", event.parent_span_id)
    _set_attr(attrs, "agent_assure.stream.timestamp", event.timestamp)
    segment = event.usage_segment
    if segment is None and event.observation is not None:
        segment = event.observation.usage_segment
    if segment is not None:
        _usage_attrs(attrs, segment)
    for key, value in sorted(event.privacy_filtered_attributes.items()):
        attrs[f"agent_assure.stream.attr.{key}"] = safe_attribute(value)
    return SpanEvent(
        artifact_kind="span-event",
        name=f"agent_assure.stream.{safe_attribute(event.event_type)}",
        attributes=tuple(_attribute(key, attrs[key]) for key in sorted(attrs)),
    )


def _usage_attrs(attrs: dict[str, str | int | bool], segment: object) -> None:
    for field_name, attr_name in (
        ("prompt_tokens", "agent_assure.usage.prompt_tokens"),
        ("completion_tokens", "agent_assure.usage.completion_tokens"),
        ("total_tokens", "agent_assure.usage.total_tokens"),
        ("tool_call_count", "agent_assure.usage.tool_call_count"),
        ("retry_count", "agent_assure.usage.retry_count"),
        ("latency_ms", "agent_assure.usage.latency_ms"),
        ("estimated_cost_microusd", "agent_assure.usage.estimated_cost_microusd"),
    ):
        value = getattr(segment, field_name)
        if value is not None:
            attrs[attr_name] = value


def _trace_context(
    run_id: str,
    events: tuple[StreamEventRecord, ...],
) -> RuntimeTraceContext:
    for event in events:
        if event.traceparent is not None:
            return RuntimeTraceContext(event.traceparent, None)
    return trace_context_for_seed(run_id)


def _set_attr(
    attrs: dict[str, str | int | bool],
    key: str,
    value: str | None,
) -> None:
    if value is not None:
        attrs[key] = safe_attribute(value)


def _attribute(key: str, value: str | int | bool) -> SpanAttribute:
    return SpanAttribute(artifact_kind="span-attribute", key=key, value=value)
