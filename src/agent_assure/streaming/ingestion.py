from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    MAX_STATIC_JSONL_BYTES,
    MAX_STATIC_JSONL_LINE_BYTES,
    read_text_bounded,
)
from agent_assure.schema.stream import (
    StreamDuplicateSummary,
    StreamEventRecord,
    StreamIngestionDiagnostics,
    StreamRunRecord,
    StreamSequenceContract,
    StreamSequenceScope,
    parse_stream_timestamp_utc,
)
from agent_assure.schema.usage import UsageSegment, UsageSummary
from agent_assure.usage.aggregation import aggregate_usage_segments

_SequenceScopeInput = Literal["global", "producer_local", "producer-local"]
_ProducerFieldInput = Literal["producer_id", "node_id", "span_id"]
STREAM_DIGEST_OMITTED_FIELDS = frozenset(
    {
        "digest",
        "event_id",
        "artifact_kind",
        "schema_version",
    }
)
STREAM_DIGEST_DEFAULT_OMISSIONS = {"currency": "USD"}


@dataclass(frozen=True)
class StreamIngestionResult:
    stream_run: StreamRunRecord
    diagnostics: StreamIngestionDiagnostics


def ingest_jsonl_events(
    path: Path,
    *,
    sequence_scope: _SequenceScopeInput,
    producer_field: _ProducerFieldInput | None = None,
) -> StreamIngestionResult:
    contract = _sequence_contract(
        sequence_scope=sequence_scope,
        producer_field=producer_field,
    )
    events, duplicate_summaries, source_event_count = _deduplicated_events(path, contract)
    if not events:
        raise ValueError("stream JSONL contains no events")
    _validate_producer_local_timestamp_order(events, contract)
    ordered = tuple(sorted(events, key=lambda event: _event_sort_key(event, contract)))
    segments = tuple(_usage_segment_for_event(event) for event in ordered)
    usage = aggregate_usage_segments(segment for segment in segments if segment is not None)
    stream_id = _stream_id(ordered, contract)
    diagnostics = StreamIngestionDiagnostics(
        artifact_kind="stream-ingestion-diagnostics",
        stream_id=stream_id,
        sequence_contract=contract,
        source_event_count=source_event_count,
        accepted_event_count=len(ordered),
        duplicate_event_count=sum(summary.duplicate_count for summary in duplicate_summaries),
        run_ids=tuple(sorted({event.run_id for event in ordered})),
        diagnostics=_diagnostic_messages(contract, duplicate_summaries),
        duplicates=duplicate_summaries,
    )
    stream_run = StreamRunRecord(
        artifact_kind="stream-run",
        stream_id=stream_id,
        sequence_contract=contract,
        source_event_count=source_event_count,
        accepted_event_count=len(ordered),
        duplicate_event_count=diagnostics.duplicate_event_count,
        run_ids=tuple(sorted({event.run_id for event in ordered})),
        case_ids=tuple(sorted({event.case_id for event in ordered if event.case_id is not None})),
        events=ordered,
        usage_ledger=usage.usage_ledger,
        usage_summary=usage.usage_summary,
    )
    return StreamIngestionResult(stream_run=stream_run, diagnostics=diagnostics)


def validate_stream_run_integrity(stream_run: StreamRunRecord) -> None:
    """Re-check ingest-time guarantees on a persisted stream-run artifact."""

    expected_duplicate_count = stream_run.source_event_count - stream_run.accepted_event_count
    if expected_duplicate_count < 0:
        raise ValueError("stream run source_event_count must be >= accepted_event_count")
    if stream_run.duplicate_event_count != expected_duplicate_count:
        raise ValueError("stream run duplicate_event_count must match source minus accepted")
    by_key: dict[tuple[str, ...], StreamEventRecord] = {}
    for event in stream_run.events:
        key = _composite_key(event, stream_run.sequence_contract, line_number=None)
        if key in by_key:
            raise ValueError(
                "stream run contains duplicate composite key " + _format_key(key)
            )
        by_key[key] = event
        computed_digest = _payload_digest(event.model_dump(mode="json"))
        if event.digest != computed_digest:
            raise ValueError(
                f"stream event {event.event_id!r} digest does not match payload"
            )
    _validate_producer_local_timestamp_order(
        stream_run.events,
        stream_run.sequence_contract,
    )
    expected_order = tuple(
        sorted(
            stream_run.events,
            key=lambda event: _event_sort_key(event, stream_run.sequence_contract),
        )
    )
    if stream_run.events != expected_order:
        raise ValueError("stream run events must be in deterministic stream order")
    expected_stream_id = _stream_id(stream_run.events, stream_run.sequence_contract)
    if stream_run.stream_id != expected_stream_id:
        raise ValueError("stream run stream_id does not match events and sequence contract")


def incremental_usage_summaries(
    events: tuple[StreamEventRecord, ...],
) -> tuple[UsageSummary, ...]:
    segments: list[UsageSegment] = []
    summaries: list[UsageSummary] = []
    for event in events:
        segment = _usage_segment_for_event(event)
        if segment is not None:
            segments.append(segment)
        summaries.append(aggregate_usage_segments(segments).usage_summary)
    return tuple(summaries)


def _sequence_contract(
    *,
    sequence_scope: _SequenceScopeInput,
    producer_field: _ProducerFieldInput | None,
) -> StreamSequenceContract:
    normalized_scope: StreamSequenceScope
    if sequence_scope == "producer-local":
        normalized_scope = "producer_local"
    elif sequence_scope in {"global", "producer_local"}:
        normalized_scope = sequence_scope
    else:
        raise ValueError("sequence_scope must be global or producer_local")
    normalized_field = producer_field
    return StreamSequenceContract(
        scope=normalized_scope,
        producer_field=normalized_field,
    )


def _deduplicated_events(
    path: Path,
    contract: StreamSequenceContract,
) -> tuple[tuple[StreamEventRecord, ...], tuple[StreamDuplicateSummary, ...], int]:
    text = read_text_bounded(path, max_bytes=MAX_STATIC_JSONL_BYTES, label="stream JSONL")
    by_key: dict[tuple[str, ...], StreamEventRecord] = {}
    duplicate_event_ids: dict[tuple[str, ...], list[str]] = {}
    source_event_count = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > MAX_STATIC_JSONL_LINE_BYTES:
            raise ValueError(f"line {line_number}: stream JSONL event exceeds line limit")
        source_event_count += 1
        event = _event_from_line(line, line_number=line_number)
        key = _composite_key(event, contract, line_number=line_number)
        if key not in by_key:
            by_key[key] = event
            continue
        kept = by_key[key]
        if event.event_id != kept.event_id:
            raise ValueError(
                f"line {line_number}: duplicate stream composite key "
                f"{_format_key(key)} has conflicting event_id"
            )
        if event.digest != kept.digest:
            raise ValueError(
                f"line {line_number}: duplicate stream composite key "
                f"{_format_key(key)} has conflicting digest"
            )
        duplicate_event_ids.setdefault(key, []).append(event.event_id)
    duplicates = tuple(
        StreamDuplicateSummary(
            artifact_kind="stream-duplicate-summary",
            composite_key=key,
            kept_event_id=by_key[key].event_id,
            duplicate_event_ids=tuple(values),
            duplicate_count=len(values),
            digest=by_key[key].digest,
        )
        for key, values in sorted(duplicate_event_ids.items())
    )
    return tuple(by_key.values()), duplicates, source_event_count


def _event_from_line(line: str, *, line_number: int) -> StreamEventRecord:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"line {line_number}: invalid JSONL event") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"line {line_number}: stream event must be a JSON object")
    raw = {str(key): value for key, value in payload.items()}
    _require_event_fields(raw, line_number=line_number)
    computed_digest = _payload_digest(raw)
    declared_digest = raw.get("digest")
    if declared_digest is not None and declared_digest != computed_digest:
        raise ValueError(f"line {line_number}: stream event digest does not match payload")
    normalized = dict(raw)
    normalized.setdefault("artifact_kind", "stream-event-record")
    normalized["digest"] = computed_digest
    try:
        return StreamEventRecord.model_validate(normalized)
    except ValidationError as exc:
        raise ValueError(f"line {line_number}: invalid stream event: {exc}") from exc


def _require_event_fields(payload: dict[str, Any], *, line_number: int) -> None:
    if not payload.get("run_id"):
        raise ValueError(f"line {line_number}: stream event missing run_id")
    if "sequence_number" not in payload:
        raise ValueError(f"line {line_number}: stream event missing sequence_number")
    if not isinstance(payload["sequence_number"], int) or isinstance(
        payload["sequence_number"], bool
    ):
        raise ValueError(f"line {line_number}: stream event sequence_number must be an integer")
    if not payload.get("event_id"):
        raise ValueError(f"line {line_number}: stream event missing event_id")


def _payload_digest(payload: dict[str, Any]) -> str:
    return sha256_hexdigest(_digest_payload_projection(payload))


def _digest_payload_projection(value: object) -> object:
    if isinstance(value, dict):
        projected: dict[str, object] = {}
        for key, child in value.items():
            field_name = str(key)
            if field_name in STREAM_DIGEST_OMITTED_FIELDS:
                continue
            if child is None:
                continue
            if STREAM_DIGEST_DEFAULT_OMISSIONS.get(field_name) == child:
                continue
            projected_child = _digest_payload_projection(child)
            if projected_child in ({}, []):
                continue
            projected[field_name] = projected_child
        return projected
    if isinstance(value, list | tuple):
        return [
            _digest_payload_projection(item)
            for item in value
            if item is not None
        ]
    return value


def _composite_key(
    event: StreamEventRecord,
    contract: StreamSequenceContract,
    *,
    line_number: int | None,
) -> tuple[str, ...]:
    if contract.scope == "global":
        return (event.run_id, str(event.sequence_number))
    if contract.producer_field is None:
        raise ValueError("producer-local stream sequencing requires producer_field")
    producer_value = getattr(event, contract.producer_field)
    if producer_value is None:
        prefix = f"line {line_number}: " if line_number is not None else ""
        raise ValueError(
            f"{prefix}producer-local stream event missing "
            f"{contract.producer_field}"
        )
    return (event.run_id, contract.producer_field, producer_value, str(event.sequence_number))


def _event_sort_key(
    event: StreamEventRecord,
    contract: StreamSequenceContract,
) -> tuple[str | int, ...]:
    if contract.scope == "global":
        return (
            event.run_id,
            event.sequence_number,
            _timestamp_sort_value(event.timestamp, required=False, owner=event.event_id),
            event.digest,
        )
    if contract.producer_field is None:
        raise ValueError("producer-local stream sequencing requires producer_field")
    producer_value = getattr(event, contract.producer_field)
    if producer_value is None:
        raise ValueError(
            f"producer-local stream event {event.event_id!r} missing "
            f"{contract.producer_field}"
        )
    return (
        event.run_id,
        _timestamp_sort_value(event.timestamp, required=True, owner=event.event_id),
        producer_value,
        event.sequence_number,
        event.digest,
    )


def _validate_producer_local_timestamp_order(
    events: tuple[StreamEventRecord, ...],
    contract: StreamSequenceContract,
) -> None:
    if contract.scope != "producer_local":
        return
    if contract.producer_field is None:
        raise ValueError("producer-local stream sequencing requires producer_field")
    by_producer: dict[tuple[str, str], list[StreamEventRecord]] = {}
    for event in events:
        producer_value = getattr(event, contract.producer_field)
        if producer_value is None:
            raise ValueError(
                f"producer-local stream event {event.event_id!r} missing "
                f"{contract.producer_field}"
            )
        by_producer.setdefault((event.run_id, producer_value), []).append(event)
    for (run_id, producer_value), producer_events in by_producer.items():
        ordered = sorted(producer_events, key=lambda event: event.sequence_number)
        previous_timestamp: str | None = None
        previous_event_id: str | None = None
        for event in ordered:
            timestamp = _timestamp_sort_value(
                event.timestamp,
                required=True,
                owner=event.event_id,
            )
            if previous_timestamp is not None and timestamp < previous_timestamp:
                raise ValueError(
                    "producer-local stream timestamps must be monotonic within "
                    f"run {run_id!r} producer {producer_value!r}: event "
                    f"{event.event_id!r} sequence {event.sequence_number} is earlier "
                    f"than event {previous_event_id!r}"
                )
            previous_timestamp = timestamp
            previous_event_id = event.event_id


def _timestamp_sort_value(
    timestamp: str | None,
    *,
    required: bool,
    owner: str,
) -> str:
    if timestamp is None:
        if required:
            raise ValueError(
                f"producer-local stream event {owner!r} requires timestamp "
                "for cross-producer ordering"
            )
        return ""
    parsed = parse_stream_timestamp_utc(timestamp, owner=f"stream event {owner!r}")
    return parsed.isoformat(timespec="microseconds")


def _usage_segment_for_event(event: StreamEventRecord) -> UsageSegment | None:
    segment = event.usage_segment
    if segment is None and event.observation is not None:
        segment = event.observation.usage_segment
    if segment is None:
        return None
    payload = segment.model_dump(mode="json")
    _set_if_none(payload, "run_id", event.run_id)
    _set_if_none(payload, "case_id", event.case_id)
    _set_if_none(payload, "span_id", event.span_id)
    _set_if_none(payload, "parent_span_id", event.parent_span_id)
    _set_if_none(payload, "operation", event.event_type)
    _set_if_none(payload, "event_range_start", event.sequence_number)
    _set_if_none(payload, "event_range_end", event.sequence_number)
    if event.observation is not None:
        _set_if_none(payload, "provider", event.observation.provider)
        _set_if_none(payload, "model", event.observation.model)
    return UsageSegment.model_validate(payload)


def _stream_id(
    events: tuple[StreamEventRecord, ...],
    contract: StreamSequenceContract,
) -> str:
    digest = sha256_hexdigest(
        {
            "sequence_contract": contract.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in events],
        }
    )
    return f"stream-{digest[:16]}"


def _diagnostic_messages(
    contract: StreamSequenceContract,
    duplicates: tuple[StreamDuplicateSummary, ...],
) -> tuple[str, ...]:
    messages = [
        (
            "sequence contract: global run-level sequence numbers"
            if contract.scope == "global"
            else f"sequence contract: producer-local sequence numbers by {contract.producer_field}"
        ),
        (
            "deterministic order: run_id, sequence_number, timestamp, digest"
            if contract.scope == "global"
            else (
                "deterministic order: run_id, timestamp, producer, "
                "sequence_number, digest"
            )
        ),
    ]
    if duplicates:
        messages.append(f"deduplicated {sum(item.duplicate_count for item in duplicates)} events")
    return tuple(messages)


def _format_key(key: tuple[str, ...]) -> str:
    return "/".join(key)


def _set_if_none(payload: dict[str, Any], key: str, value: object) -> None:
    if payload.get(key) is None and value is not None:
        payload[key] = value
