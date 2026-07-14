from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.stream import StreamEventRecord, StreamRunRecord
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.usage import UsageLedger, UsageSegment, UsageSummary
from agent_assure.streaming.ingestion import validate_stream_run_integrity
from agent_assure.usage.aggregation import aggregate_usage_segments

_TRUTHY = {"1", "true", "yes", "required", "performed"}
_FALSEY = {"0", "false", "no", "none", "not_required", "bypass", "skipped"}


@dataclass
class _RunProjection:
    run_id: str
    case_id: str | None = None
    pipeline_id: str = "streaming-process"
    recommendation: str | None = None
    outcome: str | None = None
    provider: str | None = None
    model: str | None = None
    tools: list[str] = field(default_factory=list)
    evidence_sources: dict[str, str] = field(default_factory=dict)
    active_evidence_refs: set[str] = field(default_factory=set)
    active_links: dict[str, set[str]] = field(default_factory=dict)
    observed_claims: set[str] = field(default_factory=set)
    human_review_required: bool = False
    human_review_performed: bool = False
    retry_count: int = 0
    rate_limit_events: int = 0
    started_at_utc: str | None = None
    completed_at_utc: str | None = None
    traceparent: str | None = None
    usage_segments: list[UsageSegment] = field(default_factory=list)


def stream_run_to_runset(
    stream_run: StreamRunRecord,
    suite: CompiledSuite,
    *,
    source_path: Path | None = None,
) -> RunSet:
    validate_stream_run_integrity(stream_run)
    suite_digest = compiled_suite_digest(suite)
    fixture_digest = sha256_hexdigest(stream_run.model_dump(mode="json"))
    by_run = _events_by_run(stream_run)
    runs = tuple(
        _run_record_from_events(
            run_id,
            events,
            suite=suite,
            fixture_digest=fixture_digest,
            stream_run=stream_run,
        )
        for run_id, events in sorted(by_run.items())
    )
    all_segments: list[UsageSegment] = []
    for run in runs:
        if run.usage_ledger is not None:
            all_segments.extend(run.usage_ledger.segments)
    usage = aggregate_usage_segments(all_segments)
    runset_id = _runset_id(stream_run, suite, source_path=source_path)
    return RunSet(
        artifact_kind="run-set",
        runset_id=runset_id,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=suite_digest,
        fixture_manifest_digest=fixture_digest,
        execution_mode=ExecutionMode.fixture,
        usage_ledger=usage.usage_ledger,
        usage_summary=usage.usage_summary,
        runs=runs,
    )


def _events_by_run(stream_run: StreamRunRecord) -> dict[str, tuple[StreamEventRecord, ...]]:
    grouped: dict[str, list[StreamEventRecord]] = defaultdict(list)
    for event in stream_run.events:
        grouped[event.run_id].append(event)
    return {run_id: tuple(events) for run_id, events in grouped.items()}


def _run_record_from_events(
    run_id: str,
    events: tuple[StreamEventRecord, ...],
    *,
    suite: CompiledSuite,
    fixture_digest: str,
    stream_run: StreamRunRecord,
) -> AgentRunRecord:
    projection = _project_run(run_id, events)
    case_id = projection.case_id
    if case_id is None:
        raise ValueError(f"stream run {run_id!r} has no case_id")
    if projection.recommendation is None or projection.outcome is None:
        raise ValueError(
            f"stream run {run_id!r} must include final recommendation and outcome "
            "privacy_filtered_attributes"
        )
    material_claims = _suite_material_claims(suite, case_id)
    claim_ids = tuple(sorted(projection.observed_claims | set(material_claims)))
    evidence_refs = tuple(
        EvidenceRef(
            artifact_kind="evidence-ref",
            ref_id=ref_id,
            source_id=projection.evidence_sources.get(ref_id, ref_id),
            claim_ids=tuple(sorted(projection.active_links.get(ref_id, set()))),
        )
        for ref_id in sorted(projection.active_evidence_refs)
    )
    links = tuple(
        ClaimEvidenceLink(
            artifact_kind="claim-evidence-link",
            claim_id=claim_id,
            evidence_ref_id=ref_id,
        )
        for ref_id, claims in sorted(projection.active_links.items())
        for claim_id in sorted(claims)
    )
    usage_ledger, usage_summary = _usage_artifacts(tuple(projection.usage_segments))
    observation_digest = sha256_hexdigest([event.digest for event in events])[:16]
    observation_id = f"stream-observation-{observation_digest}"
    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id=run_id,
        case_id=case_id,
        execution_mode=ExecutionMode.fixture,
        pipeline_id=projection.pipeline_id,
        recommendation=projection.recommendation,
        outcome=projection.outcome,
        input_summary=f"stream case={case_id}; events={len(events)}",
        output_summary=(
            f"recommendation={projection.recommendation}; outcome={projection.outcome}; "
            f"stream_events={len(events)}"
        ),
        observation_id=observation_id,
        adapter_id="stream-jsonl",
        provider=projection.provider,
        model=projection.model,
        resolved_model=projection.model,
        traceparent=projection.traceparent,
        started_at_utc=projection.started_at_utc,
        completed_at_utc=projection.completed_at_utc,
        latency_ms=_latency_ms(projection.started_at_utc, projection.completed_at_utc),
        attempt_count=(
            projection.retry_count + 1
            if projection.retry_count or projection.provider is not None
            else None
        ),
        retry_count=projection.retry_count,
        rate_limit_events=projection.rate_limit_events,
        tools=tuple(dict.fromkeys(projection.tools)),
        evidence_refs=evidence_refs,
        claims=tuple(
            ClaimRecord(artifact_kind="claim-record", claim_id=claim_id)
            for claim_id in claim_ids
        ),
        claim_evidence_links=links,
        human_review_required=projection.human_review_required,
        human_review_performed=projection.human_review_performed,
        usage_ledger=usage_ledger,
        usage_summary=usage_summary,
        provenance=Provenance(
            artifact_kind="provenance",
            fixture_manifest_digest=fixture_digest,
            configuration_digest=sha256_hexdigest(
                {
                    "stream_id": stream_run.stream_id,
                    "sequence_contract": stream_run.sequence_contract.model_dump(mode="json"),
                }
            ),
            model_identifier=projection.model,
        ),
    )


def _project_run(run_id: str, events: tuple[StreamEventRecord, ...]) -> _RunProjection:
    projection = _RunProjection(run_id=run_id)
    for event in events:
        attrs = _attributes(event)
        if event.case_id is not None:
            if projection.case_id is not None and projection.case_id != event.case_id:
                raise ValueError(f"stream run {run_id!r} has conflicting case_id values")
            projection.case_id = event.case_id
        if "pipeline_id" in attrs:
            projection.pipeline_id = attrs["pipeline_id"]
        _update_provider_model(projection, event, attrs)
        _update_tool(projection, event, attrs)
        _update_evidence(projection, event, attrs)
        _update_review(projection, event, attrs)
        if event.event_type == "retry":
            projection.retry_count += 1
        if event.event_type == "rate_limit":
            projection.rate_limit_events += 1
        if event.event_type == "run_started":
            projection.started_at_utc = event.timestamp or projection.started_at_utc
        if event.event_type == "run_completed":
            projection.completed_at_utc = event.timestamp or projection.completed_at_utc
        if "recommendation" in attrs:
            projection.recommendation = attrs["recommendation"]
        if "outcome" in attrs:
            projection.outcome = attrs["outcome"]
        if event.traceparent is not None:
            projection.traceparent = event.traceparent
        if segment := _usage_segment_for_event(event):
            projection.usage_segments.append(segment)
    return projection


def _attributes(event: StreamEventRecord) -> dict[str, str]:
    attrs = dict(event.privacy_filtered_attributes)
    if event.observation is not None:
        attrs.update(event.observation.privacy_filtered_attributes)
    return attrs


def _update_provider_model(
    projection: _RunProjection,
    event: StreamEventRecord,
    attrs: dict[str, str],
) -> None:
    if event.observation is not None:
        projection.provider = event.observation.provider or projection.provider
        projection.model = event.observation.model or projection.model
    projection.provider = attrs.get("provider", projection.provider)
    projection.model = attrs.get("model", projection.model)


def _update_tool(
    projection: _RunProjection,
    event: StreamEventRecord,
    attrs: dict[str, str],
) -> None:
    tool_name = attrs.get("tool_name")
    if event.observation is not None and event.observation.tool_name is not None:
        tool_name = event.observation.tool_name
    if tool_name is not None and tool_name not in projection.tools:
        projection.tools.append(tool_name)


def _update_evidence(
    projection: _RunProjection,
    event: StreamEventRecord,
    attrs: dict[str, str],
) -> None:
    ref_ids = _evidence_ref_ids(event, attrs)
    claim_ids = _claim_ids(attrs)
    source_id = attrs.get("source_id")
    if event.event_type == "evidence_link_removed":
        if not ref_ids:
            raise ValueError("evidence_link_removed requires evidence_ref_id or evidence_ref_ids")
        _remove_evidence_links(projection, ref_ids=ref_ids, claim_ids=claim_ids)
        return
    if event.event_type != "evidence_link_added":
        return
    if not ref_ids:
        raise ValueError("evidence_link_added requires evidence_ref_id or evidence_ref_ids")
    for ref_id in ref_ids:
        projection.active_evidence_refs.add(ref_id)
        if source_id is not None:
            projection.evidence_sources[ref_id] = source_id
        else:
            projection.evidence_sources.setdefault(ref_id, ref_id)
        if claim_ids:
            projection.active_links.setdefault(ref_id, set()).update(claim_ids)
            projection.observed_claims.update(claim_ids)
        elif event.event_type == "evidence_link_added":
            projection.active_links.setdefault(ref_id, set())


def _remove_evidence_links(
    projection: _RunProjection,
    *,
    ref_ids: tuple[str, ...],
    claim_ids: tuple[str, ...],
) -> None:
    if not ref_ids:
        raise ValueError("evidence_link_removed requires evidence_ref_id or evidence_ref_ids")
    for ref_id in ref_ids:
        if ref_id not in projection.active_links:
            continue
        if not claim_ids:
            del projection.active_links[ref_id]
            projection.active_evidence_refs.discard(ref_id)
            continue
        projection.active_links[ref_id].difference_update(claim_ids)
        if not projection.active_links[ref_id]:
            del projection.active_links[ref_id]
            projection.active_evidence_refs.discard(ref_id)


def _update_review(
    projection: _RunProjection,
    event: StreamEventRecord,
    attrs: dict[str, str],
) -> None:
    route = attrs.get("review_route")
    if event.observation is not None and event.observation.review_route is not None:
        route = event.observation.review_route
    if event.event_type == "review_route_selected" and route is not None:
        if route.lower() in _FALSEY:
            projection.human_review_required = False
            projection.human_review_performed = False
            return
        projection.human_review_required = True
        if route.lower() in {"human_review", "manager_review", "clinical_review"}:
            projection.human_review_performed = True
    required = _bool_label(attrs.get("human_review_required"))
    if required is not None:
        projection.human_review_required = required
        if not required:
            projection.human_review_performed = False
    performed = _bool_label(attrs.get("human_review_performed"))
    if performed is None:
        return
    projection.human_review_performed = performed
    if performed:
        projection.human_review_performed = True
        projection.human_review_required = True


def _evidence_ref_ids(event: StreamEventRecord, attrs: dict[str, str]) -> tuple[str, ...]:
    refs = list(_split_compact_list(attrs.get("evidence_ref_id")))
    refs.extend(_split_compact_list(attrs.get("evidence_ref_ids")))
    if event.observation is not None:
        refs.extend(event.observation.evidence_refs)
    return tuple(dict.fromkeys(ref for ref in refs if ref))


def _claim_ids(attrs: dict[str, str]) -> tuple[str, ...]:
    claims = list(_split_compact_list(attrs.get("claim_id")))
    claims.extend(_split_compact_list(attrs.get("claim_ids")))
    return tuple(dict.fromkeys(claim for claim in claims if claim))


def _split_compact_list(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(part for part in value.split(",") if part)


def _bool_label(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSEY:
        return False
    return None


def _usage_segment_for_event(event: StreamEventRecord) -> UsageSegment | None:
    segment = event.usage_segment
    if segment is None and event.observation is not None:
        segment = event.observation.usage_segment
    if segment is None:
        return None
    payload: dict[str, Any] = segment.model_dump(mode="json")
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


def _usage_artifacts(
    segments: tuple[UsageSegment, ...],
) -> tuple[UsageLedger | None, UsageSummary | None]:
    if not segments:
        return None, None
    usage = aggregate_usage_segments(segments)
    return usage.usage_ledger, usage.usage_summary


def _suite_material_claims(suite: CompiledSuite, case_id: str) -> tuple[str, ...]:
    for expectation in suite.resolved_expectations:
        if expectation.case_id == case_id:
            return expectation.material_claim_ids
    return ()


def _runset_id(
    stream_run: StreamRunRecord,
    suite: CompiledSuite,
    *,
    source_path: Path | None,
) -> str:
    digest = sha256_hexdigest(
        {
            "stream_id": stream_run.stream_id,
            "suite_id": suite.suite_id,
            "suite_version": suite.suite_version,
            "source_path": source_path.as_posix() if source_path else None,
        }
    )
    return f"stream-runset-{digest[:16]}"


def _latency_ms(started: str | None, completed: str | None) -> int | None:
    if started is None or completed is None:
        return None
    start = _parse_timestamp(started)
    end = _parse_timestamp(completed)
    if start is None or end is None or end < start:
        return None
    return int((end - start).total_seconds() * 1000)


def _parse_timestamp(value: str) -> datetime | None:
    text = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _set_if_none(payload: dict[str, Any], key: str, value: object) -> None:
    if payload.get(key) is None and value is not None:
        payload[key] = value
