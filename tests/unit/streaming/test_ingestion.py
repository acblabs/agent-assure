from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_assure.evaluation.evaluator import evaluate_runset
from agent_assure.reporting.evidence_diff_html import render_evidence_diff_html
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.suite import CompiledSuite
from agent_assure.streaming.ingestion import (
    incremental_usage_summaries,
    ingest_jsonl_events,
)
from agent_assure.streaming.projection import stream_run_to_runset
from agent_assure.streaming.telemetry import stream_run_to_span_plans

_DIGEST = "c" * 64


def test_stream_ingest_sorts_out_of_order_global_events(tmp_path: Path) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event("evt-2", sequence_number=2, event_type="run_completed"),
            _event("evt-1", sequence_number=1, event_type="run_started"),
        ],
    )

    result = ingest_jsonl_events(path, sequence_scope="global")

    assert [event.sequence_number for event in result.stream_run.events] == [1, 2]
    assert result.stream_run.sequence_contract.scope == "global"
    assert "global run-level sequence" in result.diagnostics.diagnostics[0]


def test_stream_ingest_requires_explicit_producer_field_for_local_sequences(
    tmp_path: Path,
) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event("evt-a", sequence_number=1, event_type="node_completed", producer_id="a"),
            _event("evt-b", sequence_number=1, event_type="node_completed", producer_id="b"),
        ],
    )

    result = ingest_jsonl_events(
        path,
        sequence_scope="producer_local",
        producer_field="producer_id",
    )

    assert {event.event_id for event in result.stream_run.events} == {"evt-a", "evt-b"}
    assert [event.sequence_number for event in result.stream_run.events] == [1, 1]
    assert result.stream_run.sequence_contract.producer_field == "producer_id"


def test_stream_ingest_orders_producer_local_events_by_timestamp(
    tmp_path: Path,
) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event(
                "producer-a-2",
                sequence_number=2,
                event_type="node_completed",
                producer_id="a",
                timestamp="2026-07-14T00:00:02Z",
            ),
            _event(
                "producer-b-1",
                sequence_number=1,
                event_type="node_completed",
                producer_id="b",
                timestamp="2026-07-14T00:00:03Z",
            ),
            _event(
                "producer-a-1",
                sequence_number=1,
                event_type="node_started",
                producer_id="a",
                timestamp="2026-07-14T00:00:01Z",
            ),
        ],
    )

    result = ingest_jsonl_events(
        path,
        sequence_scope="producer_local",
        producer_field="producer_id",
    )

    assert [event.event_id for event in result.stream_run.events] == [
        "producer-a-1",
        "producer-a-2",
        "producer-b-1",
    ]
    assert "timestamp, producer" in result.diagnostics.diagnostics[1]


def test_stream_ingest_rejects_producer_local_events_without_timestamp(
    tmp_path: Path,
) -> None:
    event = _event(
        "producer-a-1",
        sequence_number=1,
        event_type="node_started",
        producer_id="a",
    )
    event.pop("timestamp")
    path = _jsonl(tmp_path, [event])

    with pytest.raises(ValueError, match="requires timestamp"):
        ingest_jsonl_events(
            path,
            sequence_scope="producer_local",
            producer_field="producer_id",
        )


def test_stream_ingest_rejects_producer_local_event_missing_producer_field(
    tmp_path: Path,
) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event(
                "producer-missing-1",
                sequence_number=1,
                event_type="node_started",
                timestamp="2026-07-14T00:00:01Z",
            ),
        ],
    )

    with pytest.raises(ValueError, match="missing producer_id"):
        ingest_jsonl_events(
            path,
            sequence_scope="producer_local",
            producer_field="producer_id",
        )


def test_stream_ingest_deduplicates_identical_composite_key(tmp_path: Path) -> None:
    event = _event("evt-1", sequence_number=1, event_type="run_started")
    path = _jsonl(tmp_path, [event, event])

    result = ingest_jsonl_events(path, sequence_scope="global")

    assert result.stream_run.accepted_event_count == 1
    assert result.stream_run.duplicate_event_count == 1
    assert result.diagnostics.duplicates[0].kept_event_id == "evt-1"


def test_stream_ingest_rejects_conflicting_duplicate_event_id(tmp_path: Path) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event("evt-1", sequence_number=1, event_type="run_started"),
            _event("evt-2", sequence_number=1, event_type="run_started"),
        ],
    )

    with pytest.raises(ValueError, match="conflicting event_id"):
        ingest_jsonl_events(path, sequence_scope="global")


def test_stream_ingest_rejects_conflicting_duplicate_digest(tmp_path: Path) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event("evt-1", sequence_number=1, event_type="run_started"),
            _event(
                "evt-1",
                sequence_number=1,
                event_type="run_started",
                attrs={"pipeline_id": "changed"},
            ),
        ],
    )

    with pytest.raises(ValueError, match="conflicting digest"):
        ingest_jsonl_events(path, sequence_scope="global")


def test_stream_ingest_rejects_producer_local_conflicting_duplicate_digest(
    tmp_path: Path,
) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event(
                "evt-1",
                sequence_number=1,
                event_type="node_started",
                producer_id="node-a",
            ),
            _event(
                "evt-1",
                sequence_number=1,
                event_type="node_started",
                producer_id="node-a",
                attrs={"pipeline_id": "changed"},
            ),
        ],
    )

    with pytest.raises(ValueError, match="conflicting digest"):
        ingest_jsonl_events(
            path,
            sequence_scope="producer_local",
            producer_field="producer_id",
        )


def test_stream_ingest_missing_required_fields_fail_clearly(tmp_path: Path) -> None:
    missing_run = _event("evt-1", sequence_number=1, event_type="run_started")
    missing_run.pop("run_id")
    path = _jsonl(tmp_path, [missing_run])

    with pytest.raises(ValueError, match="missing run_id"):
        ingest_jsonl_events(path, sequence_scope="global")

    missing_sequence = _event("evt-2", sequence_number=2, event_type="run_started")
    missing_sequence.pop("sequence_number")
    path = _jsonl(tmp_path, [missing_sequence])

    with pytest.raises(ValueError, match="missing sequence_number"):
        ingest_jsonl_events(path, sequence_scope="global")


def test_stream_usage_aggregation_is_incremental(tmp_path: Path) -> None:
    path = _jsonl(
        tmp_path,
        [
            _event(
                "evt-1",
                sequence_number=1,
                event_type="token_chunk_observed",
                usage={"segment_id": "seg-1", "total_tokens": 5},
            ),
            _event(
                "evt-2",
                sequence_number=2,
                event_type="tool_call_completed",
                usage={"segment_id": "seg-2", "tool_call_count": 1},
            ),
        ],
    )

    stream_run = ingest_jsonl_events(path, sequence_scope="global").stream_run
    summaries = incremental_usage_summaries(stream_run.events)

    assert summaries[0].total_tokens == 5
    assert summaries[1].total_tokens == 5
    assert summaries[1].total_tool_calls == 1
    assert stream_run.usage_summary is not None
    assert stream_run.usage_summary.total_tokens == 5


def test_stream_projection_uses_timestamp_merge_order_for_producer_local_state(
    tmp_path: Path,
) -> None:
    suite = _suite()
    stream_run = ingest_jsonl_events(
        _jsonl(
            tmp_path,
            [
                _event(
                    "reviewer-remove-before-local-seq-add",
                    sequence_number=1,
                    event_type="evidence_link_removed",
                    producer_id="reviewer",
                    timestamp="2026-07-14T00:00:03Z",
                    attrs={"evidence_ref_id": "ref-stream", "claim_id": "claim-stream"},
                ),
                _event(
                    "retriever-add-after-local-seq-remove",
                    sequence_number=2,
                    event_type="evidence_link_added",
                    producer_id="retriever",
                    timestamp="2026-07-14T00:00:02Z",
                    attrs={
                        "evidence_ref_id": "ref-stream",
                        "claim_id": "claim-stream",
                        "content_digest": "a" * 64,
                    },
                ),
                _event(
                    "coordinator-start",
                    sequence_number=1,
                    event_type="run_started",
                    producer_id="coordinator",
                    timestamp="2026-07-14T00:00:01Z",
                ),
                _event(
                    "coordinator-complete",
                    sequence_number=2,
                    event_type="run_completed",
                    producer_id="coordinator",
                    timestamp="2026-07-14T00:00:04Z",
                    attrs={"recommendation": "approve", "outcome": "approved"},
                ),
            ],
        ),
        sequence_scope="producer_local",
        producer_field="producer_id",
    ).stream_run

    assert [event.event_id for event in stream_run.events] == [
        "coordinator-start",
        "retriever-add-after-local-seq-remove",
        "reviewer-remove-before-local-seq-add",
        "coordinator-complete",
    ]
    runset = stream_run_to_runset(stream_run, suite)
    report = evaluate_runset(suite, runset)

    assert not runset.runs[0].claim_evidence_links
    assert {
        finding.reason_code for finding in report.candidate_vs_expectations.findings
    } >= {
        ReasonCode.REQUIRED_SOURCE_MISSING,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
    }


def test_stream_projection_catches_select_then_bypass_review_regression(
    tmp_path: Path,
) -> None:
    suite = _review_suite()
    candidate = ingest_jsonl_events(
        _jsonl(
            tmp_path,
            [
                _event("evt-1", sequence_number=1, event_type="run_started"),
                _event(
                    "evt-2",
                    sequence_number=2,
                    event_type="evidence_link_added",
                    attrs={
                        "evidence_ref_id": "ref-stream",
                        "claim_id": "claim-stream",
                        "content_digest": "a" * 64,
                    },
                ),
                _event(
                    "evt-3",
                    sequence_number=3,
                    event_type="review_route_selected",
                    attrs={"review_route": "manager_review"},
                ),
                _event(
                    "evt-4",
                    sequence_number=4,
                    event_type="review_route_selected",
                    attrs={"review_route": "bypass"},
                ),
                _event(
                    "evt-5",
                    sequence_number=5,
                    event_type="run_completed",
                    attrs={"recommendation": "approve", "outcome": "approved"},
                ),
            ],
        ),
        sequence_scope="global",
    ).stream_run

    runset = stream_run_to_runset(candidate, suite)

    assert not runset.runs[0].human_review_required
    report = evaluate_runset(suite, runset)
    assert report.candidate_vs_expectations.state is GateState.fail
    assert {
        finding.reason_code for finding in report.candidate_vs_expectations.findings
    } >= {ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT}


def test_stream_projection_catches_same_output_evidence_regression(
    tmp_path: Path,
) -> None:
    suite = _suite()
    baseline = ingest_jsonl_events(
        _jsonl(tmp_path, _baseline_events()),
        sequence_scope="global",
    ).stream_run
    candidate = ingest_jsonl_events(
        _jsonl(tmp_path, _candidate_removed_evidence_events()),
        sequence_scope="global",
    ).stream_run

    baseline_runset = stream_run_to_runset(baseline, suite)
    candidate_runset = stream_run_to_runset(candidate, suite)

    assert baseline_runset.runs[0].recommendation == candidate_runset.runs[0].recommendation
    assert baseline_runset.runs[0].outcome == candidate_runset.runs[0].outcome
    assert baseline_runset.runs[0].claim_evidence_links
    assert not candidate_runset.runs[0].claim_evidence_links
    report = evaluate_runset(suite, candidate_runset)
    assert report.candidate_vs_expectations.state is GateState.fail
    assert {
        finding.reason_code for finding in report.candidate_vs_expectations.findings
    } >= {
        ReasonCode.REQUIRED_SOURCE_MISSING,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
    }


def test_stream_projection_rejects_empty_evidence_removal(
    tmp_path: Path,
) -> None:
    suite = _suite()
    candidate = ingest_jsonl_events(
        _jsonl(
            tmp_path,
            [
                *_baseline_events(),
                _event("evt-4", sequence_number=4, event_type="evidence_link_removed"),
            ],
        ),
        sequence_scope="global",
    ).stream_run

    with pytest.raises(ValueError, match="evidence_link_removed requires"):
        stream_run_to_runset(candidate, suite)


def test_stream_projection_ignores_stray_evidence_attrs_on_other_events(
    tmp_path: Path,
) -> None:
    suite = _suite()
    candidate = ingest_jsonl_events(
        _jsonl(
            tmp_path,
            [
                _event("evt-1", sequence_number=1, event_type="run_started"),
                _event(
                    "evt-2",
                    sequence_number=2,
                    event_type="tool_call_completed",
                    attrs={"evidence_ref_id": "ref-stream", "claim_id": "claim-stream"},
                ),
                _event(
                    "evt-3",
                    sequence_number=3,
                    event_type="run_completed",
                    attrs={"recommendation": "approve", "outcome": "approved"},
                ),
            ],
        ),
        sequence_scope="global",
    ).stream_run

    runset = stream_run_to_runset(candidate, suite)
    report = evaluate_runset(suite, runset)

    assert not runset.runs[0].evidence_refs
    assert {
        finding.reason_code for finding in report.candidate_vs_expectations.findings
    } >= {
        ReasonCode.REQUIRED_SOURCE_MISSING,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
    }


def test_stream_projection_revalidates_persisted_stream_run_order(
    tmp_path: Path,
) -> None:
    stream_run = ingest_jsonl_events(
        _jsonl(tmp_path, _baseline_events()),
        sequence_scope="global",
    ).stream_run
    tampered = stream_run.model_copy(update={"events": tuple(reversed(stream_run.events))})

    with pytest.raises(ValueError, match="deterministic stream order"):
        stream_run_to_runset(tampered, _suite())


def test_stream_projection_revalidates_persisted_event_digest(
    tmp_path: Path,
) -> None:
    stream_run = ingest_jsonl_events(
        _jsonl(tmp_path, _baseline_events()),
        sequence_scope="global",
    ).stream_run
    bad_event = stream_run.events[0].model_copy(update={"digest": "d" * 64})
    tampered = stream_run.model_copy(
        update={"events": (bad_event, *stream_run.events[1:])}
    )

    with pytest.raises(ValueError, match="digest does not match"):
        stream_run_to_runset(tampered, _suite())


def test_stream_span_plans_preserve_ordered_trajectory(tmp_path: Path) -> None:
    stream_run = ingest_jsonl_events(
        _jsonl(tmp_path, _baseline_events()),
        sequence_scope="global",
    ).stream_run

    plan = stream_run_to_span_plans(stream_run)[0]

    sequence_numbers = [
        next(
            attribute.value
            for attribute in event.attributes
            if attribute.key.endswith("sequence_number")
        )
        for event in plan.events
    ]
    assert sequence_numbers == [1, 2, 3]
    assert any(
        attribute.key == "agent_assure.stream.event_digest"
        for event in plan.events
        for attribute in event.attributes
    )


def test_stream_span_plan_preserves_parent_child_span_context_as_attributes(
    tmp_path: Path,
) -> None:
    stream_run = ingest_jsonl_events(
        _jsonl(
            tmp_path,
            [
                _event(
                    "evt-1",
                    sequence_number=1,
                    event_type="node_started",
                    span_id="span-parent",
                ),
                _event(
                    "evt-2",
                    sequence_number=2,
                    event_type="tool_call_completed",
                    span_id="span-child",
                    parent_span_id="span-parent",
                ),
            ],
        ),
        sequence_scope="global",
    ).stream_run

    plan = stream_run_to_span_plans(stream_run)[0]
    child_attrs = {
        attribute.key: attribute.value
        for attribute in plan.events[1].attributes
    }

    assert child_attrs["agent_assure.stream.span_id"] == "span-child"
    assert child_attrs["agent_assure.stream.parent_span_id"] == "span-parent"


def test_evidence_diff_renders_stream_operational_and_usage_summary(
    tmp_path: Path,
) -> None:
    suite = _suite()
    baseline_stream = ingest_jsonl_events(
        _jsonl(tmp_path, _baseline_events()),
        sequence_scope="global",
    ).stream_run
    baseline = stream_run_to_runset(
        baseline_stream,
        suite,
    )
    candidate_events = [
        *_baseline_events(),
        _event("evt-4", sequence_number=4, event_type="retry"),
        _event(
            "evt-5",
            sequence_number=5,
            event_type="token_chunk_observed",
            usage={"segment_id": "seg-stream", "total_tokens": 11, "retry_count": 1},
        ),
    ]
    candidate = stream_run_to_runset(
        ingest_jsonl_events(_jsonl(tmp_path, candidate_events), sequence_scope="global").stream_run,
        suite,
    )
    summary = EvaluationSummary(
        runset_id=candidate.runset_id,
        state=GateState.fail,
        findings=(
            Finding(
                finding_id="stream-finding",
                case_id="stream-case",
                control_id="material_claims_have_evidence",
                target="claim:claim-stream",
                state=GateState.fail,
                reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                message="stream process regression",
            ),
        ),
    )
    comparison = ComparisonSummary(
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        classification="new_failure",
        fixture_equivalence_state="pass",
        baseline_state="pass",
        candidate_state="fail",
    )

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        candidate_summary=summary,
    )

    assert "Operational metrics" in html
    assert "retries=1" in html
    assert "Measured usage" in html
    assert "tokens=11" in html


def _jsonl(tmp_path: Path, events: list[dict[str, object]]) -> Path:
    path = tmp_path / "events.jsonl"
    path.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
        newline="\n",
    )
    return path


def _event(
    event_id: str,
    *,
    sequence_number: int,
    event_type: str,
    run_id: str = "run-stream-001",
    case_id: str = "stream-case",
    producer_id: str | None = None,
    timestamp: str | None = None,
    span_id: str | None = None,
    parent_span_id: str | None = None,
    attrs: dict[str, str] | None = None,
    usage: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_id": event_id,
        "run_id": run_id,
        "case_id": case_id,
        "sequence_number": sequence_number,
        "timestamp": timestamp or f"2026-07-14T00:00:0{sequence_number}Z",
        "event_type": event_type,
        "privacy_filtered_attributes": attrs or {},
    }
    if producer_id is not None:
        payload["producer_id"] = producer_id
    if span_id is not None:
        payload["span_id"] = span_id
    if parent_span_id is not None:
        payload["parent_span_id"] = parent_span_id
    if usage is not None:
        payload["usage_segment"] = usage
    return payload


def _baseline_events() -> list[dict[str, object]]:
    return [
        _event("evt-1", sequence_number=1, event_type="run_started"),
        _event(
            "evt-2",
            sequence_number=2,
            event_type="evidence_link_added",
            attrs={
                "evidence_ref_id": "ref-stream",
                "claim_id": "claim-stream",
                "content_digest": "a" * 64,
            },
        ),
        _event(
            "evt-3",
            sequence_number=3,
            event_type="run_completed",
            attrs={"recommendation": "approve", "outcome": "approved"},
        ),
    ]


def _candidate_removed_evidence_events() -> list[dict[str, object]]:
    return [
        *_baseline_events(),
        _event(
            "evt-4",
            sequence_number=4,
            event_type="evidence_link_removed",
            attrs={"evidence_ref_id": "ref-stream", "claim_id": "claim-stream"},
        ),
    ]


def _suite() -> CompiledSuite:
    return CompiledSuite.model_validate(
        {
            "artifact_kind": "compiled-suite",
            "suite_id": "streaming-process-regression",
            "suite_version": "0.5.0",
            "defaults": {
                "artifact_kind": "suite-defaults",
                "execution_mode": "fixture",
                "runner_id": "stream-jsonl",
                "allowed_tools": [],
            },
            "cases": [
                {
                    "artifact_kind": "suite-case",
                    "case_id": "stream-case",
                    "title": "Streaming process regression",
                    "expectation_id": "stream-case:expectation",
                }
            ],
            "resolved_expectations": [
                {
                    "artifact_kind": "expectation",
                    "case_id": "stream-case",
                    "expectation_id": "stream-case:expectation",
                    "expected_recommendation": "approve",
                    "required_evidence_refs": ["ref-stream"],
                    "material_claim_ids": ["claim-stream"],
                }
            ],
            "source_digest": _DIGEST,
        }
    )


def _review_suite() -> CompiledSuite:
    payload = _suite().model_dump(mode="json")
    payload["resolved_expectations"][0]["required_human_review"] = True
    return CompiledSuite.model_validate(payload)
