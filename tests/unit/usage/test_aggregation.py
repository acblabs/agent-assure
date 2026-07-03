from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationMetrics, EvaluationReport
from agent_assure.reporting.markdown import render_evaluation_markdown
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.usage import UsageLedger, UsageSegment, UsageSummary, UsageSummaryDelta
from agent_assure.usage.aggregation import (
    aggregate_usage_segments,
    compare_usage_summaries,
    format_usage_delta,
)


def test_usage_segments_use_integer_micro_usd() -> None:
    segment = UsageSegment(
        segment_id="seg-001",
        total_tokens=42,
        estimated_cost_microusd=123,
        pricing_snapshot_id="local-demo-pricing-v1",
        limitations=("Cost is estimated from a declared pricing snapshot.",),
    )

    assert segment.estimated_cost_microusd == 123
    assert "estimated_cost_usd" not in UsageSegment.model_fields

    with pytest.raises(ValidationError):
        UsageSegment(segment_id="bad-money", estimated_cost_microusd=1.25)  # type: ignore[arg-type]


def test_usage_segment_supports_future_stream_attachment_fields() -> None:
    segment = UsageSegment(
        segment_id="seg-stream-001",
        run_id="run-001",
        span_id="span-child",
        parent_span_id="span-parent",
        event_range_start=7,
        event_range_end=9,
    )

    assert segment.span_id == "span-child"
    assert segment.parent_span_id == "span-parent"
    assert segment.event_range_start == 7
    assert segment.event_range_end == 9


def test_usage_segment_rejects_inverted_event_range() -> None:
    with pytest.raises(ValidationError, match="event_range_end"):
        UsageSegment(segment_id="seg-bad-range", event_range_start=10, event_range_end=9)


def test_usage_segment_requires_limitations_for_declared_estimated_cost() -> None:
    with pytest.raises(ValidationError, match="cost-bearing usage segments require"):
        UsageSegment(segment_id="seg-cost-no-limitation", estimated_cost_microusd=1)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            UsageSegment,
            {
                "artifact_kind": "usage-segment",
                "schema_version": "0.2.0",
                "segment_id": "seg-legacy-version",
            },
        ),
        (
            UsageLedger,
            {
                "artifact_kind": "usage-ledger",
                "schema_version": "0.2.0",
            },
        ),
        (
            UsageSummary,
            {
                "artifact_kind": "usage-summary",
                "schema_version": "0.2.0",
            },
        ),
        (
            UsageSummaryDelta,
            {
                "artifact_kind": "usage-summary-delta",
                "schema_version": "0.2.0",
                "comparison_state": "observed",
                "baseline_observed": True,
                "candidate_observed": True,
            },
        ),
    ],
)
def test_usage_roots_reject_legacy_schema_version(
    model: type[BaseModel],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_usage_ledger_rejects_missingness_that_conflicts_with_segments() -> None:
    segment = UsageSegment(segment_id="seg-missingness", total_tokens=5)

    with pytest.raises(ValidationError, match="usage ledger missingness must match segments"):
        UsageLedger(segments=(segment,), missingness={})


def test_legacy_labeled_containers_reject_usage_fields() -> None:
    cases: tuple[tuple[type[BaseModel], dict[str, object]], ...] = (
        (AgentRunRecord, _legacy_agent_run_record_payload(usage_summary=_usage_summary_payload())),
        (RunSet, _legacy_runset_payload(usage_summary=_usage_summary_payload())),
        (RunSet, _legacy_runset_payload(runs=(_agent_run_record_payload(),))),
        (EvaluationSummary, _legacy_evaluation_summary_payload(_usage_summary_payload())),
        (ComparisonSummary, _legacy_comparison_summary_payload(_usage_delta_payload())),
        (EvidencePacket, _legacy_evidence_packet_payload(usage_summary=_usage_summary_payload())),
        (
            EvidencePacket,
            _legacy_evidence_packet_payload(
                evaluation=_evaluation_summary_payload(usage_summary=_usage_summary_payload())
            ),
        ),
        (EvaluationReport, _legacy_evaluation_report_payload(_usage_summary_payload())),
        (
            EvaluationReport,
            _legacy_evaluation_report_payload(
                None,
                candidate_vs_expectations=_evaluation_summary_payload(
                    usage_summary=_usage_summary_payload()
                ),
            ),
        ),
        (ComparisonReport, _legacy_comparison_report_payload(usage_delta=_usage_delta_payload())),
        (
            ComparisonReport,
            _legacy_comparison_report_payload(
                comparison_summary=_comparison_summary_payload(usage_delta=_usage_delta_payload())
            ),
        ),
    )

    for model, payload in cases:
        with pytest.raises(ValidationError, match="usage fields require schema_version 0.3.1"):
            model.model_validate(payload)


def test_aggregate_usage_segments_sums_known_fields_and_tracks_missingness() -> None:
    first = UsageSegment(
        segment_id="seg-001",
        total_tokens=100,
        tool_call_count=2,
        retry_count=1,
        latency_ms=50,
        estimated_cost_microusd=400,
        limitations=("Cost is estimated from a declared pricing snapshot.",),
    )
    second = UsageSegment(
        segment_id="seg-002",
        total_tokens=50,
        retry_count=0,
        estimated_cost_microusd=100,
        limitations=("Cost is estimated from a declared pricing snapshot.",),
    )

    aggregation = aggregate_usage_segments((first, second))

    assert aggregation.usage_ledger == UsageLedger(
        segments=(first, second),
        aggregation_method="sum_known_fields_v1",
        missingness={
            "cached_tokens": 2,
            "completion_tokens": 2,
            "latency_ms": 1,
            "prompt_tokens": 2,
            "reasoning_tokens": 2,
            "tool_call_count": 1,
        },
    )
    assert aggregation.usage_summary == UsageSummary(
        total_tokens=150,
        total_tool_calls=2,
        total_retries=1,
        total_latency_ms=50,
        estimated_cost_microusd=500,
        limitations=(
            "Cost is estimated from a declared pricing snapshot.",
            (
                "Usage summary sums known fields only; missing segment fields: "
                "cached_tokens=2, completion_tokens=2, latency_ms=1, prompt_tokens=2, "
                "reasoning_tokens=2, tool_call_count=1."
            ),
        ),
    )


def test_runset_rejects_usage_summary_that_conflicts_with_ledger() -> None:
    segment = UsageSegment(segment_id="seg-001", total_tokens=100)
    aggregation = aggregate_usage_segments((segment,))

    with pytest.raises(ValidationError, match="usage_summary does not match usage_ledger"):
        RunSet(
            runset_id="runset-001",
            suite_id="suite-001",
            suite_version="0.1.0",
            suite_digest="0" * 64,
            fixture_manifest_digest="1" * 64,
            usage_ledger=aggregation.usage_ledger,
            usage_summary=aggregation.usage_summary.model_copy(update={"total_tokens": 999}),
            runs=(),
        )


def test_compare_usage_summaries_reports_observed_delta_without_float_money() -> None:
    baseline = UsageSummary(
        total_tokens=100,
        total_tool_calls=2,
        total_retries=1,
        total_latency_ms=50,
        estimated_cost_microusd=400,
    )
    candidate = UsageSummary(
        total_tokens=140,
        total_tool_calls=3,
        total_retries=1,
        total_latency_ms=75,
        estimated_cost_microusd=425,
    )

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.comparison_state == "observed"
    assert delta.total_tokens_delta == 40
    assert delta.total_tool_calls_delta == 1
    assert delta.total_retries_delta == 0
    assert delta.total_latency_ms_delta == 25
    assert delta.estimated_cost_microusd_delta == 25
    assert "ROI" not in format_usage_delta(delta)


def test_compare_usage_summaries_treats_missing_usage_as_not_observed() -> None:
    delta = compare_usage_summaries(None, None)

    assert delta.comparison_state == "not_observed"
    assert delta.baseline_observed is False
    assert delta.candidate_observed is False
    assert format_usage_delta(delta) == "Measured usage: not_observed."


def test_usage_delta_carries_partial_missingness_limitations() -> None:
    baseline = aggregate_usage_segments(
        (UsageSegment(segment_id="baseline-seg", total_tokens=100),)
    ).usage_summary
    candidate = aggregate_usage_segments(
        (UsageSegment(segment_id="candidate-seg", total_tokens=125),)
    ).usage_summary

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.total_tokens_delta == 25
    assert any("sums known fields only" in limitation for limitation in delta.limitations)
    assert "sums known fields only" in format_usage_delta(delta)


def test_report_markdown_uses_measured_language_for_missing_usage() -> None:
    report = EvaluationReport(
        candidate_vs_expectations=EvaluationSummary(
            runset_id="runset-001",
            state=GateState.pass_,
        ),
        runset_id="runset-001",
        suite_id="suite-001",
        suite_version="0.1.0",
        gate_profile="default",
        metrics=EvaluationMetrics(
            total_cases=1,
            evaluated_cases=1,
            unevaluated_cases=0,
            passed_cases=1,
            failed_cases=0,
            warning_findings=0,
            blocking_findings=0,
            global_blocking_findings=0,
            findings_by_reason={},
            findings_by_control={},
        ),
    )

    rendered = render_evaluation_markdown(report)

    assert "## Measured Usage" in rendered
    assert "not_observed" in rendered
    assert "ROI" not in rendered


def _usage_summary_payload() -> dict[str, object]:
    return UsageSummary(total_tokens=1).model_dump(mode="json")


def _usage_delta_payload() -> dict[str, object]:
    return UsageSummaryDelta(
        comparison_state="observed",
        baseline_observed=True,
        candidate_observed=True,
        total_tokens_delta=1,
    ).model_dump(mode="json")


def _agent_run_record_payload() -> dict[str, object]:
    payload = _legacy_agent_run_record_payload()
    payload["schema_version"] = "0.3.1"
    payload["usage_summary"] = _usage_summary_payload()
    return payload


def _legacy_agent_run_record_payload(
    *,
    usage_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "agent-run-record",
        "schema_version": "0.2.0",
        "run_id": "run-001",
        "case_id": "case-001",
        "pipeline_id": "pipeline-001",
        "recommendation": "approve",
        "outcome": "approved",
        "input_summary": "input",
        "output_summary": "output",
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_runset_payload(
    *,
    usage_summary: dict[str, object] | None = None,
    runs: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "run-set",
        "schema_version": "0.2.0",
        "runset_id": "runset-001",
        "suite_id": "suite-001",
        "suite_version": "0.1.0",
        "suite_digest": "0" * 64,
        "fixture_manifest_digest": "1" * 64,
        "runs": list(runs),
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _evaluation_summary_payload(
    *,
    usage_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "evaluation-summary",
        "schema_version": "0.3.1",
        "runset_id": "runset-001",
        "state": "pass",
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_evaluation_summary_payload(
    usage_summary: dict[str, object],
) -> dict[str, object]:
    payload = _evaluation_summary_payload(usage_summary=usage_summary)
    payload["schema_version"] = "0.2.0"
    return payload


def _comparison_summary_payload(
    *,
    usage_delta: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "comparison-summary",
        "schema_version": "0.3.1",
        "baseline_runset_id": "baseline",
        "candidate_runset_id": "candidate",
        "classification": ComparisonClassification.not_evaluated.value,
    }
    if usage_delta is not None:
        payload["usage_delta"] = usage_delta
    return payload


def _legacy_comparison_summary_payload(
    usage_delta: dict[str, object],
) -> dict[str, object]:
    payload = _comparison_summary_payload(usage_delta=usage_delta)
    payload["schema_version"] = "0.2.0"
    return payload


def _legacy_evidence_packet_payload(
    *,
    evaluation: dict[str, object] | None = None,
    usage_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "evidence-packet",
        "schema_version": "0.2.0",
        "packet_id": "packet-001",
        "interpretation": ["read candidate state first"],
        "evaluation": evaluation or _evaluation_summary_payload(),
        "limitations": ["fixture evidence only"],
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_evaluation_report_payload(
    usage_summary: dict[str, object] | None,
    *,
    candidate_vs_expectations: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "evaluation-report",
        "schema_version": "0.2.0",
        "candidate_vs_expectations": candidate_vs_expectations or _evaluation_summary_payload(),
        "runset_id": "runset-001",
        "suite_id": "suite-001",
        "suite_version": "0.1.0",
        "gate_profile": "default",
        "metrics": _metrics_payload(),
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_comparison_report_payload(
    *,
    comparison_summary: dict[str, object] | None = None,
    usage_delta: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "comparison-report",
        "schema_version": "0.2.0",
        "candidate_vs_expectations": _evaluation_summary_payload(),
        "verdict_explanations": [],
        "fixture_equivalence": {"state": "not_evaluated"},
        "baseline_vs_expectations": _evaluation_summary_payload(),
        "control_changes": [],
        "behavioral_changes": [],
        "provenance_changes": [],
        "not_evaluated_capabilities": [],
        "limitations": ["fixture evidence only"],
        "comparison_summary": comparison_summary or _comparison_summary_payload(),
        "baseline_metrics": _metrics_payload(),
        "candidate_metrics": _metrics_payload(),
        "suite_id": "suite-001",
        "suite_version": "0.1.0",
        "gate_profile": "default",
    }
    if usage_delta is not None:
        payload["usage_delta"] = usage_delta
    return payload


def _metrics_payload() -> dict[str, object]:
    return EvaluationMetrics(
        total_cases=1,
        evaluated_cases=1,
        unevaluated_cases=0,
        passed_cases=1,
        failed_cases=0,
        warning_findings=0,
        blocking_findings=0,
        global_blocking_findings=0,
        findings_by_reason={},
        findings_by_control={},
    ).model_dump(mode="json")
