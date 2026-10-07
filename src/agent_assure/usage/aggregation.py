from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol

from agent_assure.fixed_point import microusd_from_picousd
from agent_assure.schema.common import DigestHex
from agent_assure.schema.run import RunSet
from agent_assure.schema.usage import (
    UsageComparisonState,
    UsageLedger,
    UsageMetricCoverage,
    UsageSegment,
    UsageSummary,
    UsageSummaryDelta,
    summarize_usage_segments,
    usage_segment_missingness,
    usage_summary_from_ledger,
    validate_usage_summary_consistency,
)
from agent_assure.schema.validation import validate_loaded_artifact_payload


class _UsageBearingRun(Protocol):
    usage_ledger: UsageLedger | None
    usage_summary: UsageSummary | None


@dataclass(frozen=True)
class UsageAggregation:
    usage_ledger: UsageLedger
    usage_summary: UsageSummary

    @property
    def ledger(self) -> UsageLedger:
        return self.usage_ledger

    @property
    def summary(self) -> UsageSummary:
        return self.usage_summary

    def __iter__(self) -> Iterator[UsageLedger | UsageSummary]:
        yield self.usage_ledger
        yield self.usage_summary


@dataclass(frozen=True)
class _SummaryCostAggregation:
    estimated_cost_microusd: int | None
    estimated_cost_picousd: int | None
    currency: str
    cost_basis_ids: tuple[str, ...]
    pricing_snapshot_ids: tuple[str, ...]
    pricing_snapshot_digests: tuple[DigestHex, ...]
    cost_observation_count: int | None
    limitations: list[str]


_INCOMPLETE_RUN_COVERAGE_LIMITATION = (
    "Run-set usage aggregation was suppressed because the usage ledger did not "
    "bind at least one segment to every run or contained a segment not bound to a run."
)
_UNVERIFIED_RUNSET_SUMMARY_LIMITATION = (
    "Run-set usage aggregation was suppressed because a top-level summary had "
    "no ledger or run-level coverage evidence."
)
_UNTRUSTWORTHY_RUN_SUMMARY_LIMITATION = (
    "Run-level usage was excluded because summary-only rollups require "
    "schema_version 0.6.6 coverage derived from usage segments or run records."
)


def aggregate_usage_segments(segments: Iterable[UsageSegment]) -> UsageAggregation:
    segment_tuple = tuple(_validated_usage_segment(segment) for segment in segments)
    ledger = _validated_usage_ledger(
        UsageLedger(
            artifact_kind="usage-ledger",
            segments=segment_tuple,
            aggregation_method="sum_complete_fields_v2",
            missingness=usage_segment_missingness(segment_tuple),
        )
    )
    summary = _validated_usage_summary(usage_summary_from_ledger(ledger))
    return UsageAggregation(usage_ledger=ledger, usage_summary=summary)


def usage_summary_for_runset(runset: RunSet) -> UsageSummary | None:
    runset = _validated_runset(runset)
    summary = _usage_summary_for_validated_runset(runset)
    return None if summary is None else _validated_usage_summary(summary)


def _usage_summary_for_validated_runset(runset: RunSet) -> UsageSummary | None:
    if runset.usage_ledger is not None:
        validate_usage_summary_consistency(
            runset.usage_ledger,
            runset.usage_summary,
            owner="run set",
        )
        ledger_run_summary = _summary_from_summaries(_run_summaries_from_ledger(runset))
        if not _ledger_has_exact_run_coverage(runset):
            return _suppress_usage_summary(
                ledger_run_summary,
                limitation=_INCOMPLETE_RUN_COVERAGE_LIMITATION,
            )
        run_summaries = tuple(_usage_summary_for_run(run) for run in runset.runs)
        if (
            run_summaries
            and all(summary is not None for summary in run_summaries)
            and not _usage_summaries_match(
                _summary_from_summaries(
                    tuple(summary for summary in run_summaries if summary is not None)
                ),
                ledger_run_summary,
            )
        ):
            raise ValueError(
                "run set usage_ledger does not match complete run-level usage summaries"
            )
        return ledger_run_summary
    run_summaries = tuple(_usage_summary_for_run(run) for run in runset.runs)
    observed_run_summaries = tuple(summary for summary in run_summaries if summary is not None)
    if not observed_run_summaries:
        has_run_summary_evidence = any(run.usage_summary is not None for run in runset.runs)
        if runset.usage_summary is not None or has_run_summary_evidence:
            limitations: list[str] = []
            if runset.usage_summary is not None:
                limitations.extend(runset.usage_summary.limitations)
                limitations.append(_UNVERIFIED_RUNSET_SUMMARY_LIMITATION)
            if has_run_summary_evidence:
                limitations.append(_UNTRUSTWORTHY_RUN_SUMMARY_LIMITATION)
            return _suppress_usage_summary(
                _empty_run_coverage_summary(
                    source_count=len(runset.runs),
                    currency=(
                        runset.usage_summary.currency if runset.usage_summary is not None else "USD"
                    ),
                    limitations=tuple(limitations),
                ),
                limitation=(
                    _UNVERIFIED_RUNSET_SUMMARY_LIMITATION
                    if runset.usage_summary is not None
                    else _UNTRUSTWORTHY_RUN_SUMMARY_LIMITATION
                ),
            )
        return None
    complete_run_summaries = tuple(
        summary
        if summary is not None
        else _missing_run_summary(
            limitation=(
                _UNTRUSTWORTHY_RUN_SUMMARY_LIMITATION
                if run.usage_summary is not None
                else _INCOMPLETE_RUN_COVERAGE_LIMITATION
            )
        )
        for run, summary in zip(runset.runs, run_summaries, strict=True)
    )
    derived = _summary_from_summaries(complete_run_summaries)
    if runset.usage_summary is not None:
        if not _is_trustworthy_run_rollup(
            runset.usage_summary,
            expected_source_count=len(runset.runs),
        ):
            raise ValueError(
                "run set usage_summary lacks trustworthy schema_version 0.6.6 run-record coverage"
            )
        if not _usage_summaries_match(runset.usage_summary, derived):
            raise ValueError(
                "run set usage_summary does not match complete run-level usage summaries"
            )
    return derived


def _run_summaries_from_ledger(runset: RunSet) -> tuple[UsageSummary, ...]:
    assert runset.usage_ledger is not None
    return tuple(
        (
            summarize_usage_segments(
                tuple(
                    segment
                    for segment in runset.usage_ledger.segments
                    if segment.run_id == run.run_id
                ),
                aggregation_method="sum_complete_fields_v2",
            )
            if any(segment.run_id == run.run_id for segment in runset.usage_ledger.segments)
            else _missing_run_summary(limitation=_INCOMPLETE_RUN_COVERAGE_LIMITATION)
        )
        for run in runset.runs
    )


def _ledger_has_exact_run_coverage(runset: RunSet) -> bool:
    ledger = runset.usage_ledger
    if ledger is None:
        return False
    run_ids = {run.run_id for run in runset.runs}
    segment_run_ids = tuple(segment.run_id for segment in ledger.segments)
    return (
        bool(run_ids)
        and bool(segment_run_ids)
        and all(run_id in run_ids for run_id in segment_run_ids)
        and {run_id for run_id in segment_run_ids if run_id is not None} == run_ids
    )


def _suppress_usage_summary(
    summary: UsageSummary,
    *,
    limitation: str,
) -> UsageSummary:
    return UsageSummary(
        schema_version="0.6.6",
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="run_record",
        source_count=summary.source_count or 0,
        coverage_counts=summary.coverage_counts or UsageMetricCoverage(),
        currency=summary.currency,
        limitations=tuple(sorted({*summary.limitations, limitation})),
    )


def _empty_run_coverage_summary(
    *,
    source_count: int,
    currency: str = "USD",
    limitations: tuple[str, ...] = (),
) -> UsageSummary:
    return UsageSummary(
        schema_version="0.6.6",
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="run_record",
        source_count=source_count,
        coverage_counts=UsageMetricCoverage(),
        currency=currency,
        limitations=limitations,
    )


def _missing_run_summary(*, limitation: str) -> UsageSummary:
    return _empty_run_coverage_summary(
        source_count=1,
        limitations=(limitation,),
    )


def _usage_summary_for_run(run: _UsageBearingRun) -> UsageSummary | None:
    if run.usage_ledger is not None:
        validate_usage_summary_consistency(
            run.usage_ledger,
            run.usage_summary,
            owner="run record",
        )
        return summarize_usage_segments(
            run.usage_ledger.segments,
            aggregation_method="sum_complete_fields_v2",
        )
    if run.usage_summary is not None and _is_trustworthy_run_summary(run.usage_summary):
        return run.usage_summary
    return None


def _has_trustworthy_summary_coverage(summary: UsageSummary) -> bool:
    return (
        summary.schema_version == "0.6.6"
        and summary.aggregation_method == "sum_complete_fields_v2"
        and summary.coverage_basis in {"usage_segment", "run_record"}
        and summary.source_count is not None
        and summary.coverage_counts is not None
    )


def _is_trustworthy_run_summary(summary: UsageSummary) -> bool:
    return (
        _has_trustworthy_summary_coverage(summary)
        and summary.source_count is not None
        and summary.source_count > 0
        and (
            summary.coverage_basis == "usage_segment"
            or (summary.coverage_basis == "run_record" and summary.source_count == 1)
        )
    )


def _is_trustworthy_run_rollup(
    summary: UsageSummary,
    *,
    expected_source_count: int,
) -> bool:
    return (
        _has_trustworthy_summary_coverage(summary)
        and summary.coverage_basis == "run_record"
        and summary.source_count == expected_source_count
    )


def _usage_summaries_match(left: UsageSummary, right: UsageSummary) -> bool:
    return all(
        getattr(left, field_name) == getattr(right, field_name)
        for field_name in (
            "aggregation_method",
            "coverage_basis",
            "source_count",
            "coverage_counts",
            "total_tokens",
            "total_tool_calls",
            "total_retries",
            "total_latency_ms",
            "estimated_cost_microusd",
            "estimated_cost_picousd",
            "currency",
            "cost_basis_ids",
            "pricing_snapshot_ids",
            "pricing_snapshot_digests",
            "cost_observation_count",
        )
    )


def compare_usage_summaries(
    baseline: UsageSummary | None,
    candidate: UsageSummary | None,
) -> UsageSummaryDelta:
    baseline = None if baseline is None else _validated_usage_summary(baseline)
    candidate = None if candidate is None else _validated_usage_summary(candidate)
    return _validated_usage_summary_delta(_compare_validated_usage_summaries(baseline, candidate))


def _compare_validated_usage_summaries(
    baseline: UsageSummary | None,
    candidate: UsageSummary | None,
) -> UsageSummaryDelta:
    baseline_observed = _has_observed_usage(baseline)
    candidate_observed = _has_observed_usage(candidate)
    limitations: list[str] = []
    if not baseline_observed and not candidate_observed:
        return UsageSummaryDelta(
            artifact_kind="usage-summary-delta",
            comparison_state="not_observed",
            baseline_observed=False,
            candidate_observed=False,
            limitations=("Measured usage was not observed for baseline or candidate.",),
        )
    if not baseline_observed:
        limitations.append("Measured usage was not observed for baseline.")
    if not candidate_observed:
        limitations.append("Measured usage was not observed for candidate.")
    if baseline is not None:
        limitations.extend(baseline.limitations)
    if candidate is not None:
        limitations.extend(candidate.limitations)

    currency = _comparison_currency(baseline, candidate)
    total_tokens_delta, total_tokens_delta_bps = _metric_delta_pair(
        baseline,
        candidate,
        "total_tokens",
        limitations=limitations,
    )
    total_tool_calls_delta, total_tool_calls_delta_bps = _metric_delta_pair(
        baseline,
        candidate,
        "total_tool_calls",
        limitations=limitations,
    )
    total_retries_delta, total_retries_delta_bps = _metric_delta_pair(
        baseline,
        candidate,
        "total_retries",
        limitations=limitations,
    )
    total_latency_ms_delta, total_latency_ms_delta_bps = _metric_delta_pair(
        baseline,
        candidate,
        "total_latency_ms",
        limitations=limitations,
    )
    estimated_cost_microusd_delta: int | None = None
    estimated_cost_microusd_delta_bps: int | None = None
    estimated_cost_picousd_delta: int | None = None
    estimated_cost_picousd_delta_bps: int | None = None
    if (
        baseline is not None
        and candidate is not None
        and baseline.estimated_cost_microusd is not None
        and candidate.estimated_cost_microusd is not None
    ):
        cost_limitation = _metric_comparison_limitation(
            baseline,
            candidate,
            "estimated_cost_microusd",
        )
        if cost_limitation is None:
            cost_limitation = _cost_comparison_limitation(baseline, candidate)
        if cost_limitation is None:
            current_exact_cost = (
                baseline.schema_version == "0.6.6" and candidate.schema_version == "0.6.6"
            )
            if current_exact_cost and (
                baseline.estimated_cost_picousd is None or candidate.estimated_cost_picousd is None
            ):
                limitations.append(
                    "Declared estimated cost was not compared because current summaries "
                    "require exact pico-USD values."
                )
            else:
                if current_exact_cost:
                    estimated_cost_microusd_delta = _delta_value(
                        baseline,
                        candidate,
                        "estimated_cost_microusd",
                    )
                    estimated_cost_picousd_delta = _delta_value(
                        baseline,
                        candidate,
                        "estimated_cost_picousd",
                    )
                    estimated_cost_picousd_delta_bps = _delta_bps(
                        baseline,
                        candidate,
                        "estimated_cost_picousd",
                        limitations=limitations,
                    )
                    estimated_cost_microusd_delta_bps = estimated_cost_picousd_delta_bps
                else:
                    (
                        estimated_cost_microusd_delta,
                        estimated_cost_microusd_delta_bps,
                    ) = _metric_delta_pair(
                        baseline,
                        candidate,
                        "estimated_cost_microusd",
                        limitations=limitations,
                    )
        else:
            limitations.append(cost_limitation)

    return UsageSummaryDelta(
        artifact_kind="usage-summary-delta",
        comparison_state=_comparison_state(baseline_observed, candidate_observed),
        baseline_observed=baseline_observed,
        candidate_observed=candidate_observed,
        total_tokens_delta=total_tokens_delta,
        total_tokens_delta_bps=total_tokens_delta_bps,
        total_tool_calls_delta=total_tool_calls_delta,
        total_tool_calls_delta_bps=total_tool_calls_delta_bps,
        total_retries_delta=total_retries_delta,
        total_retries_delta_bps=total_retries_delta_bps,
        total_latency_ms_delta=total_latency_ms_delta,
        total_latency_ms_delta_bps=total_latency_ms_delta_bps,
        estimated_cost_microusd_delta=estimated_cost_microusd_delta,
        estimated_cost_microusd_delta_bps=estimated_cost_microusd_delta_bps,
        estimated_cost_picousd_delta=estimated_cost_picousd_delta,
        estimated_cost_picousd_delta_bps=estimated_cost_picousd_delta_bps,
        currency=currency,
        limitations=tuple(sorted(set(limitations))),
    )


def _validated_runset(runset: RunSet) -> RunSet:
    payload = runset.model_dump(mode="json", warnings="error")
    validated = RunSet.model_validate(payload)
    validate_loaded_artifact_payload(payload, "run-set")
    return validated


def _validated_usage_segment(segment: UsageSegment) -> UsageSegment:
    payload = segment.model_dump(mode="json", warnings="error")
    validated = UsageSegment.model_validate(payload)
    validate_loaded_artifact_payload(payload, "usage-segment")
    return validated


def _validated_usage_ledger(ledger: UsageLedger) -> UsageLedger:
    payload = ledger.model_dump(mode="json", warnings="error")
    validated = UsageLedger.model_validate(payload)
    validate_loaded_artifact_payload(payload, "usage-ledger")
    return validated


def _validated_usage_summary(summary: UsageSummary) -> UsageSummary:
    payload = summary.model_dump(mode="json", warnings="error")
    validated = UsageSummary.model_validate(payload)
    validate_loaded_artifact_payload(payload, "usage-summary")
    return validated


def _validated_usage_summary_delta(delta: UsageSummaryDelta) -> UsageSummaryDelta:
    payload = delta.model_dump(mode="json", warnings="error")
    validated = UsageSummaryDelta.model_validate(payload)
    validate_loaded_artifact_payload(payload, "usage-summary-delta")
    return validated


def format_usage_delta(delta: UsageSummaryDelta) -> str:
    delta = _validated_usage_summary_delta(delta)
    if delta.comparison_state == "not_observed":
        return "Measured usage: not_observed."
    parts = [f"measured usage: {delta.comparison_state}"]
    metric_parts = [
        _format_delta("total_tokens", delta.total_tokens_delta, delta.total_tokens_delta_bps),
        _format_delta(
            "tool_calls",
            delta.total_tool_calls_delta,
            delta.total_tool_calls_delta_bps,
        ),
        _format_delta("retries", delta.total_retries_delta, delta.total_retries_delta_bps),
        _format_delta("latency_ms", delta.total_latency_ms_delta, delta.total_latency_ms_delta_bps),
    ]
    observed_metrics = [part for part in metric_parts if part is not None]
    if observed_metrics:
        parts.append("usage delta " + ", ".join(observed_metrics))
    if delta.estimated_cost_picousd_delta is not None:
        bps = (
            ""
            if delta.estimated_cost_picousd_delta_bps is None
            else f" ({delta.estimated_cost_picousd_delta_bps:+d} bps)"
        )
        parts.append(
            f"declared estimated cost delta {delta.estimated_cost_picousd_delta:+d} pico-USD{bps}"
        )
    elif delta.estimated_cost_microusd_delta is not None:
        bps = (
            ""
            if delta.estimated_cost_microusd_delta_bps is None
            else f" ({delta.estimated_cost_microusd_delta_bps:+d} bps)"
        )
        parts.append(
            f"declared estimated cost delta {delta.estimated_cost_microusd_delta:+d} micro-USD{bps}"
        )
    if delta.limitations:
        parts.append("limitations: " + "; ".join(delta.limitations))
    return "; ".join(parts) + "."


def _summary_from_summaries(summaries: tuple[UsageSummary, ...]) -> UsageSummary:
    limitations = sorted(
        {limitation for summary in summaries for limitation in summary.limitations}
    )
    cost = _sum_summary_cost(summaries)
    limitations.extend(cost.limitations)
    return UsageSummary(
        artifact_kind="usage-summary",
        schema_version="0.6.6",
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="run_record",
        source_count=len(summaries),
        coverage_counts=UsageMetricCoverage(
            total_tokens=sum(summary.total_tokens is not None for summary in summaries),
            total_tool_calls=sum(summary.total_tool_calls is not None for summary in summaries),
            total_retries=sum(summary.total_retries is not None for summary in summaries),
            total_latency_ms=sum(summary.total_latency_ms is not None for summary in summaries),
            estimated_cost_microusd=sum(
                summary.estimated_cost_microusd is not None for summary in summaries
            ),
        ),
        total_tokens=_sum_complete(summary.total_tokens for summary in summaries),
        total_tool_calls=_sum_complete(summary.total_tool_calls for summary in summaries),
        total_retries=_sum_complete(summary.total_retries for summary in summaries),
        total_latency_ms=_sum_complete(summary.total_latency_ms for summary in summaries),
        estimated_cost_microusd=cost.estimated_cost_microusd,
        estimated_cost_picousd=cost.estimated_cost_picousd,
        currency=cost.currency,
        cost_basis_ids=cost.cost_basis_ids,
        pricing_snapshot_ids=cost.pricing_snapshot_ids,
        pricing_snapshot_digests=cost.pricing_snapshot_digests,
        cost_observation_count=cost.cost_observation_count,
        limitations=tuple(sorted(set(limitations))),
    )


def _sum_complete(values: Iterable[int | None]) -> int | None:
    materialized = tuple(values)
    if not materialized or any(value is None for value in materialized):
        return None
    return sum(value for value in materialized if value is not None)


def _sum_summary_cost(summaries: tuple[UsageSummary, ...]) -> _SummaryCostAggregation:
    cost_summaries = tuple(
        summary for summary in summaries if summary.estimated_cost_microusd is not None
    )
    if not cost_summaries:
        return _SummaryCostAggregation(
            None,
            None,
            summaries[0].currency if summaries else "USD",
            (),
            (),
            (),
            None,
            [],
        )
    if len(cost_summaries) != len(summaries):
        return _SummaryCostAggregation(
            None,
            None,
            cost_summaries[0].currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because cost coverage "
                "was incomplete across usage summaries."
            ],
        )
    currencies = {summary.currency for summary in cost_summaries}
    if len(currencies) != 1:
        return _SummaryCostAggregation(
            None,
            None,
            "USD",
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because multiple currencies "
                "were observed."
            ],
        )
    currency = next(iter(currencies))
    if currency != "USD":
        return _SummaryCostAggregation(
            None,
            None,
            "USD",
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because currency is not USD."],
        )
    if any(not summary.cost_basis_ids for summary in cost_summaries):
        return _SummaryCostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because cost basis was "
                "not declared for every cost summary."
            ],
        )
    if any(not summary.pricing_snapshot_ids for summary in cost_summaries):
        return _SummaryCostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because pricing snapshot "
                "IDs were not declared for every cost summary."
            ],
        )
    if any(not summary.pricing_snapshot_digests for summary in cost_summaries):
        return _SummaryCostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because pricing snapshot "
                "digests were not declared for every cost summary."
            ],
        )
    cost_basis_sets = {summary.cost_basis_ids for summary in cost_summaries}
    if len(cost_basis_sets) != 1:
        return _SummaryCostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because cost bases differ."],
        )
    snapshot_id_sets = {summary.pricing_snapshot_ids for summary in cost_summaries}
    if len(snapshot_id_sets) != 1:
        return _SummaryCostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because pricing snapshot IDs differ."],
        )
    snapshot_digest_sets = {summary.pricing_snapshot_digests for summary in cost_summaries}
    if len(snapshot_digest_sets) != 1:
        return _SummaryCostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because pricing snapshot digests differ."],
        )
    if any(summary.estimated_cost_picousd is None for summary in cost_summaries):
        return _SummaryCostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because exact pico-USD "
                "coverage was incomplete across usage summaries."
            ],
        )
    aggregate_cost_picousd = sum(summary.estimated_cost_picousd or 0 for summary in cost_summaries)
    aggregate_cost_microusd = microusd_from_picousd(aggregate_cost_picousd)
    cost_observation_count: int | None = None
    if all(summary.cost_observation_count is not None for summary in cost_summaries):
        cost_observation_count = sum(
            summary.cost_observation_count or 0 for summary in cost_summaries
        )
    else:
        limitations = [
            "Declared estimated cost per cost observation was not rendered because "
            "not every cost summary declared cost_observation_count."
        ]
        return _SummaryCostAggregation(
            aggregate_cost_microusd,
            aggregate_cost_picousd,
            currency,
            next(iter(cost_basis_sets)),
            next(iter(snapshot_id_sets)),
            next(iter(snapshot_digest_sets)),
            cost_observation_count,
            limitations,
        )
    return _SummaryCostAggregation(
        aggregate_cost_microusd,
        aggregate_cost_picousd,
        currency,
        next(iter(cost_basis_sets)),
        next(iter(snapshot_id_sets)),
        next(iter(snapshot_digest_sets)),
        cost_observation_count,
        [],
    )


def _has_observed_usage(summary: UsageSummary | None) -> bool:
    if summary is None:
        return False
    return any(
        value is not None
        for value in (
            summary.total_tokens,
            summary.total_tool_calls,
            summary.total_retries,
            summary.total_latency_ms,
            summary.estimated_cost_microusd,
        )
    )


def _comparison_state(
    baseline_observed: bool,
    candidate_observed: bool,
) -> UsageComparisonState:
    if baseline_observed and candidate_observed:
        return "observed"
    if baseline_observed:
        return "candidate_not_observed"
    if candidate_observed:
        return "baseline_not_observed"
    return "not_observed"


def _comparison_currency(
    baseline: UsageSummary | None,
    candidate: UsageSummary | None,
) -> str:
    if baseline is not None and candidate is not None and baseline.currency == candidate.currency:
        return baseline.currency
    if candidate is not None:
        return candidate.currency
    if baseline is not None:
        return baseline.currency
    return "USD"


def _cost_comparison_limitation(
    baseline: UsageSummary,
    candidate: UsageSummary,
) -> str | None:
    if baseline.currency != candidate.currency:
        return "Declared estimated cost was not compared because currencies differ."
    if baseline.currency != "USD":
        return "Declared estimated cost was not compared because currency is not USD."
    if not baseline.cost_basis_ids or not candidate.cost_basis_ids:
        return (
            "Declared estimated cost was not compared because cost basis was not "
            "declared for both sides."
        )
    if baseline.cost_basis_ids != candidate.cost_basis_ids:
        return "Declared estimated cost was not compared because cost bases differ."
    if not baseline.pricing_snapshot_ids or not candidate.pricing_snapshot_ids:
        return (
            "Declared estimated cost was not compared because pricing snapshot IDs "
            "were not declared for both sides."
        )
    if baseline.pricing_snapshot_ids != candidate.pricing_snapshot_ids:
        return "Declared estimated cost was not compared because pricing snapshots differ."
    if not baseline.pricing_snapshot_digests or not candidate.pricing_snapshot_digests:
        return (
            "Declared estimated cost was not compared because pricing snapshot digests "
            "were not declared for both sides."
        )
    if baseline.pricing_snapshot_digests != candidate.pricing_snapshot_digests:
        return "Declared estimated cost was not compared because pricing snapshot digests differ."
    return None


def _metric_comparison_limitation(
    baseline: UsageSummary,
    candidate: UsageSummary,
    field_name: str,
) -> str | None:
    if getattr(baseline, field_name) is None or getattr(candidate, field_name) is None:
        return None
    if (
        baseline.schema_version != "0.6.6"
        or candidate.schema_version != "0.6.6"
        or baseline.aggregation_method != "sum_complete_fields_v2"
        or candidate.aggregation_method != "sum_complete_fields_v2"
        or baseline.coverage_basis is None
        or candidate.coverage_basis is None
        or baseline.source_count is None
        or candidate.source_count is None
        or baseline.coverage_counts is None
        or candidate.coverage_counts is None
    ):
        return (
            f"Measured usage {field_name} was not compared because both sides "
            "require schema_version 0.6.6 complete-coverage metadata."
        )
    if baseline.coverage_basis != candidate.coverage_basis:
        return f"Measured usage {field_name} was not compared because coverage bases differ."
    if baseline.source_count != candidate.source_count:
        return (
            f"Measured usage {field_name} was not compared because coverage source counts differ."
        )
    if baseline.source_count == 0:
        return (
            f"Measured usage {field_name} was not compared because coverage "
            "has no expected sources."
        )
    if (
        getattr(baseline.coverage_counts, field_name) != baseline.source_count
        or getattr(candidate.coverage_counts, field_name) != candidate.source_count
    ):
        return f"Measured usage {field_name} was not compared because coverage is incomplete."
    return None


def _metric_delta_pair(
    baseline: UsageSummary | None,
    candidate: UsageSummary | None,
    field_name: str,
    *,
    limitations: list[str],
) -> tuple[int | None, int | None]:
    if baseline is None or candidate is None:
        return None, None
    if getattr(baseline, field_name) is None or getattr(candidate, field_name) is None:
        return None, None
    coverage_limitation = _metric_comparison_limitation(
        baseline,
        candidate,
        field_name,
    )
    if coverage_limitation is not None:
        limitations.append(coverage_limitation)
        return None, None
    return (
        _delta_value(baseline, candidate, field_name),
        _delta_bps(
            baseline,
            candidate,
            field_name,
            limitations=limitations,
        ),
    )


def _delta_value(
    baseline: UsageSummary | None,
    candidate: UsageSummary | None,
    field_name: str,
) -> int | None:
    if baseline is None or candidate is None:
        return None
    baseline_value = getattr(baseline, field_name)
    candidate_value = getattr(candidate, field_name)
    if baseline_value is None or candidate_value is None:
        return None
    return int(candidate_value) - int(baseline_value)


def _delta_bps(
    baseline: UsageSummary | None,
    candidate: UsageSummary | None,
    field_name: str,
    *,
    limitations: list[str],
) -> int | None:
    if baseline is None or candidate is None:
        return None
    baseline_value = getattr(baseline, field_name)
    candidate_value = getattr(candidate, field_name)
    if baseline_value is None or candidate_value is None:
        return None
    baseline_int = int(baseline_value)
    candidate_int = int(candidate_value)
    delta = candidate_int - baseline_int
    if baseline_int == 0:
        if candidate_int == 0:
            return 0
        limitations.append(
            f"{field_name}_delta_bps was not computed because the baseline value is zero."
        )
        return None
    magnitude = abs(delta) * 10_000 // baseline_int
    return -magnitude if delta < 0 else magnitude


def _format_delta(label: str, value: int | None, bps: int | None) -> str | None:
    if value is None:
        return None
    suffix = "" if bps is None else f" ({bps:+d} bps)"
    return f"{label} {value:+d}{suffix}"
