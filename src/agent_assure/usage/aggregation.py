from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol

from agent_assure.schema.common import DigestHex
from agent_assure.schema.run import RunSet
from agent_assure.schema.usage import (
    UsageComparisonState,
    UsageLedger,
    UsageSegment,
    UsageSummary,
    UsageSummaryDelta,
    usage_segment_missingness,
    usage_summary_from_ledger,
    validate_usage_summary_consistency,
)


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
    currency: str
    cost_basis_ids: tuple[str, ...]
    pricing_snapshot_ids: tuple[str, ...]
    pricing_snapshot_digests: tuple[DigestHex, ...]
    cost_observation_count: int | None
    limitations: list[str]


def aggregate_usage_segments(segments: Iterable[UsageSegment]) -> UsageAggregation:
    segment_tuple = tuple(segments)
    ledger = UsageLedger(
        artifact_kind="usage-ledger",
        segments=segment_tuple,
        aggregation_method="sum_known_fields_v1",
        missingness=usage_segment_missingness(segment_tuple),
    )
    summary = usage_summary_from_ledger(ledger)
    return UsageAggregation(usage_ledger=ledger, usage_summary=summary)


def usage_summary_for_runset(runset: RunSet) -> UsageSummary | None:
    if runset.usage_ledger is not None:
        validate_usage_summary_consistency(
            runset.usage_ledger,
            runset.usage_summary,
            owner="run set",
        )
        return usage_summary_from_ledger(runset.usage_ledger)
    if runset.usage_summary is not None:
        return runset.usage_summary
    summaries = tuple(
        summary
        for run in runset.runs
        if (summary := _usage_summary_for_run(run)) is not None
    )
    if not summaries:
        return None
    return _summary_from_summaries(summaries)


def _usage_summary_for_run(run: _UsageBearingRun) -> UsageSummary | None:
    if run.usage_ledger is not None:
        validate_usage_summary_consistency(
            run.usage_ledger,
            run.usage_summary,
            owner="run record",
        )
        return usage_summary_from_ledger(run.usage_ledger)
    return run.usage_summary


def compare_usage_summaries(
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
    total_tokens_delta = _delta_value(baseline, candidate, "total_tokens")
    total_tokens_delta_bps = _delta_bps(
        baseline,
        candidate,
        "total_tokens",
        limitations=limitations,
    )
    total_tool_calls_delta = _delta_value(baseline, candidate, "total_tool_calls")
    total_tool_calls_delta_bps = _delta_bps(
        baseline,
        candidate,
        "total_tool_calls",
        limitations=limitations,
    )
    total_retries_delta = _delta_value(baseline, candidate, "total_retries")
    total_retries_delta_bps = _delta_bps(
        baseline,
        candidate,
        "total_retries",
        limitations=limitations,
    )
    total_latency_ms_delta = _delta_value(baseline, candidate, "total_latency_ms")
    total_latency_ms_delta_bps = _delta_bps(
        baseline,
        candidate,
        "total_latency_ms",
        limitations=limitations,
    )
    estimated_cost_microusd_delta: int | None = None
    estimated_cost_microusd_delta_bps: int | None = None
    if (
        baseline is not None
        and candidate is not None
        and baseline.estimated_cost_microusd is not None
        and candidate.estimated_cost_microusd is not None
    ):
        cost_limitation = _cost_comparison_limitation(baseline, candidate)
        if cost_limitation is None:
            estimated_cost_microusd_delta = (
                candidate.estimated_cost_microusd - baseline.estimated_cost_microusd
            )
            estimated_cost_microusd_delta_bps = _delta_bps(
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
        currency=currency,
        limitations=tuple(sorted(set(limitations))),
    )


def format_usage_delta(delta: UsageSummaryDelta) -> str:
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
    if delta.estimated_cost_microusd_delta is not None:
        bps = (
            ""
            if delta.estimated_cost_microusd_delta_bps is None
            else f" ({delta.estimated_cost_microusd_delta_bps:+d} bps)"
        )
        parts.append(
            "declared estimated cost delta "
            f"{delta.estimated_cost_microusd_delta:+d} micro-USD{bps}"
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
        total_tokens=_sum_known(summary.total_tokens for summary in summaries),
        total_tool_calls=_sum_known(summary.total_tool_calls for summary in summaries),
        total_retries=_sum_known(summary.total_retries for summary in summaries),
        total_latency_ms=_sum_known(summary.total_latency_ms for summary in summaries),
        estimated_cost_microusd=cost.estimated_cost_microusd,
        currency=cost.currency,
        cost_basis_ids=cost.cost_basis_ids,
        pricing_snapshot_ids=cost.pricing_snapshot_ids,
        pricing_snapshot_digests=cost.pricing_snapshot_digests,
        cost_observation_count=cost.cost_observation_count,
        limitations=tuple(sorted(set(limitations))),
    )


def _sum_known(values: Iterable[int | None]) -> int | None:
    known = tuple(value for value in values if value is not None)
    if not known:
        return None
    return sum(known)


def _sum_summary_cost(summaries: tuple[UsageSummary, ...]) -> _SummaryCostAggregation:
    cost_summaries = tuple(
        summary for summary in summaries if summary.estimated_cost_microusd is not None
    )
    if not cost_summaries:
        return _SummaryCostAggregation(
            None,
            summaries[0].currency if summaries else "USD",
            (),
            (),
            (),
            None,
            [],
        )
    currencies = {summary.currency for summary in cost_summaries}
    if len(currencies) != 1:
        return _SummaryCostAggregation(
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
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because pricing snapshot "
                "IDs differ."
            ],
        )
    snapshot_digest_sets = {summary.pricing_snapshot_digests for summary in cost_summaries}
    if len(snapshot_digest_sets) != 1:
        return _SummaryCostAggregation(
            None,
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because pricing snapshot "
                "digests differ."
            ],
        )
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
            sum(summary.estimated_cost_microusd or 0 for summary in cost_summaries),
            currency,
            next(iter(cost_basis_sets)),
            next(iter(snapshot_id_sets)),
            next(iter(snapshot_digest_sets)),
            cost_observation_count,
            limitations,
        )
    return _SummaryCostAggregation(
        sum(summary.estimated_cost_microusd or 0 for summary in cost_summaries),
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
        return (
            "Declared estimated cost was not compared because pricing snapshot digests differ."
        )
    return None


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
