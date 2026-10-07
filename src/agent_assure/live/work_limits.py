from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal

from agent_assure.io_limits import MAX_PERSISTED_OBSERVATIONS
from agent_assure.statistics.binomial_intervals import validate_clopper_pearson_work_budget

# These limits are part of the persisted live-analysis contract. Keep the
# iteration counts explicit rather than accepting artifact-controlled values.
LIVE_RATE_BOOTSTRAP_ITERATIONS = 2_000
LIVE_ICC_BOOTSTRAP_ITERATIONS = 1_000
LIVE_MONTE_CARLO_ITERATIONS = 10_000
LIVE_MAX_EXACT_PERMUTATION_CLUSTERS = 17

# Advanced endpoints are evaluated over every observation and may each request
# an ICC bootstrap. Outcome categories similarly create one rate series each.
# The caps preserve a generous protocol surface while preventing a bounded JSON
# document from expanding into thousands of statistical passes.
MAX_LIVE_ADVANCED_ENDPOINTS = 64
MAX_LIVE_OUTCOME_CATEGORIES = 64
# Monitoring plans and persisted diagnostics are likewise bounded before
# validators construct sets, indexes, or cross-window projections.
MAX_LIVE_MONITORING_ITEMS = 64

# One ICC bootstrap over the largest supported persisted RunSet defines an
# auditable conservative ceiling. Large RunSets remain supported by
# non-resampling methods; other expensive methods must fit this same budget.
MAX_LIVE_RESAMPLING_WORK = MAX_PERSISTED_OBSERVATIONS * LIVE_ICC_BOOTSTRAP_ITERATIONS


@dataclass(frozen=True, slots=True)
class LiveAnalysisWorkPlan:
    """Complete expensive-work plan for one live analysis transaction."""

    resampling_items: tuple[tuple[str, int], ...] = ()
    clopper_pearson_intervals: tuple[tuple[int, int, Decimal], ...] = ()


def combine_live_analysis_work_plans(
    *plans: LiveAnalysisWorkPlan,
) -> LiveAnalysisWorkPlan:
    """Combine subplans before enforcing either aggregate resource ceiling."""

    return LiveAnalysisWorkPlan(
        resampling_items=tuple(item for plan in plans for item in plan.resampling_items),
        clopper_pearson_intervals=tuple(
            interval for plan in plans for interval in plan.clopper_pearson_intervals
        ),
    )


def validate_live_analysis_work_plan(plan: LiveAnalysisWorkPlan) -> tuple[int, int]:
    """Validate all resampling and exact-tail work before any kernel executes."""

    if not isinstance(plan, LiveAnalysisWorkPlan):
        raise TypeError("live analysis work plan has an invalid type")
    resampling_work = validate_live_resampling_work(plan.resampling_items)
    exact_tail_work = validate_clopper_pearson_work_budget(plan.clopper_pearson_intervals)
    return resampling_work, exact_tail_work


def validate_live_resampling_work(
    work_items: Iterable[tuple[str, int]],
    *,
    maximum: int = MAX_LIVE_RESAMPLING_WORK,
) -> int:
    """Validate aggregate primitive resampling work before any kernel runs.

    A work unit is one sampled cluster value or one sign evaluation. The
    optional maximum exists for tests and stricter internal callers, but cannot
    raise the process-wide security ceiling.
    """

    if type(maximum) is not int or not 0 <= maximum <= MAX_LIVE_RESAMPLING_WORK:
        raise ValueError("live resampling maximum must be within the supported work ceiling")
    total = 0
    for label, units in work_items:
        if not isinstance(label, str) or not label:
            raise ValueError("live resampling work labels must be non-empty strings")
        if type(units) is not int or units < 0:
            raise ValueError("live resampling work units must be non-negative integers")
        if units > maximum - total:
            raise ValueError(
                "aggregate live resampling work exceeds the maximum supported work budget"
            )
        total += units
    return total


def validate_live_protocol_resampling_work(
    analysis_method: str,
    planned_clusters: int,
    *,
    baseline_mode: str = "concurrent_paired",
) -> int:
    """Reject a protocol whose declared resampling method exceeds safe work."""

    if type(planned_clusters) is not int or planned_clusters < 1:
        raise ValueError("planned live clusters must be a positive integer")
    if baseline_mode not in {"concurrent_paired", "fixed_reference"}:
        raise ValueError("live baseline mode is invalid for resampling work planning")
    if analysis_method == "paired_cluster_permutation_exact":
        if planned_clusters > LIVE_MAX_EXACT_PERMUTATION_CLUSTERS:
            raise ValueError(
                "paired exact permutation supports at most "
                f"{LIVE_MAX_EXACT_PERMUTATION_CLUSTERS} planned clusters"
            )
        work = (1 << planned_clusters) * planned_clusters
    elif analysis_method == "paired_cluster_permutation_monte_carlo":
        work = LIVE_MONTE_CARLO_ITERATIONS * planned_clusters
    elif analysis_method == "paired_cluster_bootstrap_percentile":
        # A concurrent paired bootstrap runs one rate bootstrap for each arm
        # plus the paired-difference bootstrap. A fixed reference has no
        # baseline-arm kernel.
        kernel_count = 2 if baseline_mode == "fixed_reference" else 3
        work = kernel_count * LIVE_RATE_BOOTSTRAP_ITERATIONS * planned_clusters
    else:
        work = 0
    return validate_live_resampling_work(((f"planned {analysis_method}", work),))


__all__ = [
    "LIVE_ICC_BOOTSTRAP_ITERATIONS",
    "LIVE_MAX_EXACT_PERMUTATION_CLUSTERS",
    "LIVE_MONTE_CARLO_ITERATIONS",
    "LIVE_RATE_BOOTSTRAP_ITERATIONS",
    "LiveAnalysisWorkPlan",
    "MAX_LIVE_ADVANCED_ENDPOINTS",
    "MAX_LIVE_MONITORING_ITEMS",
    "MAX_LIVE_OUTCOME_CATEGORIES",
    "MAX_LIVE_RESAMPLING_WORK",
    "combine_live_analysis_work_plans",
    "validate_live_analysis_work_plan",
    "validate_live_protocol_resampling_work",
    "validate_live_resampling_work",
]
