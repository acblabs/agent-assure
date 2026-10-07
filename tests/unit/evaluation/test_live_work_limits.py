from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import ValidationError

import agent_assure.live.advanced as live_advanced
import agent_assure.live.comparison as live_comparison
from agent_assure.io_limits import MAX_PERSISTED_OBSERVATIONS
from agent_assure.live.advanced import evaluate_statistical_invariants
from agent_assure.live.comparison import (
    _derive_paired_comparison_statistics_from_projection,
    _PairedEvidenceProjection,
    _validate_comparison_work_budget,
)
from agent_assure.live.statistics import _validate_live_evaluation_work_budget
from agent_assure.live.work_limits import (
    LIVE_MAX_EXACT_PERMUTATION_CLUSTERS,
    LIVE_MONTE_CARLO_ITERATIONS,
    LIVE_RATE_BOOTSTRAP_ITERATIONS,
    MAX_LIVE_ADVANCED_ENDPOINTS,
    MAX_LIVE_MONITORING_ITEMS,
    MAX_LIVE_OUTCOME_CATEGORIES,
    MAX_LIVE_RESAMPLING_WORK,
    validate_live_protocol_resampling_work,
    validate_live_resampling_work,
)
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.live import (
    AdvancedAnalysisPlan,
    DriftMetricPlan,
    DriftMonitoringPlan,
    LiveDriftReport,
    LiveObservationResult,
    LiveProtocolRecord,
    LiveTrajectoryReport,
    StatisticalEndpointPlan,
    TrajectoryAnalysisPlan,
)
from agent_assure.schema.run import AgentRunRecord


def _endpoint(index: int) -> StatisticalEndpointPlan:
    return StatisticalEndpointPlan(
        endpoint_id=f"endpoint-{index}",
        label=f"Endpoint {index}",
        endpoint_kind="expectation_pass_rate",
        role="primary" if index == 0 else "secondary",
        interpretation="exploratory",
        analysis_method="descriptive_rate",
    )


def test_advanced_endpoint_cap_accepts_limit_and_rejects_one_over() -> None:
    endpoints = tuple(_endpoint(index) for index in range(MAX_LIVE_ADVANCED_ENDPOINTS))

    plan = AdvancedAnalysisPlan(endpoints=endpoints)

    assert len(plan.endpoints) == MAX_LIVE_ADVANCED_ENDPOINTS
    with pytest.raises(ValidationError, match="at most 64 items"):
        AdvancedAnalysisPlan(endpoints=(*endpoints, _endpoint(MAX_LIVE_ADVANCED_ENDPOINTS)))


def test_monitoring_plan_cap_rejects_one_over() -> None:
    metric = DriftMetricPlan(
        metric="expectation_pass_rate",
        label="Expectation pass rate",
    )

    with pytest.raises(ValidationError, match="at most 64 items"):
        DriftMonitoringPlan(
            plan_id="over-limit-drift-plan",
            metrics=(metric,) * (MAX_LIVE_MONITORING_ITEMS + 1),
        )


def test_monitoring_report_schemas_publish_collection_caps() -> None:
    drift_properties = LiveDriftReport.model_json_schema()["properties"]
    trajectory_plan_properties = TrajectoryAnalysisPlan.model_json_schema()["properties"]
    trajectory_properties = LiveTrajectoryReport.model_json_schema()["properties"]

    assert drift_properties["windows"]["maxItems"] == MAX_PERSISTED_OBSERVATIONS
    assert drift_properties["diagnostics"]["maxItems"] == MAX_LIVE_MONITORING_ITEMS
    assert trajectory_plan_properties["invariants"]["maxItems"] == MAX_LIVE_MONITORING_ITEMS
    assert trajectory_properties["paths"]["maxItems"] == MAX_PERSISTED_OBSERVATIONS
    assert trajectory_properties["invariants"]["maxItems"] == MAX_LIVE_MONITORING_ITEMS
    assert trajectory_properties["history_dependent_checks"]["maxItems"] == (
        MAX_LIVE_MONITORING_ITEMS
    )
    assert trajectory_properties["event_processes"]["maxItems"] == 7


def _outcome_preflight_inputs(
    outcome_count: int,
) -> tuple[tuple[AgentRunRecord, ...], tuple[LiveObservationResult, ...]]:
    runs = tuple(
        SimpleNamespace(
            outcome=f"outcome-{index}",
            provider="provider",
            model="model",
            adapter_id="adapter",
            pipeline_id="pipeline",
        )
        for index in range(outcome_count)
    )
    observations = tuple(
        SimpleNamespace(observation_status="included") for _ in range(outcome_count)
    )
    return (
        cast(tuple[AgentRunRecord, ...], runs),
        cast(tuple[LiveObservationResult, ...], observations),
    )


def test_outcome_category_cap_accepts_limit_and_rejects_one_over() -> None:
    protocol = cast(
        LiveProtocolRecord,
        SimpleNamespace(analysis_method="paired_cluster_t_interval"),
    )
    runs, observations = _outcome_preflight_inputs(MAX_LIVE_OUTCOME_CATEGORIES)

    assert (
        _validate_live_evaluation_work_budget(
            runs,
            observations,
            protocol=protocol,
        )
        == 0
    )

    runs, observations = _outcome_preflight_inputs(MAX_LIVE_OUTCOME_CATEGORIES + 1)
    with pytest.raises(ValueError, match="outcome categories exceed"):
        _validate_live_evaluation_work_budget(
            runs,
            observations,
            protocol=protocol,
        )


def test_resampling_budget_accepts_exact_limit_and_rejects_one_over() -> None:
    assert (
        validate_live_resampling_work((("maximum supported operation", MAX_LIVE_RESAMPLING_WORK),))
        == MAX_LIVE_RESAMPLING_WORK
    )
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        validate_live_resampling_work((("over-budget operation", MAX_LIVE_RESAMPLING_WORK + 1),))


def test_resampling_budget_is_aggregate_across_kernels() -> None:
    left = MAX_LIVE_RESAMPLING_WORK // 2
    right = MAX_LIVE_RESAMPLING_WORK - left

    assert validate_live_resampling_work((("left", left), ("right", right))) == left + right
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        validate_live_resampling_work((("left", left), ("right", right + 1)))


def test_protocol_resampling_preflight_enforces_method_specific_boundaries() -> None:
    maximum_monte_carlo_clusters = MAX_LIVE_RESAMPLING_WORK // LIVE_MONTE_CARLO_ITERATIONS
    maximum_concurrent_bootstrap_clusters = MAX_LIVE_RESAMPLING_WORK // (
        3 * LIVE_RATE_BOOTSTRAP_ITERATIONS
    )
    maximum_fixed_bootstrap_clusters = MAX_LIVE_RESAMPLING_WORK // (
        2 * LIVE_RATE_BOOTSTRAP_ITERATIONS
    )

    assert (
        validate_live_protocol_resampling_work(
            "paired_cluster_permutation_exact",
            LIVE_MAX_EXACT_PERMUTATION_CLUSTERS,
        )
        == (1 << LIVE_MAX_EXACT_PERMUTATION_CLUSTERS) * LIVE_MAX_EXACT_PERMUTATION_CLUSTERS
    )
    with pytest.raises(ValueError, match="at most 17 planned clusters"):
        validate_live_protocol_resampling_work(
            "paired_cluster_permutation_exact",
            LIVE_MAX_EXACT_PERMUTATION_CLUSTERS + 1,
        )
    assert (
        validate_live_protocol_resampling_work(
            "paired_cluster_bootstrap_percentile",
            maximum_concurrent_bootstrap_clusters,
            baseline_mode="concurrent_paired",
        )
        == 3 * LIVE_RATE_BOOTSTRAP_ITERATIONS * maximum_concurrent_bootstrap_clusters
    )
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        validate_live_protocol_resampling_work(
            "paired_cluster_bootstrap_percentile",
            maximum_concurrent_bootstrap_clusters + 1,
            baseline_mode="concurrent_paired",
        )
    assert (
        validate_live_protocol_resampling_work(
            "paired_cluster_bootstrap_percentile",
            maximum_fixed_bootstrap_clusters,
            baseline_mode="fixed_reference",
        )
        == MAX_LIVE_RESAMPLING_WORK
    )
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        validate_live_protocol_resampling_work(
            "paired_cluster_bootstrap_percentile",
            maximum_fixed_bootstrap_clusters + 1,
            baseline_mode="fixed_reference",
        )
    assert (
        validate_live_protocol_resampling_work(
            "paired_cluster_permutation_monte_carlo",
            maximum_monte_carlo_clusters,
        )
        == LIVE_MONTE_CARLO_ITERATIONS * maximum_monte_carlo_clusters
    )
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        validate_live_protocol_resampling_work(
            "paired_cluster_permutation_monte_carlo",
            maximum_monte_carlo_clusters + 1,
        )
    assert (
        validate_live_protocol_resampling_work(
            "paired_cluster_t_interval",
            MAX_PERSISTED_OBSERVATIONS,
        )
        == 0
    )


def _comparison_projection(
    cluster_count: int,
    *,
    fixed_reference: bool = False,
) -> _PairedEvidenceProjection:
    baseline_values = (
        None
        if fixed_reference
        else tuple((f"cluster-{index:04d}", index % 2 == 0) for index in range(cluster_count))
    )
    candidate_values = tuple(
        (f"cluster-{index:04d}", index % 3 == 0) for index in range(cluster_count)
    )
    if fixed_reference:
        differences = tuple(
            Decimal("0.5") if passed else Decimal("-0.5") for _, passed in candidate_values
        )
    else:
        assert baseline_values is not None
        differences = tuple(
            Decimal(int(candidate_passed) - int(baseline_passed))
            for (_, baseline_passed), (_, candidate_passed) in zip(
                baseline_values,
                candidate_values,
                strict=True,
            )
        )
    return _PairedEvidenceProjection(
        baseline_values=baseline_values,
        candidate_values=candidate_values,
        differences=differences,
    )


def test_comparison_preflight_matches_monte_carlo_protocol_boundary() -> None:
    protocol = cast(
        LiveProtocolRecord,
        SimpleNamespace(analysis_method="paired_cluster_permutation_monte_carlo"),
    )
    maximum_clusters = MAX_LIVE_RESAMPLING_WORK // LIVE_MONTE_CARLO_ITERATIONS
    projection = _comparison_projection(maximum_clusters)

    expected_work = LIVE_MONTE_CARLO_ITERATIONS * len(projection.differences)
    assert expected_work <= MAX_LIVE_RESAMPLING_WORK
    assert expected_work + LIVE_MONTE_CARLO_ITERATIONS > MAX_LIVE_RESAMPLING_WORK
    assert (
        _validate_comparison_work_budget(
            projection,
            protocol=protocol,
            randomization_prerequisite_status="met",
        )
        == expected_work
    )

    with pytest.raises(ValueError, match="aggregate live resampling work"):
        _validate_comparison_work_budget(
            _comparison_projection(maximum_clusters + 1),
            protocol=protocol,
            randomization_prerequisite_status="met",
        )


def test_comparison_preflight_aggregates_both_arms_and_difference_bootstrap() -> None:
    protocol = cast(
        LiveProtocolRecord,
        SimpleNamespace(analysis_method="paired_cluster_bootstrap_percentile"),
    )
    maximum_clusters = MAX_LIVE_RESAMPLING_WORK // (3 * LIVE_RATE_BOOTSTRAP_ITERATIONS)
    projection = _comparison_projection(maximum_clusters)
    expected_work = 3 * LIVE_RATE_BOOTSTRAP_ITERATIONS * maximum_clusters

    assert expected_work <= MAX_LIVE_RESAMPLING_WORK
    assert expected_work + 3 * LIVE_RATE_BOOTSTRAP_ITERATIONS > MAX_LIVE_RESAMPLING_WORK
    assert (
        _validate_comparison_work_budget(
            projection,
            protocol=protocol,
            randomization_prerequisite_status=None,
        )
        == expected_work
    )
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        _validate_comparison_work_budget(
            _comparison_projection(maximum_clusters + 1),
            protocol=protocol,
            randomization_prerequisite_status=None,
        )

    maximum_fixed_clusters = MAX_LIVE_RESAMPLING_WORK // (2 * LIVE_RATE_BOOTSTRAP_ITERATIONS)
    fixed_projection = _comparison_projection(
        maximum_fixed_clusters,
        fixed_reference=True,
    )
    assert (
        _validate_comparison_work_budget(
            fixed_projection,
            protocol=protocol,
            randomization_prerequisite_status=None,
        )
        == MAX_LIVE_RESAMPLING_WORK
    )
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        _validate_comparison_work_budget(
            _comparison_projection(
                maximum_fixed_clusters + 1,
                fixed_reference=True,
            ),
            protocol=protocol,
            randomization_prerequisite_status=None,
        )


def test_comparison_preflight_rejects_before_any_statistical_kernel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = cast(
        LiveProtocolRecord,
        SimpleNamespace(analysis_method="paired_cluster_bootstrap_percentile"),
    )
    maximum_clusters = MAX_LIVE_RESAMPLING_WORK // (3 * LIVE_RATE_BOOTSTRAP_ITERATIONS)
    projection = _comparison_projection(maximum_clusters + 1)
    kernel_calls: list[str] = []

    def forbidden_rate_kernel(*_args: object, **_kwargs: object) -> object:
        kernel_calls.append("arm-rate")
        raise AssertionError("arm-rate kernel ran before aggregate work preflight")

    def forbidden_difference_kernel(*_args: object, **_kwargs: object) -> object:
        kernel_calls.append("difference")
        raise AssertionError("difference kernel ran before aggregate work preflight")

    monkeypatch.setattr(live_comparison, "_rate_from_values", forbidden_rate_kernel)
    monkeypatch.setattr(
        live_comparison,
        "_paired_cluster_difference_from_values",
        forbidden_difference_kernel,
    )
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        _derive_paired_comparison_statistics_from_projection(
            projection,
            protocol=protocol,
            randomization_prerequisite_status=None,
            randomization_prerequisite_limitations=(),
        )
    assert kernel_calls == []


def _aggregate_rate_and_icc_inputs(
    cluster_count: int,
) -> tuple[tuple[AgentRunRecord, ...], tuple[LiveObservationResult, ...]]:
    runs: list[SimpleNamespace] = []
    observations: list[SimpleNamespace] = []
    for cluster_index in range(cluster_count):
        for observation_index in range(2):
            excluded = cluster_index == 0 and observation_index == 0
            runs.append(
                SimpleNamespace(
                    outcome="constant-outcome",
                    provider="provider",
                    model="model",
                    adapter_id="adapter",
                    pipeline_id="pipeline",
                )
            )
            observations.append(
                SimpleNamespace(
                    cluster_id=f"cluster-{cluster_index}",
                    observation_status="excluded" if excluded else "included",
                    state=(GateState.pass_ if cluster_index % 2 == 0 else GateState.fail),
                    reason_codes=(),
                )
            )
    return (
        cast(tuple[AgentRunRecord, ...], tuple(runs)),
        cast(tuple[LiveObservationResult, ...], tuple(observations)),
    )


def test_evaluation_preflight_aggregates_rate_and_icc_bootstrap_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clusters = MAX_LIVE_RESAMPLING_WORK // (4 * LIVE_RATE_BOOTSTRAP_ITERATIONS)
    runs, observations = _aggregate_rate_and_icc_inputs(clusters)
    without_advanced = cast(
        LiveProtocolRecord,
        SimpleNamespace(
            analysis_method="paired_cluster_bootstrap_percentile",
            advanced_analysis_plan=None,
        ),
    )
    assert (
        _validate_live_evaluation_work_budget(
            runs,
            observations,
            protocol=without_advanced,
        )
        == MAX_LIVE_RESAMPLING_WORK
    )

    advanced_plan = AdvancedAnalysisPlan(endpoints=(_endpoint(0),))
    with_advanced = cast(
        LiveProtocolRecord,
        SimpleNamespace(
            analysis_method="paired_cluster_bootstrap_percentile",
            advanced_analysis_plan=advanced_plan,
        ),
    )

    def forbidden_icc_kernel(_counts: object) -> Decimal:
        raise AssertionError("ICC kernel ran before aggregate work preflight")

    monkeypatch.setattr(live_advanced, "_icc_from_counts", forbidden_icc_kernel)
    with pytest.raises(ValueError, match="aggregate live resampling work"):
        _validate_live_evaluation_work_budget(
            runs,
            observations,
            protocol=with_advanced,
        )


def test_exact_interval_collection_is_preflighted_before_first_kernel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reason_codes = (
        ReasonCode.EXPECTED_OUTCOME_MISMATCH,
        ReasonCode.FORBIDDEN_OUTCOME,
        ReasonCode.POLICY_FAILED,
    )
    endpoints = tuple(
        StatisticalEndpointPlan(
            endpoint_id=f"rare-{index}",
            label=f"Rare endpoint {index}",
            endpoint_kind="reason_code_rate",
            role="primary" if index == 0 else "secondary",
            interpretation="exploratory",
            analysis_method="clopper_pearson_exact_one_sided",
            reason_codes=(reason_code,),
            minimum_clusters=1,
            exposure_unit="independence_cluster",
        )
        for index, reason_code in enumerate(reason_codes)
    )
    advanced_plan = AdvancedAnalysisPlan(endpoints=endpoints)
    runs = cast(
        tuple[AgentRunRecord, ...],
        tuple(SimpleNamespace(outcome="constant-outcome") for _ in range(1_000)),
    )
    observations = cast(
        tuple[LiveObservationResult, ...],
        tuple(
            SimpleNamespace(
                cluster_id=f"cluster-{index}",
                observation_status="included",
                state=GateState.pass_,
                reason_codes=tuple(
                    reason_code
                    for threshold, reason_code in zip((499, 500, 501), reason_codes, strict=True)
                    if index < threshold
                ),
            )
            for index in range(1_000)
        ),
    )
    protocol = cast(
        LiveProtocolRecord,
        SimpleNamespace(
            analysis_method="paired_cluster_t_interval",
            advanced_analysis_plan=advanced_plan,
            confidence_level="0.950000",
        ),
    )
    kernel_calls = 0

    def forbidden_exact_kernel(*_args: object, **_kwargs: object) -> object:
        nonlocal kernel_calls
        kernel_calls += 1
        raise AssertionError("exact interval kernel ran before aggregate preflight")

    monkeypatch.setattr(
        live_advanced,
        "binomial_upper_bound_one_sided",
        forbidden_exact_kernel,
    )
    with pytest.raises(ValueError, match="aggregate Clopper-Pearson exact-tail work"):
        evaluate_statistical_invariants(runs, observations, protocol)
    assert kernel_calls == 0
