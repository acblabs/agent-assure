from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from itertools import pairwise
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.schema.common import GateState
from agent_assure.schema.live import (
    DriftAnalysisMethod,
    DriftComparabilityResult,
    DriftComparabilityStatus,
    DriftMetric,
    DriftMetricDiagnostic,
    DriftMetricPlan,
    DriftMonitoringPlan,
    DriftMonitoringStatus,
    DriftStateEstimate,
    DriftStationaritySignal,
    DriftWindowMetric,
    DriftWindowSummary,
    EndpointPrerequisiteStatus,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveObservationResult,
    LiveProtocolRecord,
)

_SIX_PLACES = Decimal("0.000001")
_MetricSource = Literal[
    "pooled_rate",
    "observation_rate",
    "distribution_p50",
    "distribution_total",
    "reason_code_rate",
]
_StateName = Literal["governance_health", "control_reliability", "drift_state"]
_BASE_LIMITATIONS = (
    "cross-window monitoring is a review signal and is not a release-verdict gate",
    "stationarity or drift signals do not establish safety, compliance, clinical "
    "validity, provider quality, or model intent",
    "latent-state summaries describe governance health, control reliability, or drift "
    "state from observable records only",
    "dependence review thresholds are policy heuristics and are not calibrated "
    "null false-positive rates",
)


def build_live_drift_report(
    reports: Sequence[LiveEvaluationReport],
    *,
    protocol: LiveProtocolRecord,
) -> LiveDriftReport:
    if not reports:
        raise ValueError("drift monitoring requires at least one live evaluation report")
    plan = protocol.drift_monitoring_plan or _default_monitoring_plan()
    protocol_digest = sha256_hexdigest(protocol)
    windows = tuple(
        _window_summary(report, window_index=index, plan=plan)
        for index, report in enumerate(reports)
    )
    comparability = _comparability(windows, protocol=protocol, protocol_digest=protocol_digest)
    diagnostics = tuple(
        _diagnostic(metric_plan, windows, comparability=comparability)
        for metric_plan in plan.metrics
    )
    monitoring_status = _monitoring_status(plan, comparability, diagnostics)
    starts = tuple(
        window.observation_window_start_utc
        for window in windows
        if window.observation_window_start_utc is not None
    )
    ends = tuple(
        window.observation_window_end_utc
        for window in windows
        if window.observation_window_end_utc is not None
    )
    first = reports[0]
    report_id = "live-drift-" + sha256_hexdigest(
        {
            "protocol_digest": protocol_digest,
            "drift_plan": plan,
            "runset_ids": [report.runset_id for report in reports],
        }
    )[:16]
    limitations = list(_BASE_LIMITATIONS)
    limitations.extend(comparability.limitations)
    if any(window.provider_version_unknown for window in windows):
        limitations.append(
            "one or more windows have unknown resolved provider-version metadata; "
            "version-specific drift interpretation is limited"
        )
    limitations.extend(plan.known_provider_version_unknowns)
    return LiveDriftReport(
        artifact_kind="live-drift-report",
        report_id=report_id,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        drift_plan_id=plan.plan_id,
        suite_id=first.suite_id,
        suite_version=first.suite_version,
        ordering_variable=plan.ordering_variable,
        interpretation=plan.interpretation,
        state=GateState.not_evaluated,
        monitoring_status=monitoring_status,
        observation_window_start_utc=_timestamp_bound(starts, pick="min"),
        observation_window_end_utc=_timestamp_bound(ends, pick="max"),
        comparability=comparability,
        windows=windows,
        diagnostics=diagnostics,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _default_monitoring_plan() -> DriftMonitoringPlan:
    methods: tuple[DriftAnalysisMethod, ...] = (
        "descriptive_trend",
        "lag1_autocorrelation",
        "ar1_summary",
        "state_space_ewma",
    )
    return DriftMonitoringPlan(
        artifact_kind="drift-monitoring-plan",
        plan_id="default-exploratory-live-drift",
        interpretation="exploratory",
        ordering_variable="window_index",
        comparability_mode="strict_protocol_digest",
        metrics=(
            DriftMetricPlan(
                artifact_kind="drift-metric-plan",
                metric="expectation_pass_rate",
                label="Expectation pass rate",
                analysis_methods=methods,
                minimum_windows=6,
                slope_review_threshold="0.050000",
                step_review_threshold="0.100000",
            ),
            DriftMetricPlan(
                artifact_kind="drift-metric-plan",
                metric="exclusion_rate",
                label="Exclusion rate",
                analysis_methods=methods,
                minimum_windows=6,
                slope_review_threshold="0.020000",
                step_review_threshold="0.050000",
            ),
            DriftMetricPlan(
                artifact_kind="drift-metric-plan",
                metric="retry_rate",
                label="Retry rate",
                analysis_methods=methods,
                minimum_windows=6,
                slope_review_threshold="0.020000",
                step_review_threshold="0.050000",
            ),
            DriftMetricPlan(
                artifact_kind="drift-metric-plan",
                metric="rate_limit_rate",
                label="Rate-limit rate",
                analysis_methods=methods,
                minimum_windows=6,
                slope_review_threshold="0.010000",
                step_review_threshold="0.020000",
            ),
            DriftMetricPlan(
                artifact_kind="drift-metric-plan",
                metric="latency_p50_ms",
                label="P50 latency ms",
                analysis_methods=methods,
                minimum_windows=6,
                slope_review_threshold="25.000000",
                step_review_threshold="100.000000",
            ),
            DriftMetricPlan(
                artifact_kind="drift-metric-plan",
                metric="cost_total_usd",
                label="Total estimated cost USD",
                analysis_methods=methods,
                minimum_windows=6,
                slope_review_threshold="0.010000",
                step_review_threshold="0.050000",
            ),
        ),
    )


def _window_summary(
    report: LiveEvaluationReport,
    *,
    window_index: int,
    plan: DriftMonitoringPlan,
) -> DriftWindowSummary:
    starts = tuple(
        observation.started_at_utc
        for observation in report.observations
        if observation.started_at_utc is not None
    )
    ends = tuple(
        observation.completed_at_utc
        for observation in report.observations
        if observation.completed_at_utc is not None
    )
    provider_version_keys, provider_version_unknown = _provider_version_keys(report.observations)
    return DriftWindowSummary(
        artifact_kind="drift-window-summary",
        window_id=f"window-{window_index:04d}",
        window_index=window_index,
        runset_id=report.runset_id,
        suite_id=report.suite_id,
        suite_version=report.suite_version,
        protocol_id=report.protocol_id,
        protocol_digest=report.protocol_digest,
        baseline_mode=report.baseline_mode,
        analysis_method=report.analysis_method,
        observation_window_start_utc=_timestamp_bound(starts, pick="min"),
        observation_window_end_utc=_timestamp_bound(ends, pick="max"),
        observations=report.overall.observations,
        included_observations=report.overall.included_observations,
        excluded_observations=report.overall.excluded_observations,
        provider_version_unknown=provider_version_unknown,
        provider_version_keys=provider_version_keys,
        tool_schema_digests=tuple(
            sorted({observation.tool_schema_digest for observation in report.observations})
        ),
        policy_bundle_digests=tuple(
            sorted({observation.policy_bundle_digest for observation in report.observations})
        ),
        metrics=tuple(_metric_value(report, metric_plan) for metric_plan in plan.metrics),
    )


def _provider_version_keys(
    observations: tuple[LiveObservationResult, ...],
) -> tuple[tuple[str, ...], bool]:
    keys: set[str] = set()
    unknown = False
    for observation in observations:
        resolved = observation.resolved_model
        api = observation.provider_api_version
        sdk = observation.provider_sdk
        if resolved is None and api is None and sdk is None:
            unknown = True
        keys.add(
            "|".join(
                (
                    f"provider={observation.provider or 'unknown'}",
                    f"model={observation.model or 'unknown'}",
                    f"resolved={resolved or 'unknown'}",
                    f"api={api or 'unknown'}",
                    f"sdk={sdk or 'unknown'}",
                    f"region={observation.provider_region or 'unknown'}",
                )
            )
        )
    return tuple(sorted(keys)), unknown


def _metric_value(
    report: LiveEvaluationReport,
    metric_plan: DriftMetricPlan,
) -> DriftWindowMetric:
    metric = metric_plan.metric
    if metric == "expectation_pass_rate":
        rate = report.overall.expectation_pass_rate
        return _window_metric(
            metric_plan,
            value=Decimal(rate.rate),
            numerator=rate.numerator,
            denominator=rate.denominator,
            source="pooled_rate",
        )
    if metric == "exclusion_rate":
        rate = report.overall.exclusion_rate
        return _window_metric(
            metric_plan,
            value=Decimal(rate.rate),
            numerator=rate.numerator,
            denominator=rate.denominator,
            source="observation_rate",
        )
    if metric == "reason_code_rate":
        reason_codes = set(metric_plan.reason_codes)
        included = tuple(
            observation
            for observation in report.observations
            if observation.observation_status == "included"
        )
        numerator = sum(
            1 for observation in included if reason_codes.intersection(observation.reason_codes)
        )
        denominator = len(included)
        return _window_metric(
            metric_plan,
            value=_rate_decimal(numerator, denominator),
            numerator=numerator,
            denominator=denominator,
            source="reason_code_rate",
        )
    if metric == "retry_rate":
        numerator = sum(1 for observation in report.observations if (observation.retry_count or 0))
        denominator = len(report.observations)
        return _window_metric(
            metric_plan,
            value=_rate_decimal(numerator, denominator),
            numerator=numerator,
            denominator=denominator,
            source="observation_rate",
        )
    if metric == "rate_limit_rate":
        numerator = sum(
            1 for observation in report.observations if (observation.rate_limit_events or 0)
        )
        denominator = len(report.observations)
        return _window_metric(
            metric_plan,
            value=_rate_decimal(numerator, denominator),
            numerator=numerator,
            denominator=denominator,
            source="observation_rate",
        )
    if metric == "latency_p50_ms":
        value = (
            Decimal(report.overall.latency_ms.p50)
            if report.overall.latency_ms.p50 is not None
            else None
        )
        return _window_metric(
            metric_plan,
            value=value,
            numerator=None,
            denominator=report.overall.latency_ms.count,
            source="distribution_p50",
        )
    if metric == "cost_total_usd":
        value = (
            Decimal(report.overall.estimated_cost_usd.total)
            if report.overall.estimated_cost_usd.total is not None
            else None
        )
        return _window_metric(
            metric_plan,
            value=value,
            numerator=None,
            denominator=report.overall.estimated_cost_usd.count,
            source="distribution_total",
        )
    raise ValueError(f"unsupported drift metric: {metric}")


def _window_metric(
    metric_plan: DriftMetricPlan,
    *,
    value: Decimal | None,
    numerator: int | None,
    denominator: int | None,
    source: _MetricSource,
) -> DriftWindowMetric:
    return DriftWindowMetric(
        artifact_kind="drift-window-metric",
        metric=metric_plan.metric,
        label=metric_plan.label,
        reason_codes=metric_plan.reason_codes,
        value=_decimal(value) if value is not None else None,
        numerator=numerator,
        denominator=denominator,
        source=source,
    )


def _comparability(
    windows: tuple[DriftWindowSummary, ...],
    *,
    protocol: LiveProtocolRecord,
    protocol_digest: str,
) -> DriftComparabilityResult:
    suite_matches = len({(window.suite_id, window.suite_version) for window in windows}) == 1
    suite_matches = (
        suite_matches
        and windows[0].suite_id == protocol.suite_id
        and windows[0].suite_version == protocol.suite_version
    )
    baseline_mode_matches = len({window.baseline_mode for window in windows}) == 1
    baseline_mode_matches = (
        baseline_mode_matches and windows[0].baseline_mode == protocol.baseline_mode
    )
    analysis_method_matches = len({window.analysis_method for window in windows}) == 1
    analysis_method_matches = (
        analysis_method_matches and windows[0].analysis_method == protocol.analysis_method
    )
    protocol_digest_matches = all(
        window.protocol_digest == protocol_digest for window in windows
    )
    tool_schema_digest_matches = all(
        window.tool_schema_digests == (protocol.tool_schema_digest,) for window in windows
    )
    policy_bundle_digest_matches = all(
        window.policy_bundle_digests == (protocol.policy_bundle_digest,) for window in windows
    )
    material_fields_match = all(
        (
            suite_matches,
            baseline_mode_matches,
            analysis_method_matches,
            tool_schema_digest_matches,
            policy_bundle_digest_matches,
        )
    )
    failures: list[str] = []
    limitations: list[str] = []
    if not suite_matches:
        failures.append("suite identity or version differs across monitoring windows")
    if not baseline_mode_matches:
        failures.append("baseline mode differs across monitoring windows")
    if not analysis_method_matches:
        failures.append("analysis method differs across monitoring windows")
    if not tool_schema_digest_matches:
        failures.append("tool-schema digest differs across monitoring windows")
    if not policy_bundle_digest_matches:
        failures.append("policy-bundle digest differs across monitoring windows")
    if not protocol_digest_matches:
        failures.append("one or more windows are not bound to the reference protocol digest")
    ordering_failures, ordering_limitations = _ordering_findings(windows, protocol)
    failures.extend(ordering_failures)
    limitations.extend(ordering_limitations)
    plan = protocol.drift_monitoring_plan
    comparability_mode = (
        plan.comparability_mode if plan is not None else "strict_protocol_digest"
    )
    allow_sensitivity = (
        plan.allow_bounded_sensitivity_on_comparability_failure if plan is not None else False
    )
    hard_failures = [
        failure for failure in failures if "reference protocol digest" not in failure
    ]
    status: DriftComparabilityStatus
    if hard_failures:
        status = "invalid"
    elif protocol_digest_matches:
        status = "pass"
    elif comparability_mode == "material_fields" or allow_sensitivity:
        status = "exploratory"
        limitations.append(
            "protocol digests differ; drift inference is limited to a bounded "
            "sensitivity review over matching material report fields"
        )
    else:
        status = "invalid"
    if len(windows) < 2:
        status = "invalid"
        failures.append("cross-window drift monitoring requires at least two windows")
    return DriftComparabilityResult(
        artifact_kind="drift-comparability-result",
        status=status,
        compared_windows=len(windows),
        suite_matches=suite_matches,
        baseline_mode_matches=baseline_mode_matches,
        analysis_method_matches=analysis_method_matches,
        protocol_digest_matches=protocol_digest_matches,
        material_fields_match=material_fields_match,
        tool_schema_digest_matches=tool_schema_digest_matches,
        policy_bundle_digest_matches=policy_bundle_digest_matches,
        reference_protocol_digest=protocol_digest,
        suite_id=protocol.suite_id,
        suite_version=protocol.suite_version,
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        failures=tuple(dict.fromkeys(failures)),
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _ordering_findings(
    windows: tuple[DriftWindowSummary, ...],
    protocol: LiveProtocolRecord,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    plan = protocol.drift_monitoring_plan
    ordering_variable = plan.ordering_variable if plan is not None else "window_index"
    failures: list[str] = []
    limitations: list[str] = []
    missing_windows: list[str] = []
    invalid_windows: list[str] = []
    parsed_rows: list[tuple[str, datetime]] = []
    for window in windows:
        timestamp = window.observation_window_start_utc
        if timestamp is None:
            missing_windows.append(window.window_id)
            continue
        parsed = _parse_timestamp(timestamp)
        if parsed is None:
            invalid_windows.append(window.window_id)
            continue
        parsed_rows.append((window.window_id, parsed))
    if missing_windows:
        missing = ", ".join(missing_windows)
        if ordering_variable == "window_start_utc":
            failures.append(
                "window_start_utc ordering requires a start timestamp on every window; "
                f"missing windows: {missing}"
            )
        else:
            limitations.append(
                "one or more windows lack start timestamps; input window_index order is "
                f"treated as authoritative; missing windows: {missing}"
            )
    if invalid_windows:
        failures.append(
            "window start timestamp is not timezone-aware ISO-8601; invalid windows: "
            + ", ".join(invalid_windows)
        )
    for left, right in pairwise(parsed_rows):
        if right[1] < left[1]:
            failures.append(
                "observation windows are not nondecreasing by start timestamp between "
                f"{left[0]} and {right[0]}"
            )
    if (
        ordering_variable == "window_index"
        and parsed_rows
        and not failures
        and not missing_windows
    ):
        limitations.append(
            "input window order is authoritative; start timestamps were checked for "
            "nondecreasing order"
        )
    return tuple(dict.fromkeys(failures)), tuple(dict.fromkeys(limitations))


def _diagnostic(
    metric_plan: DriftMetricPlan,
    windows: tuple[DriftWindowSummary, ...],
    *,
    comparability: DriftComparabilityResult,
) -> DriftMetricDiagnostic:
    values = _series(metric_plan, windows)
    missing_windows = len(windows) - len(values)
    observations = sum(denominator for _, _, denominator in values)
    prerequisite_status, prerequisite_limitations = _prerequisite_status(
        metric_plan,
        values,
        comparability=comparability,
    )
    limitations = list(prerequisite_limitations)
    series_values = tuple(value for _, value, _ in values)
    slope = _slope(values) if len(values) >= 2 else None
    max_step = _max_step(series_values) if len(series_values) >= 2 else None
    lag1 = None
    ar1_phi = None
    ar1_intercept = None
    ar1_variance = None
    state_estimate = None
    if "lag1_autocorrelation" in metric_plan.analysis_methods:
        if len(series_values) >= metric_plan.minimum_dependence_windows:
            lag1 = _lag1_autocorrelation(series_values)
        else:
            limitations.append(
                "lag-1 autocorrelation requires at least "
                f"{metric_plan.minimum_dependence_windows} ordered windows; observed "
                f"{len(series_values)}"
            )
        if len(series_values) >= metric_plan.minimum_dependence_windows and lag1 is None:
            limitations.append("lag-1 autocorrelation was not evaluated for this series")
    if "ar1_summary" in metric_plan.analysis_methods:
        if len(series_values) >= metric_plan.minimum_dependence_windows:
            ar1_phi, ar1_intercept, ar1_variance = _ar1_summary(series_values)
        else:
            limitations.append(
                "AR(1) summary requires at least "
                f"{metric_plan.minimum_dependence_windows} ordered windows; observed "
                f"{len(series_values)}"
            )
        if len(series_values) >= metric_plan.minimum_dependence_windows and ar1_phi is None:
            limitations.append("AR(1) summary was not evaluated for this series")
    if "state_space_ewma" in metric_plan.analysis_methods:
        if len(series_values) >= metric_plan.minimum_state_space_windows:
            state_estimate = _state_estimate(
                metric_plan,
                series_values,
                prerequisite_status=prerequisite_status,
            )
        else:
            limitations.append(
                "EWMA state summary requires at least "
                f"{metric_plan.minimum_state_space_windows} ordered windows; observed "
                f"{len(series_values)}"
            )
        if state_estimate is None:
            limitations.append("state-space EWMA summary was not evaluated for this series")
    stationarity_reasons = _stationarity_review_reasons(
        metric_plan,
        slope=slope,
        max_step=max_step,
    )
    dependence_reasons = _dependence_review_reasons(
        metric_plan,
        lag1=lag1,
        ar1_phi=ar1_phi,
    )
    review_reasons = (*stationarity_reasons, *dependence_reasons)
    stationarity_signal = _signal_from_reasons(prerequisite_status, stationarity_reasons)
    dependence_signal = _signal_from_reasons(prerequisite_status, dependence_reasons)
    return DriftMetricDiagnostic(
        artifact_kind="drift-metric-diagnostic",
        metric=metric_plan.metric,
        label=metric_plan.label,
        reason_codes=metric_plan.reason_codes,
        interpretation=metric_plan.interpretation,
        analysis_methods=metric_plan.analysis_methods,
        prerequisite_status=prerequisite_status,
        windows=len(values),
        observations=observations,
        missing_windows=missing_windows,
        first_value=_decimal(series_values[0]) if series_values else None,
        last_value=_decimal(series_values[-1]) if series_values else None,
        mean_value=_decimal(_mean(series_values)) if series_values else None,
        slope_per_window=_decimal(slope) if slope is not None else None,
        max_step_change=_decimal(max_step) if max_step is not None else None,
        lag1_autocorrelation=_signed_unit_decimal(lag1) if lag1 is not None else None,
        ar1_phi=_signed_unit_decimal(ar1_phi) if ar1_phi is not None else None,
        ar1_intercept=_decimal(ar1_intercept) if ar1_intercept is not None else None,
        ar1_innovation_variance=_decimal(ar1_variance) if ar1_variance is not None else None,
        stationarity_signal=stationarity_signal,
        dependence_signal=dependence_signal,
        review_reasons=review_reasons,
        state_estimate=state_estimate,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _series(
    metric_plan: DriftMetricPlan,
    windows: tuple[DriftWindowSummary, ...],
) -> tuple[tuple[int, Decimal, int], ...]:
    rows: list[tuple[int, Decimal, int]] = []
    for window in windows:
        metric = next(
            (
                candidate
                for candidate in window.metrics
                if candidate.metric == metric_plan.metric
                and candidate.reason_codes == metric_plan.reason_codes
            ),
            None,
        )
        if metric is None or metric.value is None:
            continue
        rows.append((window.window_index, Decimal(metric.value), metric.denominator or 0))
    return tuple(rows)


def _prerequisite_status(
    metric_plan: DriftMetricPlan,
    values: tuple[tuple[int, Decimal, int], ...],
    *,
    comparability: DriftComparabilityResult,
) -> tuple[EndpointPrerequisiteStatus, tuple[str, ...]]:
    limitations: list[str] = []
    if comparability.status == "invalid":
        return "invalid", ("comparability gate failed, so drift inference is invalid",)
    if len(values) < 2:
        return "invalid", ("fewer than two ordered windows were available",)
    if any(
        denominator < metric_plan.minimum_observations_per_window
        for _, _, denominator in values
    ):
        limitations.append("one or more windows are below the metric observation threshold")
    if len(values) < metric_plan.minimum_windows:
        limitations.append("ordered window count is below the metric threshold")
    if comparability.status == "exploratory":
        limitations.append("comparability is exploratory for this monitoring series")
    if limitations:
        return "exploratory", tuple(limitations)
    return "met", ()


def _stationarity_review_reasons(
    metric_plan: DriftMetricPlan,
    *,
    slope: Decimal | None,
    max_step: Decimal | None,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if slope is not None and abs(slope) >= Decimal(metric_plan.slope_review_threshold):
        reasons.append("absolute linear trend exceeds the metric review threshold")
    if max_step is not None and max_step >= Decimal(metric_plan.step_review_threshold):
        reasons.append("largest adjacent-window step exceeds the metric review threshold")
    return tuple(reasons)


def _dependence_review_reasons(
    metric_plan: DriftMetricPlan,
    *,
    lag1: Decimal | None,
    ar1_phi: Decimal | None,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if (
        lag1 is not None
        and abs(lag1) >= Decimal(metric_plan.autocorrelation_review_threshold)
    ):
        reasons.append("absolute lag-1 autocorrelation exceeds the metric review threshold")
    if ar1_phi is not None and abs(ar1_phi) >= Decimal(metric_plan.ar1_review_threshold):
        reasons.append("absolute AR(1) coefficient exceeds the metric review threshold")
    return tuple(reasons)


def _signal_from_reasons(
    prerequisite_status: EndpointPrerequisiteStatus,
    review_reasons: tuple[str, ...],
) -> DriftStationaritySignal:
    if prerequisite_status == "invalid":
        return "invalid"
    if review_reasons:
        return "review"
    return "none"


def _slope(values: tuple[tuple[int, Decimal, int], ...]) -> Decimal | None:
    if len(values) < 2:
        return None
    xs = tuple(Decimal(index) for index, _, _ in values)
    ys = tuple(value for _, value, _ in values)
    mean_x = _mean(xs)
    mean_y = _mean(ys)
    denominator = sum((x - mean_x) ** 2 for x in xs)
    if denominator == 0:
        return None
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    return numerator / denominator


def _max_step(values: tuple[Decimal, ...]) -> Decimal | None:
    if len(values) < 2:
        return None
    return max(abs(right - left) for left, right in pairwise(values))


def _lag1_autocorrelation(values: tuple[Decimal, ...]) -> Decimal | None:
    if len(values) < 3:
        return None
    mean_value = _mean(values)
    denominator = sum((value - mean_value) ** 2 for value in values)
    if denominator == 0:
        return None
    numerator = sum(
        (left - mean_value) * (right - mean_value)
        for left, right in pairwise(values)
    )
    return numerator / denominator


def _ar1_summary(
    values: tuple[Decimal, ...],
) -> tuple[Decimal | None, Decimal | None, Decimal | None]:
    if len(values) < 4:
        return None, None, None
    previous = values[:-1]
    current = values[1:]
    mean_previous = _mean(previous)
    mean_current = _mean(current)
    denominator = sum((value - mean_previous) ** 2 for value in previous)
    if denominator == 0:
        return None, None, None
    phi = sum(
        (prev - mean_previous) * (curr - mean_current)
        for prev, curr in zip(previous, current, strict=True)
    ) / denominator
    phi = max(Decimal("-1"), min(Decimal("1"), phi))
    intercept = mean_current - phi * mean_previous
    residuals = tuple(
        curr - (intercept + phi * prev)
        for prev, curr in zip(previous, current, strict=True)
    )
    variance = _mean(tuple(residual * residual for residual in residuals))
    return phi, intercept, variance


def _state_estimate(
    metric_plan: DriftMetricPlan,
    values: tuple[Decimal, ...],
    *,
    prerequisite_status: EndpointPrerequisiteStatus,
) -> DriftStateEstimate | None:
    if len(values) < 2:
        return None
    alpha = Decimal(metric_plan.state_space_alpha)
    level = values[0]
    residuals: list[Decimal] = []
    previous_level = level
    previous_smoothed = level
    for value in values[1:]:
        residuals.append(value - previous_level)
        previous_smoothed = level
        level = alpha * value + (Decimal("1") - alpha) * level
        previous_level = level
    drift = level - previous_smoothed
    variance = _mean(tuple(residual * residual for residual in residuals))
    return DriftStateEstimate(
        artifact_kind="drift-state-estimate",
        state_name=_state_name(metric_plan.metric),
        metric=metric_plan.metric,
        label=metric_plan.label,
        prerequisite_status=prerequisite_status,
        smoothing_alpha=_decimal(alpha),
        latest_level=_decimal(level),
        latest_drift_per_window=_decimal(drift),
        innovation_variance=_decimal(variance),
        limitations=(
            "EWMA state is an observable governance-control summary and is not a hidden "
            "model-state or intent claim",
        ),
    )


def _state_name(metric: DriftMetric) -> _StateName:
    if metric == "expectation_pass_rate":
        return "governance_health"
    if metric in {"reason_code_rate", "exclusion_rate", "retry_rate", "rate_limit_rate"}:
        return "control_reliability"
    return "drift_state"


def _monitoring_status(
    plan: DriftMonitoringPlan,
    comparability: DriftComparabilityResult,
    diagnostics: tuple[DriftMetricDiagnostic, ...],
) -> DriftMonitoringStatus:
    if comparability.status == "invalid":
        return "invalid"
    if plan.interpretation == "exploratory" or comparability.status == "exploratory":
        return "exploratory"
    if any(diagnostic.prerequisite_status != "met" for diagnostic in diagnostics):
        return "exploratory"
    return "valid"


def _rate_decimal(numerator: int, denominator: int) -> Decimal:
    if denominator == 0:
        return Decimal("0")
    return Decimal(numerator) / Decimal(denominator)


def _mean(values: tuple[Decimal, ...]) -> Decimal:
    if not values:
        return Decimal("0")
    return sum(values, Decimal("0")) / Decimal(len(values))


def _timestamp_bound(values: tuple[str, ...], *, pick: Literal["min", "max"]) -> str | None:
    if not values:
        return None
    parsed_rows = tuple(
        (parsed, value)
        for value in values
        if (parsed := _parse_timestamp(value)) is not None
    )
    if len(parsed_rows) != len(values):
        return None
    selected = min(parsed_rows, key=lambda row: row[0]) if pick == "min" else max(
        parsed_rows,
        key=lambda row: row[0],
    )
    return selected[1]


def _parse_timestamp(value: str) -> datetime | None:
    text = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _decimal(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    quantized = projected.quantize(_SIX_PLACES)
    if quantized == Decimal("-0.000000"):
        quantized = Decimal("0.000000")
    return f"{quantized:f}"


def _signed_unit_decimal(value: Decimal) -> str:
    return _decimal(max(Decimal("-1"), min(Decimal("1"), value)))
