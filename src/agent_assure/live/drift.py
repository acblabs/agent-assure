from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from itertools import pairwise
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.primitives import (
    decimal_string,
    mean_decimal,
    parse_timestamp,
    rate_decimal,
    signed_unit_decimal_string,
    with_live_decimal_context,
)
from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact
from agent_assure.schema.common import GateState
from agent_assure.schema.live import (
    LIVE_DRIFT_SOURCE_LINKAGE_LIMITATION,
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
)
_STATE_SPACE_LIMITATION = (
    "latent-state summaries describe governance health, control reliability, or drift "
    "state from observable records only"
)
_DEPENDENCE_LIMITATION = (
    "dependence review thresholds are policy heuristics and are not calibrated "
    "null false-positive rates"
)
_SOURCE_EVALUATION_INCOMPLETE_LIMITATION = (
    "one or more source evaluations are incomplete; confirmatory drift inference is disqualified"
)
_SOURCE_RUNSET_INCOMPLETE_LIMITATION = (
    "one or more source RunSets are incomplete; confirmatory drift inference is disqualified"
)
_SOURCE_EVALUATION_EXPLORATORY_LIMITATION = (
    "one or more source evaluations are exploratory; confirmatory drift inference is disqualified"
)
_SUPPORTED_ORDERING_VARIABLES = frozenset({"window_index", "window_start_utc"})


@with_live_decimal_context
def build_live_drift_report(
    reports: Sequence[LiveEvaluationReport],
    *,
    protocol: LiveProtocolRecord,
) -> LiveDriftReport:
    if not reports:
        raise ValueError("drift monitoring requires at least one live evaluation report")
    protocol = LiveProtocolRecord.model_validate(protocol.model_dump(mode="json", warnings="error"))
    _require_current_input(protocol, owner="drift protocol")
    plan = protocol.drift_monitoring_plan or _default_monitoring_plan()
    _require_supported_ordering(plan)
    reports = tuple(
        LiveEvaluationReport.model_validate(report.model_dump(mode="json", warnings="error"))
        for report in reports
    )
    for report in reports:
        _require_current_input(report, owner="drift source evaluation")
    protocol_digest = sha256_hexdigest(protocol)
    source_evaluation_digests = tuple(sha256_hexdigest(report) for report in reports)
    for report in reports:
        if report.suite_digest != protocol.suite_digest:
            raise ValueError("drift evaluation report suite_digest does not match protocol")
        if report.configuration_digest is None:
            raise ValueError("drift evaluation report is missing configuration_digest")
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
    report_id = _drift_report_id(
        protocol_digest=protocol_digest,
        plan=plan,
        source_evaluation_digests=source_evaluation_digests,
        windows=windows,
    )
    limitations = _drift_limitations(plan, comparability, windows)
    return LiveDriftReport(
        artifact_kind="live-drift-report",
        derivation_contract="agent-assure/live-drift/v1",
        report_id=report_id,
        source_evaluation_digests=source_evaluation_digests,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        protocol=protocol,
        drift_plan_id=plan.plan_id,
        drift_plan=plan,
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
        limitations=limitations,
    )


def verify_live_drift_report_derivation(report: LiveDriftReport) -> None:
    """Replay every persisted drift conclusion from its bound projection."""

    protocol = report.protocol
    plan = report.drift_plan
    if protocol is None or plan is None:
        raise ValueError("live drift derivation requires a bound protocol and plan")
    protocol_digest = sha256_hexdigest(protocol)
    if report.protocol_id != protocol.protocol_id or report.protocol_digest != protocol_digest:
        raise ValueError("live drift protocol identity does not match its bound protocol")
    effective_plan = protocol.drift_monitoring_plan or _default_monitoring_plan()
    _require_supported_ordering(effective_plan)
    if plan != effective_plan or report.drift_plan_id != effective_plan.plan_id:
        raise ValueError("live drift effective plan does not match its bound protocol")
    if report.ordering_variable != plan.ordering_variable:
        raise ValueError("live drift ordering variable does not match its plan")
    if report.interpretation != plan.interpretation:
        raise ValueError("live drift interpretation does not match its plan")
    if len(report.source_evaluation_digests) != len(report.windows):
        raise ValueError("live drift source digest count does not match its ordered windows")
    if len(report.source_evaluation_digests) != len(set(report.source_evaluation_digests)):
        raise ValueError("live drift source evaluation digests must be unique")
    runset_ids = tuple(window.runset_id for window in report.windows)
    if len(runset_ids) != len(set(runset_ids)):
        raise ValueError("live drift source windows must reference unique RunSets")
    if report.suite_id != protocol.suite_id or report.suite_version != protocol.suite_version:
        raise ValueError("live drift suite identity does not match its bound protocol")

    expected_comparability = _comparability(
        report.windows,
        protocol=protocol,
        protocol_digest=protocol_digest,
    )
    if report.comparability != expected_comparability:
        raise ValueError("live drift comparability does not match replayed source windows")
    expected_diagnostics = tuple(
        _diagnostic(metric_plan, report.windows, comparability=expected_comparability)
        for metric_plan in plan.metrics
    )
    if report.diagnostics != expected_diagnostics:
        raise ValueError("live drift diagnostics do not match replayed plan and windows")
    expected_status = _monitoring_status(plan, expected_comparability, expected_diagnostics)
    if report.monitoring_status != expected_status:
        raise ValueError("live drift monitoring status does not match replayed diagnostics")
    starts = tuple(
        window.observation_window_start_utc
        for window in report.windows
        if window.observation_window_start_utc is not None
    )
    ends = tuple(
        window.observation_window_end_utc
        for window in report.windows
        if window.observation_window_end_utc is not None
    )
    if report.observation_window_start_utc != _timestamp_bound(starts, pick="min"):
        raise ValueError("live drift start timestamp does not match source windows")
    if report.observation_window_end_utc != _timestamp_bound(ends, pick="max"):
        raise ValueError("live drift end timestamp does not match source windows")
    if report.limitations != _drift_limitations(plan, expected_comparability, report.windows):
        raise ValueError("live drift limitations do not match replayed derivation")
    expected_report_id = _drift_report_id(
        protocol_digest=protocol_digest,
        plan=plan,
        source_evaluation_digests=report.source_evaluation_digests,
        windows=report.windows,
    )
    if report.report_id != expected_report_id:
        raise ValueError("live drift report_id does not match its bound derivation inputs")


def verify_live_drift_report_sources(
    report: LiveDriftReport,
    source_reports: Sequence[LiveEvaluationReport],
    *,
    protocol: LiveProtocolRecord,
) -> None:
    """Resolve external digests and require an exact rebuild from trusted sources."""

    report = LiveDriftReport.model_validate(report.model_dump(mode="json", warnings="error"))
    _require_current_input(report, owner="drift report")
    protocol = LiveProtocolRecord.model_validate(protocol.model_dump(mode="json", warnings="error"))
    _require_current_input(protocol, owner="drift protocol")
    source_reports = tuple(
        LiveEvaluationReport.model_validate(source.model_dump(mode="json", warnings="error"))
        for source in source_reports
    )
    for source in source_reports:
        _require_current_input(source, owner="drift source evaluation")
    source_digests = tuple(sha256_hexdigest(source) for source in source_reports)
    if source_digests != report.source_evaluation_digests:
        raise ValueError(
            "live drift ordered source evaluation digests do not match trusted sources"
        )
    expected = build_live_drift_report(source_reports, protocol=protocol)
    if report != expected:
        raise ValueError("live drift report does not exactly match trusted-source rebuild")


def _drift_report_id(
    *,
    protocol_digest: str,
    plan: DriftMonitoringPlan,
    source_evaluation_digests: tuple[str, ...],
    windows: tuple[DriftWindowSummary, ...],
) -> str:
    return (
        "live-drift-"
        + sha256_hexdigest(
            {
                "protocol_digest": protocol_digest,
                "drift_plan": plan,
                "source_evaluation_digests": source_evaluation_digests,
                "windows": windows,
            }
        )[:16]
    )


def _drift_limitations(
    plan: DriftMonitoringPlan,
    comparability: DriftComparabilityResult,
    windows: tuple[DriftWindowSummary, ...],
) -> tuple[str, ...]:
    limitations = list(_BASE_LIMITATIONS)
    methods = {method for metric in plan.metrics for method in metric.analysis_methods}
    if "state_space_ewma" in methods:
        limitations.append(_STATE_SPACE_LIMITATION)
    if {"lag1_autocorrelation", "ar1_summary"}.intersection(methods):
        limitations.append(_DEPENDENCE_LIMITATION)
    limitations.append(LIVE_DRIFT_SOURCE_LINKAGE_LIMITATION)
    limitations.extend(comparability.limitations)
    if any(window.provider_version_unknown for window in windows):
        limitations.append(
            "one or more windows have unknown resolved provider-version metadata; "
            "version-specific drift interpretation is limited"
        )
    _, qualification_limitations = _source_evaluation_qualification(windows)
    limitations.extend(qualification_limitations)
    limitations.extend(plan.known_provider_version_unknowns)
    return tuple(dict.fromkeys(limitations))


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
        configuration_digest=report.configuration_digest,
        source_runset_completion_status=report.source_completion_status,
        source_evaluation_completion_status=report.completion_status,
        source_evaluation_exploratory=report.exploratory,
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
            value=Decimal(rate.rate) if rate.denominator > 0 else None,
            numerator=rate.numerator,
            denominator=rate.denominator,
            source="pooled_rate",
        )
    if metric == "exclusion_rate":
        rate = report.overall.exclusion_rate
        return _window_metric(
            metric_plan,
            value=Decimal(rate.rate) if rate.denominator > 0 else None,
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
            value=(rate_decimal(numerator, denominator) if denominator > 0 else None),
            numerator=numerator,
            denominator=denominator,
            source="reason_code_rate",
        )
    if metric == "retry_rate":
        numerator = sum(1 for observation in report.observations if (observation.retry_count or 0))
        denominator = len(report.observations)
        return _window_metric(
            metric_plan,
            value=(rate_decimal(numerator, denominator) if denominator > 0 else None),
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
            value=(rate_decimal(numerator, denominator) if denominator > 0 else None),
            numerator=numerator,
            denominator=denominator,
            source="observation_rate",
        )
    if metric == "latency_p50_ms":
        value = (
            Decimal(report.overall.latency_ms.p50)
            if (report.overall.latency_ms.count > 0 and report.overall.latency_ms.p50 is not None)
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
            if (
                report.overall.estimated_cost_usd.count > 0
                and report.overall.estimated_cost_usd.total is not None
            )
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
        value=decimal_string(value) if value is not None else None,
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
    configuration_digest_matches = len({window.configuration_digest for window in windows}) == 1
    protocol_digest_matches = all(window.protocol_digest == protocol_digest for window in windows)
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
            configuration_digest_matches,
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
    if not configuration_digest_matches:
        failures.append("execution configuration differs across monitoring windows")
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
    comparability_mode = plan.comparability_mode if plan is not None else "strict_protocol_digest"
    allow_sensitivity = (
        plan.allow_bounded_sensitivity_on_comparability_failure if plan is not None else False
    )
    hard_failures = [failure for failure in failures if "reference protocol digest" not in failure]
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
        configuration_digest_matches=configuration_digest_matches,
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
    if plan is not None:
        _require_supported_ordering(plan)
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
        parsed = parse_timestamp(timestamp)
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
        if ordering_variable == "window_start_utc" and right[1] <= left[1]:
            failures.append(
                "observation windows are not strictly increasing by start timestamp between "
                f"{left[0]} and {right[0]}"
            )
        elif right[1] < left[1]:
            failures.append(
                "observation windows are not nondecreasing by start timestamp between "
                f"{left[0]} and {right[0]}"
            )
    if ordering_variable == "window_index" and parsed_rows and not failures and not missing_windows:
        limitations.append(
            "input window order is authoritative; start timestamps were checked for "
            "nondecreasing order"
        )
    return tuple(dict.fromkeys(failures)), tuple(dict.fromkeys(limitations))


@with_live_decimal_context
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
        windows=windows,
        total_windows=len(windows),
        comparability=comparability,
    )
    limitations = list(prerequisite_limitations)
    series_values = tuple(value for _, value, _ in values)
    complete_ordered_series = len(values) == len(windows)
    slope = _slope(values) if len(values) >= 2 else None
    max_step = (
        _max_step(series_values) if complete_ordered_series and len(series_values) >= 2 else None
    )
    lag1 = None
    ar1_phi = None
    ar1_intercept = None
    ar1_variance = None
    ar1_stationary_fit_invalid = False
    state_estimate = None
    if "lag1_autocorrelation" in metric_plan.analysis_methods:
        if complete_ordered_series and len(series_values) >= metric_plan.minimum_dependence_windows:
            lag1 = _lag1_autocorrelation(series_values)
        elif complete_ordered_series:
            limitations.append(
                "lag-1 autocorrelation requires at least "
                f"{metric_plan.minimum_dependence_windows} ordered windows; observed "
                f"{len(series_values)}"
            )
        if (
            complete_ordered_series
            and len(series_values) >= metric_plan.minimum_dependence_windows
            and lag1 is None
        ):
            limitations.append("lag-1 autocorrelation was not evaluated for this series")
    if "ar1_summary" in metric_plan.analysis_methods:
        if complete_ordered_series and len(series_values) >= metric_plan.minimum_dependence_windows:
            (
                ar1_phi,
                ar1_intercept,
                ar1_variance,
                ar1_stationary_fit_invalid,
            ) = _ar1_summary(series_values)
        elif complete_ordered_series:
            limitations.append(
                "AR(1) summary requires at least "
                f"{metric_plan.minimum_dependence_windows} ordered windows; observed "
                f"{len(series_values)}"
            )
        if ar1_stationary_fit_invalid:
            limitations.append(
                "raw AR(1) coefficient magnitude was at least one; stationary AR(1) "
                "fitted statistics were suppressed"
            )
        if (
            complete_ordered_series
            and len(series_values) >= metric_plan.minimum_dependence_windows
            and ar1_phi is None
            and not ar1_stationary_fit_invalid
        ):
            limitations.append("AR(1) summary was not evaluated for this series")
    if "state_space_ewma" in metric_plan.analysis_methods:
        if (
            complete_ordered_series
            and len(series_values) >= metric_plan.minimum_state_space_windows
        ):
            state_estimate = _state_estimate(
                metric_plan,
                series_values,
                prerequisite_status=prerequisite_status,
            )
        elif complete_ordered_series:
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
    dependence_declared = bool(
        {"lag1_autocorrelation", "ar1_summary"}.intersection(metric_plan.analysis_methods)
    )
    dependence_reasons = (
        _dependence_review_reasons(
            metric_plan,
            lag1=lag1,
            ar1_phi=ar1_phi,
            ar1_stationary_fit_invalid=ar1_stationary_fit_invalid,
        )
        if dependence_declared
        else ()
    )
    review_reasons = (*stationarity_reasons, *dependence_reasons)
    stationarity_signal = _signal_from_reasons(prerequisite_status, stationarity_reasons)
    dependence_signal = (
        _signal_from_reasons(prerequisite_status, dependence_reasons)
        if dependence_declared
        else "not_evaluated"
    )
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
        first_value=decimal_string(series_values[0]) if series_values else None,
        last_value=decimal_string(series_values[-1]) if series_values else None,
        mean_value=decimal_string(mean_decimal(series_values)) if series_values else None,
        slope_per_window=decimal_string(slope) if slope is not None else None,
        max_step_change=decimal_string(max_step) if max_step is not None else None,
        lag1_autocorrelation=(signed_unit_decimal_string(lag1) if lag1 is not None else None),
        ar1_phi=signed_unit_decimal_string(ar1_phi) if ar1_phi is not None else None,
        ar1_intercept=decimal_string(ar1_intercept) if ar1_intercept is not None else None,
        ar1_innovation_variance=(
            decimal_string(ar1_variance) if ar1_variance is not None else None
        ),
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
    windows: tuple[DriftWindowSummary, ...],
    total_windows: int,
    comparability: DriftComparabilityResult,
) -> tuple[EndpointPrerequisiteStatus, tuple[str, ...]]:
    limitations: list[str] = []
    if comparability.status == "invalid":
        return "invalid", ("comparability gate failed, so drift inference is invalid",)
    invalid = False
    if len(values) != total_windows:
        limitations.append(
            "one or more declared metric windows are missing; adjacency, dependence, and "
            "state-space diagnostics were not evaluated across the gap"
        )
        if metric_plan.interpretation == "confirmatory":
            invalid = True
    if len(values) < 2:
        limitations.append("fewer than two ordered windows were available")
        invalid = True
    source_qualified, qualification_limitations = _source_evaluation_qualification(windows)
    limitations.extend(qualification_limitations)
    if not source_qualified and metric_plan.interpretation == "confirmatory":
        invalid = True
    if invalid:
        return "invalid", tuple(dict.fromkeys(limitations))
    if any(
        denominator < metric_plan.minimum_observations_per_window for _, _, denominator in values
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
    ar1_stationary_fit_invalid: bool,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if ar1_stationary_fit_invalid:
        reasons.append("raw AR(1) coefficient magnitude is outside the stationary range")
    if lag1 is not None and abs(lag1) >= Decimal(metric_plan.autocorrelation_review_threshold):
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


@with_live_decimal_context
def _slope(values: tuple[tuple[int, Decimal, int], ...]) -> Decimal | None:
    if len(values) < 2:
        return None
    if any(observation_count <= 0 for _, _, observation_count in values):
        return None
    weighted = tuple(
        (Decimal(index), value, Decimal(observation_count))
        for index, value, observation_count in values
    )
    total_weight = sum((weight for _, _, weight in weighted), Decimal("0"))
    mean_x = sum((weight * x for x, _, weight in weighted), Decimal("0")) / total_weight
    mean_y = sum((weight * y for _, y, weight in weighted), Decimal("0")) / total_weight
    denominator = sum(
        (weight * (x - mean_x) ** 2 for x, _, weight in weighted),
        Decimal("0"),
    )
    if denominator == 0:
        return None
    numerator = sum(
        (weight * (x - mean_x) * (y - mean_y) for x, y, weight in weighted),
        Decimal("0"),
    )
    return numerator / denominator


@with_live_decimal_context
def _max_step(values: tuple[Decimal, ...]) -> Decimal | None:
    if len(values) < 2:
        return None
    return max(abs(right - left) for left, right in pairwise(values))


@with_live_decimal_context
def _lag1_autocorrelation(values: tuple[Decimal, ...]) -> Decimal | None:
    if len(values) < 3:
        return None
    mean_value = mean_decimal(values)
    denominator = sum((value - mean_value) ** 2 for value in values)
    if denominator == 0:
        return None
    numerator = sum((left - mean_value) * (right - mean_value) for left, right in pairwise(values))
    return numerator / denominator


@with_live_decimal_context
def _ar1_summary(
    values: tuple[Decimal, ...],
) -> tuple[Decimal | None, Decimal | None, Decimal | None, bool]:
    if len(values) < 4:
        return None, None, None, False
    # Descriptive AR(1) screen only: lag and lead means are estimated separately,
    # and residual variance is a simple mean-square diagnostic rather than a
    # formal small-sample time-series estimator.
    previous = values[:-1]
    current = values[1:]
    mean_previous = mean_decimal(previous)
    mean_current = mean_decimal(current)
    denominator = sum((value - mean_previous) ** 2 for value in previous)
    if denominator == 0:
        return None, None, None, False
    phi = (
        sum(
            (prev - mean_previous) * (curr - mean_current)
            for prev, curr in zip(previous, current, strict=True)
        )
        / denominator
    )
    if abs(phi) >= Decimal("1"):
        return None, None, None, True
    intercept = mean_current - phi * mean_previous
    residuals = tuple(
        curr - (intercept + phi * prev) for prev, curr in zip(previous, current, strict=True)
    )
    variance = mean_decimal(tuple(residual * residual for residual in residuals))
    return phi, intercept, variance, False


@with_live_decimal_context
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
    variance = mean_decimal(tuple(residual * residual for residual in residuals))
    return DriftStateEstimate(
        artifact_kind="drift-state-estimate",
        state_name=_state_name(metric_plan.metric),
        metric=metric_plan.metric,
        label=metric_plan.label,
        prerequisite_status=prerequisite_status,
        smoothing_alpha=decimal_string(alpha),
        latest_level=decimal_string(level),
        latest_drift_per_window=decimal_string(drift),
        innovation_variance=decimal_string(variance),
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
    authoritative = (
        diagnostics
        if plan.interpretation == "exploratory"
        else tuple(
            diagnostic for diagnostic in diagnostics if diagnostic.interpretation == "confirmatory"
        )
    )
    if not authoritative:
        return "invalid"
    if any(diagnostic.prerequisite_status == "invalid" for diagnostic in authoritative):
        return "invalid"
    if plan.interpretation == "exploratory" or comparability.status == "exploratory":
        return "exploratory"
    if any(diagnostic.prerequisite_status != "met" for diagnostic in authoritative):
        return "exploratory"
    return "valid"


def _source_evaluation_qualification(
    windows: tuple[DriftWindowSummary, ...],
) -> tuple[bool, tuple[str, ...]]:
    limitations: list[str] = []
    if any(window.source_runset_completion_status != "complete" for window in windows):
        limitations.append(_SOURCE_RUNSET_INCOMPLETE_LIMITATION)
    if any(window.source_evaluation_completion_status != "complete" for window in windows):
        limitations.append(_SOURCE_EVALUATION_INCOMPLETE_LIMITATION)
    if any(window.source_evaluation_exploratory is not False for window in windows):
        limitations.append(_SOURCE_EVALUATION_EXPLORATORY_LIMITATION)
    return not limitations, tuple(limitations)


def _require_supported_ordering(plan: DriftMonitoringPlan) -> None:
    if plan.ordering_variable not in _SUPPORTED_ORDERING_VARIABLES:
        raise ValueError(
            "drift ordering_variable must be window_index or window_start_utc; "
            f"{plan.ordering_variable!r} has no authenticated ordering-key implementation"
        )


def _require_current_input(value: PersistedArtifact, *, owner: str) -> None:
    if value.schema_version != SCHEMA_VERSION:
        raise ValueError(f"{owner} must use current schema_version {SCHEMA_VERSION}")


def _timestamp_bound(values: tuple[str, ...], *, pick: Literal["min", "max"]) -> str | None:
    if not values:
        return None
    parsed_rows = tuple(
        (parsed, value) for value in values if (parsed := parse_timestamp(value)) is not None
    )
    if len(parsed_rows) != len(values):
        return None
    selected = (
        min(parsed_rows, key=lambda row: row[0])
        if pick == "min"
        else max(
            parsed_rows,
            key=lambda row: row[0],
        )
    )
    return selected[1]
