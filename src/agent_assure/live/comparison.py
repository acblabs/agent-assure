from __future__ import annotations

from collections import defaultdict
from decimal import Decimal
from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import load_json_bounded
from agent_assure.live.advanced import (
    evaluate_paired_randomization_test,
    paired_randomization_prerequisites,
)
from agent_assure.live.intervals import difference_bootstrap_interval, difference_t_interval
from agent_assure.live.primitives import (
    decimal_string,
    live_record_group_id,
    signed_unit_decimal_string,
)
from agent_assure.schema.common import GateState
from agent_assure.schema.live import (
    LiveComparisonReport,
    LiveEvaluationReport,
    LiveGroupSummary,
    LiveObservationResult,
    LiveProtocolRecord,
    LiveRate,
)


def load_live_evaluation_report(path: Path) -> LiveEvaluationReport:
    payload = load_json_bounded(path)
    return LiveEvaluationReport.model_validate(payload)


def compare_live_reports(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    *,
    protocol: LiveProtocolRecord,
) -> LiveComparisonReport:
    _verify_report_binding(baseline, candidate, protocol)
    baseline_group = _group(baseline, protocol.baseline_group_id)
    candidate_group = _group(candidate, protocol.candidate_group_id)
    incomplete_limitations = _incomplete_comparison_limitations(baseline, candidate)
    if incomplete_limitations:
        return _incomplete_comparison_report(
            baseline,
            candidate,
            protocol=protocol,
            baseline_group=baseline_group,
            candidate_group=candidate_group,
            limitations=incomplete_limitations,
        )
    if protocol.baseline_mode == "fixed_reference":
        difference, lower, upper, compared_clusters = _fixed_reference_difference(
            candidate,
            protocol,
        )
        baseline_rate = _fixed_reference_rate(protocol)
        differences: tuple[Decimal, ...] = ()
    else:
        differences = _paired_cluster_differences(
            baseline,
            candidate,
            protocol,
        )
        difference, lower, upper, compared_clusters = _paired_cluster_difference_from_values(
            differences,
            protocol,
        )
        baseline_rate = baseline_group.expectation_pass_rate
    margin = Decimal(protocol.non_inferiority_margin)
    randomization_test = None
    if protocol.analysis_method in {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }:
        prerequisite_status, prerequisite_limitations = paired_randomization_prerequisites(
            protocol=protocol,
            compared_clusters=compared_clusters,
        )
        randomization_test = evaluate_paired_randomization_test(
            differences,
            protocol=protocol,
            prerequisite_status=prerequisite_status,
            limitations=prerequisite_limitations,
        )
        exploratory = (
            randomization_test is None
            or randomization_test.prerequisite_status != "met"
            or randomization_test.interpretation == "exploratory"
        )
        state = _randomization_comparison_state(
            difference,
            margin,
            randomization_test,
            protocol,
        )
    else:
        exploratory = _comparison_exploratory(protocol, compared_clusters)
        state = _comparison_state(lower, margin, compared_clusters, exploratory)
    limitations = list(
        _comparison_limitations(
            protocol,
            compared_clusters,
            exploratory,
            difference,
            lower,
            upper,
        )
    )
    if randomization_test is not None:
        limitations.extend(randomization_test.limitations)
        if randomization_test.prerequisite_status == "met":
            limitations.append(
                "paired randomization p-value is one-sided for the declared "
                "non-inferiority margin"
            )
    return LiveComparisonReport(
        artifact_kind="live-comparison-report",
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        suite_id=baseline.suite_id,
        suite_version=baseline.suite_version,
        baseline_group_id=protocol.baseline_group_id,
        candidate_group_id=protocol.candidate_group_id,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        exploratory=exploratory,
        state=state,
        confidence_level=candidate.confidence_level,
        non_inferiority_margin=decimal_string(margin),
        baseline_pass_rate=baseline_rate,
        candidate_pass_rate=candidate_group.expectation_pass_rate,
        pass_rate_difference=signed_unit_decimal_string(difference),
        difference_ci_lower=signed_unit_decimal_string(lower),
        difference_ci_upper=signed_unit_decimal_string(upper),
        compared_clusters=compared_clusters,
        effective_n=_comparison_effective_n(baseline_group, candidate_group, protocol),
        fixed_reference_pass_rate=protocol.fixed_reference_pass_rate,
        latency_p50_difference_ms=_difference(
            candidate_group.latency_ms.p50,
            baseline_group.latency_ms.p50,
        ),
        cost_total_difference_usd=_difference(
            candidate_group.estimated_cost_usd.total,
            baseline_group.estimated_cost_usd.total,
        ),
        randomization_tests=() if randomization_test is None else (randomization_test,),
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _verify_report_binding(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> None:
    if baseline.suite_id != candidate.suite_id:
        raise ValueError("live reports reference different suite_id values")
    if baseline.suite_version != candidate.suite_version:
        raise ValueError("live reports reference different suite_version values")
    protocol_digest = sha256_hexdigest(protocol)
    for label, report in (("baseline", baseline), ("candidate", candidate)):
        if report.protocol_id != protocol.protocol_id or report.protocol_digest != protocol_digest:
            raise ValueError(f"{label} live report protocol binding does not match protocol")


def _incomplete_comparison_limitations(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
) -> tuple[str, ...]:
    limitations: list[str] = []
    for label, report in (("baseline", baseline), ("candidate", candidate)):
        if report.completion_status == "incomplete":
            stop_reasons = ", ".join(report.stop_reasons) or "unknown"
            limitations.append(
                f"{label} live report is incomplete with stop reasons: {stop_reasons}; "
                "live comparison is not evaluated"
            )
    return tuple(limitations)


def _incomplete_comparison_report(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    *,
    protocol: LiveProtocolRecord,
    baseline_group: LiveGroupSummary,
    candidate_group: LiveGroupSummary,
    limitations: tuple[str, ...],
) -> LiveComparisonReport:
    margin = Decimal(protocol.non_inferiority_margin)
    baseline_rate = (
        _fixed_reference_rate(protocol)
        if protocol.baseline_mode == "fixed_reference"
        else baseline_group.expectation_pass_rate
    )
    candidate_rate = candidate_group.expectation_pass_rate
    observed_difference = Decimal(candidate_rate.rate) - Decimal(baseline_rate.rate)
    report_limitations = (
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
        *limitations,
        "pass-rate difference is an observed incomplete-window delta, not an inferential "
        "comparison interval",
    )
    return LiveComparisonReport(
        artifact_kind="live-comparison-report",
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        suite_id=baseline.suite_id,
        suite_version=baseline.suite_version,
        baseline_group_id=protocol.baseline_group_id,
        candidate_group_id=protocol.candidate_group_id,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        exploratory=True,
        state=GateState.not_evaluated,
        confidence_level=candidate.confidence_level,
        non_inferiority_margin=decimal_string(margin),
        baseline_pass_rate=baseline_rate,
        candidate_pass_rate=candidate_rate,
        pass_rate_difference=signed_unit_decimal_string(observed_difference),
        difference_ci_lower=signed_unit_decimal_string(observed_difference),
        difference_ci_upper=signed_unit_decimal_string(observed_difference),
        compared_clusters=0,
        effective_n="0.000000",
        fixed_reference_pass_rate=protocol.fixed_reference_pass_rate,
        latency_p50_difference_ms=_difference(
            candidate_group.latency_ms.p50,
            baseline_group.latency_ms.p50,
        ),
        cost_total_difference_usd=_difference(
            candidate_group.estimated_cost_usd.total,
            baseline_group.estimated_cost_usd.total,
        ),
        randomization_tests=(),
        limitations=tuple(dict.fromkeys(report_limitations)),
    )


def _paired_cluster_differences(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, ...]:
    _validate_paired_observation_sets(baseline, candidate, protocol)
    baseline_rates = _cluster_pass_rates(baseline, protocol.baseline_group_id)
    candidate_rates = _cluster_pass_rates(candidate, protocol.candidate_group_id)
    _validate_paired_cluster_sets(baseline_rates, candidate_rates)
    common_clusters = sorted(baseline_rates)
    return tuple(
        candidate_rates[cluster] - baseline_rates[cluster] for cluster in common_clusters
    )


def _paired_cluster_difference_from_values(
    differences: tuple[Decimal, ...],
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, Decimal, Decimal, int]:
    if protocol.analysis_method == "paired_cluster_bootstrap_percentile":
        return _bootstrap_difference_interval(differences, protocol)
    return _difference_interval(differences, protocol.confidence_level)


def _fixed_reference_difference(
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, Decimal, Decimal, int]:
    if protocol.fixed_reference_pass_rate is None:
        raise ValueError("fixed_reference protocol requires fixed_reference_pass_rate")
    reference = Decimal(protocol.fixed_reference_pass_rate)
    candidate_rates = _cluster_pass_rates(candidate, protocol.candidate_group_id)
    differences = tuple(rate - reference for rate in candidate_rates.values())
    return _difference_interval(differences, protocol.confidence_level)


def _difference_interval(
    differences: tuple[Decimal, ...],
    confidence_level: str,
) -> tuple[Decimal, Decimal, Decimal, int]:
    return difference_t_interval(differences, confidence_level)


def _bootstrap_difference_interval(
    differences: tuple[Decimal, ...],
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, Decimal, Decimal, int]:
    return difference_bootstrap_interval(
        differences,
        confidence_level=protocol.confidence_level,
        seed=f"{protocol.protocol_id}:{protocol.analysis_digest}:paired_cluster_bootstrap",
    )


def _validate_paired_cluster_sets(
    baseline_rates: dict[str, Decimal],
    candidate_rates: dict[str, Decimal],
) -> None:
    baseline_only = sorted(set(baseline_rates) - set(candidate_rates))
    candidate_only = sorted(set(candidate_rates) - set(baseline_rates))
    if baseline_only or candidate_only:
        raise ValueError(
            "paired live comparison requires identical included cluster sets; "
            f"baseline_only={baseline_only or []}; candidate_only={candidate_only or []}"
        )


def _validate_paired_observation_sets(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> None:
    baseline_sets = _paired_observation_sets(baseline, protocol.baseline_group_id)
    candidate_sets = _paired_observation_sets(candidate, protocol.candidate_group_id)
    if baseline_sets == candidate_sets:
        return
    baseline_only = _observation_set_delta(baseline_sets, candidate_sets)
    candidate_only = _observation_set_delta(candidate_sets, baseline_sets)
    raise ValueError(
        "paired live comparison requires identical included case/repetition sets "
        "within each cluster; "
        f"baseline_only={baseline_only or []}; candidate_only={candidate_only or []}"
    )


def _paired_observation_sets(
    report: LiveEvaluationReport,
    group_id: str,
) -> dict[str, set[tuple[str, int]]]:
    observations = _included_group_observations(report, group_id)
    paired: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for observation in observations:
        paired[observation.cluster_id].add(
            (observation.case_id, observation.repetition_index)
        )
    return dict(paired)


def _included_group_observations(
    report: LiveEvaluationReport,
    group_id: str,
) -> tuple[LiveObservationResult, ...]:
    if group_id == "overall":
        observations = report.observations
    else:
        observations = tuple(
            observation
            for observation in report.observations
            if live_record_group_id(observation) == group_id
        )
    return tuple(
        observation
        for observation in observations
        if observation.observation_status == "included"
    )


def _observation_set_delta(
    left: dict[str, set[tuple[str, int]]],
    right: dict[str, set[tuple[str, int]]],
) -> list[str]:
    delta: list[str] = []
    for cluster_id in sorted(set(left) | set(right)):
        missing = sorted(left.get(cluster_id, set()) - right.get(cluster_id, set()))
        delta.extend(f"{cluster_id}:{case_id}:{repetition}" for case_id, repetition in missing)
    return delta


def _cluster_pass_rates(report: LiveEvaluationReport, group_id: str) -> dict[str, Decimal]:
    group = _group(report, group_id)
    if group.group_id == "overall":
        group_observations = report.observations
    else:
        group_observations = tuple(
            observation
            for observation in report.observations
            if live_record_group_id(observation) == group_id
        )
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for observation in group_observations:
        if observation.observation_status != "included":
            continue
        counts[observation.cluster_id][0] += int(observation.state is GateState.pass_)
        counts[observation.cluster_id][1] += 1
    return {
        cluster_id: Decimal(values[0]) / Decimal(values[1])
        for cluster_id, values in counts.items()
        if values[1] > 0
    }


def _fixed_reference_rate(protocol: LiveProtocolRecord) -> LiveRate:
    rate = protocol.fixed_reference_pass_rate or "0.000000"
    return LiveRate(
        artifact_kind="live-rate",
        label="fixed_reference_expectation_pass",
        numerator=0,
        denominator=0,
        cluster_count=0,
        effective_n="0.000000",
        design_effect="1.000000",
        largest_cluster_size=0,
        largest_cluster_design_effect="1.000000",
        largest_cluster_effective_n="0.000000",
        assumed_intraclass_correlation=protocol.assumed_intraclass_correlation,
        analysis_method="fixed_reference",
        exploratory=False,
        rate=rate,
        cluster_mean_rate=rate,
        interval_center="pooled_rate",
        interval_center_value=rate,
        confidence_level=protocol.confidence_level,
        ci_lower=rate,
        ci_upper=rate,
    )


def _group(report: LiveEvaluationReport, group_id: str) -> LiveGroupSummary:
    if group_id == "overall":
        return report.overall
    for group in report.groups:
        if group.group_id == group_id:
            return group
    known = ", ".join(["overall", *(group.group_id for group in report.groups)])
    raise KeyError(f"unknown live group {group_id!r}; expected one of: {known}")


def _difference(candidate: str | None, baseline: str | None) -> str | None:
    if candidate is None or baseline is None:
        return None
    return decimal_string(Decimal(candidate) - Decimal(baseline))


def _comparison_state(
    lower: Decimal,
    margin: Decimal,
    compared_clusters: int,
    exploratory: bool,
) -> GateState:
    if compared_clusters == 0:
        return GateState.not_evaluated
    if lower < -margin:
        return GateState.fail
    if exploratory:
        return GateState.not_evaluated
    return GateState.pass_


def _randomization_comparison_state(
    difference: Decimal,
    margin: Decimal,
    randomization_test: object,
    protocol: LiveProtocolRecord,
) -> GateState:
    if randomization_test is None:
        return GateState.not_evaluated
    p_value = getattr(randomization_test, "adjusted_p_value", None)
    prerequisite_status = getattr(randomization_test, "prerequisite_status", None)
    interpretation = getattr(randomization_test, "interpretation", None)
    if difference < -margin:
        return GateState.fail
    if prerequisite_status != "met" or interpretation == "exploratory" or p_value is None:
        return GateState.not_evaluated
    plan = protocol.advanced_analysis_plan
    alpha = Decimal(plan.familywise_alpha if plan is not None else "0.050000")
    if Decimal(p_value) <= alpha:
        return GateState.pass_
    return GateState.not_evaluated


def _comparison_exploratory(protocol: LiveProtocolRecord, compared_clusters: int) -> bool:
    if compared_clusters < 30:
        return True
    if protocol.analysis_method == "exploratory":
        return True
    if (
        protocol.analysis_method == "paired_cluster_bootstrap_percentile"
        and compared_clusters < 50
    ):
        return True
    return False


def _comparison_effective_n(
    baseline_group: LiveGroupSummary,
    candidate_group: LiveGroupSummary,
    protocol: LiveProtocolRecord,
) -> str:
    if protocol.baseline_mode == "fixed_reference":
        return candidate_group.effective_n
    return decimal_string(
        min(
            Decimal(baseline_group.effective_n),
            Decimal(candidate_group.effective_n),
        )
    )


def _comparison_limitations(
    protocol: LiveProtocolRecord,
    compared_clusters: int,
    exploratory: bool,
    difference: Decimal,
    lower: Decimal,
    upper: Decimal,
) -> tuple[str, ...]:
    limitations = [
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
    ]
    if compared_clusters > 1 and lower == upper == difference:
        limitations.append(
            "all compared cluster differences were identical; the empirical difference "
            "interval collapsed to zero width and should be interpreted as a degenerate "
            "descriptive interval"
        )
    if compared_clusters > 0 and lower < -Decimal(protocol.non_inferiority_margin):
        limitations.append(
            "the gate fails closed because the lower interval bound crosses the "
            "non-inferiority margin; this does not prove candidate inferiority"
        )
    if exploratory:
        if compared_clusters < 30:
            limitations.append(
                "fewer than 30 compared clusters makes this comparison exploratory"
            )
        elif protocol.analysis_method == "paired_cluster_bootstrap_percentile":
            limitations.append(
                "paired cluster percentile bootstrap requires at least 50 compared clusters "
                "for confirmatory interpretation"
            )
    return tuple(limitations)
