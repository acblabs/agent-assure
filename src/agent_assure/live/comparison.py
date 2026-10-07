from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import cast

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.advanced import (
    evaluate_paired_randomization_test,
    paired_randomization_prerequisites,
)
from agent_assure.live.intervals import difference_bootstrap_interval, difference_t_interval
from agent_assure.live.primitives import (
    decimal_string,
    live_record_group_id,
    signed_unit_decimal_string,
    signed_unit_lower_string,
    signed_unit_upper_string,
    with_live_decimal_context,
)
from agent_assure.live.statistics import (
    _rate_analysis_method,
    _rate_from_values,
    _rate_requires_resampling,
)
from agent_assure.live.work_limits import (
    LIVE_MAX_EXACT_PERMUTATION_CLUSTERS,
    LIVE_MONTE_CARLO_ITERATIONS,
    LIVE_RATE_BOOTSTRAP_ITERATIONS,
    LiveAnalysisWorkPlan,
    validate_live_analysis_work_plan,
)
from agent_assure.schema.common import GateState
from agent_assure.schema.live import (
    LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION,
    LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION,
    EndpointPrerequisiteStatus,
    LiveComparisonReport,
    LiveEvaluationReport,
    LiveGroupSummary,
    LiveObservationResult,
    LiveProtocolRecord,
    LiveRate,
    PairedClusterRate,
)
from agent_assure.schema.validation import (
    load_validated_artifact_model,
    validate_loaded_artifact_payload,
)


def load_live_evaluation_report(path: Path) -> LiveEvaluationReport:
    return load_validated_artifact_model(
        path,
        LiveEvaluationReport,
        kind="live-evaluation-report",
        label="live evaluation report JSON",
    )


@with_live_decimal_context
def compare_live_reports(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    *,
    protocol: LiveProtocolRecord,
) -> LiveComparisonReport:
    baseline_payload = baseline.model_dump(mode="json", warnings="error")
    baseline = LiveEvaluationReport.model_validate(baseline_payload)
    validate_loaded_artifact_payload(baseline_payload, "live-evaluation-report")
    candidate_payload = candidate.model_dump(mode="json", warnings="error")
    candidate = LiveEvaluationReport.model_validate(candidate_payload)
    validate_loaded_artifact_payload(candidate_payload, "live-evaluation-report")
    protocol_payload = protocol.model_dump(mode="json", warnings="error")
    protocol = LiveProtocolRecord.model_validate(protocol_payload)
    validate_loaded_artifact_payload(protocol_payload, "live-protocol-record")
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
        paired_clusters = _fixed_reference_cluster_rates(
            candidate,
            protocol,
        )
    else:
        paired_clusters = _paired_cluster_rates(
            baseline,
            candidate,
            protocol,
        )
    derived = _derive_paired_comparison_statistics(
        paired_clusters,
        protocol=protocol,
    )
    baseline_rate = derived.baseline_rate
    candidate_rate = derived.candidate_rate
    differences = derived.projection.differences
    difference = derived.difference
    lower = derived.lower
    upper = derived.upper
    compared_clusters = derived.compared_clusters
    margin = Decimal(protocol.non_inferiority_margin)
    if lower == upper:
        difference_ci_lower = difference_ci_upper = signed_unit_decimal_string(lower)
    else:
        difference_ci_lower = signed_unit_lower_string(lower)
        difference_ci_upper = signed_unit_upper_string(upper)
    persisted_lower = Decimal(difference_ci_lower)
    randomization_test = None
    if protocol.analysis_method in {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }:
        prerequisite_status = derived.randomization_prerequisite_status
        if prerequisite_status is None:
            raise ValueError("paired randomization derivation is missing prerequisite status")
        randomization_test = evaluate_paired_randomization_test(
            differences,
            protocol=protocol,
            prerequisite_status=prerequisite_status,
            limitations=derived.randomization_prerequisite_limitations,
        )
        exploratory = (
            randomization_test is None
            or randomization_test.prerequisite_status != "met"
            or randomization_test.interpretation == "exploratory"
            or not LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION
        )
        state = _randomization_comparison_state(
            difference,
            margin,
            randomization_test,
            protocol,
        )
        if exploratory and state is GateState.pass_:
            state = GateState.not_evaluated
    else:
        degenerate_interval = compared_clusters > 1 and lower == upper == difference
        exploratory = _comparison_exploratory(protocol, compared_clusters) or degenerate_interval
        state = _comparison_state(persisted_lower, margin, compared_clusters, exploratory)
    limitations = list(
        _comparison_limitations(
            protocol,
            compared_clusters,
            exploratory,
            difference,
            lower,
            upper,
            decision_lower=persisted_lower,
        )
    )
    if randomization_test is not None:
        limitations.extend(randomization_test.limitations)
        if randomization_test.prerequisite_status == "met":
            limitations.append(
                "paired randomization p-value is one-sided for the predeclared "
                "zero-margin candidate-improvement null"
            )
    return LiveComparisonReport(
        artifact_kind="live-comparison-report",
        derivation_contract="agent-assure/live-comparison/v1",
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        baseline_evaluation_digest=sha256_hexdigest(baseline),
        candidate_evaluation_digest=sha256_hexdigest(candidate),
        baseline_completion_status=baseline.completion_status,
        candidate_completion_status=candidate.completion_status,
        baseline_stop_reasons=baseline.stop_reasons,
        candidate_stop_reasons=candidate.stop_reasons,
        suite_id=baseline.suite_id,
        suite_version=baseline.suite_version,
        baseline_group_id=protocol.baseline_group_id,
        candidate_group_id=protocol.candidate_group_id,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        protocol=protocol,
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        exploratory=exploratory,
        state=state,
        confidence_level=candidate.confidence_level,
        non_inferiority_margin=decimal_string(margin),
        baseline_pass_rate=baseline_rate,
        candidate_pass_rate=candidate_rate,
        pass_rate_difference=signed_unit_decimal_string(difference),
        difference_ci_lower=difference_ci_lower,
        difference_ci_upper=difference_ci_upper,
        compared_clusters=compared_clusters,
        effective_n=_comparison_effective_n(baseline_rate, candidate_rate, protocol),
        fixed_reference_pass_rate=protocol.fixed_reference_pass_rate,
        paired_clusters=paired_clusters,
        baseline_latency_p50_ms=baseline_group.latency_ms.p50,
        candidate_latency_p50_ms=candidate_group.latency_ms.p50,
        baseline_cost_total_usd=baseline_group.estimated_cost_usd.total,
        candidate_cost_total_usd=candidate_group.estimated_cost_usd.total,
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
    if baseline.suite_id != protocol.suite_id:
        raise ValueError("live report suite_id does not match protocol")
    if baseline.suite_version != protocol.suite_version:
        raise ValueError("live report suite_version does not match protocol")
    protocol_digest = sha256_hexdigest(protocol)
    for label, report in (("baseline", baseline), ("candidate", candidate)):
        if report.protocol_id != protocol.protocol_id or report.protocol_digest != protocol_digest:
            raise ValueError(f"{label} live report protocol binding does not match protocol")
        if report.suite_digest != protocol.suite_digest:
            raise ValueError(f"{label} live report suite_digest does not match protocol")
        if report.configuration_digest is None:
            raise ValueError(f"{label} live report is missing configuration_digest")


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
        LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION,
        *limitations,
        "pass-rate difference is an observed incomplete-window delta, not an inferential "
        "comparison interval",
    )
    return LiveComparisonReport(
        artifact_kind="live-comparison-report",
        derivation_contract="agent-assure/live-comparison/v1",
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        baseline_evaluation_digest=sha256_hexdigest(baseline),
        candidate_evaluation_digest=sha256_hexdigest(candidate),
        baseline_completion_status=baseline.completion_status,
        candidate_completion_status=candidate.completion_status,
        baseline_stop_reasons=baseline.stop_reasons,
        candidate_stop_reasons=candidate.stop_reasons,
        suite_id=baseline.suite_id,
        suite_version=baseline.suite_version,
        baseline_group_id=protocol.baseline_group_id,
        candidate_group_id=protocol.candidate_group_id,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        protocol=protocol,
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        exploratory=True,
        state=GateState.not_evaluated,
        confidence_level=candidate.confidence_level,
        non_inferiority_margin=decimal_string(margin),
        baseline_pass_rate=baseline_rate,
        candidate_pass_rate=candidate_rate,
        pass_rate_difference=signed_unit_decimal_string(observed_difference),
        difference_ci_lower=signed_unit_lower_string(observed_difference),
        difference_ci_upper=signed_unit_upper_string(observed_difference),
        compared_clusters=0,
        effective_n="0.000000",
        fixed_reference_pass_rate=protocol.fixed_reference_pass_rate,
        paired_clusters=(),
        baseline_latency_p50_ms=baseline_group.latency_ms.p50,
        candidate_latency_p50_ms=candidate_group.latency_ms.p50,
        baseline_cost_total_usd=baseline_group.estimated_cost_usd.total,
        candidate_cost_total_usd=candidate_group.estimated_cost_usd.total,
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


def _paired_cluster_rates(
    baseline: LiveEvaluationReport,
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> tuple[PairedClusterRate, ...]:
    _validate_paired_observation_sets(baseline, candidate, protocol)
    baseline_counts = _cluster_pass_counts(baseline, protocol.baseline_group_id)
    candidate_counts = _cluster_pass_counts(candidate, protocol.candidate_group_id)
    _validate_paired_cluster_sets(baseline_counts, candidate_counts)
    common_clusters = sorted(baseline_counts)
    return tuple(
        PairedClusterRate(
            artifact_kind="paired-cluster-rate",
            cluster_id=cluster,
            baseline_numerator=baseline_counts[cluster][0],
            baseline_denominator=baseline_counts[cluster][1],
            candidate_numerator=candidate_counts[cluster][0],
            candidate_denominator=candidate_counts[cluster][1],
            baseline_rate=_count_rate(*baseline_counts[cluster]),
            candidate_rate=_count_rate(*candidate_counts[cluster]),
            difference=signed_unit_decimal_string(
                Decimal(candidate_counts[cluster][0]) / Decimal(candidate_counts[cluster][1])
                - Decimal(baseline_counts[cluster][0]) / Decimal(baseline_counts[cluster][1])
            ),
        )
        for cluster in common_clusters
    )


def _paired_cluster_difference_from_values(
    differences: tuple[Decimal, ...],
    protocol: LiveProtocolRecord,
) -> tuple[Decimal, Decimal, Decimal, int]:
    if protocol.analysis_method == "paired_cluster_bootstrap_percentile":
        return _bootstrap_difference_interval(differences, protocol)
    return _difference_interval(differences, protocol.confidence_level)


def _fixed_reference_cluster_rates(
    candidate: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> tuple[PairedClusterRate, ...]:
    if protocol.fixed_reference_pass_rate is None:
        raise ValueError("fixed_reference protocol requires fixed_reference_pass_rate")
    reference = Decimal(protocol.fixed_reference_pass_rate)
    candidate_counts = _cluster_pass_counts(candidate, protocol.candidate_group_id)
    return tuple(
        PairedClusterRate(
            artifact_kind="paired-cluster-rate",
            cluster_id=cluster_id,
            baseline_numerator=0,
            baseline_denominator=0,
            candidate_numerator=candidate_counts[cluster_id][0],
            candidate_denominator=candidate_counts[cluster_id][1],
            baseline_rate=decimal_string(reference),
            candidate_rate=_count_rate(*candidate_counts[cluster_id]),
            difference=signed_unit_decimal_string(
                Decimal(candidate_counts[cluster_id][0]) / Decimal(candidate_counts[cluster_id][1])
                - reference
            ),
        )
        for cluster_id in sorted(candidate_counts)
    )


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
        iterations=LIVE_RATE_BOOTSTRAP_ITERATIONS,
    )


def _validate_paired_cluster_sets(
    baseline_rates: dict[str, tuple[int, int]],
    candidate_rates: dict[str, tuple[int, int]],
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
        "paired live comparison requires identical included prompt, schedule, "
        "case, and repetition identities within each cluster; "
        f"baseline_only={baseline_only or []}; candidate_only={candidate_only or []}"
    )


def _paired_observation_sets(
    report: LiveEvaluationReport,
    group_id: str,
) -> dict[str, Counter[tuple[str, int, int, str, str]]]:
    observations = _included_group_observations(report, group_id)
    paired: dict[str, Counter[tuple[str, int, int, str, str]]] = defaultdict(Counter)
    for observation in observations:
        paired[observation.cluster_id][_pairing_identity(observation)] += 1
    return dict(paired)


def _pairing_identity(
    observation: LiveObservationResult,
) -> tuple[str, int, int, str, str]:
    if (
        observation.schedule_index is None
        or observation.randomization_block_id is None
        or observation.prompt_digest is None
    ):
        raise ValueError("paired live comparison requires complete prompt and schedule identity")
    return (
        observation.case_id,
        observation.repetition_index,
        observation.schedule_index,
        observation.randomization_block_id,
        observation.prompt_digest,
    )


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
        observation for observation in observations if observation.observation_status == "included"
    )


def _observation_set_delta(
    left: dict[str, Counter[tuple[str, int, int, str, str]]],
    right: dict[str, Counter[tuple[str, int, int, str, str]]],
) -> list[str]:
    delta: list[str] = []
    for cluster_id in sorted(set(left) | set(right)):
        missing = sorted(
            (left.get(cluster_id, Counter()) - right.get(cluster_id, Counter())).elements()
        )
        delta.extend(
            (
                f"{cluster_id}:{case_id}:{repetition}:schedule={schedule_index}:"
                f"block={block_id}:prompt={prompt_digest[:12]}"
            )
            for case_id, repetition, schedule_index, block_id, prompt_digest in missing
        )
    return delta


def _cluster_pass_counts(
    report: LiveEvaluationReport,
    group_id: str,
) -> dict[str, tuple[int, int]]:
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
        cluster_id: (values[0], values[1]) for cluster_id, values in counts.items() if values[1] > 0
    }


@with_live_decimal_context
def _count_rate(numerator: int, denominator: int) -> str:
    if denominator <= 0 or not 0 <= numerator <= denominator:
        raise ValueError("paired cluster counts are outside the binomial domain")
    return decimal_string(Decimal(numerator) / Decimal(denominator))


def _required_paired_count(item: PairedClusterRate, field_name: str) -> int:
    value = cast(int | None, getattr(item, field_name))
    if value is None:
        raise ValueError("current paired cluster evidence requires per-arm counts")
    return value


@dataclass(frozen=True, slots=True)
class _PairedEvidenceProjection:
    """Kernel-free sufficient statistics for one current comparison."""

    baseline_values: tuple[tuple[str, bool], ...] | None
    candidate_values: tuple[tuple[str, bool], ...]
    differences: tuple[Decimal, ...]


@dataclass(frozen=True, slots=True)
class _PairedComparisonStatistics:
    """Fully derived comparison statistics after aggregate work preflight."""

    projection: _PairedEvidenceProjection
    baseline_rate: LiveRate
    candidate_rate: LiveRate
    difference: Decimal
    lower: Decimal
    upper: Decimal
    compared_clusters: int
    randomization_prerequisite_status: EndpointPrerequisiteStatus | None
    randomization_prerequisite_limitations: tuple[str, ...]


@with_live_decimal_context
def _project_paired_cluster_evidence(
    paired_clusters: tuple[PairedClusterRate, ...],
    *,
    protocol: LiveProtocolRecord,
) -> _PairedEvidenceProjection:
    if not paired_clusters:
        raise ValueError("complete live comparison requires paired cluster evidence")
    if len(paired_clusters) > protocol.planned_clusters:
        raise ValueError("paired cluster evidence exceeds protocol planned_clusters")
    cluster_ids = [item.cluster_id for item in paired_clusters]
    if cluster_ids != sorted(cluster_ids) or len(cluster_ids) != len(set(cluster_ids)):
        raise ValueError("paired cluster evidence must have unique sorted cluster_id values")

    fixed_reference = protocol.baseline_mode == "fixed_reference"
    reference = protocol.fixed_reference_pass_rate
    if fixed_reference and reference is None:
        raise ValueError("fixed-reference comparison is missing its reference rate")
    counts: list[tuple[str, int, int, int, int]] = []
    differences: list[Decimal] = []
    baseline_observations = 0
    candidate_observations = 0
    for item in paired_clusters:
        baseline_numerator = _required_paired_count(item, "baseline_numerator")
        baseline_denominator = _required_paired_count(item, "baseline_denominator")
        candidate_numerator = _required_paired_count(item, "candidate_numerator")
        candidate_denominator = _required_paired_count(item, "candidate_denominator")
        if candidate_denominator <= 0:
            raise ValueError("paired cluster candidate denominators must be positive")
        if fixed_reference:
            if (baseline_numerator, baseline_denominator) != (0, 0):
                raise ValueError("fixed-reference paired cluster baseline counts must be 0/0")
            if item.baseline_rate != reference:
                raise ValueError("paired cluster baseline rates do not match fixed reference")
        else:
            if baseline_denominator <= 0:
                raise ValueError("concurrent paired cluster arm denominators must be positive")
            if baseline_denominator != candidate_denominator:
                raise ValueError("concurrent paired cluster arm denominators must be equal")
        if item.candidate_rate != _count_rate(candidate_numerator, candidate_denominator):
            raise ValueError("paired cluster candidate rate does not match its count evidence")
        if not fixed_reference and item.baseline_rate != _count_rate(
            baseline_numerator,
            baseline_denominator,
        ):
            raise ValueError("paired cluster baseline rate does not match its count evidence")
        exact_candidate_rate = Decimal(candidate_numerator) / Decimal(candidate_denominator)
        exact_baseline_rate = (
            Decimal(reference)
            if fixed_reference and reference is not None
            else Decimal(baseline_numerator) / Decimal(baseline_denominator)
        )
        exact_difference = exact_candidate_rate - exact_baseline_rate
        if item.difference != signed_unit_decimal_string(exact_difference):
            raise ValueError(
                "paired cluster difference does not match exact per-arm count evidence"
            )
        differences.append(exact_difference)
        counts.append(
            (
                item.cluster_id,
                baseline_numerator,
                baseline_denominator,
                candidate_numerator,
                candidate_denominator,
            )
        )
        baseline_observations += baseline_denominator
        candidate_observations += candidate_denominator

    if candidate_observations > protocol.planned_observations:
        raise ValueError("paired candidate counts exceed protocol planned_observations")
    if not fixed_reference and baseline_observations > protocol.planned_observations:
        raise ValueError("paired baseline counts exceed protocol planned_observations")

    candidate_values = tuple(
        (cluster_id, observation_index < candidate_numerator)
        for (
            cluster_id,
            _,
            _,
            candidate_numerator,
            candidate_denominator,
        ) in counts
        for observation_index in range(candidate_denominator)
    )
    baseline_values = (
        None
        if fixed_reference
        else tuple(
            (cluster_id, observation_index < baseline_numerator)
            for (
                cluster_id,
                baseline_numerator,
                baseline_denominator,
                _,
                _,
            ) in counts
            for observation_index in range(baseline_denominator)
        )
    )
    return _PairedEvidenceProjection(
        baseline_values=baseline_values,
        candidate_values=candidate_values,
        differences=tuple(differences),
    )


def _comparison_randomization_prerequisites(
    projection: _PairedEvidenceProjection,
    *,
    protocol: LiveProtocolRecord,
) -> tuple[EndpointPrerequisiteStatus | None, tuple[str, ...]]:
    if protocol.analysis_method not in {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }:
        return None, ()
    status, limitations = paired_randomization_prerequisites(
        protocol=protocol,
        compared_clusters=len(projection.differences),
    )
    return status, limitations


def _comparison_work_plan(
    projection: _PairedEvidenceProjection,
    *,
    protocol: LiveProtocolRecord,
    randomization_prerequisite_status: EndpointPrerequisiteStatus | None,
) -> LiveAnalysisWorkPlan:
    """Plan every arm and comparison resampling kernel without executing one."""

    rate_analysis_method = _rate_analysis_method(protocol)
    work_items: list[tuple[str, int]] = []
    if projection.baseline_values is not None:
        baseline_clusters = (
            _rate_requires_resampling(projection.baseline_values)
            if rate_analysis_method == "descriptive_cluster_bootstrap_percentile"
            else 0
        )
        work_items.append(
            (
                "live comparison baseline arm rate",
                LIVE_RATE_BOOTSTRAP_ITERATIONS * baseline_clusters,
            )
        )
    candidate_clusters = (
        _rate_requires_resampling(projection.candidate_values)
        if rate_analysis_method == "descriptive_cluster_bootstrap_percentile"
        else 0
    )
    work_items.append(
        (
            "live comparison candidate arm rate",
            LIVE_RATE_BOOTSTRAP_ITERATIONS * candidate_clusters,
        )
    )

    sample_size = len(projection.differences)
    comparison_work = 0
    if protocol.analysis_method == "paired_cluster_bootstrap_percentile":
        if sample_size > 1 and not all(
            value == projection.differences[0] for value in projection.differences[1:]
        ):
            comparison_work = LIVE_RATE_BOOTSTRAP_ITERATIONS * sample_size
    elif (
        protocol.analysis_method == "paired_cluster_permutation_exact"
        and randomization_prerequisite_status == "met"
    ):
        if 0 < sample_size <= LIVE_MAX_EXACT_PERMUTATION_CLUSTERS:
            comparison_work = (1 << sample_size) * sample_size
    elif (
        protocol.analysis_method == "paired_cluster_permutation_monte_carlo"
        and randomization_prerequisite_status == "met"
    ):
        comparison_work = LIVE_MONTE_CARLO_ITERATIONS * sample_size
    work_items.append(("live comparison difference or randomization", comparison_work))
    return LiveAnalysisWorkPlan(resampling_items=tuple(work_items))


def _validate_comparison_work_budget(
    projection: _PairedEvidenceProjection,
    *,
    protocol: LiveProtocolRecord,
    randomization_prerequisite_status: EndpointPrerequisiteStatus | None,
) -> int:
    plan = _comparison_work_plan(
        projection,
        protocol=protocol,
        randomization_prerequisite_status=randomization_prerequisite_status,
    )
    resampling_work, _ = validate_live_analysis_work_plan(plan)
    return resampling_work


def _pass_rates_from_paired_evidence_projection(
    projection: _PairedEvidenceProjection,
    *,
    protocol: LiveProtocolRecord,
) -> tuple[LiveRate, LiveRate]:
    rate_analysis_method = _rate_analysis_method(protocol)
    candidate_rate = _rate_from_values(
        "expectation_pass",
        projection.candidate_values,
        protocol=protocol,
        analysis_method=rate_analysis_method,
    )
    if projection.baseline_values is None:
        baseline_rate = _fixed_reference_rate(protocol)
    else:
        baseline_rate = _rate_from_values(
            "expectation_pass",
            projection.baseline_values,
            protocol=protocol,
            analysis_method=rate_analysis_method,
        )
    return baseline_rate, candidate_rate


def _derive_paired_comparison_statistics_from_projection(
    projection: _PairedEvidenceProjection,
    *,
    protocol: LiveProtocolRecord,
    randomization_prerequisite_status: EndpointPrerequisiteStatus | None,
    randomization_prerequisite_limitations: tuple[str, ...],
) -> _PairedComparisonStatistics:
    """Preflight aggregate work, then execute every selected statistical kernel."""

    _validate_comparison_work_budget(
        projection,
        protocol=protocol,
        randomization_prerequisite_status=randomization_prerequisite_status,
    )
    baseline_rate, candidate_rate = _pass_rates_from_paired_evidence_projection(
        projection,
        protocol=protocol,
    )
    difference, lower, upper, compared_clusters = _paired_cluster_difference_from_values(
        projection.differences,
        protocol,
    )
    return _PairedComparisonStatistics(
        projection=projection,
        baseline_rate=baseline_rate,
        candidate_rate=candidate_rate,
        difference=difference,
        lower=lower,
        upper=upper,
        compared_clusters=compared_clusters,
        randomization_prerequisite_status=randomization_prerequisite_status,
        randomization_prerequisite_limitations=randomization_prerequisite_limitations,
    )


def _derive_paired_comparison_statistics(
    paired_clusters: tuple[PairedClusterRate, ...],
    *,
    protocol: LiveProtocolRecord,
) -> _PairedComparisonStatistics:
    projection = _project_paired_cluster_evidence(
        paired_clusters,
        protocol=protocol,
    )
    prerequisite_status, prerequisite_limitations = _comparison_randomization_prerequisites(
        projection,
        protocol=protocol,
    )
    return _derive_paired_comparison_statistics_from_projection(
        projection,
        protocol=protocol,
        randomization_prerequisite_status=prerequisite_status,
        randomization_prerequisite_limitations=prerequisite_limitations,
    )


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
    if _non_inferiority_boundary_breached(lower, margin):
        return GateState.fail
    if margin == Decimal("0") and lower == Decimal("0"):
        return GateState.not_evaluated
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
    if _non_inferiority_boundary_breached(difference, margin):
        return GateState.fail
    if margin == Decimal("0") and difference == Decimal("0"):
        return GateState.not_evaluated
    if prerequisite_status != "met" or interpretation == "exploratory" or p_value is None:
        return GateState.not_evaluated
    plan = protocol.advanced_analysis_plan
    alpha = Decimal(plan.familywise_alpha if plan is not None else "0.050000")
    if Decimal(p_value) <= alpha:
        return GateState.pass_
    return GateState.not_evaluated


def _comparison_exploratory(protocol: LiveProtocolRecord, compared_clusters: int) -> bool:
    if not LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION:
        return True
    if protocol.cluster_by == "source_group_id":
        return True
    if compared_clusters < 30:
        return True
    if protocol.analysis_method == "exploratory":
        return True
    if protocol.analysis_method == "paired_cluster_bootstrap_percentile" and compared_clusters < 50:
        return True
    return False


def _comparison_effective_n(
    baseline_rate: LiveRate,
    candidate_rate: LiveRate,
    protocol: LiveProtocolRecord,
) -> str:
    if protocol.baseline_mode == "fixed_reference":
        return candidate_rate.effective_n
    return decimal_string(
        min(
            Decimal(baseline_rate.effective_n),
            Decimal(candidate_rate.effective_n),
        )
    )


def _require_comparison_projection(*, owner: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise ValueError(f"{owner} does not match source-derived comparison evidence")


def _source_difference(candidate: str | None, baseline: str | None) -> str | None:
    return _difference(candidate, baseline)


@with_live_decimal_context
def verify_live_comparison_report_derivation(report: LiveComparisonReport) -> None:
    """Recompute comparison inference from bound protocol and paired statistics."""

    protocol = report.protocol
    if protocol is None:
        raise ValueError("current live comparison is missing its bound protocol")
    bindings = {
        "protocol_id": (report.protocol_id, protocol.protocol_id),
        "protocol_digest": (report.protocol_digest, sha256_hexdigest(protocol)),
        "suite_id": (report.suite_id, protocol.suite_id),
        "suite_version": (report.suite_version, protocol.suite_version),
        "baseline_group_id": (report.baseline_group_id, protocol.baseline_group_id),
        "candidate_group_id": (report.candidate_group_id, protocol.candidate_group_id),
        "baseline_mode": (report.baseline_mode, protocol.baseline_mode),
        "analysis_method": (report.analysis_method, protocol.analysis_method),
        "confidence_level": (report.confidence_level, protocol.confidence_level),
        "non_inferiority_margin": (
            report.non_inferiority_margin,
            protocol.non_inferiority_margin,
        ),
        "fixed_reference_pass_rate": (
            report.fixed_reference_pass_rate,
            protocol.fixed_reference_pass_rate,
        ),
    }
    for field_name, (actual, expected) in bindings.items():
        if actual != expected:
            raise ValueError(f"live comparison {field_name} does not match bound protocol")

    for owner, reasons in (
        ("baseline", report.baseline_stop_reasons),
        ("candidate", report.candidate_stop_reasons),
    ):
        if reasons != tuple(sorted(set(reasons))):
            raise ValueError(f"{owner} comparison stop reasons must be unique and sorted")
    _require_comparison_projection(
        owner="latency p50 difference",
        actual=report.latency_p50_difference_ms,
        expected=_source_difference(
            report.candidate_latency_p50_ms,
            report.baseline_latency_p50_ms,
        ),
    )
    _require_comparison_projection(
        owner="cost total difference",
        actual=report.cost_total_difference_usd,
        expected=_source_difference(
            report.candidate_cost_total_usd,
            report.baseline_cost_total_usd,
        ),
    )

    incomplete_limitations: list[str] = []
    for owner, status, reasons in (
        ("baseline", report.baseline_completion_status, report.baseline_stop_reasons),
        ("candidate", report.candidate_completion_status, report.candidate_stop_reasons),
    ):
        if status == "incomplete":
            rendered_reasons = ", ".join(reasons) or "unknown"
            incomplete_limitations.append(
                f"{owner} live report is incomplete with stop reasons: "
                f"{rendered_reasons}; live comparison is not evaluated"
            )
    if incomplete_limitations:
        if report.paired_clusters:
            raise ValueError("incomplete live comparison cannot carry paired cluster evidence")
        baseline_rate = report.baseline_pass_rate
        candidate_rate = report.candidate_pass_rate
        observed_difference = Decimal(candidate_rate.rate) - Decimal(baseline_rate.rate)
        expected_limitations = tuple(
            dict.fromkeys(
                (
                    "live comparison intervals are descriptive unless the protocol predeclares "
                    "the comparison as confirmatory",
                    LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION,
                    *incomplete_limitations,
                    "pass-rate difference is an observed incomplete-window delta, not an "
                    "inferential comparison interval",
                )
            )
        )
        expected_difference = signed_unit_decimal_string(observed_difference)
        incomplete_expectations: dict[str, tuple[object, object]] = {
            "state": (report.state, GateState.not_evaluated),
            "exploratory": (report.exploratory, True),
            "compared_clusters": (report.compared_clusters, 0),
            "effective_n": (report.effective_n, "0.000000"),
            "pass_rate_difference": (report.pass_rate_difference, expected_difference),
            "difference_ci_lower": (
                report.difference_ci_lower,
                signed_unit_lower_string(observed_difference),
            ),
            "difference_ci_upper": (
                report.difference_ci_upper,
                signed_unit_upper_string(observed_difference),
            ),
            "randomization_tests": (report.randomization_tests, ()),
            "limitations": (report.limitations, expected_limitations),
        }
        for field_name, (observed_value, expected_value) in incomplete_expectations.items():
            _require_comparison_projection(
                owner=f"incomplete comparison {field_name}",
                actual=observed_value,
                expected=expected_value,
            )
        return

    if report.baseline_stop_reasons or report.candidate_stop_reasons:
        raise ValueError("complete live comparison sources cannot carry stop reasons")
    if not report.paired_clusters:
        raise ValueError("complete live comparison requires paired cluster evidence")
    cluster_ids = [item.cluster_id for item in report.paired_clusters]
    if cluster_ids != sorted(cluster_ids) or len(cluster_ids) != len(set(cluster_ids)):
        raise ValueError("paired cluster evidence must have unique sorted cluster_id values")

    fixed_reference = protocol.baseline_mode == "fixed_reference"
    derived = _derive_paired_comparison_statistics(
        report.paired_clusters,
        protocol=protocol,
    )
    expected_baseline_rate = derived.baseline_rate
    expected_candidate_rate = derived.candidate_rate
    differences = derived.projection.differences
    _require_comparison_projection(
        owner="baseline_pass_rate",
        actual=report.baseline_pass_rate,
        expected=expected_baseline_rate,
    )
    _require_comparison_projection(
        owner="candidate_pass_rate",
        actual=report.candidate_pass_rate,
        expected=expected_candidate_rate,
    )

    difference = derived.difference
    lower = derived.lower
    upper = derived.upper
    compared_clusters = derived.compared_clusters
    if lower == upper:
        expected_lower = expected_upper = signed_unit_decimal_string(lower)
    else:
        expected_lower = signed_unit_lower_string(lower)
        expected_upper = signed_unit_upper_string(upper)

    margin = Decimal(protocol.non_inferiority_margin)
    randomization_test = None
    if protocol.analysis_method in {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }:
        prerequisite_status = derived.randomization_prerequisite_status
        if prerequisite_status is None:
            raise ValueError("paired randomization derivation is missing prerequisite status")
        randomization_test = evaluate_paired_randomization_test(
            differences,
            protocol=protocol,
            prerequisite_status=prerequisite_status,
            limitations=derived.randomization_prerequisite_limitations,
        )
        exploratory = (
            randomization_test is None
            or randomization_test.prerequisite_status != "met"
            or randomization_test.interpretation == "exploratory"
            or not LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION
        )
        expected_state = _randomization_comparison_state(
            difference,
            margin,
            randomization_test,
            protocol,
        )
        if exploratory and expected_state is GateState.pass_:
            expected_state = GateState.not_evaluated
    else:
        degenerate_interval = compared_clusters > 1 and lower == upper == difference
        exploratory = _comparison_exploratory(protocol, compared_clusters) or degenerate_interval
        expected_state = _comparison_state(
            Decimal(expected_lower),
            margin,
            compared_clusters,
            exploratory,
        )

    expected_tests = () if randomization_test is None else (randomization_test,)
    limitations = list(
        _comparison_limitations(
            protocol,
            compared_clusters,
            exploratory,
            difference,
            lower,
            upper,
            decision_lower=Decimal(expected_lower),
        )
    )
    if randomization_test is not None:
        limitations.extend(randomization_test.limitations)
        if randomization_test.prerequisite_status == "met":
            limitations.append(
                "paired randomization p-value is one-sided for the predeclared "
                "zero-margin candidate-improvement null"
            )
    expected_effective_n = (
        expected_candidate_rate.effective_n
        if fixed_reference
        else decimal_string(
            min(
                Decimal(expected_baseline_rate.effective_n),
                Decimal(expected_candidate_rate.effective_n),
            )
        )
    )
    complete_expectations: dict[str, tuple[object, object]] = {
        "pass_rate_difference": (
            report.pass_rate_difference,
            signed_unit_decimal_string(difference),
        ),
        "difference_ci_lower": (report.difference_ci_lower, expected_lower),
        "difference_ci_upper": (report.difference_ci_upper, expected_upper),
        "compared_clusters": (report.compared_clusters, compared_clusters),
        "effective_n": (report.effective_n, expected_effective_n),
        "exploratory": (report.exploratory, exploratory),
        "state": (report.state, expected_state),
        "randomization_tests": (report.randomization_tests, expected_tests),
        "limitations": (report.limitations, tuple(dict.fromkeys(limitations))),
    }
    for field_name, (observed_value, expected_value) in complete_expectations.items():
        _require_comparison_projection(
            owner=f"live comparison {field_name}",
            actual=observed_value,
            expected=expected_value,
        )


def _comparison_limitations(
    protocol: LiveProtocolRecord,
    compared_clusters: int,
    exploratory: bool,
    difference: Decimal,
    lower: Decimal,
    upper: Decimal,
    *,
    decision_lower: Decimal | None = None,
) -> tuple[str, ...]:
    limitations = [
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
        LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION,
    ]
    if not LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION:
        limitations.append(
            "the current protocol does not bind the complete arm configurations and "
            "prompt manifest before execution, so the comparison is exploratory"
        )
    if compared_clusters > 1 and lower == upper == difference:
        limitations.append(
            "all compared cluster differences were identical; the empirical difference "
            "interval collapsed to zero width and is not eligible for confirmatory "
            "interpretation"
        )
    margin = Decimal(protocol.non_inferiority_margin)
    boundary_value = (
        difference
        if protocol.analysis_method
        in {
            "paired_cluster_permutation_exact",
            "paired_cluster_permutation_monte_carlo",
        }
        else decision_lower
        if decision_lower is not None
        else lower
    )
    if compared_clusters > 0 and _non_inferiority_boundary_breached(
        boundary_value,
        margin,
    ):
        limitations.append(
            "the gate fails closed because the comparison crossed the non-inferiority "
            "boundary; this does not prove candidate inferiority or establish a "
            "statistically confirmatory regression"
        )
    elif compared_clusters > 0 and margin == Decimal("0") and boundary_value == Decimal("0"):
        limitations.append(
            "the comparison reached the zero-margin equality boundary and is inconclusive; "
            "it is not evaluated and does not prove candidate regression"
        )
    if exploratory:
        if protocol.cluster_by == "source_group_id":
            limitations.append(
                "source_group_id membership is not bound in the current protocol schema, "
                "so the comparison is exploratory"
            )
        if compared_clusters < 30:
            limitations.append("fewer than 30 compared clusters makes this comparison exploratory")
        elif protocol.analysis_method == "paired_cluster_bootstrap_percentile":
            limitations.append(
                "paired cluster percentile bootstrap requires at least 50 compared clusters "
                "for confirmatory interpretation"
            )
    return tuple(limitations)


def _non_inferiority_boundary_breached(value: Decimal, margin: Decimal) -> bool:
    boundary = -margin
    return value < boundary or (margin != Decimal("0") and value == boundary)
