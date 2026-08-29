"""Planning and fail-closed inference for repeated evidence sensitivity.

The only supported inferential endpoint is one predeclared binary response per
 independent cluster. Pair-level observations are reduced to a cluster response
of one only when every planned pair in that cluster exhibits the expected
decision response. The descriptive vector contains complete clusters only; the
confirmatory vector retains every planned cluster and assigns non-analyzable
clusters response zero. Exact binomial inference is authoritative; Monte Carlo
output, when present, is a reproducibility diagnostic only.
"""

from __future__ import annotations

from collections import Counter
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
from typing import Literal

from agent_assure.schema.common import decimal_string
from agent_assure.schema.stochastic_sensitivity import (
    MAX_PLANNED_CASES,
    ArtifactDependency,
    BinaryPairedDesignPlan,
    ClusterBinomialAnalysisResult,
    PairDisposition,
    PairDispositionCount,
    PairedSensitivityObservation,
    PrerequisiteCheckState,
    RepeatedEvidenceSensitivityProtocol,
    RunSetArtifactDependency,
    SensitivityExecutionMode,
    SensitivityInterpretation,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
    StochasticGateEffect,
    StochasticSensitivityState,
    SufficiencyState,
    derive_cluster_binomial_analysis,
    derive_cluster_response_vector,
    derive_sufficiency_prerequisites,
    has_structural_prerequisite_failure,
)
from agent_assure.statistics.cluster_binomial import (
    cluster_binomial_rejection_region_contains,
    plan_cluster_binomial_design,
)


def plan_binary_paired_design(
    *,
    familywise_alpha: str,
    desired_power: str,
    null_response_rate: str,
    alternative_response_rate: str,
    maximum_exclusion_rate: str = "0.000000",
    multiplicity_method: Literal["single_endpoint", "bonferroni"] = ("single_endpoint"),
    multiplicity_family_size: int = 1,
    planned_inferential_clusters: int | None = None,
    monte_carlo_diagnostic_threshold_clusters: int = 20,
    monte_carlo_resamples: int = 1_000,
) -> BinaryPairedDesignPlan:
    """Plan the same exact one-sided planned-frame test used at analysis.

    The null and alternative rates describe the composite endpoint over every
    frozen planned cluster: one only when all planned pairs are included and
    respond, otherwise zero. Without an authored frame size, the minimum
    planned-frame size is obtained without an asymptotic approximation. When
    ``planned_inferential_clusters`` is supplied, the critical value and power
    are recomputed at exactly that N and an underpowered N is rejected.
    Repetitions do not increase the inferential sample size.
    """

    alpha = _six_place_input(familywise_alpha, name="familywise_alpha")
    target_power = _six_place_input(desired_power, name="desired_power")
    p0 = _six_place_input(null_response_rate, name="null_response_rate")
    p1 = _six_place_input(alternative_response_rate, name="alternative_response_rate")
    exclusion = _six_place_input(
        maximum_exclusion_rate,
        name="maximum_exclusion_rate",
    )
    if multiplicity_method not in {"single_endpoint", "bonferroni"}:
        raise ValueError("unsupported multiplicity method")
    if type(multiplicity_family_size) is not int or multiplicity_family_size < 1:
        raise ValueError("multiplicity_family_size must be a positive integer")
    if multiplicity_method == "single_endpoint" and multiplicity_family_size != 1:
        raise ValueError("single_endpoint multiplicity requires family size one")
    if not Decimal("0") <= exclusion < Decimal("1"):
        raise ValueError("maximum_exclusion_rate must be in [0, 1)")
    if planned_inferential_clusters is not None and (
        type(planned_inferential_clusters) is not int
        or not 2 <= planned_inferential_clusters <= MAX_PLANNED_CASES
    ):
        raise ValueError(f"planned_inferential_clusters must be in [2, {MAX_PLANNED_CASES:,}]")

    adjusted_alpha = (
        Decimal(_probability_floor(alpha / Decimal(multiplicity_family_size)))
        if multiplicity_method == "bonferroni"
        else alpha
    )
    if adjusted_alpha <= Decimal("0"):
        raise ValueError("multiplicity-adjusted alpha is below persisted precision")
    try:
        exact = plan_cluster_binomial_design(
            adjusted_alpha=adjusted_alpha,
            desired_power=target_power,
            null_response_rate=p0,
            alternative_response_rate=p1,
            min_clusters=planned_inferential_clusters or 2,
            max_clusters=planned_inferential_clusters or MAX_PLANNED_CASES,
        )
    except ValueError as error:
        if planned_inferential_clusters is not None:
            raise ValueError(
                f"planned_inferential_clusters={planned_inferential_clusters} "
                "does not meet desired_power under the exact fixed-frame test"
            ) from error
        raise
    if exact.required_clusters > MAX_PLANNED_CASES:
        raise ValueError(f"exact plan exceeds the supported {MAX_PLANNED_CASES:,}-cluster bound")
    return BinaryPairedDesignPlan(
        familywise_alpha=decimal_string(alpha),
        adjusted_alpha=decimal_string(adjusted_alpha),
        desired_power=decimal_string(target_power),
        null_response_rate=decimal_string(p0),
        alternative_response_rate=decimal_string(p1),
        minimum_detectable_difference=decimal_string(p1 - p0),
        maximum_exclusion_rate=decimal_string(exclusion),
        planned_inferential_clusters=exact.required_clusters,
        critical_cluster_responses=exact.critical_successes,
        achieved_type_i_error=_probability_ceiling(exact.exact_type_i_error),
        achieved_power=_probability_floor(exact.achieved_power),
        monte_carlo_diagnostic_threshold_clusters=(monte_carlo_diagnostic_threshold_clusters),
        monte_carlo_resamples=monte_carlo_resamples,
    )


def validate_binary_paired_design_plan(
    protocol: RepeatedEvidenceSensitivityProtocol,
) -> BinaryPairedDesignPlan:
    """Revalidate the protocol and independently reconstruct its design."""

    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    design = protocol.design
    expected = plan_binary_paired_design(
        familywise_alpha=design.familywise_alpha,
        desired_power=design.desired_power,
        null_response_rate=design.null_response_rate,
        alternative_response_rate=design.alternative_response_rate,
        maximum_exclusion_rate=design.maximum_exclusion_rate,
        planned_inferential_clusters=design.planned_inferential_clusters,
        multiplicity_method=protocol.multiplicity_method,
        multiplicity_family_size=protocol.multiplicity_family_size,
        monte_carlo_diagnostic_threshold_clusters=(
            design.monte_carlo_diagnostic_threshold_clusters
        ),
        monte_carlo_resamples=design.monte_carlo_resamples,
    )
    if design != expected:
        raise ValueError("binary paired design does not match the exact cluster-binomial planner")
    return expected


def analyze_cluster_response(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
) -> ClusterBinomialAnalysisResult:
    """Recompute the exact cluster response analysis from the pair manifest."""

    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    validate_binary_paired_design_plan(protocol)
    observations = _validated_observations(protocol, observations)
    expected_clusters = {item.case_id: item.cluster_id for item in protocol.case_cluster_bindings}
    if any(item.cluster_id != expected_clusters[item.case_id] for item in observations):
        raise ValueError("observation cluster identity differs from the frozen mapping")
    return derive_cluster_binomial_analysis(protocol, observations)


def evaluate_statistical_sufficiency(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
    *,
    source_runsets: tuple[RunSetArtifactDependency, ...] = (),
) -> StatisticalSufficiencyReport:
    """Derive sufficiency from protocol-bound observations and dependencies.

    Underpowered and incomplete data remain inspectable but are non-verdict.
    Structural invalidity is represented separately as ``prerequisites_unmet``.
    """

    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    validate_binary_paired_design_plan(protocol)
    observations = _validated_observations(protocol, observations)
    source_runsets = tuple(
        RunSetArtifactDependency.model_validate(item.model_dump(mode="json"))
        for item in source_runsets
    )
    included = tuple(item for item in observations if item.disposition is PairDisposition.included)
    missing_dispositions = {
        PairDisposition.missing_both,
        PairDisposition.missing_baseline,
        PairDisposition.missing_counterfactual,
    }
    excluded_dispositions = {
        PairDisposition.excluded_baseline,
        PairDisposition.excluded_counterfactual,
        PairDisposition.excluded_both,
    }
    missing_pairs = sum(item.disposition in missing_dispositions for item in observations)
    excluded_pairs = sum(item.disposition in excluded_dispositions for item in observations)
    nonmissing = tuple(
        item for item in observations if item.disposition not in missing_dispositions
    )
    actual_pairs = len(nonmissing)
    actual_clusters = len({item.cluster_id for item in nonmissing})
    analyzable_clusters = len(derive_cluster_response_vector(protocol, observations))
    prerequisites = derive_sufficiency_prerequisites(
        protocol,
        observations,
        source_runsets=source_runsets,
        excluded_pairs=excluded_pairs,
        missing_pairs=missing_pairs,
    )
    structural_unmet = has_structural_prerequisite_failure(prerequisites)
    all_satisfied = all(item.state is PrerequisiteCheckState.satisfied for item in prerequisites)
    state = (
        SufficiencyState.prerequisites_unmet
        if structural_unmet
        else SufficiencyState.satisfied
        if all_satisfied
        else SufficiencyState.inconclusive
    )
    analysis = None
    if protocol.execution_mode is SensitivityExecutionMode.stochastic_live and not structural_unmet:
        analysis = derive_cluster_binomial_analysis(protocol, observations)

    limitations = [
        (
            "Confirmatory exact inference retains every frozen planned cluster and "
            "assigns response zero to each non-analyzable cluster; observed analyzable "
            "cluster counts remain separate descriptive facts."
        ),
        (
            "Observed pair counterexamples are sample facts; the independent-"
            "cluster response rate is a separate inferential summary."
        ),
        (
            "Sufficiency establishes only evaluated operational checks for a "
            "schema-validated design; it does not verify cluster independence, "
            "causality, external validity, or general provider quality."
        ),
    ]
    if state is not SufficiencyState.satisfied:
        limitations.append("Unsatisfied or inconclusive prerequisites prohibit a passing verdict.")
    if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture:
        limitations.append(
            "Deterministic fixture execution reports observations only and bypasses inference."
        )
    return StatisticalSufficiencyReport.build(
        report_id=f"{protocol.protocol_id}/sufficiency",
        protocol=protocol,
        source_runsets=source_runsets,
        observations=observations,
        state=state,
        planned_pairs=protocol.planned_pairs,
        actual_pairs=actual_pairs,
        included_pairs=len(included),
        missing_pairs=missing_pairs,
        excluded_pairs=excluded_pairs,
        planned_clusters=len(protocol.planned_cluster_ids),
        actual_clusters=actual_clusters,
        analyzable_clusters=analyzable_clusters,
        disposition_counts=_disposition_counts(observations),
        prerequisites=prerequisites,
        analysis=analysis,
        population_claim_permitted=(
            state is SufficiencyState.satisfied
            and protocol.execution_mode is SensitivityExecutionMode.stochastic_live
            and protocol.interpretation is SensitivityInterpretation.confirmatory
        ),
        limitations=tuple(sorted(limitations)),
    )


def build_stochastic_sensitivity_report(
    sufficiency: StatisticalSufficiencyReport,
) -> StochasticEvidenceSensitivityReport:
    """Build the only verdict-bearing result from authenticated sufficiency."""

    sufficiency = StatisticalSufficiencyReport.model_validate(sufficiency.model_dump(mode="json"))
    protocol = sufficiency.protocol
    included = tuple(
        item for item in sufficiency.observations if item.disposition is PairDisposition.included
    )
    pair_responses = sum(item.endpoint_value == 1 for item in included)
    pair_counterexamples = len(included) - pair_responses
    cluster_responses = derive_cluster_response_vector(
        protocol,
        sufficiency.observations,
    )
    responding_clusters = sum(cluster_responses)
    estimated_rate = None
    if (
        protocol.execution_mode is SensitivityExecutionMode.stochastic_live
        and sufficiency.state is not SufficiencyState.prerequisites_unmet
    ):
        estimated_rate = (
            sufficiency.analysis.planned_cluster_response_rate
            if sufficiency.analysis is not None
            else None
        )

    if sufficiency.state is SufficiencyState.prerequisites_unmet:
        state = StochasticSensitivityState.prerequisites_unmet
    elif sufficiency.state is SufficiencyState.inconclusive:
        state = StochasticSensitivityState.inconclusive
    else:
        analysis = sufficiency.analysis
        if analysis is None:
            raise ValueError("satisfied stochastic sufficiency requires an analysis")
        supported = cluster_binomial_rejection_region_contains(
            trials=analysis.compared_clusters,
            successes=analysis.responding_clusters,
            critical_successes=protocol.design.critical_cluster_responses,
        )
        state = StochasticSensitivityState.pass_ if supported else StochasticSensitivityState.block

    verdict_bearing = state in {
        StochasticSensitivityState.pass_,
        StochasticSensitivityState.block,
    }
    gate_effect = (
        StochasticGateEffect.pass_
        if state is StochasticSensitivityState.pass_
        else StochasticGateEffect.block
        if state is StochasticSensitivityState.block
        else StochasticGateEffect.non_verdict
    )
    population_claim = (
        "expected_decision_response_cluster_rate_above_null_supported"
        if state is StochasticSensitivityState.pass_
        else "expected_decision_response_cluster_rate_above_null_not_supported"
        if state is StochasticSensitivityState.block
        else "none"
    )
    dependency = (
        ArtifactDependency(
            target_artifact_id=sufficiency.report_id,
            target_digest=sufficiency.report_digest,
        )
        if verdict_bearing
        else None
    )
    limitations = [
        (
            "Confirmatory estimated response rates use the full planned-cluster "
            "denominator with non-analyzable clusters assigned response zero; "
            "observed cluster counts remain descriptive."
        ),
        (
            "The population statement is scoped to the predeclared provider, "
            "model, exact configurations, corpus pair, case population, and protocol."
        ),
        (
            "An observed pair counterexample and the estimated independent-cluster "
            "response rate are distinct; neither is a causal or general quality claim."
        ),
    ]
    if not verdict_bearing:
        limitations.append(
            "This result is non-verdict because statistical prerequisites were not satisfied."
        )
    return StochasticEvidenceSensitivityReport.build(
        report_id=f"{protocol.protocol_id}/stochastic-result",
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol.protocol_digest,
        sufficiency_report=sufficiency,
        dependency=dependency,
        state=state,
        gate_effect=gate_effect,
        verdict_bearing=verdict_bearing,
        population_claim=population_claim,
        observed_pair_count=len(included),
        observed_response_count=pair_responses,
        observed_counterexample_count=pair_counterexamples,
        observed_cluster_count=len(cluster_responses),
        observed_cluster_response_count=responding_clusters,
        estimated_response_rate=estimated_rate,
        limitations=tuple(sorted(limitations)),
    )


def _validated_observations(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
) -> tuple[PairedSensitivityObservation, ...]:
    if not isinstance(observations, tuple):
        raise TypeError("observations must be a tuple")
    canonical = tuple(
        sorted(
            (
                PairedSensitivityObservation.model_validate(item.model_dump(mode="json"))
                for item in observations
            ),
            key=lambda item: (item.case_id, item.repetition_index),
        )
    )
    keys = tuple((item.case_id, item.repetition_index) for item in canonical)
    expected = tuple(
        (case_id, repetition)
        for case_id in protocol.planned_case_ids
        for repetition in range(protocol.repetitions_per_arm)
    )
    if keys != expected:
        raise ValueError("paired observations must exactly and uniquely cover the planned manifest")
    return canonical


def _disposition_counts(
    observations: tuple[PairedSensitivityObservation, ...],
) -> tuple[PairDispositionCount, ...]:
    counts = Counter(
        (item.disposition, item.disposition_reason)
        for item in observations
        if item.disposition is not PairDisposition.included
    )
    return tuple(
        PairDispositionCount(
            disposition=disposition,
            reason_code=reason or "unspecified",
            count=count,
        )
        for (disposition, reason), count in sorted(
            counts.items(),
            key=lambda item: (item[0][0].value, item[0][1] or ""),
        )
    )


def _six_place_input(value: str, *, name: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except Exception as error:
        raise ValueError(f"{name} must be a finite six-place decimal") from error
    if not parsed.is_finite() or decimal_string(parsed) != value:
        raise ValueError(f"{name} must use canonical six-place decimal syntax")
    return parsed


def _six_place_probability(value: Decimal, *, rounding: str) -> str:
    if not value.is_finite() or not Decimal("0") <= value <= Decimal("1"):
        raise ValueError("probability must be finite and in [0, 1]")
    with localcontext() as context:
        context.prec = max(32, len(value.as_tuple().digits) + 2)
        rendered = value.quantize(Decimal("0.000001"), rounding=rounding)
    return f"{rendered:.6f}"


def _probability_ceiling(value: Decimal) -> str:
    return _six_place_probability(value, rounding=ROUND_CEILING)


def _probability_floor(value: Decimal) -> str:
    return _six_place_probability(value, rounding=ROUND_FLOOR)


__all__ = [
    "analyze_cluster_response",
    "build_stochastic_sensitivity_report",
    "evaluate_statistical_sufficiency",
    "plan_binary_paired_design",
    "validate_binary_paired_design_plan",
]
