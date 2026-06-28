from __future__ import annotations

import math
from collections import defaultdict
from decimal import Decimal
from statistics import mean
from typing import Literal, cast

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.intervals import percentile_interval, seeded_random, stable_seed_int
from agent_assure.schema.common import GateState
from agent_assure.schema.live import (
    AdvancedAnalysisPlan,
    ClusterCorrelationSummary,
    EndpointPrerequisiteStatus,
    LiveObservationResult,
    LiveProtocolRecord,
    PairedRandomizationTestResult,
    RareEventUpperBound,
    StatisticalEndpointPlan,
    StatisticalInvariantResult,
)
from agent_assure.schema.run import AgentRunRecord

_SIX_PLACES = Decimal("0.000001")
_MAX_EXACT_PERMUTATION_CLUSTERS = 20
_MONTE_CARLO_RESAMPLES = 10000
_ICC_BOOTSTRAP_ITERATIONS = 1000
_RandomizationMethod = Literal[
    "paired_cluster_permutation_exact",
    "paired_cluster_permutation_monte_carlo",
]
_IccUncertaintyMethod = Literal["cluster_bootstrap_percentile", "not_evaluated"]
_ObservedIccConfirmatoryUse = Literal[
    "disabled",
    "eligible_large_cluster_threshold",
    "eligible_external_review",
]


def evaluate_statistical_invariants(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    protocol: LiveProtocolRecord,
) -> tuple[StatisticalInvariantResult, ...]:
    plan = protocol.advanced_analysis_plan
    if plan is None:
        return ()
    confirmatory_count = sum(
        1 for endpoint in plan.endpoints if endpoint.interpretation == "confirmatory"
    )
    return tuple(
        _evaluate_endpoint(
            endpoint,
            runs,
            observations,
            protocol=protocol,
            plan=plan,
            confirmatory_count=confirmatory_count,
        )
        for endpoint in plan.endpoints
    )


def evaluate_paired_randomization_test(
    differences: tuple[Decimal, ...],
    *,
    protocol: LiveProtocolRecord,
    prerequisite_status: EndpointPrerequisiteStatus,
    limitations: tuple[str, ...] = (),
) -> PairedRandomizationTestResult | None:
    if protocol.analysis_method not in {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }:
        return None
    plan = protocol.advanced_analysis_plan
    if plan is None:
        return None
    endpoint = next(endpoint for endpoint in plan.endpoints if endpoint.role == "primary")
    observed = _mean(differences)
    margin = Decimal(protocol.non_inferiority_margin)
    seed_material = f"{protocol.protocol_id}:{protocol.analysis_digest}:paired-permutation"
    if prerequisite_status == "met":
        p_value, resamples, exhaustive = _permutation_p_value(
            differences,
            margin=margin,
            method=protocol.analysis_method,
            seed=seed_material,
        )
        adjusted_p_value = _adjust_p_value(
            p_value,
            plan=plan,
            endpoint=endpoint,
        )
    else:
        p_value = None
        adjusted_p_value = None
        resamples = 0
        exhaustive = False
    return PairedRandomizationTestResult(
        artifact_kind="paired-randomization-test-result",
        endpoint_id=endpoint.endpoint_id,
        label=endpoint.label,
        interpretation=endpoint.interpretation,
        analysis_method=cast(_RandomizationMethod, protocol.analysis_method),
        prerequisite_status=prerequisite_status,
        exchangeability_assumption=endpoint.exchangeability_assumption,
        compared_clusters=len(differences),
        observed_difference=_signed_decimal(observed),
        non_inferiority_margin=_decimal(margin),
        p_value=_probability(p_value) if p_value is not None else None,
        adjusted_p_value=_probability(adjusted_p_value) if adjusted_p_value is not None else None,
        exhaustive=exhaustive,
        resamples=resamples,
        seed=str(stable_seed_int(seed_material)) if not exhaustive else None,
        limitations=limitations,
    )


def paired_randomization_prerequisites(
    *,
    protocol: LiveProtocolRecord,
    compared_clusters: int,
) -> tuple[EndpointPrerequisiteStatus, tuple[str, ...]]:
    if protocol.analysis_method not in {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }:
        return "invalid", ("protocol did not declare a paired randomization method",)
    plan = protocol.advanced_analysis_plan
    if plan is None:
        return "invalid", ("protocol did not declare an advanced analysis plan",)
    endpoint = next(endpoint for endpoint in plan.endpoints if endpoint.role == "primary")
    limitations: list[str] = []
    if endpoint.exchangeability_assumption != "baseline_candidate_relabeling":
        limitations.append(
            "paired randomization requires the declared baseline/candidate relabeling "
            "exchangeability assumption"
        )
        return "invalid", tuple(limitations)
    if compared_clusters == 0:
        return "invalid", ("no paired clusters were available for randomization testing",)
    if (
        protocol.analysis_method == "paired_cluster_permutation_exact"
        and compared_clusters > _MAX_EXACT_PERMUTATION_CLUSTERS
    ):
        limitations.append(
            "exact paired permutation was declared with more clusters than the exact "
            "enumeration limit"
        )
        return "invalid", tuple(limitations)
    if compared_clusters < endpoint.minimum_clusters:
        limitations.append(
            "compared cluster count is below the predeclared endpoint threshold"
        )
        return "exploratory", tuple(limitations)
    return "met", ()


def _evaluate_endpoint(
    endpoint: StatisticalEndpointPlan,
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    *,
    protocol: LiveProtocolRecord,
    plan: AdvancedAnalysisPlan,
    confirmatory_count: int,
) -> StatisticalInvariantResult:
    values = _endpoint_values(endpoint, runs, observations)
    numerator = sum(1 for _, event in values if event)
    denominator = len(values)
    cluster_count = len({cluster_id for cluster_id, _ in values})
    prerequisite_status = _endpoint_prerequisite_status(
        endpoint,
        denominator=denominator,
        cluster_count=cluster_count,
        event_count=numerator,
    )
    adjusted_alpha = _endpoint_alpha(
        endpoint,
        plan=plan,
        confirmatory_count=confirmatory_count,
    )
    limitations = list(
        _endpoint_limitations(
            endpoint,
            prerequisite_status=prerequisite_status,
            denominator=denominator,
            cluster_count=cluster_count,
        )
    )
    rare_event_bound = None
    if endpoint.analysis_method == "poisson_upper_bound":
        rare_event_bound = _rare_event_bound(
            endpoint,
            observed_events=numerator,
            exposure=denominator,
            confidence_alpha=adjusted_alpha,
            protocol=protocol,
        )
        limitations.extend(rare_event_bound.limitations)
    cluster_correlation = _cluster_correlation_summary(
        endpoint,
        values,
        protocol=protocol,
        plan=plan,
    )
    return StatisticalInvariantResult(
        artifact_kind="statistical-invariant-result",
        endpoint_id=endpoint.endpoint_id,
        label=endpoint.label,
        endpoint_kind=endpoint.endpoint_kind,
        role=endpoint.role,
        interpretation=endpoint.interpretation,
        analysis_method=endpoint.analysis_method,
        prerequisite_status=prerequisite_status,
        multiplicity_method=plan.multiplicity_method,
        adjusted_alpha=_decimal(adjusted_alpha),
        numerator=numerator,
        denominator=denominator,
        cluster_count=cluster_count,
        rate=_rate(numerator, denominator),
        reason_codes=endpoint.reason_codes,
        outcome=endpoint.outcome,
        rare_event_bound=rare_event_bound,
        cluster_correlation=cluster_correlation,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _endpoint_values(
    endpoint: StatisticalEndpointPlan,
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
) -> tuple[tuple[str, bool], ...]:
    pairs = tuple(zip(runs, observations, strict=True))
    if endpoint.endpoint_kind == "expectation_pass_rate":
        return tuple(
            (observation.cluster_id, observation.state is GateState.pass_)
            for _, observation in pairs
            if observation.observation_status == "included"
        )
    if endpoint.endpoint_kind == "exclusion_rate":
        return tuple(
            (observation.cluster_id, observation.observation_status == "excluded")
            for _, observation in pairs
        )
    if endpoint.endpoint_kind in {"reason_code_rate", "critical_event_rate"}:
        reason_codes = set(endpoint.reason_codes)
        return tuple(
            (
                observation.cluster_id,
                bool(reason_codes.intersection(observation.reason_codes)),
            )
            for _, observation in pairs
            if observation.observation_status == "included"
        )
    if endpoint.endpoint_kind == "outcome_rate":
        return tuple(
            (observation.cluster_id, run.outcome == endpoint.outcome)
            for run, observation in pairs
            if observation.observation_status == "included"
        )
    raise ValueError(f"unsupported endpoint kind: {endpoint.endpoint_kind}")


def _endpoint_prerequisite_status(
    endpoint: StatisticalEndpointPlan,
    *,
    denominator: int,
    cluster_count: int,
    event_count: int,
) -> EndpointPrerequisiteStatus:
    if denominator < endpoint.minimum_observations:
        return "invalid"
    if cluster_count < endpoint.minimum_clusters:
        return "exploratory"
    if event_count < endpoint.minimum_events:
        return "exploratory"
    if endpoint.analysis_method in {
        "hierarchical_binomial_summary",
        "beta_binomial_cluster_summary",
    } and cluster_count < 2:
        return "invalid"
    return "met"


def _endpoint_alpha(
    endpoint: StatisticalEndpointPlan,
    *,
    plan: AdvancedAnalysisPlan,
    confirmatory_count: int,
) -> Decimal:
    alpha = Decimal(plan.familywise_alpha)
    if endpoint.interpretation != "confirmatory":
        return alpha
    if plan.multiplicity_method == "holm_bonferroni" and confirmatory_count > 1:
        return alpha / Decimal(confirmatory_count)
    return alpha


def _adjust_p_value(
    p_value: Decimal,
    *,
    plan: AdvancedAnalysisPlan,
    endpoint: StatisticalEndpointPlan,
) -> Decimal:
    if endpoint.interpretation != "confirmatory":
        return p_value
    if plan.multiplicity_method == "holm_bonferroni":
        confirmatory_count = sum(
            1 for candidate in plan.endpoints if candidate.interpretation == "confirmatory"
        )
        return min(Decimal("1"), p_value * Decimal(confirmatory_count))
    return p_value


def _endpoint_limitations(
    endpoint: StatisticalEndpointPlan,
    *,
    prerequisite_status: EndpointPrerequisiteStatus,
    denominator: int,
    cluster_count: int,
) -> tuple[str, ...]:
    limitations: list[str] = []
    if prerequisite_status == "invalid":
        limitations.append(
            "endpoint prerequisites were not met, so this endpoint is not evaluated"
        )
    elif prerequisite_status == "exploratory":
        limitations.append(
            "endpoint prerequisites were not sufficient for confirmatory interpretation"
        )
    if denominator == 0:
        limitations.append("endpoint exposure is zero")
    if cluster_count < endpoint.minimum_clusters:
        limitations.append(
            "observed cluster count is below the predeclared endpoint threshold"
        )
    return tuple(limitations)


def _rare_event_bound(
    endpoint: StatisticalEndpointPlan,
    *,
    observed_events: int,
    exposure: int,
    confidence_alpha: Decimal,
    protocol: LiveProtocolRecord,
) -> RareEventUpperBound:
    if exposure == 0:
        upper_count = Decimal("0")
        upper_rate = Decimal("0")
    else:
        upper_count = _poisson_upper_count_bound(
            observed_events,
            alpha=confidence_alpha,
        )
        upper_rate = upper_count / Decimal(exposure)
    limitations = []
    if observed_events == 0:
        limitations.append(
            "zero observed events produce an upper bound, not proof that the event is absent"
        )
    return RareEventUpperBound(
        artifact_kind="rare-event-upper-bound",
        endpoint_id=endpoint.endpoint_id,
        label=endpoint.label,
        observed_events=observed_events,
        exposure=exposure,
        exposure_unit=endpoint.exposure_unit,
        event_rate=_rate(observed_events, exposure),
        upper_count_bound=_decimal(upper_count),
        upper_rate_bound=_decimal(upper_rate),
        confidence_level=protocol.confidence_level,
        analysis_method="poisson_upper_bound",
        zero_events=observed_events == 0,
        limitations=tuple(limitations),
    )


def _cluster_correlation_summary(
    endpoint: StatisticalEndpointPlan,
    values: tuple[tuple[str, bool], ...],
    *,
    protocol: LiveProtocolRecord,
    plan: AdvancedAnalysisPlan,
) -> ClusterCorrelationSummary:
    clustered = _cluster_counts(values)
    cluster_count = len(clustered)
    observation_count = sum(denominator for _, denominator in clustered.values())
    seed = sha256_hexdigest(
        {
            "protocol_id": protocol.protocol_id,
            "analysis_digest": protocol.analysis_digest,
            "endpoint_id": endpoint.endpoint_id,
            "purpose": "cluster-correlation-bootstrap",
        }
    )
    observed_icc = _icc_from_counts(tuple(clustered.values()))
    lower: Decimal | None = None
    upper: Decimal | None = None
    uncertainty_method: _IccUncertaintyMethod = "not_evaluated"
    iterations = 0
    limitations: list[str] = [
        "observed cluster correlation is reported as descriptive evidence; "
        "confirmatory rate intervals continue to use the predeclared planning value"
    ]
    if observed_icc is not None and cluster_count >= 3:
        lower, upper = _bootstrap_icc_interval(
            tuple(clustered.values()),
            seed=seed,
            confidence_level=protocol.confidence_level,
            iterations=_ICC_BOOTSTRAP_ITERATIONS,
        )
        uncertainty_method = "cluster_bootstrap_percentile"
        iterations = _ICC_BOOTSTRAP_ITERATIONS
    elif cluster_count < 3:
        limitations.append("fewer than three clusters makes ICC uncertainty not evaluated")
    confirmatory_use: _ObservedIccConfirmatoryUse = "disabled"
    if plan.observed_icc_confirmatory_use == "external_review":
        confirmatory_use = "eligible_external_review"
    elif (
        plan.observed_icc_confirmatory_use == "large_cluster_threshold"
        and plan.observed_icc_large_cluster_threshold is not None
        and cluster_count >= plan.observed_icc_large_cluster_threshold
    ):
        confirmatory_use = "eligible_large_cluster_threshold"
    return ClusterCorrelationSummary(
        artifact_kind="cluster-correlation-summary",
        endpoint_id=endpoint.endpoint_id,
        label=endpoint.label,
        cluster_count=cluster_count,
        observation_count=observation_count,
        planned_intraclass_correlation=protocol.assumed_intraclass_correlation,
        observed_intraclass_correlation=(
            _signed_decimal(observed_icc) if observed_icc is not None else None
        ),
        uncertainty_method=uncertainty_method,
        ci_lower=_signed_decimal(lower) if lower is not None else None,
        ci_upper=_signed_decimal(upper) if upper is not None else None,
        bootstrap_iterations=iterations,
        confirmatory_use=confirmatory_use,
        confirmatory_interval_uses_planned_icc=True,
        limitations=tuple(limitations),
    )


def _cluster_counts(values: tuple[tuple[str, bool], ...]) -> dict[str, tuple[int, int]]:
    clustered: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for cluster_id, event in values:
        clustered[cluster_id][0] += int(event)
        clustered[cluster_id][1] += 1
    return {cluster_id: (counts[0], counts[1]) for cluster_id, counts in clustered.items()}


def _icc_from_counts(counts: tuple[tuple[int, int], ...]) -> Decimal | None:
    if len(counts) < 2:
        return None
    total_observations = sum(denominator for _, denominator in counts)
    if total_observations <= len(counts):
        return None
    total_successes = sum(numerator for numerator, _ in counts)
    grand_mean = Decimal(total_successes) / Decimal(total_observations)
    between = sum(
        Decimal(denominator) * ((Decimal(numerator) / Decimal(denominator)) - grand_mean) ** 2
        for numerator, denominator in counts
    )
    within = sum(
        Decimal(denominator)
        * (Decimal(numerator) / Decimal(denominator))
        * (Decimal("1") - (Decimal(numerator) / Decimal(denominator)))
        for numerator, denominator in counts
    )
    ms_between = between / Decimal(len(counts) - 1)
    ms_within = within / Decimal(total_observations - len(counts))
    squared_sizes = sum(Decimal(denominator * denominator) for _, denominator in counts)
    n_bar = (Decimal(total_observations) - squared_sizes / Decimal(total_observations)) / Decimal(
        len(counts) - 1
    )
    denominator = ms_between + (n_bar - Decimal("1")) * ms_within
    if denominator == 0:
        return Decimal("0")
    return max(Decimal("-1"), min(Decimal("1"), (ms_between - ms_within) / denominator))


def _bootstrap_icc_interval(
    counts: tuple[tuple[int, int], ...],
    *,
    seed: str,
    confidence_level: str,
    iterations: int,
) -> tuple[Decimal, Decimal]:
    rng = seeded_random(seed)
    estimates: list[Decimal] = []
    for _ in range(iterations):
        sample = tuple(counts[rng.randrange(len(counts))] for _ in range(len(counts)))
        estimate = _icc_from_counts(sample)
        if estimate is not None:
            estimates.append(estimate)
    if not estimates:
        return Decimal("0"), Decimal("0")
    return percentile_interval(tuple(sorted(estimates)), confidence_level)


def _permutation_p_value(
    differences: tuple[Decimal, ...],
    *,
    margin: Decimal,
    method: str,
    seed: str,
) -> tuple[Decimal, int, bool]:
    shifted = tuple(difference + margin for difference in differences)
    observed = _mean(shifted)
    if not shifted:
        return Decimal("1"), 0, False
    if method == "paired_cluster_permutation_exact":
        if len(shifted) > _MAX_EXACT_PERMUTATION_CLUSTERS:
            return Decimal("1"), 0, False
        count = 0
        total = 1 << len(shifted)
        for mask in range(total):
            statistic = sum(
                value if mask & (1 << index) else -value
                for index, value in enumerate(shifted)
            ) / Decimal(len(shifted))
            if statistic >= observed:
                count += 1
        return Decimal(count) / Decimal(total), total, True
    rng = seeded_random(seed)
    count = 1
    total = _MONTE_CARLO_RESAMPLES + 1
    for _ in range(_MONTE_CARLO_RESAMPLES):
        statistic = sum(
            value if rng.randrange(2) else -value
            for value in shifted
        ) / Decimal(len(shifted))
        if statistic >= observed:
            count += 1
    return Decimal(count) / Decimal(total), total, False


def _poisson_upper_count_bound(events: int, *, alpha: Decimal) -> Decimal:
    alpha_float = float(alpha)
    low = 0.0
    high = max(1.0, float(events + 1))
    while _poisson_cdf(events, high) > alpha_float:
        high *= 2.0
    for _ in range(80):
        midpoint = (low + high) / 2.0
        if _poisson_cdf(events, midpoint) > alpha_float:
            low = midpoint
        else:
            high = midpoint
    return Decimal(str(high))


def _poisson_cdf(events: int, rate: float) -> float:
    term = math.exp(-rate)
    total = term
    for index in range(1, events + 1):
        term *= rate / index
        total += term
    return total


def _mean(values: tuple[Decimal, ...]) -> Decimal:
    if not values:
        return Decimal("0")
    return Decimal(str(mean(values)))


def _rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.000000"
    return _probability(Decimal(numerator) / Decimal(denominator))


def _probability(value: Decimal) -> str:
    return _decimal(min(Decimal("1"), max(Decimal("0"), value)))


def _signed_decimal(value: Decimal) -> str:
    return _decimal(max(Decimal("-1"), min(Decimal("1"), value)))


def _decimal(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    if projected == Decimal("-0"):
        projected = Decimal("0")
    quantized = projected.quantize(_SIX_PLACES)
    if quantized == Decimal("-0.000000"):
        quantized = Decimal("0.000000")
    return f"{quantized:f}"
