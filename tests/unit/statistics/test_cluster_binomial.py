from __future__ import annotations

from dataclasses import FrozenInstanceError
from decimal import Decimal, localcontext
from math import comb

import pytest

from agent_assure.statistics import clear_cluster_binomial_caches, cluster_binomial
from agent_assure.statistics.cluster_binomial import (
    MAX_CLUSTERS,
    MAX_MONTE_CARLO_BERNOULLI_DRAWS,
    RATIONAL_BERNOULLI_SAMPLER_ID,
    SHA256_COUNTER_BITSTREAM_ID,
    ClusterBinomialAnalysis,
    analyze_cluster_binomial,
    cluster_binomial_rejection_region_contains,
    exact_binomial_upper_tail,
    plan_cluster_binomial_design,
)


def _brute_tail(trials: int, threshold: int, probability: Decimal) -> Decimal:
    if threshold == 0:
        return Decimal("1")
    if threshold > trials:
        return Decimal("0")
    if probability == Decimal("0"):
        return Decimal("0")
    if probability == Decimal("1"):
        return Decimal("1")
    with localcontext() as context:
        context.prec = 200
        return sum(
            (
                Decimal(comb(trials, successes))
                * probability**successes
                * (Decimal("1") - probability) ** (trials - successes)
                for successes in range(threshold, trials + 1)
            ),
            start=Decimal("0"),
        )


def _brute_design(
    *,
    adjusted_alpha: Decimal,
    desired_power: Decimal,
    null_response_rate: Decimal,
    alternative_response_rate: Decimal,
    max_clusters: int,
) -> tuple[int, int] | None:
    for clusters in range(1, max_clusters + 1):
        for critical in range(1, clusters + 1):
            if (
                _brute_tail(clusters, critical, null_response_rate) <= adjusted_alpha
                and Decimal(critical) / Decimal(clusters) > null_response_rate
            ):
                if _brute_tail(clusters, critical, alternative_response_rate) >= desired_power:
                    return clusters, critical
                break
    return None


@pytest.mark.parametrize(
    "probability",
    [
        Decimal("0.000000"),
        Decimal("0.000001"),
        Decimal("0.100000"),
        Decimal("0.500000"),
        Decimal("0.900000"),
        Decimal("0.999999"),
        Decimal("1.000000"),
    ],
)
def test_exact_tail_matches_brute_force_small_vectors(probability: Decimal) -> None:
    for trials in range(0, 9):
        for threshold in range(0, trials + 2):
            assert exact_binomial_upper_tail(
                trials,
                threshold,
                probability,
            ) == _brute_tail(trials, threshold, probability)


def test_exact_tail_reference_vector_is_not_six_place_rounded() -> None:
    assert exact_binomial_upper_tail(8, 7, Decimal("0.500000")) == Decimal("0.03515625")
    assert exact_binomial_upper_tail(8, 7, Decimal("0.900000")) == Decimal("0.81310473")


def test_exact_tail_is_monotone_in_threshold() -> None:
    tails = tuple(
        exact_binomial_upper_tail(20, threshold, Decimal("0.370000")) for threshold in range(0, 22)
    )
    assert all(left >= right for left, right in zip(tails, tails[1:], strict=False))
    assert tails[0] == Decimal("1")
    assert tails[-1] == Decimal("0")


@pytest.mark.parametrize(
    ("value", "error"),
    [
        (Decimal("-0.000001"), "in \\[0, 1\\]"),
        (Decimal("1.000001"), "in \\[0, 1\\]"),
        (Decimal("0.1234567"), "six decimal"),
        (Decimal("NaN"), "finite"),
        (Decimal("Infinity"), "finite"),
    ],
)
def test_exact_tail_rejects_invalid_probabilities(value: Decimal, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        exact_binomial_upper_tail(4, 2, value)


def test_probability_arguments_require_decimal_not_float() -> None:
    with pytest.raises(TypeError, match="Decimal"):
        exact_binomial_upper_tail(4, 2, 0.5)  # type: ignore[arg-type]


def test_planner_reference_vector_and_exact_operating_characteristics() -> None:
    design = plan_cluster_binomial_design(
        adjusted_alpha=Decimal("0.050000"),
        desired_power=Decimal("0.800000"),
        null_response_rate=Decimal("0.500000"),
        alternative_response_rate=Decimal("0.900000"),
    )

    assert design.required_clusters == 8
    assert design.critical_successes == 7
    assert design.exact_type_i_error == Decimal("0.03515625")
    assert design.achieved_power == Decimal("0.81310473")
    assert design.exact_type_i_error == exact_binomial_upper_tail(
        design.required_clusters,
        design.critical_successes,
        design.null_response_rate,
    )
    assert design.achieved_power == exact_binomial_upper_tail(
        design.required_clusters,
        design.critical_successes,
        design.alternative_response_rate,
    )


@pytest.mark.parametrize(
    ("alpha", "power", "p0", "p1", "limit"),
    [
        ("0.100000", "0.500000", "0.000000", "0.500000", 8),
        ("0.100000", "0.700000", "0.100000", "0.700000", 20),
        ("0.100000", "0.700000", "0.123456", "0.654321", 20),
        ("0.050000", "0.800000", "0.500000", "0.900000", 20),
        ("0.200000", "0.600000", "0.700000", "1.000000", 30),
        ("0.900000", "0.800000", "0.500000", "0.600000", 100),
    ],
)
def test_planner_matches_brute_force_minimum_design(
    alpha: str,
    power: str,
    p0: str,
    p1: str,
    limit: int,
) -> None:
    expected = _brute_design(
        adjusted_alpha=Decimal(alpha),
        desired_power=Decimal(power),
        null_response_rate=Decimal(p0),
        alternative_response_rate=Decimal(p1),
        max_clusters=limit,
    )
    assert expected is not None
    design = plan_cluster_binomial_design(
        adjusted_alpha=Decimal(alpha),
        desired_power=Decimal(power),
        null_response_rate=Decimal(p0),
        alternative_response_rate=Decimal(p1),
        max_clusters=limit,
    )
    assert (design.required_clusters, design.critical_successes) == expected


def test_high_alpha_planner_and_gate_share_one_exact_rejection_region() -> None:
    design = plan_cluster_binomial_design(
        adjusted_alpha=Decimal("0.900000"),
        desired_power=Decimal("0.800000"),
        null_response_rate=Decimal("0.500000"),
        alternative_response_rate=Decimal("0.600000"),
        max_clusters=100,
    )

    assert design.required_clusters > 2
    assert Decimal(design.critical_successes) / Decimal(design.required_clusters) > Decimal(
        "0.500000"
    )
    for successes in range(design.required_clusters + 1):
        planned_region = successes >= design.critical_successes
        p_value_and_direction = (
            exact_binomial_upper_tail(
                design.required_clusters,
                successes,
                design.null_response_rate,
            )
            <= design.adjusted_alpha
            and Decimal(successes) / Decimal(design.required_clusters) > design.null_response_rate
        )
        assert (
            cluster_binomial_rejection_region_contains(
                trials=design.required_clusters,
                successes=successes,
                critical_successes=design.critical_successes,
            )
            is planned_region
            is p_value_and_direction
        )


def test_planner_is_monotone_in_effect_power_and_alpha() -> None:
    base = plan_cluster_binomial_design(
        adjusted_alpha=Decimal("0.050000"),
        desired_power=Decimal("0.800000"),
        null_response_rate=Decimal("0.500000"),
        alternative_response_rate=Decimal("0.800000"),
    )
    stronger_effect = plan_cluster_binomial_design(
        adjusted_alpha=Decimal("0.050000"),
        desired_power=Decimal("0.800000"),
        null_response_rate=Decimal("0.500000"),
        alternative_response_rate=Decimal("0.900000"),
    )
    higher_power = plan_cluster_binomial_design(
        adjusted_alpha=Decimal("0.050000"),
        desired_power=Decimal("0.900000"),
        null_response_rate=Decimal("0.500000"),
        alternative_response_rate=Decimal("0.800000"),
    )
    stricter_alpha = plan_cluster_binomial_design(
        adjusted_alpha=Decimal("0.010000"),
        desired_power=Decimal("0.800000"),
        null_response_rate=Decimal("0.500000"),
        alternative_response_rate=Decimal("0.800000"),
    )

    assert stronger_effect.required_clusters <= base.required_clusters
    assert higher_power.required_clusters >= base.required_clusters
    assert stricter_alpha.required_clusters >= base.required_clusters


def test_planner_completes_the_full_bounded_search() -> None:
    with pytest.raises(ValueError, match="within 10000"):
        plan_cluster_binomial_design(
            adjusted_alpha=Decimal("0.000001"),
            desired_power=Decimal("0.999999"),
            null_response_rate=Decimal("0.500000"),
            alternative_response_rate=Decimal("0.500001"),
            max_clusters=MAX_CLUSTERS,
        )


def test_planner_rejects_invalid_domains_and_work_bounds() -> None:
    arguments = {
        "adjusted_alpha": Decimal("0.050000"),
        "desired_power": Decimal("0.800000"),
        "null_response_rate": Decimal("0.500000"),
        "alternative_response_rate": Decimal("0.900000"),
    }
    with pytest.raises(ValueError, match="exceed"):
        plan_cluster_binomial_design(
            **{**arguments, "alternative_response_rate": Decimal("0.500000")}
        )
    with pytest.raises(ValueError, match="strictly between"):
        plan_cluster_binomial_design(**{**arguments, "adjusted_alpha": Decimal("0")})
    with pytest.raises(ValueError, match="max_clusters"):
        plan_cluster_binomial_design(**arguments, max_clusters=MAX_CLUSTERS + 1)


def test_analysis_always_uses_exact_analytic_p_value() -> None:
    result = analyze_cluster_binomial(
        (1, 1, 1, 0, 1, 0),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="protocol-a",
        exact_diagnostic_cap=100,
        monte_carlo_resamples=2_000,
    )

    assert result.cluster_count == 6
    assert result.success_count == 4
    assert result.exact_p_value == Decimal("0.34375")
    assert result.monte_carlo_diagnostic is None


def test_monte_carlo_diagnostic_has_stable_reference_vector() -> None:
    result = analyze_cluster_binomial(
        (1, 1, 1, 0, 1, 0),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="protocol-a",
        exact_diagnostic_cap=5,
        monte_carlo_resamples=2_000,
    )
    diagnostic = result.monte_carlo_diagnostic

    assert result.exact_p_value == Decimal("0.34375")
    assert diagnostic is not None
    assert diagnostic.seed_digest == (
        "797e54b0adbfe82f11a2528b9f86be6f017eb84fc20afc601daa324dcfdde038"
    )
    assert diagnostic.extreme_count == 683
    assert diagnostic.plus_one_numerator == 684
    assert diagnostic.plus_one_denominator == 2_001
    assert diagnostic.plus_one_estimate == Decimal(
        "0.34182908545727136431784107946026986506746626686657"
    )
    assert diagnostic.bitstream_id == SHA256_COUNTER_BITSTREAM_ID
    assert diagnostic.sampler_id == RATIONAL_BERNOULLI_SAMPLER_ID
    assert diagnostic.plus_one_estimate != result.exact_p_value


def test_monte_carlo_is_exchangeable_and_reproducible() -> None:
    arguments = {
        "null_response_rate": Decimal("0.370000"),
        "diagnostic_seed_material": "registered-protocol-digest",
        "exact_diagnostic_cap": 3,
        "monte_carlo_resamples": 1_000,
    }
    endpoints = (1, 0, 1, 1, 0, 0)

    first = analyze_cluster_binomial(endpoints, **arguments)
    repeated = analyze_cluster_binomial(endpoints, **arguments)
    reordered = analyze_cluster_binomial(tuple(reversed(endpoints)), **arguments)

    assert first == repeated == reordered


def test_pure_exact_derivations_are_memoized_by_canonical_inputs() -> None:
    clear_cluster_binomial_caches()
    plan_arguments = {
        "adjusted_alpha": Decimal("0.050000"),
        "desired_power": Decimal("0.800000"),
        "null_response_rate": Decimal("0.500000"),
        "alternative_response_rate": Decimal("0.900000"),
    }
    analysis_arguments = {
        "null_response_rate": Decimal("0.500000"),
        "diagnostic_seed_material": "cache-bound-protocol",
        "exact_diagnostic_cap": 3,
        "monte_carlo_resamples": 1_000,
    }

    assert plan_cluster_binomial_design(**plan_arguments) == plan_cluster_binomial_design(
        **plan_arguments
    )
    assert analyze_cluster_binomial((1, 1, 1, 0), **analysis_arguments) == (
        analyze_cluster_binomial((0, 1, 1, 1), **analysis_arguments)
    )

    assert cluster_binomial._plan_cluster_binomial_design_cached.cache_info().hits == 1
    assert cluster_binomial._analyze_cluster_binomial_cached.cache_info().hits == 1
    assert cluster_binomial._analyze_cluster_binomial_cached.cache_info().currsize == 1


def test_public_cache_clear_releases_all_exact_statistics_entries() -> None:
    clear_cluster_binomial_caches()
    exact_binomial_upper_tail(8, 6, Decimal("0.500000"))
    plan_cluster_binomial_design(
        adjusted_alpha=Decimal("0.050000"),
        desired_power=Decimal("0.800000"),
        null_response_rate=Decimal("0.500000"),
        alternative_response_rate=Decimal("0.900000"),
    )
    analyze_cluster_binomial(
        (1, 1, 1, 0),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="cache-lifecycle-protocol",
        exact_diagnostic_cap=3,
        monte_carlo_resamples=1_000,
    )

    assert cluster_binomial._exact_binomial_upper_tail_cached.cache_info().currsize > 0
    assert cluster_binomial._plan_cluster_binomial_design_cached.cache_info().currsize > 0
    assert cluster_binomial._analyze_cluster_binomial_cached.cache_info().currsize > 0

    clear_cluster_binomial_caches()

    assert cluster_binomial._exact_binomial_upper_tail_cached.cache_info().currsize == 0
    assert cluster_binomial._plan_cluster_binomial_design_cached.cache_info().currsize == 0
    assert cluster_binomial._analyze_cluster_binomial_cached.cache_info().currsize == 0


def test_seed_is_domain_bound_to_every_diagnostic_input() -> None:
    base = analyze_cluster_binomial(
        (1, 1, 0, 0),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="protocol-a",
        exact_diagnostic_cap=0,
        monte_carlo_resamples=500,
    )
    changed_material = analyze_cluster_binomial(
        (1, 1, 0, 0),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="protocol-b",
        exact_diagnostic_cap=0,
        monte_carlo_resamples=500,
    )
    changed_null = analyze_cluster_binomial(
        (1, 1, 0, 0),
        null_response_rate=Decimal("0.500001"),
        diagnostic_seed_material="protocol-a",
        exact_diagnostic_cap=0,
        monte_carlo_resamples=500,
    )
    changed_success_count = analyze_cluster_binomial(
        (1, 1, 1, 0),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="protocol-a",
        exact_diagnostic_cap=0,
        monte_carlo_resamples=500,
    )
    changed_resamples = analyze_cluster_binomial(
        (1, 1, 0, 0),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="protocol-a",
        exact_diagnostic_cap=0,
        monte_carlo_resamples=501,
    )

    digests = {
        result.monte_carlo_diagnostic.seed_digest
        for result in (
            base,
            changed_material,
            changed_null,
            changed_success_count,
            changed_resamples,
        )
        if result.monte_carlo_diagnostic is not None
    }
    assert len(digests) == 5


@pytest.mark.parametrize(
    ("probability", "endpoints", "expected_exact", "expected_extreme"),
    [
        ("0.000000", (1, 0, 0), "0", 0),
        ("0.000000", (0, 0, 0), "1", 200),
        ("1.000000", (1, 1, 1), "1", 200),
        ("1.000000", (1, 0, 0), "1", 200),
    ],
)
def test_extreme_null_probabilities_are_exact_and_deterministic(
    probability: str,
    endpoints: tuple[int, ...],
    expected_exact: str,
    expected_extreme: int,
) -> None:
    result = analyze_cluster_binomial(
        endpoints,  # type: ignore[arg-type]
        null_response_rate=Decimal(probability),
        diagnostic_seed_material="edge-case",
        exact_diagnostic_cap=0,
        monte_carlo_resamples=200,
    )
    assert result.exact_p_value == Decimal(expected_exact)
    assert result.monte_carlo_diagnostic is not None
    assert result.monte_carlo_diagnostic.extreme_count == expected_extreme


def test_analysis_rejects_invalid_endpoints_seed_and_work() -> None:
    arguments = {
        "null_response_rate": Decimal("0.500000"),
        "diagnostic_seed_material": "protocol",
    }
    with pytest.raises(TypeError, match="tuple"):
        analyze_cluster_binomial(  # type: ignore[arg-type]
            [0, 1],
            **arguments,
        )
    with pytest.raises(ValueError, match="literal integer"):
        analyze_cluster_binomial((False, True), **arguments)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="literal integer"):
        analyze_cluster_binomial((0, 2), **arguments)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="cannot be empty"):
        analyze_cluster_binomial(
            (0,),
            null_response_rate=Decimal("0.500000"),
            diagnostic_seed_material="",
        )

    endpoints = (0,) * MAX_CLUSTERS
    excessive_resamples = MAX_MONTE_CARLO_BERNOULLI_DRAWS // len(endpoints) + 1
    with pytest.raises(ValueError, match="draw budget"):
        analyze_cluster_binomial(
            endpoints,
            null_response_rate=Decimal("0.500000"),
            diagnostic_seed_material="protocol",
            exact_diagnostic_cap=0,
            monte_carlo_resamples=excessive_resamples,
        )


def test_returned_dataclasses_are_frozen() -> None:
    result = analyze_cluster_binomial(
        (0, 1),
        null_response_rate=Decimal("0.500000"),
        diagnostic_seed_material="protocol",
    )
    with pytest.raises(FrozenInstanceError):
        result.success_count = 2  # type: ignore[misc]
    assert isinstance(result, ClusterBinomialAnalysis)
