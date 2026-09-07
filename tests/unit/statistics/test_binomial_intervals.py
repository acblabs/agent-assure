from __future__ import annotations

from dataclasses import FrozenInstanceError
from decimal import (
    ROUND_CEILING,
    ROUND_FLOOR,
    ROUND_HALF_EVEN,
    Decimal,
    Inexact,
    Overflow,
    Rounded,
    Underflow,
    localcontext,
)
from math import comb

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_assure.statistics.binomial_intervals import (
    CLOPPER_PEARSON_BISECTION_STEPS,
    CLOPPER_PEARSON_METHOD,
    MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS,
    MAX_CLOPPER_PEARSON_TRIALS,
    ClopperPearsonInterval,
    clear_binomial_interval_cache,
    clopper_pearson_interval_pair_work_units,
    clopper_pearson_one_sided,
    clopper_pearson_work_units,
    validate_clopper_pearson_work_budget,
)


def _decimal_upper_tail(
    trials: int,
    threshold: int,
    probability: Decimal,
) -> Decimal:
    """Independent direct-sum oracle used only by these small-vector tests."""

    with localcontext() as context:
        context.prec = 180
        failure_probability = Decimal("1") - probability
        return sum(
            (
                Decimal(comb(trials, successes))
                * probability**successes
                * failure_probability ** (trials - successes)
                for successes in range(threshold, trials + 1)
            ),
            start=Decimal("0"),
        )


@pytest.mark.parametrize(
    ("successes", "trials", "side", "expected"),
    [
        # Reference values independently reproduced by R's qbeta formulation:
        # lower=qbeta(.05, x, n-x+1), upper=qbeta(.95, x+1, n-x).
        (1, 10, "lower", "0.005116196891824"),
        (1, 10, "upper", "0.394163302436505"),
        (2, 10, "lower", "0.036771437887465"),
        (2, 10, "upper", "0.506901301063202"),
        (5, 10, "lower", "0.222441101008129"),
        (5, 10, "upper", "0.777558898991871"),
        (20, 30, "lower", "0.500561302824047"),
        (20, 30, "upper", "0.806691578879407"),
    ],
)
def test_reference_vectors(
    successes: int,
    trials: int,
    side: str,
    expected: str,
) -> None:
    result = clopper_pearson_one_sided(
        successes,
        trials,
        Decimal("0.050000"),
        side=side,  # type: ignore[arg-type]
    )

    with localcontext() as context:
        context.prec = 100
        rendered = result.bound.quantize(
            Decimal("0.000000000000001"),
            rounding=ROUND_HALF_EVEN,
        )
    assert rendered == Decimal(expected)
    assert result.method == CLOPPER_PEARSON_METHOD
    assert result.confidence_level == Decimal("0.95")


def test_lower_bound_brackets_exact_coverage_equation_conservatively() -> None:
    result = clopper_pearson_one_sided(
        5,
        10,
        Decimal("0.050000"),
        side="lower",
    )

    at_bound = _decimal_upper_tail(result.trials, result.successes, result.bound)
    just_above = _decimal_upper_tail(
        result.trials,
        result.successes,
        result.bound + result.absolute_error_bound,
    )
    assert at_bound < result.alpha
    assert just_above > result.alpha
    assert result.absolute_error_bound < Decimal("1e-23")
    assert result.bisection_steps == CLOPPER_PEARSON_BISECTION_STEPS


def test_upper_bound_brackets_exact_coverage_equation_conservatively() -> None:
    result = clopper_pearson_one_sided(
        5,
        10,
        Decimal("0.050000"),
        side="upper",
    )
    target = Decimal("1") - result.alpha

    at_bound = _decimal_upper_tail(result.trials, result.successes + 1, result.bound)
    just_below = _decimal_upper_tail(
        result.trials,
        result.successes + 1,
        result.bound - result.absolute_error_bound,
    )
    assert at_bound > target
    assert just_below < target
    assert result.absolute_error_bound < Decimal("1e-23")
    assert result.bisection_steps == CLOPPER_PEARSON_BISECTION_STEPS


def test_six_place_outward_rendering_preserves_conservatism() -> None:
    lower = clopper_pearson_one_sided(5, 10, Decimal("0.050000"), side="lower")
    upper = clopper_pearson_one_sided(5, 10, Decimal("0.050000"), side="upper")

    with localcontext() as context:
        context.prec = 100
        rendered_lower = lower.bound.quantize(Decimal("0.000001"), rounding=ROUND_FLOOR)
        rendered_upper = upper.bound.quantize(Decimal("0.000001"), rounding=ROUND_CEILING)
    assert rendered_lower == Decimal("0.222441")
    assert rendered_upper == Decimal("0.777559")


def test_boundary_observations_have_analytic_one_sided_bounds() -> None:
    lower = clopper_pearson_one_sided(0, 10, Decimal("0.050000"), side="lower")
    upper = clopper_pearson_one_sided(10, 10, Decimal("0.050000"), side="upper")

    assert lower.bound == Decimal("0")
    assert upper.bound == Decimal("1")
    assert lower.absolute_error_bound == upper.absolute_error_bound == Decimal("0")
    assert lower.bisection_steps == upper.bisection_steps == 0

    # The opposite bounds remain informative at the same observations.
    zero_success_upper = clopper_pearson_one_sided(
        0,
        10,
        Decimal("0.050000"),
        side="upper",
    )
    all_success_lower = clopper_pearson_one_sided(
        10,
        10,
        Decimal("0.050000"),
        side="lower",
    )
    assert zero_success_upper.bound.quantize(Decimal("0.000000000001")) == Decimal("0.258865550893")
    assert all_success_lower.bound.quantize(Decimal("0.000000000001")) == Decimal("0.741134449107")


def test_exact_dyadic_root_stops_without_numerical_error() -> None:
    lower = clopper_pearson_one_sided(1, 1, Decimal("0.500000"), side="lower")
    upper = clopper_pearson_one_sided(0, 1, Decimal("0.500000"), side="upper")

    assert lower.bound == upper.bound == Decimal("0.5")
    assert lower.absolute_error_bound == upper.absolute_error_bound == Decimal("0")
    assert lower.bisection_steps == upper.bisection_steps == 1

    later_root = clopper_pearson_one_sided(1, 1, Decimal("0.250000"), side="lower")
    assert later_root.bound == Decimal("0.25")
    assert later_root.absolute_error_bound == Decimal("0")
    assert later_root.bisection_steps == 2


def test_maximum_supported_trial_count_is_computable() -> None:
    result = clopper_pearson_one_sided(
        MAX_CLOPPER_PEARSON_TRIALS // 2,
        MAX_CLOPPER_PEARSON_TRIALS,
        Decimal("0.050000"),
        side="lower",
    )

    assert Decimal("0") < result.bound < Decimal("0.5")
    assert result.bisection_steps == CLOPPER_PEARSON_BISECTION_STEPS


def test_work_proxy_tracks_analytic_boundaries_and_shorter_exact_tail() -> None:
    trials = MAX_CLOPPER_PEARSON_TRIALS
    one_term_work = CLOPPER_PEARSON_BISECTION_STEPS * trials

    assert clopper_pearson_work_units(0, trials, side="lower") == 0
    assert clopper_pearson_work_units(0, trials, side="upper") == one_term_work
    assert clopper_pearson_work_units(trials, trials, side="lower") == one_term_work
    assert clopper_pearson_work_units(trials, trials, side="upper") == 0
    assert clopper_pearson_interval_pair_work_units(trials // 2, trials) == 80_000_000


def test_aggregate_work_budget_bounds_worst_case_without_evaluating_intervals() -> None:
    worst_pair = (
        MAX_CLOPPER_PEARSON_TRIALS // 2,
        MAX_CLOPPER_PEARSON_TRIALS,
    )
    alpha_values = (Decimal("0.025000"), Decimal("0.016666"), Decimal("0.012500"))

    exactly_at_cap = tuple((*worst_pair, alpha) for alpha in alpha_values[:2])
    assert validate_clopper_pearson_work_budget(exactly_at_cap) == (
        MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS
    )
    with pytest.raises(ValueError, match="aggregate Clopper-Pearson exact-tail work"):
        validate_clopper_pearson_work_budget((*exactly_at_cap, (*worst_pair, alpha_values[2])))


def test_aggregate_work_budget_accepts_limit_and_rejects_one_unit_over() -> None:
    interval = (500, 1_000, Decimal("0.025000"))
    interval_work = clopper_pearson_interval_pair_work_units(*interval[:2])

    assert (
        validate_clopper_pearson_work_budget(
            (interval,),
            maximum_work_units=interval_work,
        )
        == interval_work
    )
    with pytest.raises(ValueError, match=f"{interval_work - 1} unit resource limit"):
        validate_clopper_pearson_work_budget(
            (interval,),
            maximum_work_units=interval_work - 1,
        )


def test_aggregate_work_budget_deduplicates_exact_interval_cache_keys() -> None:
    worst_pair = (
        MAX_CLOPPER_PEARSON_TRIALS // 2,
        MAX_CLOPPER_PEARSON_TRIALS,
        Decimal("0.025000"),
    )

    assert validate_clopper_pearson_work_budget(worst_pair for _ in range(64)) == 80_000_000


def test_aggregate_work_budget_admits_every_canonical_n42_count() -> None:
    alpha = Decimal("0.025000")
    every_count_then_duplicates = tuple(
        (successes, 42, alpha) for successes in (*range(43), *range(21))
    )
    workload = validate_clopper_pearson_work_budget(every_count_then_duplicates)

    assert len(every_count_then_duplicates) == 64
    assert workload == 3_104_640
    assert workload < MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS


@pytest.mark.parametrize("maximum", (0, -1, True, MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS + 1))
def test_aggregate_work_budget_override_is_strictly_bounded(maximum: object) -> None:
    with pytest.raises((TypeError, ValueError), match="maximum_work_units"):
        validate_clopper_pearson_work_budget(
            ((0, 42, Decimal("0.025000")),),
            maximum_work_units=maximum,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("successes", "trials", "error_type", "message"),
    [
        (0, 0, ValueError, "trials must be in"),
        (0, MAX_CLOPPER_PEARSON_TRIALS + 1, ValueError, "trials must be in"),
        (-1, 10, ValueError, "successes must be in"),
        (11, 10, ValueError, "successes must be in"),
        (False, 10, TypeError, "successes must be an integer"),
        (1, True, TypeError, "trials must be an integer"),
        (1.0, 10, TypeError, "successes must be an integer"),
        (1, 10.0, TypeError, "trials must be an integer"),
    ],
)
def test_integer_inputs_are_strict_and_bounded(
    successes: object,
    trials: object,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        clopper_pearson_one_sided(
            successes,  # type: ignore[arg-type]
            trials,  # type: ignore[arg-type]
            Decimal("0.050000"),
            side="lower",
        )


@pytest.mark.parametrize(
    ("alpha", "error_type", "message"),
    [
        (0.05, TypeError, "alpha must be a Decimal"),
        ("0.05", TypeError, "alpha must be a Decimal"),
        (Decimal("NaN"), ValueError, "alpha must be finite"),
        (Decimal("Infinity"), ValueError, "alpha must be finite"),
        (Decimal("-0.1"), ValueError, "strictly between"),
        (Decimal("0"), ValueError, "strictly between"),
        (Decimal("1"), ValueError, "strictly between"),
        (Decimal("1.1"), ValueError, "strictly between"),
        (Decimal("0.1234567"), ValueError, "six decimal places"),
        (Decimal((0, (1,), -1_000_000)), ValueError, "six decimal places"),
    ],
)
def test_alpha_is_a_strict_six_place_decimal(
    alpha: object,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type, match=message):
        clopper_pearson_one_sided(
            5,
            10,
            alpha,  # type: ignore[arg-type]
            side="lower",
        )


def test_side_is_validated_at_runtime() -> None:
    with pytest.raises(ValueError, match="side must be 'lower' or 'upper'"):
        clopper_pearson_one_sided(
            5,
            10,
            Decimal("0.050000"),
            side="two-sided",  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="side must be a string"):
        clopper_pearson_one_sided(
            5,
            10,
            Decimal("0.050000"),
            side=1,  # type: ignore[arg-type]
        )


def test_result_is_frozen() -> None:
    result = clopper_pearson_one_sided(5, 10, Decimal("0.050000"), side="lower")
    assert isinstance(result, ClopperPearsonInterval)
    with pytest.raises(FrozenInstanceError):
        result.bound = Decimal("0")  # type: ignore[misc]


def test_results_do_not_depend_on_ambient_decimal_context() -> None:
    clear_binomial_interval_cache()
    with localcontext() as context:
        context.prec = 1
        context.Emin = -5
        context.Emax = 5
        for signal in (Inexact, Overflow, Rounded, Underflow):
            context.traps[signal] = True
        first = clopper_pearson_one_sided(7, 13, Decimal("0.012345"), side="lower")
    clear_binomial_interval_cache()
    with localcontext() as context:
        context.prec = 60
        second = clopper_pearson_one_sided(7, 13, Decimal("0.012345"), side="lower")

    assert first == second


@given(
    data=st.data(),
    trials=st.integers(min_value=1, max_value=30),
    alpha=st.sampled_from(
        (
            Decimal("0.000001"),
            Decimal("0.001000"),
            Decimal("0.010000"),
            Decimal("0.050000"),
            Decimal("0.100000"),
            Decimal("0.500000"),
            Decimal("0.999999"),
        )
    ),
)
@settings(max_examples=50, deadline=None)
def test_interval_properties_and_success_failure_symmetry(
    data: st.DataObject,
    trials: int,
    alpha: Decimal,
) -> None:
    successes = data.draw(st.integers(min_value=0, max_value=trials))
    lower = clopper_pearson_one_sided(successes, trials, alpha, side="lower")
    upper = clopper_pearson_one_sided(successes, trials, alpha, side="upper")
    complement_upper = clopper_pearson_one_sided(
        trials - successes,
        trials,
        alpha,
        side="upper",
    )

    with localcontext() as context:
        context.prec = 100
        observed_rate = Decimal(successes) / Decimal(trials)
        reflected_upper = Decimal("1") - complement_upper.bound
    assert Decimal("0") <= lower.bound <= Decimal("1")
    assert Decimal("0") <= upper.bound <= Decimal("1")
    if alpha <= Decimal("0.5"):
        assert lower.bound <= observed_rate <= upper.bound
    assert lower.bound == reflected_upper

    if successes > 0:
        lower_tail = _decimal_upper_tail(trials, successes, lower.bound)
        lower_bracket_tail = _decimal_upper_tail(
            trials,
            successes,
            lower.bound + lower.absolute_error_bound,
        )
        assert lower_tail <= alpha <= lower_bracket_tail
    if successes < trials:
        upper_target = Decimal("1") - alpha
        upper_tail = _decimal_upper_tail(trials, successes + 1, upper.bound)
        upper_bracket_tail = _decimal_upper_tail(
            trials,
            successes + 1,
            upper.bound - upper.absolute_error_bound,
        )
        assert upper_bracket_tail <= upper_target <= upper_tail


def test_bounds_are_monotone_in_success_count_and_confidence() -> None:
    lower_bounds = tuple(
        clopper_pearson_one_sided(x, 12, Decimal("0.050000"), side="lower").bound for x in range(13)
    )
    upper_bounds = tuple(
        clopper_pearson_one_sided(x, 12, Decimal("0.050000"), side="upper").bound for x in range(13)
    )
    assert all(left <= right for left, right in zip(lower_bounds, lower_bounds[1:], strict=False))
    assert all(left <= right for left, right in zip(upper_bounds, upper_bounds[1:], strict=False))

    high_confidence_lower = clopper_pearson_one_sided(
        6,
        12,
        Decimal("0.010000"),
        side="lower",
    )
    lower_confidence_lower = clopper_pearson_one_sided(
        6,
        12,
        Decimal("0.100000"),
        side="lower",
    )
    high_confidence_upper = clopper_pearson_one_sided(
        6,
        12,
        Decimal("0.010000"),
        side="upper",
    )
    lower_confidence_upper = clopper_pearson_one_sided(
        6,
        12,
        Decimal("0.100000"),
        side="upper",
    )
    assert high_confidence_lower.bound < lower_confidence_lower.bound
    assert high_confidence_upper.bound > lower_confidence_upper.bound
