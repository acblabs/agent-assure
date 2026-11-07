"""Independent exact-arithmetic design QA for ADR 0019.

These finite reference checks exercise mathematical identities and small-history
counterexamples. They do not call production statistics, estimate empirical
efficacy, qualify a sampling design, or supply independent human method admission.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from fractions import Fraction
from itertools import product
from math import comb, factorial, prod

import pytest

ZERO = Fraction(0)
ONE = Fraction(1)
HALF = Fraction(1, 2)
VALUES = (ZERO, Fraction(1, 4), HALF, Fraction(3, 4), ONE)
MARGINS = (Fraction(1, 4), HALF, Fraction(3, 4))


def _histories(max_length: int) -> Iterator[tuple[Fraction, ...]]:
    for length in range(max_length + 1):
        yield from product(VALUES, repeat=length)


def _pseudo_moments(
    delta: Fraction, history: Sequence[Fraction]
) -> tuple[Fraction, Fraction, Fraction]:
    """Compute moments directly from the weighted atoms, not the closed formula."""
    atoms = ((ZERO, ONE - delta), (ONE, delta)) + tuple((x, ONE) for x in history)
    weight = sum((mass for _, mass in atoms), ZERO)
    mean = sum((x * mass for x, mass in atoms), ZERO) / weight
    second = sum((x * x * mass for x, mass in atoms), ZERO) / weight
    variance = sum((mass * (x - mean) ** 2 for x, mass in atoms), ZERO) / weight
    return mean, second, variance


def _bets(delta: Fraction, history: Sequence[Fraction]) -> tuple[Fraction, Fraction]:
    mean, _, variance = _pseudo_moments(delta, history)
    ratio = (mean - delta) / (variance + (mean - delta) ** 2)
    return max(-HALF / (ONE - delta), min(ZERO, ratio)), min(HALF / delta, max(ZERO, ratio))


@pytest.mark.parametrize("delta", MARGINS)
def test_centered_pseudomeasure_has_exact_moments_and_positive_variance(
    delta: Fraction,
) -> None:
    for history in _histories(4):
        mean, second, variance = _pseudo_moments(delta, history)
        weight = len(history) + 1
        assert mean == (delta + sum(history, ZERO)) / weight
        assert second == (delta + sum((x * x for x in history), ZERO)) / weight
        assert variance == second - mean * mean

        # Expand the two Bernoulli pseudo-atoms about the empirical mean.
        centered_sum = sum(((x - mean) ** 2 for x in history), ZERO)
        assert weight * variance == (delta * (ONE - delta) + (delta - mean) ** 2 + centered_sum)
        assert variance >= delta * (ONE - delta) / weight > ZERO

        # Independently center all real observations about the null boundary.
        boundary_second = (
            delta * (ONE - delta) + sum(((x - delta) ** 2 for x in history), ZERO)
        ) / weight
        assert variance + (mean - delta) ** 2 == boundary_second > ZERO


@pytest.mark.parametrize("delta", MARGINS)
def test_directional_sign_caps_factor_floor_and_null_expectation(delta: Fraction) -> None:
    for history in _histories(3):
        pass_bet, fail_bet = _bets(delta, history)
        assert -HALF / (ONE - delta) <= pass_bet <= ZERO
        assert ZERO <= fail_bet <= HALF / delta
        for value in VALUES:
            assert ONE + pass_bet * (value - delta) >= HALF
            assert ONE + fail_bet * (value - delta) >= HALF

        # The factor is affine: Bernoulli endpoint masses realize each mean.
        # With a predictable fixed bet, this is the conditional one-step check.
        for null_mean in VALUES:
            pass_expectation = (ONE - null_mean) * (ONE - pass_bet * delta) + null_mean * (
                ONE + pass_bet * (ONE - delta)
            )
            fail_expectation = (ONE - null_mean) * (ONE - fail_bet * delta) + null_mean * (
                ONE + fail_bet * (ONE - delta)
            )
            assert pass_expectation == ONE + pass_bet * (null_mean - delta)
            assert fail_expectation == ONE + fail_bet * (null_mean - delta)
            if null_mean >= delta:
                assert pass_expectation <= ONE
            if null_mean <= delta:
                assert fail_expectation <= ONE
            if null_mean == delta:
                assert pass_expectation == fail_expectation == ONE


@pytest.mark.parametrize(
    ("delta", "history", "expected_pass", "expected_fail", "next_value", "next_factor"),
    [
        (HALF, (ZERO,), Fraction(-1), ZERO, ZERO, Fraction(3, 2)),
        (Fraction(1, 4), (ZERO,), Fraction(-2, 3), ZERO, ZERO, Fraction(7, 6)),
        (Fraction(1, 4), (ONE,), ZERO, ONE, ONE, Fraction(7, 4)),
    ],
)
def test_frozen_adr_directional_vectors(
    delta: Fraction,
    history: tuple[Fraction, ...],
    expected_pass: Fraction,
    expected_fail: Fraction,
    next_value: Fraction,
    next_factor: Fraction,
) -> None:
    pass_bet, fail_bet = _bets(delta, history)
    assert (pass_bet, fail_bet) == (expected_pass, expected_fail)
    active_bet = fail_bet if next_value == ONE else pass_bet
    assert ONE + active_bet * (next_value - delta) == next_factor


@pytest.mark.parametrize("delta", MARGINS)
def test_entire_first_batch_has_zero_bets_and_unit_wealth(delta: Fraction) -> None:
    pass_bet, fail_bet = _bets(delta, ())
    assert pass_bet == fail_bet == ZERO
    for batch in _histories(4):
        # One checkpoint freezes the bet for the whole batch, without updates.
        for bet in (pass_bet, fail_bet):
            wealth = prod((ONE + bet * (x - delta) for x in batch), start=ONE)
            assert wealth == ONE
            for alpha in (HALF, Fraction(1, 20), Fraction(1, 100)):
                assert wealth < ONE / alpha

    # Updating within an assigned first batch would change its contract.
    serial_second_pass, _ = _bets(delta, (ZERO,))
    assert ONE + serial_second_pass * (ZERO - delta) > ONE


def test_shared_latent_batch_refutes_marginal_only_null_argument() -> None:
    # This valid-sign/cap fixed FAIL bet demonstrates the theorem's assumption
    # boundary; it is not the actual zero bet selected by D1 at empty history.
    delta = HALF
    fixed_bet = ONE
    assert fixed_bet == HALF / delta
    marginal_factor_mean = sum(
        (HALF * (ONE + fixed_bet * (latent - delta)) for latent in (ZERO, ONE)), ZERO
    )
    assert marginal_factor_mean == ONE
    shared_latent_batch_mean = sum(
        (HALF * (ONE + fixed_bet * (latent - delta)) ** 2 for latent in (ZERO, ONE)), ZERO
    )
    assert shared_latent_batch_mean == Fraction(5, 4) > ONE
    # If the first value is one, the second conditional mean is one, not <=1/2.
    assert ONE > delta


def _integrated_binary_likelihood(successes: int, failures: int) -> Fraction:
    """Integrate theta**s*(1-theta)**f by its exact polynomial expansion."""
    return sum(
        (Fraction((-1) ** j * comb(failures, j), successes + j + 1) for j in range(failures + 1)),
        ZERO,
    )


def _b1_value(history: Sequence[int], probability: Fraction) -> Fraction:
    successes = sum(history)
    failures = len(history) - successes
    null_likelihood = probability**successes * (ONE - probability) ** failures
    if null_likelihood == ZERO:
        raise ValueError("null-impossible boundary history")
    return _integrated_binary_likelihood(successes, failures) / null_likelihood


def test_uniform_binary_mixture_integral_matches_factorial_identity() -> None:
    for successes, failures in product(range(9), repeat=2):
        expected = Fraction(
            factorial(successes) * factorial(failures), factorial(successes + failures + 1)
        )
        assert _integrated_binary_likelihood(successes, failures) == expected > ZERO


@pytest.mark.parametrize("probability", MARGINS)
def test_interior_uniform_binary_mixture_has_exact_conditional_martingale_identity(
    probability: Fraction,
) -> None:
    for length in range(7):
        for history in product((0, 1), repeat=length):
            current = _b1_value(history, probability)
            conditional_next = (ONE - probability) * _b1_value(
                (*history, 0), probability
            ) + probability * _b1_value((*history, 1), probability)
            assert conditional_next == current


@pytest.mark.parametrize(("probability", "compatible_bit"), [(ZERO, 0), (ONE, 1)])
def test_boundary_uniform_binary_mixture_is_nonincreasing_on_feasible_paths(
    probability: Fraction, compatible_bit: int
) -> None:
    previous = ONE
    for length in range(13):
        history = (compatible_bit,) * length
        value = _b1_value(history, probability)
        assert value == Fraction(1, length + 1)
        assert ZERO < value <= previous
        previous = value
        # Impossible observations are typed exclusions, never stored infinity.
        with pytest.raises(ValueError, match="null-impossible boundary history"):
            _b1_value((*history, 1 - compatible_bit), probability)
