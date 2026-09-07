"""Exact one-sided Clopper--Pearson intervals for binomial proportions.

The Clopper--Pearson construction inverts an exact binomial tail.  This
implementation deliberately depends only on the Python standard library and
uses integer arithmetic for every tail comparison.  Decimal arithmetic is
used only to render the final dyadic bisection endpoint, so callers do not
inherit the process-wide Decimal context or binary-float behavior.

The returned endpoint is conservative: lower bounds use the lower endpoint of
the final root bracket and upper bounds use the upper endpoint.  Consequently,
rounding a lower bound toward zero or an upper bound away from zero preserves
coverage.  The finite bisection error is reported explicitly.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
from math import comb
from typing import Final, Literal, TypeAlias

from agent_assure.statistics.cluster_binomial import PROBABILITY_SCALE, PROBABILITY_SCALE_DIGITS

IntervalSide: TypeAlias = Literal["lower", "upper"]

CLOPPER_PEARSON_METHOD: Final[Literal["clopper_pearson_exact_one_sided"]] = (
    "clopper_pearson_exact_one_sided"
)
"""Stable identifier for the interval construction."""

CLOPPER_PEARSON_BISECTION_STEPS: Final = 80
"""Number of binary root-refinement steps for non-boundary intervals."""

MAX_CLOPPER_PEARSON_TRIALS: Final = 1_000
"""Hard resource bound for one interval evaluation.

The integer binomial-tail work grows roughly cubically with ``trials`` for
non-boundary intervals because each bisection step evaluates a tail of large
integer powers. One reference run measured approximately 0.04 s, 0.15 s,
0.43 s, and 1.65 s at ``n = 100, 250, 500, 1000``, respectively. At the
otherwise permitted structural maximum of two bounds for each of 64
1,000-trial conditions, that implies roughly 3.5 minutes without an aggregate
guard. These figures are illustrative calibration points, not latency
guarantees; Python build, CPU, load, endpoint, and alpha all matter. The
declared maximum is intentionally an offline resource ceiling, not a latency
target. Callers accepting collections of intervals must additionally enforce
``MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS`` before evaluating any member.
"""

MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS: Final = 160_000_000
"""Maximum uncached exact-tail work accepted from one persisted collection.

One work unit represents one binomial-tail recurrence term at one trial of
integer bit width for one bisection comparison. The proxy deliberately
overestimates analytic and early-exact-root cases and does not claim to be a
wall-clock model. Identical ``(successes, trials, alpha)`` pairs are charged
once because both exact calls fit inside the 512-entry LRU for the 64-condition
study limit. The ceiling admits two distinct worst-case two-sided interval
pairs at ``n=1000`` and every possible pair at the canonical ``n=42``.

This validation ceiling is intentionally below the structural 64-condition by
1000-trial maximum. A preregistered design whose possible distinct intervals
can exceed it must be reduced or partitioned into separately preregistered,
independently interpreted studies before observations begin. It must not be
split after outcomes are known to evade either this resource limit or the
frozen multiplicity family.
"""

_BISECTION_DENOMINATOR: Final = 1 << CLOPPER_PEARSON_BISECTION_STEPS


@dataclass(frozen=True, slots=True)
class ClopperPearsonInterval:
    """A conservative numerical representation of an exact one-sided interval.

    ``bound`` is the non-trivial endpoint: it is a lower confidence bound when
    ``side == "lower"`` and an upper confidence bound otherwise.  The opposite
    endpoint is zero or one, respectively.  ``absolute_error_bound`` is zero
    for analytic boundary cases and exact dyadic roots; otherwise it is the
    width of the final bisection bracket.
    """

    successes: int
    trials: int
    alpha: Decimal
    confidence_level: Decimal
    side: IntervalSide
    bound: Decimal
    absolute_error_bound: Decimal
    bisection_steps: int
    method: Literal["clopper_pearson_exact_one_sided"] = CLOPPER_PEARSON_METHOD


def clopper_pearson_one_sided(
    successes: int,
    trials: int,
    alpha: Decimal,
    *,
    side: IntervalSide,
) -> ClopperPearsonInterval:
    """Return an exact one-sided Clopper--Pearson confidence bound.

    ``successes`` and ``trials`` must be literal integers (booleans are not
    accepted). ``alpha`` must be a finite :class:`~decimal.Decimal`, strictly
    between zero and one, and exactly representable to six decimal places.
    The confidence level is ``1 - alpha``.

    For a lower bound with ``x > 0``, this function solves

    ``P_p[Binomial(n, p) >= x] = alpha``.

    For an upper bound with ``x < n``, it solves the equivalent equation

    ``P_p[Binomial(n, p) >= x + 1] = 1 - alpha``.

    The statistical construction is exact.  A non-analytic root is enclosed
    by 80 deterministic bisection steps, and the outward endpoint is returned
    so numerical approximation cannot make the interval anti-conservative.
    """

    validated_trials = _bounded_int(
        trials,
        name="trials",
        lower=1,
        upper=MAX_CLOPPER_PEARSON_TRIALS,
    )
    validated_successes = _bounded_int(
        successes,
        name="successes",
        lower=0,
        upper=validated_trials,
    )
    alpha_numerator = _alpha_numerator(alpha)
    validated_side = _interval_side(side)
    return _clopper_pearson_one_sided_cached(
        validated_successes,
        validated_trials,
        alpha_numerator,
        validated_side,
    )


@lru_cache(maxsize=512)
def _clopper_pearson_one_sided_cached(
    successes: int,
    trials: int,
    alpha_numerator: int,
    side: IntervalSide,
) -> ClopperPearsonInterval:
    alpha = _scaled_probability(alpha_numerator)
    confidence_level = _scaled_probability(PROBABILITY_SCALE - alpha_numerator)

    if side == "lower" and successes == 0:
        return ClopperPearsonInterval(
            successes=successes,
            trials=trials,
            alpha=alpha,
            confidence_level=confidence_level,
            side=side,
            bound=Decimal("0"),
            absolute_error_bound=Decimal("0"),
            bisection_steps=0,
        )
    if side == "upper" and successes == trials:
        return ClopperPearsonInterval(
            successes=successes,
            trials=trials,
            alpha=alpha,
            confidence_level=confidence_level,
            side=side,
            bound=Decimal("1"),
            absolute_error_bound=Decimal("0"),
            bisection_steps=0,
        )

    if side == "lower":
        threshold = successes
        target_numerator = alpha_numerator
        choose_upper_endpoint = False
    else:
        threshold = successes + 1
        target_numerator = PROBABILITY_SCALE - alpha_numerator
        choose_upper_endpoint = True

    lower_index, upper_index, iterations = _invert_increasing_binomial_tail(
        trials=trials,
        threshold=threshold,
        target_numerator=target_numerator,
        target_denominator=PROBABILITY_SCALE,
    )
    exact_root = lower_index == upper_index
    selected_index = upper_index if choose_upper_endpoint else lower_index
    bound = _dyadic_decimal(selected_index)
    absolute_error_bound = (
        Decimal("0") if exact_root else _dyadic_decimal(upper_index - lower_index)
    )
    return ClopperPearsonInterval(
        successes=successes,
        trials=trials,
        alpha=alpha,
        confidence_level=confidence_level,
        side=side,
        bound=bound,
        absolute_error_bound=absolute_error_bound,
        bisection_steps=iterations,
    )


def clear_binomial_interval_cache() -> None:
    """Clear bounded interval memoization at a quiescent process boundary."""

    _clopper_pearson_one_sided_cached.cache_clear()


def clopper_pearson_work_units(
    successes: int,
    trials: int,
    *,
    side: IntervalSide,
) -> int:
    """Return a deterministic upper-bound proxy for one uncached evaluation.

    The result mirrors the exact implementation's shorter-tail selection and
    charges for every configured bisection comparison. It intentionally does
    not discount possible cache hits: persisted-input validation must remain
    bounded even when an adversary chooses every count to defeat memoization.
    """

    validated_trials = _bounded_int(
        trials,
        name="trials",
        lower=1,
        upper=MAX_CLOPPER_PEARSON_TRIALS,
    )
    validated_successes = _bounded_int(
        successes,
        name="successes",
        lower=0,
        upper=validated_trials,
    )
    validated_side = _interval_side(side)
    if (
        validated_side == "lower"
        and validated_successes == 0
        or validated_side == "upper"
        and validated_successes == validated_trials
    ):
        return 0
    threshold = validated_successes if validated_side == "lower" else validated_successes + 1
    recurrence_terms = min(
        threshold,
        validated_trials - threshold + 1,
    )
    return CLOPPER_PEARSON_BISECTION_STEPS * validated_trials * recurrence_terms


def clopper_pearson_interval_pair_work_units(successes: int, trials: int) -> int:
    """Return the conservative work proxy for lower and upper bounds together."""

    return clopper_pearson_work_units(
        successes,
        trials,
        side="lower",
    ) + clopper_pearson_work_units(
        successes,
        trials,
        side="upper",
    )


def validate_clopper_pearson_work_budget(
    intervals: Iterable[tuple[int, int, Decimal]],
    *,
    maximum_work_units: int = MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS,
) -> int:
    """Fail fast if a collection of lower/upper interval pairs is too costly.

    Each input tuple is ``(successes, trials, alpha)`` for one persisted
    interval pair. Exact duplicate cache keys are charged once; a different
    alpha is distinct because it defeats the underlying interval cache. The
    running total is checked after every new key, so a lazy or oversized
    untrusted collection cannot force unbounded preprocessing. Callers parsing
    nested models must invoke this helper on raw fields *before* individual
    interval validators perform exact-tail recomputation.
    """

    validated_maximum = _bounded_int(
        maximum_work_units,
        name="maximum_work_units",
        lower=1,
        upper=MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS,
    )
    total = 0
    seen: set[tuple[int, int, int]] = set()
    for successes, trials, alpha in intervals:
        pair_work = clopper_pearson_interval_pair_work_units(successes, trials)
        alpha_numerator = _alpha_numerator(alpha)
        cache_key = (successes, trials, alpha_numerator)
        if cache_key in seen:
            continue
        seen.add(cache_key)
        total += pair_work
        if total > validated_maximum:
            raise ValueError(
                "aggregate Clopper-Pearson exact-tail work exceeds the "
                f"{validated_maximum} unit resource limit"
            )
    return total


def _invert_increasing_binomial_tail(
    *,
    trials: int,
    threshold: int,
    target_numerator: int,
    target_denominator: int,
) -> tuple[int, int, int]:
    """Bracket the unique solution to an increasing binomial-tail equation."""

    lower_index = 0
    upper_index = _BISECTION_DENOMINATOR
    iterations = 0
    while upper_index - lower_index > 1:
        midpoint_index = (lower_index + upper_index) // 2
        comparison = _compare_binomial_upper_tail(
            trials=trials,
            threshold=threshold,
            probability_numerator=midpoint_index,
            probability_denominator=_BISECTION_DENOMINATOR,
            target_numerator=target_numerator,
            target_denominator=target_denominator,
        )
        iterations += 1
        if comparison < 0:
            lower_index = midpoint_index
        elif comparison > 0:
            upper_index = midpoint_index
        else:
            # A dyadic root can be represented exactly; no outward adjustment
            # is necessary (for example x=n=1 and alpha=0.5).
            return midpoint_index, midpoint_index, iterations

    if iterations != CLOPPER_PEARSON_BISECTION_STEPS:
        raise ArithmeticError("internal Clopper-Pearson bisection did not converge as bounded")
    return lower_index, upper_index, iterations


def _compare_binomial_upper_tail(
    *,
    trials: int,
    threshold: int,
    probability_numerator: int,
    probability_denominator: int,
    target_numerator: int,
    target_denominator: int,
) -> int:
    """Compare a binomial upper tail with a rational target exactly."""

    probability_numerator, probability_denominator = _reduce_dyadic_probability(
        probability_numerator,
        probability_denominator,
    )
    tail_numerator, tail_denominator = _binomial_upper_tail_fraction(
        trials,
        threshold,
        probability_numerator,
        probability_denominator,
    )
    left = tail_numerator * target_denominator
    right = target_numerator * tail_denominator
    return (left > right) - (left < right)


def _binomial_upper_tail_fraction(
    trials: int,
    threshold: int,
    probability_numerator: int,
    probability_denominator: int,
) -> tuple[int, int]:
    """Return an unreduced exact rational binomial upper tail."""

    denominator = probability_denominator**trials
    if threshold == 0:
        return denominator, denominator
    if threshold > trials or probability_numerator == 0:
        return 0, denominator
    if probability_numerator == probability_denominator:
        return denominator, denominator

    failure_numerator = probability_denominator - probability_numerator
    lower_term_count = threshold
    upper_term_count = trials - threshold + 1
    if lower_term_count <= upper_term_count:
        term = failure_numerator**trials
        lower_numerator = 0
        for successes in range(threshold):
            lower_numerator += term
            if successes + 1 < threshold:
                term = _exact_quotient(
                    term * (trials - successes) * probability_numerator,
                    (successes + 1) * failure_numerator,
                )
        return denominator - lower_numerator, denominator

    term = (
        comb(trials, threshold)
        * probability_numerator**threshold
        * failure_numerator ** (trials - threshold)
    )
    tail_numerator = 0
    for successes in range(threshold, trials + 1):
        tail_numerator += term
        if successes < trials:
            term = _exact_quotient(
                term * (trials - successes) * probability_numerator,
                (successes + 1) * failure_numerator,
            )
    return tail_numerator, denominator


def _reduce_dyadic_probability(numerator: int, denominator: int) -> tuple[int, int]:
    if numerator == 0:
        return 0, 1
    # The denominator is a power of two, so its only possible common factor
    # with the numerator is the numerator's trailing power of two.
    trailing_zero_bits = (numerator & -numerator).bit_length() - 1
    denominator_bits = denominator.bit_length() - 1
    shift = min(trailing_zero_bits, denominator_bits)
    return numerator >> shift, denominator >> shift


def _dyadic_decimal(numerator: int) -> Decimal:
    if numerator == 0:
        return Decimal("0")
    if numerator == _BISECTION_DENOMINATOR:
        return Decimal("1")
    # A / 2**k == (A * 5**k) / 10**k. Constructing that terminating decimal
    # avoids division and is independent of the ambient Decimal context.
    coefficient = numerator * (5**CLOPPER_PEARSON_BISECTION_STEPS)
    return _terminating_decimal(
        coefficient,
        fractional_places=CLOPPER_PEARSON_BISECTION_STEPS,
    )


def _alpha_numerator(value: Decimal) -> int:
    if not isinstance(value, Decimal):
        raise TypeError("alpha must be a Decimal")
    if not value.is_finite():
        raise ValueError("alpha must be finite")
    components = value.as_tuple()
    raw_exponent = components.exponent
    if not isinstance(raw_exponent, int):
        raise ValueError("alpha must be finite")
    if components.sign or not any(components.digits):
        raise ValueError("alpha must be strictly between zero and one")
    exponent = int(raw_exponent)
    if len(components.digits) + exponent > 0:
        raise ValueError("alpha must be strictly between zero and one")
    significant_end = len(components.digits)
    while significant_end > 1 and components.digits[significant_end - 1] == 0:
        significant_end -= 1
        exponent += 1
    scale_exponent = exponent + PROBABILITY_SCALE_DIGITS
    if scale_exponent < 0:
        raise ValueError("alpha must be exactly representable to six decimal places")
    if scale_exponent > PROBABILITY_SCALE_DIGITS:
        raise ValueError("alpha must be strictly between zero and one")
    coefficient: int = 0
    for digit in components.digits[:significant_end]:
        coefficient = coefficient * 10 + int(digit)
    scaled_numerator: int = int(coefficient * (10**scale_exponent))
    if not 0 < scaled_numerator < PROBABILITY_SCALE:
        raise ArithmeticError("internal alpha scaling escaped its validated probability range")
    return scaled_numerator


def _bounded_int(value: int, *, name: str, lower: int, upper: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < lower or value > upper:
        raise ValueError(f"{name} must be in [{lower}, {upper}]")
    return value


def _interval_side(value: IntervalSide) -> IntervalSide:
    if not isinstance(value, str):
        raise TypeError("side must be a string")
    if value == "lower":
        return "lower"
    if value == "upper":
        return "upper"
    raise ValueError("side must be 'lower' or 'upper'")


def _scaled_probability(numerator: int) -> Decimal:
    return _terminating_decimal(
        numerator,
        fractional_places=PROBABILITY_SCALE_DIGITS,
    )


def _terminating_decimal(coefficient: int, *, fractional_places: int) -> Decimal:
    """Construct a non-negative terminating Decimal without consulting context."""

    if coefficient == 0:
        return Decimal("0")
    exponent = -fractional_places
    while coefficient % 10 == 0:
        coefficient //= 10
        exponent += 1
    digits = tuple(ord(character) - ord("0") for character in str(coefficient))
    return Decimal((0, digits, exponent))


def _exact_quotient(numerator: int, denominator: int) -> int:
    quotient, remainder = divmod(numerator, denominator)
    if remainder:
        raise ArithmeticError("internal binomial recurrence lost integer exactness")
    return quotient


__all__ = [
    "CLOPPER_PEARSON_BISECTION_STEPS",
    "CLOPPER_PEARSON_METHOD",
    "MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS",
    "MAX_CLOPPER_PEARSON_TRIALS",
    "ClopperPearsonInterval",
    "IntervalSide",
    "clear_binomial_interval_cache",
    "clopper_pearson_interval_pair_work_units",
    "clopper_pearson_one_sided",
    "clopper_pearson_work_units",
    "validate_clopper_pearson_work_budget",
]
