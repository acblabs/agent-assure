"""Resource-bounded one-sided upper intervals for binomial proportions.

The Clopper--Pearson construction inverts an exact binomial tail.  This
implementation deliberately depends only on the Python standard library and
uses integer arithmetic for every tail comparison.  Decimal arithmetic is
used only to render the final dyadic bisection endpoint, so callers do not
inherit the process-wide Decimal context or binary-float behavior.

The returned endpoint is conservative: lower bounds use the lower endpoint of
the final root bracket and upper bounds use the upper endpoint.  Consequently,
rounding a lower bound toward zero or an upper bound away from zero preserves
coverage.  The finite bisection error is reported explicitly.

The scalable upper-bound dispatcher retains that exact inversion through the
declared work ceiling. Above it, zero-event inputs use the exact
Clopper--Pearson closed-form boundary with rational log enclosures, while
nonzero inputs invert the one-sided Bernoulli KL-Chernoff inequality with the
same rational log enclosures. Those branches use bounded work independent of
the trial count.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
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

MAX_SCALABLE_BINOMIAL_TRIALS: Final = (1 << 53) - 1
"""Largest trial count exactly representable by the artifact JSON contract."""

ZERO_EVENT_CLOSED_FORM_METHOD: Final[Literal["clopper_pearson_zero_event_closed_form"]] = (
    "clopper_pearson_zero_event_closed_form"
)
"""Exact zero-event Clopper--Pearson boundary, rounded outward."""

BERNOULLI_KL_CHERNOFF_UPPER_BOUND_METHOD: Final[
    Literal["bernoulli_kl_chernoff_upper_bound_one_sided"]
] = "bernoulli_kl_chernoff_upper_bound_one_sided"
"""Conservative scalable KL-Chernoff upper bound for nonzero endpoints."""

BinomialUpperBoundMethod: TypeAlias = Literal[
    "clopper_pearson_exact_one_sided",
    "clopper_pearson_zero_event_closed_form",
    "bernoulli_kl_chernoff_upper_bound_one_sided",
]
_LOG_SERIES_TERMS: Final = 32
# Keep count-scale discretization below one serialized micro-unit even at the
# maximum RFC 8785-safe exposure: MAX_SCALABLE_BINOMIAL_TRIALS / 10**24 < 1e-8.
_SCALABLE_BOUND_SCALE: Final = 10**24


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


@dataclass(frozen=True, slots=True)
class BinomialUpperBound:
    """Persistable one-sided binomial upper bound selected by bounded work."""

    successes: int
    trials: int
    alpha: Decimal
    confidence_level: Decimal
    upper_rate_bound: Decimal
    upper_count_bound: Decimal
    method: BinomialUpperBoundMethod
    exact: bool


def binomial_upper_bound_one_sided(
    successes: int,
    trials: int,
    alpha: Decimal,
) -> BinomialUpperBound:
    """Return a rigorous one-sided upper bound with bounded large-n work.

    Exact integer-tail Clopper--Pearson inversion is retained through
    ``MAX_CLOPPER_PEARSON_TRIALS``. Above that resource ceiling, zero-event
    endpoints use the exact Clopper--Pearson closed-form boundary, located on
    the six-decimal output grid with rational logarithm enclosures. Nonzero
    endpoints invert the separately labeled one-sided Bernoulli KL-Chernoff
    inequality on a fixed internal grid. No branch performs work proportional
    to ``trials`` once the exact ceiling is crossed.
    """

    validated_trials = _bounded_int(
        trials,
        name="trials",
        lower=1,
        upper=MAX_SCALABLE_BINOMIAL_TRIALS,
    )
    validated_successes = _bounded_int(
        successes,
        name="successes",
        lower=0,
        upper=validated_trials,
    )
    alpha_numerator = _alpha_numerator(alpha)
    validated_alpha = _scaled_probability(alpha_numerator)
    confidence_level = _scaled_probability(PROBABILITY_SCALE - alpha_numerator)

    if validated_trials <= MAX_CLOPPER_PEARSON_TRIALS:
        interval = clopper_pearson_one_sided(
            validated_successes,
            validated_trials,
            validated_alpha,
            side="upper",
        )
        rate = Fraction(interval.bound)
        return BinomialUpperBound(
            successes=validated_successes,
            trials=validated_trials,
            alpha=validated_alpha,
            confidence_level=confidence_level,
            upper_rate_bound=_fraction_outward_decimal(rate),
            upper_count_bound=_fraction_outward_decimal(rate * validated_trials),
            method=CLOPPER_PEARSON_METHOD,
            exact=True,
        )

    alpha_fraction = Fraction(alpha_numerator, PROBABILITY_SCALE)
    _, negative_log_alpha_upper = _negative_log_interval(alpha_fraction)
    if validated_successes == 0:
        upper_rate_micro = _zero_event_closed_form_upper_micro(
            trials=validated_trials,
            alpha=alpha_fraction,
        )
        upper_count_micro = _zero_event_closed_form_upper_count_micro(
            trials=validated_trials,
            negative_log_alpha_upper=negative_log_alpha_upper,
        )
        return BinomialUpperBound(
            successes=0,
            trials=validated_trials,
            alpha=validated_alpha,
            confidence_level=confidence_level,
            upper_rate_bound=_scaled_probability(upper_rate_micro),
            upper_count_bound=_scaled_probability(upper_count_micro),
            method=ZERO_EVENT_CLOSED_FORM_METHOD,
            exact=True,
        )

    rate = _bernoulli_kl_chernoff_upper_fraction(
        successes=validated_successes,
        trials=validated_trials,
        negative_log_alpha_upper=negative_log_alpha_upper,
    )
    return BinomialUpperBound(
        successes=validated_successes,
        trials=validated_trials,
        alpha=validated_alpha,
        confidence_level=confidence_level,
        upper_rate_bound=_fraction_outward_decimal(rate),
        upper_count_bound=_fraction_outward_decimal(rate * validated_trials),
        method=BERNOULLI_KL_CHERNOFF_UPPER_BOUND_METHOD,
        exact=False,
    )


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


def _zero_event_closed_form_upper_micro(*, trials: int, alpha: Fraction) -> int:
    """Locate an outward six-place rendering of ``1 - alpha**(1/n)``.

    For a candidate grid value ``u``, ``u`` is above the exact boundary iff
    ``n * -ln(1-u) >= -ln(alpha)``. Rational lower/upper log enclosures make
    that comparison rigorous without constructing powers whose size scales
    with ``n``.
    """

    _, target_upper = _negative_log_interval(alpha)
    lower_micro = 0
    upper_micro = PROBABILITY_SCALE
    while lower_micro < upper_micro:
        midpoint = (lower_micro + upper_micro) // 2
        if midpoint == PROBABILITY_SCALE:
            proven_upper = True
        else:
            survival = Fraction(PROBABILITY_SCALE - midpoint, PROBABILITY_SCALE)
            survival_log_lower, _ = _negative_log_interval(survival)
            proven_upper = trials * survival_log_lower >= target_upper
        if proven_upper:
            upper_micro = midpoint
        else:
            lower_micro = midpoint + 1
    return lower_micro


def _zero_event_closed_form_upper_count_micro(
    *,
    trials: int,
    negative_log_alpha_upper: Fraction,
) -> int:
    """Locate an outward six-place rendering of ``n * (1-alpha**(1/n))``.

    The exact count-scale endpoint is at most ``-ln(alpha)`` because
    ``1-exp(-x) <= x``. That inequality supplies a small finite search range
    even when ``trials`` is the largest RFC 8785-safe integer. Each candidate
    is then proved above the exact endpoint using rational log enclosures.
    """

    lower_micro = 0
    upper_micro = _ceil_fraction(negative_log_alpha_upper * PROBABILITY_SCALE)
    while lower_micro < upper_micro:
        midpoint = (lower_micro + upper_micro) // 2
        survival = Fraction(
            trials * PROBABILITY_SCALE - midpoint,
            trials * PROBABILITY_SCALE,
        )
        survival_log_lower, _ = _negative_log_interval(survival)
        if trials * survival_log_lower >= negative_log_alpha_upper:
            upper_micro = midpoint
        else:
            lower_micro = midpoint + 1
    return lower_micro


def _bernoulli_kl_chernoff_upper_fraction(
    *,
    successes: int,
    trials: int,
    negative_log_alpha_upper: Fraction,
) -> Fraction:
    """Invert n * KL(x/n || p) >= -ln(alpha) conservatively.

    For 0 < x < n the Bernoulli divergence is strictly increasing in p on
    [x/n, 1). Every midpoint comparison uses a rational lower enclosure for
    the divergence and an upper enclosure for -ln(alpha); therefore a
    midpoint is accepted only after it is proved to lie on the conservative
    side of the root. The returned fixed-point endpoint is the first proved
    upper grid point, so subsequent decimal rendering remains outward. The
    number of comparisons is bounded by the fixed scale rather than trials.
    """

    if not 0 < successes <= trials:
        raise ValueError("KL-Chernoff inversion requires 0 < successes <= trials")
    if negative_log_alpha_upper <= 0:
        raise ValueError("KL-Chernoff inversion requires a positive log threshold")
    if successes == trials:
        return Fraction(1)

    observed = Fraction(successes, trials)
    lower_index = (successes * _SCALABLE_BOUND_SCALE) // trials
    upper_index = _SCALABLE_BOUND_SCALE
    while upper_index - lower_index > 1:
        midpoint_index = (lower_index + upper_index) // 2
        candidate = Fraction(midpoint_index, _SCALABLE_BOUND_SCALE)
        if candidate <= observed:
            lower_index = midpoint_index
            continue
        divergence_lower = _bernoulli_kl_lower(observed, candidate)
        if trials * divergence_lower >= negative_log_alpha_upper:
            upper_index = midpoint_index
        else:
            lower_index = midpoint_index
    return Fraction(upper_index, _SCALABLE_BOUND_SCALE)


def _bernoulli_kl_lower(observed: Fraction, candidate: Fraction) -> Fraction:
    """Return a rigorous lower enclosure of KL(observed || candidate)."""

    if not Fraction(0) < observed < candidate < Fraction(1):
        raise ValueError("Bernoulli KL inputs must satisfy 0 < observed < candidate < 1")
    failure_ratio = (1 - candidate) / (1 - observed)
    success_ratio = observed / candidate
    failure_log_lower, _ = _negative_log_interval(failure_ratio)
    _, success_log_upper = _negative_log_interval(success_ratio)
    return (1 - observed) * failure_log_lower - observed * success_log_upper


@lru_cache(maxsize=512)
def _negative_log_interval(value: Fraction) -> tuple[Fraction, Fraction]:
    """Return exact rational lower/upper enclosures for ``-ln(value)``."""

    if not Fraction(0) < value <= Fraction(1):
        raise ValueError("logarithm input must be in (0, 1]")
    reduced = value
    powers_of_two = 0
    while reduced < Fraction(1, 2):
        reduced *= 2
        powers_of_two += 1
    log_two_lower, log_two_upper = _atanh_log_interval(Fraction(1, 3))
    reduced_z = (1 - reduced) / (1 + reduced)
    reduced_lower, reduced_upper = _atanh_log_interval(reduced_z)
    return (
        powers_of_two * log_two_lower + reduced_lower,
        powers_of_two * log_two_upper + reduced_upper,
    )


@lru_cache(maxsize=1024)
def _atanh_log_interval(z: Fraction) -> tuple[Fraction, Fraction]:
    """Enclose ``2*atanh(z)`` using a positive series and geometric tail."""

    if not Fraction(0) <= z <= Fraction(1, 3):
        raise ValueError("log-series argument must be in [0, 1/3]")
    z_squared = z * z
    term = z
    partial = Fraction(0)
    for index in range(_LOG_SERIES_TERMS):
        partial += term / (2 * index + 1)
        term *= z_squared
    lower = 2 * partial
    tail = 2 * term / ((2 * _LOG_SERIES_TERMS + 1) * (1 - z_squared))
    return lower, lower + tail


def _fraction_outward_decimal(value: Fraction) -> Decimal:
    if value < 0:
        raise ValueError("outward decimal value must be non-negative")
    scaled = _ceil_fraction(value * PROBABILITY_SCALE)
    return _terminating_decimal(scaled, fractional_places=PROBABILITY_SCALE_DIGITS)


def _ceil_fraction(value: Fraction) -> int:
    return -(-value.numerator // value.denominator)


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
    "BERNOULLI_KL_CHERNOFF_UPPER_BOUND_METHOD",
    "BinomialUpperBound",
    "BinomialUpperBoundMethod",
    "CLOPPER_PEARSON_BISECTION_STEPS",
    "CLOPPER_PEARSON_METHOD",
    "MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS",
    "MAX_CLOPPER_PEARSON_TRIALS",
    "MAX_SCALABLE_BINOMIAL_TRIALS",
    "ZERO_EVENT_CLOSED_FORM_METHOD",
    "ClopperPearsonInterval",
    "IntervalSide",
    "binomial_upper_bound_one_sided",
    "clear_binomial_interval_cache",
    "clopper_pearson_interval_pair_work_units",
    "clopper_pearson_one_sided",
    "clopper_pearson_work_units",
    "validate_clopper_pearson_work_budget",
]
