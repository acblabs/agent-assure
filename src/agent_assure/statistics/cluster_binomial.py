"""Exact inference for independent exchangeable binary cluster endpoints.

The inferential unit in this module is one *independent cluster*, represented by
exactly one binary endpoint.  Repeated observations within a cluster must be
reduced to a predeclared binary cluster endpoint before calling this module.
Neither pairing nor repeated calls make clusters independent.

All authoritative probabilities are analytic binomial probabilities.  The
optional Monte Carlo result is a reproducibility diagnostic only; it never
replaces or modifies the exact p-value.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import Decimal, localcontext
from functools import lru_cache
from math import comb
from typing import Final, Literal, TypeAlias

BinaryEndpoint: TypeAlias = Literal[0, 1]

PROBABILITY_SCALE: Final = 1_000_000
PROBABILITY_SCALE_DIGITS: Final = 6
MAX_CLUSTERS: Final = 10_000
MAX_MONTE_CARLO_RESAMPLES: Final = 1_000_000
MAX_MONTE_CARLO_BERNOULLI_DRAWS: Final = 10_000_000
MAX_SEED_MATERIAL_BYTES: Final = 4_096

BINARY_CLUSTER_ASSUMPTION: Final = (
    "Each endpoint is a predeclared binary outcome from one independent, "
    "exchangeable cluster with a common null success probability."
)
MONTE_CARLO_SEED_DOMAIN: Final = "agent-assure/statistics/cluster-binomial/monte-carlo-seed/v1"
SHA256_COUNTER_BITSTREAM_ID: Final[
    Literal["agent-assure/statistics/cluster-binomial/sha256-counter-msb/v1"]
] = "agent-assure/statistics/cluster-binomial/sha256-counter-msb/v1"
RATIONAL_BERNOULLI_SAMPLER_ID: Final[Literal["uint20-rejection-denominator-1000000/v1"]] = (
    "uint20-rejection-denominator-1000000/v1"
)

_MONTE_CARLO_SEED_DOMAIN_BYTES: Final = MONTE_CARLO_SEED_DOMAIN.encode("ascii")
_COUNTER_BITSTREAM_DOMAIN_BYTES: Final = SHA256_COUNTER_BITSTREAM_ID.encode("ascii")
_COUNTER_LIMIT: Final = 1 << 128
_SAMPLE_BITS: Final = 20
_SAMPLE_RANGE: Final = 1 << _SAMPLE_BITS
_SAMPLE_ACCEPT_LIMIT: Final = (_SAMPLE_RANGE // PROBABILITY_SCALE) * PROBABILITY_SCALE


@dataclass(frozen=True, slots=True)
class ClusterBinomialDesign:
    """Minimum exact design satisfying the declared size and power constraints."""

    required_clusters: int
    critical_successes: int
    adjusted_alpha: Decimal
    desired_power: Decimal
    null_response_rate: Decimal
    alternative_response_rate: Decimal
    exact_type_i_error: Decimal
    achieved_power: Decimal
    assumption: str = BINARY_CLUSTER_ASSUMPTION


@dataclass(frozen=True, slots=True)
class MonteCarloBinomialDiagnostic:
    """Non-authoritative Monte Carlo check of an exact binomial p-value.

    ``plus_one_numerator`` and ``plus_one_denominator`` preserve the exact
    rational estimate.  ``plus_one_estimate`` is its 50-significant-digit
    Decimal rendering because the rational need not have a terminating decimal
    expansion.
    """

    resamples: int
    extreme_count: int
    plus_one_numerator: int
    plus_one_denominator: int
    plus_one_estimate: Decimal
    seed_digest: str
    bitstream_id: Literal["agent-assure/statistics/cluster-binomial/sha256-counter-msb/v1"] = (
        SHA256_COUNTER_BITSTREAM_ID
    )
    sampler_id: Literal["uint20-rejection-denominator-1000000/v1"] = RATIONAL_BERNOULLI_SAMPLER_ID


@dataclass(frozen=True, slots=True)
class ClusterBinomialAnalysis:
    """Exact one-sided result for independent exchangeable cluster endpoints."""

    cluster_count: int
    success_count: int
    null_response_rate: Decimal
    exact_p_value: Decimal
    monte_carlo_diagnostic: MonteCarloBinomialDiagnostic | None
    assumption: str = BINARY_CLUSTER_ASSUMPTION


@dataclass(frozen=True, slots=True)
class _PlanningTailState:
    """Integer numerators at a shared threshold and denominator scale**n."""

    tail_numerator: int
    below_mass_numerator: int


def exact_binomial_upper_tail(
    trials: int,
    threshold: int,
    probability: Decimal,
) -> Decimal:
    """Return the exact analytic ``P[X >= threshold]`` for ``X ~ Binomial``.

    ``probability`` must be finite, in ``[0, 1]``, and exactly representable in
    millionths.  Threshold zero and ``trials + 1`` are supported so callers can
    represent the certain and impossible rejection regions without sentinels.
    The returned Decimal is terminating and is not rounded to six places.
    """

    validated_trials = _bounded_int(trials, name="trials", lower=0, upper=MAX_CLUSTERS)
    validated_threshold = _bounded_int(
        threshold,
        name="threshold",
        lower=0,
        upper=validated_trials + 1,
    )
    probability_numerator = _probability_numerator(probability, name="probability")
    return _exact_binomial_upper_tail_cached(
        validated_trials,
        validated_threshold,
        probability_numerator,
    )


@lru_cache(maxsize=512)
def _exact_binomial_upper_tail_cached(
    trials: int,
    threshold: int,
    probability_numerator: int,
) -> Decimal:
    tail_numerator, denominator = _binomial_tail_fraction(
        trials,
        threshold,
        probability_numerator,
    )
    return _terminating_probability(tail_numerator, denominator, trials)


def plan_cluster_binomial_design(
    *,
    adjusted_alpha: Decimal,
    desired_power: Decimal,
    null_response_rate: Decimal,
    alternative_response_rate: Decimal,
    min_clusters: int = 1,
    max_clusters: int = MAX_CLUSTERS,
) -> ClusterBinomialDesign:
    """Find the minimum non-randomized exact one-sided cluster design.

    For each cluster count ``n``, the critical value is the smallest ``k`` for
    which ``P_p0[X >= k] <= adjusted_alpha`` and ``k / n > p0``. The first
    design whose exact power ``P_p1[X >= k]`` reaches ``desired_power`` is
    returned. The search
    updates the two binomial tails in constant many exact-integer operations per
    ``n`` and is bounded by ``max_clusters <= 10_000``.

    This design is valid only when each input bit is one independent,
    exchangeable cluster endpoint.  It does not apply a design-effect
    approximation to repeated observations.
    """

    alpha_numerator = _probability_numerator(
        adjusted_alpha,
        name="adjusted_alpha",
        open_interval=True,
    )
    power_numerator = _probability_numerator(
        desired_power,
        name="desired_power",
        open_interval=True,
    )
    null_numerator = _probability_numerator(
        null_response_rate,
        name="null_response_rate",
    )
    alternative_numerator = _probability_numerator(
        alternative_response_rate,
        name="alternative_response_rate",
    )
    if alternative_numerator <= null_numerator:
        raise ValueError("alternative_response_rate must exceed null_response_rate")
    search_limit = _bounded_int(
        max_clusters,
        name="max_clusters",
        lower=1,
        upper=MAX_CLUSTERS,
    )
    minimum = _bounded_int(
        min_clusters,
        name="min_clusters",
        lower=1,
        upper=search_limit,
    )

    return _plan_cluster_binomial_design_cached(
        alpha_numerator,
        power_numerator,
        null_numerator,
        alternative_numerator,
        minimum,
        search_limit,
    )


@lru_cache(maxsize=256)
def _plan_cluster_binomial_design_cached(
    alpha_numerator: int,
    power_numerator: int,
    null_numerator: int,
    alternative_numerator: int,
    minimum: int,
    search_limit: int,
) -> ClusterBinomialDesign:
    """Run the pure exact design search over canonical integer inputs."""

    # At n=0, threshold 1 is the smallest zero-size rejection region with size 0.
    threshold = 1
    denominator = 1
    null_state = _PlanningTailState(tail_numerator=0, below_mass_numerator=1)
    alternative_state = _PlanningTailState(tail_numerator=0, below_mass_numerator=1)

    for cluster_count in range(1, search_limit + 1):
        next_denominator = denominator * PROBABILITY_SCALE
        candidate_null_tail = _tail_at_unchanged_threshold(
            null_state,
            null_numerator,
        )
        size_requires_increment = (
            candidate_null_tail * PROBABILITY_SCALE > alpha_numerator * next_denominator
        )
        # The final gate rejects only above the declared null rate. Include that
        # directional condition in the planned region so the advertised power
        # is for exactly the same test over the full accepted alpha domain.
        directional_threshold = (cluster_count * null_numerator // PROBABILITY_SCALE) + 1
        increment_threshold = size_requires_increment or threshold < directional_threshold
        candidate_alternative_tail = _tail_at_unchanged_threshold(
            alternative_state,
            alternative_numerator,
        )
        null_state = _advance_tail_state(
            state=null_state,
            trials=cluster_count - 1,
            threshold=threshold,
            probability_numerator=null_numerator,
            denominator=denominator,
            candidate_tail_numerator=candidate_null_tail,
            increment_threshold=increment_threshold,
        )
        alternative_state = _advance_tail_state(
            state=alternative_state,
            trials=cluster_count - 1,
            threshold=threshold,
            probability_numerator=alternative_numerator,
            denominator=denominator,
            candidate_tail_numerator=candidate_alternative_tail,
            increment_threshold=increment_threshold,
        )
        if increment_threshold:
            threshold += 1
        denominator = next_denominator

        has_nonempty_rejection_region = threshold <= cluster_count
        reaches_power = (
            alternative_state.tail_numerator * PROBABILITY_SCALE >= power_numerator * denominator
        )
        if cluster_count >= minimum and has_nonempty_rejection_region and reaches_power:
            return ClusterBinomialDesign(
                required_clusters=cluster_count,
                critical_successes=threshold,
                adjusted_alpha=_six_decimal_probability(alpha_numerator),
                desired_power=_six_decimal_probability(power_numerator),
                null_response_rate=_six_decimal_probability(null_numerator),
                alternative_response_rate=_six_decimal_probability(alternative_numerator),
                exact_type_i_error=_terminating_probability(
                    null_state.tail_numerator,
                    denominator,
                    cluster_count,
                ),
                achieved_power=_terminating_probability(
                    alternative_state.tail_numerator,
                    denominator,
                    cluster_count,
                ),
            )

    raise ValueError(
        "no exact cluster-binomial design meets desired_power within "
        f"{search_limit} independent clusters"
    )


def cluster_binomial_rejection_region_contains(
    *,
    trials: int,
    successes: int,
    critical_successes: int,
) -> bool:
    """Return whether counts fall in a frozen non-randomized rejection region."""

    validated_trials = _bounded_int(trials, name="trials", lower=1, upper=MAX_CLUSTERS)
    validated_successes = _bounded_int(
        successes,
        name="successes",
        lower=0,
        upper=validated_trials,
    )
    validated_critical = _bounded_int(
        critical_successes,
        name="critical_successes",
        lower=1,
        upper=validated_trials,
    )
    return validated_successes >= validated_critical


def analyze_cluster_binomial(
    endpoints: tuple[BinaryEndpoint, ...],
    *,
    null_response_rate: Decimal,
    diagnostic_seed_material: str,
    exact_diagnostic_cap: int = 256,
    monte_carlo_resamples: int = 1_000,
) -> ClusterBinomialAnalysis:
    """Analyze one bit per independent exchangeable cluster.

    The exact analytic upper-tail probability is always computed and is the
    sole inferential p-value.  If ``len(endpoints) > exact_diagnostic_cap``, a
    reproducible Monte Carlo estimate of the same null tail is attached only as
    a diagnostic.

    The diagnostic seed is SHA-256 over the ASCII seed-domain string, NUL, an
    unsigned 64-bit big-endian byte length, the UTF-8 seed material, then
    unsigned big-endian fields ``n`` (64 bit), observed successes (64 bit),
    millionths of ``p0`` (32 bit), and resamples (64 bit).  Simulation bits are
    the concatenation of SHA-256 blocks over the bitstream-domain string, NUL,
    the 32-byte seed digest, and a zero-based unsigned 128-bit counter.  Bits are
    consumed most-significant first.  Each Bernoulli draw consumes a 20-bit
    integer; values at least 1_000_000 are rejected, and an accepted value below
    the integer millionths of ``p0`` is a success.  This is unbiased for the
    required denominator of 1_000_000.
    """

    if not isinstance(endpoints, tuple):
        raise TypeError("endpoints must be a tuple of literal integer bits")
    cluster_count = _bounded_int(
        len(endpoints),
        name="cluster_count",
        lower=1,
        upper=MAX_CLUSTERS,
    )
    if any(type(endpoint) is not int or endpoint not in (0, 1) for endpoint in endpoints):
        raise ValueError("endpoints must contain only literal integer 0 or 1 values")
    null_numerator = _probability_numerator(
        null_response_rate,
        name="null_response_rate",
    )
    diagnostic_cap = _bounded_int(
        exact_diagnostic_cap,
        name="exact_diagnostic_cap",
        lower=0,
        upper=MAX_CLUSTERS,
    )
    resamples = _bounded_int(
        monte_carlo_resamples,
        name="monte_carlo_resamples",
        lower=1,
        upper=MAX_MONTE_CARLO_RESAMPLES,
    )
    seed_bytes = _validated_seed_material(diagnostic_seed_material)
    success_count = sum(endpoints)
    diagnostic_request: tuple[bytes, int] | None = None
    if cluster_count > diagnostic_cap:
        diagnostic_request = (
            _monte_carlo_seed_digest(
                seed_material=seed_bytes,
                cluster_count=cluster_count,
                success_count=success_count,
                probability_numerator=null_numerator,
                resamples=resamples,
            ),
            resamples,
        )

    return _analyze_cluster_binomial_cached(
        cluster_count,
        success_count,
        null_numerator,
        diagnostic_request,
    )


@lru_cache(maxsize=256)
def _analyze_cluster_binomial_cached(
    cluster_count: int,
    success_count: int,
    null_numerator: int,
    diagnostic_request: tuple[bytes, int] | None,
) -> ClusterBinomialAnalysis:
    """Run pure exact inference once per canonical immutable analysis input."""

    exact_p_value = exact_binomial_upper_tail(
        cluster_count,
        success_count,
        _six_decimal_probability(null_numerator),
    )

    diagnostic = None
    if diagnostic_request is not None:
        seed_digest_bytes, resamples = diagnostic_request
        requested_draws = cluster_count * resamples
        if requested_draws > MAX_MONTE_CARLO_BERNOULLI_DRAWS:
            raise ValueError(
                "Monte Carlo diagnostic exceeds the bounded Bernoulli-draw budget: "
                f"{requested_draws} > {MAX_MONTE_CARLO_BERNOULLI_DRAWS}"
            )
        extreme_count = _monte_carlo_extreme_count(
            cluster_count=cluster_count,
            observed_successes=success_count,
            probability_numerator=null_numerator,
            resamples=resamples,
            seed_digest=seed_digest_bytes,
        )
        plus_one_numerator = extreme_count + 1
        plus_one_denominator = resamples + 1
        with localcontext() as context:
            context.prec = 50
            plus_one_estimate = Decimal(plus_one_numerator) / Decimal(plus_one_denominator)
        diagnostic = MonteCarloBinomialDiagnostic(
            resamples=resamples,
            extreme_count=extreme_count,
            plus_one_numerator=plus_one_numerator,
            plus_one_denominator=plus_one_denominator,
            plus_one_estimate=plus_one_estimate,
            seed_digest=seed_digest_bytes.hex(),
        )

    return ClusterBinomialAnalysis(
        cluster_count=cluster_count,
        success_count=success_count,
        null_response_rate=_six_decimal_probability(null_numerator),
        exact_p_value=exact_p_value,
        monte_carlo_diagnostic=diagnostic,
    )


def clear_cluster_binomial_caches() -> None:
    """Clear all bounded exact-statistics memoization at a quiescent boundary.

    This is a process-lifecycle memory control for embedded services. It does
    not cancel in-flight computations and is not a secure-erasure primitive;
    concurrent calls can repopulate the caches immediately.
    """

    _exact_binomial_upper_tail_cached.cache_clear()
    _plan_cluster_binomial_design_cached.cache_clear()
    _analyze_cluster_binomial_cached.cache_clear()


def _probability_numerator(
    value: Decimal,
    *,
    name: str,
    open_interval: bool = False,
) -> int:
    if not isinstance(value, Decimal):
        raise TypeError(f"{name} must be a Decimal")
    if not value.is_finite():
        raise ValueError(f"{name} must be finite")
    if value < Decimal("0") or value > Decimal("1"):
        raise ValueError(f"{name} must be in [0, 1]")
    numerator, denominator = value.as_integer_ratio()
    scaled_numerator, remainder = divmod(numerator * PROBABILITY_SCALE, denominator)
    if remainder:
        raise ValueError(f"{name} must be exactly representable to six decimal places")
    if open_interval and scaled_numerator in (0, PROBABILITY_SCALE):
        raise ValueError(f"{name} must be strictly between zero and one")
    return scaled_numerator


def _bounded_int(value: int, *, name: str, lower: int, upper: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if value < lower or value > upper:
        raise ValueError(f"{name} must be in [{lower}, {upper}]")
    return value


def _six_decimal_probability(numerator: int) -> Decimal:
    with localcontext() as context:
        context.prec = PROBABILITY_SCALE_DIGITS + 2
        return Decimal(numerator).scaleb(-PROBABILITY_SCALE_DIGITS)


def _terminating_probability(
    numerator: int,
    denominator: int,
    trials: int,
) -> Decimal:
    if numerator == 0:
        return Decimal("0")
    if numerator == denominator:
        return Decimal("1")
    with localcontext() as context:
        # denominator == 10 ** (six digits per Bernoulli trial).
        context.prec = max(1, PROBABILITY_SCALE_DIGITS * trials + 1)
        value = Decimal(numerator).scaleb(-(PROBABILITY_SCALE_DIGITS * trials))
        return value.normalize()


def _binomial_tail_fraction(
    trials: int,
    threshold: int,
    probability_numerator: int,
) -> tuple[int, int]:
    denominator = PROBABILITY_SCALE**trials
    if threshold == 0:
        return denominator, denominator
    if threshold > trials:
        return 0, denominator
    if probability_numerator == 0:
        return 0, denominator
    if probability_numerator == PROBABILITY_SCALE:
        return denominator, denominator

    failure_numerator = PROBABILITY_SCALE - probability_numerator
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


def _tail_at_unchanged_threshold(
    state: _PlanningTailState,
    probability_numerator: int,
) -> int:
    return (
        state.tail_numerator * PROBABILITY_SCALE
        + probability_numerator * state.below_mass_numerator
    )


def _advance_tail_state(
    *,
    state: _PlanningTailState,
    trials: int,
    threshold: int,
    probability_numerator: int,
    denominator: int,
    candidate_tail_numerator: int,
    increment_threshold: bool,
) -> _PlanningTailState:
    failure_numerator = PROBABILITY_SCALE - probability_numerator
    below_index = threshold - 1
    if increment_threshold:
        upper_mass = _adjacent_mass_numerator(
            mass_numerator=state.below_mass_numerator,
            trials=trials,
            index=below_index,
            probability_numerator=probability_numerator,
            denominator=denominator,
            direction=1,
        )
        new_below_mass = (
            failure_numerator * upper_mass + probability_numerator * state.below_mass_numerator
        )
        return _PlanningTailState(
            tail_numerator=candidate_tail_numerator - new_below_mass,
            below_mass_numerator=new_below_mass,
        )

    lower_mass = _adjacent_mass_numerator(
        mass_numerator=state.below_mass_numerator,
        trials=trials,
        index=below_index,
        probability_numerator=probability_numerator,
        denominator=denominator,
        direction=-1,
    )
    new_below_mass = (
        failure_numerator * state.below_mass_numerator + probability_numerator * lower_mass
    )
    return _PlanningTailState(
        tail_numerator=candidate_tail_numerator,
        below_mass_numerator=new_below_mass,
    )


def _adjacent_mass_numerator(
    *,
    mass_numerator: int,
    trials: int,
    index: int,
    probability_numerator: int,
    denominator: int,
    direction: Literal[-1, 1],
) -> int:
    target = index + direction
    if target < 0 or target > trials:
        return 0
    if probability_numerator == 0:
        return denominator if target == 0 else 0
    if probability_numerator == PROBABILITY_SCALE:
        return denominator if target == trials else 0

    failure_numerator = PROBABILITY_SCALE - probability_numerator
    if direction == -1:
        return _exact_quotient(
            mass_numerator * index * failure_numerator,
            (trials - index + 1) * probability_numerator,
        )
    return _exact_quotient(
        mass_numerator * (trials - index) * probability_numerator,
        (index + 1) * failure_numerator,
    )


def _exact_quotient(numerator: int, denominator: int) -> int:
    quotient, remainder = divmod(numerator, denominator)
    if remainder:
        raise ArithmeticError("internal binomial recurrence lost integer exactness")
    return quotient


def _validated_seed_material(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("diagnostic_seed_material must be a string")
    encoded = value.encode("utf-8")
    if not encoded:
        raise ValueError("diagnostic_seed_material cannot be empty")
    if len(encoded) > MAX_SEED_MATERIAL_BYTES:
        raise ValueError(
            "diagnostic_seed_material exceeds the bounded UTF-8 byte length: "
            f"{len(encoded)} > {MAX_SEED_MATERIAL_BYTES}"
        )
    return encoded


def _monte_carlo_seed_digest(
    *,
    seed_material: bytes,
    cluster_count: int,
    success_count: int,
    probability_numerator: int,
    resamples: int,
) -> bytes:
    payload = b"".join(
        (
            _MONTE_CARLO_SEED_DOMAIN_BYTES,
            b"\x00",
            len(seed_material).to_bytes(8, "big"),
            seed_material,
            cluster_count.to_bytes(8, "big"),
            success_count.to_bytes(8, "big"),
            probability_numerator.to_bytes(4, "big"),
            resamples.to_bytes(8, "big"),
        )
    )
    return hashlib.sha256(payload).digest()


class _Sha256CounterBitstream:
    __slots__ = ("_buffer", "_buffer_bits", "_counter", "_seed_digest")

    def __init__(self, seed_digest: bytes) -> None:
        if len(seed_digest) != hashlib.sha256().digest_size:
            raise ValueError("seed_digest must contain exactly one SHA-256 digest")
        self._seed_digest = seed_digest
        self._counter = 0
        self._buffer = 0
        self._buffer_bits = 0

    def take_bits(self, bit_count: int) -> int:
        if bit_count < 1:
            raise ValueError("bit_count must be positive")
        while self._buffer_bits < bit_count:
            self._refill()
        remaining = self._buffer_bits - bit_count
        value = self._buffer >> remaining
        self._buffer &= (1 << remaining) - 1
        self._buffer_bits = remaining
        return value

    def _refill(self) -> None:
        if self._counter >= _COUNTER_LIMIT:
            raise OverflowError("SHA-256 diagnostic counter exhausted")
        block = hashlib.sha256(
            b"".join(
                (
                    _COUNTER_BITSTREAM_DOMAIN_BYTES,
                    b"\x00",
                    self._seed_digest,
                    self._counter.to_bytes(16, "big"),
                )
            )
        ).digest()
        self._counter += 1
        self._buffer = (self._buffer << (len(block) * 8)) | int.from_bytes(block, "big")
        self._buffer_bits += len(block) * 8


def _sample_rational_bernoulli(
    stream: _Sha256CounterBitstream,
    probability_numerator: int,
) -> int:
    if probability_numerator == 0:
        return 0
    if probability_numerator == PROBABILITY_SCALE:
        return 1
    while True:
        candidate = stream.take_bits(_SAMPLE_BITS)
        if candidate < _SAMPLE_ACCEPT_LIMIT:
            return int(candidate < probability_numerator)


def _monte_carlo_extreme_count(
    *,
    cluster_count: int,
    observed_successes: int,
    probability_numerator: int,
    resamples: int,
    seed_digest: bytes,
) -> int:
    if observed_successes == 0 or probability_numerator == PROBABILITY_SCALE:
        return resamples
    if probability_numerator == 0:
        return 0
    stream = _Sha256CounterBitstream(seed_digest)
    extreme_count = 0
    for _ in range(resamples):
        simulated_successes = 0
        for _ in range(cluster_count):
            simulated_successes += _sample_rational_bernoulli(
                stream,
                probability_numerator,
            )
        extreme_count += simulated_successes >= observed_successes
    return extreme_count


__all__ = [
    "BINARY_CLUSTER_ASSUMPTION",
    "MAX_CLUSTERS",
    "MAX_MONTE_CARLO_BERNOULLI_DRAWS",
    "MAX_MONTE_CARLO_RESAMPLES",
    "MONTE_CARLO_SEED_DOMAIN",
    "PROBABILITY_SCALE",
    "RATIONAL_BERNOULLI_SAMPLER_ID",
    "SHA256_COUNTER_BITSTREAM_ID",
    "ClusterBinomialAnalysis",
    "ClusterBinomialDesign",
    "MonteCarloBinomialDiagnostic",
    "analyze_cluster_binomial",
    "clear_cluster_binomial_caches",
    "exact_binomial_upper_tail",
    "plan_cluster_binomial_design",
]
