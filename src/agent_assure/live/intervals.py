from __future__ import annotations

import hashlib
import random
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from statistics import mean

TWO_SIDED_95_T_CRITICALS: dict[int, str] = {
    1: "12.706205",
    2: "4.302653",
    3: "3.182446",
    4: "2.776445",
    5: "2.570582",
    6: "2.446912",
    7: "2.364624",
    8: "2.306004",
    9: "2.262157",
    10: "2.228139",
    11: "2.200985",
    12: "2.178813",
    13: "2.160369",
    14: "2.144787",
    15: "2.131450",
    16: "2.119905",
    17: "2.109816",
    18: "2.100922",
    19: "2.093024",
    20: "2.085963",
    21: "2.079614",
    22: "2.073873",
    23: "2.068658",
    24: "2.063899",
    25: "2.059539",
    26: "2.055529",
    27: "2.051831",
    28: "2.048407",
    29: "2.045230",
    30: "2.042272",
    40: "2.021075",
    60: "2.000298",
    120: "1.979930",
}


def stable_seed_int(seed: str) -> int:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return int.from_bytes(digest[:16], byteorder="big", signed=False)


def seeded_random(seed: str) -> random.Random:
    return random.Random(stable_seed_int(seed))


def t_critical_95(confidence_level: str, degrees_of_freedom: int) -> Decimal:
    if confidence_level != "0.950000":
        raise ValueError(f"unsupported live confidence_level: {confidence_level}")
    if degrees_of_freedom < 1:
        raise ValueError("degrees_of_freedom must be at least 1")
    if degrees_of_freedom in TWO_SIDED_95_T_CRITICALS:
        return Decimal(TWO_SIDED_95_T_CRITICALS[degrees_of_freedom])
    conservative_bucket = max(
        bucket for bucket in TWO_SIDED_95_T_CRITICALS if bucket <= degrees_of_freedom
    )
    return Decimal(TWO_SIDED_95_T_CRITICALS[conservative_bucket])


def cluster_t_interval(
    values: tuple[Decimal, ...],
    confidence_level: str,
) -> tuple[Decimal, Decimal, Decimal]:
    if not values:
        return Decimal("0"), Decimal("0"), Decimal("0")
    center = Decimal(str(mean(values)))
    if len(values) == 1:
        return center, Decimal("0"), Decimal("1")
    variance = sum((value - center) ** 2 for value in values) / Decimal(len(values) - 1)
    standard_error = (variance / Decimal(len(values))).sqrt()
    if standard_error == 0:
        lower, upper = degenerate_cluster_boundary_interval(
            center * Decimal(len(values)),
            len(values),
            confidence_level,
        )
        return center, lower, upper
    half_width = t_critical_95(confidence_level, len(values) - 1) * standard_error
    return center, max(Decimal("0"), center - half_width), min(Decimal("1"), center + half_width)


def difference_t_interval(
    differences: tuple[Decimal, ...],
    confidence_level: str,
) -> tuple[Decimal, Decimal, Decimal, int]:
    if not differences:
        return Decimal("0"), Decimal("0"), Decimal("0"), 0
    center = Decimal(str(mean(differences)))
    if len(differences) == 1:
        return center, Decimal("-1"), Decimal("1"), 1
    variance = sum((value - center) ** 2 for value in differences) / Decimal(
        len(differences) - 1
    )
    standard_error = (variance / Decimal(len(differences))).sqrt()
    if standard_error == 0:
        return center, center, center, len(differences)
    half_width = t_critical_95(confidence_level, len(differences) - 1) * standard_error
    return (
        center,
        max(Decimal("-1"), center - half_width),
        min(Decimal("1"), center + half_width),
        len(differences),
    )


def bootstrap_mean_interval(
    values: tuple[Decimal, ...],
    *,
    confidence_level: str,
    seed: str,
    iterations: int = 2000,
) -> tuple[Decimal, Decimal, Decimal]:
    if confidence_level != "0.950000":
        raise ValueError(f"unsupported live confidence_level: {confidence_level}")
    if not values:
        return Decimal("0"), Decimal("0"), Decimal("0")
    center = Decimal(str(mean(values)))
    if len(values) == 1:
        return center, Decimal("0"), Decimal("1")
    rng = seeded_random(seed)
    sample_size = len(values)
    bootstrap_means: list[Decimal] = []
    for _ in range(iterations):
        total = sum((values[rng.randrange(sample_size)] for _ in range(sample_size)), Decimal("0"))
        bootstrap_means.append(total / Decimal(sample_size))
    lower, upper = percentile_interval(
        tuple(sorted(bootstrap_means)),
        confidence_level,
    )
    return center, max(Decimal("0"), lower), min(Decimal("1"), upper)


def difference_bootstrap_interval(
    differences: tuple[Decimal, ...],
    *,
    confidence_level: str,
    seed: str,
    iterations: int = 2000,
) -> tuple[Decimal, Decimal, Decimal, int]:
    if confidence_level != "0.950000":
        raise ValueError(f"unsupported live confidence_level: {confidence_level}")
    if not differences:
        return Decimal("0"), Decimal("0"), Decimal("0"), 0
    center = Decimal(str(mean(differences)))
    if len(differences) == 1:
        return center, Decimal("-1"), Decimal("1"), 1
    rng = seeded_random(seed)
    sample_size = len(differences)
    bootstrap_means: list[Decimal] = []
    for _ in range(iterations):
        total = sum(
            (differences[rng.randrange(sample_size)] for _ in range(sample_size)),
            Decimal("0"),
        )
        bootstrap_means.append(total / Decimal(sample_size))
    lower, upper = percentile_interval(tuple(sorted(bootstrap_means)), confidence_level)
    return center, max(Decimal("-1"), lower), min(Decimal("1"), upper), sample_size


def percentile_interval(
    ordered: tuple[Decimal, ...],
    confidence_level: str,
) -> tuple[Decimal, Decimal]:
    if confidence_level != "0.950000":
        raise ValueError(f"unsupported live confidence_level: {confidence_level}")
    if not ordered:
        return Decimal("0"), Decimal("0")
    alpha = (Decimal("1") - Decimal(confidence_level)) / Decimal("2")
    lower_index = int((alpha * Decimal(len(ordered))).to_integral_value(rounding=ROUND_FLOOR))
    upper_index = (
        int(
            ((Decimal("1") - alpha) * Decimal(len(ordered))).to_integral_value(
                rounding=ROUND_CEILING
            )
        )
        - 1
    )
    return (
        ordered[max(0, min(len(ordered) - 1, lower_index))],
        ordered[max(0, min(len(ordered) - 1, upper_index))],
    )


def nearest_rank_percentile(values: tuple[Decimal, ...], percentile: Decimal) -> Decimal:
    raw_rank = int((percentile * Decimal(len(values))).to_integral_value(rounding=ROUND_CEILING))
    index = max(0, min(len(values) - 1, raw_rank - 1))
    return values[index]


def degenerate_cluster_boundary_interval(
    successes: Decimal,
    trials: int,
    confidence_level: str,
) -> tuple[Decimal, Decimal]:
    return wilson_score_interval(successes, trials, confidence_level)


def wilson_score_interval(
    successes: Decimal,
    trials: int,
    confidence_level: str,
) -> tuple[Decimal, Decimal]:
    if confidence_level != "0.950000":
        raise ValueError(f"unsupported live confidence_level: {confidence_level}")
    if trials <= 0:
        return Decimal("0"), Decimal("0")
    z = Decimal("1.959964")
    n = Decimal(trials)
    p = successes / n
    z2 = z * z
    denominator = Decimal("1") + z2 / n
    center = (p + z2 / (Decimal("2") * n)) / denominator
    half_width = (
        z
        * ((p * (Decimal("1") - p) / n + z2 / (Decimal("4") * n * n)).sqrt())
        / denominator
    )
    return max(Decimal("0"), center - half_width), min(Decimal("1"), center + half_width)
