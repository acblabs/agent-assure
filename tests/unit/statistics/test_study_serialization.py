from __future__ import annotations

from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, getcontext

import pytest

from agent_assure.statistics.study_serialization import (
    bonferroni_adjusted_alpha,
    format_six_place_rate,
    format_twelve_place_bound,
)


def test_study_serialization_is_exact_and_independent_of_decimal_context() -> None:
    original_precision = getcontext().prec
    try:
        getcontext().prec = 6
        assert bonferroni_adjusted_alpha("0.050000", 3) == Decimal("0.016666")
        assert format_six_place_rate(1, 3) == "0.333333"
        value = Decimal("0.1234567890125")
        assert format_twelve_place_bound(value, rounding=ROUND_FLOOR) == "0.123456789012"
        assert format_twelve_place_bound(value, rounding=ROUND_CEILING) == "0.123456789013"
    finally:
        getcontext().prec = original_precision


@pytest.mark.parametrize("family_size", (0, -1, True))
def test_bonferroni_family_size_is_a_positive_literal_integer(family_size: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        bonferroni_adjusted_alpha("0.050000", family_size)  # type: ignore[arg-type]


@pytest.mark.parametrize("counts", ((-1, 1), (2, 1), (0, 0), (True, 1)))
def test_rate_serialization_rejects_invalid_counts(counts: tuple[object, object]) -> None:
    with pytest.raises(ValueError, match="rate counts"):
        format_six_place_rate(*counts)  # type: ignore[arg-type]
