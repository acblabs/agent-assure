"""Canonical numerical serialization for real-model study inference."""

from __future__ import annotations

from decimal import ROUND_FLOOR, Context, Decimal, localcontext


def bonferroni_adjusted_alpha(familywise_alpha: str, family_size: int) -> Decimal:
    """Return the preregistered six-place conservative Bonferroni alpha."""

    if isinstance(family_size, bool) or not isinstance(family_size, int) or family_size < 1:
        raise ValueError("Bonferroni family_size must be a positive integer")
    with localcontext(Context(prec=32)):
        adjusted = (Decimal(familywise_alpha) / Decimal(family_size)).quantize(
            Decimal("0.000001"),
            rounding=ROUND_FLOOR,
        )
    if adjusted <= 0:
        raise ValueError("Bonferroni-adjusted alpha is below supported precision")
    return adjusted


def format_six_place_rate(numerator: int, denominator: int) -> str:
    """Render an exact count ratio using the study contract's six places."""

    if (
        isinstance(numerator, bool)
        or not isinstance(numerator, int)
        or numerator < 0
        or isinstance(denominator, bool)
        or not isinstance(denominator, int)
        or denominator < 1
        or numerator > denominator
    ):
        raise ValueError("rate counts require 0 <= numerator <= denominator")
    with localcontext(Context(prec=32)):
        rendered = (Decimal(numerator) / Decimal(denominator)).quantize(Decimal("0.000001"))
    return f"{rendered:.6f}"


def format_twelve_place_bound(value: Decimal, *, rounding: str) -> str:
    """Render a confidence bound using an explicitly supplied rounding mode."""

    if not isinstance(value, Decimal) or not value.is_finite() or not Decimal(0) <= value <= 1:
        raise ValueError("confidence bound must be a finite Decimal in [0, 1]")
    with localcontext(Context(prec=max(32, len(value.as_tuple().digits) + 4))):
        rendered = value.quantize(Decimal("0.000000000001"), rounding=rounding)
    return f"{rendered:.12f}"


__all__ = [
    "bonferroni_adjusted_alpha",
    "format_six_place_rate",
    "format_twelve_place_bound",
]
