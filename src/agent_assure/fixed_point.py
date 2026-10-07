from __future__ import annotations

MICRODOLLARS_PER_DOLLAR = 1_000_000
PICODOLLARS_PER_MICRODOLLAR = 1_000_000
PICODOLLARS_PER_DOLLAR = MICRODOLLARS_PER_DOLLAR * PICODOLLARS_PER_MICRODOLLAR


def round_half_even_nonnegative(numerator: int, denominator: int) -> int:
    """Round a non-negative rational to an integer without ambient Decimal state."""

    if numerator < 0 or denominator <= 0:
        raise ValueError("half-even fixed-point rounding requires non-negative input")
    quotient, remainder = divmod(numerator, denominator)
    doubled = remainder * 2
    if doubled > denominator or (doubled == denominator and quotient % 2 == 1):
        return quotient + 1
    return quotient


def microusd_from_picousd(picousd: int) -> int:
    return round_half_even_nonnegative(picousd, PICODOLLARS_PER_MICRODOLLAR)


def usd_six_from_picousd(picousd: int) -> str:
    microusd = microusd_from_picousd(picousd)
    return f"{microusd // MICRODOLLARS_PER_DOLLAR}.{microusd % MICRODOLLARS_PER_DOLLAR:06d}"


def picousd_from_usd_six(value: str) -> int:
    whole, separator, fractional = value.partition(".")
    if (
        separator != "."
        or not whole
        or not fractional
        or len(fractional) != 6
        or not whole.isascii()
        or not fractional.isascii()
        or not whole.isdecimal()
        or not fractional.isdecimal()
        or (len(whole) > 1 and whole.startswith("0"))
    ):
        raise ValueError("USD value must be a non-negative six-decimal string")
    microusd = int(whole) * MICRODOLLARS_PER_DOLLAR + int(fractional)
    return microusd * PICODOLLARS_PER_MICRODOLLAR
