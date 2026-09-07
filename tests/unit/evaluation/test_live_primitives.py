from __future__ import annotations

from decimal import (
    ROUND_DOWN,
    Clamped,
    Decimal,
    Inexact,
    Rounded,
    Subnormal,
    Underflow,
    localcontext,
)
from types import SimpleNamespace

import pytest

from agent_assure.live.primitives import (
    decimal_string,
    live_record_group_id,
    mean_decimal,
    probability_string,
    rate_decimal,
    rate_string,
    signed_unit_decimal_string,
)


def test_live_record_group_id_uses_canonical_unknown_fallbacks() -> None:
    record = SimpleNamespace(
        provider="",
        model=None,
        adapter_id="",
        pipeline_id=None,
    )

    assert (
        live_record_group_id(record)
        == "provider=unknown|model=unknown|adapter=unknown|pipeline=unknown"
    )


def test_decimal_primitives_share_report_formatting() -> None:
    assert decimal_string(Decimal("-0.0000001")) == "0.000000"
    assert probability_string(Decimal("1.2")) == "1.000000"
    assert signed_unit_decimal_string(Decimal("-1.2")) == "-1.000000"
    assert rate_string(1, 3) == "0.333333"
    assert mean_decimal((Decimal("0.1"), Decimal("0.2"))) == Decimal("0.15")


def test_decimal_string_is_bounded_and_independent_of_ambient_context() -> None:
    with localcontext() as context:
        context.prec = 1
        context.Emin = -5
        context.Emax = 5
        context.rounding = ROUND_DOWN
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        context.traps[Underflow] = True
        context.traps[Subnormal] = True
        context.traps[Clamped] = True
        assert decimal_string(Decimal("1.2345655")) == "1.234566"
        assert decimal_string(Decimal("1e-4090")) == "0.000000"

    with pytest.raises(ValueError, match="must be finite"):
        decimal_string(Decimal("NaN"))
    with pytest.raises(ValueError, match="precision bound"):
        decimal_string(Decimal((0, (1,) * 4_097, -4_097)))


def test_rate_primitives_reject_zero_denominators() -> None:
    with pytest.raises(ValueError, match="undefined for a zero denominator"):
        rate_decimal(0, 0)
    with pytest.raises(ValueError, match="undefined for a zero denominator"):
        rate_string(0, 0)


def test_mean_primitive_rejects_an_empty_sample() -> None:
    with pytest.raises(ValueError, match="undefined for an empty sample"):
        mean_decimal(())
