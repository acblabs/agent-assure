from __future__ import annotations

import subprocess
import sys
from decimal import (
    ROUND_DOWN,
    ROUND_UP,
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
    count_rate_string,
    decimal_string,
    live_record_group_id,
    mean_decimal,
    probability_lower_string,
    probability_string,
    probability_upper_string,
    rate_decimal,
    rate_string,
    signed_unit_decimal_string,
    signed_unit_lower_string,
    signed_unit_upper_string,
)


@pytest.mark.parametrize(
    "module_name",
    (
        "agent_assure.live.adapters",
        "agent_assure.live.advanced",
        "agent_assure.live.comparison",
        "agent_assure.live.config",
        "agent_assure.live.drift",
        "agent_assure.live.identity",
        "agent_assure.live.output_contract",
        "agent_assure.live.paths",
        "agent_assure.live.primitives",
        "agent_assure.live.intervals",
        "agent_assure.live.runner",
        "agent_assure.live.statistics",
        "agent_assure.live.trajectory",
    ),
)
def test_live_modules_import_in_a_fresh_isolated_process(module_name: str) -> None:
    completed = subprocess.run(
        [sys.executable, "-I", "-c", f"import {module_name}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr


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
    assert count_rate_string(3, 1) == "3.000000"
    assert mean_decimal((Decimal("0.1"), Decimal("0.2"))) == Decimal("0.15")


def test_confidence_interval_endpoints_are_serialized_outward() -> None:
    assert probability_lower_string(Decimal("0.103675691290")) == "0.103675"
    assert probability_upper_string(Decimal("0.496324308709")) == "0.496325"
    assert signed_unit_lower_string(Decimal("-0.196324308709")) == "-0.196325"
    assert signed_unit_upper_string(Decimal("0.196324308709")) == "0.196325"
    assert signed_unit_lower_string(Decimal("0.196324308709")) == "0.196324"
    assert signed_unit_upper_string(Decimal("-0.196324308709")) == "-0.196324"


def test_directional_endpoint_serialization_is_clamped_and_context_independent() -> None:
    with localcontext() as context:
        context.prec = 1
        context.rounding = ROUND_DOWN
        assert probability_lower_string(Decimal("-0.1")) == "0.000000"
        assert probability_upper_string(Decimal("1.1")) == "1.000000"
        assert signed_unit_lower_string(Decimal("-1.1")) == "-1.000000"
        assert signed_unit_upper_string(Decimal("1.1")) == "1.000000"
        assert signed_unit_lower_string(Decimal("-0.0000001")) == "-0.000001"
        assert signed_unit_upper_string(Decimal("-0.0000001")) == "0.000000"


@pytest.mark.parametrize("value", (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")))
def test_directional_endpoint_serialization_rejects_nonfinite_values(value: Decimal) -> None:
    with pytest.raises(ValueError, match="finite"):
        probability_lower_string(value)
    with pytest.raises(ValueError, match="finite"):
        signed_unit_lower_string(value)
    with pytest.raises(ValueError, match="finite"):
        signed_unit_upper_string(value)


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


def test_live_arithmetic_is_bounded_and_restores_hostile_ambient_context() -> None:
    expected_rate = Decimal("0.3333333333333333333333333333333333")

    with localcontext() as context:
        context.prec = 6
        context.rounding = ROUND_UP
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        context.clear_flags()

        assert rate_decimal(1, 3) == expected_rate
        assert mean_decimal((Decimal("0.1234567"), Decimal("0.7654321"))) == Decimal("0.4444444")
        assert context.prec == 6
        assert context.rounding == ROUND_UP
        assert context.traps[Inexact] is True
        assert context.traps[Rounded] is True
        assert context.flags[Inexact] is False
        assert context.flags[Rounded] is False


def test_rate_primitives_reject_zero_denominators() -> None:
    with pytest.raises(ValueError, match="undefined for a zero denominator"):
        rate_decimal(0, 0)
    with pytest.raises(ValueError, match="undefined for a zero denominator"):
        rate_string(0, 0)
    with pytest.raises(ValueError, match="undefined for a zero denominator"):
        count_rate_string(0, 0)
    with pytest.raises(ValueError, match="non-negative"):
        count_rate_string(-1, 1)


def test_mean_primitive_rejects_an_empty_sample() -> None:
    with pytest.raises(ValueError, match="undefined for an empty sample"):
        mean_decimal(())
