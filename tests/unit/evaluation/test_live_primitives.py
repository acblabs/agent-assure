from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

from agent_assure.live.primitives import (
    decimal_string,
    live_record_group_id,
    mean_decimal,
    probability_string,
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
