from __future__ import annotations

from datetime import datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal

from agent_assure._decimal_context import (
    live_decimal_context as live_decimal_context,
)
from agent_assure._decimal_context import (
    with_live_decimal_context as with_live_decimal_context,
)
from agent_assure.schema.common import decimal_string as schema_decimal_string

_PERSISTED_DECIMAL_QUANTUM = Decimal("0.000001")


def decimal_string(value: Decimal | str | int) -> str:
    return schema_decimal_string(value)


def probability_string(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    return decimal_string(min(Decimal("1"), max(Decimal("0"), projected)))


def probability_lower_string(value: Decimal | str | int) -> str:
    """Render a probability lower endpoint without rounding it inward."""

    projected = Decimal(str(value))
    if not projected.is_finite():
        raise ValueError("probability lower endpoint must be finite")
    projected = min(Decimal("1"), max(Decimal("0"), projected))
    with live_decimal_context():
        rounded = projected.quantize(
            _PERSISTED_DECIMAL_QUANTUM,
            rounding=ROUND_FLOOR,
        )
    return format(rounded, "f")


def outward_upper_string(value: Decimal | str | int) -> str:
    """Render a non-negative upper endpoint without rounding it inward."""

    projected = Decimal(str(value))
    if not projected.is_finite() or projected < Decimal("0"):
        raise ValueError("upper endpoint must be a finite non-negative decimal")
    with live_decimal_context():
        rounded = projected.quantize(
            _PERSISTED_DECIMAL_QUANTUM,
            rounding=ROUND_CEILING,
        )
    return format(rounded, "f")


def probability_upper_string(value: Decimal | str | int) -> str:
    """Render a probability conservatively for ``p <= alpha`` decisions."""

    projected = Decimal(str(value))
    return outward_upper_string(min(Decimal("1"), max(Decimal("0"), projected)))


def signed_unit_decimal_string(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    return decimal_string(max(Decimal("-1"), min(Decimal("1"), projected)))


def signed_unit_lower_string(value: Decimal | str | int) -> str:
    """Render a signed-unit lower endpoint without rounding it inward."""

    projected = Decimal(str(value))
    if not projected.is_finite():
        raise ValueError("signed-unit lower endpoint must be finite")
    projected = max(Decimal("-1"), min(Decimal("1"), projected))
    with live_decimal_context():
        rounded = projected.quantize(
            _PERSISTED_DECIMAL_QUANTUM,
            rounding=ROUND_FLOOR,
        )
    if rounded.is_zero():
        rounded = Decimal("0.000000")
    return format(rounded, "f")


def signed_unit_upper_string(value: Decimal | str | int) -> str:
    """Render a signed-unit upper endpoint without rounding it inward."""

    projected = Decimal(str(value))
    if not projected.is_finite():
        raise ValueError("signed-unit upper endpoint must be finite")
    projected = max(Decimal("-1"), min(Decimal("1"), projected))
    with live_decimal_context():
        rounded = projected.quantize(
            _PERSISTED_DECIMAL_QUANTUM,
            rounding=ROUND_CEILING,
        )
    if rounded.is_zero():
        rounded = Decimal("0.000000")
    return format(rounded, "f")


@with_live_decimal_context
def rate_decimal(numerator: int, denominator: int) -> Decimal:
    if denominator == 0:
        raise ValueError("rate is undefined for a zero denominator")
    return Decimal(numerator) / Decimal(denominator)


def rate_string(numerator: int, denominator: int) -> str:
    return probability_string(rate_decimal(numerator, denominator))


def count_rate_string(event_count: int, exposure: int) -> str:
    """Render an uncapped non-negative count rate per exposure unit.

    Unlike :func:`rate_string`, this is not a probability: repeated events can
    make the rate greater than one. Keeping the two renderers separate makes
    accidental probability clamping visible at call sites.
    """

    if event_count < 0:
        raise ValueError("event_count must be non-negative")
    return decimal_string(rate_decimal(event_count, exposure))


@with_live_decimal_context
def mean_decimal(values: tuple[Decimal, ...]) -> Decimal:
    if not values:
        raise ValueError("mean is undefined for an empty sample")
    return sum(values, Decimal("0")) / Decimal(len(values))


def parse_timestamp(value: str) -> datetime | None:
    text = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def provider_model_group_id(
    *,
    provider: str | None,
    model: str | None,
    adapter_id: str | None,
    pipeline_id: str | None,
) -> str:
    return "|".join(
        (
            f"provider={provider or 'unknown'}",
            f"model={model or 'unknown'}",
            f"adapter={adapter_id or 'unknown'}",
            f"pipeline={pipeline_id or 'unknown'}",
        )
    )


def live_record_group_id(record: object) -> str:
    return provider_model_group_id(
        provider=getattr(record, "provider", None),
        model=getattr(record, "model", None),
        adapter_id=getattr(record, "adapter_id", None),
        pipeline_id=getattr(record, "pipeline_id", None),
    )
