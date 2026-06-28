from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from agent_assure.schema.common import decimal_string as schema_decimal_string


def decimal_string(value: Decimal | str | int) -> str:
    return schema_decimal_string(value)


def probability_string(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    return decimal_string(min(Decimal("1"), max(Decimal("0"), projected)))


def signed_unit_decimal_string(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    return decimal_string(max(Decimal("-1"), min(Decimal("1"), projected)))


def rate_decimal(numerator: int, denominator: int) -> Decimal:
    if denominator == 0:
        return Decimal("0")
    return Decimal(numerator) / Decimal(denominator)


def rate_string(numerator: int, denominator: int) -> str:
    return probability_string(rate_decimal(numerator, denominator))


def mean_decimal(values: tuple[Decimal, ...]) -> Decimal:
    if not values:
        return Decimal("0")
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
