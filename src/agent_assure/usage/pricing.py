from __future__ import annotations

from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixed_point import microusd_from_picousd
from agent_assure.io_limits import MAX_CONFIG_TEXT_BYTES
from agent_assure.schema.common import DigestHex
from agent_assure.schema.usage import UsagePricingModel, UsagePricingSnapshot, UsageSegment
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)

DECLARED_PRICING_LIMITATION = (
    "Cost is estimated from a declared pricing snapshot with a persisted content digest."
)
_DEMO_FIXTURE_PRICING_LIMITATION = "Demo fixture pricing only; not live provider pricing."
_KNOWN_GENERATED_PRICING_LIMITATIONS = frozenset(
    {
        DECLARED_PRICING_LIMITATION,
        _DEMO_FIXTURE_PRICING_LIMITATION,
    }
)


def load_pricing_snapshot(path: Path) -> UsagePricingSnapshot:
    payload = load_validated_artifact_payload(
        path,
        "usage-pricing-snapshot",
        max_bytes=MAX_CONFIG_TEXT_BYTES,
        label="pricing snapshot",
    )
    return project_validated_artifact_payload(
        payload,
        UsagePricingSnapshot,
        kind="usage-pricing-snapshot",
    )


def pricing_snapshot_digest(snapshot: UsagePricingSnapshot) -> DigestHex:
    snapshot = _validated_pricing_snapshot(snapshot)
    return sha256_hexdigest(snapshot.model_dump(mode="json"))


def estimate_segment_cost(
    segment: UsageSegment,
    snapshot: UsagePricingSnapshot,
    *,
    overwrite: bool = False,
) -> UsageSegment:
    segment = _validated_usage_segment(segment)
    snapshot = _validated_pricing_snapshot(snapshot)
    if segment.estimated_cost_microusd is not None and not overwrite:
        return segment
    if segment.prompt_tokens is None or segment.completion_tokens is None:
        raise ValueError("declared pricing snapshots require prompt_tokens and completion_tokens")
    price = _price_for_segment(segment, snapshot)
    estimated_cost, exact_cost_picousd = _estimated_cost(segment, price)
    source_limitations = _limitations_to_preserve(segment, overwrite=overwrite)
    limitations = tuple(
        sorted(
            {
                *source_limitations,
                *snapshot.limitations,
                DECLARED_PRICING_LIMITATION,
            }
        )
    )
    payload = segment.model_dump(mode="json")
    payload.update(
        {
            "schema_version": "0.6.6",
            "estimated_cost_microusd": estimated_cost,
            "estimated_cost_picousd": exact_cost_picousd,
            "currency": snapshot.currency,
            "cost_basis": (
                "declared_pricing_snapshot_v2"
                if price.input_million_tokens_usd is not None
                else "declared_pricing_snapshot_v1"
            ),
            "pricing_snapshot_id": snapshot.pricing_snapshot_id,
            "pricing_snapshot_digest": pricing_snapshot_digest(snapshot),
            "limitations": limitations,
        }
    )
    return _validated_usage_segment(UsageSegment.model_validate(payload))


def estimate_segment_costs(
    segments: tuple[UsageSegment, ...],
    snapshot: UsagePricingSnapshot,
    *,
    overwrite: bool = False,
) -> tuple[UsageSegment, ...]:
    return tuple(
        estimate_segment_cost(segment, snapshot, overwrite=overwrite) for segment in segments
    )


def _validated_usage_segment(segment: UsageSegment) -> UsageSegment:
    payload = segment.model_dump(mode="json", warnings="error")
    validated = UsageSegment.model_validate(payload)
    validate_loaded_artifact_payload(payload, "usage-segment")
    return validated


def _validated_pricing_snapshot(snapshot: UsagePricingSnapshot) -> UsagePricingSnapshot:
    payload = snapshot.model_dump(mode="json", warnings="error")
    validated = UsagePricingSnapshot.model_validate(payload)
    validate_loaded_artifact_payload(payload, "usage-pricing-snapshot")
    return validated


def _limitations_to_preserve(
    segment: UsageSegment,
    *,
    overwrite: bool,
) -> tuple[str, ...]:
    if not overwrite or segment.estimated_cost_microusd is None:
        return segment.limitations
    return tuple(
        limitation
        for limitation in segment.limitations
        if not _is_known_generated_pricing_limitation(limitation)
    )


def _is_known_generated_pricing_limitation(limitation: str) -> bool:
    return limitation.strip() in _KNOWN_GENERATED_PRICING_LIMITATIONS


def _price_for_segment(
    segment: UsageSegment,
    snapshot: UsagePricingSnapshot,
) -> UsagePricingModel:
    if segment.provider is None or segment.model is None:
        raise ValueError("pricing snapshots require segment provider and model labels")
    for price in snapshot.models:
        if price.provider == segment.provider and price.model == segment.model:
            return price
    raise ValueError(
        f"pricing snapshot has no rate for provider={segment.provider!r}, model={segment.model!r}"
    )


def _estimated_cost(
    segment: UsageSegment,
    price: UsagePricingModel,
) -> tuple[int, int]:
    if segment.prompt_tokens is None or segment.completion_tokens is None:
        raise ValueError("declared pricing snapshots require prompt_tokens and completion_tokens")
    cached_tokens = segment.cached_tokens or 0
    reasoning_tokens = segment.reasoning_tokens or 0
    if cached_tokens > segment.prompt_tokens:
        raise ValueError("cached_tokens cannot exceed prompt_tokens for pricing")
    if reasoning_tokens > segment.completion_tokens:
        raise ValueError("reasoning_tokens cannot exceed completion_tokens for pricing")
    precise_rates = price.input_million_tokens_usd is not None
    cached_rate_missing = (
        price.cached_input_million_tokens_usd is None
        if precise_rates
        else price.cached_input_token_microusd is None
    )
    reasoning_rate_missing = (
        price.reasoning_million_tokens_usd is None
        if precise_rates
        else price.reasoning_token_microusd is None
    )
    if cached_tokens and cached_rate_missing:
        raise ValueError(
            "declared pricing snapshots require an explicit cached-input rate "
            "when cached_tokens are present"
        )
    if reasoning_tokens and reasoning_rate_missing:
        raise ValueError(
            "declared pricing snapshots require an explicit reasoning-token rate "
            "when reasoning_tokens are present"
        )
    uncached_prompt_tokens = segment.prompt_tokens - cached_tokens
    non_reasoning_completion_tokens = segment.completion_tokens - reasoning_tokens
    if precise_rates:
        assert price.input_million_tokens_usd is not None
        assert price.output_million_tokens_usd is not None
        numerator = (
            uncached_prompt_tokens * _six_place_integer(price.input_million_tokens_usd)
            + cached_tokens
            * _six_place_integer(price.cached_input_million_tokens_usd or "0.000000")
            + non_reasoning_completion_tokens * _six_place_integer(price.output_million_tokens_usd)
            + reasoning_tokens
            * _six_place_integer(price.reasoning_million_tokens_usd or "0.000000")
        )
        return microusd_from_picousd(numerator), numerator
    assert price.input_token_microusd is not None
    assert price.output_token_microusd is not None
    cached_cost = cached_tokens * (price.cached_input_token_microusd or 0)
    reasoning_cost = reasoning_tokens * (price.reasoning_token_microusd or 0)
    estimated_cost_microusd = (
        uncached_prompt_tokens * price.input_token_microusd
        + cached_cost
        + non_reasoning_completion_tokens * price.output_token_microusd
        + reasoning_cost
    )
    return estimated_cost_microusd, estimated_cost_microusd * 1_000_000


def _six_place_integer(value: str) -> int:
    whole, fractional = value.split(".", 1)
    return int(whole) * 1_000_000 + int(fractional)
