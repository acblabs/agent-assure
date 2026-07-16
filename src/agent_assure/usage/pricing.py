from __future__ import annotations

import json
from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import MAX_CONFIG_TEXT_BYTES, read_text_bounded
from agent_assure.schema.common import DigestHex
from agent_assure.schema.usage import UsagePricingModel, UsagePricingSnapshot, UsageSegment

DECLARED_PRICING_LIMITATION = (
    "Cost is estimated from a declared pricing snapshot with a persisted content digest."
)
_DEMO_FIXTURE_PRICING_LIMITATION = (
    "Demo fixture pricing only; not live provider pricing."
)
_KNOWN_GENERATED_PRICING_LIMITATIONS = frozenset(
    {
        DECLARED_PRICING_LIMITATION,
        _DEMO_FIXTURE_PRICING_LIMITATION,
    }
)


def load_pricing_snapshot(path: Path) -> UsagePricingSnapshot:
    payload = json.loads(
        read_text_bounded(path, max_bytes=MAX_CONFIG_TEXT_BYTES, label="pricing snapshot")
    )
    return UsagePricingSnapshot.model_validate(payload)


def pricing_snapshot_digest(snapshot: UsagePricingSnapshot) -> DigestHex:
    return sha256_hexdigest(snapshot.model_dump(mode="json"))


def estimate_segment_cost(
    segment: UsageSegment,
    snapshot: UsagePricingSnapshot,
    *,
    overwrite: bool = False,
) -> UsageSegment:
    if segment.estimated_cost_microusd is not None and not overwrite:
        return segment
    if segment.prompt_tokens is None or segment.completion_tokens is None:
        raise ValueError(
            "declared pricing snapshots require prompt_tokens and completion_tokens"
        )
    price = _price_for_segment(segment, snapshot)
    estimated_cost = _estimated_cost(segment, price)
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
    return segment.model_copy(
        update={
            "estimated_cost_microusd": estimated_cost,
            "currency": snapshot.currency,
            "cost_basis": "declared_pricing_snapshot_v1",
            "pricing_snapshot_id": snapshot.pricing_snapshot_id,
            "pricing_snapshot_digest": pricing_snapshot_digest(snapshot),
            "limitations": limitations,
        }
    )


def estimate_segment_costs(
    segments: tuple[UsageSegment, ...],
    snapshot: UsagePricingSnapshot,
    *,
    overwrite: bool = False,
) -> tuple[UsageSegment, ...]:
    return tuple(
        estimate_segment_cost(segment, snapshot, overwrite=overwrite)
        for segment in segments
    )


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
        "pricing snapshot has no rate for "
        f"provider={segment.provider!r}, model={segment.model!r}"
    )


def _estimated_cost(segment: UsageSegment, price: UsagePricingModel) -> int:
    if segment.prompt_tokens is None or segment.completion_tokens is None:
        raise ValueError(
            "declared pricing snapshots require prompt_tokens and completion_tokens"
        )
    cached_tokens = segment.cached_tokens or 0
    reasoning_tokens = segment.reasoning_tokens or 0
    if cached_tokens > segment.prompt_tokens:
        raise ValueError("cached_tokens cannot exceed prompt_tokens for pricing")
    if reasoning_tokens > segment.completion_tokens:
        raise ValueError("reasoning_tokens cannot exceed completion_tokens for pricing")
    if cached_tokens and price.cached_input_token_microusd is None:
        raise ValueError(
            "declared pricing snapshots require cached_input_token_microusd "
            "when cached_tokens are present"
        )
    if reasoning_tokens and price.reasoning_token_microusd is None:
        raise ValueError(
            "declared pricing snapshots require reasoning_token_microusd "
            "when reasoning_tokens are present"
        )
    uncached_prompt_tokens = segment.prompt_tokens - cached_tokens
    non_reasoning_completion_tokens = segment.completion_tokens - reasoning_tokens
    cached_cost = cached_tokens * (price.cached_input_token_microusd or 0)
    reasoning_cost = reasoning_tokens * (price.reasoning_token_microusd or 0)
    return (
        uncached_prompt_tokens * price.input_token_microusd
        + cached_cost
        + non_reasoning_completion_tokens * price.output_token_microusd
        + reasoning_cost
    )
