from __future__ import annotations

from typing import Any

from agent_assure.canonical.hmac_tokens import hmac_sha256_token
from agent_assure.runner.evidence import evidence_from_tool_output
from agent_assure.runner.fixture_runner import LoadedFixtures, RunnerContext, VariantConfig
from agent_assure.runner.fixture_values import optional_string, required_string, string_sequence
from agent_assure.runner.records import build_fixture_run_record
from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.suite import SuiteCase
from agent_assure.schema.usage import UsageSegment
from agent_assure.usage.aggregation import aggregate_usage_segments

_PROFILE_BY_VARIANT_ID = {
    "baseline": "baseline",
    "candidate-process-regressions": "candidate",
}
_COST_BASIS = "declared_process_measurement_fixture_v1"
_PRICING_SNAPSHOT_ID = "process-measurement-demo-pricing-v1"
_PRICING_SNAPSHOT_DIGEST = "8888888888888888888888888888888888888888888888888888888888888888"
_COST_LIMITATION = "Synthetic process-measurement fixture cost; not live provider pricing."


def run_process_measurement_case(
    case: SuiteCase,
    fixtures: LoadedFixtures,
    variant: VariantConfig,
    context: RunnerContext,
) -> AgentRunRecord:
    profile = _profile_for_variant(variant)
    model_profile = _profile_mapping(fixtures.model_output, profile, owner="model_output")
    tool_profile = _profile_mapping(fixtures.tool_output, profile, owner="tool_output")
    provider = optional_string(model_profile.get("provider"))
    model = optional_string(model_profile.get("model"))
    recommendation = required_string(model_profile, "recommendation")
    outcome = required_string(model_profile, "outcome")

    record = build_fixture_run_record(
        case=case,
        variant=variant,
        context=context,
        recommendation=recommendation,
        outcome=outcome,
        input_summary=_input_summary(case, fixtures, context),
        provider=provider,
        model=model,
        tools=tuple(sorted(string_sequence(tool_profile.get("tools", ())))),
        evidence=evidence_from_tool_output(tool_profile),
        policy_events=(),
        human_review_required=bool(model_profile.get("human_review_required", False)),
        human_review_performed=bool(model_profile.get("human_review_performed", False)),
    )
    return _attach_operational_measurements(record, model_profile, profile=profile)


def _profile_for_variant(variant: VariantConfig) -> str:
    try:
        return _PROFILE_BY_VARIANT_ID[variant.variant_id]
    except KeyError as exc:
        known = ", ".join(sorted(_PROFILE_BY_VARIANT_ID))
        raise ValueError(
            f"process measurement runner does not know variant_id {variant.variant_id!r}; "
            f"known variants: {known}"
        ) from exc


def _profile_mapping(
    payload: dict[str, object],
    profile: str,
    *,
    owner: str,
) -> dict[str, object]:
    value = payload.get(profile)
    if not isinstance(value, dict):
        raise ValueError(f"{owner} must contain a {profile!r} object")
    return {str(key): item for key, item in value.items()}


def _attach_operational_measurements(
    record: AgentRunRecord,
    model_profile: dict[str, object],
    *,
    profile: str,
) -> AgentRunRecord:
    updates: dict[str, object] = {}
    if "attempt_count" in model_profile:
        updates["attempt_count"] = _positive_int(
            model_profile["attempt_count"],
            "attempt_count",
        )
    for field_name in ("retry_count", "rate_limit_events", "latency_ms"):
        if field_name in model_profile:
            updates[field_name] = _non_negative_int(model_profile[field_name], field_name)
    usage_payload = model_profile.get("usage")
    if usage_payload is not None:
        if not isinstance(usage_payload, dict):
            raise ValueError("usage must be an object when present")
        segment = _usage_segment(
            record,
            {str(key): value for key, value in usage_payload.items()},
            profile,
        )
        usage = aggregate_usage_segments((segment,))
        updates["usage_ledger"] = usage.usage_ledger
        updates["usage_summary"] = usage.usage_summary
    if not updates:
        return record
    return record.model_copy(update=updates)


def _usage_segment(
    record: AgentRunRecord,
    usage_payload: dict[str, object],
    profile: str,
) -> UsageSegment:
    estimated_cost = _optional_non_negative_int(
        usage_payload.get("estimated_cost_microusd"),
        "estimated_cost_microusd",
    )
    kwargs: dict[str, Any] = {
        "segment_id": f"usage-{profile}-{record.case_id}",
        "case_id": record.case_id,
        "run_id": record.run_id,
        "provider": record.provider,
        "model": record.model,
        "operation": "process_measurement_fixture",
        "prompt_tokens": _optional_non_negative_int(
            usage_payload.get("prompt_tokens"),
            "prompt_tokens",
        ),
        "completion_tokens": _optional_non_negative_int(
            usage_payload.get("completion_tokens"),
            "completion_tokens",
        ),
        "total_tokens": _optional_non_negative_int(
            usage_payload.get("total_tokens"),
            "total_tokens",
        ),
        "tool_call_count": _optional_non_negative_int(
            usage_payload.get("tool_call_count"),
            "tool_call_count",
        ),
        "retry_count": _optional_non_negative_int(
            usage_payload.get("retry_count"),
            "retry_count",
        ),
        "latency_ms": _optional_non_negative_int(
            usage_payload.get("latency_ms"),
            "latency_ms",
        ),
        "estimated_cost_microusd": estimated_cost,
    }
    if estimated_cost is not None:
        kwargs.update(
            {
                "cost_basis": _COST_BASIS,
                "pricing_snapshot_id": _PRICING_SNAPSHOT_ID,
                "pricing_snapshot_digest": _PRICING_SNAPSHOT_DIGEST,
                "limitations": (_COST_LIMITATION,),
            }
        )
    return UsageSegment(**kwargs)


def _input_summary(case: SuiteCase, fixtures: LoadedFixtures, context: RunnerContext) -> str:
    subject_id = fixtures.request.get("subject_id")
    subject_token = hmac_sha256_token(str(subject_id or case.case_id), key=context.hmac_key)[:16]
    return f"case={case.case_id}; subject_token={subject_token}; fixture={fixtures.fixture_id}"


def _optional_non_negative_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _non_negative_int(value, field_name)


def _non_negative_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


def _positive_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value
