from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Literal, TypedDict

if TYPE_CHECKING:
    from agent_assure.schema.live import LiveObservationResult
    from agent_assure.schema.run import AgentRunRecord


BUDGET_STOP_REASONS = frozenset(
    {
        "budget_exhausted",
        "cost_budget_exhausted_before_attempt",
        "cost_budget_exceeded_after_response",
        "generated_token_budget_exhausted_before_attempt",
        "generated_token_budget_exceeded_after_response",
        "token_budget_exhausted_before_attempt",
        "token_budget_exceeded_after_response",
        "token_budget_exhausted",
        "generated_token_budget_exhausted",
    }
)


class LiveObservationSourceValues(TypedDict):
    observation_id: str
    run_id: str
    case_id: str
    repetition_index: int
    schedule_index: int
    randomization_block_id: str
    prompt_digest: str
    provider: str | None
    model: str | None
    resolved_model: str | None
    provider_api_version: str | None
    provider_sdk: str | None
    provider_region: str | None
    adapter_id: str | None
    pipeline_id: str
    cluster_id: str
    source_group_id: str | None
    started_at_utc: str | None
    completed_at_utc: str | None
    observation_status: Literal["included", "excluded"]
    exclusion_reason: str | None
    attempt_count: int | None
    retry_count: int | None
    rate_limit_events: int | None
    tool_schema_digest: str
    policy_bundle_digest: str
    outcome: str
    latency_ms: int | None
    estimated_cost_usd: str | None
    estimated_cost_picousd: int | None


def project_live_stop_reasons(
    runset_stop_reasons: Iterable[str],
    exclusion_reasons: Iterable[str | None],
) -> tuple[str, ...]:
    """Return the canonical effective stop reasons for a live RunSet projection."""

    reasons = set(runset_stop_reasons)
    reasons.update(reason for reason in exclusion_reasons if reason in BUDGET_STOP_REASONS)
    return tuple(sorted(reasons))


@dataclass(frozen=True)
class LiveObservationSourceProjection:
    """RunSet-derived portion of a persisted live evaluation observation."""

    observation_id: str
    run_id: str
    case_id: str
    repetition_index: int
    schedule_index: int
    randomization_block_id: str
    prompt_digest: str
    provider: str | None
    model: str | None
    resolved_model: str | None
    provider_api_version: str | None
    provider_sdk: str | None
    provider_region: str | None
    adapter_id: str | None
    pipeline_id: str
    cluster_id: str
    source_group_id: str | None
    started_at_utc: str | None
    completed_at_utc: str | None
    observation_status: Literal["included", "excluded"]
    exclusion_reason: str | None
    attempt_count: int | None
    retry_count: int | None
    rate_limit_events: int | None
    tool_schema_digest: str
    policy_bundle_digest: str
    outcome: str
    latency_ms: int | None
    estimated_cost_usd: str | None
    estimated_cost_picousd: int | None

    def model_values(self) -> LiveObservationSourceValues:
        """Return constructor values without introducing a schema-module dependency."""

        return LiveObservationSourceValues(
            observation_id=self.observation_id,
            run_id=self.run_id,
            case_id=self.case_id,
            repetition_index=self.repetition_index,
            schedule_index=self.schedule_index,
            randomization_block_id=self.randomization_block_id,
            prompt_digest=self.prompt_digest,
            provider=self.provider,
            model=self.model,
            resolved_model=self.resolved_model,
            provider_api_version=self.provider_api_version,
            provider_sdk=self.provider_sdk,
            provider_region=self.provider_region,
            adapter_id=self.adapter_id,
            pipeline_id=self.pipeline_id,
            cluster_id=self.cluster_id,
            source_group_id=self.source_group_id,
            started_at_utc=self.started_at_utc,
            completed_at_utc=self.completed_at_utc,
            observation_status=self.observation_status,
            exclusion_reason=self.exclusion_reason,
            attempt_count=self.attempt_count,
            retry_count=self.retry_count,
            rate_limit_events=self.rate_limit_events,
            tool_schema_digest=self.tool_schema_digest,
            policy_bundle_digest=self.policy_bundle_digest,
            outcome=self.outcome,
            latency_ms=self.latency_ms,
            estimated_cost_usd=self.estimated_cost_usd,
            estimated_cost_picousd=self.estimated_cost_picousd,
        )


def project_run_observation_source(run: AgentRunRecord) -> LiveObservationSourceProjection:
    """Project exactly the RunSet fields persisted by the live evaluator."""

    return LiveObservationSourceProjection(
        observation_id=run.observation_id or f"missing-observation:{run.run_id}",
        run_id=run.run_id,
        case_id=run.case_id,
        repetition_index=run.repetition_index or 0,
        schedule_index=run.schedule_index or 0,
        randomization_block_id=_required_text(
            run.randomization_block_id,
            "randomization_block_id",
        ),
        prompt_digest=_required_digest(
            run.provenance.prompt_digest,
            "prompt_digest",
        ),
        provider=run.provider,
        model=run.model,
        resolved_model=run.resolved_model,
        provider_api_version=run.provider_api_version,
        provider_sdk=run.provider_sdk,
        provider_region=run.provider_region,
        adapter_id=run.adapter_id,
        pipeline_id=run.pipeline_id,
        cluster_id=run.cluster_id or run.case_id,
        source_group_id=run.source_group_id,
        started_at_utc=run.started_at_utc,
        completed_at_utc=run.completed_at_utc,
        observation_status=run.observation_status,
        exclusion_reason=run.exclusion_reason,
        attempt_count=run.attempt_count,
        retry_count=run.retry_count,
        rate_limit_events=run.rate_limit_events,
        tool_schema_digest=_required_digest(
            run.provenance.tool_schema_digest,
            "tool_schema_digest",
        ),
        policy_bundle_digest=_required_digest(
            run.provenance.policy_bundle_digest,
            "policy_bundle_digest",
        ),
        outcome=run.outcome,
        latency_ms=run.latency_ms,
        estimated_cost_usd=run.estimated_cost_usd,
        estimated_cost_picousd=run.estimated_cost_picousd,
    )


def project_persisted_observation_source(
    observation: LiveObservationResult,
) -> LiveObservationSourceProjection:
    """Project the source-derived fields from a persisted evaluation observation."""

    return LiveObservationSourceProjection(
        observation_id=observation.observation_id,
        run_id=observation.run_id,
        case_id=observation.case_id,
        repetition_index=observation.repetition_index,
        schedule_index=_required_integer(observation.schedule_index, "schedule_index"),
        randomization_block_id=_required_text(
            observation.randomization_block_id,
            "randomization_block_id",
        ),
        prompt_digest=_required_digest(observation.prompt_digest, "prompt_digest"),
        provider=observation.provider,
        model=observation.model,
        resolved_model=observation.resolved_model,
        provider_api_version=observation.provider_api_version,
        provider_sdk=observation.provider_sdk,
        provider_region=observation.provider_region,
        adapter_id=observation.adapter_id,
        pipeline_id=observation.pipeline_id,
        cluster_id=observation.cluster_id,
        source_group_id=observation.source_group_id,
        started_at_utc=observation.started_at_utc,
        completed_at_utc=observation.completed_at_utc,
        observation_status=observation.observation_status,
        exclusion_reason=observation.exclusion_reason,
        attempt_count=observation.attempt_count,
        retry_count=observation.retry_count,
        rate_limit_events=observation.rate_limit_events,
        tool_schema_digest=observation.tool_schema_digest,
        policy_bundle_digest=observation.policy_bundle_digest,
        outcome=_required_string(observation.outcome, "outcome"),
        latency_ms=observation.latency_ms,
        estimated_cost_usd=observation.estimated_cost_usd,
        estimated_cost_picousd=observation.estimated_cost_picousd,
    )


def differing_projection_fields(
    expected: LiveObservationSourceProjection,
    actual: LiveObservationSourceProjection,
) -> tuple[str, ...]:
    """Return source-projection field names that differ, without leaking values."""

    return tuple(
        field.name
        for field in fields(expected)
        if getattr(expected, field.name) != getattr(actual, field.name)
    )


def _required_digest(value: str | None, field_name: str) -> str:
    if value is None:
        raise ValueError(f"live observation missing provenance {field_name}")
    return value


def _required_text(value: str | None, field_name: str) -> str:
    if not value:
        raise ValueError(f"live observation missing {field_name}")
    return value


def _required_integer(value: int | None, field_name: str) -> int:
    if value is None:
        raise ValueError(f"live observation missing {field_name}")
    return value


def _required_string(value: str | None, field_name: str) -> str:
    if value is None:
        raise ValueError(f"live observation missing {field_name}")
    return value
