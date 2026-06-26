from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from agent_assure.schema.common import GateState, ReasonCode

ProviderPolicyPrecedence = Literal["policy_over_runtime", "runtime_over_policy"]


@dataclass(frozen=True)
class PolicyEvent:
    policy_id: str
    state: GateState
    reason_codes: tuple[ReasonCode, ...] = ()


@dataclass(frozen=True)
class ProviderPolicyApplication:
    recommendation: str
    outcome: str
    human_review_required: bool
    events: tuple[PolicyEvent, ...]


def apply_provider_policy(
    provider: str | None,
    *,
    recommendation: str,
    outcome: str,
    human_review_required: bool,
    forbidden_providers: tuple[str, ...],
    runtime_allowed_providers: tuple[str, ...],
    precedence: ProviderPolicyPrecedence,
    fail_recommendation: str,
    fail_outcome: str,
    policy_id: str = "provider-selection",
) -> ProviderPolicyApplication:
    event = provider_policy_event(
        provider,
        forbidden_providers=forbidden_providers,
        runtime_allowed_providers=runtime_allowed_providers,
        precedence=precedence,
        policy_id=policy_id,
    )
    if event is None:
        return ProviderPolicyApplication(
            recommendation=recommendation,
            outcome=outcome,
            human_review_required=human_review_required,
            events=(),
        )
    if event.state is GateState.fail:
        return ProviderPolicyApplication(
            recommendation=fail_recommendation,
            outcome=fail_outcome,
            human_review_required=True,
            events=(event,),
        )
    return ProviderPolicyApplication(
        recommendation=recommendation,
        outcome=outcome,
        human_review_required=human_review_required,
        events=(event,),
    )


def provider_policy_event(
    provider: str | None,
    *,
    forbidden_providers: tuple[str, ...],
    runtime_allowed_providers: tuple[str, ...],
    precedence: ProviderPolicyPrecedence,
    policy_id: str = "provider-selection",
) -> PolicyEvent | None:
    if provider is None:
        return None
    effective_forbidden = _effective_forbidden_providers(
        forbidden_providers=forbidden_providers,
        runtime_allowed_providers=runtime_allowed_providers,
        precedence=precedence,
    )
    if provider_is_allowed(provider, effective_forbidden):
        return PolicyEvent(policy_id=policy_id, state=GateState.pass_)
    return PolicyEvent(
        policy_id=policy_id,
        state=GateState.fail,
        reason_codes=(ReasonCode.FORBIDDEN_PROVIDER,),
    )


def provider_is_allowed(provider: str, forbidden_providers: tuple[str, ...]) -> bool:
    return provider not in set(forbidden_providers)


def _effective_forbidden_providers(
    *,
    forbidden_providers: tuple[str, ...],
    runtime_allowed_providers: tuple[str, ...],
    precedence: ProviderPolicyPrecedence,
) -> tuple[str, ...]:
    if precedence == "policy_over_runtime":
        return forbidden_providers
    runtime_allowed = set(runtime_allowed_providers)
    return tuple(provider for provider in forbidden_providers if provider not in runtime_allowed)
