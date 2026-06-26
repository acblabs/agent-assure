from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from agent_assure.schema.common import GateState, ReasonCode

EvidenceAssemblyMode = Literal["association_preserving", "catalog_reconstruction"]
ProviderPolicyPrecedence = Literal["policy_over_runtime", "runtime_over_policy"]


@dataclass(frozen=True)
class EvidenceAssociation:
    ref_id: str
    source_id: str
    content_digest: str
    claim_ids: tuple[str, ...]


@dataclass(frozen=True)
class AppPolicyEvent:
    policy_id: str
    state: GateState
    reason_codes: tuple[ReasonCode, ...] = ()


@dataclass(frozen=True)
class PriorAuthDecision:
    provider: str | None
    model: str | None
    recommendation: str
    outcome: str
    human_review_required: bool
    human_review_performed: bool
    tools: tuple[str, ...]
    evidence: tuple[EvidenceAssociation, ...]
    policy_events: tuple[AppPolicyEvent, ...]


def run_prior_auth_app(
    request: dict[str, object],
    model_output: dict[str, object],
    tool_output: dict[str, object],
    *,
    evidence_assembly: EvidenceAssemblyMode,
    forbidden_providers: tuple[str, ...],
    runtime_allowed_providers: tuple[str, ...],
    provider_policy_precedence: ProviderPolicyPrecedence,
) -> PriorAuthDecision:
    del request
    provider = _optional_string(model_output.get("provider"))
    model = _optional_string(model_output.get("model"))
    recommendation = _required_string(model_output, "recommendation")
    outcome = _required_string(model_output, "outcome")
    human_review_required = bool(model_output.get("human_review_required", False))
    policy_events: list[AppPolicyEvent] = []

    if bool(tool_output.get("prompt_injection_detected", False)):
        recommendation = "escalate"
        outcome = "escalate"
        human_review_required = True
        policy_events.append(
            AppPolicyEvent(
                policy_id="prompt-injection-boundary",
                state=GateState.warn,
                reason_codes=(ReasonCode.PROMPT_INJECTION_BOUNDARY,),
            )
        )

    provider_event = _provider_policy_event(
        provider,
        forbidden_providers=forbidden_providers,
        runtime_allowed_providers=runtime_allowed_providers,
        precedence=provider_policy_precedence,
    )
    if provider_event is not None:
        policy_events.append(provider_event)
        if provider_event.state is GateState.fail:
            recommendation = "escalate"
            outcome = "escalate"
            human_review_required = True

    return PriorAuthDecision(
        provider=provider,
        model=model,
        recommendation=recommendation,
        outcome=outcome,
        human_review_required=human_review_required,
        human_review_performed=bool(model_output.get("human_review_performed", False)),
        tools=tuple(sorted(_string_sequence(tool_output.get("tools", ())))),
        evidence=assemble_evidence(tool_output, evidence_assembly),
        policy_events=tuple(policy_events),
    )


def assemble_evidence(
    tool_output: dict[str, object],
    mode: EvidenceAssemblyMode,
) -> tuple[EvidenceAssociation, ...]:
    associations = evidence_from_tool_output(tool_output)
    if mode == "association_preserving":
        return preserve_associations(associations)
    return reconstruct_from_catalog(associations)


def evidence_from_tool_output(payload: dict[str, object]) -> tuple[EvidenceAssociation, ...]:
    raw_items = payload.get("evidence", ())
    if not isinstance(raw_items, list | tuple):
        raise TypeError("evidence must be a sequence")
    associations: list[EvidenceAssociation] = []
    for item in raw_items:
        if not isinstance(item, dict):
            raise TypeError("evidence item must be a mapping")
        claim_ids = item.get("claim_ids", ())
        if not isinstance(claim_ids, list | tuple):
            raise TypeError("claim_ids must be a sequence")
        associations.append(
            EvidenceAssociation(
                ref_id=str(item["ref_id"]),
                source_id=str(item["source_id"]),
                content_digest=str(item["content_digest"]),
                claim_ids=tuple(str(claim_id) for claim_id in claim_ids),
            )
        )
    return tuple(associations)


def preserve_associations(
    items: tuple[EvidenceAssociation, ...],
) -> tuple[EvidenceAssociation, ...]:
    return tuple(sorted(items, key=lambda item: item.ref_id))


def reconstruct_from_catalog(
    items: tuple[EvidenceAssociation, ...],
) -> tuple[EvidenceAssociation, ...]:
    catalog: dict[tuple[str, str], EvidenceAssociation] = {}
    for item in items:
        catalog.setdefault(
            (item.source_id, item.content_digest),
            EvidenceAssociation(
                ref_id=item.ref_id,
                source_id=item.source_id,
                content_digest=item.content_digest,
                claim_ids=item.claim_ids,
            ),
        )
    return tuple(catalog[key] for key in sorted(catalog))


def provider_is_allowed(provider: str, forbidden_providers: tuple[str, ...]) -> bool:
    return provider not in set(forbidden_providers)


def _provider_policy_event(
    provider: str | None,
    *,
    forbidden_providers: tuple[str, ...],
    runtime_allowed_providers: tuple[str, ...],
    precedence: ProviderPolicyPrecedence,
) -> AppPolicyEvent | None:
    if provider is None:
        return None
    effective_forbidden = _effective_forbidden_providers(
        forbidden_providers=forbidden_providers,
        runtime_allowed_providers=runtime_allowed_providers,
        precedence=precedence,
    )
    if provider_is_allowed(provider, effective_forbidden):
        return AppPolicyEvent("provider-selection", GateState.pass_)
    return AppPolicyEvent(
        policy_id="provider-selection",
        state=GateState.fail,
        reason_codes=(ReasonCode.FORBIDDEN_PROVIDER,),
    )


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


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise TypeError("expected string sequence")
    return tuple(str(item) for item in value)


def _required_string(data: dict[str, object], field_name: str) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return str(value)
