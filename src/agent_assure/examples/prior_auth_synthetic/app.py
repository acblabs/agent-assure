from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from agent_assure.runner.evidence import (
    EvidenceAssociation,
    evidence_from_tool_output,
)
from agent_assure.runner.fixture_values import optional_string, required_string, string_sequence
from agent_assure.runner.governance_controls import (
    PolicyEvent,
    ProviderPolicyPrecedence,
    apply_provider_policy,
    provider_is_allowed,
)
from agent_assure.schema.common import GateState, ReasonCode, Severity

EvidenceAssemblyMode = Literal["association_preserving", "catalog_reconstruction"]

__all__ = [
    "EvidenceAssemblyMode",
    "EvidenceAssociation",
    "assemble_evidence",
    "evidence_from_tool_output",
    "preserve_associations",
    "provider_is_allowed",
    "reconstruct_first_association_by_catalog_key",
    "run_prior_auth_app",
]


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
    policy_events: tuple[PolicyEvent, ...]


def run_prior_auth_app(
    model_output: dict[str, object],
    tool_output: dict[str, object],
    *,
    evidence_assembly: EvidenceAssemblyMode,
    forbidden_providers: tuple[str, ...],
    runtime_allowed_providers: tuple[str, ...],
    provider_policy_precedence: ProviderPolicyPrecedence,
) -> PriorAuthDecision:
    provider = optional_string(model_output.get("provider"))
    model = optional_string(model_output.get("model"))
    recommendation = required_string(model_output, "recommendation")
    outcome = required_string(model_output, "outcome")
    human_review_required = bool(model_output.get("human_review_required", False))
    policy_events: list[PolicyEvent] = []

    if bool(tool_output.get("prompt_injection_detected", False)):
        recommendation = "escalate"
        outcome = "escalate"
        human_review_required = True
        policy_events.append(
            PolicyEvent(
                policy_id="prompt-injection-boundary",
                state=GateState.warn,
                reason_codes=(ReasonCode.PROMPT_INJECTION_BOUNDARY,),
                severity=Severity.warning,
                message="prompt-boundary signal routed the case to review",
            )
        )

    provider_application = apply_provider_policy(
        provider,
        recommendation=recommendation,
        outcome=outcome,
        human_review_required=human_review_required,
        forbidden_providers=forbidden_providers,
        runtime_allowed_providers=runtime_allowed_providers,
        precedence=provider_policy_precedence,
        fail_recommendation="escalate",
        fail_outcome="escalate",
    )
    recommendation = provider_application.recommendation
    outcome = provider_application.outcome
    human_review_required = provider_application.human_review_required
    policy_events.extend(provider_application.events)

    return PriorAuthDecision(
        provider=provider,
        model=model,
        recommendation=recommendation,
        outcome=outcome,
        human_review_required=human_review_required,
        human_review_performed=bool(model_output.get("human_review_performed", False)),
        tools=tuple(sorted(string_sequence(tool_output.get("tools", ())))),
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
    return reconstruct_first_association_by_catalog_key(associations)


def preserve_associations(
    items: tuple[EvidenceAssociation, ...],
) -> tuple[EvidenceAssociation, ...]:
    return tuple(sorted(items, key=lambda item: item.ref_id))


def reconstruct_first_association_by_catalog_key(
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
