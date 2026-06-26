from __future__ import annotations

from dataclasses import dataclass

from agent_assure.schema.common import GateState

BUILT_IN_POLICY_IDS: tuple[str, ...] = (
    "runtime_success_required",
    "structured_output_required",
    "evidence_required",
    "material_claims_have_evidence",
    "tool_allowlist",
    "provider_review_boundary",
    "human_review_required",
    "redaction_required",
    "prompt_injection_control_boundary",
)


@dataclass(frozen=True)
class CapabilityStatus:
    capability_id: str
    state: GateState
    reason: str

    def model_dump(self) -> dict[str, str]:
        return {
            "capability_id": self.capability_id,
            "state": self.state.value,
            "reason": self.reason,
        }


DEFAULT_NOT_EVALUATED_CAPABILITIES: tuple[CapabilityStatus, ...] = (
    CapabilityStatus(
        capability_id="raw_payload_persistence_forbidden",
        state=GateState.not_evaluated,
        reason=(
            "runset writers redact summary fields and evaluation checks raw summaries, "
            "but no evaluator policy inspects external raw payload storage"
        ),
    ),
    CapabilityStatus(
        capability_id="live_stochastic_model_quality_regression",
        state=GateState.not_evaluated,
        reason="fixture mode does not run live stochastic model comparisons",
    ),
    CapabilityStatus(
        capability_id="production_runtime_isolation",
        state=GateState.not_evaluated,
        reason="offline run records do not observe production sandbox isolation",
    ),
    CapabilityStatus(
        capability_id="regulatory_compliance_certification",
        state=GateState.not_evaluated,
        reason="deterministic checks do not certify legal or regulatory compliance",
    ),
)
