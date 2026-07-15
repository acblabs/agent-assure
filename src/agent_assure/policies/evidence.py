from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import AgentRunRecord


def evaluate_required_evidence(
    run: AgentRunRecord,
    expectation: Expectation,
) -> tuple[ControlResult, ...]:
    observed_refs = _observed_evidence_refs(run)
    return tuple(
        ControlResult(
            control_id="evidence_required",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.REQUIRED_SOURCE_MISSING,
            severity=Severity.error,
            target=f"evidence_ref:{ref_id}",
            message=f"required evidence ref {ref_id!r} is missing",
        )
        for ref_id in expectation.required_evidence_refs
        if ref_id not in observed_refs
    )


def evaluate_material_claim_evidence(
    run: AgentRunRecord,
    expectation: Expectation,
) -> tuple[ControlResult, ...]:
    existing_items = _observed_evidence_items(run)
    linked_claims = {
        link.claim_id
        for link in run.claim_evidence_links
        if link.evidence_ref_id in existing_items
    }
    return tuple(
        ControlResult(
            control_id="material_claims_have_evidence",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
            severity=Severity.error,
            target=f"claim:{claim_id}",
            message=(
                f"fixture-declared material claim {claim_id!r} has no "
                "content-addressed evidence item link"
            ),
        )
        for claim_id in expectation.material_claim_ids
        if claim_id not in linked_claims
    )


def _observed_evidence_refs(run: AgentRunRecord) -> set[str]:
    return {ref.ref_id for ref in run.evidence_refs}


def _observed_evidence_items(run: AgentRunRecord) -> set[str]:
    return {item.ref_id for item in run.evidence_items}
