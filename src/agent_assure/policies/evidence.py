from __future__ import annotations

import hashlib
import unicodedata

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
            target=evidence_ref_finding_target(ref_id),
            message="required evidence reference is missing",
        )
        for ref_id in expectation.required_evidence_refs
        if ref_id not in observed_refs
    )


def evaluate_material_claim_evidence(
    run: AgentRunRecord,
    expectation: Expectation,
) -> tuple[ControlResult, ...]:
    complete_evidence = _observed_evidence_refs(run) & _observed_evidence_items(run)
    linked_claims = {
        link.claim_id
        for link in run.claim_evidence_links
        if link.evidence_ref_id in complete_evidence
    }
    return tuple(
        ControlResult(
            control_id="material_claims_have_evidence",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
            severity=Severity.error,
            target=claim_finding_target(claim_id),
            message=(
                "fixture-declared material claim has no "
                "paired reference and content-addressed evidence item link"
            ),
        )
        for claim_id in expectation.material_claim_ids
        if claim_id not in linked_claims
    )


def evaluate_evidence_provenance_identity(
    run: AgentRunRecord,
) -> tuple[ControlResult, ...]:
    """Require a complete evidence graph with one source identity per ref ID.

    Every ID on either side must have both reference and content-addressed item
    records. Paired records must agree on exactly one source identity. Findings
    carry only a domain-separated digest of the reference ID so caller-controlled
    identifiers and source values are not copied into reports.
    """
    ref_sources: dict[str, set[str]] = {}
    for ref in run.evidence_refs:
        ref_sources.setdefault(ref.ref_id, set()).add(ref.source_id)
    item_sources: dict[str, set[str]] = {}
    item_content_identities: dict[tuple[str, str], set[str]] = {}
    for item in run.evidence_items:
        item_sources.setdefault(item.ref_id, set()).add(item.source_id)
        item_content_identities.setdefault((item.ref_id, item.source_id), set()).add(
            item.content_digest
        )

    findings: list[ControlResult] = []
    for ref_id in sorted(set(ref_sources) | set(item_sources)):
        sources_from_refs = ref_sources.get(ref_id)
        sources_from_items = item_sources.get(ref_id)
        observed_sources = (sources_from_refs or set()) | (sources_from_items or set())
        if (
            sources_from_refs is not None
            and sources_from_items is not None
            and sources_from_refs == sources_from_items
            and len(observed_sources) == 1
            and all(
                len(content_digests) == 1
                for (item_ref_id, _), content_digests in item_content_identities.items()
                if item_ref_id == ref_id
            )
            and _is_meaningful_evidence_identifier(ref_id)
            and all(_is_meaningful_evidence_identifier(source_id) for source_id in observed_sources)
        ):
            continue
        findings.append(
            ControlResult(
                control_id="evidence_provenance_identity",
                case_id=run.case_id,
                state=GateState.fail,
                reason_code=ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
                severity=Severity.blocker,
                target=evidence_ref_finding_target(ref_id),
                message=(
                    "evidence reference and content-addressed item records are "
                    "missing or have inconsistent source/content identity"
                ),
            )
        )
    return tuple(findings)


def evidence_ref_finding_target(ref_id: str) -> str:
    """Return a stable privacy-minimized target for one evidence reference ID."""
    digest = hashlib.sha256(
        b"agent-assure/evidence-reference-target/v1\x00" + ref_id.encode("utf-8")
    ).hexdigest()
    return f"evidence_ref_digest:{digest}"


def claim_finding_target(claim_id: str) -> str:
    """Return a stable privacy-minimized target for one material claim ID."""
    digest = hashlib.sha256(
        b"agent-assure/material-claim-target/v1\x00" + claim_id.encode("utf-8")
    ).hexdigest()
    return f"claim_digest:{digest}"


def _is_meaningful_evidence_identifier(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


def _observed_evidence_refs(run: AgentRunRecord) -> set[str]:
    return {ref.ref_id for ref in run.evidence_refs}


def _observed_evidence_items(run: AgentRunRecord) -> set[str]:
    return {item.ref_id for item in run.evidence_items}
