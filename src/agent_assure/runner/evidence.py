from __future__ import annotations

from dataclasses import dataclass

from agent_assure.schema.run import EvidenceRef


@dataclass(frozen=True)
class EvidenceAssociation:
    ref_id: str
    source_id: str
    content_digest: str
    claim_ids: tuple[str, ...]


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

def evidence_refs_from_associations(
    evidence: tuple[EvidenceAssociation, ...],
) -> tuple[EvidenceRef, ...]:
    refs: dict[str, tuple[str, set[str]]] = {}
    for item in evidence:
        existing = refs.get(item.ref_id)
        if existing is None:
            refs[item.ref_id] = (item.source_id, set(item.claim_ids))
            continue
        source_id, claim_ids = existing
        if source_id != item.source_id:
            raise ValueError(f"evidence ref_id {item.ref_id!r} has conflicting source_id values")
        claim_ids.update(item.claim_ids)
    return tuple(
        EvidenceRef(
            artifact_kind="evidence-ref",
            ref_id=ref_id,
            source_id=source_id,
            claim_ids=tuple(sorted(claim_ids)),
        )
        for ref_id, (source_id, claim_ids) in sorted(refs.items())
    )
