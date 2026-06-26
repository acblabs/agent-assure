from __future__ import annotations

import pytest

from agent_assure.runner.evidence import EvidenceAssociation, evidence_refs_from_associations


def test_evidence_refs_merge_duplicate_ref_claims() -> None:
    refs = evidence_refs_from_associations(
        (
            EvidenceAssociation(
                ref_id="ref-shared",
                source_id="source-a",
                content_digest="a" * 64,
                claim_ids=("claim-b",),
            ),
            EvidenceAssociation(
                ref_id="ref-shared",
                source_id="source-a",
                content_digest="a" * 64,
                claim_ids=("claim-a",),
            ),
        )
    )

    assert len(refs) == 1
    assert refs[0].ref_id == "ref-shared"
    assert refs[0].claim_ids == ("claim-a", "claim-b")


def test_evidence_refs_reject_conflicting_sources_for_same_ref() -> None:
    with pytest.raises(ValueError, match="conflicting source_id"):
        evidence_refs_from_associations(
            (
                EvidenceAssociation(
                    ref_id="ref-shared",
                    source_id="source-a",
                    content_digest="a" * 64,
                    claim_ids=("claim-a",),
                ),
                EvidenceAssociation(
                    ref_id="ref-shared",
                    source_id="source-b",
                    content_digest="b" * 64,
                    claim_ids=("claim-b",),
                ),
            )
        )
