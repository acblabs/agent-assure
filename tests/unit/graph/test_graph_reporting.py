from __future__ import annotations

from pathlib import Path

import pytest

from agent_assure.graph.builder import build_evidence_graph
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting import graph as graph_reporting
from agent_assure.reporting.graph import (
    evidence_graph_json_text,
    load_evidence_graph,
    write_evidence_graph,
)
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.graph import (
    AssuranceEvidenceGraph,
    EvidenceGraphEvidencePayload,
    EvidenceGraphNode,
    EvidenceGraphReference,
    EvidenceGraphReferenceRole,
    EvidenceGraphSubjectPayload,
)


def _subject_only_graph() -> AssuranceEvidenceGraph:
    return build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="graph-reporting-runset",
            subject_digest="a" * 64,
        )
    )


def _evaluation_graph_with_reference(
    value: str,
    *,
    role: EvidenceGraphReferenceRole = EvidenceGraphReferenceRole.source_digest,
) -> AssuranceEvidenceGraph:
    evaluation = EvaluationSummary(
        runset_id="graph-reporting-runset",
        runset_digest="a" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=evaluation.runset_id,
            subject_digest=evaluation.runset_digest,
        ),
        evaluation=evaluation,
    )
    evidence_node = next(
        node for node in graph.nodes if isinstance(node.payload, EvidenceGraphEvidencePayload)
    )
    evidence_payload = evidence_node.payload
    assert isinstance(evidence_payload, EvidenceGraphEvidencePayload)
    payload = evidence_payload.model_copy(
        update={
            "references": (
                *evidence_payload.references,
                EvidenceGraphReference(
                    role=role,
                    value=value,
                ),
            )
        }
    )
    updated_node = EvidenceGraphNode.build(
        kind=evidence_node.kind,
        payload=payload,
        subject_node_id=graph.primary_subject_node_id,
    )
    return AssuranceEvidenceGraph.from_parts(
        primary_subject_node_id=graph.primary_subject_node_id,
        nodes=tuple(
            updated_node if node.node_id == evidence_node.node_id else node for node in graph.nodes
        ),
        edges=graph.edges,
        compatibility=graph.compatibility,
        limitations=graph.limitations,
    )


def test_graph_writer_and_bounded_loader_round_trip_exact_bytes(tmp_path: Path) -> None:
    graph = _subject_only_graph()
    path = tmp_path / "assurance-evidence-graph.json"

    write_evidence_graph(graph, path)

    assert path.read_text(encoding="utf-8") == evidence_graph_json_text(graph)
    assert load_evidence_graph(path) == graph


def test_graph_persistence_rejects_unfiltered_sensitive_payloads() -> None:
    evaluation = EvaluationSummary(
        runset_id="graph-reporting-runset",
        runset_digest="a" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(
            Finding(
                finding_id="sensitive-finding",
                case_id="case-sensitive",
                control_id="material_claims_have_evidence",
                state=GateState.fail,
                reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                message="Contact alice@example.com about the missing evidence.",
            ),
        ),
    )
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=evaluation.runset_id,
            subject_digest=evaluation.runset_digest,
        ),
        evaluation=evaluation,
    )

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


def test_graph_persistence_accepts_card_like_digits_in_validated_node_ids() -> None:
    evaluation = EvaluationSummary(
        runset_id="relocated-packet-candidate",
        runset_digest="b154f9a3766d9729cc9e01508248c445de1198da60511179f95d9f702f6c713a",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=evaluation.runset_id,
            subject_digest=evaluation.runset_digest,
        ),
        evaluation=evaluation,
    )
    card_like_node_id = "evidence:09b07bd1dd6c3df985385cad530b971ec10471c91af93748654877853ab541df"

    assert card_like_node_id in {node.node_id for node in graph.nodes}
    assert card_like_node_id in evidence_graph_json_text(graph)


def test_graph_persistence_accepts_card_like_digits_in_validated_source_references() -> None:
    card_like_digest = "cd18620ee20204105499754aa35d7ff45d9c37483cfb06df8ab3b461571d7993"
    graph = _evaluation_graph_with_reference(card_like_digest)

    assert card_like_digest in evidence_graph_json_text(graph)


def test_graph_persistence_scans_card_like_digests_in_non_digest_references() -> None:
    card_like_digest = "cd18620ee20204105499754aa35d7ff45d9c37483cfb06df8ab3b461571d7993"
    graph = _evaluation_graph_with_reference(
        card_like_digest,
        role=EvidenceGraphReferenceRole.diagnostic,
    )

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


def test_graph_persistence_rejects_card_numbers_disguised_as_source_references() -> None:
    graph = _evaluation_graph_with_reference("4111111111111111")

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


def test_graph_persistence_still_rejects_card_numbers_in_human_identifiers() -> None:
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="4111111111111111",
            subject_digest="a" * 64,
        )
    )

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


def test_graph_persistence_revalidates_forged_model_copies() -> None:
    graph = _subject_only_graph()
    forged = graph.model_copy(update={"graph_digest": "f" * 64})

    with pytest.raises(ValueError, match="model validation"):
        evidence_graph_json_text(forged)


def test_oversized_graph_is_rejected_before_destination_side_effects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    graph = _subject_only_graph()
    destination = tmp_path / "not-created" / "assurance-evidence-graph.json"
    monkeypatch.setattr(graph_reporting, "MAX_ARTIFACT_JSON_BYTES", 1)

    with pytest.raises(ValueError, match="byte limit"):
        write_evidence_graph(graph, destination)

    assert not destination.parent.exists()
