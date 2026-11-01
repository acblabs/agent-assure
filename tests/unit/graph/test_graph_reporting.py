from __future__ import annotations

import json
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
    EvidenceGraphEdge,
    EvidenceGraphEdgeKind,
    EvidenceGraphEvidencePayload,
    EvidenceGraphEvidenceType,
    EvidenceGraphFindingPayload,
    EvidenceGraphFindingType,
    EvidenceGraphNode,
    EvidenceGraphNodeKind,
    EvidenceGraphReference,
    EvidenceGraphReferenceRole,
    EvidenceGraphSubjectPayload,
)
from agent_assure.schema.mutation import EvidenceEvaluationBasis, EvidenceState

_CARD_LIKE_MUTATION_DIGEST = "2f0a75cc3e0a2aa2093465386277bf617e3b9a3199b661366fd1b4d1a242f035"


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


def _mutation_digest_graph(
    *,
    source_id: str = _CARD_LIKE_MUTATION_DIGEST,
    source_digest: str = _CARD_LIKE_MUTATION_DIGEST,
    source_artifact_kind: str = "assurance-mutation-result",
    evidence_type: EvidenceGraphEvidenceType = EvidenceGraphEvidenceType.mutation_result,
    references: tuple[EvidenceGraphReference, ...] = (),
    limitations: tuple[str, ...] = (),
    subject_id: str = "graph-reporting-runset",
) -> AssuranceEvidenceGraph:
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=subject_id,
            subject_digest="a" * 64,
        )
    )
    is_mutation = evidence_type is EvidenceGraphEvidenceType.mutation_result
    node = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=EvidenceGraphEvidencePayload(
            evidence_type=evidence_type,
            source_artifact_kind=source_artifact_kind,
            source_id=source_id,
            source_digest=source_digest,
            state=EvidenceState.error if is_mutation else EvidenceState.inconclusive,
            verdict_bearing=False,
            evaluation_basis=EvidenceEvaluationBasis.deterministic if is_mutation else None,
            references=references,
            limitations=limitations,
        ),
        subject_node_id=graph.primary_subject_node_id,
    )
    nodes = [*graph.nodes, node]
    edges = [
        EvidenceGraphEdge(
            kind=EvidenceGraphEdgeKind.scoped_to,
            source_node_id=node.node_id,
            target_node_id=graph.primary_subject_node_id,
        ),
    ]
    if is_mutation:
        outcome = EvidenceGraphNode.build(
            kind=EvidenceGraphNodeKind.finding,
            payload=EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.mutation_result,
                source_artifact_kind=source_artifact_kind,
                source_id="drop-material-evidence-link:outcome",
                source_path="/state",
                state=EvidenceState.error,
                verdict_bearing=False,
                reason_codes=("MUTATION_EXECUTION_ERROR",),
            ),
            subject_node_id=graph.primary_subject_node_id,
            parent_evidence_node_id=node.node_id,
        )
        nodes.append(outcome)
        edges.extend(
            (
                EvidenceGraphEdge(
                    kind=EvidenceGraphEdgeKind.derived_from,
                    source_node_id=outcome.node_id,
                    target_node_id=node.node_id,
                ),
                EvidenceGraphEdge(
                    kind=EvidenceGraphEdgeKind.scoped_to,
                    source_node_id=outcome.node_id,
                    target_node_id=graph.primary_subject_node_id,
                ),
            )
        )
    return AssuranceEvidenceGraph.from_parts(
        primary_subject_node_id=graph.primary_subject_node_id,
        nodes=tuple(nodes),
        edges=tuple(edges),
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


def test_mutation_digest_aliases_round_trip_without_changing_graph_identity(tmp_path: Path) -> None:
    graph = _mutation_digest_graph()
    before = graph.model_dump(mode="json")
    path = tmp_path / "mutation-evidence-graph.json"

    write_evidence_graph(graph, path)

    assert path.read_text(encoding="utf-8") == json.dumps(before, indent=2, sort_keys=True) + "\n"
    loaded = load_evidence_graph(path)
    assert loaded == graph
    assert loaded.graph_digest == graph.graph_digest
    assert tuple(node.node_id for node in loaded.nodes) == tuple(
        node.node_id for node in graph.nodes
    )
    evidence_node = next(
        node for node in loaded.nodes if node.kind is EvidenceGraphNodeKind.evidence
    )
    assert isinstance(evidence_node.payload, EvidenceGraphEvidencePayload)
    assert (
        evidence_node.payload.source_id
        == evidence_node.payload.source_digest
        == (_CARD_LIKE_MUTATION_DIGEST)
    )
    assert evidence_node.identity.model_dump(mode="json")["source_id"] == _CARD_LIKE_MUTATION_DIGEST
    assert graph.model_dump(mode="json") == before


@pytest.mark.parametrize(
    ("source_id", "source_digest", "source_artifact_kind", "evidence_type"),
    [
        (
            _CARD_LIKE_MUTATION_DIGEST,
            "b" * 64,
            "assurance-mutation-result",
            EvidenceGraphEvidenceType.mutation_result,
        ),
        (
            _CARD_LIKE_MUTATION_DIGEST,
            _CARD_LIKE_MUTATION_DIGEST,
            "evaluation-summary",
            EvidenceGraphEvidenceType.mutation_result,
        ),
        (
            _CARD_LIKE_MUTATION_DIGEST,
            _CARD_LIKE_MUTATION_DIGEST,
            "assurance-mutation-result",
            EvidenceGraphEvidenceType.gate_profile,
        ),
        (
            "4111111111111111",
            _CARD_LIKE_MUTATION_DIGEST,
            "assurance-mutation-result",
            EvidenceGraphEvidenceType.mutation_result,
        ),
    ],
    ids=("different-digest", "different-artifact", "different-evidence-role", "card-number"),
)
def test_mutation_source_ids_remain_scanned_without_complete_digest_context(
    source_id: str,
    source_digest: str,
    source_artifact_kind: str,
    evidence_type: EvidenceGraphEvidenceType,
) -> None:
    graph = _mutation_digest_graph(
        source_id=source_id,
        source_digest=source_digest,
        source_artifact_kind=source_artifact_kind,
        evidence_type=evidence_type,
    )

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


@pytest.mark.parametrize("source_id", [_CARD_LIKE_MUTATION_DIGEST.upper(), "4111111111111111"])
def test_digest_alias_review_requires_complete_lowercase_sha256_grammar(source_id: str) -> None:
    # Isolate the review policy even for a forged payload that the public schema
    # would reject first. Consistent aliases alone cannot excuse a non-digest.
    payload = _mutation_digest_graph().model_dump(mode="json")
    node = next(node for node in payload["nodes"] if node["kind"] == "evidence")
    node["identity"]["source_id"] = source_id
    node["payload"]["source_id"] = source_id
    node["payload"]["source_digest"] = source_id

    review = graph_reporting._privacy_review_projection(payload)

    assert isinstance(review, dict)
    reviewed_node = next(node for node in review["nodes"] if node["kind"] == "evidence")
    assert reviewed_node["identity"]["source_id"] == source_id
    assert reviewed_node["payload"]["source_id"] == source_id


def test_digest_alias_exemption_is_limited_to_graph_root_nodes() -> None:
    # A node-shaped object elsewhere cannot borrow the graph node exemption.
    # Sharing the input object also checks that projection never mutates it.
    payload = _mutation_digest_graph().model_dump(mode="json")
    node = next(node for node in payload["nodes"] if node["kind"] == "evidence")
    payload["diagnostic"] = node

    review = graph_reporting._privacy_review_projection(payload)

    diagnostic = review["diagnostic"]
    assert isinstance(diagnostic, dict)
    assert diagnostic["identity"]["source_id"] == _CARD_LIKE_MUTATION_DIGEST
    assert diagnostic["payload"]["source_id"] == _CARD_LIKE_MUTATION_DIGEST
    reviewed_node = next(node for node in review["nodes"] if node["kind"] == "evidence")
    assert reviewed_node["payload"]["source_id"] != _CARD_LIKE_MUTATION_DIGEST
    assert node["payload"]["source_id"] == _CARD_LIKE_MUTATION_DIGEST


@pytest.mark.parametrize("sensitive", ["alice@example.com", "4111111111111111"])
def test_digest_alias_exemption_still_rejects_real_pii_without_writing(
    sensitive: str, tmp_path: Path
) -> None:
    graph = _mutation_digest_graph(limitations=(sensitive,))
    destination = tmp_path / "not-created" / "mutation-evidence-graph.json"

    with pytest.raises(ValueError, match="privacy-filtered"):
        write_evidence_graph(graph, destination)

    assert not destination.parent.exists()


def test_mutation_digest_alias_is_still_scanned_in_human_identifiers() -> None:
    graph = _mutation_digest_graph(subject_id=_CARD_LIKE_MUTATION_DIGEST)

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


def test_mutation_digest_alias_is_still_scanned_in_diagnostic_references() -> None:
    graph = _mutation_digest_graph(
        references=(
            EvidenceGraphReference(
                role=EvidenceGraphReferenceRole.diagnostic,
                value=_CARD_LIKE_MUTATION_DIGEST,
            ),
        )
    )

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


def test_mutation_digest_alias_cannot_bypass_forged_identity_validation(tmp_path: Path) -> None:
    graph = _mutation_digest_graph()
    node = next(node for node in graph.nodes if node.kind is EvidenceGraphNodeKind.evidence)
    forged_identity = node.identity.model_copy(update={"source_id": "b" * 64})
    forged_node = node.model_copy(update={"identity": forged_identity})
    forged_graph = graph.model_copy(
        update={"nodes": tuple(forged_node if item is node else item for item in graph.nodes)}
    )
    destination = tmp_path / "not-created" / "mutation-evidence-graph.json"

    with pytest.raises(ValueError, match="model validation"):
        write_evidence_graph(forged_graph, destination)

    assert not destination.parent.exists()


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
