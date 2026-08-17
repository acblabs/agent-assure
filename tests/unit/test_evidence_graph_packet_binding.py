from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

import agent_assure.reporting.packet as packet_reporting
from agent_assure.graph.builder import build_evidence_graph
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.reporting.graph import write_evidence_graph
from agent_assure.reporting.packet import (
    DEFAULT_PACKET_LIMITATIONS,
    build_evidence_packet,
    build_privacy_filtered_evidence_graph,
    packet_summary_files_binding_error,
    packet_summary_files_binding_error_for_trusted_publication,
    render_evidence_packet_markdown,
)
from agent_assure.schema.common import GateState
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.graph import EvidenceGraphSubjectPayload
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest


def test_graph_binding_is_optional_but_fails_closed_when_declared() -> None:
    evaluation = _evaluation()
    evaluation_digest = PacketArtifactDigest(role="evaluation-summary", sha256="1" * 64)
    graph_file_digest = PacketArtifactDigest(
        role="assurance-evidence-graph",
        sha256="2" * 64,
    )

    graphless = build_evidence_packet(
        evaluation,
        artifact_digests=(evaluation_digest,),
    )
    assert graphless.evidence_graph_digest is None
    assert "## Evidence Graph" not in render_evidence_packet_markdown(graphless)

    with pytest.raises(ValidationError, match="evidence_graph_digest presence"):
        build_evidence_packet(
            evaluation,
            evidence_graph_digest="3" * 64,
            artifact_digests=(evaluation_digest,),
        )
    with pytest.raises(ValidationError, match="evidence_graph_digest presence"):
        build_evidence_packet(
            evaluation,
            artifact_digests=(evaluation_digest, graph_file_digest),
        )

    bound = build_evidence_packet(
        evaluation,
        evidence_graph_digest="3" * 64,
        artifact_digests=(evaluation_digest, graph_file_digest),
    )
    same_semantics_different_file = build_evidence_packet(
        evaluation,
        evidence_graph_digest="3" * 64,
        artifact_digests=(
            evaluation_digest,
            graph_file_digest.model_copy(update={"sha256": "4" * 64}),
        ),
    )
    different_semantics = build_evidence_packet(
        evaluation,
        evidence_graph_digest="5" * 64,
        artifact_digests=(evaluation_digest, graph_file_digest),
    )

    assert bound.packet_id == same_semantics_different_file.packet_id
    assert bound.packet_id != different_semantics.packet_id
    markdown = render_evidence_packet_markdown(bound)
    assert "## Evidence Graph" in markdown
    assert "AssuranceEvidenceGraph/v1" in markdown
    assert "3" * 64 in markdown
    assert "2" * 64 in markdown


def test_shared_graph_projection_applies_mandatory_packet_privacy_filter() -> None:
    evaluation = _evaluation().model_copy(
        update={
            "environment": EnvironmentInfo(
                platform="api_key=abcdef1234567890",
                python_version="3.14",
            )
        }
    )
    filtered_evaluation = EvaluationSummary.model_validate(
        redact_packet_payload(evaluation.model_dump(mode="json"))
    )

    graph = build_privacy_filtered_evidence_graph(
        evaluation,
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )
    expected = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=filtered_evaluation.runset_id,
        ),
        evaluation=filtered_evaluation,
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )
    unfiltered = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=evaluation.runset_id,
        ),
        evaluation=evaluation,
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )

    assert graph == expected
    assert graph.graph_digest != unfiltered.graph_digest


def test_graph_binding_verifies_manifest_bytes_and_semantic_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = _evaluation()
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=evaluation.runset_id,
        ),
        evaluation=evaluation,
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"
    evaluation_path.write_text(
        json.dumps(evaluation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_evidence_graph(graph, graph_path)
    evaluation_sha = _sha256(evaluation_path)
    graph_sha = _sha256(graph_path)
    manifest = ReleaseArtifactManifest(
        manifest_id="graph-bound-packet",
        artifacts=(
            ReleaseArtifact(
                role="evaluation-summary",
                path=evaluation_path.name,
                sha256=evaluation_sha,
            ),
            ReleaseArtifact(
                role="assurance-evidence-graph",
                path=graph_path.name,
                sha256=graph_sha,
            ),
        ),
        environment=EnvironmentInfo(platform="test", python_version="3.14"),
    )
    packet = build_evidence_packet(
        evaluation,
        release_manifest=manifest,
        evidence_graph_digest=graph.graph_digest,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256=evaluation_sha),
            PacketArtifactDigest(role="assurance-evidence-graph", sha256=graph_sha),
        ),
    )

    def fail_rebuild(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the supplied graph must avoid a redundant projection rebuild")

    monkeypatch.setattr(
        packet_reporting,
        "build_privacy_filtered_evidence_graph",
        fail_rebuild,
    )
    assert (
        packet_summary_files_binding_error_for_trusted_publication(
            packet,
            artifact_root=tmp_path,
            expected_graph=graph,
        )
        is None
    )

    legacy_missing_manifest_role = packet.model_copy(
        update={
            "schema_version": "0.6.2",
            "release_manifest": manifest.model_copy(update={"artifacts": ()}),
        }
    )
    assert (
        packet_summary_files_binding_error(
            legacy_missing_manifest_role,
            artifact_root=tmp_path,
        )
        == "evidence packet evaluation-summary is missing from release manifest"
    )

    semantic_mismatch = packet.model_copy(update={"evidence_graph_digest": "f" * 64})
    assert packet_summary_files_binding_error(
        semantic_mismatch,
        artifact_root=tmp_path,
    ) == (
        "evidence packet assurance-evidence-graph semantic digest does not match "
        "evidence_graph_digest"
    )

    graph_path.write_bytes(graph_path.read_bytes() + b" ")
    assert packet_summary_files_binding_error_for_trusted_publication(
        packet,
        artifact_root=tmp_path,
        expected_graph=graph,
    ) == (
        "evidence packet assurance-evidence-graph source file digest does not match "
        "release manifest"
    )


def test_public_graph_binding_reconstructs_and_rejects_unrelated_valid_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = _evaluation()
    unrelated = evaluation.model_copy(update={"runset_id": "unrelated-candidate"})
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=unrelated.runset_id,
        ),
        evaluation=unrelated,
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"
    evaluation_path.write_text(
        json.dumps(evaluation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    write_evidence_graph(graph, graph_path)
    evaluation_sha = _sha256(evaluation_path)
    graph_sha = _sha256(graph_path)
    manifest = ReleaseArtifactManifest(
        manifest_id="unrelated-valid-graph",
        artifacts=(
            ReleaseArtifact(
                role="evaluation-summary",
                path=evaluation_path.name,
                sha256=evaluation_sha,
            ),
            ReleaseArtifact(
                role="assurance-evidence-graph",
                path=graph_path.name,
                sha256=graph_sha,
            ),
        ),
        environment=EnvironmentInfo(platform="test", python_version="3.14"),
    )
    packet = build_evidence_packet(
        evaluation,
        release_manifest=manifest,
        evidence_graph_digest=graph.graph_digest,
        artifact_digests=(
            PacketArtifactDigest(
                role="evaluation-summary",
                sha256=evaluation_sha,
            ),
            PacketArtifactDigest(
                role="assurance-evidence-graph",
                sha256=graph_sha,
            ),
        ),
    )

    rebuild = Mock(wraps=packet_reporting.build_privacy_filtered_evidence_graph)
    monkeypatch.setattr(
        packet_reporting,
        "build_privacy_filtered_evidence_graph",
        rebuild,
    )
    assert packet_summary_files_binding_error(
        packet,
        artifact_root=tmp_path,
    ) == ("evidence packet assurance-evidence-graph does not correspond to nested packet evidence")
    rebuild.assert_called_once()


def test_graph_release_manifest_role_and_raw_digest_are_exact() -> None:
    evaluation = _evaluation()
    evaluation_artifact = ReleaseArtifact(
        role="evaluation-summary",
        path="evaluation-summary.json",
        sha256="1" * 64,
    )
    graph_artifact = ReleaseArtifact(
        role="assurance-evidence-graph",
        path="assurance-evidence-graph.json",
        sha256="2" * 64,
    )
    manifest = ReleaseArtifactManifest(
        manifest_id="graph-bound-packet",
        artifacts=(evaluation_artifact, graph_artifact),
        environment=EnvironmentInfo(platform="test", python_version="3.14"),
    )
    digests = (
        PacketArtifactDigest(role="evaluation-summary", sha256="1" * 64),
        PacketArtifactDigest(role="assurance-evidence-graph", sha256="2" * 64),
    )

    packet = build_evidence_packet(
        evaluation,
        release_manifest=manifest,
        evidence_graph_digest="3" * 64,
        artifact_digests=digests,
    )
    assert EvidencePacket.model_validate(packet.model_dump(mode="json")) == packet

    with pytest.raises(ValidationError, match="artifact must match evidence_graph_digest presence"):
        build_evidence_packet(
            evaluation,
            release_manifest=manifest.model_copy(update={"artifacts": (evaluation_artifact,)}),
            evidence_graph_digest="3" * 64,
            artifact_digests=digests,
        )
    with pytest.raises(ValidationError, match="digest must match release manifest"):
        build_evidence_packet(
            evaluation,
            release_manifest=manifest.model_copy(
                update={
                    "artifacts": (
                        evaluation_artifact,
                        graph_artifact.model_copy(update={"sha256": "4" * 64}),
                    )
                }
            ),
            evidence_graph_digest="3" * 64,
            artifact_digests=digests,
        )


def _evaluation() -> EvaluationSummary:
    return EvaluationSummary(
        runset_id="packet-graph-candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
