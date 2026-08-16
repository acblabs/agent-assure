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
from agent_assure.schema.graph import AssuranceEvidenceGraph, EvidenceGraphSubjectPayload


def _subject_only_graph() -> AssuranceEvidenceGraph:
    return build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="graph-reporting-runset",
            subject_digest="a" * 64,
        )
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
        ),
        evaluation=evaluation,
    )

    with pytest.raises(ValueError, match="privacy-filtered"):
        evidence_graph_json_text(graph)


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
