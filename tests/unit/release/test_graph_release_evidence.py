from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.graph.builder import build_evidence_graph
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.release_evidence import build_digest_replay, verify_digest_replay
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.graph import (
    EvidenceGraphSubjectPayload,
    calculate_evidence_graph_digest,
)
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest

_GRAPH_ROLE = "assurance-evidence-graph"
_REPLAY_ROLES = (
    _GRAPH_ROLE,
    "evidence-packet",
    "release-artifact-manifest",
)


def test_graph_bound_release_replay_ignores_nested_source_environment_drift(
    tmp_path: Path,
) -> None:
    first_graph_digest = _write_graph_bound_bundle(tmp_path, platform="environment-a")
    artifacts = _replay_artifacts(tmp_path)
    replay = build_digest_replay(artifacts, project_root=tmp_path, source_commit="abc123")
    first_raw_graph_digest = _file_digest(tmp_path / "assurance-evidence-graph.json")

    second_graph_digest = _write_graph_bound_bundle(tmp_path, platform="environment-b")

    assert second_graph_digest != first_graph_digest
    assert _file_digest(tmp_path / "assurance-evidence-graph.json") != first_raw_graph_digest
    assert {artifact.digest_mode for artifact in replay.artifacts} == {"replay-stable-json-sha256"}
    assert verify_digest_replay(replay, artifact_root=tmp_path).ok


def test_graph_bound_release_replay_still_detects_semantic_graph_drift(
    tmp_path: Path,
) -> None:
    _write_graph_bound_bundle(
        tmp_path,
        platform="same-environment",
        runset_id="candidate-a",
    )
    replay = build_digest_replay(
        _replay_artifacts(tmp_path),
        project_root=tmp_path,
        source_commit="abc123",
    )

    _write_graph_bound_bundle(
        tmp_path,
        platform="same-environment",
        runset_id="candidate-b",
    )
    verification = verify_digest_replay(replay, artifact_root=tmp_path)

    assert not verification.ok
    assert {finding.role for finding in verification.findings} == set(_REPLAY_ROLES)


def test_frozen_v063_graph_replay_enforces_self_digest_and_relations(
    tmp_path: Path,
) -> None:
    _write_graph_bound_bundle(tmp_path, platform="frozen-v063")
    graph_path = tmp_path / "assurance-evidence-graph.json"
    payload = cast(
        dict[str, object],
        json.loads(graph_path.read_text(encoding="utf-8")),
    )
    payload["schema_version"] = "0.6.3"
    projection = {key: value for key, value in payload.items() if key != "graph_digest"}
    payload["graph_digest"] = calculate_evidence_graph_digest(projection)
    _write_json(graph_path, payload)

    replay = build_digest_replay(
        ((_GRAPH_ROLE, graph_path),),
        project_root=tmp_path,
    )
    assert verify_digest_replay(
        replay,
        artifact_root=tmp_path,
        required_roles=(_GRAPH_ROLE,),
    ).ok

    wrong_digest = deepcopy(payload)
    wrong_digest["graph_digest"] = "0" * 64
    _write_json(graph_path, wrong_digest)
    with pytest.raises(ValueError, match="failed model validation"):
        build_digest_replay(
            ((_GRAPH_ROLE, graph_path),),
            project_root=tmp_path,
        )

    broken_relation = deepcopy(payload)
    edges = cast(list[dict[str, object]], broken_relation["edges"])
    scoped_index = next(index for index, edge in enumerate(edges) if edge["kind"] == "scoped_to")
    edges.pop(scoped_index)
    broken_projection = {
        key: value for key, value in broken_relation.items() if key != "graph_digest"
    }
    broken_relation["graph_digest"] = sha256_hexdigest(broken_projection)
    _write_json(graph_path, broken_relation)
    with pytest.raises(ValueError, match="failed model validation"):
        build_digest_replay(
            ((_GRAPH_ROLE, graph_path),),
            project_root=tmp_path,
        )


def _write_graph_bound_bundle(
    root: Path,
    *,
    platform: str,
    runset_id: str = "candidate",
) -> str:
    candidate_runset_digest = sha256_hexdigest({"runset_id": runset_id})
    environment = EnvironmentInfo(
        platform=platform,
        python_version="3.13",
    )
    evaluation = EvaluationSummary(
        runset_id=runset_id,
        runset_digest=candidate_runset_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
        environment=environment,
    )
    evaluation_path = root / "evaluation-summary.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id=runset_id,
        baseline_runset_digest="b" * 64,
        candidate_runset_digest=candidate_runset_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.pass_,
        environment=environment,
    )
    comparison_path = root / "comparison-summary.json"
    _write_json(comparison_path, comparison.model_dump(mode="json"))

    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=runset_id,
            subject_digest=candidate_runset_digest,
        ),
        evaluation=evaluation,
        comparison=comparison,
    )
    graph_path = root / "assurance-evidence-graph.json"
    _write_json(graph_path, graph.model_dump(mode="json"))

    evaluation_digest = _file_digest(evaluation_path)
    comparison_digest = _file_digest(comparison_path)
    graph_file_digest = _file_digest(graph_path)
    manifest = ReleaseArtifactManifest(
        manifest_id="graph-bound-release-manifest",
        environment=environment,
        artifacts=(
            ReleaseArtifact(
                role="evaluation-summary",
                path=evaluation_path.name,
                sha256=evaluation_digest,
            ),
            ReleaseArtifact(
                role="comparison-summary",
                path=comparison_path.name,
                sha256=comparison_digest,
            ),
            ReleaseArtifact(
                role=_GRAPH_ROLE,
                path=graph_path.name,
                sha256=graph_file_digest,
            ),
        ),
    )
    manifest_path = root / "release-artifact-manifest.json"
    _write_json(manifest_path, manifest.model_dump(mode="json"))

    packet = EvidencePacket(
        packet_id="graph-bound-release-packet",
        interpretation=("Read the candidate state before interpreting evidence.",),
        evaluation=evaluation,
        comparison=comparison,
        environment=environment,
        release_manifest=manifest,
        evidence_graph_digest=graph.graph_digest,
        artifact_digests=(
            PacketArtifactDigest(
                role="evaluation-summary",
                sha256=evaluation_digest,
            ),
            PacketArtifactDigest(
                role="comparison-summary",
                sha256=comparison_digest,
            ),
            PacketArtifactDigest(
                role=_GRAPH_ROLE,
                sha256=graph_file_digest,
            ),
        ),
        limitations=("Synthetic release replay fixture.",),
    )
    _write_json(root / "evidence-packet.json", packet.model_dump(mode="json"))
    return graph.graph_digest


def _replay_artifacts(root: Path) -> tuple[tuple[str, Path], ...]:
    return (
        (_GRAPH_ROLE, root / "assurance-evidence-graph.json"),
        ("evidence-packet", root / "evidence-packet.json"),
        ("release-artifact-manifest", root / "release-artifact-manifest.json"),
    )


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
