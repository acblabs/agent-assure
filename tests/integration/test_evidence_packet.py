from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.reporting.packet import build_evidence_packet
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest

RUNNER = CliRunner()


def test_evidence_packet_schema_exists() -> None:
    packet = EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id="packet-001",
        evaluation=EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="runset-001",
            state=GateState.not_evaluated,
        ),
        comparison=ComparisonSummary(
            artifact_kind="comparison-summary",
            baseline_runset_id="baseline",
            candidate_runset_id="candidate",
            classification=ComparisonClassification.provenance_only_change,
        ),
        interpretation=("read candidate state first",),
        artifact_digests=(
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="evaluation-summary",
                sha256="0" * 64,
            ),
        ),
        limitations=("packet summarizes deterministic fixture-mode evidence",),
    )
    assert packet.schema_version == SCHEMA_VERSION


def test_packet_build_cli_writes_digested_packet_and_ci_gate_fails_it(tmp_path: Path) -> None:
    evaluation = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate",
        state=GateState.fail,
    )
    comparison = ComparisonSummary(
        artifact_kind="comparison-summary",
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        classification=ComparisonClassification.new_failure,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.fail,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    comparison_path = tmp_path / "comparison-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    _write_json(comparison_path, comparison.model_dump(mode="json"))

    result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--comparison",
            str(comparison_path),
            "--out",
            str(packet_path),
        ],
    )

    assert result.exit_code == 0, result.output
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    assert packet["artifact_kind"] == "evidence-packet"
    assert packet["interpretation"]
    assert packet["evaluation"]["state"] == GateState.fail.value
    assert packet["comparison"]["classification"] == ComparisonClassification.new_failure.value
    assert packet["environment"]["artifact_kind"] == "environment-info"
    assert "python_executable" not in packet["environment"]
    assert packet["release_manifest"]["artifact_kind"] == "release-artifact-manifest"
    assert packet["artifact_digests"] == [
        {
            "artifact_kind": "packet-artifact-digest",
            "role": "evaluation-summary",
            "schema_version": SCHEMA_VERSION,
            "sha256": _file_sha256(evaluation_path),
        },
        {
            "artifact_kind": "packet-artifact-digest",
            "role": "comparison-summary",
            "schema_version": SCHEMA_VERSION,
            "sha256": _file_sha256(comparison_path),
        },
    ]
    assert b"\r\n" not in packet_path.read_bytes()
    assert (tmp_path / "evidence-packet.md").exists()
    assert (tmp_path / "dependency-inventory.json").exists()
    assert (tmp_path / "release-artifact-manifest.json").exists()

    gate = RUNNER.invoke(app, ["ci", "gate", str(packet_path)])
    assert gate.exit_code == 1, gate.output


def test_packet_id_excludes_local_environment_and_exact_file_digests() -> None:
    evaluation = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate",
        state=GateState.pass_,
        environment=EnvironmentInfo(
            artifact_kind="environment-info",
            platform="Linux",
            python_version="3.11.0",
            dependency_inventory_digest="0" * 64,
        ),
    )
    first = build_evidence_packet(
        evaluation,
        artifact_digests=(
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="evaluation-summary",
                sha256="1" * 64,
            ),
        ),
    )
    second = build_evidence_packet(
        evaluation.model_copy(
            update={
                "environment": EnvironmentInfo(
                    artifact_kind="environment-info",
                    platform="Windows",
                    python_version="3.14.0",
                    git_dirty=True,
                    dependency_inventory_digest="2" * 64,
                )
            }
        ),
        artifact_digests=(
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="evaluation-summary",
                sha256="3" * 64,
            ),
        ),
    )

    assert first.packet_id == second.packet_id


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
