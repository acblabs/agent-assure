from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

import agent_assure.cli.packet_cmd as packet_cmd
import agent_assure.onboarding.path_safety as path_safety
import agent_assure.reporting.environment as environment_reporting
import agent_assure.reporting.packet as packet_reporting
from agent_assure.ci import (
    GateOutcome,
    gate_evidence_packet,
    gate_evidence_sensitivity_report,
)
from agent_assure.cli.main import app
from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES, BoundedFileContents
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.rag.sensitivity import (
    execute_sensitivity_experiment,
    load_sensitivity_corpus,
)
from agent_assure.release_evidence import build_digest_replay, verify_digest_replay
from agent_assure.reporting.packet import (
    DEFAULT_PACKET_LIMITATIONS,
    build_evidence_packet,
    build_privacy_filtered_evidence_graph,
    load_evaluation_summary_snapshot,
    load_evidence_packet,
    packet_artifact_digest_from_snapshot,
    packet_summary_files_binding_error,
    packet_summary_snapshots_binding_error,
    release_artifact_from_summary_snapshot,
    render_evidence_packet_markdown,
)
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.sensitivity import (
    DetectorTestStatus,
    EvidenceSensitivityExpectedRelation,
    EvidenceSensitivityGateEffect,
    EvidenceSensitivityOutcomeClassification,
    EvidenceSensitivityReasonCode,
    EvidenceSensitivityState,
    RAGSensitivityCorpusManifest,
    RAGSensitivityKnowledgeContract,
    RAGSensitivityReport,
    RAGSensitivitySyntheticDataAttestation,
)
from agent_assure.sensitivity_comparison import derive_sensitivity_comparison
from tests.unit.controls.test_control_efficacy import _DROP_OPERATOR, _campaign
from tests.unit.reporting.test_packet_stochastic import (
    _evaluation as _stochastic_evaluation,
)
from tests.unit.reporting.test_packet_stochastic import _reports as _stochastic_reports

RUNNER = CliRunner()


def test_evidence_packet_schema_exists() -> None:
    packet = EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id="packet-001",
        evaluation=EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="runset-001",
            runset_digest="c" * 64,
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.not_evaluated,
        ),
        comparison=ComparisonSummary(
            artifact_kind="comparison-summary",
            baseline_runset_id="baseline",
            candidate_runset_id="runset-001",
            baseline_runset_digest="b" * 64,
            candidate_runset_digest="c" * 64,
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            classification=ComparisonClassification.provenance_only_change,
        ),
        interpretation=("read candidate state first",),
        artifact_digests=(
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="evaluation-summary",
                sha256="0" * 64,
            ),
            PacketArtifactDigest(
                artifact_kind="packet-artifact-digest",
                role="comparison-summary",
                sha256="1" * 64,
            ),
        ),
        limitations=("packet summarizes deterministic fixture-mode evidence",),
    )
    assert packet.schema_version == SCHEMA_VERSION


def test_packet_markdown_revalidates_model_copy_and_privacy_payload() -> None:
    evaluation = EvaluationSummary(
        runset_id="renderer-candidate",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    packet = build_evidence_packet(
        evaluation,
        artifact_digests=(PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64),),
    )
    tampered = packet.model_copy(
        update={"evaluation": evaluation.model_copy(update={"runset_id": ""})}
    )
    unsafe = packet.model_copy(update={"interpretation": ("contact reviewer@example.com",)})

    with pytest.raises(ValidationError):
        render_evidence_packet_markdown(tampered)
    rendered = render_evidence_packet_markdown(unsafe)
    assert "reviewer@example.com" not in rendered
    assert "REDACTED" in rendered


def test_packet_manifest_verifier_caps_entries_before_filesystem_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=False)
    (tmp_path / "evaluation-summary.json").unlink()

    monkeypatch.setattr(packet_reporting, "_MAX_RELEASE_MANIFEST_ARTIFACTS", 0)

    error = packet_summary_files_binding_error(packet, artifact_root=tmp_path)

    assert error == "evidence packet release manifest exceeds the artifact verification limit"


def test_packet_manifest_verifier_stops_at_aggregate_read_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=True)
    evaluation_size = (tmp_path / "evaluation-summary.json").stat().st_size
    (tmp_path / "auxiliary-review.txt").unlink()

    monkeypatch.setattr(
        packet_reporting,
        "_MAX_RELEASE_MANIFEST_TOTAL_BYTES",
        evaluation_size - 1,
    )

    error = packet_summary_files_binding_error(packet, artifact_root=tmp_path)

    assert error == "evidence packet release manifest exceeds the aggregate verification limit"


def test_packet_snapshot_and_path_manifest_verifiers_agree(tmp_path: Path) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=True)
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)

    path_error = packet_summary_files_binding_error(packet, artifact_root=tmp_path)
    snapshot_error = packet_summary_snapshots_binding_error(
        packet,
        snapshots_by_path=snapshots,
    )

    assert path_error is None
    assert snapshot_error == path_error


@pytest.mark.parametrize("role", ["evaluation-summary", "auxiliary-review"])
def test_packet_snapshot_verifier_checks_every_manifest_artifact_digest(
    tmp_path: Path,
    role: str,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=True)
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)
    assert packet.release_manifest is not None
    artifact = next(item for item in packet.release_manifest.artifacts if item.role == role)
    original = snapshots[artifact.path]
    corrupt_bytes = original.data + b"corruption"
    snapshots[artifact.path] = replace(
        original,
        data=corrupt_bytes,
        sha256=hashlib.sha256(corrupt_bytes).hexdigest(),
        size=len(corrupt_bytes),
    )

    error = packet_summary_snapshots_binding_error(
        packet,
        snapshots_by_path=snapshots,
    )

    assert error == (f"evidence packet {role} source file digest does not match release manifest")


def test_packet_snapshot_verifier_rejects_corrupt_snapshot_metadata(
    tmp_path: Path,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=False)
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)
    evaluation = snapshots["evaluation-summary.json"]
    snapshots["evaluation-summary.json"] = replace(
        evaluation,
        data=evaluation.data + b"corruption",
    )

    error = packet_summary_snapshots_binding_error(
        packet,
        snapshots_by_path=snapshots,
    )

    assert error == (
        "evidence packet evaluation-summary source snapshot metadata does not match exact bytes"
    )


def test_packet_snapshot_verifier_rejects_missing_and_extra_snapshots(
    tmp_path: Path,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=True)
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)
    missing = dict(snapshots)
    missing.pop("auxiliary-review.txt")
    extra = {
        **snapshots,
        "unmanifested-review.txt": snapshots["auxiliary-review.txt"],
    }

    missing_error = packet_summary_snapshots_binding_error(
        packet,
        snapshots_by_path=missing,
    )
    extra_error = packet_summary_snapshots_binding_error(
        packet,
        snapshots_by_path=extra,
    )

    assert missing_error == "evidence packet auxiliary-review source snapshot is missing"
    assert extra_error == "evidence packet artifact snapshots contain unmanifested paths"


def test_packet_snapshot_verifier_classifies_case_variant_extra_by_host(
    tmp_path: Path,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=True)
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)
    ambiguous = {
        **snapshots,
        "AUXILIARY-REVIEW.TXT": snapshots["auxiliary-review.txt"],
    }

    error = packet_summary_snapshots_binding_error(
        packet,
        snapshots_by_path=ambiguous,
    )

    expected = (
        "evidence packet artifact snapshots contain ambiguous paths"
        if os.path.normcase("A") == os.path.normcase("a")
        else "evidence packet artifact snapshots contain unmanifested paths"
    )
    assert error == expected


def test_packet_snapshot_verifier_revalidates_model_copy_tampering(
    tmp_path: Path,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=False)
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)
    tampered = packet.model_copy(
        update={
            "evaluation": packet.evaluation.model_copy(update={"runset_id": ""}),
        }
    )

    path_error = packet_summary_files_binding_error(tampered, artifact_root=tmp_path)
    snapshot_error = packet_summary_snapshots_binding_error(
        tampered,
        snapshots_by_path=snapshots,
    )

    assert path_error == "evidence packet failed trusted model revalidation"
    assert snapshot_error == path_error


def test_packet_snapshot_verifier_parses_summary_from_captured_bytes(
    tmp_path: Path,
) -> None:
    packet = _packet_with_release_manifest(tmp_path, include_auxiliary=False)
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)
    replacement = packet.evaluation.model_copy(update={"runset_id": "different-candidate"})
    replacement_bytes = (json.dumps(replacement.model_dump(mode="json"), indent=2) + "\n").encode()
    replacement_digest = hashlib.sha256(replacement_bytes).hexdigest()
    evaluation_snapshot = snapshots["evaluation-summary.json"]
    snapshots["evaluation-summary.json"] = replace(
        evaluation_snapshot,
        data=replacement_bytes,
        sha256=replacement_digest,
        size=len(replacement_bytes),
    )
    assert packet.release_manifest is not None
    rebound_manifest = packet.release_manifest.model_copy(
        update={
            "artifacts": tuple(
                artifact.model_copy(update={"sha256": replacement_digest})
                if artifact.role == "evaluation-summary"
                else artifact
                for artifact in packet.release_manifest.artifacts
            )
        }
    )
    rebound_packet = packet.model_copy(
        update={
            "release_manifest": rebound_manifest,
            "artifact_digests": (
                PacketArtifactDigest(
                    role="evaluation-summary",
                    sha256=replacement_digest,
                ),
            ),
        }
    )

    error = packet_summary_snapshots_binding_error(
        rebound_packet,
        snapshots_by_path=snapshots,
    )

    assert error == ("evidence packet evaluation-summary source file does not match nested summary")


def test_packet_snapshot_verifier_reconstructs_graph_from_nested_evidence(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="snapshot-graph-candidate",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    graph = build_privacy_filtered_evidence_graph(
        evaluation,
        limitations=DEFAULT_PACKET_LIMITATIONS,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    _write_json(graph_path, graph.model_dump(mode="json"))
    manifest = ReleaseArtifactManifest(
        manifest_id="snapshot-graph-manifest",
        artifacts=(
            ReleaseArtifact(
                role="evaluation-summary",
                path=evaluation_path.name,
                sha256=_file_sha256(evaluation_path),
            ),
            ReleaseArtifact(
                role="assurance-evidence-graph",
                path=graph_path.name,
                sha256=_file_sha256(graph_path),
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
                sha256=_file_sha256(evaluation_path),
            ),
            PacketArtifactDigest(
                role="assurance-evidence-graph",
                sha256=_file_sha256(graph_path),
            ),
        ),
    )
    snapshots = _manifest_file_snapshots(packet, root=tmp_path)
    assert (
        packet_summary_snapshots_binding_error(
            packet,
            snapshots_by_path=snapshots,
        )
        is None
    )

    replacement_graph = build_privacy_filtered_evidence_graph(
        evaluation,
        limitations=("different graph limitation",),
    )
    replacement_bytes = (
        json.dumps(replacement_graph.model_dump(mode="json"), indent=2) + "\n"
    ).encode()
    replacement_digest = hashlib.sha256(replacement_bytes).hexdigest()
    graph_snapshot = snapshots[graph_path.name]
    snapshots[graph_path.name] = replace(
        graph_snapshot,
        data=replacement_bytes,
        sha256=replacement_digest,
        size=len(replacement_bytes),
    )
    rebound_manifest = manifest.model_copy(
        update={
            "artifacts": tuple(
                artifact.model_copy(update={"sha256": replacement_digest})
                if artifact.role == "assurance-evidence-graph"
                else artifact
                for artifact in manifest.artifacts
            )
        }
    )
    rebound_packet = packet.model_copy(
        update={
            "release_manifest": rebound_manifest,
            "evidence_graph_digest": replacement_graph.graph_digest,
            "artifact_digests": tuple(
                artifact.model_copy(update={"sha256": replacement_digest})
                if artifact.role == "assurance-evidence-graph"
                else artifact
                for artifact in packet.artifact_digests
            ),
        }
    )

    error = packet_summary_snapshots_binding_error(
        rebound_packet,
        snapshots_by_path=snapshots,
    )

    assert error == (
        "evidence packet assurance-evidence-graph does not correspond to nested packet evidence"
    )


def test_evidence_packet_rejects_mismatched_privacy_detector_profiles() -> None:
    evaluation = EvaluationSummary(
        runset_id="candidate",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="b" * 64,
        candidate_runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest="f" * 64,
        classification=ComparisonClassification.unchanged,
    )

    with pytest.raises(ValidationError, match="same privacy detector profile"):
        EvidencePacket(
            packet_id="packet-mismatch",
            interpretation=(),
            evaluation=evaluation,
            comparison=comparison,
            artifact_digests=(
                PacketArtifactDigest(role="evaluation-summary", sha256="0" * 64),
                PacketArtifactDigest(role="comparison-summary", sha256="1" * 64),
            ),
            limitations=(),
        )


def test_evidence_packet_rejects_evaluation_for_a_different_candidate() -> None:
    evaluation = EvaluationSummary(
        runset_id="stale-candidate",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="b" * 64,
        candidate_runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
    )

    with pytest.raises(ValidationError, match="candidate_runset_id"):
        EvidencePacket(
            packet_id="packet-stale-candidate",
            interpretation=(),
            evaluation=evaluation,
            comparison=comparison,
            artifact_digests=(
                PacketArtifactDigest(role="evaluation-summary", sha256="0" * 64),
                PacketArtifactDigest(role="comparison-summary", sha256="1" * 64),
            ),
            limitations=(),
        )


def test_packet_build_load_and_gate_reject_contradictory_candidate_runset_digests(
    tmp_path: Path,
) -> None:
    candidate_digest = "a" * 64
    evaluation = EvaluationSummary(
        runset_id="candidate",
        runset_digest=candidate_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="b" * 64,
        candidate_runset_digest=candidate_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.pass_,
    )
    artifact_digests = (
        PacketArtifactDigest(role="evaluation-summary", sha256="0" * 64),
        PacketArtifactDigest(role="comparison-summary", sha256="1" * 64),
    )
    valid_packet = build_evidence_packet(
        evaluation,
        comparison=comparison,
        artifact_digests=artifact_digests,
    )
    contradictory = comparison.model_copy(update={"candidate_runset_digest": "c" * 64})

    with pytest.raises(ValidationError, match="candidate_runset_digest"):
        build_evidence_packet(
            evaluation,
            comparison=contradictory,
            artifact_digests=artifact_digests,
        )

    payload = valid_packet.model_dump(mode="json")
    nested_comparison = cast(dict[str, object], payload["comparison"])
    nested_comparison["candidate_runset_digest"] = "c" * 64
    packet_path = tmp_path / "contradictory-packet.json"
    _write_json(packet_path, payload)
    with pytest.raises(ValueError, match="evidence-packet artifact failed model validation"):
        load_evidence_packet(packet_path)

    unchecked = valid_packet.model_copy(update={"comparison": contradictory})
    decision = gate_evidence_packet(unchecked)
    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "candidate_runset_digest" in decision.message

    unbound_evaluation = evaluation.model_copy(update={"runset_digest": None})
    with pytest.raises(
        ValidationError,
        match="current evaluation summaries require an authenticated runset_digest",
    ):
        build_evidence_packet(
            unbound_evaluation,
            comparison=comparison,
            artifact_digests=artifact_digests,
        )


def test_packet_build_cli_writes_digested_packet_and_ci_gate_fails_it(tmp_path: Path) -> None:
    candidate_runset_digest = "c" * 64
    evaluation = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate",
        runset_digest=candidate_runset_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
    )
    comparison = ComparisonSummary(
        artifact_kind="comparison-summary",
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="b" * 64,
        candidate_runset_digest=candidate_runset_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.new_failure,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.fail,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    comparison_path = tmp_path / "comparison-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"
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
        terminal_width=32,
    )

    assert result.exit_code == 0, result.output
    assert f"evidence packet: {packet_path}" in result.output.splitlines()
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    assert packet["artifact_kind"] == "evidence-packet"
    assert packet["interpretation"]
    assert packet["evaluation"]["state"] == GateState.fail.value
    assert packet["comparison"]["classification"] == ComparisonClassification.new_failure.value
    assert packet["environment"]["artifact_kind"] == "environment-info"
    assert "python_executable" not in packet["environment"]
    assert packet["release_manifest"]["artifact_kind"] == "release-artifact-manifest"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    assert packet["evidence_graph_digest"] == graph["graph_digest"]
    assert packet["artifact_digests"] == [
        {
            "artifact_kind": "packet-artifact-digest",
            "role": "evaluation-summary",
            "schema_version": SCHEMA_VERSION,
            "sha256": _file_sha256(evaluation_path),
        },
        {
            "artifact_kind": "packet-artifact-digest",
            "role": "assurance-evidence-graph",
            "schema_version": SCHEMA_VERSION,
            "sha256": _file_sha256(graph_path),
        },
        {
            "artifact_kind": "packet-artifact-digest",
            "role": "comparison-summary",
            "schema_version": SCHEMA_VERSION,
            "sha256": _file_sha256(comparison_path),
        },
    ]
    manifest_by_role = {
        artifact["role"]: artifact for artifact in packet["release_manifest"]["artifacts"]
    }
    assert manifest_by_role["assurance-evidence-graph"] == {
        "artifact_kind": "release-artifact",
        "path": "assurance-evidence-graph.json",
        "role": "assurance-evidence-graph",
        "schema_version": SCHEMA_VERSION,
        "sha256": _file_sha256(graph_path),
    }
    assert b"\r\n" not in packet_path.read_bytes()
    assert b"\r\n" not in graph_path.read_bytes()
    assert (tmp_path / "evidence-packet.md").exists()
    assert (tmp_path / "dependency-inventory.json").exists()
    assert (tmp_path / "release-artifact-manifest.json").exists()

    gate = RUNNER.invoke(app, ["ci", "gate", str(packet_path)])
    assert gate.exit_code == 1, gate.output


def test_packet_build_cli_publishes_and_gates_stochastic_evidence_end_to_end(
    tmp_path: Path,
) -> None:
    inputs = _write_stochastic_packet_inputs(tmp_path)
    packet_path = tmp_path / "evidence-packet.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"

    built = RUNNER.invoke(
        app,
        _stochastic_packet_build_args(inputs, packet_path),
        terminal_width=240,
    )

    assert built.exit_code == 0, built.output
    packet = load_evidence_packet(packet_path)
    assert packet.statistical_sufficiency is not None
    assert packet.stochastic_evidence_sensitivity is not None
    assert packet.stochastic_evidence_sensitivity.state.value == "pass"
    assert packet_summary_files_binding_error(packet, artifact_root=tmp_path) is None
    assert packet.release_manifest is not None
    assert {artifact.role for artifact in packet.release_manifest.artifacts} >= {
        "statistical-sufficiency-report",
        "stochastic-evidence-sensitivity-report",
        "stochastic-baseline-source-runset",
        "stochastic-counterfactual-source-runset",
    }

    projected_path = tmp_path / "projected-stochastic-graph.json"
    projected = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(projected_path),
        ],
    )
    assert projected.exit_code == 0, projected.output
    assert projected_path.read_bytes() == graph_path.read_bytes()

    gated = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--artifact-root",
            str(tmp_path),
            "--require-stochastic-evidence-sensitivity",
        ],
    )
    assert gated.exit_code == 0, gated.output
    assert "stochastic_evidence_sensitivity=required state=pass" in gated.output


@pytest.mark.parametrize(
    "missing_option",
    (
        "--statistical-sufficiency",
        "--stochastic-evidence-sensitivity",
        "--stochastic-baseline-source-runset",
        "--stochastic-counterfactual-source-runset",
    ),
)
def test_packet_build_cli_rejects_partial_stochastic_inputs_before_publication(
    tmp_path: Path,
    missing_option: str,
) -> None:
    inputs = _write_stochastic_packet_inputs(tmp_path)
    packet_path = tmp_path / "evidence-packet.json"
    args = _stochastic_packet_build_args(inputs, packet_path)
    option_index = args.index(missing_option)
    del args[option_index : option_index + 2]

    result = RUNNER.invoke(app, args, terminal_width=240)

    assert result.exit_code == 2
    assert "must be provided together" in result.output
    assert not packet_path.exists()
    assert not (tmp_path / "assurance-evidence-graph.json").exists()
    assert not (tmp_path / "release-artifact-manifest.json").exists()


def test_packet_build_cli_rejects_mismatched_stochastic_source_runsets(
    tmp_path: Path,
) -> None:
    inputs = _write_stochastic_packet_inputs(tmp_path)
    packet_path = tmp_path / "evidence-packet.json"
    args = _stochastic_packet_build_args(inputs, packet_path)
    baseline_index = args.index("--stochastic-baseline-source-runset") + 1
    counterfactual_index = args.index("--stochastic-counterfactual-source-runset") + 1
    args[baseline_index], args[counterfactual_index] = (
        args[counterfactual_index],
        args[baseline_index],
    )

    result = RUNNER.invoke(app, args, terminal_width=240)

    assert result.exit_code == 2
    assert "stochastic source RunSets" in result.output
    assert not packet_path.exists()
    assert not (tmp_path / "assurance-evidence-graph.json").exists()
    assert not (tmp_path / "release-artifact-manifest.json").exists()


@pytest.mark.parametrize(
    ("source_key", "mutation_kind"),
    (
        ("baseline", "in_place"),
        ("baseline", "replacement"),
        ("counterfactual", "in_place"),
        ("counterfactual", "replacement"),
    ),
)
def test_packet_build_rejects_stochastic_source_change_during_snapshot_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_key: str,
    mutation_kind: str,
) -> None:
    inputs = _write_stochastic_packet_inputs(tmp_path)
    target_path = inputs[source_key]
    packet_path = tmp_path / "evidence-packet.json"
    original_reader = path_safety.read_file_bounded_at
    target_reads = 0

    def mutate_after_descriptor_read(
        root: Path,
        relative_path: str | Path,
        **kwargs: object,
    ) -> BoundedFileContents:
        nonlocal target_reads
        contents = original_reader(root, relative_path, **kwargs)
        if (root / relative_path).absolute() == target_path.absolute():
            target_reads += 1
            _mutate_stochastic_source(target_path, mutation_kind)
        return contents

    monkeypatch.setattr(
        path_safety,
        "read_file_bounded_at",
        mutate_after_descriptor_read,
    )

    result = RUNNER.invoke(
        app,
        _stochastic_packet_build_args(inputs, packet_path),
        terminal_width=240,
    )

    assert result.exit_code == 2
    assert "changed path" in result.output
    assert "identity" in result.output
    assert "after it was read" in result.output
    assert target_reads == 1
    for owned_path in _packet_owned_output_paths(packet_path):
        assert not owned_path.exists()


@pytest.mark.parametrize(
    ("source_key", "mutation_kind"),
    (
        ("baseline", "in_place"),
        ("baseline", "replacement"),
        ("counterfactual", "in_place"),
        ("counterfactual", "replacement"),
    ),
)
def test_packet_build_revalidates_stochastic_sources_at_publication_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_key: str,
    mutation_kind: str,
) -> None:
    inputs = _write_stochastic_packet_inputs(tmp_path)
    target_path = inputs[source_key]
    packet_path = tmp_path / "evidence-packet.json"
    args = _stochastic_packet_build_args(inputs, packet_path)
    initial = RUNNER.invoke(app, args, terminal_width=240)
    assert initial.exit_code == 0, initial.output
    owned_paths = _packet_owned_output_paths(packet_path)
    original_output_bytes = {path: path.read_bytes() for path in owned_paths}
    original_environment_builder = packet_cmd.environment_with_dependency_inventory
    mutated = False

    def mutate_after_preflight(*builder_args: object, **builder_kwargs: object) -> object:
        nonlocal mutated
        environment = original_environment_builder(*builder_args, **builder_kwargs)
        assert not mutated
        _mutate_stochastic_source(target_path, mutation_kind)
        mutated = True
        return environment

    monkeypatch.setattr(
        packet_cmd,
        "environment_with_dependency_inventory",
        mutate_after_preflight,
    )

    failed = RUNNER.invoke(app, args, terminal_width=240)

    assert failed.exit_code == 2
    expected_change = "contents" if mutation_kind == "in_place" else "identity"
    assert expected_change in failed.output
    assert "changed after its producer snapshot" in failed.output
    assert mutated
    assert {path: path.read_bytes() for path in owned_paths} == original_output_bytes


def test_packet_graph_cli_round_trips_bound_graph_and_rejects_mismatch_and_alias(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="round-trip-candidate",
        runset_digest=_fixture_runset_digest("round-trip-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    built_graph_path = tmp_path / "built-graph.json"
    projected_graph_path = tmp_path / "projected-graph.json"
    manifest_path = tmp_path / "custom-release-artifact-manifest.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))

    built = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(built_graph_path),
            "--manifest-out",
            str(manifest_path),
        ],
    )

    assert built.exit_code == 0, built.output
    projected = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(projected_graph_path),
        ],
    )
    assert projected.exit_code == 0, projected.output
    assert projected_graph_path.read_bytes() == built_graph_path.read_bytes()

    suffixless_graph_path = tmp_path / "projected-graph"
    suffixless = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(suffixless_graph_path),
        ],
    )
    assert suffixless.exit_code == 0, suffixless.output
    assert suffixless_graph_path.read_bytes() == built_graph_path.read_bytes()

    original_graph_bytes = built_graph_path.read_bytes()
    in_place = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(built_graph_path),
        ],
    )
    assert in_place.exit_code == 0, in_place.output
    assert built_graph_path.read_bytes() == original_graph_bytes

    markdown_path = packet_path.with_suffix(".md")
    original_markdown_bytes = markdown_path.read_bytes()
    markdown_alias = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(markdown_path),
        ],
        terminal_width=240,
    )
    assert markdown_alias.exit_code == 2
    assert "graph output must not target packet Markdown" in markdown_alias.output
    assert markdown_path.read_bytes() == original_markdown_bytes

    markdown_hardlink = tmp_path / "packet-markdown-hardlink"
    markdown_hardlink.hardlink_to(markdown_path)
    hardlink_alias = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(markdown_hardlink),
        ],
        terminal_width=240,
    )
    assert hardlink_alias.exit_code == 2
    assert "graph output must not target packet Markdown" in hardlink_alias.output
    assert markdown_hardlink.read_bytes() == original_markdown_bytes
    assert markdown_path.read_bytes() == original_markdown_bytes

    altered_markdown_bytes = b"altered packet Markdown\n"
    markdown_path.write_bytes(altered_markdown_bytes)
    altered_markdown = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(markdown_path),
        ],
        terminal_width=240,
    )
    assert altered_markdown.exit_code == 2
    assert "graph output must not target packet Markdown" in altered_markdown.output
    assert markdown_path.read_bytes() == altered_markdown_bytes
    markdown_path.write_bytes(original_markdown_bytes)

    missing_markdown_paths = [tmp_path / "missing-packet.MD"]
    if os.name == "nt":
        missing_markdown_paths.append(tmp_path / "missing-packet.md.")
    for missing_markdown_path in missing_markdown_paths:
        missing_markdown = RUNNER.invoke(
            app,
            [
                "packet",
                "graph",
                "--packet",
                str(packet_path),
                "--out",
                str(missing_markdown_path),
            ],
            terminal_width=240,
        )
        assert missing_markdown.exit_code == 2
        assert "graph output must not target packet Markdown" in missing_markdown.output
        assert not missing_markdown_path.exists()

    for protected_path in (evaluation_path, manifest_path):
        original_protected_bytes = protected_path.read_bytes()
        protected = RUNNER.invoke(
            app,
            [
                "packet",
                "graph",
                "--packet",
                str(packet_path),
                "--out",
                str(protected_path),
            ],
            terminal_width=240,
        )
        assert protected.exit_code == 2
        assert "graph output aliases a packet-bound artifact" in protected.output
        assert protected_path.read_bytes() == original_protected_bytes

    original_packet_bytes = packet_path.read_bytes()
    alias = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(packet_path),
        ],
    )
    assert alias.exit_code == 2
    assert "input aliases an owned output path" in alias.output
    assert packet_path.read_bytes() == original_packet_bytes

    mismatched_payload = json.loads(original_packet_bytes)
    mismatched_payload["evidence_graph_digest"] = "f" * 64
    mismatched_packet_path = tmp_path / "mismatched-packet.json"
    mismatched_graph_path = tmp_path / "mismatched-graph.json"
    _write_json(mismatched_packet_path, mismatched_payload)
    mismatched = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(mismatched_packet_path),
            "--out",
            str(mismatched_graph_path),
        ],
    )
    assert mismatched.exit_code == 2
    assert "projected graph digest does not match" in mismatched.output
    assert not mismatched_graph_path.exists()


def test_packet_graph_cli_rejects_intact_custom_packet_markdown(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="custom-markdown-candidate",
        runset_digest=_fixture_runset_digest("custom-markdown-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    custom_markdown_path = tmp_path / "custom-packet-render.txt"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))

    built = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--markdown-out",
            str(custom_markdown_path),
        ],
    )
    assert built.exit_code == 0, built.output
    original_markdown_bytes = custom_markdown_path.read_bytes()

    targeted = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(custom_markdown_path),
        ],
        terminal_width=240,
    )

    assert targeted.exit_code == 2
    assert "graph output must not target packet Markdown" in targeted.output
    assert custom_markdown_path.read_bytes() == original_markdown_bytes


def test_packet_graph_cli_uses_most_specific_manifest_match_for_graph_recovery(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    evaluation = EvaluationSummary(
        runset_id="overlapping-graph-path-candidate",
        runset_digest=_fixture_runset_digest("overlapping-graph-path-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "artifact.json"
    packet_path = tmp_path / "evidence-packet.json"
    graph_path = nested / "artifact.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    built = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(graph_path),
            "--project-root",
            str(tmp_path),
        ],
    )
    assert built.exit_code == 0, built.output
    packet = load_evidence_packet(packet_path)
    assert packet.release_manifest is not None
    paths_by_role = {item.role: item.path for item in packet.release_manifest.artifacts}
    assert paths_by_role["evaluation-summary"] == "artifact.json"
    assert paths_by_role["assurance-evidence-graph"] == "nested/artifact.json"
    canonical_graph_bytes = graph_path.read_bytes()

    in_place = RUNNER.invoke(
        app,
        ["packet", "graph", "--packet", str(packet_path), "--out", str(graph_path)],
        terminal_width=240,
    )
    assert in_place.exit_code == 0, in_place.output
    assert graph_path.read_bytes() == canonical_graph_bytes

    graph_path.unlink()
    recovered = RUNNER.invoke(
        app,
        ["packet", "graph", "--packet", str(packet_path), "--out", str(graph_path)],
        terminal_width=240,
    )
    assert recovered.exit_code == 0, recovered.output
    assert graph_path.read_bytes() == canonical_graph_bytes


def test_packet_graph_cli_uses_most_specific_non_graph_manifest_match(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    evaluation = EvaluationSummary(
        runset_id="overlapping-evaluation-path-candidate",
        runset_digest=_fixture_runset_digest("overlapping-evaluation-path-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = nested / "artifact.json"
    packet_path = tmp_path / "evidence-packet.json"
    graph_path = tmp_path / "artifact.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    built = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(graph_path),
            "--project-root",
            str(tmp_path),
        ],
    )
    assert built.exit_code == 0, built.output

    packet_payload = json.loads(packet_path.read_bytes())
    artifacts = packet_payload["release_manifest"]["artifacts"]
    artifacts.sort(key=lambda item: item["role"] != "assurance-evidence-graph")
    _write_json(packet_path, packet_payload)
    altered_evaluation_bytes = b"altered overlapping evaluation\n"
    evaluation_path.write_bytes(altered_evaluation_bytes)

    targeted = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(evaluation_path),
        ],
        terminal_width=240,
    )

    assert targeted.exit_code == 2
    assert "graph output aliases a packet-bound artifact" in targeted.output
    assert "existing graph bytes do not match" not in targeted.output
    assert evaluation_path.read_bytes() == altered_evaluation_bytes


def test_packet_graph_cli_protects_original_artifacts_from_relocated_packets(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    original_root = tmp_path_factory.mktemp("packet-original")
    relocated_root = tmp_path_factory.mktemp("packet-relocated")
    mutation_result = _campaign(operator_ids=(_DROP_OPERATOR,)).campaign.operator_results[0].result
    evaluation = EvaluationSummary(
        runset_id="relocated-packet-candidate",
        runset_digest=mutation_result.source_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = original_root / "evaluation-summary.json"
    packet_path = original_root / "evidence-packet.json"
    graph_path = original_root / "assurance-evidence-graph.json"
    markdown_path = original_root / "evidence-packet.md"
    mutation_path = relocated_root / "mutation-result.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))

    built = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert built.exit_code == 0, built.output
    canonical_graph_bytes = graph_path.read_bytes()
    original_markdown_bytes = markdown_path.read_bytes()

    hardlinked_packet = relocated_root / "hardlinked-packet.json"
    copied_packet = relocated_root / "copied-packet.json"
    hardlinked_packet.hardlink_to(packet_path)
    copied_packet.write_bytes(packet_path.read_bytes())

    markdown_target = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(hardlinked_packet),
            "--out",
            str(markdown_path),
        ],
        terminal_width=240,
    )
    assert markdown_target.exit_code == 2
    assert "graph output must not target packet Markdown" in markdown_target.output
    assert markdown_path.read_bytes() == original_markdown_bytes

    altered_evaluation_bytes = b"altered evaluation evidence\n"
    evaluation_path.write_bytes(altered_evaluation_bytes)
    for relocated_packet in (hardlinked_packet, copied_packet):
        evaluation_target = RUNNER.invoke(
            app,
            [
                "packet",
                "graph",
                "--packet",
                str(relocated_packet),
                "--out",
                str(evaluation_path),
            ],
            terminal_width=240,
        )
        assert evaluation_target.exit_code == 2
        assert "graph output aliases a packet-bound artifact" in evaluation_target.output
        assert evaluation_path.read_bytes() == altered_evaluation_bytes

    graph_path.unlink()
    recovered = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(hardlinked_packet),
            "--out",
            str(graph_path),
        ],
        terminal_width=240,
    )
    assert recovered.exit_code == 0, recovered.output
    assert graph_path.read_bytes() == canonical_graph_bytes

    _write_json(mutation_path, mutation_result.model_dump(mode="json"))
    graph_path.unlink()
    enriched_target = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(copied_packet),
            "--mutation-result",
            str(mutation_path),
            "--out",
            str(graph_path),
        ],
        terminal_width=240,
    )
    assert enriched_target.exit_code == 2
    assert "mutation-enriched graph output aliases" in enriched_target.output
    assert not graph_path.exists()
    graph_path.write_bytes(canonical_graph_bytes)


def test_packet_graph_cli_does_not_clobber_markdown_through_packet_symlink(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="symlinked-packet-candidate",
        runset_digest=_fixture_runset_digest("symlinked-packet-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    markdown_path = tmp_path / "evidence-packet.md"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    built = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert built.exit_code == 0, built.output
    original_markdown_bytes = markdown_path.read_bytes()

    packet_symlink = tmp_path / "symlinked-packet.json"
    try:
        packet_symlink.symlink_to(packet_path)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")

    targeted = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_symlink),
            "--out",
            str(markdown_path),
        ],
        terminal_width=240,
    )

    assert targeted.exit_code == 2
    assert markdown_path.read_bytes() == original_markdown_bytes


@pytest.mark.parametrize(
    "path_kind",
    ("traversal", "absolute", "ads", "control", "reserved-device"),
)
def test_packet_graph_cli_rejects_unsafe_manifest_paths_before_writing(
    tmp_path: Path,
    path_kind: str,
) -> None:
    evaluation = EvaluationSummary(
        runset_id=f"unsafe-manifest-{path_kind}",
        runset_digest=_fixture_runset_digest(f"unsafe-manifest-{path_kind}"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    unsafe_packet_path = tmp_path / f"unsafe-{path_kind}-packet.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    built = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert built.exit_code == 0, built.output

    packet_payload = json.loads(packet_path.read_bytes())
    evaluation_artifact = next(
        artifact
        for artifact in packet_payload["release_manifest"]["artifacts"]
        if artifact["role"] == "evaluation-summary"
    )
    unsafe_paths = {
        "traversal": "../evaluation-summary.json",
        "absolute": evaluation_path.resolve().as_posix(),
        "ads": "evaluation-summary.json::$DATA",
        "control": "evaluation-\nsummary.json",
        "reserved-device": "CON.json",
    }
    evaluation_artifact["path"] = unsafe_paths[path_kind]
    _write_json(unsafe_packet_path, packet_payload)
    altered_evaluation_bytes = b"altered traversal target\n"
    evaluation_path.write_bytes(altered_evaluation_bytes)

    targeted = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(unsafe_packet_path),
            "--out",
            str(evaluation_path),
        ],
        terminal_width=240,
    )

    assert targeted.exit_code == 2
    assert "manifest path is not canonical portable POSIX-relative" in targeted.output
    assert evaluation_path.read_bytes() == altered_evaluation_bytes


@pytest.mark.skipif(
    os.path.normcase("A") != os.path.normcase("a"),
    reason="host normcase preserves filename case",
)
def test_packet_graph_cli_matches_manifest_paths_case_insensitively(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="case-variant-manifest-path",
        runset_digest=_fixture_runset_digest("case-variant-manifest-path"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "artifact.json"
    packet_path = tmp_path / "evidence-packet.json"
    case_variant_output = tmp_path / "ARTIFACT.JSON"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    built = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert built.exit_code == 0, built.output
    altered_evaluation_bytes = b"altered case-variant target\n"
    evaluation_path.write_bytes(altered_evaluation_bytes)

    targeted = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(case_variant_output),
        ],
        terminal_width=240,
    )

    assert targeted.exit_code == 2
    assert "graph output aliases a packet-bound artifact" in targeted.output
    assert evaluation_path.read_bytes() == altered_evaluation_bytes
    assert os.path.samefile(case_variant_output, evaluation_path)


@pytest.mark.skipif(
    os.path.normcase("A") == os.path.normcase("a"),
    reason="host normcase folds filename case",
)
def test_packet_graph_cli_preserves_case_distinct_manifest_paths(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="case-distinct-manifest-path",
        runset_digest=_fixture_runset_digest("case-distinct-manifest-path"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "Artifact.json"
    graph_path = tmp_path / "artifact.json"
    packet_path = tmp_path / "evidence-packet.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    if graph_path.exists():
        pytest.skip("filesystem does not preserve case-distinct filenames")
    built = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(graph_path),
            "--project-root",
            str(tmp_path),
        ],
    )
    assert built.exit_code == 0, built.output
    packet = load_evidence_packet(packet_path)
    assert packet.release_manifest is not None
    paths_by_role = {item.role: item.path for item in packet.release_manifest.artifacts}
    assert paths_by_role["evaluation-summary"] == "Artifact.json"
    assert paths_by_role["assurance-evidence-graph"] == "artifact.json"
    canonical_graph_bytes = graph_path.read_bytes()

    in_place = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--out",
            str(graph_path),
        ],
        terminal_width=240,
    )
    assert in_place.exit_code == 0, in_place.output
    assert graph_path.read_bytes() == canonical_graph_bytes

    graph_path.unlink()
    recovered = RUNNER.invoke(
        app,
        ["packet", "graph", "--packet", str(packet_path), "--out", str(graph_path)],
        terminal_width=240,
    )
    assert recovered.exit_code == 0, recovered.output
    assert graph_path.read_bytes() == canonical_graph_bytes


def test_packet_graph_cli_rejects_in_place_semantic_graph_with_unbound_rendering(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="alternate-rendering-candidate",
        runset_digest=_fixture_runset_digest("alternate-rendering-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))

    built = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(graph_path),
        ],
    )
    assert built.exit_code == 0, built.output

    canonical_graph_bytes = graph_path.read_bytes()
    graph_payload = json.loads(canonical_graph_bytes)
    alternate_graph_bytes = (
        json.dumps(graph_payload, separators=(",", ":"), sort_keys=False) + "\n"
    ).encode("utf-8")
    assert alternate_graph_bytes != graph_path.read_bytes()
    assert json.loads(alternate_graph_bytes) == graph_payload
    graph_path.write_bytes(alternate_graph_bytes)
    alternate_sha256 = hashlib.sha256(alternate_graph_bytes).hexdigest()

    altered = RUNNER.invoke(
        app,
        ["packet", "graph", "--packet", str(packet_path), "--out", str(graph_path)],
        terminal_width=240,
    )
    assert altered.exit_code == 2
    assert "existing graph bytes do not match packet binding" in altered.output
    assert graph_path.read_bytes() == alternate_graph_bytes

    graph_path.unlink()
    missing = RUNNER.invoke(
        app,
        ["packet", "graph", "--packet", str(packet_path), "--out", str(graph_path)],
        terminal_width=240,
    )
    assert missing.exit_code == 0, missing.output
    assert graph_path.read_bytes() == canonical_graph_bytes
    graph_path.write_bytes(alternate_graph_bytes)

    packet_payload = json.loads(packet_path.read_bytes())
    for artifact in packet_payload["artifact_digests"]:
        if artifact["role"] == "assurance-evidence-graph":
            artifact["sha256"] = alternate_sha256
    for artifact in packet_payload["release_manifest"]["artifacts"]:
        if artifact["role"] == "assurance-evidence-graph":
            artifact["sha256"] = alternate_sha256
    _write_json(packet_path, packet_payload)

    projected = RUNNER.invoke(
        app,
        ["packet", "graph", "--packet", str(packet_path), "--out", str(graph_path)],
        terminal_width=240,
    )

    assert projected.exit_code == 2
    assert "projected graph bytes do not match packet binding" in projected.output
    assert graph_path.read_bytes() == alternate_graph_bytes


def test_packet_graph_cli_verifies_bound_base_before_mutation_enrichment(
    tmp_path: Path,
) -> None:
    mutation_result = _campaign(operator_ids=(_DROP_OPERATOR,)).campaign.operator_results[0].result
    evaluation = EvaluationSummary(
        runset_id="enriched-graph-candidate",
        runset_digest=mutation_result.source_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    base_graph_path = tmp_path / "base-graph.json"
    mutation_path = tmp_path / "mutation-result.json"
    enriched_graph_path = tmp_path / "enriched-graph.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    _write_json(mutation_path, mutation_result.model_dump(mode="json"))

    built = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(base_graph_path),
        ],
    )
    assert built.exit_code == 0, built.output
    packet = load_evidence_packet(packet_path)
    assert packet.evidence_graph_digest is not None
    base_graph_bytes = base_graph_path.read_bytes()

    for protected_path in (base_graph_path, evaluation_path):
        protected_bytes = protected_path.read_bytes()
        protected = RUNNER.invoke(
            app,
            [
                "packet",
                "graph",
                "--packet",
                str(packet_path),
                "--mutation-result",
                str(mutation_path),
                "--out",
                str(protected_path),
            ],
            terminal_width=240,
        )
        assert protected.exit_code == 2
        assert "mutation-enriched graph output aliases" in protected.output
        assert protected_path.read_bytes() == protected_bytes

    base_graph_path.unlink()
    missing_bound_graph = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--mutation-result",
            str(mutation_path),
            "--out",
            str(base_graph_path),
        ],
        terminal_width=240,
    )
    assert missing_bound_graph.exit_code == 2
    assert "mutation-enriched graph output aliases" in missing_bound_graph.output
    assert not base_graph_path.exists()
    base_graph_path.write_bytes(base_graph_bytes)

    enriched = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--mutation-result",
            str(mutation_path),
            "--out",
            str(enriched_graph_path),
        ],
    )

    assert enriched.exit_code == 0, enriched.output
    assert f"packet-bound base graph digest: {packet.evidence_graph_digest}" in enriched.output
    enriched_payload = json.loads(enriched_graph_path.read_text(encoding="utf-8"))
    assert enriched_payload["graph_digest"] != packet.evidence_graph_digest
    mutation_evidence = next(
        node
        for node in enriched_payload["nodes"]
        if node["payload"].get("evidence_type") == "mutation_result"
    )
    mutation_subject_id = next(
        edge["target_node_id"]
        for edge in enriched_payload["edges"]
        if edge["kind"] == "scoped_to" and edge["source_node_id"] == mutation_evidence["node_id"]
    )
    mutation_subject = next(
        node for node in enriched_payload["nodes"] if node["node_id"] == mutation_subject_id
    )
    assert mutation_subject_id == enriched_payload["primary_subject_node_id"]
    assert mutation_subject["payload"]["subject_id"] == evaluation.runset_id
    assert mutation_subject["payload"]["subject_digest"] == (mutation_result.source_digest)


def test_packet_graph_cli_bounds_aggregate_mutation_input_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="bounded-enrichment-candidate",
        runset_digest=_fixture_runset_digest("bounded-enrichment-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    mutation_result = _campaign(operator_ids=(_DROP_OPERATOR,)).campaign.operator_results[0].result
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    mutation_path = tmp_path / "mutation-result.json"
    output_path = tmp_path / "enriched-graph.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    _write_json(mutation_path, mutation_result.model_dump(mode="json"))
    built = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert built.exit_code == 0, built.output
    monkeypatch.setattr(
        packet_cmd,
        "_MAX_PACKET_MUTATION_RESULTS_TOTAL_BYTES",
        mutation_path.stat().st_size - 1,
    )

    result = RUNNER.invoke(
        app,
        [
            "packet",
            "graph",
            "--packet",
            str(packet_path),
            "--mutation-result",
            str(mutation_path),
            "--out",
            str(output_path),
        ],
        terminal_width=240,
    )

    assert result.exit_code == 2
    assert "mutation result inputs exceed" in result.output
    assert not output_path.exists()


def test_summary_snapshot_drives_parse_digest_and_manifest_from_one_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="single-snapshot-candidate",
        runset_digest=_fixture_runset_digest("single-snapshot-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    original_reader = path_safety.read_file_bounded_at
    reads = 0

    def counting_reader(
        root: Path,
        relative_path: str | Path,
        **kwargs: object,
    ) -> object:
        nonlocal reads
        reads += 1
        return original_reader(root, relative_path, **kwargs)

    monkeypatch.setattr(path_safety, "read_file_bounded_at", counting_reader)

    snapshot = load_evaluation_summary_snapshot(
        evaluation_path,
        root=tmp_path,
        artifact_root=tmp_path,
    )
    digest = packet_artifact_digest_from_snapshot("evaluation-summary", snapshot)
    manifest_artifact = release_artifact_from_summary_snapshot(
        "evaluation-summary",
        snapshot,
    )

    assert reads == 1
    assert snapshot.summary == evaluation
    assert digest.sha256 == _file_sha256(evaluation_path)
    assert manifest_artifact.sha256 == digest.sha256
    assert manifest_artifact.path == "evaluation-summary.json"


def test_packet_build_rejects_summary_replacement_during_snapshot_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="snapshot-race-candidate",
        runset_digest=_fixture_runset_digest("snapshot-race-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    replacement = evaluation.model_copy(update={"runset_id": "replacement-candidate"})
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    original_reader = path_safety.read_file_bounded_at
    reads = 0

    def replace_after_descriptor_read(
        root: Path,
        relative_path: str | Path,
        **kwargs: object,
    ) -> object:
        nonlocal reads
        contents = original_reader(root, relative_path, **kwargs)
        if (root / relative_path).absolute() == evaluation_path.absolute():
            reads += 1
            _write_json(evaluation_path, replacement.model_dump(mode="json"))
        return contents

    monkeypatch.setattr(
        path_safety,
        "read_file_bounded_at",
        replace_after_descriptor_read,
    )

    result = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )

    assert result.exit_code == 2
    assert "changed path identity after it was read" in result.output
    assert reads == 1
    assert not packet_path.exists()


def test_packet_build_rolls_back_every_owned_output_after_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="rollback-candidate",
        runset_digest=_fixture_runset_digest("rollback-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    owned_paths = (
        packet_path,
        packet_path.with_suffix(".md"),
        tmp_path / "release-artifact-manifest.json",
        tmp_path / "assurance-evidence-graph.json",
        tmp_path / "dependency-inventory.json",
    )
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    initial = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert initial.exit_code == 0, initial.output
    original_bytes = {path: path.read_bytes() for path in owned_paths}

    changed = evaluation.model_copy(update={"state": GateState.not_evaluated})
    _write_json(evaluation_path, changed.model_dump(mode="json"))

    def fail_markdown_write(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected late packet publication failure")

    monkeypatch.setattr(
        packet_cmd,
        "write_evidence_packet_markdown",
        fail_markdown_write,
    )
    failed = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
        terminal_width=240,
    )

    assert failed.exit_code == 2
    assert "injected late packet publication failure" in failed.output
    assert {path: path.read_bytes() for path in owned_paths} == original_bytes


def test_packet_build_rolls_back_inventory_when_later_environment_collection_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="inventory-rollback-candidate",
        runset_digest=_fixture_runset_digest("inventory-rollback-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    owned_paths = _packet_owned_output_paths(packet_path)
    inventory_path = tmp_path / "dependency-inventory.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    initial = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert initial.exit_code == 0, initial.output
    original_bytes = {path: path.read_bytes() for path in owned_paths}
    _write_json(
        evaluation_path,
        evaluation.model_copy(update={"state": GateState.not_evaluated}).model_dump(mode="json"),
    )
    original_collector = environment_reporting.collect_environment
    collection_calls = 0

    def change_inventory_then_fail(*args: object, **kwargs: object) -> EnvironmentInfo:
        nonlocal collection_calls
        collection_calls += 1
        if collection_calls == 1:
            collected = original_collector(*args, **kwargs)
            return collected.model_copy(update={"platform": f"{collected.platform}-rollback-probe"})
        assert collection_calls == 2
        assert inventory_path.read_bytes() != original_bytes[inventory_path]
        raise OSError("injected post-inventory environment collection failure")

    monkeypatch.setattr(
        environment_reporting,
        "collect_environment",
        change_inventory_then_fail,
    )

    failed = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
        terminal_width=240,
    )

    assert failed.exit_code == 2
    assert "injected post-inventory environment collection failure" in failed.output
    assert collection_calls == 2
    assert {path: path.read_bytes() for path in owned_paths} == original_bytes


def test_packet_build_rollback_refuses_to_clobber_concurrent_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="rollback-concurrency-candidate",
        runset_digest=_fixture_runset_digest("rollback-concurrency-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    initial = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert initial.exit_code == 0, initial.output
    _write_json(
        evaluation_path,
        evaluation.model_copy(update={"state": GateState.not_evaluated}).model_dump(mode="json"),
    )
    concurrent_bytes = b"concurrent writer output\n"

    def fail_after_concurrent_write(*_args: object, **_kwargs: object) -> None:
        packet_path.write_bytes(concurrent_bytes)
        raise OSError("injected failure after concurrent write")

    monkeypatch.setattr(
        packet_cmd,
        "write_evidence_packet_markdown",
        fail_after_concurrent_write,
    )

    failed = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
        terminal_width=240,
    )

    assert failed.exit_code == 2
    assert "packet publication failed" in failed.output
    assert packet_path.read_bytes() == concurrent_bytes


def test_packet_build_rejects_custom_graph_output_outside_artifact_root(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="confined-output-candidate",
        runset_digest=_fixture_runset_digest("confined-output-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    outside_graph = tmp_path.parent / f"{tmp_path.name}-outside-graph.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))

    result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(outside_graph),
        ],
    )

    assert result.exit_code == 2
    assert "output paths must stay within the artifact root" in result.output
    assert not outside_graph.exists()
    assert not packet_path.exists()
    assert not (tmp_path / "dependency-inventory.json").exists()


def test_packet_build_rejects_nested_owned_outputs_before_writing(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="nested-output-candidate",
        runset_digest=_fixture_runset_digest("nested-output-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "packet"
    nested_graph_path = packet_path / "graph.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))

    result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--out",
            str(packet_path),
            "--graph-out",
            str(nested_graph_path),
        ],
    )

    assert result.exit_code == 2
    assert "output paths must not contain one another" in result.output
    assert not packet_path.exists()
    assert not (tmp_path / "dependency-inventory.json").exists()


def test_packet_build_and_trusted_gate_reject_summary_file_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="trusted-source-candidate",
        runset_digest=_fixture_runset_digest("trusted-source-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    replacement = evaluation.model_copy(update={"runset_id": "tampered-candidate"})
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    manifest_path = tmp_path / "release-artifact-manifest.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    original_environment_builder = packet_cmd.environment_with_dependency_inventory

    def replace_after_creation_snapshot(*args: object, **kwargs: object) -> object:
        environment = original_environment_builder(*args, **kwargs)
        _write_json(evaluation_path, replacement.model_dump(mode="json"))
        return environment

    monkeypatch.setattr(
        packet_cmd,
        "environment_with_dependency_inventory",
        replace_after_creation_snapshot,
    )

    swapped = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
        terminal_width=200,
    )

    assert swapped.exit_code == 2
    assert "source file digest does" in swapped.output
    assert "not match release manifest" in swapped.output
    assert not packet_path.exists()
    assert not manifest_path.exists()

    monkeypatch.setattr(
        packet_cmd,
        "environment_with_dependency_inventory",
        original_environment_builder,
    )
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    built = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )
    assert built.exit_code == 0, built.output
    packet = load_evidence_packet(packet_path)

    _write_json(evaluation_path, replacement.model_dump(mode="json"))
    tampered_file = gate_evidence_packet(packet, artifact_root=tmp_path)
    standalone_tampered_file = RUNNER.invoke(
        app,
        ["ci", "gate", str(packet_path)],
    )
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    nested_tamper = packet.model_copy(
        update={"evaluation": packet.evaluation.model_copy(update={"runset_id": "forged"})}
    )
    tampered_nested = gate_evidence_packet(nested_tamper, artifact_root=tmp_path)

    assert tampered_file.exit_code == 2
    assert tampered_file.outcome is GateOutcome.invalid
    assert "source file digest does not match release manifest" in tampered_file.message
    assert standalone_tampered_file.exit_code == 2
    assert "source file digest does not match release manifest" in standalone_tampered_file.output
    assert tampered_nested.exit_code == 2
    assert tampered_nested.outcome is GateOutcome.invalid
    assert "source file does not match nested summary" in tampered_nested.message

    assert packet.release_manifest is not None
    unsafe_artifacts = tuple(
        item.model_copy(update={"path": "../escaped-evaluation-summary.json"})
        if item.role == "evaluation-summary"
        else item
        for item in packet.release_manifest.artifacts
    )
    unsafe_manifest = packet.release_manifest.model_copy(update={"artifacts": unsafe_artifacts})
    unsafe_packet = packet.model_copy(update={"release_manifest": unsafe_manifest})

    unsafe_path = gate_evidence_packet(unsafe_packet, artifact_root=tmp_path)

    assert unsafe_path.exit_code == 2
    assert unsafe_path.outcome is GateOutcome.invalid
    assert "source file could not be safely verified" in unsafe_path.message


def test_trusted_gate_rejects_nested_difference_that_redaction_would_mask(
    tmp_path: Path,
) -> None:
    nested_sensitive_value = "nested-owner@example.com"
    source_summary = EvaluationSummary(
        runset_id="source-owner@example.com",
        runset_digest=_fixture_runset_digest("source-owner@example.com"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(
            Finding(
                finding_id="nested-sensitive-finding",
                case_id="case-sensitive",
                control_id="material_claims_have_evidence",
                state=GateState.fail,
                reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                message=f"Contact {nested_sensitive_value} about the missing evidence.",
            ),
        ),
    )
    evaluation_path = tmp_path / "evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"
    _write_json(evaluation_path, source_summary.model_dump(mode="json"))

    built = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )

    assert built.exit_code == 0, built.output
    packet = load_evidence_packet(packet_path)
    assert packet.evaluation != source_summary
    assert redact_packet_payload(packet.evaluation.model_dump(mode="json")) == (
        redact_packet_payload(source_summary.model_dump(mode="json"))
    )
    persisted_graph = graph_path.read_text(encoding="utf-8")
    assert source_summary.runset_id not in persisted_graph
    assert nested_sensitive_value not in persisted_graph
    assert packet.evaluation.runset_id in persisted_graph
    assert packet.evaluation.findings[0].message in persisted_graph
    assert packet.evidence_graph_digest == json.loads(persisted_graph)["graph_digest"]

    gated = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--artifact-root",
            str(tmp_path),
        ],
    )

    assert gated.exit_code == 2
    assert "source file does not match nested summary" in gated.output


def test_packet_build_rejects_legacy_summary_before_packet_write(tmp_path: Path) -> None:
    evaluation = EvaluationSummary(
        runset_id="legacy-candidate",
        runset_digest=_fixture_runset_digest("legacy-candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_payload = evaluation.model_dump(mode="json")
    evaluation_payload["schema_version"] = "0.6.1"
    evaluation_payload.pop("runset_digest")
    evaluation_path = tmp_path / "legacy-evaluation-summary.json"
    packet_path = tmp_path / "evidence-packet.json"
    _write_json(evaluation_path, evaluation_payload)

    result = RUNNER.invoke(
        app,
        ["packet", "build", str(evaluation_path), "--out", str(packet_path)],
    )

    assert result.exit_code == 2
    assert f"evidence packet schema_version '{SCHEMA_VERSION}' requires" in result.output
    assert f"evaluation.schema_version '{SCHEMA_VERSION}'; received '0.6.1'" in result.output
    assert not packet_path.exists()


def test_packet_id_excludes_local_environment_and_exact_file_digests() -> None:
    evaluation = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate",
        runset_digest=_fixture_runset_digest("candidate"),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
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


def test_packet_build_cli_carries_authenticated_evidence_sensitivity(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "examples" / "evidence_sensitivity"
    artifacts = execute_sensitivity_experiment(
        suite_path=example / "responsive_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=example / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    evaluation_path = tmp_path / "counterfactual-evaluation-summary.json"
    sensitivity_path = tmp_path / "evidence-sensitivity.json"
    packet_path = tmp_path / "evidence-packet.json"
    graph_path = tmp_path / "assurance-evidence-graph.json"
    _write_json(
        evaluation_path,
        artifacts.counterfactual_evaluation.model_dump(mode="json"),
    )
    _write_json(
        sensitivity_path,
        artifacts.report.model_dump(mode="json"),
    )

    result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(evaluation_path),
            "--evidence-sensitivity",
            str(sensitivity_path),
            "--out",
            str(packet_path),
        ],
    )

    assert result.exit_code == 0, result.output
    packet = load_evidence_packet(packet_path)
    assert packet.evidence_sensitivity == artifacts.report
    assert packet.evidence_sensitivity.detector_test_status is (
        DetectorTestStatus.synthetic_detector_contract_test
    )
    assert {item.role: item.sha256 for item in packet.artifact_digests}[
        "evidence-sensitivity-report"
    ] == _file_sha256(sensitivity_path)
    assert packet.release_manifest is not None
    assert {item.role: item.sha256 for item in packet.release_manifest.artifacts}[
        "evidence-sensitivity-report"
    ] == _file_sha256(sensitivity_path)

    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    sensitivity_evidence = next(
        node["payload"]
        for node in graph["nodes"]
        if node["payload"].get("evidence_type") == "evidence_sensitivity"
    )
    projection = sensitivity_evidence["evidence_sensitivity_projection"]
    assert sensitivity_evidence["source_digest"] == artifacts.report.report_digest
    assert sensitivity_evidence["limitations"] == list(artifacts.report.limitations)
    assert projection["state"] == "responsive"
    assert projection["endpoint_value"] is True
    assert projection["claim_scope"] == ("controlled_evidence_sensitivity_not_causal_guarantee")
    assert projection["population_claim"] == "none_bundled_synthetic_fixture_only"
    assert projection["synthetic_data_provenance"] == "bundled_digest_verified"
    assert projection["synthetic_data_attestation_digest"] is None
    assert projection["raw_content_persistence"] == "exact_corpus_and_fixture_utf8_embedded"
    assert projection["detector_test_status"] == "synthetic_detector_contract_test"
    markdown = packet_path.with_suffix(".md").read_text(encoding="utf-8")
    assert "## Controlled Evidence Sensitivity" in markdown
    assert (
        "does not show that a model used contextual evidence instead of parametric memory"
        in markdown
    )
    assert "not a causal guarantee or real-model prevalence estimate" in markdown
    assert all(limitation in markdown for limitation in artifacts.report.limitations)
    replay = build_digest_replay(
        (("evidence-sensitivity-report", sensitivity_path),),
        project_root=tmp_path,
    )
    assert replay.artifacts[0].digest_mode == "replay-stable-json-sha256"
    assert verify_digest_replay(replay, artifact_root=tmp_path).ok

    gated = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--artifact-root",
            str(tmp_path),
        ],
    )
    assert gated.exit_code == 0, gated.output


def test_cli_comparison_of_sensitivity_runsets_packet_builds_end_to_end(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "examples" / "evidence_sensitivity"
    sensitivity_out = tmp_path / "sensitivity"
    sensitivity_result = RUNNER.invoke(
        app,
        [
            "rag",
            "sensitivity",
            "--suite",
            str(example / "responsive_suite.yaml"),
            "--baseline-corpus",
            str(example / "corpora" / "policy_a"),
            "--counterfactual-corpus",
            str(example / "corpora" / "policy_b"),
            "--knowledge-contract",
            str(example / "knowledge-contract.yaml"),
            "--expected-relation",
            "decision_flip",
            "--out",
            str(sensitivity_out),
        ],
    )
    assert sensitivity_result.exit_code == 0, sensitivity_result.output

    comparison_out = tmp_path / "comparison"
    comparison_result = RUNNER.invoke(
        app,
        [
            "compare",
            str(sensitivity_out / "baseline.runset.json"),
            str(sensitivity_out / "counterfactual.runset.json"),
            "--suite",
            str(sensitivity_out / "compiled-suite.json"),
            "--out-dir",
            str(comparison_out),
        ],
    )
    assert comparison_result.exit_code == 0, comparison_result.output
    cli_comparison = ComparisonSummary.model_validate(
        json.loads((comparison_out / "comparison-summary.json").read_text(encoding="utf-8"))
    )
    assert cli_comparison.environment is not None

    packet_path = tmp_path / "packet" / "evidence-packet.json"
    packet_result = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(sensitivity_out / "counterfactual-evaluation-summary.json"),
            "--comparison",
            str(comparison_out / "comparison-summary.json"),
            "--evidence-sensitivity",
            str(sensitivity_out / "evidence-sensitivity.json"),
            "--out",
            str(packet_path),
            "--project-root",
            str(tmp_path),
        ],
    )
    assert packet_result.exit_code == 0, packet_result.output
    packet = load_evidence_packet(packet_path)
    report = packet.evidence_sensitivity
    comparison = packet.comparison
    assert report is not None
    assert comparison is not None
    assert comparison.environment == cli_comparison.environment
    assert comparison.baseline_runset_digest == report.baseline_arm.runset_digest
    assert comparison.candidate_runset_digest == report.counterfactual_arm.runset_digest

    gate_result = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--artifact-root",
            str(tmp_path),
        ],
    )
    assert gate_result.exit_code == 0, gate_result.output


def test_packet_and_ci_reject_comparison_that_contradicts_embedded_sensitivity() -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "examples" / "evidence_sensitivity"
    artifacts = execute_sensitivity_experiment(
        suite_path=example / "responsive_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=example / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    comparison = derive_sensitivity_comparison(artifacts.report)
    packet = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        comparison=comparison,
        evidence_sensitivity=artifacts.report,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64),
            PacketArtifactDigest(role="comparison-summary", sha256="b" * 64),
            PacketArtifactDigest(role="evidence-sensitivity-report", sha256="c" * 64),
        ),
    )
    environment = EnvironmentInfo(platform="test", python_version="3.14")
    environment_comparison = comparison.model_copy(update={"environment": environment})
    environment_packet = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        comparison=environment_comparison,
        evidence_sensitivity=artifacts.report,
        artifact_digests=packet.artifact_digests,
    )
    assert environment_packet.comparison is not None
    assert environment_packet.comparison.environment == environment

    for field_name in ("baseline_runset_digest", "candidate_runset_digest"):
        original_digest = getattr(comparison, field_name)
        replacement = "0" * 64 if original_digest != "0" * 64 else "1" * 64
        digest_tampered = comparison.model_copy(update={field_name: replacement})
        with pytest.raises(ValidationError, match=field_name):
            build_evidence_packet(
                artifacts.counterfactual_evaluation,
                comparison=digest_tampered,
                evidence_sensitivity=artifacts.report,
                artifact_digests=packet.artifact_digests,
            )

    contradictory = comparison.model_copy(update={"baseline_state": GateState.fail})

    with pytest.raises(
        ValidationError,
        match="must exactly equal the canonical comparison",
    ):
        build_evidence_packet(
            artifacts.counterfactual_evaluation,
            comparison=contradictory,
            evidence_sensitivity=artifacts.report,
            artifact_digests=packet.artifact_digests,
        )

    unchecked = packet.model_copy(update={"comparison": contradictory})
    decision = gate_evidence_packet(unchecked)

    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "must exactly equal the canonical comparison" in decision.message


def test_report_rejects_unauthenticated_sensitivity_evaluation_digest_before_packet() -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "examples" / "evidence_sensitivity"
    artifacts = execute_sensitivity_experiment(
        suite_path=example / "responsive_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=example / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    report_payload = artifacts.report.model_dump(
        mode="json",
        exclude={"report_digest"},
    )
    counterfactual = cast(dict[str, object], report_payload["counterfactual_arm"])
    counterfactual["evaluation_summary_digest"] = "a" * 64

    with pytest.raises(
        ValidationError,
        match="counterfactual exact evaluation summary must match the sensitivity arm",
    ):
        RAGSensitivityReport.build(**report_payload)


def test_evidence_insensitive_packet_blocks_ci_gate_and_cannot_be_silently_required(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "examples" / "evidence_sensitivity"
    artifacts = execute_sensitivity_experiment(
        suite_path=example / "evidence_inertial_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=example / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    packet = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        evidence_sensitivity=artifacts.report,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64),
            PacketArtifactDigest(
                role="evidence-sensitivity-report",
                sha256="b" * 64,
            ),
        ),
    )

    decision = gate_evidence_packet(packet)

    assert artifacts.report.state is EvidenceSensitivityState.evidence_insensitive
    assert decision.outcome is GateOutcome.fail
    assert decision.exit_code == 1
    assert decision.reason_code is EvidenceSensitivityReasonCode.expected_response_missing
    assert "state=evidence_insensitive gate_effect=block" in decision.message

    stripped = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        artifact_digests=(PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64),),
    )
    assert gate_evidence_packet(stripped).outcome is GateOutcome.pass_

    required = gate_evidence_packet(
        stripped,
        require_evidence_sensitivity=True,
    )
    assert required.outcome is GateOutcome.invalid
    assert required.exit_code == 2
    assert "--require-evidence-sensitivity" in required.message

    stripped_path = tmp_path / "stripped-packet.json"
    _write_json(stripped_path, stripped.model_dump(mode="json"))
    cli_required = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(stripped_path),
            "--require-evidence-sensitivity",
        ],
    )
    assert cli_required.exit_code == 2
    assert "--require-evidence-sensitivity" in cli_required.output


def test_sensitivity_gates_revalidate_model_copy_tampering() -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "examples" / "evidence_sensitivity"
    artifacts = execute_sensitivity_experiment(
        suite_path=example / "evidence_inertial_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=example / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    packet = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        evidence_sensitivity=artifacts.report,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64),
            PacketArtifactDigest(role="evidence-sensitivity-report", sha256="b" * 64),
        ),
    )
    forged_report = artifacts.report.model_copy(
        update={
            "state": EvidenceSensitivityState.responsive,
            "gate_effect": EvidenceSensitivityGateEffect.pass_,
            "verdict_bearing": True,
            "reason_codes": (),
            "outcome_classification": (
                EvidenceSensitivityOutcomeClassification.expected_response_observed
            ),
            "endpoint_value": True,
        }
    )

    direct_decision = gate_evidence_sensitivity_report(forged_report)
    packet_decision = gate_evidence_packet(
        packet.model_copy(update={"evidence_sensitivity": forged_report})
    )

    for decision in (direct_decision, packet_decision):
        assert decision.outcome is GateOutcome.invalid
        assert decision.exit_code == 2
        assert "failed trusted model revalidation" in decision.message


def test_reversed_sensitivity_packet_markdown_explains_wrong_direction() -> None:
    root = Path(__file__).resolve().parents[2]
    example = root / "examples" / "evidence_sensitivity"
    artifacts = execute_sensitivity_experiment(
        suite_path=example / "evidence_reversed_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=example / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    packet = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        evidence_sensitivity=artifacts.report,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64),
            PacketArtifactDigest(role="evidence-sensitivity-report", sha256="b" * 64),
        ),
    )

    markdown = render_evidence_packet_markdown(packet)

    assert "- Outcome classification: `wrong_direction_flip`" in markdown
    assert "- Outcome: Expected decisions" in markdown
    assert "wrong direction relative to the authority contract" in markdown


def test_nonverdict_sensitivity_fails_closed_unless_explicitly_allowed(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[2]
    source_example = root / "examples" / "evidence_sensitivity"
    example = tmp_path / "evidence-sensitivity"
    shutil.copytree(source_example, example)
    bundled_artifacts = execute_sensitivity_experiment(
        suite_path=example / "responsive_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=example / "knowledge-contract.yaml",
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
    )
    manifest_path = example / "corpora" / "policy_b" / "corpus-manifest.json"
    manifest_payload = cast(
        dict[str, object],
        json.loads(manifest_path.read_text(encoding="utf-8")),
    )
    old_digest = cast(str, manifest_payload.pop("corpus_digest"))
    manifest_payload["top_k"] = 2
    manifest = RAGSensitivityCorpusManifest.build(**manifest_payload)
    _write_json(manifest_path, manifest.model_dump(mode="json"))

    contract_path = example / "knowledge-contract.yaml"
    contract_payload = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    assert isinstance(contract_payload, dict)
    contract_payload.pop("knowledge_contract_digest")
    assignments = cast(list[dict[str, object]], contract_payload["assignments"])
    for assignment in assignments:
        if assignment["corpus_digest"] == old_digest:
            assignment["corpus_digest"] = manifest.corpus_digest
    assignments.sort(key=lambda item: cast(str, item["corpus_digest"]))
    contract = RAGSensitivityKnowledgeContract.build(**contract_payload)
    contract_path.write_text(
        yaml.safe_dump(contract.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    baseline_corpus = load_sensitivity_corpus(example / "corpora" / "policy_a")
    counterfactual_corpus = load_sensitivity_corpus(example / "corpora" / "policy_b")
    attestation = RAGSensitivitySyntheticDataAttestation.build(
        attestation_id="operator-attested-nonverdict-fixture",
        suite_digest=bundled_artifacts.protocol.suite_digest,
        fixture_manifest_digest=bundled_artifacts.protocol.fixture_manifest_digest,
        knowledge_contract_digest=contract.knowledge_contract_digest,
        corpus_digests=tuple(
            sorted(
                (
                    bundled_artifacts.protocol.baseline_corpus_digest,
                    manifest.corpus_digest,
                )
            )
        ),
        corpus_snapshot_digests=tuple(
            sorted(
                (
                    baseline_corpus.snapshot.snapshot_digest,
                    counterfactual_corpus.snapshot.snapshot_digest,
                )
            )
        ),
    )
    attestation_path = example / "synthetic-data-attestation.json"
    _write_json(attestation_path, attestation.model_dump(mode="json"))
    artifacts = execute_sensitivity_experiment(
        suite_path=example / "responsive_suite.yaml",
        baseline_corpus_dir=example / "corpora" / "policy_a",
        counterfactual_corpus_dir=example / "corpora" / "policy_b",
        knowledge_contract_path=contract_path,
        expected_relation=EvidenceSensitivityExpectedRelation.decision_flip,
        synthetic_data_attestation_path=attestation_path,
    )
    packet = build_evidence_packet(
        artifacts.counterfactual_evaluation,
        evidence_sensitivity=artifacts.report,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64),
            PacketArtifactDigest(
                role="evidence-sensitivity-report",
                sha256="b" * 64,
            ),
        ),
    )

    direct = gate_evidence_sensitivity_report(artifacts.report)
    packet_default = gate_evidence_packet(packet)
    packet_allowed = gate_evidence_packet(
        packet,
        allow_sensitivity_non_verdict=True,
    )
    packet_strict = gate_evidence_packet(packet, fail_on_not_evaluated=True)

    assert artifacts.report.state is EvidenceSensitivityState.confounded
    assert artifacts.counterfactual_evaluation.state is GateState.pass_
    assert direct.outcome is GateOutcome.not_evaluated
    assert direct.reason_code is EvidenceSensitivityReasonCode.confounded
    assert packet_default.outcome is GateOutcome.invalid
    assert packet_default.exit_code == 2
    assert "--allow-sensitivity-non-verdict" in packet_default.message
    assert packet_allowed.outcome is GateOutcome.not_evaluated
    assert packet_allowed.exit_code == 0
    assert "state=confounded gate_effect=non_verdict" in packet_allowed.message
    assert packet_strict.outcome is GateOutcome.fail
    assert packet_strict.exit_code == 1
    assert packet_strict.reason_code is EvidenceSensitivityReasonCode.confounded

    packet_path = tmp_path / "confounded-packet.json"
    _write_json(packet_path, packet.model_dump(mode="json"))
    cli_default = RUNNER.invoke(app, ["ci", "gate", str(packet_path)])
    cli_allowed = RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--allow-sensitivity-non-verdict",
        ],
    )
    assert cli_default.exit_code == 2
    assert "--allow-sensitivity-non-verdict" in cli_default.output
    assert cli_allowed.exit_code == 0, cli_allowed.output
    assert "state=confounded gate_effect=non_verdict" in cli_allowed.output


def _write_stochastic_packet_inputs(root: Path) -> dict[str, Path]:
    sufficiency, stochastic, sources = _stochastic_reports()
    evaluation = _stochastic_evaluation(sufficiency)
    paths = {
        "evaluation": root / "evaluation-summary.json",
        "sufficiency": root / "statistical-sufficiency-report.json",
        "stochastic": root / "stochastic-evidence-sensitivity.json",
        "baseline": root / "baseline.source.runset.json",
        "counterfactual": root / "counterfactual.source.runset.json",
    }
    _write_json(paths["evaluation"], evaluation.model_dump(mode="json"))
    _write_json(paths["sufficiency"], sufficiency.model_dump(mode="json"))
    _write_json(paths["stochastic"], stochastic.model_dump(mode="json"))
    _write_json(paths["baseline"], sources[0].model_dump(mode="json"))
    _write_json(paths["counterfactual"], sources[1].model_dump(mode="json"))
    return paths


def _stochastic_packet_build_args(inputs: dict[str, Path], out: Path) -> list[str]:
    return [
        "packet",
        "build",
        str(inputs["evaluation"]),
        "--statistical-sufficiency",
        str(inputs["sufficiency"]),
        "--stochastic-evidence-sensitivity",
        str(inputs["stochastic"]),
        "--stochastic-baseline-source-runset",
        str(inputs["baseline"]),
        "--stochastic-counterfactual-source-runset",
        str(inputs["counterfactual"]),
        "--out",
        str(out),
    ]


def _mutate_stochastic_source(path: Path, mutation_kind: str) -> None:
    original_bytes = path.read_bytes()
    if mutation_kind == "in_place":
        path.write_bytes(original_bytes + b" ")
        return
    if mutation_kind == "replacement":
        replacement = path.with_name(f"{path.name}.replacement")
        replacement.write_bytes(original_bytes)
        os.replace(replacement, path)
        return
    raise AssertionError(f"unsupported test mutation kind: {mutation_kind}")


def _packet_owned_output_paths(packet_path: Path) -> tuple[Path, ...]:
    return (
        packet_path,
        packet_path.with_suffix(".md"),
        packet_path.parent / "release-artifact-manifest.json",
        packet_path.parent / "assurance-evidence-graph.json",
        packet_path.parent / "dependency-inventory.json",
    )


def _packet_with_release_manifest(
    root: Path,
    *,
    include_auxiliary: bool,
) -> EvidencePacket:
    evaluation = EvaluationSummary(
        runset_id="manifest-budget-candidate",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_path = root / "evaluation-summary.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    artifacts = [
        ReleaseArtifact(
            role="evaluation-summary",
            path=evaluation_path.name,
            sha256=_file_sha256(evaluation_path),
        )
    ]
    if include_auxiliary:
        auxiliary_path = root / "auxiliary-review.txt"
        auxiliary_path.write_text("bounded auxiliary review\n", encoding="utf-8")
        artifacts.append(
            ReleaseArtifact(
                role="auxiliary-review",
                path=auxiliary_path.name,
                sha256=_file_sha256(auxiliary_path),
            )
        )
    manifest = ReleaseArtifactManifest(
        manifest_id="manifest-budget-test",
        artifacts=tuple(artifacts),
        environment=EnvironmentInfo(platform="test", python_version="3.14"),
    )
    return build_evidence_packet(
        evaluation,
        release_manifest=manifest,
        artifact_digests=(
            PacketArtifactDigest(
                role="evaluation-summary",
                sha256=_file_sha256(evaluation_path),
            ),
        ),
    )


def _manifest_file_snapshots(
    packet: EvidencePacket,
    *,
    root: Path,
) -> dict[str, BoundedFileContents]:
    assert packet.release_manifest is not None
    return {
        artifact.path: path_safety.read_confined_file_snapshot(
            root / artifact.path,
            root=root,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label=f"test {artifact.role} artifact",
        )
        for artifact in packet.release_manifest.artifacts
    }


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def _fixture_runset_digest(runset_id: str) -> str:
    return hashlib.sha256(f"synthetic-runset:{runset_id}".encode()).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
