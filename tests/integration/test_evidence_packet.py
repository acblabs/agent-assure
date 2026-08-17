from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import agent_assure.cli.packet_cmd as packet_cmd
import agent_assure.onboarding.path_safety as path_safety
from agent_assure.ci import GateOutcome, gate_evidence_packet
from agent_assure.cli.main import app
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.reporting.packet import (
    build_evidence_packet,
    load_evaluation_summary_snapshot,
    load_evidence_packet,
    packet_artifact_digest_from_snapshot,
    release_artifact_from_summary_snapshot,
)
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from tests.unit.controls.test_control_efficacy import _DROP_OPERATOR, _campaign

RUNNER = CliRunner()


def test_evidence_packet_schema_exists() -> None:
    packet = EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id="packet-001",
        evaluation=EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="runset-001",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.not_evaluated,
        ),
        comparison=ComparisonSummary(
            artifact_kind="comparison-summary",
            baseline_runset_id="baseline",
            candidate_runset_id="runset-001",
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


def test_evidence_packet_rejects_mismatched_privacy_detector_profiles() -> None:
    evaluation = EvaluationSummary(
        runset_id="candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
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
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
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


def test_packet_build_cli_writes_digested_packet_and_ci_gate_fails_it(tmp_path: Path) -> None:
    evaluation = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
    )
    comparison = ComparisonSummary(
        artifact_kind="comparison-summary",
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
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


def test_packet_graph_cli_round_trips_bound_graph_and_rejects_mismatch_and_alias(
    tmp_path: Path,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="round-trip-candidate",
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
    evaluation = EvaluationSummary(
        runset_id="relocated-packet-candidate",
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

    mutation_result = _campaign(operator_ids=(_DROP_OPERATOR,)).campaign.operator_results[0].result
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
    evaluation = EvaluationSummary(
        runset_id="enriched-graph-candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    mutation_result = _campaign(operator_ids=(_DROP_OPERATOR,)).campaign.operator_results[0].result
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
    assert mutation_subject_id != enriched_payload["primary_subject_node_id"]
    assert mutation_subject["payload"]["subject_id"] == (f"sha256:{mutation_result.source_digest}")
    assert mutation_subject["payload"]["subject_digest"] == (mutation_result.source_digest)


def test_packet_graph_cli_bounds_aggregate_mutation_input_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="bounded-enrichment-candidate",
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


def test_packet_build_rollback_refuses_to_clobber_concurrent_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = EvaluationSummary(
        runset_id="rollback-concurrency-candidate",
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
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )
    evaluation_payload = evaluation.model_dump(mode="json")
    evaluation_payload["schema_version"] = "0.6.1"
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


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
