from __future__ import annotations

import json

from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest


def test_controls_map_cli_writes_json_and_markdown(tmp_path) -> None:  # type: ignore[no-untyped-def]
    packet_path = tmp_path / "evidence-packet.json"
    out_dir = tmp_path / "control-map"
    packet_path.write_text(
        json.dumps(_packet().model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "controls",
            "map",
            str(packet_path),
            "--framework",
            "owasp-llm-top-10-2025",
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    report_json = out_dir / "control-coverage-report.json"
    report_markdown = out_dir / "control-coverage-report.md"
    assert report_json.exists()
    assert report_markdown.exists()
    payload = json.loads(report_json.read_text(encoding="utf-8"))
    assert payload["artifact_kind"] == "control-coverage-report"
    assert payload["framework"] == "owasp-llm-top-10-2025"
    assert payload["evidence_packet_digest"]
    assert "pass/fail" not in report_markdown.read_text(encoding="utf-8").lower()


def _packet() -> EvidencePacket:
    finding = Finding(
        finding_id="finding-material-evidence",
        case_id="case-001",
        control_id="material_claims_have_evidence",
        target="claim:claim-duration",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        message="fixture-declared material claim has no evidence link",
    )
    summary = EvaluationSummary(
        runset_id="candidate-runset",
        state=GateState.fail,
        findings=(finding,),
    )
    return EvidencePacket(
        packet_id="packet-cli-test",
        interpretation=("Review candidate findings before interpreting mappings.",),
        evaluation=summary,
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256="1" * 64),
        ),
        limitations=("fixture evidence only",),
    )
