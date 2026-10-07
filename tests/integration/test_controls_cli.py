from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema import validation as schema_validation
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


def test_controls_map_hashes_the_same_packet_bytes_it_validates(
    tmp_path,
    monkeypatch,
) -> None:  # type: ignore[no-untyped-def]
    packet_path = tmp_path / "evidence-packet.json"
    out_dir = tmp_path / "control-map"
    packet_path.write_text(
        json.dumps(_packet().model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    validated_bytes = packet_path.read_bytes()
    replacement = _packet().model_copy(update={"packet_id": "replacement-packet"})
    original_reader = schema_validation.read_file_bounded_from_filesystem_root
    packet_reads = 0

    def swap_after_packet_read(path: Path, **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal packet_reads
        contents = original_reader(path, **kwargs)  # type: ignore[arg-type]
        if Path(path).resolve() == packet_path.resolve():
            packet_reads += 1
            packet_path.write_text(
                json.dumps(replacement.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )
        return contents

    monkeypatch.setattr(
        schema_validation,
        "read_file_bounded_from_filesystem_root",
        swap_after_packet_read,
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
    payload = json.loads((out_dir / "control-coverage-report.json").read_text(encoding="utf-8"))
    assert packet_reads == 1
    assert payload["evidence_packet_digest"] == hashlib.sha256(validated_bytes).hexdigest()
    assert payload["evidence_packet_digest"] != hashlib.sha256(packet_path.read_bytes()).hexdigest()


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
        runset_digest=hashlib.sha256(b"synthetic-runset:candidate-runset").hexdigest(),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(finding,),
    )
    return EvidencePacket(
        packet_id="packet-cli-test",
        interpretation=("Review candidate findings before interpreting mappings.",),
        evaluation=summary,
        artifact_digests=(PacketArtifactDigest(role="evaluation-summary", sha256="1" * 64),),
        limitations=("fixture evidence only",),
    )
