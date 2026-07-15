from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel
from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.reporting.evidence_diff_html import THESIS_TITLE
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)

RUNNER = CliRunner()
_DIGEST = "b" * 64


def test_diff_render_cli_uses_packet_and_comparison_contract(tmp_path: Path) -> None:
    baseline, candidate, comparison, packet = _artifacts()
    baseline_path = _write_json(tmp_path / "prior-auth.baseline.json", baseline)
    candidate_path = _write_json(tmp_path / "prior-auth.evidence-candidate.json", candidate)
    comparison_path = _write_json(tmp_path / "comparison-summary.json", comparison)
    packet_path = _write_json(tmp_path / "evidence-packet.json", packet)
    out_path = tmp_path / "evidence-diff.html"

    result = RUNNER.invoke(
        app,
        [
            "diff",
            "render",
            "--baseline",
            str(baseline_path),
            "--candidate",
            str(candidate_path),
            "--comparison",
            str(comparison_path),
            "--packet",
            str(packet_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "evidence diff:" in result.output
    html = out_path.read_text(encoding="utf-8")
    assert THESIS_TITLE in html
    assert "CI Gate Blocked Candidate Regression" in html
    assert "Decision-Field Comparison" in html
    assert "<dt>Decision fields (recommendation, outcome)</dt><dd>preserved</dd>" in html
    assert "Process Evidence Diff" in html
    assert "Process scope" in html
    assert "1 of 1 cases" in html
    assert "failed invariant" in html
    assert "Missing Evidence Link Diff" in html
    assert "claim-duration" in html
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in html
    assert "Comparison Classification" in html
    assert ComparisonClassification.new_failure.value in html
    assert "Fixture-Equivalence State" in html
    assert "CI Gate Result" in html
    assert "blocked" in html
    assert str(tmp_path) not in html
    assert "prior-auth.baseline.json" in html
    assert "evidence-packet.json" in html
    assert "<script" not in html.lower()
    assert "http://" not in html.lower()
    assert "https://" not in html.lower()


def test_diff_render_cli_rejects_mismatched_artifact_bundle(tmp_path: Path) -> None:
    baseline, candidate, comparison, packet = _artifacts()
    stale_packet = packet.model_copy(
        update={
            "evaluation": packet.evaluation.model_copy(update={"runset_id": "stale-candidate"})
        }
    )
    baseline_path = _write_json(tmp_path / "baseline.json", baseline)
    candidate_path = _write_json(tmp_path / "candidate.json", candidate)
    comparison_path = _write_json(tmp_path / "comparison-summary.json", comparison)
    packet_path = _write_json(tmp_path / "evidence-packet.json", stale_packet)

    result = RUNNER.invoke(
        app,
        [
            "diff",
            "render",
            "--baseline",
            str(baseline_path),
            "--candidate",
            str(candidate_path),
            "--comparison",
            str(comparison_path),
            "--packet",
            str(packet_path),
            "--out",
            str(tmp_path / "evidence-diff.html"),
        ],
    )

    assert result.exit_code != 0
    assert "packet.evaluation.runset_id" in result.output


def _artifacts() -> tuple[RunSet, RunSet, ComparisonSummary, EvidencePacket]:
    baseline = _runset(
        "baseline",
        _run(
            "shared-source-multi-claim",
            evidence_refs=(
                EvidenceRef(
                    ref_id="evidence-duration",
                    source_id="guideline-duration",
                    claim_ids=("claim-duration",),
                ),
            ),
        ),
    )
    candidate = _runset("candidate", _run("shared-source-multi-claim", evidence_refs=()))
    finding = Finding(
        finding_id="finding-duration",
        case_id="shared-source-multi-claim",
        control_id="material_claims_have_evidence",
        target="claim:claim-duration",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        message="fixture-declared material claim 'claim-duration' has no evidence link",
    )
    candidate_summary = EvaluationSummary(
        runset_id="candidate",
        state=GateState.fail,
        findings=(finding,),
    )
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        classification=ComparisonClassification.new_failure,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.fail,
        verdict_findings=(ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value,),
    )
    packet = EvidencePacket(
        packet_id="packet-duration",
        interpretation=("Candidate omitted a material evidence link.",),
        evaluation=candidate_summary,
        comparison=comparison,
        limitations=("Local deterministic fixture evidence for human review.",),
    )
    return baseline, candidate, comparison, packet


def _runset(runset_id: str, run: AgentRunRecord) -> RunSet:
    return RunSet(
        runset_id=runset_id,
        suite_id="prior-auth-synthetic",
        suite_version="0.1.0",
        suite_digest=_DIGEST,
        fixture_manifest_digest=_DIGEST,
        runs=(run,),
    )


def _run(case_id: str, *, evidence_refs: tuple[EvidenceRef, ...]) -> AgentRunRecord:
    return AgentRunRecord(
        run_id=f"run-{case_id}",
        case_id=case_id,
        pipeline_id="demo",
        recommendation="approve",
        outcome="approve",
        input_summary="redacted fixture input",
        output_summary="redacted fixture output",
        claims=(ClaimRecord(claim_id="claim-duration"),),
        evidence_refs=evidence_refs,
        evidence_items=tuple(
            EvidenceItem(ref_id=ref.ref_id, source_id=ref.source_id, content_digest=_DIGEST)
            for ref in evidence_refs
        ),
        claim_evidence_links=(
            (
                ClaimEvidenceLink(
                    claim_id="claim-duration",
                    evidence_ref_id="evidence-duration",
                ),
            )
            if any(ref.ref_id == "evidence-duration" for ref in evidence_refs)
            else ()
        ),
    )


def _write_json(path: Path, artifact: BaseModel) -> Path:
    path.write_text(
        artifact.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path
