from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.cli.main import app
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.run import AgentRunRecord, RunSet

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)
EDGE_CASE_ID = "shared-source-multi-claim"
RUNNER = CliRunner()


def test_flagship_showcase_sequence_matches_public_demo(tmp_path: Path) -> None:
    compiled_path = tmp_path / "prior-auth.compiled.json"
    manifest_path = tmp_path / "prior-auth.fixtures.json"
    baseline_path = tmp_path / "prior-auth.baseline.json"
    candidate_path = tmp_path / "prior-auth.evidence-candidate.json"
    baseline_report_dir = tmp_path / "baseline-report"
    candidate_report_dir = tmp_path / "evidence-report"
    comparison_report_dir = tmp_path / "comparison-report"

    _invoke(
        [
            "suite",
            "compile",
            str(SUITE),
            "--out",
            str(compiled_path),
            "--manifest",
            str(manifest_path),
        ],
        expected_exit=0,
    )
    _invoke(
        [
            "suite",
            "run",
            str(compiled_path),
            "--variant",
            str(BASELINE),
            "--manifest",
            str(manifest_path),
            "--out",
            str(baseline_path),
        ],
        expected_exit=0,
    )
    _invoke(
        [
            "suite",
            "run",
            str(compiled_path),
            "--variant",
            str(EVIDENCE_CANDIDATE),
            "--manifest",
            str(manifest_path),
            "--out",
            str(candidate_path),
        ],
        expected_exit=0,
    )

    _invoke(
        [
            "evaluate",
            str(baseline_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(baseline_report_dir),
        ],
        expected_exit=0,
    )
    _invoke(
        [
            "evaluate",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(candidate_report_dir),
        ],
        expected_exit=1,
    )
    _invoke(
        [
            "compare",
            str(baseline_path),
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(comparison_report_dir),
        ],
        expected_exit=1,
    )

    baseline_summary = _json(baseline_report_dir / "evaluation-summary.json")
    candidate_summary = _json(candidate_report_dir / "evaluation-summary.json")
    comparison_summary = _json(comparison_report_dir / "comparison-summary.json")
    baseline_run = _case_run(baseline_path)
    candidate_run = _case_run(candidate_path)

    assert baseline_summary["state"] == GateState.pass_.value
    assert baseline_summary["findings"] == []
    assert candidate_summary["state"] == GateState.fail.value
    findings = candidate_summary["findings"]
    assert isinstance(findings, list)
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, dict)
    assert finding["case_id"] == EDGE_CASE_ID
    assert finding["control_id"] == "material_claims_have_evidence"
    assert finding["target"] == "claim:claim-duration"
    assert finding["reason_code"] == ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value
    assert finding["state"] == GateState.fail.value
    assert (
        finding["message"]
        == "fixture-declared material claim 'claim-duration' has no content-addressed "
        "evidence item link"
    )
    assert comparison_summary["classification"] == ComparisonClassification.new_failure.value
    assert comparison_summary["fixture_equivalence_state"] == GateState.pass_.value
    assert comparison_summary["baseline_state"] == GateState.pass_.value
    assert comparison_summary["candidate_state"] == GateState.fail.value
    assert baseline_run.recommendation == candidate_run.recommendation == "approve"
    assert baseline_run.outcome == candidate_run.outcome == "approve"
    assert _claim_ids(baseline_run) == {"claim-duration", "claim-eligibility"}
    assert _claim_ids(candidate_run) == {"claim-eligibility"}


def _invoke(args: list[str], *, expected_exit: int) -> None:
    result = RUNNER.invoke(app, args)
    assert result.exit_code == expected_exit, result.output


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _case_run(runset_path: Path) -> AgentRunRecord:
    runset = RunSet.model_validate_json(runset_path.read_text(encoding="utf-8"))
    runs = {run.case_id: run for run in runset.runs}
    return runs[EDGE_CASE_ID]


def _claim_ids(run: AgentRunRecord) -> set[str]:
    return {claim_id for ref in run.evidence_refs for claim_id in ref.claim_ids}
