from __future__ import annotations

from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.evidence_diff_html import render_evidence_diff_html
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.run import AgentRunRecord, RunSet

_DIGEST = "0" * 64


def test_evidence_diff_marks_missing_candidate_case_as_changed() -> None:
    baseline = _runset(
        "baseline",
        (
            _run("case-a", outcome="approve"),
            _run("case-b", outcome="manual_review"),
        ),
    )
    candidate = _runset("candidate", (_run("case-a", outcome="approve"),))

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        baseline_summary=EvaluationSummary(
            runset_id="baseline",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ),
        candidate_summary=EvaluationSummary(
            runset_id="candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            state=GateState.pass_,
        ),
        comparison_summary=ComparisonSummary(
            baseline_runset_id="baseline",
            candidate_runset_id="candidate",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            classification=ComparisonClassification.not_evaluated,
            fixture_equivalence_state=GateState.not_evaluated,
            baseline_state=GateState.pass_,
            candidate_state=GateState.pass_,
        ),
    )

    assert "<dt>Decision fields (recommendation, outcome)</dt><dd>changed</dd>" in html
    assert "<dt>Case coverage</dt><dd>missing candidate cases: case-b</dd>" in html
    assert "<td>case-b</td>" in html
    assert "&lt;missing&gt;" in html


def _run(case_id: str, *, outcome: str) -> AgentRunRecord:
    return AgentRunRecord(
        run_id=f"run-{case_id}",
        case_id=case_id,
        pipeline_id="demo",
        recommendation="approve",
        outcome=outcome,
        input_summary="fixture input",
        output_summary="fixture output",
    )


def _runset(runset_id: str, runs: tuple[AgentRunRecord, ...]) -> RunSet:
    return RunSet(
        runset_id=runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="demo",
        suite_version="0.1.0",
        suite_digest=_DIGEST,
        fixture_manifest_digest=_DIGEST,
        runs=runs,
    )
