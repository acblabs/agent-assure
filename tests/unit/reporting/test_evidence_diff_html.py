from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agent_assure.reporting.evidence_diff_html import THESIS_TITLE, render_evidence_diff_html
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceRef,
    RunSet,
)

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.check_claim_boundaries as claim_boundaries  # noqa: E402
import scripts.update_golden as update_golden  # noqa: E402

_DIGEST = "a" * 64


def test_evidence_diff_html_surfaces_punchline_without_raw_json() -> None:
    baseline, candidate, comparison, packet = _artifacts()

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        packet=packet,
        artifact_paths={
            "baseline run set": "baseline.json",
            "candidate run set": "candidate.json",
        },
    )

    assert THESIS_TITLE in html
    assert "This report is not a compliance attestation." in html
    assert "This artifact does not certify safety." in html
    assert "CI Gate Blocked Candidate Regression" in html
    assert html.index("CI Gate Blocked Candidate Regression") < html.index(
        "Decision-Field Comparison"
    )
    assert "<dt>Decision fields (recommendation, outcome)</dt><dd>preserved</dd>" in html
    assert "Process regression" in html
    assert "caught" in html
    assert "Process scope" in html
    assert "1 of 1 cases" in html
    assert "1 missing material-claim link of 1 baseline claim link" in html
    assert "1 material claim link regression" in html
    assert "CI gate" in html
    assert "blocked" in html
    assert "state-expected" in html
    assert "Process Evidence Diff" in html
    assert "Process-affected cases are sourced from candidate findings" in html
    assert "caught:" not in html
    assert 'data-label="Changed fields"' in html
    assert 'data-label="Claim-evidence links"' in html
    assert 'data-label="Provider/model"' in html
    assert 'class="key-finding-table"' in html
    assert '<div class="cell-value">' in html
    assert "diff-removed-token" in html
    assert ".key-finding-table td::before" in html
    assert ".process-diff-table td::before" in html
    assert ".process-evidence-table td::before" in html
    assert "content: attr(data-label)" in html
    assert "@media screen" in html
    assert "grid-template-columns: repeat(4, minmax(0, 1fr));" in html
    assert ".process-diff-table td:nth-child(6)" in html
    assert 'class="wrap-token"' in html
    assert "code.wrap-token" in html
    assert ".value-list li" in html
    assert "grid-template-rows: auto auto auto auto 1fr;" in html
    assert "align-self: start;" in html
    assert '<td class="state-good">' not in html
    assert '<td class="state-bad">' not in html
    assert "table-layout: fixed" not in html
    assert "min-width: 1120px" not in html
    assert "min-width: 300px" not in html
    assert "code {\n  display: inline-block;" in html
    assert "white-space: nowrap;" in html
    assert "hyphens: none" in html
    assert "border-radius: 999px" not in html
    assert "claim-duration" in html
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in html
    assert "compiled-suite" in html
    assert "compiled.json" in html
    assert "Retrieval corpus digest" not in html
    assert "artifact_kind" not in html


def test_evidence_diff_html_missing_link_panel_agrees_with_material_finding() -> None:
    baseline, candidate, comparison, packet = _artifacts()

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        packet=packet,
    )

    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in html
    assert "No missing evidence links were observed." not in html
    assert "No baseline evidence links were missing from the candidate run set." not in html
    assert "Key Finding" in html
    assert "1 material claim link regression" in html
    assert "failed invariant" in html
    missing_section = html[html.index("Missing Evidence Link Diff") :]
    assert "claim-duration" in missing_section
    assert "evidence-duration" in missing_section


def test_flagship_golden_fixture_missing_link_panel_agrees_with_finding() -> None:
    html = update_golden._evidence_diff_html()

    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in html
    assert "No missing evidence links were observed." not in html
    assert "No baseline evidence links were missing from the candidate run set." not in html
    assert "CI Gate Blocked Candidate Regression" in html
    assert "Process Evidence Diff" in html
    assert "1 material claim link regression" in html


def test_evidence_diff_html_escapes_dynamic_content_and_stays_static() -> None:
    baseline, candidate, comparison, packet = _artifacts(
        case_id='case-<script>alert("x")</script>',
        finding_message='missing evidence <script src="https://evil.example/x.js"></script>',
    )

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        packet=packet,
    )
    lowered = html.lower()

    assert "&lt;script&gt;" in html
    assert "<script" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "raw_prompt" not in html
    assert "tool_args" not in html
    assert "input_summary" not in html


def test_evidence_diff_html_rendered_output_passes_claim_boundary_linter() -> None:
    baseline, candidate, comparison, packet = _artifacts()

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        packet=packet,
    )

    assert claim_boundaries.find_claim_boundary_violations(
        html,
        path=Path("tests/golden/reports/evidence-diff.html"),
    ) == []


def test_evidence_diff_html_rejects_mismatched_packet_binding() -> None:
    baseline, candidate, comparison, packet = _artifacts()
    stale_evaluation = packet.evaluation.model_copy(update={"runset_id": "stale-candidate"})
    stale_packet = packet.model_copy(update={"evaluation": stale_evaluation})

    with pytest.raises(ValueError, match="packet.evaluation.runset_id"):
        render_evidence_diff_html(
            baseline=baseline,
            candidate=candidate,
            comparison_summary=comparison,
            packet=stale_packet,
        )


def test_evidence_diff_html_rejects_packet_state_contradicting_comparison() -> None:
    baseline, candidate, comparison, packet = _artifacts()
    contradictory_packet = packet.model_copy(
        update={"evaluation": packet.evaluation.model_copy(update={"state": GateState.pass_})}
    )

    with pytest.raises(ValueError, match="packet.evaluation.state"):
        render_evidence_diff_html(
            baseline=baseline,
            candidate=candidate,
            comparison_summary=comparison,
            packet=contradictory_packet,
        )


def test_evidence_diff_html_rejects_summary_state_contradicting_comparison() -> None:
    baseline, candidate, comparison, packet = _artifacts()
    baseline_summary = EvaluationSummary(runset_id="baseline", state=GateState.fail)
    candidate_summary = packet.evaluation

    with pytest.raises(ValueError, match="baseline_summary.state"):
        render_evidence_diff_html(
            baseline=baseline,
            candidate=candidate,
            comparison_summary=comparison,
            baseline_summary=baseline_summary,
            candidate_summary=candidate_summary,
            packet=packet,
        )


def test_evidence_diff_html_rejects_duplicate_case_ids_before_rendering() -> None:
    _, candidate, comparison, packet = _artifacts()
    duplicate_run = _run("shared-source-multi-claim", evidence_refs=()).model_copy(
        update={"run_id": "run-shared-source-multi-claim-duplicate"}
    )
    baseline = RunSet(
        runset_id="baseline",
        suite_id="prior-auth-synthetic",
        suite_version="0.1.0",
        suite_digest=_DIGEST,
        fixture_manifest_digest=_DIGEST,
        runs=(
            _run("shared-source-multi-claim", evidence_refs=()),
            duplicate_run,
        ),
    )

    with pytest.raises(ValueError, match="duplicate case_id"):
        render_evidence_diff_html(
            baseline=baseline,
            candidate=candidate,
            comparison_summary=comparison,
            packet=packet,
        )


def test_evidence_diff_html_summarizes_long_comparison_lists() -> None:
    baseline, candidate, comparison, packet = _artifacts()
    long_changes = tuple(
        f"case-{index} config_digest baseline={'a' * 64} candidate={'b' * 64}"
        for index in range(6)
    )
    comparison = comparison.model_copy(update={"provenance_changes": long_changes})
    packet = packet.model_copy(update={"comparison": comparison})

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        packet=packet,
    )

    assert "6 items; first 4 shown" in html
    assert "case-5 config_digest" not in html


def test_evidence_diff_html_ignores_display_only_evidence_ref_claim_ids() -> None:
    baseline, candidate, comparison, packet = _artifacts()
    candidate_run = _run(
        "shared-source-multi-claim",
        evidence_refs=(
            EvidenceRef(
                ref_id="evidence-duration",
                source_id="guideline-duration",
                claim_ids=("claim-duration",),
            ),
        ),
        link_claims=False,
    )
    candidate = candidate.model_copy(update={"runs": (candidate_run,)})

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        packet=packet,
    )

    assert "No missing evidence links were observed." not in html
    assert "claim-duration" in html
    assert "evidence-duration" in html


def test_evidence_diff_html_handles_unscoped_findings_without_zero_case_claim() -> None:
    evidence_ref = EvidenceRef(
        ref_id="evidence-duration",
        source_id="guideline-duration",
        claim_ids=("claim-duration",),
    )
    baseline = _runset("baseline", _run("case-a", evidence_refs=(evidence_ref,)))
    candidate = _runset("candidate", _run("case-a", evidence_refs=(evidence_ref,)))
    finding = Finding(
        finding_id="finding-unscoped",
        case_id="",
        control_id="material_claims_have_evidence",
        target="claim:claim-duration",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        message="fixture-declared material claim has no evidence link",
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

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
        candidate_summary=candidate_summary,
    )

    assert "0 of 1 cases + 1 unscoped" in html
    assert "without case IDs (1 unscoped finding)" in html
    assert "1 process finding does not include a case ID" in html
    assert "unscoped" in html
    assert "across 0 process-affected cases" not in html


def test_evidence_diff_html_surfaces_non_claim_process_changed_fields() -> None:
    evidence_ref = EvidenceRef(
        ref_id="evidence-duration",
        source_id="guideline-duration",
        claim_ids=("claim-duration",),
    )
    baseline = _runset("baseline", _run("case-a", evidence_refs=(evidence_ref,)))
    candidate_run = _run("case-a", evidence_refs=(evidence_ref,)).model_copy(
        update={"tools": ("alternate-tool",)}
    )
    candidate = _runset("candidate", candidate_run)
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        classification=ComparisonClassification.provenance_only_change,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.pass_,
    )

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
    )

    assert "Changed fields" in html
    assert "<code>tools</code>" in html
    assert "alternate-tool" in html
    assert "changed" in html
    assert "Claim-evidence links" in html
    assert "failed invariant" not in html


def test_evidence_diff_html_surfaces_changed_retrieval_corpus_digest() -> None:
    baseline, candidate, comparison, _packet = _artifacts()
    baseline_digest = "1" * 64
    candidate_digest = "2" * 64
    baseline_run = baseline.runs[0].model_copy(
        update={
            "provenance": baseline.runs[0].provenance.model_copy(
                update={"retrieval_corpus_digest": baseline_digest}
            )
        }
    )
    candidate_run = candidate.runs[0].model_copy(
        update={
            "provenance": candidate.runs[0].provenance.model_copy(
                update={"retrieval_corpus_digest": candidate_digest}
            )
        }
    )
    baseline = baseline.model_copy(update={"runs": (baseline_run,)})
    candidate = candidate.model_copy(update={"runs": (candidate_run,)})

    html = render_evidence_diff_html(
        baseline=baseline,
        candidate=candidate,
        comparison_summary=comparison,
    )

    assert "Retrieval corpus digest" in html
    assert '<span class="state-bad">changed</span>' in html
    assert baseline_digest in html
    assert candidate_digest in html


def _artifacts(
    *,
    case_id: str = "shared-source-multi-claim",
    finding_message: str = "fixture-declared material claim has no evidence link",
) -> tuple[RunSet, RunSet, ComparisonSummary, EvidencePacket]:
    baseline = _runset(
        "baseline",
        _run(
            case_id,
            evidence_refs=(
                EvidenceRef(
                    ref_id="evidence-duration",
                    source_id="guideline-duration",
                    claim_ids=("claim-duration",),
                ),
            ),
        ),
    )
    candidate = _runset(
        "candidate",
        _run(case_id, evidence_refs=()),
    )
    finding = Finding(
        finding_id="finding-duration",
        case_id=case_id,
        control_id="material_claims_have_evidence",
        target="claim:claim-duration",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        message=finding_message,
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
        artifact_digests=(
            PacketArtifactDigest(role="evaluation-summary", sha256=_DIGEST),
        ),
        release_manifest=ReleaseArtifactManifest(
            manifest_id="manifest-duration",
            artifacts=(
                ReleaseArtifact(role="compiled-suite", path="compiled.json", sha256=_DIGEST),
                ReleaseArtifact(role="candidate-runset", path="candidate.json", sha256=_DIGEST),
            ),
            environment=EnvironmentInfo(platform="test", python_version="3.11.0"),
        ),
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


def _run(
    case_id: str,
    *,
    evidence_refs: tuple[EvidenceRef, ...],
    link_claims: bool = True,
) -> AgentRunRecord:
    claim_evidence_links = (
        (
            ClaimEvidenceLink(
                claim_id="claim-duration",
                evidence_ref_id="evidence-duration",
            ),
        )
        if link_claims and any(ref.ref_id == "evidence-duration" for ref in evidence_refs)
        else ()
    )
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
        claim_evidence_links=claim_evidence_links,
        tools=("benefit-policy-lookup",),
    )
