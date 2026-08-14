from __future__ import annotations

import pytest

from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation.catalog import resolve_operator
from agent_assure.mutation.detection import assess_expected_detection
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.mutation import ExpectedDetectionContract, GateEffect
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults


def test_finding_already_present_on_source_is_not_new_detection() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    existing = _finding(
        finding_id="finding-existing-normative",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    source = _report_with_findings(source, (existing,), failed_controls=(existing,))
    candidate = _report_with_findings(source, (existing,), failed_controls=(existing,))

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "survived"
    assert assessment.observed_findings == ()
    assert assessment.matched_finding_ids == ()


def test_unrelated_new_failure_does_not_count_as_caught() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    unrelated = _finding(
        finding_id="finding-unrelated-outcome",
        control_id="expected_recommendation",
        reason_code=ReasonCode.EXPECTED_OUTCOME_MISMATCH,
        target="recommendation",
    )
    candidate = _report_with_findings(
        source,
        (unrelated,),
        failed_controls=(unrelated,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "survived"
    assert assessment.observed_findings == (unrelated,)
    assert assessment.matched_finding_ids == ()


def test_normative_selector_on_wrong_target_does_not_count_as_caught() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    wrong_target = _finding(
        finding_id="finding-right-detector-wrong-target",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:a-different-claim",
    )
    candidate = _report_with_findings(
        source,
        (wrong_target,),
        failed_controls=(wrong_target,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "survived"
    assert assessment.matched_finding_ids == ()


def test_normative_finding_without_required_gate_effect_is_survived() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-normative-nonblocking",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    candidate = _report_with_findings(source, (normative,), failed_controls=())

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "survived"
    assert assessment.matched_finding_ids == ()
    assert "declared block gate effect" in assessment.limitations[0]


def test_nonblocking_raw_failure_matches_normalized_warning_summary() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    raw_failure = _finding(
        finding_id="finding-normalized-nonblocking-failure",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    candidate = _report_with_findings(
        source,
        (raw_failure,),
        failed_controls=(),
        warning_controls=(raw_failure,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert candidate.candidate_vs_expectations.findings[0].state is GateState.warn
    assert candidate.warning_controls[0].state is GateState.fail
    assert assessment.state == "survived"


def test_fail_on_warn_overlap_matches_normalized_failed_summary() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    raw_warning = _finding(
        finding_id="finding-normalized-blocking-warning",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
        state=GateState.warn,
    )
    candidate = _report_with_findings(
        source,
        (raw_warning,),
        failed_controls=(raw_warning,),
        warning_controls=(raw_warning,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert candidate.candidate_vs_expectations.findings[0].state is GateState.fail
    assert candidate.failed_controls[0].state is GateState.warn
    assert assessment.state == "caught"


def test_summary_state_must_match_effective_projection_membership() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    raw_failure = _finding(
        finding_id="finding-forged-normalized-state",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    candidate = _report_with_findings(
        source,
        (raw_failure,),
        failed_controls=(),
        warning_controls=(raw_failure,),
    )
    forged = candidate.candidate_vs_expectations.findings[0].model_copy(
        update={"state": GateState.fail}
    )
    candidate = candidate.model_copy(
        update={
            "candidate_vs_expectations": candidate.candidate_vs_expectations.model_copy(
                update={"findings": (forged,)}
            )
        }
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "invalid_operator"
    assert "gate projections were inconsistent" in assessment.limitations[0]


def test_prohibited_substitute_is_invalid_operator_even_if_normative_finding_exists() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-normative",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    substitute = _finding(
        finding_id="finding-prohibited-substitute",
        control_id="runtime_success_required",
        reason_code=ReasonCode.RUNTIME_FAILED,
        target="run-case-a",
    )
    candidate = _report_with_findings(
        source,
        (normative, substitute),
        failed_controls=(normative, substitute),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "invalid_operator"
    assert assessment.matched_finding_ids == ()
    assert assessment.observed_findings == (normative, substitute)


@pytest.mark.parametrize(
    ("effect", "finding_state", "in_failed", "in_warning", "expected_state"),
    (
        (GateEffect.block, GateState.fail, True, False, "caught"),
        (GateEffect.block, GateState.warn, True, True, "caught"),
        (GateEffect.block, GateState.fail, False, True, "survived"),
        (GateEffect.block, GateState.fail, False, False, "survived"),
        (GateEffect.review, GateState.fail, False, True, "caught"),
        (GateEffect.review, GateState.warn, False, True, "caught"),
        (GateEffect.review, GateState.warn, True, True, "survived"),
        (GateEffect.review, GateState.fail, True, False, "survived"),
        (GateEffect.review, GateState.fail, False, False, "survived"),
        (GateEffect.informational, GateState.not_evaluated, False, False, "caught"),
        (GateEffect.informational, GateState.fail, True, False, "survived"),
        (GateEffect.informational, GateState.fail, False, True, "survived"),
        (GateEffect.ignore, GateState.not_evaluated, False, False, "caught"),
        (GateEffect.ignore, GateState.fail, True, False, "survived"),
        (GateEffect.ignore, GateState.fail, False, True, "survived"),
    ),
)
def test_gate_effect_semantics_are_exact_and_projection_based(
    effect: GateEffect,
    finding_state: GateState,
    in_failed: bool,
    in_warning: bool,
    expected_state: str,
) -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-gate-effect",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
        state=finding_state,
    )
    candidate = _report_with_findings(
        source,
        (normative,),
        failed_controls=(normative,) if in_failed else (),
        warning_controls=(normative,) if in_warning else (),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract_with_effect(effect),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == expected_state
    assert assessment.matched_finding_ids == (
        (normative.finding_id,) if expected_state == "caught" else ()
    )


def test_duplicate_semantically_identical_findings_are_canonicalized() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-duplicate-normative",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    reworded = normative.model_copy(update={"message": "alternate wording"})
    candidate = _report_with_findings(
        source,
        (reworded, normative, reworded),
        failed_controls=(normative, reworded),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "caught"
    assert len(assessment.observed_findings) == 1
    assert assessment.observed_findings[0].finding_id == normative.finding_id
    assert assessment.matched_finding_ids == (normative.finding_id,)


def test_conflicting_candidate_finding_id_is_invalid_operator_with_unique_output() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-conflicting-identity",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    conflicting = normative.model_copy(
        update={
            "control_id": "runtime_success_required",
            "reason_code": ReasonCode.RUNTIME_FAILED,
            "target": "run-case-a",
        }
    )
    candidate = _report_with_findings(
        source,
        (normative, conflicting),
        failed_controls=(normative,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "invalid_operator"
    assert len(assessment.observed_findings) == 1
    assert assessment.observed_findings[0].finding_id == normative.finding_id
    assert assessment.matched_finding_ids == ()


def test_finding_id_rebound_between_source_and_candidate_is_invalid_operator() -> None:
    suite, source_payload = _fixture()
    baseline = evaluate_runset(suite, _runset(source_payload))
    source_finding = _finding(
        finding_id="finding-rebound-identity",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    candidate_finding = source_finding.model_copy(
        update={
            "control_id": "runtime_success_required",
            "reason_code": ReasonCode.RUNTIME_FAILED,
            "target": "run-case-a",
        }
    )
    source = _report_with_findings(
        baseline,
        (source_finding,),
        failed_controls=(source_finding,),
    )
    candidate = _report_with_findings(
        baseline,
        (candidate_finding,),
        failed_controls=(candidate_finding,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "invalid_operator"
    assert assessment.observed_findings == ()
    assert assessment.matched_finding_ids == ()


def test_gate_projection_conflicting_with_summary_is_invalid_operator() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-projection-conflict",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    conflicting_projection = normative.model_copy(update={"target": "claim:a-different-claim"})
    candidate = _report_with_findings(
        source,
        (normative,),
        failed_controls=(conflicting_projection,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "invalid_operator"
    assert assessment.observed_findings == (normative,)
    assert assessment.matched_finding_ids == ()


@pytest.mark.parametrize(
    ("state", "projection"),
    (
        (GateState.pass_, "failed"),
        (GateState.pass_, "warning"),
        (GateState.not_evaluated, "warning"),
    ),
)
def test_gate_projection_rejects_forged_state_semantics(
    state: GateState,
    projection: str,
) -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-forged-projection-state",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
        state=state,
    )
    candidate = _report_with_findings(
        source,
        (normative,),
        failed_controls=(normative,) if projection == "failed" else (),
        warning_controls=(normative,) if projection == "warning" else (),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "invalid_operator"
    assert assessment.matched_finding_ids == ()
    assert "gate projections were inconsistent" in assessment.limitations[0]


def test_failed_finding_cannot_be_in_failed_and_warning_projections() -> None:
    suite, source_payload = _fixture()
    source = evaluate_runset(suite, _runset(source_payload))
    normative = _finding(
        finding_id="finding-forged-overlap",
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-case-a",
    )
    candidate = _report_with_findings(
        source,
        (normative,),
        failed_controls=(normative,),
        warning_controls=(normative,),
    )

    assessment = assess_expected_detection(
        source,
        candidate,
        _contract("drop-material-evidence-link"),
        expected_target="claim:claim-case-a",
    )

    assert assessment.state == "invalid_operator"
    assert assessment.matched_finding_ids == ()


def _contract(operator_id: str) -> ExpectedDetectionContract:
    operator = resolve_operator(operator_id)
    assert operator is not None
    return operator.descriptor.expected_detection_contract


def _contract_with_effect(effect: GateEffect) -> ExpectedDetectionContract:
    base = _contract("drop-material-evidence-link")
    return ExpectedDetectionContract.build(
        operator_id=base.operator_id,
        target_control_ids=base.target_control_ids,
        required_findings=base.required_findings,
        prohibited_substitutes=base.prohibited_substitutes,
        expected_gate_effect=effect,
        secondary_findings_allowed=base.secondary_findings_allowed,
    )


def _runset(payload: dict[str, object]) -> RunSet:
    return RunSet.model_validate(payload)


def _report_with_findings(
    report: EvaluationReport,
    findings: tuple[Finding, ...],
    *,
    failed_controls: tuple[Finding, ...],
    warning_controls: tuple[Finding, ...] = (),
) -> EvaluationReport:
    failed_ids = {finding.finding_id for finding in failed_controls}
    warning_ids = {finding.finding_id for finding in warning_controls}
    normalized_findings = tuple(
        finding.model_copy(
            update={
                "state": (
                    GateState.fail
                    if finding.finding_id in failed_ids
                    else GateState.warn
                    if finding.finding_id in warning_ids
                    else GateState.not_evaluated
                )
            }
        )
        for finding in findings
    )
    summary = report.candidate_vs_expectations.model_copy(
        update={"findings": normalized_findings},
    )
    return report.model_copy(
        update={
            "candidate_vs_expectations": summary,
            "failed_controls": failed_controls,
            "warning_controls": warning_controls,
        }
    )


def _finding(
    *,
    finding_id: str,
    control_id: str,
    reason_code: ReasonCode,
    target: str,
    state: GateState = GateState.fail,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        case_id="case-a",
        control_id=control_id,
        target=target,
        state=state,
        reason_code=reason_code,
        message="synthetic detector result",
    )


def _fixture() -> tuple[CompiledSuite, dict[str, object]]:
    expectation = Expectation(
        expectation_id="expectation-case-a",
        case_id="case-a",
        material_claim_ids=("claim-case-a",),
        forbidden_tools=("blocked-tool-case-a",),
        required_human_review=True,
    )
    suite = CompiledSuite(
        suite_id="mutation-detection-test-suite",
        suite_version="1.0.0",
        defaults=SuiteDefaults(runner_id="mutation.detection.tests"),
        cases=(
            SuiteCase(
                case_id="case-a",
                title="Mutation detection case",
                expectation_id=expectation.expectation_id,
            ),
        ),
        resolved_expectations=(expectation,),
        source_digest="a" * 64,
    )
    fixture_digest = "c" * 64
    run = AgentRunRecord(
        run_id="run-case-a",
        case_id="case-a",
        pipeline_id="mutation-detection-test-pipeline",
        recommendation="approve",
        outcome="approved",
        input_summary="synthetic input",
        output_summary="synthetic output",
        tools=("safe-tool",),
        evidence_items=(
            EvidenceItem(
                ref_id="evidence-case-a",
                source_id="source-case-a",
                content_digest="d" * 64,
            ),
        ),
        claim_evidence_links=(
            ClaimEvidenceLink(
                claim_id="claim-case-a",
                evidence_ref_id="evidence-case-a",
            ),
        ),
        human_review_required=True,
        human_review_performed=True,
        provenance=Provenance(fixture_manifest_digest=fixture_digest),
    )
    runset = RunSet(
        runset_id="mutation-detection-test-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=compiled_suite_digest(suite),
        fixture_manifest_digest=fixture_digest,
        runs=(run,),
    )
    return suite, runset.model_dump(mode="json")
