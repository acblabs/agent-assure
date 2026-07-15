from __future__ import annotations

import json

from agent_assure.authoring.compiler import compile_suite
from agent_assure.compare.runsets import compare_runsets
from agent_assure.examples.adk_process_assurance.runner import (
    CANDIDATE_DELEGATION_ROUTE,
    CANDIDATE_REVIEW_ROUTE,
    RAW_REQUEST,
    SUITE_PATH,
    evaluate_variant,
    run_offline_example,
    run_variant,
)
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode


def test_adk_process_example_runs_offline() -> None:
    summary = run_offline_example()

    assert summary["status"] == "success"
    assert summary["adk_execution"] == "synthetic-adk-events"
    assert summary["baseline_state"] == GateState.pass_.value
    assert summary["candidate_state"] == GateState.fail.value
    assert summary["same_final_decision"] is True
    assert summary["candidate_review_route"] == CANDIDATE_REVIEW_ROUTE
    assert summary["candidate_delegation_route"] == CANDIDATE_DELEGATION_ROUTE
    assert summary["candidate_human_review_required"] is False


def test_adk_baseline_passes_and_candidate_fails_process_invariant() -> None:
    baseline_report = evaluate_variant("baseline")
    candidate_report = evaluate_variant("candidate_review_bypass")

    assert baseline_report.candidate_vs_expectations.state is GateState.pass_
    assert candidate_report.candidate_vs_expectations.state is GateState.fail
    reason_codes = {
        finding.reason_code for finding in candidate_report.candidate_vs_expectations.findings
    }
    assert ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT in reason_codes
    assert ReasonCode.REVIEW_BOUNDARY_FAILED in reason_codes


def test_adk_candidate_preserves_final_answer_evidence_and_omits_raw_payloads() -> None:
    baseline = run_variant("baseline")
    candidate = run_variant("candidate_review_bypass")
    baseline_run = baseline.runs[0]
    candidate_run = candidate.runs[0]

    assert candidate_run.recommendation == baseline_run.recommendation
    assert candidate_run.outcome == baseline_run.outcome
    assert candidate_run.evidence_refs == baseline_run.evidence_refs
    assert candidate_run.provider == baseline_run.provider
    assert candidate_run.tools == baseline_run.tools
    assert candidate_run.human_review_required is False
    assert candidate_run.human_review_performed is False
    assert candidate_run.usage_summary is not None
    assert candidate_run.usage_summary.total_tokens == 17
    assert RAW_REQUEST not in json.dumps(candidate.model_dump(mode="json"), sort_keys=True)


def test_adk_same_decision_candidate_classifies_as_new_failure() -> None:
    compiled = compile_suite(SUITE_PATH)
    baseline = run_variant("baseline")
    candidate = run_variant("candidate_review_bypass")

    report = compare_runsets(compiled, baseline, candidate)

    assert report.comparison_summary.classification is ComparisonClassification.new_failure
    assert report.comparison_summary.baseline_state is GateState.pass_
    assert report.comparison_summary.candidate_state is GateState.fail
