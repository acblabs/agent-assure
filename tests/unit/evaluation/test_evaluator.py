from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset, runset_digest
from agent_assure.policies.base import ControlResult, GateProfile, Waiver
from agent_assure.policies.evidence import evaluate_material_claim_evidence
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import AgentRunRecord, EvidenceRef, RunSet
from agent_assure.schema.suite import CompiledSuite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)
PROVIDER_CANDIDATE = Path("examples/prior_auth_synthetic/variants/candidate_provider_policy.yaml")
SMOKE_CANDIDATE = Path("examples/prior_auth_synthetic/variants/candidate_smoke_fail.yaml")


def test_baseline_evaluation_passes_with_not_evaluated_capabilities_separate() -> None:
    report = _report(BASELINE)

    assert report.candidate_vs_expectations.state is GateState.pass_
    assert report.candidate_vs_expectations.findings == ()
    assert report.metrics.failed_cases == 0
    assert report.metrics.evaluated_cases == report.metrics.total_cases
    assert report.metrics.global_blocking_findings == 0
    assert "tool_allowlist" not in {
        capability.capability_id for capability in report.not_evaluated_capabilities
    }
    assert all(
        capability.state is GateState.not_evaluated
        for capability in report.not_evaluated_capabilities
    )


def test_evidence_candidate_fails_material_claim_invariant() -> None:
    report = _report(EVIDENCE_CANDIDATE)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert _reason_codes(report.candidate_vs_expectations) == {
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
    }
    finding = report.candidate_vs_expectations.findings[0]
    assert finding.case_id == "shared-source-multi-claim"
    assert "fixture-declared material claim" in finding.message


def test_provider_candidate_fails_provider_policy_control() -> None:
    report = _report(PROVIDER_CANDIDATE)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.FORBIDDEN_PROVIDER in _reason_codes(
        report.candidate_vs_expectations
    )


def test_smoke_candidate_fails_multiple_controls() -> None:
    report = _report(SMOKE_CANDIDATE)
    reason_codes = _reason_codes(report.candidate_vs_expectations)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE in reason_codes
    assert ReasonCode.FORBIDDEN_PROVIDER in reason_codes
    assert ReasonCode.RUNTIME_FAILED in reason_codes


def test_tool_allowlist_failure_is_reachable() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(update={"tools": ("unexpected_tool",)})
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.FORBIDDEN_TOOL in _reason_codes(report.candidate_vs_expectations)


def test_structured_output_failure_is_reachable() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(update={"outcome": ""})
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.STRUCTURED_OUTPUT_INVALID in _reason_codes(
        report.candidate_vs_expectations
    )


def test_raw_sensitive_summary_is_verdict_bearing_redaction_failure() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(update={"input_summary": "patient=Jane ssn: 123-45-6789"})
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.RAW_SENSITIVE_CONTENT in _reason_codes(
        report.candidate_vs_expectations
    )


def test_missing_record_counts_as_unevaluated_not_failed_case() -> None:
    compiled, runset = _runset(BASELINE)
    mutated = runset.model_copy(update={"runs": runset.runs[1:]})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.VALID_RECORD_MISSING in _reason_codes(
        report.candidate_vs_expectations
    )
    assert report.metrics.total_cases == 10
    assert report.metrics.evaluated_cases == 9
    assert report.metrics.unevaluated_cases == 1
    assert report.metrics.passed_cases == 9
    assert report.metrics.failed_cases == 0
    assert (
        report.metrics.passed_cases
        + report.metrics.failed_cases
        + report.metrics.unevaluated_cases
        == report.metrics.total_cases
    )


def test_active_waiver_downgrades_matching_failure_to_warning() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    initial_report = evaluate_runset(compiled, runset)
    finding = initial_report.candidate_vs_expectations.findings[0]
    waiver = Waiver(
        waiver_id="waiver-active",
        owner="quality",
        rationale="temporary fixture review",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        finding_id=finding.finding_id,
        artifact_digest=runset_digest(runset),
        expires_on=date.today() + timedelta(days=1),
        reviewer="assurance",
    )

    report = evaluate_runset(compiled, runset, waivers=(waiver,))

    assert report.candidate_vs_expectations.state is GateState.warn
    assert report.metrics.blocking_findings == 0
    assert report.candidate_vs_expectations.findings[0].state is GateState.warn


def test_expired_waiver_fails_closed() -> None:
    compiled, runset = _runset(BASELINE)
    waiver = Waiver(
        waiver_id="waiver-expired",
        owner="quality",
        rationale="stale waiver must not suppress gates",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        finding_id="finding-expired",
        artifact_digest=runset_digest(runset),
        expires_on=date.today() - timedelta(days=1),
        reviewer="assurance",
    )

    report = evaluate_runset(compiled, runset, waivers=(waiver,))

    assert report.candidate_vs_expectations.state is GateState.fail
    assert _reason_codes(report.candidate_vs_expectations) == {ReasonCode.POLICY_FAILED}
    assert report.metrics.failed_cases == 0
    assert report.metrics.global_blocking_findings == 1


def test_fail_on_not_evaluated_marks_capabilities_blocking() -> None:
    compiled, runset = _runset(BASELINE)

    report = evaluate_runset(
        compiled,
        runset,
        gate_profile=GateProfile(fail_on_not_evaluated=True),
    )

    assert report.candidate_vs_expectations.state is GateState.fail
    assert _reason_codes(report.candidate_vs_expectations) == {ReasonCode.NOT_EVALUATED}
    assert report.metrics.global_blocking_findings == len(report.failed_controls)


def test_finding_id_is_stable_across_message_rewording() -> None:
    first = ControlResult(
        control_id="material_claims_have_evidence",
        case_id="case-1",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        severity=Severity.error,
        target="claim:alpha",
        message="old wording",
    )
    second = ControlResult(
        control_id="material_claims_have_evidence",
        case_id="case-1",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        severity=Severity.error,
        target="claim:alpha",
        message="new wording",
    )

    assert first.finding_id == second.finding_id


def test_material_claim_fallback_without_explicit_links_preserves_reason_code() -> None:
    run = AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-no-links",
        case_id="case-no-links",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="redacted input",
        output_summary="redacted output",
        evidence_refs=(
            EvidenceRef(
                artifact_kind="evidence-ref",
                ref_id="evidence-1",
                source_id="source-1",
                claim_ids=("claim-present",),
            ),
        ),
        claim_evidence_links=(),
    )
    expectation = Expectation(
        artifact_kind="expectation",
        expectation_id="expect-no-links",
        case_id="case-no-links",
        material_claim_ids=("claim-present", "claim-missing"),
    )

    findings = evaluate_material_claim_evidence(run, expectation)

    assert len(findings) == 1
    assert findings[0].control_id == "material_claims_have_evidence"
    assert findings[0].target == "claim:claim-missing"
    assert findings[0].reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE


def _report(variant: Path) -> EvaluationReport:
    compiled, runset = _runset(variant)
    return evaluate_runset(compiled, runset)


def _runset(variant: Path) -> tuple[CompiledSuite, RunSet]:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(variant), SUITE.parent)
    return compiled, runset


def _reason_codes(summary: EvaluationSummary) -> set[ReasonCode]:
    return {finding.reason_code for finding in summary.findings}
