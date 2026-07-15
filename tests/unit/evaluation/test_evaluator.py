from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from agent_assure.authoring.compiler import compile_suite
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset, runset_digest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.policies.base import ControlResult, GateProfile, Waiver, rollup_state
from agent_assure.policies.evidence import evaluate_material_claim_evidence
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import ExecutionMode, GateState, ReasonCode, Severity
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
    PolicyResult,
    RunSet,
)
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


def test_provider_policy_missing_provider_metadata_fails_closed() -> None:
    compiled, runset = _runset(BASELINE)
    mutated = runset.model_copy(
        update={
            "runs": tuple(
                run.model_copy(update={"provider": None})
                if run.case_id == "forbidden-provider"
                else run
                for run in runset.runs
            )
        }
    )

    report = evaluate_runset(compiled, mutated)

    findings = [
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.case_id == "forbidden-provider"
        and finding.reason_code is ReasonCode.VALID_RECORD_MISSING
    ]
    assert len(findings) == 1
    assert findings[0].control_id == "provider_review_boundary"
    assert findings[0].target == "provider"


def test_required_human_review_must_be_performed() -> None:
    compiled, runset = _runset(BASELINE)
    required_review_cases = {
        expectation.case_id
        for expectation in compiled.resolved_expectations
        if expectation.required_human_review
    }
    target_run = next(run for run in runset.runs if run.case_id in required_review_cases)
    bad_run = target_run.model_copy(
        update={"human_review_required": True, "human_review_performed": False}
    )
    mutated = runset.model_copy(
        update={
            "runs": tuple(
                bad_run if run.case_id == target_run.case_id else run
                for run in runset.runs
            )
        }
    )

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.case_id == target_run.case_id
        and finding.control_id == "human_review_required"
    )
    assert finding.reason_code is ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT
    assert finding.target == "human_review_performed"


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


def test_empty_case_tool_allowlist_overrides_suite_defaults() -> None:
    compiled, runset = _runset(BASELINE)
    target_case_id = runset.runs[0].case_id
    resolved_expectations = tuple(
        expectation.model_copy(
            update={
                "allowed_tools": (),
                "allowed_tools_override": True,
            }
        )
        if expectation.case_id == target_case_id
        else expectation
        for expectation in compiled.resolved_expectations
    )
    mutated_suite = compiled.model_copy(
        update={"resolved_expectations": resolved_expectations}
    )
    mutated_runset = runset.model_copy(
        update={"suite_digest": compiled_suite_digest(mutated_suite)}
    )

    report = evaluate_runset(mutated_suite, mutated_runset)

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


def test_persisted_policy_result_failure_is_verdict_bearing() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(
        update={
            "execution_mode": ExecutionMode.live,
            "policy_results": (
                PolicyResult(
                    artifact_kind="policy-result",
                    policy_id="adapter.injected_policy",
                    state=GateState.fail,
                    reason_codes=(ReasonCode.POLICY_FAILED,),
                    severity=Severity.warning,
                    message="adapter-reported policy failure",
                ),
            )
        }
    )
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == "policy_result:adapter.injected_policy"
    )
    assert finding.reason_code is ReasonCode.POLICY_FAILED


def test_fixture_policy_result_failure_is_verdict_bearing() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(
        update={
            "policy_results": (
                *first_run.policy_results,
                PolicyResult(
                    artifact_kind="policy-result",
                    policy_id="fixture.declared_policy",
                    state=GateState.fail,
                    reason_codes=(ReasonCode.POLICY_FAILED,),
                    severity=Severity.warning,
                    message="fixture-declared policy failure",
                ),
            )
        }
    )
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == "policy_result:fixture.declared_policy"
    )
    assert finding.reason_code is ReasonCode.POLICY_FAILED
    assert finding.state is GateState.fail


def test_required_policy_id_must_be_observed() -> None:
    compiled, runset = _runset(BASELINE)
    mutated = runset.model_copy(
        update={
            "runs": tuple(run.model_copy(update={"policy_results": ()}) for run in runset.runs)
        }
    )

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == "required_policy_evaluated"
    )
    assert finding.target == "provider-selection"
    assert finding.reason_code is ReasonCode.POLICY_FAILED
    assert finding.case_id in {run.case_id for run in runset.runs}
    assert report.metrics.failed_cases == report.metrics.total_cases
    assert report.metrics.global_blocking_findings == 0


def test_required_policy_id_must_be_observed_for_each_case() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(update={"policy_results": ()})
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    findings = [
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == "required_policy_evaluated"
    ]
    assert len(findings) == 1
    assert findings[0].case_id == first_run.case_id
    assert findings[0].target == "provider-selection"
    assert report.metrics.failed_cases == 1


def test_required_policy_id_failure_is_verdict_bearing_in_fixture_mode() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(
        update={
            "policy_results": (
                PolicyResult(
                    artifact_kind="policy-result",
                    policy_id="provider-selection",
                    state=GateState.fail,
                    reason_codes=(ReasonCode.POLICY_FAILED,),
                    severity=Severity.warning,
                    message="fixture policy failure",
                ),
            )
        }
    )
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == "required_policy:provider-selection"
    )
    assert finding.case_id == first_run.case_id
    assert finding.state is GateState.fail
    assert not any(
        finding.control_id == "policy_result:provider-selection"
        for finding in report.candidate_vs_expectations.findings
    )
    assert report.metrics.findings_by_control["required_policy:provider-selection"] == 1
    assert "policy_result:provider-selection" not in report.metrics.findings_by_control


def test_missing_record_counts_as_unevaluated_case_and_blocking_finding() -> None:
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
    assert report.metrics.blocking_findings == 1


def test_incomplete_runset_fails_ordinary_evaluation() -> None:
    compiled, runset = _runset(BASELINE)
    mutated = runset.model_copy(
        update={
            "completion_status": "incomplete",
            "stop_reasons": ("budget_exhausted",),
        }
    )

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == "runset_completion_required"
    )
    assert finding.reason_code is ReasonCode.RUNTIME_FAILED
    assert report.metrics.global_blocking_findings == 1


def test_excluded_observation_fails_ordinary_evaluation() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    excluded = first_run.model_copy(
        update={
            "observation_status": "excluded",
            "exclusion_reason": "pre_provider_filter",
        }
    )
    mutated = runset.model_copy(update={"runs": (excluded, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.case_id == first_run.case_id and finding.target == "observation_status"
    )
    assert finding.reason_code is ReasonCode.VALID_RECORD_MISSING
    assert report.metrics.evaluated_cases == 9
    assert report.metrics.unevaluated_cases == 1
    assert report.metrics.passed_cases == 9
    assert report.metrics.failed_cases == 0
    assert report.metrics.blocking_findings == 1


def test_active_waiver_downgrades_matching_failure_to_warning() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    initial_report = evaluate_runset(compiled, runset)
    finding = initial_report.candidate_vs_expectations.findings[0]
    today = date(2026, 7, 3)
    waiver = Waiver(
        waiver_id="waiver-active",
        owner="quality",
        rationale="temporary fixture review",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        finding_id=finding.finding_id,
        artifact_digest=runset_digest(runset),
        expires_on=today + timedelta(days=1),
        reviewer="assurance",
    )

    report = evaluate_runset(compiled, runset, waivers=(waiver,), today=today)

    assert report.candidate_vs_expectations.state is GateState.warn
    assert report.metrics.blocking_findings == 0
    assert report.candidate_vs_expectations.findings[0].state is GateState.warn


def test_expired_waiver_fails_closed() -> None:
    compiled, runset = _runset(BASELINE)
    today = date(2026, 7, 3)
    waiver = Waiver(
        waiver_id="waiver-expired",
        owner="quality",
        rationale="stale waiver must not suppress gates",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        finding_id="finding-expired",
        artifact_digest=runset_digest(runset),
        expires_on=today - timedelta(days=1),
        reviewer="assurance",
    )

    report = evaluate_runset(compiled, runset, waivers=(waiver,), today=today)

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


def test_fail_on_warn_marks_warning_controls_blocking() -> None:
    warning = ControlResult(
        control_id="policy.warning",
        case_id="case-1",
        state=GateState.warn,
        reason_code=ReasonCode.POLICY_FAILED,
        severity=Severity.warning,
        target="policy.warning",
        message="warning policy result",
    )

    assert GateProfile().is_blocking(warning) is False
    assert rollup_state((warning,), GateProfile()) is GateState.warn
    assert GateProfile(fail_on_warn=True).is_blocking(warning) is True
    assert rollup_state((warning,), GateProfile(fail_on_warn=True)) is GateState.fail


def test_failed_control_blocks_by_default_and_profile_filters_are_active() -> None:
    low_severity_failure = ControlResult(
        control_id="custom.low_severity_failure",
        case_id="case-1",
        state=GateState.fail,
        reason_code=ReasonCode.POLICY_FAILED,
        severity=Severity.info,
        target="custom",
        message="custom control reported fail",
    )

    severity_profile = GateProfile(
        fail_severities=(Severity.error,),
        fail_reason_codes=(),
    )
    reason_profile = GateProfile(
        fail_severities=(),
        fail_reason_codes=(ReasonCode.POLICY_FAILED,),
    )

    assert GateProfile().is_blocking(low_severity_failure) is True
    assert severity_profile.is_blocking(low_severity_failure) is False
    assert rollup_state((low_severity_failure,), severity_profile) is GateState.warn
    assert reason_profile.is_blocking(low_severity_failure) is True
    assert rollup_state((low_severity_failure,), reason_profile) is GateState.fail


def test_nonblocking_failure_rolls_up_as_warning_not_clean_pass() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    profile = GateProfile(
        fail_severities=(Severity.blocker,),
        fail_reason_codes=(),
    )

    report = evaluate_runset(compiled, runset, gate_profile=profile)

    assert report.candidate_vs_expectations.state is GateState.warn
    assert report.failed_controls == ()
    assert len(report.warning_controls) == 1
    assert report.warning_controls[0].state is GateState.fail
    assert (
        report.warning_controls[0].reason_code
        is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
    )
    assert report.metrics.blocking_findings == 0
    assert report.metrics.warning_findings == 1
    assert report.metrics.evaluated_cases == 10
    assert report.metrics.passed_cases == 9
    assert report.metrics.failed_cases == 1


def test_gate_profile_rejects_empty_fail_filters() -> None:
    with pytest.raises(ValueError, match="at least one fail severity or fail reason code"):
        GateProfile(fail_severities=(), fail_reason_codes=())


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


def test_material_claims_require_explicit_claim_evidence_links() -> None:
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

    assert {finding.target for finding in findings} == {
        "claim:claim-present",
        "claim:claim-missing",
    }
    assert all(finding.control_id == "material_claims_have_evidence" for finding in findings)
    assert all(
        finding.reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
        for finding in findings
    )


def test_claim_evidence_links_must_target_evidence_items_not_hollow_refs() -> None:
    run = AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-ref-only-link",
        case_id="case-ref-only-link",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="redacted input",
        output_summary="redacted output",
        evidence_refs=(
            EvidenceRef(
                artifact_kind="evidence-ref",
                ref_id="declared-ref",
                source_id="source-1",
            ),
        ),
        claim_evidence_links=(
            ClaimEvidenceLink(
                artifact_kind="claim-evidence-link",
                claim_id="claim-present",
                evidence_ref_id="declared-ref",
            ),
        ),
    )
    expectation = Expectation(
        artifact_kind="expectation",
        expectation_id="expect-ref-only-link",
        case_id="case-ref-only-link",
        material_claim_ids=("claim-present",),
    )

    findings = evaluate_material_claim_evidence(run, expectation)

    assert {finding.target for finding in findings} == {"claim:claim-present"}


def test_claim_evidence_links_accept_content_addressed_evidence_items() -> None:
    run = AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-item-link",
        case_id="case-item-link",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="redacted input",
        output_summary="redacted output",
        evidence_items=(
            EvidenceItem(
                artifact_kind="evidence-item",
                ref_id="item-ref",
                source_id="source-1",
                content_digest="a" * 64,
            ),
        ),
        claim_evidence_links=(
            ClaimEvidenceLink(
                artifact_kind="claim-evidence-link",
                claim_id="claim-present",
                evidence_ref_id="item-ref",
            ),
        ),
    )
    expectation = Expectation(
        artifact_kind="expectation",
        expectation_id="expect-item-link",
        case_id="case-item-link",
        material_claim_ids=("claim-present",),
    )

    assert evaluate_material_claim_evidence(run, expectation) == ()


def _report(variant: Path) -> EvaluationReport:
    compiled, runset = _runset(variant)
    return evaluate_runset(compiled, runset)


def _runset(variant: Path) -> tuple[CompiledSuite, RunSet]:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(variant), SUITE.parent)
    return compiled, runset


def _reason_codes(summary: EvaluationSummary) -> set[ReasonCode]:
    return {finding.reason_code for finding in summary.findings}
