from __future__ import annotations

import json
from datetime import date, timedelta
from inspect import signature
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

import agent_assure.ci as ci_module
from agent_assure.authoring.compiler import compile_suite
from agent_assure.ci import gate_evaluation_summary
from agent_assure.evaluation.evaluator import (
    EvaluationCaseOutcome,
    EvaluationReport,
    EvaluationSourceVerificationError,
    evaluate_runset,
    load_runset,
    load_runset_with_size,
    runset_digest,
    verify_evaluation_report_sources,
)
from agent_assure.evaluation.expectations import ExpectationResolver
from agent_assure.evaluation.invariants import evaluate_case
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.io_limits import MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
from agent_assure.policies.base import (
    ControlResult,
    GateProfile,
    Waiver,
    control_finding_id,
    rollup_state,
)
from agent_assure.policies.evidence import (
    claim_finding_target,
    evaluate_material_claim_evidence,
)
from agent_assure.policies.providers import evaluate_provider_boundary
from agent_assure.reporting.markdown import render_evaluation_markdown
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import (
    BLOCKED_PROVIDER_SELECTION,
    GateState,
    ReasonCode,
    Severity,
)
from agent_assure.schema.evaluation import (
    EvaluationSummary,
    WaiverDispositionStatus,
)
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    EvidenceRef,
    LiveNetworkAuthorityReceipt,
    PolicyResult,
    RunSet,
    StructuredFieldOrigin,
    StructuredFieldOrigins,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import validate_artifact_payload

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)
PROVIDER_CANDIDATE = Path("examples/prior_auth_synthetic/variants/candidate_provider_policy.yaml")
SMOKE_CANDIDATE = Path("examples/prior_auth_synthetic/variants/candidate_smoke_fail.yaml")
AUTHORIZED_EVALUATION_DATE = date(2026, 1, 15)


def test_baseline_evaluation_passes_with_not_evaluated_capabilities_separate() -> None:
    report = _report(BASELINE)

    assert report.candidate_vs_expectations.state is GateState.pass_
    assert report.candidate_vs_expectations.findings == ()
    assert report.waiver_dispositions == ()
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
    assert len(report.case_outcomes) == report.metrics.total_cases
    assert all(outcome.state is GateState.pass_ for outcome in report.case_outcomes)
    assert {capability.capability_id for capability in report.capability_coverage} == {
        "live_stochastic_model_quality_regression",
        "production_runtime_isolation",
        "raw_payload_persistence_forbidden",
        "regulatory_compliance_certification",
        "tool_allowlist",
    }
    assert (
        next(
            capability
            for capability in report.capability_coverage
            if capability.capability_id == "tool_allowlist"
        ).state
        is GateState.pass_
    )
    assert report.source_projection is not None
    assert tuple(item.case_id for item in report.source_projection.cases) == tuple(
        item.case_id for item in report.case_outcomes
    )
    assert all(item.record_status == "included" for item in report.source_projection.cases)


def test_evaluate_runset_rejects_unsafe_nested_source_before_scoring() -> None:
    compiled, runset = _runset(BASELINE)
    ref_id = "typed-boundary-ref"
    source_id = "typed-boundary-source"
    forged_link = ClaimEvidenceLink(
        artifact_kind="claim-evidence-link",
        claim_id="typed-boundary-claim",
        evidence_ref_id=ref_id,
    ).model_copy(update={"artifact_kind": "evidence-ref"})
    first_run = runset.runs[0]
    unsafe_run = first_run.model_copy(
        update={
            "evidence_refs": (
                *first_run.evidence_refs,
                EvidenceRef(
                    artifact_kind="evidence-ref",
                    ref_id=ref_id,
                    source_id=source_id,
                ),
            ),
            "evidence_items": (
                *first_run.evidence_items,
                EvidenceItem(
                    artifact_kind="evidence-item",
                    ref_id=ref_id,
                    source_id=source_id,
                    content_digest="a" * 64,
                ),
            ),
            "claim_evidence_links": (*first_run.claim_evidence_links, forged_link),
        }
    )
    unsafe_runset = runset.model_copy(update={"runs": (unsafe_run, *runset.runs[1:])})

    with pytest.raises(ValidationError, match="artifact_kind"):
        evaluate_runset(compiled, unsafe_runset)


@pytest.mark.parametrize("mutation", ("delete-passing-case", "relabel-passing-case"))
def test_source_projection_rejects_coordinated_case_outcome_mutations(
    mutation: str,
) -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    if mutation == "delete-passing-case":
        payload["case_outcomes"].pop()
        payload["metrics"]["total_cases"] -= 1
        payload["metrics"]["evaluated_cases"] -= 1
        payload["metrics"]["passed_cases"] -= 1
    else:
        payload["case_outcomes"][-1]["case_id"] = "relabelled-passing-case"

    with pytest.raises(
        ValidationError,
        match="must exactly cover the persisted source suite cases",
    ):
        EvaluationReport.model_validate(payload)
    with pytest.raises((ValueError, JsonSchemaValidationError)):
        validate_artifact_payload(payload, "evaluation-report")


def test_source_projection_rejects_coordinated_tool_capability_upgrade() -> None:
    _, _, report = _no_tool_policy_report()
    payload = report.model_dump(mode="json")
    tool = next(
        item for item in payload["capability_coverage"] if item["capability_id"] == "tool_allowlist"
    )
    tool.update(
        {
            "state": "pass",
            "reason": (
                "suite or case expectations configure a tool policy; per-case evaluation "
                "is reported separately"
            ),
        }
    )
    payload["not_evaluated_capabilities"] = [
        item
        for item in payload["not_evaluated_capabilities"]
        if item["capability_id"] != "tool_allowlist"
    ]

    with pytest.raises(
        ValidationError,
        match="tool_allowlist capability state must match persisted source policy coverage",
    ):
        EvaluationReport.model_validate(payload)
    with pytest.raises((ValueError, JsonSchemaValidationError)):
        validate_artifact_payload(payload, "evaluation-report")


@pytest.mark.parametrize(
    "mutation",
    ("delete-passing-case", "relabel-passing-case", "upgrade-tool-capability"),
)
def test_trusted_source_verification_rejects_fully_coordinated_projection_rewrites(
    mutation: str,
) -> None:
    if mutation == "upgrade-tool-capability":
        compiled, runset, report = _no_tool_policy_report()
    else:
        compiled, runset = _runset(BASELINE)
        report = evaluate_runset(compiled, runset, today=AUTHORIZED_EVALUATION_DATE)
    payload = report.model_dump(mode="json")

    if mutation == "delete-passing-case":
        payload["source_projection"]["cases"].pop()
        payload["case_outcomes"].pop()
        payload["metrics"]["total_cases"] -= 1
        payload["metrics"]["evaluated_cases"] -= 1
        payload["metrics"]["passed_cases"] -= 1
    elif mutation == "relabel-passing-case":
        payload["source_projection"]["cases"][-1]["case_id"] = "relabelled-passing-case"
        payload["case_outcomes"][-1]["case_id"] = "relabelled-passing-case"
    else:
        payload["source_projection"]["tool_policy_configured"] = True
        tool = next(
            item
            for item in payload["capability_coverage"]
            if item["capability_id"] == "tool_allowlist"
        )
        tool.update(
            {
                "state": "pass",
                "reason": (
                    "suite or case expectations configure a tool policy; per-case evaluation "
                    "is reported separately"
                ),
            }
        )
        payload["not_evaluated_capabilities"] = [
            item
            for item in payload["not_evaluated_capabilities"]
            if item["capability_id"] != "tool_allowlist"
        ]

    internally_consistent = EvaluationReport.model_validate(payload)
    with pytest.raises(
        EvaluationSourceVerificationError,
        match="does not match the trusted suite and RunSet",
    ):
        verify_evaluation_report_sources(
            internally_consistent,
            compiled,
            runset,
            gate_profile=GateProfile(),
            waivers=(),
            evaluation_date=AUTHORIZED_EVALUATION_DATE,
        )


def test_trusted_source_verification_accepts_exact_inputs() -> None:
    compiled, runset = _runset(BASELINE)
    gate_profile = GateProfile()
    report = evaluate_runset(
        compiled,
        runset,
        gate_profile=gate_profile,
        today=AUTHORIZED_EVALUATION_DATE,
    )

    verified = verify_evaluation_report_sources(
        report,
        compiled,
        runset,
        gate_profile=gate_profile,
        waivers=(),
        evaluation_date=AUTHORIZED_EVALUATION_DATE,
    )

    assert verified == report.source_projection


def test_trusted_source_verification_rejects_coordinated_fail_to_pass_rewrite() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    report = evaluate_runset(compiled, runset, today=AUTHORIZED_EVALUATION_DATE)
    payload = report.model_dump(mode="json")
    assert len(payload["candidate_vs_expectations"]["findings"]) == 1
    failing_case_id = payload["candidate_vs_expectations"]["findings"][0]["case_id"]

    payload["candidate_vs_expectations"]["state"] = "pass"
    payload["candidate_vs_expectations"]["findings"] = []
    payload["failed_controls"] = []
    outcome = next(item for item in payload["case_outcomes"] if item["case_id"] == failing_case_id)
    outcome["state"] = "pass"
    payload["metrics"].update(
        {
            "passed_cases": payload["metrics"]["passed_cases"] + 1,
            "failed_cases": payload["metrics"]["failed_cases"] - 1,
            "blocking_findings": 0,
            "warning_findings": 0,
            "global_blocking_findings": 0,
            "findings_by_reason": {},
            "findings_by_control": {},
        }
    )

    internally_consistent = EvaluationReport.model_validate(payload)
    with pytest.raises(
        EvaluationSourceVerificationError,
        match="decision evidence does not match trusted-source replay",
    ):
        verify_evaluation_report_sources(
            internally_consistent,
            compiled,
            runset,
            gate_profile=GateProfile(),
            waivers=(),
            evaluation_date=AUTHORIZED_EVALUATION_DATE,
        )


def test_trusted_source_verification_rejects_report_selected_permissive_profile() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    attacker_profile = GateProfile(
        profile_id="attacker-permissive",
        fail_severities=(Severity.info,),
    )
    attacker_report = evaluate_runset(
        compiled,
        runset,
        gate_profile=attacker_profile,
        today=AUTHORIZED_EVALUATION_DATE,
    )
    assert attacker_report.candidate_vs_expectations.state is GateState.warn

    with pytest.raises(
        EvaluationSourceVerificationError,
        match="decision evidence does not match trusted-source replay",
    ):
        verify_evaluation_report_sources(
            attacker_report,
            compiled,
            runset,
            gate_profile=GateProfile(),
            waivers=(),
            evaluation_date=AUTHORIZED_EVALUATION_DATE,
        )


def test_trusted_source_verification_rejects_report_selected_self_waiver() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    initial_report = evaluate_runset(compiled, runset, today=AUTHORIZED_EVALUATION_DATE)
    finding = initial_report.candidate_vs_expectations.findings[0]
    attacker_waiver = Waiver(
        waiver_id="attacker-self-waiver",
        owner="attacker-owner",
        reviewer="attacker-reviewer",
        rationale="self-asserted authorization must not cross the verifier boundary",
        reason_code=finding.reason_code,
        finding_id=finding.finding_id,
        artifact_digest=runset_digest(runset),
        expires_on=AUTHORIZED_EVALUATION_DATE + timedelta(days=1),
    )
    attacker_report = evaluate_runset(
        compiled,
        runset,
        waivers=(attacker_waiver,),
        today=AUTHORIZED_EVALUATION_DATE,
    )
    assert attacker_report.candidate_vs_expectations.state is GateState.warn

    with pytest.raises(
        EvaluationSourceVerificationError,
        match="decision evidence does not match trusted-source replay",
    ):
        verify_evaluation_report_sources(
            attacker_report,
            compiled,
            runset,
            gate_profile=GateProfile(),
            waivers=(),
            evaluation_date=AUTHORIZED_EVALUATION_DATE,
        )


def test_current_evaluation_report_rejects_falsified_per_case_counts() -> None:
    payload = _report(EVIDENCE_CANDIDATE).model_dump(mode="json")
    assert payload["metrics"]["passed_cases"] == 9
    assert payload["metrics"]["failed_cases"] == 1
    payload["metrics"].update({"passed_cases": 10, "failed_cases": 0})

    with pytest.raises(
        ValidationError,
        match="passed_cases must match exhaustive case outcomes",
    ):
        EvaluationReport.model_validate(payload)


def test_current_evaluation_report_rejects_erased_unevaluated_case() -> None:
    compiled, runset = _runset(BASELINE)
    report = evaluate_runset(compiled, runset.model_copy(update={"runs": runset.runs[1:]}))
    payload = report.model_dump(mode="json")
    assert payload["metrics"]["unevaluated_cases"] == 1
    payload["metrics"].update(
        {
            "evaluated_cases": 10,
            "unevaluated_cases": 0,
            "passed_cases": 10,
        }
    )

    with pytest.raises(
        ValidationError,
        match="evaluated_cases must match exhaustive case outcomes",
    ):
        EvaluationReport.model_validate(payload)


def test_current_evaluation_report_rejects_false_global_blocker_count() -> None:
    compiled, runset = _runset(BASELINE)
    incomplete = runset.model_copy(
        update={"completion_status": "incomplete", "stop_reasons": ("operator-stop",)}
    )
    payload = evaluate_runset(compiled, incomplete).model_dump(mode="json")
    assert payload["metrics"]["global_blocking_findings"] == 1
    payload["metrics"]["global_blocking_findings"] = 0

    with pytest.raises(
        ValidationError,
        match="global_blocking_findings must equal fail-state findings outside exhaustive",
    ):
        EvaluationReport.model_validate(payload)


def test_current_evaluation_report_rejects_duplicate_or_incoherent_case_outcomes() -> None:
    report = _report(EVIDENCE_CANDIDATE)
    payload = report.model_dump(mode="json")
    payload["case_outcomes"][0]["case_id"] = payload["case_outcomes"][1]["case_id"]
    with pytest.raises(ValidationError, match="duplicate case_id"):
        EvaluationReport.model_validate(payload)

    payload = report.model_dump(mode="json")
    failed_outcome = next(
        outcome for outcome in payload["case_outcomes"] if outcome["state"] == "fail"
    )
    failed_outcome["state"] = "pass"
    payload["metrics"]["passed_cases"] += 1
    payload["metrics"]["failed_cases"] -= 1
    with pytest.raises(ValidationError, match="state must match its scoped findings"):
        EvaluationReport.model_validate(payload)

    payload = report.model_dump(mode="json")
    payload["case_outcomes"].append(
        EvaluationCaseOutcome(case_id="*", state=GateState.pass_).model_dump(mode="json")
    )
    payload["metrics"]["total_cases"] += 1
    payload["metrics"]["evaluated_cases"] += 1
    payload["metrics"]["passed_cases"] += 1
    with pytest.raises(ValidationError, match=r"reserve '\*' for global findings"):
        EvaluationReport.model_validate(payload)


@pytest.mark.parametrize(
    "mutation",
    ("delete", "pass-state", "relabel", "duplicate"),
)
def test_current_evaluation_report_rejects_capability_boundary_mutations(
    mutation: str,
) -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    if mutation == "delete":
        payload["not_evaluated_capabilities"] = []
        message = "must exactly project capability_coverage"
    elif mutation == "pass-state":
        payload["not_evaluated_capabilities"][0]["state"] = "pass"
        message = "may contain only not_evaluated states"
    elif mutation == "relabel":
        payload["capability_coverage"][0]["capability_id"] = "invented-capability"
        message = "must exactly contain every mandatory built-in capability"
    else:
        payload["capability_coverage"][1]["capability_id"] = payload["capability_coverage"][0][
            "capability_id"
        ]
        message = "duplicate capability_id"

    with pytest.raises(ValidationError, match=message):
        EvaluationReport.model_validate(payload)


@pytest.mark.parametrize("mutation", ("delete", "pass-state", "relabel", "duplicate"))
def test_current_evaluation_report_json_schema_rejects_capability_boundary_mutations(
    mutation: str,
) -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    if mutation == "delete":
        payload["not_evaluated_capabilities"] = []
    elif mutation == "pass-state":
        payload["not_evaluated_capabilities"][0]["state"] = "pass"
    elif mutation == "relabel":
        payload["capability_coverage"][0]["capability_id"] = "invented-capability"
    else:
        payload["capability_coverage"][1]["capability_id"] = payload["capability_coverage"][0][
            "capability_id"
        ]

    errors = tuple(
        Draft202012Validator(EvaluationReport.model_json_schema(mode="validation")).iter_errors(
            payload
        )
    )
    assert errors, f"JSON Schema accepted {mutation} capability evidence mutation"


@pytest.mark.parametrize("variant", (BASELINE, EVIDENCE_CANDIDATE))
def test_current_evaluation_report_json_schema_accepts_emitted_integrity_evidence(
    variant: Path,
) -> None:
    payload = _report(variant).model_dump(mode="json")

    errors = tuple(
        Draft202012Validator(EvaluationReport.model_json_schema(mode="validation")).iter_errors(
            payload
        )
    )

    assert errors == ()


def test_tool_allowlist_capability_coverage_is_explicit_when_not_configured() -> None:
    _, _, report = _no_tool_policy_report()

    coverage = {capability.capability_id: capability for capability in report.capability_coverage}
    assert coverage["tool_allowlist"].state is GateState.not_evaluated
    assert "tool_allowlist" in {
        capability.capability_id for capability in report.not_evaluated_capabilities
    }


def test_current_evaluation_report_requires_suite_bound_replay_context() -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    payload["candidate_vs_expectations"].pop("replay_context")

    with pytest.raises(ValidationError, match="require replay context binding the suite digest"):
        EvaluationReport.model_validate(payload)


def test_current_evaluation_report_requires_persisted_source_projection() -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    payload.pop("source_projection")

    with pytest.raises(ValidationError, match="require a persisted source projection"):
        EvaluationReport.model_validate(payload)
    errors = tuple(
        Draft202012Validator(EvaluationReport.model_json_schema(mode="validation")).iter_errors(
            payload
        )
    )
    assert errors


def test_evaluator_rejects_unchecked_empty_current_artifacts() -> None:
    compiled, runset = _runset(BASELINE)

    empty_suite = compiled.model_copy(update={"cases": (), "resolved_expectations": ()})
    with pytest.raises(ValueError, match="at least one case"):
        evaluate_runset(empty_suite, runset)

    empty_runset = runset.model_copy(update={"runs": ()})
    with pytest.raises(ValueError, match="at least one run record"):
        evaluate_runset(compiled, empty_runset)


def test_v06_evaluation_report_binds_exact_runset_content() -> None:
    compiled, runset = _runset(BASELINE)
    report = evaluate_runset(compiled, runset)

    assert report.schema_version == "0.6.6"
    assert report.runset_digest == runset_digest(runset)
    assert report.candidate_vs_expectations.runset_digest == runset_digest(runset)
    payload = report.model_dump(mode="json")
    payload.pop("runset_digest")
    with pytest.raises(ValidationError, match="requires runset_digest"):
        EvaluationReport.model_validate(payload)
    for schema_version in ("0.6.0", "0.6.1", "0.6.2", "0.6.3"):
        payload["schema_version"] = schema_version
        with pytest.raises(ValidationError, match="requires runset_digest"):
            EvaluationReport.model_validate(payload)
    report_schema = EvaluationReport.model_json_schema(mode="validation")
    current_schema_condition = next(
        condition
        for condition in report_schema["allOf"]
        if condition.get("if", {}).get("properties", {}).get("schema_version", {}).get("enum")
        == ["0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"]
    )
    assert set(current_schema_condition["then"]["required"]) == {
        "runset_digest",
        "waiver_dispositions",
    }
    assert report_schema["properties"]["waiver_dispositions"]["maxItems"] == 4096
    current_waiver_condition = next(
        condition
        for condition in report_schema["allOf"]
        if condition.get("if", {}).get("properties", {}).get("schema_version", {}).get("const")
        == "0.6.6"
        and "waiver_dispositions" in condition.get("then", {}).get("properties", {})
    )
    assert (
        current_waiver_condition["then"]["properties"]["waiver_dispositions"]["uniqueItems"] is True
    )


def test_evaluation_report_rejects_conflicting_nested_runset_digest() -> None:
    report = _report(BASELINE)
    conflicting_summary = report.candidate_vs_expectations.model_copy(
        update={"runset_digest": "f" * 64}
    )

    with pytest.raises(
        ValidationError,
        match="evaluation summary runset_digest must match evaluation report runset_digest",
    ):
        EvaluationReport.model_validate(
            report.model_dump(mode="python") | {"candidate_vs_expectations": conflicting_summary}
        )


def test_current_evaluation_report_rejects_impossible_case_arithmetic() -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    payload["metrics"].update(
        {
            "total_cases": 0,
            "evaluated_cases": 0,
            "unevaluated_cases": 0,
            "passed_cases": 999,
            "warning_cases": 0,
            "failed_cases": 0,
        }
    )

    with pytest.raises(
        ValidationError,
        match="current evaluation reports require at least one total case",
    ):
        EvaluationReport.model_validate(payload)
    with pytest.raises(
        ValueError,
        match="evaluation-report artifact failed model validation",
    ):
        validate_artifact_payload(payload, "evaluation-report")


@pytest.mark.parametrize(
    ("metric_updates", "message"),
    (
        ({"total_cases": 11}, "total_cases must equal evaluated_cases plus unevaluated_cases"),
        (
            {"total_cases": 11, "evaluated_cases": 11},
            "evaluated_cases must equal passed_cases plus warning_cases plus failed_cases",
        ),
        (
            {"global_blocking_findings": 1},
            "global_blocking_findings cannot exceed blocking_findings",
        ),
        (
            {"passed_cases": 9, "warning_cases": 1},
            "warning_cases cannot exceed warning_findings",
        ),
    ),
)
def test_current_evaluation_report_rejects_mismatched_metric_counts(
    metric_updates: dict[str, int],
    message: str,
) -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    payload["metrics"].update(metric_updates)

    with pytest.raises(ValidationError, match=message):
        EvaluationReport.model_validate(payload)


def test_current_evaluation_report_reconciles_finding_counts_and_indexes() -> None:
    payload = _report(EVIDENCE_CANDIDATE).model_dump(mode="json")
    payload["metrics"]["blocking_findings"] += 1
    with pytest.raises(
        ValidationError,
        match="blocking_findings must equal fail-state summary findings",
    ):
        EvaluationReport.model_validate(payload)

    payload = _report(EVIDENCE_CANDIDATE).model_dump(mode="json")
    payload["metrics"]["findings_by_reason"] = {}
    with pytest.raises(
        ValidationError,
        match="findings_by_reason must match evaluation summary findings",
    ):
        EvaluationReport.model_validate(payload)

    payload = _report(EVIDENCE_CANDIDATE).model_dump(mode="json")
    payload["metrics"]["findings_by_control"] = {}
    with pytest.raises(
        ValidationError,
        match="findings_by_control must match evaluation summary findings",
    ):
        EvaluationReport.model_validate(payload)


def test_current_evaluation_report_reconciles_control_projections() -> None:
    failed_payload = _report(EVIDENCE_CANDIDATE).model_dump(mode="json")
    assert failed_payload["failed_controls"]
    failed_payload["failed_controls"] = []
    with pytest.raises(
        ValidationError,
        match="failed_controls must exactly project fail-state evaluation summary findings",
    ):
        EvaluationReport.model_validate(failed_payload)

    tampered_payload = _report(EVIDENCE_CANDIDATE).model_dump(mode="json")
    tampered_payload["failed_controls"][0]["message"] = "tampered projection"
    with pytest.raises(
        ValidationError,
        match="must match its evaluation summary finding",
    ):
        EvaluationReport.model_validate(tampered_payload)

    warning_payload = _active_waived_report().model_dump(mode="json")
    assert warning_payload["warning_controls"]
    warning_payload["warning_controls"] = []
    with pytest.raises(
        ValidationError,
        match="warning_controls must exactly project warn-state evaluation summary findings",
    ):
        EvaluationReport.model_validate(warning_payload)


def test_current_evaluation_report_reconciles_embedded_summary_identity() -> None:
    payload = _report(BASELINE).model_dump(mode="json")
    payload["candidate_vs_expectations"]["runset_id"] = "different-runset"
    with pytest.raises(
        ValidationError,
        match="runset_id must match its evaluation summary",
    ):
        EvaluationReport.model_validate(payload)

    payload = _report(BASELINE).model_dump(mode="json")
    payload["environment"] = {
        "artifact_kind": "environment-info",
        "schema_version": "0.6.6",
        "platform": "linux",
        "python_version": "3.11",
        "installed_packages": [],
    }
    with pytest.raises(
        ValidationError,
        match="environment must match its evaluation summary",
    ):
        EvaluationReport.model_validate(payload)

    payload = _report(BASELINE).model_dump(mode="json")
    payload["gate_profile"] = "different-profile"
    with pytest.raises(
        ValidationError,
        match="gate_profile must match its evaluation summary replay context",
    ):
        EvaluationReport.model_validate(payload)


def test_evaluation_gate_revalidates_tampered_network_authority_receipt() -> None:
    summary = _report(BASELINE).candidate_vs_expectations
    receipt = LiveNetworkAuthorityReceipt(
        endpoint_host="api.openai.com",
        api_key_env="OPENAI_TEST_KEY",
    )
    forged_receipt = receipt.model_copy(update={"api_key_env": "GITHUB_TOKEN"})
    forged_summary = summary.model_copy(update={"network_authority_receipt": forged_receipt})

    decision = gate_evaluation_summary(forged_summary)

    assert decision.exit_code == 2
    assert decision.outcome.value == "invalid"
    assert "failed trusted model revalidation" in decision.message
    assert "high-privilege ambient CI or cloud credential" in decision.message


def test_load_runset_requires_explicit_current_wire_identity(tmp_path: Path) -> None:
    _, runset = _runset(BASELINE)
    payload = runset.model_dump(mode="json")
    payload.pop("artifact_kind")
    path = tmp_path / "missing-identity.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="explicit identity fields before parsing"):
        load_runset(path)


def test_explicit_runset_loaders_default_to_journal_bearing_limit() -> None:
    assert (
        signature(load_runset).parameters["max_bytes"].default
        == MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
    )
    assert (
        signature(load_runset_with_size).parameters["max_bytes"].default
        == MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
    )


def test_load_runset_enforces_frozen_legacy_shape(tmp_path: Path) -> None:
    _, runset = _runset(BASELINE)
    payload = _legacy_schema_version(runset.model_dump(mode="json"), "0.5.0")
    assert isinstance(payload, dict)
    first = payload["runs"][0]
    assert isinstance(first, dict)
    first["cost_budget_committed_usd"] = "0.000000"
    path = tmp_path / "invalid-legacy-shape.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="failed JSON Schema validation"):
        load_runset(path)


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
    assert ReasonCode.FORBIDDEN_PROVIDER in _reason_codes(report.candidate_vs_expectations)


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
                bad_run if run.case_id == target_run.case_id else run for run in runset.runs
            )
        }
    )

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.case_id == target_run.case_id and finding.control_id == "human_review_required"
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
    mutated_suite = compiled.model_copy(update={"resolved_expectations": resolved_expectations})
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
    assert ReasonCode.STRUCTURED_OUTPUT_INVALID in _reason_codes(report.candidate_vs_expectations)


def test_raw_sensitive_summary_is_verdict_bearing_redaction_failure() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(update={"input_summary": "patient=Jane ssn: 123-45-6789"})
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.RAW_SENSITIVE_CONTENT in _reason_codes(report.candidate_vs_expectations)


def test_persisted_policy_result_failure_is_verdict_bearing() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    bad_run = first_run.model_copy(
        update={
            "policy_results": (
                PolicyResult(
                    artifact_kind="policy-result",
                    policy_id="adapter.injected_policy",
                    state=GateState.fail,
                    reason_codes=(ReasonCode.POLICY_FAILED,),
                    severity=Severity.warning,
                    message="adapter-reported policy failure",
                ),
            ),
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


@pytest.mark.parametrize(
    "signal_state",
    (GateState.fail, GateState.warn, GateState.not_evaluated),
)
def test_reducing_policy_origin_trust_never_erases_nonpass_signal(
    signal_state: GateState,
) -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    signal = PolicyResult(
        artifact_kind="policy-result",
        policy_id="self_reported.negative",
        state=signal_state,
        reason_codes=(ReasonCode.POLICY_FAILED,),
        severity=Severity.warning,
        message="untrusted negative signal",
    )
    trusted = first_run.model_copy(update={"policy_results": (*first_run.policy_results, signal)})
    trusted_report = evaluate_runset(
        compiled,
        runset.model_copy(update={"runs": (trusted, *runset.runs[1:])}),
    )

    untrusted_payload = trusted.model_dump(mode="python")
    untrusted_payload.update(
        {
            "execution_mode": "live",
            "observation_id": "obs-untrusted-policy",
            "repetition_index": 0,
            "schedule_index": 0,
            "cluster_id": trusted.case_id,
            "adapter_id": "openai-chat-completions",
            "cost_budget_committed_usd": "0.000000",
            "generated_token_budget_committed": 0,
            "total_token_budget_committed": 0,
            "structured_field_origins": StructuredFieldOrigins.uniform(
                StructuredFieldOrigin.model_self_report
            ),
        }
    )
    untrusted = AgentRunRecord.model_validate(untrusted_payload)
    case_expectation = next(
        item
        for item in ExpectationResolver(compiled).cases()
        if item.case.case_id == untrusted.case_id
    )
    untrusted_results = evaluate_case(
        case_expectation,
        untrusted,
        allowed_tools=compiled.defaults.allowed_tools,
        required_policy_ids=compiled.defaults.required_policy_ids,
    )

    assert trusted_report.candidate_vs_expectations.state is not GateState.pass_
    finding = next(
        finding
        for finding in untrusted_results
        if finding.control_id == "policy_result:self_reported.negative"
    )
    assert finding.state is signal_state
    assert any(
        finding.control_id == "required_policy_evaluated" and finding.case_id == untrusted.case_id
        for finding in untrusted_results
    )


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


def test_fixture_policy_result_warning_is_reported() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    warned_run = first_run.model_copy(
        update={
            "policy_results": (
                *first_run.policy_results,
                PolicyResult(
                    artifact_kind="policy-result",
                    policy_id="fixture.declared_warning",
                    state=GateState.warn,
                    reason_codes=(ReasonCode.POLICY_FAILED,),
                    severity=Severity.warning,
                    message="fixture-declared policy warning",
                ),
            )
        }
    )
    mutated = runset.model_copy(update={"runs": (warned_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.warn
    finding = next(
        finding
        for finding in report.warning_controls
        if finding.control_id == "policy_result:fixture.declared_warning"
    )
    assert finding.state is GateState.warn


def test_native_warning_waiver_is_unmatched_and_cannot_authorize_strict_gate() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    warned_run = first_run.model_copy(
        update={
            "policy_results": (
                *first_run.policy_results,
                PolicyResult(
                    artifact_kind="policy-result",
                    policy_id="fixture.native-warning-waiver",
                    state=GateState.warn,
                    reason_codes=(ReasonCode.POLICY_FAILED,),
                    severity=Severity.warning,
                    message="native warning must remain advisory rather than waived",
                ),
            )
        }
    )
    warned = runset.model_copy(update={"runs": (warned_run, *runset.runs[1:])})
    initial_report = evaluate_runset(compiled, warned)
    finding = next(
        finding
        for finding in initial_report.candidate_vs_expectations.findings
        if finding.control_id == "policy_result:fixture.native-warning-waiver"
    )
    today = ci_module._current_gate_verification_date()
    waiver = Waiver(
        waiver_id="native-warning-does-not-apply",
        owner="native-warning-owner",
        rationale="prove an already advisory result cannot gain waiver authority",
        reason_code=finding.reason_code,
        finding_id=finding.finding_id,
        artifact_digest=runset_digest(warned),
        expires_on=today + timedelta(days=1),
        reviewer="native-warning-reviewer",
    )

    report = evaluate_runset(compiled, warned, waivers=(waiver,), today=today)
    context = report.candidate_vs_expectations.replay_context
    assert context is not None
    assert context.waivers == ()
    assert report.waiver_dispositions[0].status is WaiverDispositionStatus.unmatched_finding

    decision = gate_evaluation_summary(
        report.candidate_vs_expectations,
        fail_on_warn=True,
    )
    assert decision.exit_code == 1
    assert decision.outcome.value == "fail"
    assert decision.waiver_authorization.value == "not_applicable"


@pytest.mark.parametrize(
    ("case_id", "policy_id", "reason_code", "suppressed_control_id"),
    (
        (
            "forbidden-provider",
            "provider-selection",
            ReasonCode.FORBIDDEN_PROVIDER,
            "required_policy:provider-selection",
        ),
        (
            "prompt-injection-note",
            "prompt-injection-boundary",
            ReasonCode.PROMPT_INJECTION_BOUNDARY,
            "policy_result:prompt-injection-boundary",
        ),
    ),
)
def test_fixture_policy_result_pure_remediation_signal_is_suppressed(
    case_id: str,
    policy_id: str,
    reason_code: ReasonCode,
    suppressed_control_id: str,
) -> None:
    compiled, runset = _runset(BASELINE)
    remediated_run = next(run for run in runset.runs if run.case_id == case_id)
    remediation_result = next(
        result for result in remediated_run.policy_results if result.policy_id == policy_id
    )

    report = evaluate_runset(compiled, runset)

    assert remediation_result.reason_codes == (reason_code,)
    assert not any(
        finding.case_id == remediated_run.case_id and finding.control_id == suppressed_control_id
        for finding in (
            *report.candidate_vs_expectations.findings,
            *report.warning_controls,
        )
    )


def test_untagged_explicit_provider_constraint_remediation_is_suppressed() -> None:
    compiled, runset = _runset(BASELINE)
    target_case_id = "forbidden-provider"
    target_case = next(case for case in compiled.cases if case.case_id == target_case_id)
    target_expectation = next(
        expectation
        for expectation in compiled.resolved_expectations
        if expectation.case_id == target_case_id
    )
    target_run = next(run for run in runset.runs if run.case_id == target_case_id)
    remediation_result = next(
        result for result in target_run.policy_results if result.policy_id == "provider-selection"
    )
    assert "provider-policy" in target_case.tags
    assert target_expectation.allowed_providers or target_expectation.forbidden_providers
    assert target_run.provider == BLOCKED_PROVIDER_SELECTION
    assert remediation_result.state is GateState.fail
    assert remediation_result.reason_codes == (ReasonCode.FORBIDDEN_PROVIDER,)

    untagged_case = target_case.model_copy(
        update={"tags": tuple(tag for tag in target_case.tags if tag != "provider-policy")}
    )
    untagged_suite = compiled.model_copy(
        update={
            "cases": tuple(
                untagged_case if case.case_id == target_case_id else case for case in compiled.cases
            )
        }
    )
    bound_runset = runset.model_copy(update={"suite_digest": compiled_suite_digest(untagged_suite)})

    report = evaluate_runset(untagged_suite, bound_runset)

    assert not any(
        finding.case_id == target_case_id
        and finding.control_id in {"provider_review_boundary", "required_policy:provider-selection"}
        for finding in report.candidate_vs_expectations.findings
    )


def test_untagged_fixture_provider_failure_is_not_suppressed() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    case = next(case for case in compiled.cases if case.case_id == first_run.case_id)
    expectation = next(
        expectation
        for expectation in compiled.resolved_expectations
        if expectation.case_id == first_run.case_id
    )
    assert "provider-policy" not in case.tags
    assert not expectation.allowed_providers
    assert not expectation.forbidden_providers
    failure = PolicyResult(
        artifact_kind="policy-result",
        policy_id="provider-selection",
        state=GateState.fail,
        reason_codes=(ReasonCode.FORBIDDEN_PROVIDER,),
        severity=Severity.error,
        message="imported provider-policy failure",
    )
    mutated = runset.model_copy(
        update={
            "runs": (
                first_run.model_copy(
                    update={
                        "provider": BLOCKED_PROVIDER_SELECTION,
                        "policy_results": (failure,),
                    }
                ),
                *runset.runs[1:],
            )
        }
    )

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert any(
        finding.case_id == first_run.case_id
        and finding.control_id == "required_policy:provider-selection"
        and finding.reason_code is ReasonCode.FORBIDDEN_PROVIDER
        for finding in report.candidate_vs_expectations.findings
    )


def test_tagged_fixture_remediation_cannot_mask_forbidden_provider_use() -> None:
    compiled, runset = _runset(BASELINE)
    target = next(run for run in runset.runs if run.case_id == "forbidden-provider")
    expectation = next(
        item for item in compiled.resolved_expectations if item.case_id == target.case_id
    )
    forbidden_provider = expectation.forbidden_providers[0]
    forged = target.model_copy(
        update={
            "provider": forbidden_provider,
            "human_review_required": True,
            "human_review_performed": True,
        }
    )
    mutated = runset.model_copy(
        update={
            "runs": tuple(forged if run.case_id == target.case_id else run for run in runset.runs)
        }
    )

    report = evaluate_runset(compiled, mutated)

    findings = report.candidate_vs_expectations.findings
    assert any(
        finding.case_id == target.case_id
        and finding.control_id == "provider_review_boundary"
        and finding.reason_code is ReasonCode.FORBIDDEN_PROVIDER
        for finding in findings
    )
    assert any(
        finding.case_id == target.case_id
        and finding.control_id == "required_policy:provider-selection"
        and finding.reason_code is ReasonCode.FORBIDDEN_PROVIDER
        for finding in findings
    )


@pytest.mark.parametrize(
    ("policy_id", "expected_control_id"),
    (
        ("fixture.mixed_policy", "policy_result:fixture.mixed_policy"),
        ("provider-selection", "required_policy:provider-selection"),
    ),
)
def test_fixture_policy_result_mixed_remediation_and_independent_failure_is_reported(
    policy_id: str,
    expected_control_id: str,
) -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    mixed_result = PolicyResult(
        artifact_kind="policy-result",
        policy_id=policy_id,
        state=GateState.fail,
        reason_codes=(
            ReasonCode.FORBIDDEN_PROVIDER,
            ReasonCode.POLICY_FAILED,
        ),
        severity=Severity.error,
        message="fixture result carries remediation and independent failure signals",
    )
    bad_run = first_run.model_copy(
        update={"policy_results": (*first_run.policy_results, mixed_result)}
    )
    mutated = runset.model_copy(update={"runs": (bad_run, *runset.runs[1:])})

    report = evaluate_runset(compiled, mutated)

    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == expected_control_id
    )
    assert finding.case_id == first_run.case_id
    assert finding.state is GateState.fail
    assert report.candidate_vs_expectations.state is GateState.fail


@pytest.mark.parametrize("constraint", ("forbidden", "not_allowed"))
def test_provider_constraints_deny_without_a_review_requirement(constraint: str) -> None:
    compiled, runset = _runset(BASELINE)
    case = compiled.cases[0]
    run = runset.runs[0]
    expectation = next(
        item
        for item in compiled.resolved_expectations
        if item.expectation_id == case.expectation_id
    )
    assert run.provider is not None
    update = (
        {"forbidden_providers": (run.provider,), "allowed_providers": ()}
        if constraint == "forbidden"
        else {"forbidden_providers": (), "allowed_providers": ("different-provider",)}
    )

    findings = evaluate_provider_boundary(
        run,
        case,
        expectation.model_copy(
            update={
                **update,
                "required_human_review": False,
                "forbidden_outcomes": (),
            }
        ),
    )

    assert len(findings) == 1
    assert findings[0].reason_code is ReasonCode.FORBIDDEN_PROVIDER
    assert findings[0].state is GateState.fail


def test_required_policy_id_must_be_observed() -> None:
    compiled, runset = _runset(BASELINE)
    mutated = runset.model_copy(
        update={"runs": tuple(run.model_copy(update={"policy_results": ()}) for run in runset.runs)}
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


def test_required_policy_not_evaluated_fails_under_the_default_ci_gate() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    policy_results = tuple(
        result.model_copy(
            update={
                "state": GateState.not_evaluated,
                "reason_codes": (),
                "severity": Severity.info,
            }
        )
        if result.policy_id == "provider-selection"
        else result
        for result in first_run.policy_results
    )
    mutated = runset.model_copy(
        update={
            "runs": (
                first_run.model_copy(update={"policy_results": policy_results}),
                *runset.runs[1:],
            )
        }
    )

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        item
        for item in report.candidate_vs_expectations.findings
        if item.control_id == "required_policy_evaluated"
    )
    assert finding.reason_code is ReasonCode.POLICY_FAILED
    assert gate_evaluation_summary(report.candidate_vs_expectations).exit_code == 1


def test_case_scoped_not_evaluated_partitions_as_advisory_warning_or_strict_failure() -> None:
    compiled, runset = _runset(BASELINE)
    first_run = runset.runs[0]
    mutated = runset.model_copy(
        update={
            "runs": (
                first_run.model_copy(update={"tools": ()}),
                *runset.runs[1:],
            )
        }
    )

    advisory = evaluate_runset(compiled, mutated)
    strict = evaluate_runset(
        compiled,
        mutated,
        gate_profile=GateProfile(fail_on_not_evaluated=True),
    )

    assert advisory.metrics.warning_cases == 1
    assert advisory.metrics.failed_cases == 0
    assert advisory.metrics.passed_cases == advisory.metrics.evaluated_cases - 1
    assert advisory.metrics.warning_findings == 1
    assert strict.metrics.warning_cases == 0
    assert strict.metrics.failed_cases == 1
    assert strict.metrics.passed_cases == strict.metrics.evaluated_cases - 1
    assert advisory.failed_controls == ()
    assert advisory.warning_controls == ()
    strict_case_finding = next(
        finding
        for finding in strict.failed_controls
        if finding.control_id == "tool_allowlist" and finding.case_id == first_run.case_id
    )
    assert strict_case_finding.state is GateState.not_evaluated
    assert strict.warning_controls == ()
    for report in (advisory, strict):
        assert report.metrics.total_cases == (
            report.metrics.passed_cases
            + report.metrics.warning_cases
            + report.metrics.failed_cases
            + report.metrics.unevaluated_cases
        )


def test_missing_record_counts_as_unevaluated_case_and_blocking_finding() -> None:
    compiled, runset = _runset(BASELINE)
    mutated = runset.model_copy(update={"runs": runset.runs[1:]})

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    assert ReasonCode.VALID_RECORD_MISSING in _reason_codes(report.candidate_vs_expectations)
    assert report.metrics.total_cases == 10
    assert report.metrics.evaluated_cases == 9
    assert report.metrics.unevaluated_cases == 1
    assert report.metrics.passed_cases == 9
    assert report.metrics.failed_cases == 0
    assert report.metrics.blocking_findings == 1


def test_duplicate_case_is_not_evaluated_and_is_permutation_invariant() -> None:
    compiled, runset = _runset(BASELINE)
    original = runset.runs[0]
    conflicting = original.model_copy(
        update={
            "run_id": f"{original.run_id}-duplicate",
            "recommendation": "conflicting-recommendation",
            "outcome": "conflicting-outcome",
        }
    )
    remaining = runset.runs[1:]

    original_first = evaluate_runset(
        compiled,
        runset.model_copy(update={"runs": (original, conflicting, *remaining)}),
    )
    conflicting_first = evaluate_runset(
        compiled,
        runset.model_copy(update={"runs": (conflicting, original, *remaining)}),
    )

    assert (
        original_first.candidate_vs_expectations.findings
        == conflicting_first.candidate_vs_expectations.findings
    )
    duplicate_findings = tuple(
        finding
        for finding in original_first.candidate_vs_expectations.findings
        if finding.case_id == original.case_id
    )
    assert len(duplicate_findings) == 1
    assert duplicate_findings[0].target == "duplicate-suite-case"
    assert duplicate_findings[0].reason_code is ReasonCode.VALID_RECORD_MISSING
    assert original_first.metrics.evaluated_cases == 9
    assert original_first.metrics.unevaluated_cases == 1
    assert original_first.metrics.failed_cases == 0


def test_incomplete_runset_fails_ordinary_evaluation() -> None:
    compiled, runset = _runset(BASELINE)
    sensitive_stop_reason = "operator-private-detail@example.com"
    mutated = runset.model_copy(
        update={
            "completion_status": "incomplete",
            "stop_reasons": (sensitive_stop_reason,),
        }
    )

    report = evaluate_runset(compiled, mutated)

    assert report.candidate_vs_expectations.state is GateState.fail
    finding = next(
        finding
        for finding in report.candidate_vs_expectations.findings
        if finding.control_id == "runset_completion_required"
    )
    assert finding.reason_code is ReasonCode.RUNSET_INCOMPLETE
    assert finding.message.endswith("declared stop reason count: 1")
    assert sensitive_stop_reason not in finding.message
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
    today = ci_module._current_gate_verification_date()
    waiver = Waiver(
        waiver_id="waiver-active",
        owner="private-owner-waiver-active-729",
        rationale="private-rationale-waiver-active-729",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        finding_id=finding.finding_id,
        artifact_digest=runset_digest(runset),
        expires_on=today + timedelta(days=1),
        reviewer="private-reviewer-waiver-active-729",
    )

    report = evaluate_runset(compiled, runset, waivers=(waiver,), today=today)

    assert report.candidate_vs_expectations.state is GateState.warn
    assert report.metrics.blocking_findings == 0
    assert report.metrics.warning_cases == 1
    assert report.metrics.passed_cases == report.metrics.evaluated_cases - 1
    assert report.candidate_vs_expectations.findings[0].state is GateState.warn
    assert len(report.waiver_dispositions) == 1
    disposition = report.waiver_dispositions[0]
    assert disposition.waiver_id == waiver.waiver_id
    assert disposition.status is WaiverDispositionStatus.matched
    assert disposition.finding_id == finding.finding_id
    assert disposition.reason_code is waiver.reason_code
    assert disposition.expires_on == waiver.expires_on
    assert disposition.owner == waiver.owner
    assert disposition.reviewer == waiver.reviewer
    assert disposition.rationale == waiver.rationale
    assert set(disposition.model_dump()) == {
        "waiver_id",
        "owner",
        "reviewer",
        "rationale",
        "status",
        "reason_code",
        "finding_id",
        "expires_on",
    }
    assert (
        verify_evaluation_report_sources(
            report,
            compiled,
            runset,
            gate_profile=GateProfile(),
            waivers=(waiver,),
            evaluation_date=today,
        )
        == report.source_projection
    )
    rendered = render_evaluation_markdown(report)
    assert waiver.owner not in rendered
    assert waiver.reviewer not in rendered
    assert waiver.rationale not in rendered

    strict_report = evaluate_runset(
        compiled,
        runset,
        gate_profile=GateProfile(fail_on_warn=True),
        waivers=(waiver,),
        today=today,
    )
    assert strict_report.candidate_vs_expectations.replay_context is not None
    assert tuple(
        item.waiver_id for item in strict_report.candidate_vs_expectations.replay_context.waivers
    ) == (waiver.waiver_id,)
    assert strict_report.candidate_vs_expectations.state is GateState.warn
    assert strict_report.metrics.blocking_findings == 0
    assert (
        gate_evaluation_summary(
            strict_report.candidate_vs_expectations,
            fail_on_warn=True,
        ).exit_code
        == 0
    )
    authorized = gate_evaluation_summary(
        strict_report.candidate_vs_expectations,
        fail_on_warn=True,
    )
    assert authorized.artifact_kind == "evaluation-summary"
    assert authorized.waiver_authorization.value == "authorized_exact"

    historical_date = today - timedelta(days=2)
    historical_waiver = waiver.model_copy(
        update={"expires_on": historical_date + timedelta(days=1)}
    )
    historical_report = evaluate_runset(
        compiled,
        runset,
        gate_profile=GateProfile(fail_on_warn=True),
        waivers=(historical_waiver,),
        today=historical_date,
    )
    expired = gate_evaluation_summary(
        historical_report.candidate_vs_expectations,
        fail_on_warn=True,
    )

    future_date = today + timedelta(days=1)
    future_waiver = waiver.model_copy(update={"expires_on": future_date + timedelta(days=1)})
    future_report = evaluate_runset(
        compiled,
        runset,
        gate_profile=GateProfile(fail_on_warn=True),
        waivers=(future_waiver,),
        today=future_date,
    )
    future_dated = gate_evaluation_summary(
        future_report.candidate_vs_expectations,
        fail_on_warn=True,
    )

    assert expired.exit_code == 1
    assert expired.waiver_authorization.value == "not_applicable"
    assert future_dated.exit_code == 1
    assert future_dated.waiver_authorization.value == "not_applicable"
    waived_finding = strict_report.candidate_vs_expectations.findings[0]
    rebound_finding = waived_finding.model_copy(update={"target": "rebound-waiver-target"})
    rebound_summary = strict_report.candidate_vs_expectations.model_copy(
        update={"findings": (rebound_finding,)}
    )
    rebound_decision = gate_evaluation_summary(rebound_summary, fail_on_warn=True)
    assert rebound_decision.outcome.value == "invalid"
    assert rebound_decision.exit_code == 2
    assert "noncanonical finding_id" in rebound_decision.message

    duplicate_summary = strict_report.candidate_vs_expectations.model_copy(
        update={"findings": (waived_finding, waived_finding)}
    )
    duplicate_decision = gate_evaluation_summary(duplicate_summary, fail_on_warn=True)
    assert duplicate_decision.outcome.value == "invalid"
    assert duplicate_decision.exit_code == 2
    assert "duplicate finding_id" in duplicate_decision.message

    unrelated_not_evaluated = waived_finding.model_copy(
        update={
            "finding_id": control_finding_id(
                waived_finding.case_id,
                waived_finding.control_id,
                ReasonCode.NOT_EVALUATED,
                waived_finding.target,
            ),
            "state": GateState.not_evaluated,
            "reason_code": ReasonCode.NOT_EVALUATED,
        }
    )
    mixed_summary = strict_report.candidate_vs_expectations.model_copy(
        update={
            "findings": (
                *strict_report.candidate_vs_expectations.findings,
                unrelated_not_evaluated,
            )
        }
    )
    assert (
        gate_evaluation_summary(
            mixed_summary,
            fail_on_warn=True,
            fail_on_not_evaluated=True,
        ).exit_code
        == 1
    )


def test_current_evaluation_report_rejects_ambiguous_waiver_audit_evidence() -> None:
    report = _active_waived_report()

    duplicate = report.model_dump(mode="json")
    duplicate["waiver_dispositions"].append(
        duplicate["waiver_dispositions"][0] | {"status": "expired"}
    )
    with pytest.raises(ValidationError, match="duplicate waiver disposition ID"):
        EvaluationReport.model_validate(duplicate)

    conflicting = report.model_dump(mode="json")
    conflicting["waiver_dispositions"][0]["rationale"] = "different reviewed rationale"
    with pytest.raises(ValidationError, match="does not match its report disposition"):
        EvaluationReport.model_validate(conflicting)

    orphaned = report.model_dump(mode="json")
    orphaned["candidate_vs_expectations"]["replay_context"]["waivers"] = []
    with pytest.raises(
        ValidationError,
        match="must exactly match replay-context waiver IDs",
    ):
        EvaluationReport.model_validate(orphaned)

    rebound = report.model_dump(mode="json")
    rebound["candidate_vs_expectations"]["replay_context"]["waivers"][0]["artifact_digest"] = (
        "0" * 64
    )
    with pytest.raises(ValidationError, match="must match report runset_digest"):
        EvaluationReport.model_validate(rebound)


def test_strict_summary_gate_blocks_any_unwaived_warning() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    report = evaluate_runset(
        compiled,
        runset,
        gate_profile=GateProfile(fail_severities=(Severity.blocker,)),
    )

    decision = gate_evaluation_summary(
        report.candidate_vs_expectations,
        fail_on_warn=True,
    )

    assert decision.exit_code == 1


def test_unmatched_waivers_are_auditable_without_changing_gate_results() -> None:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    initial_report = evaluate_runset(compiled, runset)
    finding = initial_report.candidate_vs_expectations.findings[0]
    today = date(2026, 7, 3)
    waivers = (
        Waiver(
            waiver_id="waiver-reason",
            owner="sensitive-reason-owner",
            rationale="sensitive-reason-rationale",
            reason_code=ReasonCode.POLICY_FAILED,
            finding_id=finding.finding_id,
            artifact_digest=runset_digest(runset),
            expires_on=today + timedelta(days=1),
            reviewer="sensitive-reason-reviewer",
        ),
        Waiver(
            waiver_id="waiver-finding",
            owner="sensitive-finding-owner",
            rationale="sensitive-finding-rationale",
            reason_code=finding.reason_code,
            finding_id="finding-not-emitted",
            artifact_digest=runset_digest(runset),
            expires_on=today + timedelta(days=1),
            reviewer="sensitive-finding-reviewer",
        ),
        Waiver(
            waiver_id="waiver-artifact",
            owner="sensitive-artifact-owner",
            rationale="sensitive-artifact-rationale",
            reason_code=finding.reason_code,
            finding_id=finding.finding_id,
            artifact_digest="f" * 64,
            expires_on=today - timedelta(days=1),
            reviewer="sensitive-artifact-reviewer",
        ),
    )

    report = evaluate_runset(compiled, runset, waivers=waivers, today=today)
    reordered_report = evaluate_runset(
        compiled,
        runset,
        waivers=tuple(reversed(waivers)),
        today=today,
    )

    assert report.candidate_vs_expectations.model_dump(
        mode="json", exclude={"replay_context"}
    ) == initial_report.candidate_vs_expectations.model_dump(
        mode="json", exclude={"replay_context"}
    )
    assert report.candidate_vs_expectations.replay_context is not None
    assert report.candidate_vs_expectations.replay_context.waivers == ()
    assert report.metrics == initial_report.metrics
    assert report.failed_controls == initial_report.failed_controls
    assert report.warning_controls == initial_report.warning_controls
    assert report.waiver_dispositions == reordered_report.waiver_dispositions
    assert (
        verify_evaluation_report_sources(
            report,
            compiled,
            runset,
            gate_profile=GateProfile(),
            waivers=waivers,
            evaluation_date=today,
        )
        == report.source_projection
    )
    assert {
        disposition.waiver_id: disposition.status for disposition in report.waiver_dispositions
    } == {
        "waiver-artifact": WaiverDispositionStatus.unmatched_artifact,
        "waiver-finding": WaiverDispositionStatus.unmatched_finding,
        "waiver-reason": WaiverDispositionStatus.unmatched_reason,
    }
    payload = report.model_dump(mode="json")["waiver_dispositions"]
    assert isinstance(payload, list)
    assert len(payload) == len(waivers)
    assert all(
        set(disposition)
        == {
            "waiver_id",
            "owner",
            "reviewer",
            "rationale",
            "status",
            "reason_code",
            "finding_id",
            "expires_on",
        }
        for disposition in payload
    )


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
    assert len(report.waiver_dispositions) == 1
    assert report.waiver_dispositions[0].status is WaiverDispositionStatus.expired
    assert report.candidate_vs_expectations.replay_context is not None
    assert tuple(
        item.waiver_id for item in report.candidate_vs_expectations.replay_context.waivers
    ) == (waiver.waiver_id,)


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


def test_case_scoped_tool_policies_are_reported_as_evaluated() -> None:
    compiled, runset = _runset(BASELINE)
    tools_by_case = {run.case_id: run.tools for run in runset.runs}
    case_scoped = compiled.model_copy(
        update={
            "defaults": compiled.defaults.model_copy(update={"allowed_tools": ()}),
            "resolved_expectations": tuple(
                expectation.model_copy(
                    update={
                        "allowed_tools": tools_by_case[expectation.case_id],
                        "allowed_tools_override": True,
                    }
                )
                for expectation in compiled.resolved_expectations
            ),
        }
    )
    bound_runset = runset.model_copy(update={"suite_digest": compiled_suite_digest(case_scoped)})

    report = evaluate_runset(
        case_scoped,
        bound_runset,
        gate_profile=GateProfile(fail_on_not_evaluated=True),
    )

    assert "tool_allowlist" not in {
        capability.capability_id for capability in report.not_evaluated_capabilities
    }
    assert not any(
        finding.control_id == "tool_allowlist" and finding.reason_code is ReasonCode.NOT_EVALUATED
        for finding in report.candidate_vs_expectations.findings
    )


def test_forbidden_tool_policy_is_reported_as_evaluated_without_default_allowlist() -> None:
    compiled, runset = _runset(BASELINE)
    first_expectation = compiled.resolved_expectations[0]
    forbidden_only = compiled.model_copy(
        update={
            "defaults": compiled.defaults.model_copy(update={"allowed_tools": ()}),
            "resolved_expectations": (
                first_expectation.model_copy(update={"forbidden_tools": ("never-used-tool",)}),
                *compiled.resolved_expectations[1:],
            ),
        }
    )
    bound_runset = runset.model_copy(update={"suite_digest": compiled_suite_digest(forbidden_only)})

    report = evaluate_runset(forbidden_only, bound_runset)

    assert "tool_allowlist" not in {
        capability.capability_id for capability in report.not_evaluated_capabilities
    }


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
    assert report.warning_controls[0].reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
    assert report.metrics.blocking_findings == 0
    assert report.metrics.warning_findings == 1
    assert report.metrics.evaluated_cases == 10
    assert report.metrics.passed_cases == 9
    assert report.metrics.warning_cases == 1
    assert report.metrics.failed_cases == 0
    assert report.metrics.total_cases == (
        report.metrics.passed_cases
        + report.metrics.warning_cases
        + report.metrics.failed_cases
        + report.metrics.unevaluated_cases
    )


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
        claim_finding_target("claim-present"),
        claim_finding_target("claim-missing"),
    }
    assert all(finding.control_id == "material_claims_have_evidence" for finding in findings)
    assert all(
        finding.reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE for finding in findings
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

    assert {finding.target for finding in findings} == {claim_finding_target("claim-present")}


def test_claim_evidence_links_accept_complete_content_addressed_evidence_pair() -> None:
    run = AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-item-link",
        case_id="case-item-link",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="redacted input",
        output_summary="redacted output",
        evidence_refs=(
            EvidenceRef(
                artifact_kind="evidence-ref",
                ref_id="item-ref",
                source_id="source-1",
            ),
        ),
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


def _active_waived_report() -> EvaluationReport:
    compiled, runset = _runset(EVIDENCE_CANDIDATE)
    initial_report = evaluate_runset(compiled, runset)
    finding = initial_report.candidate_vs_expectations.findings[0]
    evaluation_date = date(2026, 7, 3)
    waiver = Waiver(
        waiver_id="waiver-report-integrity",
        owner="quality-owner",
        reviewer="independent-reviewer",
        rationale="bounded accepted risk for report-integrity testing",
        reason_code=finding.reason_code,
        finding_id=finding.finding_id,
        artifact_digest=runset_digest(runset),
        expires_on=evaluation_date + timedelta(days=1),
    )
    return evaluate_runset(compiled, runset, waivers=(waiver,), today=evaluation_date)


def _no_tool_policy_report() -> tuple[CompiledSuite, RunSet, EvaluationReport]:
    compiled, runset = _runset(BASELINE)
    no_tool_policy = compiled.model_copy(
        update={
            "defaults": compiled.defaults.model_copy(update={"allowed_tools": ()}),
            "resolved_expectations": tuple(
                expectation.model_copy(
                    update={
                        "allowed_tools": (),
                        "allowed_tools_override": False,
                        "forbidden_tools": (),
                    }
                )
                for expectation in compiled.resolved_expectations
            ),
        }
    )
    bound_runset = runset.model_copy(update={"suite_digest": compiled_suite_digest(no_tool_policy)})
    return no_tool_policy, bound_runset, evaluate_runset(no_tool_policy, bound_runset)


def _report(variant: Path) -> EvaluationReport:
    compiled, runset = _runset(variant)
    return evaluate_runset(compiled, runset)


def _runset(variant: Path) -> tuple[CompiledSuite, RunSet]:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(variant), SUITE.parent)
    return compiled, runset


def _reason_codes(summary: EvaluationSummary) -> set[ReasonCode]:
    return {finding.reason_code for finding in summary.findings}


def _legacy_schema_version(value: object, schema_version: str) -> object:
    if isinstance(value, dict):
        return {
            str(key): (
                schema_version
                if key == "schema_version"
                else _legacy_schema_version(nested, schema_version)
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        return [_legacy_schema_version(item, schema_version) for item in value]
    return value
