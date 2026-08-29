from __future__ import annotations

import json
import os
import threading
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from agent_assure import rooted_io
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.config import LiveAdapterConfig, LivePromptCase, LiveRunConfig
from agent_assure.privacy.detectors import (
    PRIVACY_PROFILE_DIGEST,
    PRIVACY_PROFILE_ID,
    PRIVACY_REDACTION_TEXT,
)
from agent_assure.rag.repeated_sensitivity import (
    assemble_paired_observations,
    build_paired_runset_dependencies,
    run_repeated_live_study,
)
from agent_assure.rag.sensitivity_statistics import (
    build_stochastic_sensitivity_report,
    evaluate_statistical_sufficiency,
    plan_binary_paired_design,
)
from agent_assure.reporting import stochastic_sensitivity as writer
from agent_assure.reporting.stochastic_sensitivity import (
    REPEATED_ANALYSIS_OUTPUT_FILENAMES,
    REPEATED_RUN_OUTPUT_FILENAMES,
    RepeatedSensitivityOutputConflictError,
    RepeatedSensitivityPrivacyError,
    write_repeated_analysis_artifacts,
    write_repeated_run_artifacts,
)
from agent_assure.rooted_io import RootedDirectoryClaim, RootedDirectoryDescriptor
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, PolicyResult, RunSet
from agent_assure.schema.sensitivity import (
    RAGSensitivityAuthorityAssignment,
    RAGSensitivityCaseAuthorityBinding,
)
from agent_assure.schema.stochastic_sensitivity import (
    CaseClusterBinding,
    CouplingDescriptor,
    PairDisposition,
    RepeatedEvidenceSensitivityProtocol,
    SensitivityArmBinding,
)
from agent_assure.schema.suite import CompiledSuite


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _arm(arm_id: str, *, configuration: str, corpus: str) -> SensitivityArmBinding:
    is_baseline = arm_id == "baseline_evidence"
    return SensitivityArmBinding(
        arm_id=arm_id,
        expected_recommendation="approve" if is_baseline else "deny",
        expected_outcome="approved" if is_baseline else "denied",
        configuration_digest=_digest(configuration),
        corpus_digest=_digest(corpus),
        prompt_manifest_digest=_digest("shared-prompt-manifest"),
        case_manifest_digest=_digest("shared-case-manifest"),
        knowledge_contract_digest=_digest("knowledge-contract"),
        provider="static-provider",
        requested_model="static-model",
        adapter_id="openai-chat-completions",
        pipeline_id="sensitivity-pipeline",
        tool_schema_digest=_digest("tool-schema"),
        policy_bundle_digest=_digest("policy-bundle"),
    )


def _protocol(*, source_groups: bool = False) -> RepeatedEvidenceSensitivityProtocol:
    design = plan_binary_paired_design(
        familywise_alpha="0.050000",
        desired_power="0.800000",
        null_response_rate="0.500000",
        alternative_response_rate="0.900000",
        monte_carlo_resamples=1_000,
    )
    if source_groups:
        case_ids = tuple(f"case-{index:02d}" for index in range(16))
        cluster_ids = tuple(f"source-{index:02d}" for index in range(8))
        bindings = tuple(
            CaseClusterBinding(
                case_id=case_id,
                cluster_id=cluster_ids[index // 2],
            )
            for index, case_id in enumerate(case_ids)
        )
        cluster_by = "source_group_id"
    else:
        case_ids = tuple(f"case-{index:02d}" for index in range(8))
        cluster_ids = case_ids
        bindings = tuple(
            CaseClusterBinding(case_id=case_id, cluster_id=case_id) for case_id in case_ids
        )
        cluster_by = "case_id"
    baseline = _arm(
        "baseline_evidence",
        configuration="baseline-configuration",
        corpus="baseline-corpus",
    )
    counterfactual = _arm(
        "counterfactual_evidence",
        configuration="counterfactual-configuration",
        corpus="counterfactual-corpus",
    )
    return RepeatedEvidenceSensitivityProtocol.build(
        protocol_id="live-evidence-sensitivity",
        interpretation="confirmatory",
        execution_mode="stochastic_live",
        inferential_unit=cluster_by,
        cluster_by=cluster_by,
        baseline_arm=baseline,
        counterfactual_arm=counterfactual,
        planned_case_ids=case_ids,
        planned_cluster_ids=cluster_ids,
        case_cluster_bindings=bindings,
        case_authority_bindings=tuple(
            RAGSensitivityCaseAuthorityBinding(
                case_id=case_id,
                query_family_id="shared-query-family",
                assignments=tuple(
                    sorted(
                        (
                            RAGSensitivityAuthorityAssignment(
                                corpus_digest=baseline.corpus_digest,
                                expected_decision=baseline.expected_recommendation,
                                expected_outcome=baseline.expected_outcome,
                                governing_source_id=f"source-{case_id}",
                                governing_ref_id=f"ref-{case_id}",
                                governing_content_digest=_digest(f"baseline-content-{case_id}"),
                                claim_id=f"claim-{case_id}",
                            ),
                            RAGSensitivityAuthorityAssignment(
                                corpus_digest=counterfactual.corpus_digest,
                                expected_decision=counterfactual.expected_recommendation,
                                expected_outcome=counterfactual.expected_outcome,
                                governing_source_id=f"source-{case_id}",
                                governing_ref_id=f"ref-{case_id}",
                                governing_content_digest=_digest(
                                    f"counterfactual-content-{case_id}"
                                ),
                                claim_id=f"claim-{case_id}",
                            ),
                        ),
                        key=lambda item: item.corpus_digest,
                    )
                ),
            )
            for case_id in case_ids
        ),
        repetitions_per_arm=1,
        planned_pairs=len(case_ids),
        multiplicity_family="evidence-sensitivity",
        multiplicity_method="single_endpoint",
        multiplicity_family_size=1,
        coupling=CouplingDescriptor(
            pairing_identity_verified=True,
            stochastic_dimensions=(
                "provider_sampling_randomness",
                "temporal_execution_order",
            ),
            shared=("case_identity",),
            intentionally_different=("governing_corpus_digest",),
            not_shared=(
                "provider_sampling_randomness",
                "temporal_execution_order",
            ),
            unknown=(),
            requested_provider_seed=True,
            classification="nominally_paired",
            variance_reduction_claim_permitted=False,
        ),
        design=design,
        limitations=("Synthetic protocol for a bounded live-workflow test.",),
    )


def _cluster_for(protocol: RepeatedEvidenceSensitivityProtocol, case_id: str) -> str:
    return next(
        item.cluster_id for item in protocol.case_cluster_bindings if item.case_id == case_id
    )


def _record(
    protocol: RepeatedEvidenceSensitivityProtocol,
    *,
    arm_id: str,
    case_id: str,
    schedule_index: int,
    output_summary: str = "synthetic structured decision",
) -> AgentRunRecord:
    binding = (
        protocol.baseline_arm if arm_id == "baseline_evidence" else protocol.counterfactual_arm
    )
    cluster_id = _cluster_for(protocol, case_id)
    is_counterfactual = arm_id == "counterfactual_evidence"
    return AgentRunRecord(
        run_id=f"{arm_id}-{case_id}-r0",
        case_id=case_id,
        execution_mode="live",
        pipeline_id=binding.pipeline_id,
        recommendation="deny" if is_counterfactual else "approve",
        outcome="denied" if is_counterfactual else "approved",
        input_summary="synthetic request",
        output_summary=output_summary,
        observation_id=f"obs-{arm_id}-{case_id}-r0",
        repetition_index=0,
        schedule_index=schedule_index,
        randomization_block_id=f"block-{case_id}",
        cluster_id=cluster_id,
        source_group_id=(cluster_id if protocol.cluster_by == "source_group_id" else None),
        adapter_id=binding.adapter_id,
        provider=binding.provider,
        model=binding.requested_model,
        resolved_model=binding.resolved_model,
        provider_api_version=binding.provider_api_version,
        provider_sdk=binding.provider_sdk,
        provider_region=binding.provider_region,
        cost_budget_committed_usd="1.000000",
        generated_token_budget_committed=64,
        total_token_budget_committed=128,
        provenance=Provenance(
            configuration_digest=binding.configuration_digest,
            retrieval_corpus_digest=binding.corpus_digest,
            tool_schema_digest=binding.tool_schema_digest,
            policy_bundle_digest=binding.policy_bundle_digest,
            evidence_sensitivity_design_digest=protocol.design_commitment_digest,
            model_identifier=binding.requested_model,
        ),
    )


def _runset(
    protocol: RepeatedEvidenceSensitivityProtocol,
    *,
    arm_id: str,
    omitted: frozenset[str] = frozenset(),
    completion_status: str = "complete",
    output_summary: str = "synthetic structured decision",
) -> RunSet:
    binding = (
        protocol.baseline_arm if arm_id == "baseline_evidence" else protocol.counterfactual_arm
    )
    runs = tuple(
        _record(
            protocol,
            arm_id=arm_id,
            case_id=case_id,
            schedule_index=index,
            output_summary=output_summary,
        )
        for index, case_id in enumerate(protocol.planned_case_ids)
        if case_id not in omitted
    )
    return RunSet(
        runset_id=f"{arm_id}-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="synthetic-live-suite",
        suite_version="1.0.0",
        suite_digest=_digest("compiled-suite"),
        fixture_manifest_digest=binding.configuration_digest,
        execution_mode="live",
        protocol_id="operational-live-protocol",
        protocol_digest=_digest("operational-live-protocol"),
        evidence_sensitivity_design_digest=protocol.design_commitment_digest,
        completion_status=completion_status,
        stop_reasons=("provider-budget-stop",) if completion_status == "incomplete" else (),
        runs=runs,
    )


def _replace_first_record(runset: RunSet, record: AgentRunRecord) -> RunSet:
    return runset.model_copy(update={"runs": (record, *runset.runs[1:])})


def _operational_exclusion(
    record: AgentRunRecord,
    exclusion_reason: str,
) -> AgentRunRecord:
    reason_code = "RUNTIME_FAILED" if exclusion_reason == "runtime-failed" else "POLICY_FAILED"
    outcome = "runtime_error" if exclusion_reason == "runtime-failed" else "excluded"
    return record.model_copy(
        update={
            "recommendation": "error",
            "outcome": outcome,
            "observation_status": "excluded",
            "exclusion_reason": exclusion_reason,
            "policy_results": (
                PolicyResult(
                    policy_id="runtime.live",
                    state="fail",
                    reason_codes=(reason_code,),
                    severity="blocker",
                    message="operational failure before a decision was accepted",
                ),
            ),
        }
    )


def _analysis_generation(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
):
    observations = assemble_paired_observations(protocol, baseline, counterfactual)
    sources = build_paired_runset_dependencies(protocol, baseline, counterfactual)
    sufficiency = evaluate_statistical_sufficiency(
        protocol,
        observations,
        source_runsets=sources,
    )
    return sufficiency, build_stochastic_sensitivity_report(sufficiency)


def test_assemble_realistic_current_live_runsets_and_missing_dispositions() -> None:
    protocol = _protocol()
    baseline_only = protocol.planned_case_ids[-3]
    counterfactual_only = protocol.planned_case_ids[-2]
    missing_both = protocol.planned_case_ids[-1]
    baseline = _runset(
        protocol,
        arm_id="baseline_evidence",
        omitted=frozenset({counterfactual_only, missing_both}),
    )
    counterfactual = _runset(
        protocol,
        arm_id="counterfactual_evidence",
        omitted=frozenset({baseline_only, missing_both}),
    )

    observations = assemble_paired_observations(protocol, baseline, counterfactual)
    by_case = {item.case_id: item for item in observations}

    assert len(observations) == protocol.planned_pairs
    assert by_case[baseline_only].disposition is PairDisposition.missing_counterfactual
    assert by_case[baseline_only].disposition_reason == "counterfactual-pair-missing"
    assert by_case[baseline_only].baseline_run_id is not None
    assert by_case[baseline_only].counterfactual_run_id is None
    assert by_case[counterfactual_only].disposition is PairDisposition.missing_baseline
    assert by_case[counterfactual_only].disposition_reason == "baseline-pair-missing"
    assert by_case[counterfactual_only].baseline_run_id is None
    assert by_case[counterfactual_only].counterfactual_run_id is not None
    assert by_case[missing_both].disposition is PairDisposition.missing_both
    assert by_case[missing_both].disposition_reason == "both-arm-pair-missing"
    assert by_case[missing_both].baseline_run_id is None
    assert by_case[missing_both].counterfactual_run_id is None


def test_missing_both_uses_the_frozen_source_group_binding() -> None:
    protocol = _protocol(source_groups=True)
    missing_case = protocol.planned_case_ids[-1]
    baseline = _runset(
        protocol,
        arm_id="baseline_evidence",
        omitted=frozenset({missing_case}),
    )
    counterfactual = _runset(
        protocol,
        arm_id="counterfactual_evidence",
        omitted=frozenset({missing_case}),
    )

    observation = next(
        item
        for item in assemble_paired_observations(protocol, baseline, counterfactual)
        if item.case_id == missing_case
    )

    assert observation.disposition is PairDisposition.missing_both
    assert observation.cluster_id == _cluster_for(protocol, missing_case)
    assert observation.cluster_id != missing_case


def test_incomplete_runset_is_inconclusive_and_cannot_create_a_dependency() -> None:
    protocol = _protocol()
    omitted_case = protocol.planned_case_ids[-1]
    baseline = _runset(
        protocol,
        arm_id="baseline_evidence",
        omitted=frozenset({omitted_case}),
        completion_status="incomplete",
    )
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")

    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)

    assert sufficiency.state.value == "inconclusive"
    assert report.state.value == "inconclusive"
    assert report.dependency is None
    assert not report.verdict_bearing
    assert len(sufficiency.source_runsets[0].records) == protocol.planned_pairs - 1
    assert sufficiency.analysis is not None
    assert sufficiency.analysis.compared_clusters == protocol.design.planned_inferential_clusters
    assert sufficiency.analysis.analyzable_clusters == protocol.planned_pairs - 1
    assert sufficiency.analysis.non_analyzable_clusters_scored_zero == 1
    source_record_check = next(
        item for item in sufficiency.prerequisites if item.check_id == "source_record_binding"
    )
    source_execution_check = next(
        item for item in sufficiency.prerequisites if item.check_id == "source_execution_complete"
    )
    assert source_record_check.state.value == "satisfied"
    assert source_execution_check.state.value == "unmet"


def test_complete_runset_dependency_rejects_a_missing_planned_cell() -> None:
    protocol = _protocol()
    missing_case = protocol.planned_case_ids[-1]
    baseline = _runset(
        protocol,
        arm_id="baseline_evidence",
        omitted=frozenset({missing_case}),
    )
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")

    with pytest.raises(ValueError, match="exactly cover the frozen planned cell manifest"):
        build_paired_runset_dependencies(protocol, baseline, counterfactual)


@pytest.mark.parametrize(
    ("field_name", "expected_disposition"),
    (
        ("provider", PairDisposition.identity_mismatch),
        ("model", PairDisposition.identity_mismatch),
        ("tool_schema_digest", PairDisposition.identity_mismatch),
        ("policy_bundle_digest", PairDisposition.identity_mismatch),
        ("retrieval_corpus_digest", PairDisposition.identity_mismatch),
        ("configuration_digest", PairDisposition.identity_mismatch),
        ("runset_configuration_digest", PairDisposition.undeclared_arm_difference),
    ),
)
def test_arm_identity_mismatches_are_structurally_invalid_and_never_pass(
    field_name: str,
    expected_disposition: PairDisposition,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    if field_name == "runset_configuration_digest":
        counterfactual = counterfactual.model_copy(
            update={"fixture_manifest_digest": _digest("undeclared-config")}
        )
    else:
        first = counterfactual.runs[0]
        if field_name in {"provider", "model"}:
            first = first.model_copy(update={field_name: f"unexpected-{field_name}"})
        else:
            first = first.model_copy(
                update={
                    "provenance": first.provenance.model_copy(
                        update={field_name: _digest(f"unexpected-{field_name}")}
                    )
                }
            )
        counterfactual = _replace_first_record(counterfactual, first)

    observations = assemble_paired_observations(protocol, baseline, counterfactual)
    assert observations[0].disposition is expected_disposition
    sufficiency = evaluate_statistical_sufficiency(protocol, observations)
    report = build_stochastic_sensitivity_report(sufficiency)
    arm_check = next(
        item
        for item in sufficiency.prerequisites
        if item.check_id == "arm_configuration_comparability"
    )
    assert arm_check.state.value == "unmet"
    assert sufficiency.state.value == "prerequisites_unmet"
    assert report.state.value == "prerequisites_unmet"
    assert report.dependency is None
    assert not report.verdict_bearing


def test_schedule_fields_are_audit_only_and_matching_provider_snapshot_is_comparable() -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    baseline_first = baseline.runs[0].model_copy(
        update={
            "resolved_model": "gpt-4o-2024-08-06",
            "provider_sdk": "openai/2.0",
            "provenance": baseline.runs[0].provenance.model_copy(
                update={"model_identifier": protocol.baseline_arm.requested_model}
            ),
        }
    )
    counterfactual_first = counterfactual.runs[0].model_copy(
        update={
            "schedule_index": 10_000,
            "randomization_block_id": "different-audit-block",
            "resolved_model": "gpt-4o-2024-08-06",
            "provider_sdk": "openai/2.0",
            "provenance": counterfactual.runs[0].provenance.model_copy(
                update={"model_identifier": protocol.counterfactual_arm.requested_model}
            ),
        }
    )

    observations = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, baseline_first),
        _replace_first_record(counterfactual, counterfactual_first),
    )

    assert observations[0].disposition is PairDisposition.included
    assert observations[0].endpoint_value == 1


@pytest.mark.parametrize(
    ("field_name", "baseline_value", "counterfactual_value"),
    (
        ("resolved_model", "gpt-4o-2024-08-06", "gpt-4o-2025-01-01"),
        ("provider_api_version", "2026-01-01", "2026-02-01"),
        ("provider_sdk", "openai/2.0", "openai/2.1"),
        ("provider_region", "us-east", "us-west"),
        ("resolved_model", None, "gpt-4o-2024-08-06"),
    ),
)
def test_unfrozen_provider_identity_must_still_match_across_arms(
    field_name: str,
    baseline_value: str | None,
    counterfactual_value: str | None,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")

    observations = assemble_paired_observations(
        protocol,
        _replace_first_record(
            baseline,
            baseline.runs[0].model_copy(update={field_name: baseline_value}),
        ),
        _replace_first_record(
            counterfactual,
            counterfactual.runs[0].model_copy(update={field_name: counterfactual_value}),
        ),
    )

    assert observations[0].disposition is PairDisposition.identity_mismatch
    assert observations[0].endpoint_value is None


def test_frozen_resolved_model_fails_closed_when_provider_omits_it() -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["baseline_arm"] = original.baseline_arm.model_copy(
        update={"resolved_model": "gpt-4o-2024-08-06"}
    )
    payload["counterfactual_arm"] = original.counterfactual_arm.model_copy(
        update={"resolved_model": "gpt-4o-2024-08-06"}
    )
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    baseline_first = baseline.runs[0].model_copy(
        update={
            "resolved_model": None,
            "provenance": baseline.runs[0].provenance.model_copy(
                update={"model_identifier": protocol.baseline_arm.requested_model}
            ),
        }
    )

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, baseline_first),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.identity_mismatch
    assert observation.endpoint_value is None


def test_contradictory_provenance_model_identity_is_structurally_invalid() -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    tampered = baseline.runs[0].model_copy(
        update={
            "provenance": baseline.runs[0].provenance.model_copy(
                update={"model_identifier": "different-model"}
            )
        }
    )

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, tampered),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.identity_mismatch
    assert observation.endpoint_value is None


def test_expected_endpoint_rejects_a_wrong_direction_string_flip() -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    baseline_first = baseline.runs[0].model_copy(
        update={"recommendation": "deny", "outcome": "denied"}
    )
    counterfactual_first = counterfactual.runs[0].model_copy(
        update={"recommendation": "approve", "outcome": "approved"}
    )

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, baseline_first),
        _replace_first_record(counterfactual, counterfactual_first),
    )[0]

    assert observation.disposition is PairDisposition.included
    assert observation.baseline_expected_recommendation.value == "approve"
    assert observation.counterfactual_expected_recommendation.value == "deny"
    assert observation.endpoint_value == 0


@pytest.mark.parametrize("include_policy_failure", (False, True))
def test_runtime_error_records_are_typed_invalid_and_never_score(
    include_policy_failure: bool,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    policy_results = (
        (
            PolicyResult(
                policy_id="runtime.live",
                state="fail",
                reason_codes=("RUNTIME_FAILED",),
                severity="blocker",
                message="provider failed before a structured record was accepted",
            ),
        )
        if include_policy_failure
        else ()
    )
    failed = baseline.runs[0].model_copy(
        update={
            "recommendation": "error",
            "outcome": "runtime_error",
            "observation_status": "included",
            "exclusion_reason": None,
            "policy_results": policy_results,
        }
    )

    observations = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, failed),
        counterfactual,
    )
    sufficiency = evaluate_statistical_sufficiency(protocol, observations)
    report = build_stochastic_sensitivity_report(sufficiency)

    assert observations[0].disposition is PairDisposition.invalid_baseline
    assert observations[0].endpoint_value is None
    assert sufficiency.state.value == "prerequisites_unmet"
    assert report.state.value == "prerequisites_unmet"
    assert not report.verdict_bearing


@pytest.mark.parametrize(
    ("exclusion_reason", "expected_reason"),
    (
        ("structured-output-invalid", "blocking-runtime-policy-failure"),
        ("policy-failed", "blocking-runtime-policy-failure"),
        ("runtime-failed", "invalid-operational-exclusion-provenance"),
    ),
)
def test_structural_invalid_record_cannot_be_laundered_through_exclusion_allowlist(
    exclusion_reason: str,
    expected_reason: str,
) -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = (
        "policy-failed",
        "runtime-failed",
        "structured-output-invalid",
    )
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    excluded = baseline.runs[0].model_copy(
        update={
            "recommendation": "error",
            "outcome": "runtime_error",
            "observation_status": "excluded",
            "exclusion_reason": exclusion_reason,
            "policy_results": (
                PolicyResult(
                    policy_id="runtime.live",
                    state="fail",
                    reason_codes=("STRUCTURED_OUTPUT_INVALID",),
                    severity="blocker",
                    message="no valid structured record was accepted",
                ),
            ),
        }
    )

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, excluded),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.invalid_baseline
    assert observation.disposition_reason == expected_reason
    assert observation.baseline_exclusion_reason is None
    assert observation.counterfactual_exclusion_reason is None
    assert observation.endpoint_value is None


@pytest.mark.parametrize(
    "exclusion_reason",
    ("runtime-failed", "token_budget_exhausted"),
)
def test_predeclared_operational_failure_remains_a_policy_exclusion(
    exclusion_reason: str,
) -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = (
        "runtime-failed",
        "token_budget_exhausted",
    )
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    excluded = _operational_exclusion(baseline.runs[0], exclusion_reason)

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, excluded),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.excluded_baseline
    assert observation.disposition_reason == exclusion_reason
    assert observation.baseline_exclusion_reason == exclusion_reason
    assert observation.endpoint_value is None


def test_operational_exclusion_requires_exact_runtime_policy_provenance() -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = ("runtime-failed",)
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    excluded_without_provenance = baseline.runs[0].model_copy(
        update={
            "recommendation": "error",
            "outcome": "runtime_error",
            "observation_status": "excluded",
            "exclusion_reason": "runtime-failed",
            "policy_results": (),
        }
    )

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, excluded_without_provenance),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.invalid_baseline
    assert observation.disposition_reason == "invalid-operational-exclusion-provenance"
    assert observation.baseline_exclusion_reason is None


def test_nonruntime_blocker_cannot_be_disguised_as_runtime_exclusion() -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = ("runtime-failed",)
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    disguised = baseline.runs[0].model_copy(
        update={
            "recommendation": "error",
            "outcome": "runtime_error",
            "observation_status": "excluded",
            "exclusion_reason": "runtime-failed",
            "policy_results": (
                PolicyResult(
                    policy_id="domain.safety",
                    state="fail",
                    reason_codes=("RUNTIME_FAILED",),
                    severity="blocker",
                    message="domain blocker relabeled as a runtime failure",
                ),
            ),
        }
    )

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, disguised),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.invalid_baseline
    assert observation.disposition_reason == "invalid-operational-exclusion-provenance"


def test_excluded_record_requires_randomization_audit_identity() -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = ("runtime-failed",)
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    missing_block = _operational_exclusion(
        baseline.runs[0],
        "runtime-failed",
    ).model_copy(update={"randomization_block_id": None})

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, missing_block),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.identity_mismatch
    assert observation.disposition_reason == "record-arm-binding-mismatch"


@pytest.mark.parametrize(
    "field_name",
    (
        "resolved_model",
        "provider_api_version",
        "provider_sdk",
        "provider_region",
    ),
)
def test_excluded_pair_rejects_known_cross_arm_response_identity_mismatch(
    field_name: str,
) -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = ("runtime-failed",)
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    baseline_record = _operational_exclusion(baseline.runs[0], "runtime-failed")
    counterfactual_record = _operational_exclusion(
        counterfactual.runs[0],
        "runtime-failed",
    )
    baseline_update: dict[str, object] = {field_name: "response-identity-a"}
    counterfactual_update: dict[str, object] = {field_name: "response-identity-b"}
    baseline_record = baseline_record.model_copy(update=baseline_update)
    counterfactual_record = counterfactual_record.model_copy(update=counterfactual_update)

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, baseline_record),
        _replace_first_record(counterfactual, counterfactual_record),
    )[0]

    assert observation.disposition is PairDisposition.identity_mismatch
    assert observation.disposition_reason == "paired-record-response-identity-mismatch"


def test_excluded_record_must_still_match_its_frozen_arm_binding() -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = ("runtime-failed",)
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    record = baseline.runs[0]
    tampered = _operational_exclusion(record, "runtime-failed").model_copy(
        update={
            "provenance": record.provenance.model_copy(
                update={"configuration_digest": _digest("tampered-configuration")}
            ),
        }
    )

    observation = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, tampered),
        counterfactual,
    )[0]

    assert observation.disposition is PairDisposition.identity_mismatch
    assert observation.disposition_reason == "record-arm-binding-mismatch"
    assert observation.baseline_exclusion_reason is None


@pytest.mark.parametrize(
    (
        "baseline_reason",
        "counterfactual_reason",
        "expected_disposition",
        "expected_summary",
    ),
    (
        (
            "runtime-failed",
            None,
            PairDisposition.excluded_baseline,
            "runtime-failed",
        ),
        (
            "runtime-failed",
            "runtime-failed",
            PairDisposition.excluded_both,
            "runtime-failed",
        ),
        (
            "runtime-failed",
            "budget_exhausted",
            PairDisposition.excluded_both,
            "mixed-arm-exclusions",
        ),
    ),
)
def test_predeclared_operational_exclusions_are_checked_per_arm(
    baseline_reason: str,
    counterfactual_reason: str | None,
    expected_disposition: PairDisposition,
    expected_summary: str,
) -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = (
        "budget_exhausted",
        "runtime-failed",
    )
    payload["design"] = plan_binary_paired_design(
        familywise_alpha="0.050000",
        desired_power="0.800000",
        null_response_rate="0.500000",
        alternative_response_rate="0.900000",
        maximum_exclusion_rate="0.250000",
        planned_inferential_clusters=len(original.planned_cluster_ids),
        monte_carlo_resamples=1_000,
    )
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")

    baseline_first = _operational_exclusion(baseline.runs[0], baseline_reason)
    counterfactual_first = counterfactual.runs[0]
    if counterfactual_reason is not None:
        counterfactual_first = _operational_exclusion(
            counterfactual_first,
            counterfactual_reason,
        )
    observations = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, baseline_first),
        _replace_first_record(counterfactual, counterfactual_first),
    )
    sufficiency = evaluate_statistical_sufficiency(protocol, observations)
    exclusion_check = next(
        item for item in sufficiency.prerequisites if item.check_id == "exclusion_policy"
    )
    record_check = next(
        item for item in sufficiency.prerequisites if item.check_id == "record_validity"
    )

    assert observations[0].disposition is expected_disposition
    assert observations[0].disposition_reason == expected_summary
    assert observations[0].baseline_exclusion_reason == baseline_reason
    assert observations[0].counterfactual_exclusion_reason == counterfactual_reason
    assert exclusion_check.state.value == "satisfied"
    assert record_check.state.value == "satisfied"


def test_untrusted_exclusion_reason_is_normalized_to_machine_identifier() -> None:
    original = _protocol()
    payload = original.model_dump(
        mode="python",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    payload["allowed_exclusion_reasons"] = ("runtime-failed",)
    protocol = RepeatedEvidenceSensitivityProtocol.build(**payload)
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    excluded = baseline.runs[0].model_copy(
        update={
            "observation_status": "excluded",
            "exclusion_reason": ".runtime-failed",
        }
    )

    observations = assemble_paired_observations(
        protocol,
        _replace_first_record(baseline, excluded),
        counterfactual,
    )
    observation = observations[0]
    sufficiency = evaluate_statistical_sufficiency(protocol, observations)
    exclusion_check = next(
        item for item in sufficiency.prerequisites if item.check_id == "exclusion_policy"
    )

    assert observation.disposition is PairDisposition.excluded_baseline
    assert observation.disposition_reason == "reason-.runtime-failed"
    assert observation.disposition_reason != "runtime-failed"
    assert exclusion_check.state.value == "unmet"


@pytest.mark.parametrize("cluster_id", ("wrong-cluster", ".wrong-cluster"))
def test_late_cluster_mismatch_is_typed_instead_of_raising(cluster_id: str) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    mismatched = counterfactual.runs[0].model_copy(update={"cluster_id": cluster_id})

    observation = assemble_paired_observations(
        protocol,
        baseline,
        _replace_first_record(counterfactual, mismatched),
    )[0]

    assert observation.disposition is PairDisposition.identity_mismatch
    assert observation.cluster_id == _cluster_for(protocol, observation.case_id)
    assert observation.endpoint_value is None


def test_hostile_source_identifiers_are_structural_and_digest_surrogated() -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    hostile_record = baseline.runs[0].model_copy(update={"run_id": ".hostile-run"})
    unsafe_digest = sha256_hexdigest(
        {
            "kind": "source-identifier-unsafe",
            "namespace": "run",
            "value": hostile_record.run_id,
        }
    )
    chosen_collision = f"run-unsafe-{unsafe_digest}"
    collision_record = baseline.runs[1].model_copy(update={"run_id": chosen_collision})
    hostile_baseline = baseline.model_copy(
        update={
            "runset_id": ".hostile-baseline-runset",
            "protocol_id": ".hostile-operational-protocol",
            "completion_status": "incomplete",
            "stop_reasons": (".hostile-stop",),
            "runs": (hostile_record, collision_record, *baseline.runs[2:]),
        }
    )
    hostile_counterfactual = counterfactual.model_copy(
        update={
            "runset_id": ".hostile-counterfactual-runset",
            "protocol_id": ".hostile-operational-protocol",
            "completion_status": "incomplete",
            "stop_reasons": (".hostile-stop",),
        }
    )

    observations = assemble_paired_observations(
        protocol,
        hostile_baseline,
        hostile_counterfactual,
    )
    dependencies = build_paired_runset_dependencies(
        protocol,
        hostile_baseline,
        hostile_counterfactual,
    )
    sufficiency = evaluate_statistical_sufficiency(
        protocol,
        observations,
        source_runsets=dependencies,
    )

    assert all(
        item.disposition is PairDisposition.undeclared_arm_difference for item in observations
    )
    first_observation = observations[0]
    second_observation = observations[1]
    assert first_observation.cluster_id == _cluster_for(protocol, first_observation.case_id)
    assert first_observation.baseline_run_id is not None
    assert first_observation.baseline_run_id == chosen_collision
    assert second_observation.baseline_run_id is not None
    assert second_observation.baseline_run_id.startswith("run-escaped-")
    assert second_observation.baseline_run_id != first_observation.baseline_run_id
    baseline_dependency, counterfactual_dependency = dependencies
    assert baseline_dependency.runset_id.startswith("runset-unsafe-")
    assert counterfactual_dependency.runset_id.startswith("runset-unsafe-")
    assert baseline_dependency.operational_protocol_id.startswith("protocol-unsafe-")
    assert baseline_dependency.stop_reasons[0].startswith("stop-reason-unsafe-")
    assert baseline_dependency.records[0].run_id == first_observation.baseline_run_id
    assert baseline_dependency.records[1].run_id == second_observation.baseline_run_id
    assert len({item.run_id for item in baseline_dependency.records}) == len(
        baseline_dependency.records
    )
    assert baseline_dependency.records[0].run_digest == sha256_hexdigest(
        hostile_record.model_dump(mode="json")
    )
    assert sufficiency.state.value == "prerequisites_unmet"


def test_runset_dependencies_bind_exact_record_manifests_and_commitment() -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")

    baseline_dependency, counterfactual_dependency = build_paired_runset_dependencies(
        protocol,
        baseline,
        counterfactual,
    )

    assert baseline_dependency.runset_digest == sha256_hexdigest(baseline.model_dump(mode="json"))
    assert counterfactual_dependency.runset_digest == sha256_hexdigest(
        counterfactual.model_dump(mode="json")
    )
    assert baseline_dependency.evidence_sensitivity_design_digest == (
        protocol.design_commitment_digest
    )
    assert tuple(
        (item.case_id, item.repetition_index, item.run_id, item.run_digest)
        for item in baseline_dependency.records
    ) == tuple(
        (
            run.case_id,
            run.repetition_index,
            run.run_id,
            sha256_hexdigest(run.model_dump(mode="json")),
        )
        for run in baseline.runs
    )

    wrong_commitment = _digest("wrong-preexecution-design")
    mismatched_runs = tuple(
        run.model_copy(
            update={
                "provenance": run.provenance.model_copy(
                    update={"evidence_sensitivity_design_digest": wrong_commitment}
                )
            }
        )
        for run in counterfactual.runs
    )
    mismatched = counterfactual.model_copy(
        update={
            "evidence_sensitivity_design_digest": wrong_commitment,
            "runs": mismatched_runs,
        }
    )
    with pytest.raises(ValueError, match="protocol binding|design commitment"):
        build_paired_runset_dependencies(protocol, baseline, mismatched)


def test_wrong_design_commitment_fails_before_live_adapter_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    dispatches: list[str] = []

    def unexpected_dispatch(*args: object, **kwargs: object) -> RunSet:
        dispatches.append("called")
        raise AssertionError("live adapter dispatch must not occur")

    monkeypatch.setattr(
        "agent_assure.rag.repeated_sensitivity.run_live_suite",
        unexpected_dispatch,
    )
    common = {
        "pipeline_id": "sensitivity-pipeline",
        "tool_schema_digest": _digest("tool-schema"),
        "policy_bundle_digest": _digest("policy-bundle"),
        "adapter": LiveAdapterConfig(
            adapter_id="static-jsonl",
            provider="static-provider",
            model="static-model",
            response_jsonl_path="responses.jsonl",
        ),
        "cases": tuple(
            LivePromptCase(
                case_id=case_id,
                prompt_path=f"{case_id}.txt",
                input_summary="synthetic request",
            )
            for case_id in protocol.planned_case_ids
        ),
        "repetitions": 1,
        "max_requests": len(protocol.planned_case_ids),
        "max_retries": 0,
    }
    baseline_config = LiveRunConfig(
        variant_id="baseline",
        retrieval_corpus_digest=protocol.baseline_arm.corpus_digest,
        knowledge_contract_digest=protocol.baseline_arm.knowledge_contract_digest,
        evidence_sensitivity_design_digest=_digest("wrong-design"),
        **common,
    )
    counterfactual_config = LiveRunConfig(
        variant_id="counterfactual",
        retrieval_corpus_digest=protocol.counterfactual_arm.corpus_digest,
        knowledge_contract_digest=protocol.counterfactual_arm.knowledge_contract_digest,
        evidence_sensitivity_design_digest=protocol.design_commitment_digest,
        **common,
    )

    with pytest.raises(ValueError, match="baseline.*pre-execution design commitment"):
        run_repeated_live_study(
            compiled=cast(CompiledSuite, object()),
            protocol=protocol,
            baseline_config=baseline_config,
            counterfactual_config=counterfactual_config,
            operational_protocol=cast(LiveProtocolRecord, object()),
            baseline_config_dir=tmp_path,
            counterfactual_config_dir=tmp_path,
        )
    assert dispatches == []


@pytest.mark.parametrize("adapter_id", ("static-jsonl", "external-script"))
def test_confirmatory_stochastic_study_rejects_deterministic_replay_adapters(
    adapter_id: str,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    adapter = LiveAdapterConfig(
        adapter_id=adapter_id,
        provider="replay-provider",
        model="replay-model",
        response_jsonl_path="responses.jsonl" if adapter_id == "static-jsonl" else None,
        script_path="adapter.py" if adapter_id == "external-script" else None,
    )
    common = {
        "pipeline_id": "sensitivity-pipeline",
        "tool_schema_digest": _digest("tool-schema"),
        "policy_bundle_digest": _digest("policy-bundle"),
        "retrieval_corpus_dir": "corpus",
        "knowledge_contract_path": "knowledge-contract.yaml",
        "adapter": adapter,
        "cases": tuple(
            LivePromptCase(
                case_id=case_id,
                prompt_path=f"{case_id}.txt",
                input_summary="synthetic request",
            )
            for case_id in protocol.planned_case_ids
        ),
        "repetitions": 1,
        "max_requests": len(protocol.planned_case_ids),
        "max_retries": 0,
        "evidence_sensitivity_design_digest": protocol.design_commitment_digest,
    }
    baseline_config = LiveRunConfig(
        variant_id="baseline",
        retrieval_corpus_digest=protocol.baseline_arm.corpus_digest,
        knowledge_contract_digest=protocol.baseline_arm.knowledge_contract_digest,
        **common,
    )
    counterfactual_config = LiveRunConfig(
        variant_id="counterfactual",
        retrieval_corpus_digest=protocol.counterfactual_arm.corpus_digest,
        knowledge_contract_digest=protocol.counterfactual_arm.knowledge_contract_digest,
        **common,
    )

    with pytest.raises(ValueError, match="confirmatory stochastic sensitivity"):
        run_repeated_live_study(
            compiled=cast(CompiledSuite, object()),
            protocol=protocol,
            baseline_config=baseline_config,
            counterfactual_config=counterfactual_config,
            operational_protocol=cast(LiveProtocolRecord, object()),
            baseline_config_dir=tmp_path,
            counterfactual_config_dir=tmp_path,
        )


def test_run_writer_redacts_credentials_and_raw_output(tmp_path: Path) -> None:
    protocol = _protocol()
    credential = "abcdefghijklmnopqrstuvwxyz123456"
    sensitive = f"Authorization: Bearer {credential}; patient jane@example.com"
    baseline = _runset(
        protocol,
        arm_id="baseline_evidence",
        output_summary=sensitive,
    )
    counterfactual = _runset(
        protocol,
        arm_id="counterfactual_evidence",
        output_summary=sensitive,
    )

    written = write_repeated_run_artifacts(
        protocol=protocol,
        baseline=baseline,
        counterfactual=counterfactual,
        out_dir=tmp_path / "run-generation",
    )

    assert tuple(written) == REPEATED_RUN_OUTPUT_FILENAMES
    assert baseline.runs[0].output_summary == sensitive
    persisted = json.loads(written["baseline.runset.json"].read_text(encoding="utf-8"))
    assert PRIVACY_REDACTION_TEXT in persisted["runs"][0]["output_summary"]
    assert credential not in json.dumps(persisted)
    assert "jane@example.com" not in json.dumps(persisted)


def test_analysis_writer_publishes_exact_dependency_bound_snapshots_idempotently(
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "analysis-generation"

    first = write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )
    first_text = {name: path.read_text(encoding="utf-8") for name, path in first.items()}
    second = write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )

    assert tuple(first) == REPEATED_ANALYSIS_OUTPUT_FILENAMES
    assert first == second
    assert first_text == {name: path.read_text(encoding="utf-8") for name, path in second.items()}
    baseline_payload = json.loads(first["baseline.source.runset.json"].read_text("utf-8"))
    counter_payload = json.loads(first["counterfactual.source.runset.json"].read_text("utf-8"))
    assert sha256_hexdigest(baseline_payload) == sufficiency.source_runsets[0].runset_digest
    assert sha256_hexdigest(counter_payload) == sufficiency.source_runsets[1].runset_digest
    sufficiency_payload = json.loads(
        first["statistical-sufficiency-report.json"].read_text("utf-8")
    )
    assert sufficiency_payload["source_runsets"] == [
        item.model_dump(mode="json") for item in sufficiency.source_runsets
    ]

    first["stochastic-evidence-sensitivity.md"].write_text(
        "foreign generation\n",
        encoding="utf-8",
    )
    with pytest.raises(RepeatedSensitivityOutputConflictError):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )


def test_analysis_writer_retains_early_file_pin_while_later_file_is_verified(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "coherent-analysis"
    write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )
    early = out_dir / REPEATED_ANALYSIS_OUTPUT_FILENAMES[0]
    later_name = REPEATED_ANALYSIS_OUTPUT_FILENAMES[-1]
    real_open = RootedDirectoryDescriptor.open_file_bounded
    replacement_succeeded = False
    replacement_blocked = False

    def replace_early_while_opening_later(
        self: RootedDirectoryDescriptor,
        name: str | Path,
        **kwargs: object,
    ) -> object:
        nonlocal replacement_succeeded, replacement_blocked
        if str(name) == later_name:
            try:
                early.unlink()
                early.write_text("concurrent replacement\n", encoding="utf-8")
                replacement_succeeded = True
            except OSError:
                replacement_blocked = True
        return real_open(self, name, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        RootedDirectoryDescriptor,
        "open_file_bounded",
        replace_early_while_opening_later,
    )
    try:
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )
    except RepeatedSensitivityOutputConflictError:
        assert replacement_succeeded
    else:
        assert replacement_blocked
        assert early.read_text(encoding="utf-8") != "concurrent replacement\n"


def test_analysis_writer_revalidates_early_created_file_after_later_creation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "coherent-new-analysis"
    early = out_dir / REPEATED_ANALYSIS_OUTPUT_FILENAMES[0]
    later_name = REPEATED_ANALYSIS_OUTPUT_FILENAMES[-1]
    real_open = RootedDirectoryClaim.open_regular_file_exclusive_with_metadata
    mutation_succeeded = False
    mutation_blocked = False

    def mutate_early_while_creating_later(
        self: RootedDirectoryClaim,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> tuple[int, os.stat_result]:
        nonlocal mutation_succeeded, mutation_blocked
        opened = real_open(self, name, mode=mode)
        if str(name) == later_name:
            try:
                early.write_text("concurrent mutation\n", encoding="utf-8")
                mutation_succeeded = True
            except OSError:
                mutation_blocked = True
        return opened

    monkeypatch.setattr(
        RootedDirectoryClaim,
        "open_regular_file_exclusive_with_metadata",
        mutate_early_while_creating_later,
    )
    try:
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )
    except OSError:
        assert mutation_succeeded
        assert not out_dir.exists()
    else:
        assert mutation_blocked
        assert early.read_text(encoding="utf-8") != "concurrent mutation\n"


def test_analysis_writer_rejects_redaction_or_snapshot_drift(tmp_path: Path) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)

    sensitive_record = baseline.runs[0].model_copy(
        update={"output_summary": "raw patient jane@example.com"}
    )
    sensitive_baseline = _replace_first_record(baseline, sensitive_record)
    with pytest.raises(RepeatedSensitivityPrivacyError, match="privacy-filtered"):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=sensitive_baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=tmp_path / "unsafe-analysis",
        )

    drifted_record = baseline.runs[0].model_copy(
        update={"output_summary": "different but privacy-safe summary"}
    )
    drifted_baseline = _replace_first_record(baseline, drifted_record)
    with pytest.raises(ValueError, match="source dependencies do not match"):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=drifted_baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=tmp_path / "drifted-analysis",
        )


def test_observation_schema_rejects_forged_directional_endpoint_semantics() -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, _ = _analysis_generation(protocol, baseline, counterfactual)
    first_observation_payload = sufficiency.observations[0].model_dump(mode="json")
    first_observation_payload.update(
        {
            "counterfactual_recommendation": "fabricated-deny",
            "counterfactual_outcome": "fabricated-denied",
        }
    )
    with pytest.raises(ValueError, match="endpoint_value must be exactly derived"):
        type(sufficiency.observations[0]).model_validate(first_observation_payload)


def test_analysis_writer_rejects_an_unplanned_source_cell(tmp_path: Path) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    first = baseline.runs[0]
    extra = first.model_copy(
        update={
            "run_id": "baseline-unplanned-case-r0",
            "case_id": "unplanned-case",
            "observation_id": "obs-baseline-unplanned-case-r0",
            "schedule_index": len(baseline.runs),
        }
    )
    malformed_baseline = baseline.model_copy(update={"runs": (*baseline.runs, extra)})

    with pytest.raises(ValueError, match="duplicate or unplanned"):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=malformed_baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=tmp_path / "unplanned-source",
        )


def test_analysis_writer_ignores_planted_stage_and_lock_entries_without_parent_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "retention-limited-analysis"
    target_digest = sha256(os.path.normcase(out_dir.name).encode("utf-8")).hexdigest()[:16]
    retained = tuple(
        tmp_path / f".agent-assure-stochastic-{target_digest}-{index:032x}.tmp"
        for index in range(8)
    )
    for path in retained:
        path.mkdir(mode=0o700)
    identities = tuple((os.lstat(path).st_dev, os.lstat(path).st_ino) for path in retained)
    lock_digest = sha256(os.path.normcase(out_dir.name).encode("utf-8")).hexdigest()[:32]
    planted_lock = tmp_path / f".agent-assure-stochastic-lock-{lock_digest}.lock"
    planted_lock.mkdir()
    real_entry_names = RootedDirectoryDescriptor.entry_names

    def reject_parent_inventory_scan(
        lease: RootedDirectoryDescriptor,
        *,
        max_entries: int,
        label: str,
    ) -> tuple[str, ...]:
        if lease.path == tmp_path:
            pytest.fail("publication must not enumerate the shared output parent")
        return real_entry_names(lease, max_entries=max_entries, label=label)

    monkeypatch.setattr(RootedDirectoryDescriptor, "entry_names", reject_parent_inventory_scan)

    written = write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )

    assert tuple(written) == REPEATED_ANALYSIS_OUTPUT_FILENAMES
    assert out_dir.is_dir()
    assert tuple((os.lstat(path).st_dev, os.lstat(path).st_ino) for path in retained) == identities
    assert planted_lock.is_dir()


@pytest.mark.parametrize(
    "detail",
    ("must be a regular file", "opaque rooted reader failure"),
)
def test_existing_generation_error_classification_does_not_parse_exception_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    detail: str,
) -> None:
    out_dir = tmp_path / "existing-analysis"
    out_dir.mkdir()
    (out_dir / "artifact.json").write_text("{}\n", encoding="utf-8")

    def fail_open(*_args: object, **_kwargs: object) -> object:
        raise ValueError(detail)

    monkeypatch.setattr(RootedDirectoryDescriptor, "open_file_bounded", fail_open)

    with writer.open_rooted_directory(
        tmp_path,
        ".",
        label="repeated sensitivity output parent",
    ) as parent:
        with pytest.raises(
            RepeatedSensitivityOutputConflictError,
            match="^existing repeated sensitivity output cannot be safely verified$",
        ) as exc_info:
            writer._existing_generation(parent, out_dir, ("artifact.json",))

    assert isinstance(exc_info.value.__cause__, ValueError)


def test_analysis_writer_reopens_every_child_after_fsync_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "final-child-pin-analysis"
    foreign = tmp_path / "foreign.json"
    foreign_bytes = b'{"foreign":"must-not-commit"}\n'
    foreign.write_bytes(foreign_bytes)
    real_fsync = writer._fsync_staged_generation
    planted: list[Path] = []

    def plant_hardlink_after_original_pins_close(claim: RootedDirectoryClaim) -> None:
        real_fsync(claim)
        victim = claim.path / "repeated-evidence-sensitivity-protocol.json"
        victim.unlink()
        os.link(foreign, victim)
        planted.append(victim)

    monkeypatch.setattr(
        writer,
        "_fsync_staged_generation",
        plant_hardlink_after_original_pins_close,
    )

    with pytest.raises(OSError, match="private staging retained at"):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )

    assert not out_dir.exists()
    assert len(planted) == 1
    assert planted[0].samefile(foreign)
    assert foreign.read_bytes() == foreign_bytes


def test_analysis_writer_detects_child_swap_after_final_validation_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "post-validation-child-swap-analysis"
    foreign_bytes = b'{"foreign":"swapped-after-final-validation"}\n'
    original_install = RootedDirectoryClaim.install_no_replace
    attempted: list[Path] = []

    def swap_child_then_install(
        claim: RootedDirectoryClaim,
        name: str | Path,
    ) -> None:
        victim = claim.path / "repeated-evidence-sensitivity-protocol.json"
        victim.unlink()
        victim.write_bytes(foreign_bytes)
        attempted.append(victim)
        original_install(claim, name)

    monkeypatch.setattr(
        RootedDirectoryClaim,
        "install_no_replace",
        swap_child_then_install,
    )

    with pytest.raises(
        OSError,
        match="committed, but post-commit identity validation failed",
    ):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )

    assert len(attempted) == 1
    assert out_dir.is_dir()
    assert (out_dir / "repeated-evidence-sensitivity-protocol.json").read_bytes() == foreign_bytes


@pytest.mark.skipif(os.name == "nt", reason="POSIX permits renaming an open parent directory")
def test_analysis_writer_rejects_parent_swap_at_directory_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    output_parent = tmp_path / "publication-parent"
    output_parent.mkdir()
    moved_parent = tmp_path / "publication-parent-moved"
    out_dir = output_parent / "analysis"
    original_install = RootedDirectoryClaim.install_no_replace
    swapped = False

    def replace_parent_with_exact_decoy_then_install(
        claim: RootedDirectoryClaim,
        name: str | Path,
    ) -> None:
        nonlocal swapped
        output_parent.rename(moved_parent)
        output_parent.mkdir()
        decoy = output_parent / Path(name)
        decoy.mkdir()
        moved_stage = moved_parent / claim.name
        for source in moved_stage.iterdir():
            (decoy / source.name).write_bytes(source.read_bytes())
        swapped = True
        original_install(claim, name)

    monkeypatch.setattr(
        RootedDirectoryClaim,
        "install_no_replace",
        replace_parent_with_exact_decoy_then_install,
    )

    with pytest.raises(
        OSError,
        match="committed, but post-commit durability or validation failed",
    ):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )

    assert swapped
    assert out_dir.is_dir()
    assert (moved_parent / out_dir.name).is_dir()
    assert {path.name for path in out_dir.iterdir()} == set(REPEATED_ANALYSIS_OUTPUT_FILENAMES)
    assert {path.name for path in (moved_parent / out_dir.name).iterdir()} == set(
        REPEATED_ANALYSIS_OUTPUT_FILENAMES
    )


def test_analysis_writer_keeps_failed_partial_private_and_recovers_without_deleting_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    real_open = RootedDirectoryClaim.open_regular_file_exclusive_with_metadata
    calls = 0

    def fail_second_write(
        self: RootedDirectoryClaim,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> tuple[int, os.stat_result]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected write failure")
        return real_open(self, name, mode=mode)

    monkeypatch.setattr(
        RootedDirectoryClaim,
        "open_regular_file_exclusive_with_metadata",
        fail_second_write,
    )
    out_dir = tmp_path / "atomic-analysis"
    with pytest.raises(OSError, match="private staging retained at") as exc_info:
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )

    assert not out_dir.exists()
    abandoned = tuple(tmp_path.glob(".agent-assure-stochastic-*.tmp"))
    assert len(abandoned) == 1
    assert str(abandoned[0]) in str(exc_info.value)
    abandoned_identity = os.lstat(abandoned[0])
    abandoned_names = tuple(sorted(item.name for item in abandoned[0].iterdir()))
    assert abandoned_names

    monkeypatch.setattr(
        RootedDirectoryClaim,
        "open_regular_file_exclusive_with_metadata",
        real_open,
    )
    written = write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )

    assert tuple(written) == REPEATED_ANALYSIS_OUTPUT_FILENAMES
    assert out_dir.is_dir()
    assert abandoned[0].is_dir()
    assert (os.lstat(abandoned[0]).st_dev, os.lstat(abandoned[0]).st_ino) == (
        abandoned_identity.st_dev,
        abandoned_identity.st_ino,
    )
    assert tuple(sorted(item.name for item in abandoned[0].iterdir())) == abandoned_names


def test_analysis_writer_late_failure_does_not_block_exact_generation_adoption(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "late-failure-analysis"
    committed = threading.Event()
    release_late_failure = threading.Event()
    second_started = threading.Event()
    second_finished = threading.Event()
    first_errors: list[BaseException] = []
    second_errors: list[BaseException] = []
    second_result: list[dict[str, Path]] = []
    real_after_commit = writer._after_generation_commit

    def fail_first_after_commit(parent: RootedDirectoryDescriptor) -> None:
        if not committed.is_set():
            committed.set()
            if not release_late_failure.wait(timeout=10):
                raise TimeoutError("test did not release injected late failure")
            raise OSError("injected post-commit failure")
        real_after_commit(parent)

    monkeypatch.setattr(writer, "_after_generation_commit", fail_first_after_commit)

    def publish_first() -> None:
        try:
            write_repeated_analysis_artifacts(
                protocol=protocol,
                baseline_source=baseline,
                counterfactual_source=counterfactual,
                sufficiency=sufficiency,
                report=report,
                out_dir=out_dir,
            )
        except BaseException as exc:
            first_errors.append(exc)

    def publish_second() -> None:
        second_started.set()
        try:
            second_result.append(
                write_repeated_analysis_artifacts(
                    protocol=protocol,
                    baseline_source=baseline,
                    counterfactual_source=counterfactual,
                    sufficiency=sufficiency,
                    report=report,
                    out_dir=out_dir,
                )
            )
        except BaseException as exc:
            second_errors.append(exc)
        finally:
            second_finished.set()

    first_thread = threading.Thread(target=publish_first)
    first_thread.start()
    assert committed.wait(timeout=10)
    assert out_dir.is_dir()
    second_thread = threading.Thread(target=publish_second)
    second_thread.start()
    assert second_started.wait(timeout=10)
    assert second_finished.wait(timeout=10)

    release_late_failure.set()
    first_thread.join(timeout=10)
    second_thread.join(timeout=10)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert len(first_errors) == 1
    assert isinstance(first_errors[0], OSError)
    assert "post-commit" in str(first_errors[0])
    assert not second_errors
    assert len(second_result) == 1
    assert tuple(second_result[0]) == REPEATED_ANALYSIS_OUTPUT_FILENAMES
    assert out_dir.is_dir()
    assert set(item.name for item in out_dir.iterdir()) == set(REPEATED_ANALYSIS_OUTPUT_FILENAMES)


def test_analysis_writer_adopts_exact_generation_that_wins_commit_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "exact-race-analysis"
    original_install = RootedDirectoryClaim.install_no_replace

    def commit_exact_generation_first(
        claim: RootedDirectoryClaim,
        name: str | Path,
    ) -> None:
        out_dir.mkdir()
        for source in claim.path.iterdir():
            (out_dir / source.name).write_bytes(source.read_bytes())
        original_install(claim, name)

    monkeypatch.setattr(
        RootedDirectoryClaim,
        "install_no_replace",
        commit_exact_generation_first,
    )

    adopted = write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )

    assert tuple(adopted) == REPEATED_ANALYSIS_OUTPUT_FILENAMES
    assert {path.name for path in out_dir.iterdir()} == set(REPEATED_ANALYSIS_OUTPUT_FILENAMES)
    assert len(tuple(tmp_path.glob(".agent-assure-stochastic-*.tmp"))) == 1


def test_analysis_writer_concurrent_publishers_converge_without_lock_wait(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "concurrent-analysis"
    publishers = 4
    first_check_barrier = threading.Barrier(publishers)
    first_checks: set[int] = set()
    check_lock = threading.Lock()
    real_existing = writer._existing_generation
    results: list[dict[str, Path]] = []
    errors: list[BaseException] = []

    def synchronize_first_check(
        parent: RootedDirectoryDescriptor,
        target: Path,
        expected_filenames: tuple[str, ...],
    ) -> dict[str, str] | None:
        thread_id = threading.get_ident()
        with check_lock:
            is_first = thread_id not in first_checks
            first_checks.add(thread_id)
        if is_first:
            first_check_barrier.wait(timeout=10)
        return real_existing(parent, target, expected_filenames)

    monkeypatch.setattr(writer, "_existing_generation", synchronize_first_check)

    def publish() -> None:
        try:
            results.append(
                write_repeated_analysis_artifacts(
                    protocol=protocol,
                    baseline_source=baseline,
                    counterfactual_source=counterfactual,
                    sufficiency=sufficiency,
                    report=report,
                    out_dir=out_dir,
                )
            )
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=publish) for _ in range(publishers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert all(not thread.is_alive() for thread in threads)
    assert not errors
    assert len(results) == publishers
    assert all(tuple(result) == REPEATED_ANALYSIS_OUTPUT_FILENAMES for result in results)
    assert {path.name for path in out_dir.iterdir()} == set(REPEATED_ANALYSIS_OUTPUT_FILENAMES)


def test_analysis_writer_classifies_install_validation_failure_as_postcommit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "post-install-validation-analysis"
    real_validation = rooted_io._require_installed_claim_identity

    def fail_post_install_validation(_claim: RootedDirectoryClaim) -> None:
        raise OSError("injected post-install validation failure")

    monkeypatch.setattr(
        rooted_io,
        "_require_installed_claim_identity",
        fail_post_install_validation,
    )
    with pytest.raises(OSError, match="output committed, but post-commit") as exc_info:
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )

    assert str(out_dir) in str(exc_info.value)
    assert out_dir.is_dir()
    assert not tuple(tmp_path.glob(".agent-assure-stochastic-*.tmp"))

    monkeypatch.setattr(
        rooted_io,
        "_require_installed_claim_identity",
        real_validation,
    )
    written = write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )
    assert tuple(written) == REPEATED_ANALYSIS_OUTPUT_FILENAMES


def test_analysis_writer_rejects_linked_output_directory(tmp_path: Path) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    target = tmp_path / "linked-target"
    target.mkdir()
    out_dir = tmp_path / "linked-analysis"
    try:
        out_dir.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")

    with pytest.raises(RepeatedSensitivityOutputConflictError, match="unlinked"):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )

    assert not tuple(target.iterdir())


def test_analysis_writer_rejects_hardlink_aliases_and_oversized_existing_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    protocol = _protocol()
    baseline = _runset(protocol, arm_id="baseline_evidence")
    counterfactual = _runset(protocol, arm_id="counterfactual_evidence")
    sufficiency, report = _analysis_generation(protocol, baseline, counterfactual)
    out_dir = tmp_path / "aliased-analysis"
    written = write_repeated_analysis_artifacts(
        protocol=protocol,
        baseline_source=baseline,
        counterfactual_source=counterfactual,
        sufficiency=sufficiency,
        report=report,
        out_dir=out_dir,
    )

    markdown = written["stochastic-evidence-sensitivity.md"]
    stochastic_json = written["stochastic-evidence-sensitivity.json"]
    markdown.unlink()
    try:
        os.link(stochastic_json, markdown)
    except OSError:
        pytest.skip("hard links are unavailable on this platform")
    with pytest.raises(RepeatedSensitivityOutputConflictError, match="non-regular"):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )

    markdown.unlink()
    markdown.write_text(
        writer.render_stochastic_sensitivity_markdown(report),
        encoding="utf-8",
    )
    maximum_valid_size = max(path.stat().st_size for path in written.values())
    monkeypatch.setattr(writer, "MAX_ARTIFACT_JSON_BYTES", maximum_valid_size)
    markdown.write_bytes(b"x" * (maximum_valid_size + 1))
    with pytest.raises(RepeatedSensitivityOutputConflictError, match="safely verified"):
        write_repeated_analysis_artifacts(
            protocol=protocol,
            baseline_source=baseline,
            counterfactual_source=counterfactual,
            sufficiency=sufficiency,
            report=report,
            out_dir=out_dir,
        )
