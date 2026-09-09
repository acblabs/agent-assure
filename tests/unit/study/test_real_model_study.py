from __future__ import annotations

from dataclasses import dataclass
from decimal import (
    ROUND_CEILING,
    ROUND_DOWN,
    ROUND_FLOOR,
    Decimal,
    Inexact,
    Rounded,
    localcontext,
)
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from pydantic import ValidationError

import agent_assure.study.analysis as study_analysis_module
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.config import LiveAdapterConfig, LivePromptCase, LiveRunConfig
from agent_assure.live.runner import (
    LiveExecutionSnapshot,
    calculate_provider_input_manifest_digest,
)
from agent_assure.rag.repeated_sensitivity import assemble_paired_observations
from agent_assure.rag.sensitivity_statistics import plan_binary_paired_design
from agent_assure.schema.benchmark import (
    ProcessEquivalenceBenchmarkCase,
    ProcessEquivalenceBenchmarkManifest,
)
from agent_assure.schema.run import (
    AgentRunRecord,
    LiveExecutionAttemptEvent,
    LiveExecutionAttemptJournal,
    RunSet,
)
from agent_assure.schema.sensitivity import (
    EvidenceSensitivityExpectedRelation,
    RAGSensitivityDecision,
    RAGSensitivityOutcome,
)
from agent_assure.schema.stochastic_sensitivity import (
    CaseClusterBinding,
    CouplingClassification,
    CouplingCondition,
    CouplingDescriptor,
    PairDisposition,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    SensitivityArmBinding,
)
from agent_assure.schema.study import (
    MAX_STUDY_CONDITIONS,
    RealModelStudyManifest,
    RealModelStudyReport,
    StudyBudget,
    StudyConditionBinding,
    StudyConditionResult,
    StudyConditionState,
    StudyExecutionOrigin,
    StudyExecutionWindow,
    StudyHypothesisClassification,
    StudyHypothesisDecisionRule,
    StudyIndependenceDesignBasis,
    StudyIndependenceJustification,
    StudyIndependenceJustificationStatus,
    StudyKnowledgeContract,
    StudyOneSidedInterval,
    StudyRegistration,
    StudyRegistrationMethod,
    StudyRegistrationReviewReceipt,
    StudySemanticNearDuplicateDisposition,
    calculate_study_knowledge_contract_digest,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.statistics.binomial_intervals import clopper_pearson_one_sided
from agent_assure.statistics.study_serialization import (
    bonferroni_adjusted_alpha,
    format_twelve_place_bound,
)
from agent_assure.study.analysis import (
    StudyConditionEvidence,
    analyze_real_model_study,
    bind_study_manifest_to_live_config,
    derive_study_observed_execution_provenance,
    validate_study_manifest_inputs,
)
from tests.stochastic_source_support import (
    build_case_authority_bindings,
    materialize_stochastic_sources,
)

_ArmId = Literal["baseline_evidence", "counterfactual_evidence"]


@dataclass(frozen=True, slots=True)
class StudyFixture:
    benchmark: ProcessEquivalenceBenchmarkManifest
    protocol: RepeatedEvidenceSensitivityProtocol
    manifest: RealModelStudyManifest
    evidence: StudyConditionEvidence
    protocols: dict[str, RepeatedEvidenceSensitivityProtocol]
    evidence_by_condition: dict[str, StudyConditionEvidence]
    registration_record_bytes: bytes
    registration_review_receipt: StudyRegistrationReviewReceipt


_REGISTRATION_RECORD_BYTES = b'{\n  "analysis_plan": "frozen synthetic test registration"\n}\n'


def _provider_input_digest(condition_id: str, arm_id: str, case_id: str) -> str:
    return _digest(f"provider-input:{condition_id}:{arm_id}:{case_id}")


def _provider_input_manifest_digest(
    condition_id: str,
    arm_id: str,
    case_ids: tuple[str, ...],
) -> str:
    return calculate_provider_input_manifest_digest(
        {case_id: _provider_input_digest(condition_id, arm_id, case_id) for case_id in case_ids}
    )


def _digest(value: str) -> str:
    return sha256_hexdigest(value)


def _arm(
    arm_id: _ArmId,
    *,
    condition_id: str,
    expected_decision: RAGSensitivityDecision,
    knowledge_contract_digest: str,
) -> SensitivityArmBinding:
    expected_outcome = (
        RAGSensitivityOutcome.approved
        if expected_decision is RAGSensitivityDecision.approve
        else RAGSensitivityOutcome.denied
    )
    return SensitivityArmBinding(
        arm_id=arm_id,
        expected_recommendation=expected_decision,
        expected_outcome=expected_outcome,
        configuration_digest=_digest(f"{condition_id}-{arm_id}-configuration"),
        corpus_digest=_digest(f"{condition_id}-{arm_id}-corpus"),
        prompt_manifest_digest=_digest("shared-prompt-manifest"),
        case_manifest_digest=_digest("shared-case-manifest"),
        knowledge_contract_digest=knowledge_contract_digest,
        provider="synthetic-provider",
        requested_model="synthetic-model",
        resolved_model="synthetic-model-2025-01-01",
        provider_api_version="api-v1",
        provider_sdk="sdk-v1",
        provider_region="test-region",
        adapter_id="openai-chat-completions",
        pipeline_id="study-pipeline",
        tool_schema_digest=_digest("tool-schema"),
        policy_bundle_digest=_digest("policy-bundle"),
    )


def _protocol(
    case_ids: tuple[str, ...],
    *,
    knowledge_contract_digest: str,
    condition_id: str = "a-synthetic-provider-model",
    expected_relation: EvidenceSensitivityExpectedRelation = (
        EvidenceSensitivityExpectedRelation.decision_flip
    ),
    baseline_expected_decision: RAGSensitivityDecision = RAGSensitivityDecision.approve,
    counterfactual_expected_decision: RAGSensitivityDecision = RAGSensitivityDecision.deny,
    multiplicity_family_size: int = 2,
    allowed_exclusion_reasons: tuple[str, ...] = (),
    maximum_exclusion_rate: str = "0.000000",
    execution_attempt_id: str | None = None,
) -> RepeatedEvidenceSensitivityProtocol:
    design = plan_binary_paired_design(
        familywise_alpha="0.500000",
        desired_power="0.500000",
        null_response_rate="0.100000",
        alternative_response_rate="0.900000",
        multiplicity_method="bonferroni",
        multiplicity_family_size=multiplicity_family_size,
        planned_inferential_clusters=len(case_ids),
        maximum_exclusion_rate=maximum_exclusion_rate,
        monte_carlo_resamples=1_000,
    )
    baseline = _arm(
        "baseline_evidence",
        condition_id=condition_id,
        expected_decision=baseline_expected_decision,
        knowledge_contract_digest=knowledge_contract_digest,
    )
    counterfactual = _arm(
        "counterfactual_evidence",
        condition_id=condition_id,
        expected_decision=counterfactual_expected_decision,
        knowledge_contract_digest=knowledge_contract_digest,
    )
    return RepeatedEvidenceSensitivityProtocol.build(
        protocol_id=f"{condition_id}-protocol",
        execution_attempt_id=execution_attempt_id,
        interpretation="confirmatory",
        execution_mode="stochastic_live",
        expected_relation=expected_relation,
        baseline_arm=baseline,
        counterfactual_arm=counterfactual,
        planned_case_ids=case_ids,
        planned_cluster_ids=case_ids,
        case_cluster_bindings=tuple(
            CaseClusterBinding(case_id=case_id, cluster_id=case_id) for case_id in case_ids
        ),
        case_authority_bindings=build_case_authority_bindings(
            case_ids,
            baseline,
            counterfactual,
            expected_relation=expected_relation,
        ),
        repetitions_per_arm=1,
        planned_pairs=len(case_ids),
        multiplicity_family="real-model-study",
        multiplicity_method="bonferroni",
        multiplicity_family_size=multiplicity_family_size,
        coupling=CouplingDescriptor(
            pairing_identity_verified=True,
            stochastic_dimensions=(
                CouplingCondition.provider_sampling_randomness,
                CouplingCondition.temporal_execution_order,
            ),
            shared=(CouplingCondition.case_identity,),
            intentionally_different=(CouplingCondition.governing_corpus_digest,),
            not_shared=(
                CouplingCondition.provider_sampling_randomness,
                CouplingCondition.temporal_execution_order,
            ),
            unknown=(),
            requested_provider_seed=True,
            classification=CouplingClassification.nominally_paired,
            variance_reduction_claim_permitted=False,
        ),
        design=design,
        allowed_exclusion_reasons=allowed_exclusion_reasons,
        limitations=("Synthetic unit-test protocol; no provider was contacted.",),
    )


def _benchmark(
    protocols: dict[str, RepeatedEvidenceSensitivityProtocol],
) -> ProcessEquivalenceBenchmarkManifest:
    cases = tuple(
        ProcessEquivalenceBenchmarkCase(
            task_id="synthetic-task",
            authority_contract_id="contextual-policy-authority-v1",
            query_family_id="synthetic-query-family",
            case_id=case_id,
            expected_relation=protocol.expected_relation.value,
            baseline_expected_decision=protocol.baseline_arm.expected_recommendation.value,
            counterfactual_expected_decision=(
                protocol.counterfactual_arm.expected_recommendation.value
            ),
            source_digest=_digest(f"source-{case_id}"),
            input_digest=_digest(f"input-{case_id}"),
        )
        for condition_id in sorted(protocols)
        for protocol in (protocols[condition_id],)
        for case_id in protocol.planned_case_ids
    )
    return ProcessEquivalenceBenchmarkManifest.build(
        benchmark_id="synthetic-process-equivalence",
        cases=tuple(sorted(cases, key=lambda item: item.canonical_key)),
    )


def _manifest(
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: dict[str, RepeatedEvidenceSensitivityProtocol],
    *,
    study_id: str = "synthetic-real-model-study",
    execution_origin: StudyExecutionOrigin = StudyExecutionOrigin.synthetic_fixture,
) -> RealModelStudyManifest:
    knowledge_contract = StudyKnowledgeContract()
    conditions: list[StudyConditionBinding] = []
    for condition_id in sorted(protocols):
        protocol = protocols[condition_id]
        resolved_model = protocol.baseline_arm.resolved_model
        assert resolved_model is not None
        conditions.append(
            StudyConditionBinding(
                condition_id=condition_id,
                justification="Bounded synthetic validation of the real-model study pipeline.",
                analysis_role=(
                    "inertia_estimand"
                    if protocol.expected_relation
                    is EvidenceSensitivityExpectedRelation.decision_flip
                    else "invariant_negative_control"
                ),
                execution_origin=execution_origin,
                task_ids=("synthetic-task",),
                benchmark_case_ids=protocol.planned_case_ids,
                protocol_id=protocol.protocol_id,
                execution_attempt_id=(
                    protocol.execution_attempt_id
                    if execution_origin is StudyExecutionOrigin.real_provider
                    else None
                ),
                protocol_digest=protocol.protocol_digest,
                design_commitment_digest=protocol.design_commitment_digest,
                provider=protocol.baseline_arm.provider,
                requested_model=protocol.baseline_arm.requested_model,
                expected_resolved_model=resolved_model,
                provider_api_version=protocol.baseline_arm.provider_api_version,
                provider_sdk=protocol.baseline_arm.provider_sdk,
                provider_region=protocol.baseline_arm.provider_region,
                adapter_id=protocol.baseline_arm.adapter_id,
                pipeline_id=protocol.baseline_arm.pipeline_id,
                baseline_configuration_digest=protocol.baseline_arm.configuration_digest,
                counterfactual_configuration_digest=(
                    protocol.counterfactual_arm.configuration_digest
                ),
                baseline_provider_input_manifest_digest=_provider_input_manifest_digest(
                    condition_id,
                    "baseline_evidence",
                    protocol.planned_case_ids,
                ),
                counterfactual_provider_input_manifest_digest=_provider_input_manifest_digest(
                    condition_id,
                    "counterfactual_evidence",
                    protocol.planned_case_ids,
                ),
                knowledge_contract_digest=protocol.baseline_arm.knowledge_contract_digest,
                study_knowledge_contract_digest=calculate_study_knowledge_contract_digest(
                    knowledge_contract
                ),
                planned_pairs=protocol.planned_pairs,
                planned_independent_clusters=len(protocol.planned_cluster_ids),
            )
        )
    target_condition_ids = tuple(
        condition_id
        for condition_id in sorted(protocols)
        if protocols[condition_id].expected_relation
        is EvidenceSensitivityExpectedRelation.decision_flip
    )
    negative_control_ids = tuple(
        condition_id
        for condition_id in sorted(protocols)
        if protocols[condition_id].expected_relation
        is EvidenceSensitivityExpectedRelation.decision_invariant
    )
    minimum_clusters = min(item.planned_independent_clusters for item in conditions)
    return RealModelStudyManifest.build(
        study_id=study_id,
        registration=StudyRegistration(
            method=StudyRegistrationMethod.version_control_commit,
            reference_id="synthetic-registration",
            evidence_digest=sha256(_REGISTRATION_RECORD_BYTES).hexdigest(),
            registered_at_utc="2025-01-01T00:00:00Z",
        ),
        execution_window=StudyExecutionWindow(
            start="2025-02-01T00:00:00Z",
            end="2025-03-01T00:00:00Z",
        ),
        benchmark_id=benchmark.benchmark_id,
        benchmark_digest=benchmark.benchmark_digest,
        knowledge_contract=knowledge_contract,
        conditions=tuple(conditions),
        hypothesis_decision_rule=StudyHypothesisDecisionRule(
            target_task_model_conditions=target_condition_ids,
            negative_control_conditions=negative_control_ids,
            minimum_independent_clusters=minimum_clusters,
            materiality_threshold="0.500000",
            familywise_alpha="0.500000",
            decision_boundary_rationale=(
                "The synthetic fixture freezes two inferential decision-flip targets. "
                "Its small-sample threshold is chosen only to exercise every exact "
                "classification branch in deterministic unit tests."
            ),
            independence_justification=StudyIndependenceJustification(
                status=(
                    StudyIndependenceJustificationStatus.author_asserted_design_basis_pending_qualified_review
                ),
                design_basis=(StudyIndependenceDesignBasis.independently_generated_task_clusters),
                semantic_near_duplicate_disposition=(
                    StudySemanticNearDuplicateDisposition.none_detected_by_digest_bound_audit
                ),
                independence_audit_artifact_sha256=_digest("synthetic-fixture-independence-audit"),
                inferential_unit_definition=(
                    "Each synthetic inferential unit is one separately dispatched case-ID "
                    "cluster in the finite frozen unit-test frame."
                ),
                independence_basis=(
                    "The synthetic fixture assigns every case to exactly one cluster and "
                    "generates each cluster endpoint from a separate deterministic test input."
                ),
                dependence_risks_and_mitigations=(
                    "The cases share one synthetic task template; tests therefore make no "
                    "population claim and use the assumption only to validate the finite-frame "
                    "analysis implementation."
                ),
                residual_scope_limitation=(
                    "Exact input identity and disjoint assignment establish replay structure, "
                    "not semantic, stochastic, or behavioral independence in real deployments."
                ),
            ),
        ),
        budget=StudyBudget(maximum_estimated_cost_microusd=1_000_000),
        limitations=("Synthetic evidence does not support provider-quality claims.",),
    )


def _observations(
    protocol: RepeatedEvidenceSensitivityProtocol,
    responses: tuple[bool, ...],
    *,
    missing_counterfactual_index: int | None = None,
    excluded_both_index: int | None = None,
) -> tuple[PairedSensitivityObservation, ...]:
    values: list[PairedSensitivityObservation] = []
    baseline_expected = protocol.baseline_arm.expected_recommendation
    counterfactual_expected = protocol.counterfactual_arm.expected_recommendation
    baseline_expected_outcome = protocol.baseline_arm.expected_outcome
    counterfactual_expected_outcome = protocol.counterfactual_arm.expected_outcome
    for index, (case_id, responds) in enumerate(
        zip(protocol.planned_case_ids, responses, strict=True)
    ):
        if index == excluded_both_index:
            values.append(
                PairedSensitivityObservation(
                    case_id=case_id,
                    repetition_index=0,
                    cluster_id=case_id,
                    disposition=PairDisposition.excluded_both,
                    disposition_reason="planned-exclusion",
                    baseline_run_id=f"baseline-{case_id}",
                    baseline_run_digest=_digest(f"baseline-{case_id}"),
                    counterfactual_run_id=f"counterfactual-{case_id}",
                    counterfactual_run_digest=_digest(f"counterfactual-{case_id}"),
                )
            )
            continue
        if index == missing_counterfactual_index:
            values.append(
                PairedSensitivityObservation(
                    case_id=case_id,
                    repetition_index=0,
                    cluster_id=case_id,
                    disposition=PairDisposition.missing_counterfactual,
                    disposition_reason="counterfactual-pair-missing",
                    baseline_run_id=f"baseline-{case_id}",
                    baseline_run_digest=_digest(f"baseline-{case_id}"),
                )
            )
            continue
        observed_counterfactual = (
            counterfactual_expected
            if responds
            else (
                RAGSensitivityDecision.deny
                if counterfactual_expected is RAGSensitivityDecision.approve
                else RAGSensitivityDecision.approve
            )
        )
        observed_counterfactual_outcome = (
            RAGSensitivityOutcome.approved
            if observed_counterfactual is RAGSensitivityDecision.approve
            else RAGSensitivityOutcome.denied
        )
        values.append(
            PairedSensitivityObservation(
                case_id=case_id,
                repetition_index=0,
                cluster_id=case_id,
                disposition=PairDisposition.included,
                baseline_run_id=f"baseline-{case_id}",
                baseline_run_digest=_digest(f"baseline-{case_id}"),
                counterfactual_run_id=f"counterfactual-{case_id}",
                counterfactual_run_digest=_digest(f"counterfactual-{case_id}"),
                baseline_recommendation=baseline_expected,
                baseline_outcome=baseline_expected_outcome,
                counterfactual_recommendation=observed_counterfactual,
                counterfactual_outcome=observed_counterfactual_outcome,
                baseline_expected_recommendation=baseline_expected,
                baseline_expected_outcome=baseline_expected_outcome,
                counterfactual_expected_recommendation=counterfactual_expected,
                counterfactual_expected_outcome=counterfactual_expected_outcome,
                expected_relation=protocol.expected_relation,
                endpoint_value=1 if responds else 0,
            )
        )
    return tuple(values)


def _bind_runset_to_manifest(
    source: RunSet,
    manifest: RealModelStudyManifest,
    *,
    include_provider_response_ids: bool = False,
) -> RunSet:
    payload = source.model_dump(mode="json")
    condition_arms = tuple(
        (binding.condition_id, arm_id)
        for binding in manifest.conditions
        for arm_id, configuration_digest in (
            ("baseline_evidence", binding.baseline_configuration_digest),
            ("counterfactual_evidence", binding.counterfactual_configuration_digest),
        )
        if configuration_digest == source.fixture_manifest_digest
    )
    if len(condition_arms) != 1:
        raise AssertionError("synthetic source RunSet must resolve to one study condition arm")
    condition_id, arm_id = condition_arms[0]
    rebound_runs: list[AgentRunRecord] = []
    for raw_run in payload["runs"]:
        run = dict(raw_run)
        provenance = dict(run["provenance"])
        provenance["study_manifest_digest"] = manifest.manifest_digest
        provenance["prompt_digest"] = _provider_input_digest(
            condition_id,
            arm_id,
            run["case_id"],
        )
        run.update(
            {
                "provenance": provenance,
                "started_at_utc": "2025-02-10T12:00:00Z",
                "completed_at_utc": "2025-02-10T12:00:01Z",
                "latency_ms": 1_000,
                "estimated_cost_usd": "0.010000",
                "estimated_cost_source": "provider_reported",
                "cost_budget_committed_usd": "0.010000",
            }
        )
        if include_provider_response_ids:
            run.update(
                {
                    "provider_response_id": f"provider-response-{run['run_id']}",
                    "provider_finish_reason": "stop",
                    "attempt_count": 1,
                    "retry_count": 0,
                    "rate_limit_events": 0,
                }
            )
        rebound_runs.append(AgentRunRecord.model_validate(run))
    payload["runs"] = rebound_runs
    payload["study_manifest_digest"] = manifest.manifest_digest
    if payload.get("execution_attempt_journal") is not None:
        journal_payload = dict(payload["execution_attempt_journal"])
        journal_payload.pop("journal_digest")
        journal_payload["study_manifest_digest"] = manifest.manifest_digest
        journal = LiveExecutionAttemptJournal.build(**journal_payload)
        payload["execution_attempt_journal_digest"] = journal.journal_digest
        payload["execution_attempt_journal"] = journal.model_dump(mode="json")
    return RunSet.model_validate(payload)


def _attach_execution_attempt_journal(
    *,
    protocol: RepeatedEvidenceSensitivityProtocol,
    manifest: RealModelStudyManifest,
    baseline: RunSet,
    counterfactual: RunSet,
) -> tuple[RunSet, RunSet]:
    attempt_id = protocol.execution_attempt_id
    assert attempt_id is not None
    events: list[LiveExecutionAttemptEvent] = []

    def append_event(event_type: str, **values: object) -> None:
        events.append(
            LiveExecutionAttemptEvent(
                event_index=len(events),
                event_type=event_type,  # type: ignore[arg-type]
                occurred_at_utc="2025-02-10T12:00:00Z",
                **values,
            )
        )

    for arm, runset in (
        (protocol.baseline_arm, baseline),
        (protocol.counterfactual_arm, counterfactual),
    ):
        append_event("arm_started", arm_id=arm.arm_id)
        for run in runset.runs:
            identity = {
                "arm_id": arm.arm_id,
                "run_id": run.run_id,
                "observation_id": run.observation_id,
                "case_id": run.case_id,
                "repetition_index": run.repetition_index,
                "adapter_attempt_index": 1,
            }
            append_event("request_issued", **identity)
            append_event(
                "request_succeeded",
                **identity,
                provider_response_id_digest=sha256_hexdigest(
                    {
                        "purpose": "provider-response-id/v1",
                        "provider_response_id": run.provider_response_id,
                    }
                ),
            )
        append_event("arm_completed", arm_id=arm.arm_id)
    append_event("attempt_completed")
    journal = LiveExecutionAttemptJournal.build(
        execution_attempt_id=attempt_id,
        repeated_protocol_digest=protocol.protocol_digest,
        operational_protocol_digest=baseline.protocol_digest,
        study_manifest_digest=manifest.manifest_digest,
        baseline_configuration_digest=protocol.baseline_arm.configuration_digest,
        counterfactual_configuration_digest=protocol.counterfactual_arm.configuration_digest,
        status="complete",
        events=tuple(events),
    )

    def attach(runset: RunSet) -> RunSet:
        return RunSet.model_validate(
            {
                **runset.model_dump(mode="json"),
                "execution_attempt_id": attempt_id,
                "execution_attempt_journal_digest": journal.journal_digest,
                "execution_attempt_journal": journal.model_dump(mode="json"),
            }
        )

    return attach(baseline), attach(counterfactual)


def _condition_evidence(
    *,
    manifest: RealModelStudyManifest,
    binding: StudyConditionBinding,
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline_runset: RunSet,
    counterfactual_runset: RunSet,
) -> StudyConditionEvidence:
    provenance = derive_study_observed_execution_provenance(
        manifest=manifest,
        binding=binding,
        protocol=protocol,
        baseline_runset=baseline_runset,
        counterfactual_runset=counterfactual_runset,
    )
    return StudyConditionEvidence(
        protocol=protocol,
        baseline_runset=baseline_runset,
        counterfactual_runset=counterfactual_runset,
        observed_execution_provenance=provenance,
    )


def _fixture(
    *,
    responses: tuple[bool, ...] = (True, True, True, True),
    missing_counterfactual_index: int | None = None,
    excluded_both_index: int | None = None,
    real_provider_execution: bool = False,
    condition_count: int = 4,
) -> StudyFixture:
    if condition_count < 4 or condition_count > MAX_STUDY_CONDITIONS or condition_count % 2:
        raise ValueError("synthetic study fixture requires an even condition count from 4 to 64")
    knowledge_digest = _digest("executable-rag-knowledge-contract")
    condition_specs = (
        (
            "a-synthetic-provider-model",
            ("case-a", "case-b", "case-c", "case-d"),
            EvidenceSensitivityExpectedRelation.decision_flip,
            RAGSensitivityDecision.approve,
            RAGSensitivityDecision.deny,
        ),
        (
            "b-reverse-provider-model",
            ("reverse-a", "reverse-b", "reverse-c", "reverse-d"),
            EvidenceSensitivityExpectedRelation.decision_flip,
            RAGSensitivityDecision.deny,
            RAGSensitivityDecision.approve,
        ),
        (
            "c-approve-invariant-provider-model",
            (
                "invariant-approve-a",
                "invariant-approve-b",
                "invariant-approve-c",
                "invariant-approve-d",
            ),
            EvidenceSensitivityExpectedRelation.decision_invariant,
            RAGSensitivityDecision.approve,
            RAGSensitivityDecision.approve,
        ),
        (
            "d-deny-invariant-provider-model",
            (
                "invariant-deny-a",
                "invariant-deny-b",
                "invariant-deny-c",
                "invariant-deny-d",
            ),
            EvidenceSensitivityExpectedRelation.decision_invariant,
            RAGSensitivityDecision.deny,
            RAGSensitivityDecision.deny,
        ),
    )
    target_family_size = condition_count // 2
    required_case_count = 8 if target_family_size > 3 else 4
    if required_case_count > 4:
        condition_specs = tuple(
            (
                condition_id,
                case_ids
                + tuple(
                    f"zz-{condition_id}-case-{index:02d}" for index in range(4, required_case_count)
                ),
                expected_relation,
                baseline_expected,
                counterfactual_expected,
            )
            for (
                condition_id,
                case_ids,
                expected_relation,
                baseline_expected,
                counterfactual_expected,
            ) in condition_specs
        )
    extra_specs = tuple(
        spec
        for pair_index in range((condition_count - 4) // 2)
        for spec in (
            (
                f"e-{pair_index:02d}-flip-provider-model-{'x' * 160}",
                tuple(
                    f"extra-{pair_index:02d}-flip-{case_index:02d}"
                    for case_index in range(required_case_count)
                ),
                EvidenceSensitivityExpectedRelation.decision_flip,
                RAGSensitivityDecision.approve,
                RAGSensitivityDecision.deny,
            ),
            (
                f"f-{pair_index:02d}-invariant-provider-model-{'x' * 160}",
                tuple(
                    f"extra-{pair_index:02d}-invariant-{case_index:02d}"
                    for case_index in range(required_case_count)
                ),
                EvidenceSensitivityExpectedRelation.decision_invariant,
                RAGSensitivityDecision.approve,
                RAGSensitivityDecision.approve,
            ),
        )
    )
    condition_specs += extra_specs
    protocols = {
        condition_id: _protocol(
            case_ids,
            knowledge_contract_digest=knowledge_digest,
            condition_id=condition_id,
            expected_relation=expected_relation,
            baseline_expected_decision=baseline_expected,
            counterfactual_expected_decision=counterfactual_expected,
            multiplicity_family_size=target_family_size,
            allowed_exclusion_reasons=(
                ("planned-exclusion",)
                if condition_id == "a-synthetic-provider-model" and excluded_both_index is not None
                else ()
            ),
            execution_attempt_id=(f"{condition_id}-attempt" if real_provider_execution else None),
        )
        for (
            condition_id,
            case_ids,
            expected_relation,
            baseline_expected,
            counterfactual_expected,
        ) in condition_specs
    }
    benchmark = _benchmark(protocols)
    manifest = _manifest(
        benchmark,
        protocols,
        execution_origin=(
            StudyExecutionOrigin.real_provider
            if real_provider_execution
            else StudyExecutionOrigin.synthetic_fixture
        ),
    )
    bindings = {item.condition_id: item for item in manifest.conditions}
    evidence_by_condition: dict[str, StudyConditionEvidence] = {}
    for condition_id, condition_protocol in protocols.items():
        is_primary = condition_id == "a-synthetic-provider-model"
        condition_responses = (
            responses
            + tuple(True for _ in range(len(condition_protocol.planned_case_ids) - len(responses)))
            if is_primary
            else tuple(True for _ in condition_protocol.planned_case_ids)
        )
        observations = _observations(
            condition_protocol,
            condition_responses,
            missing_counterfactual_index=(missing_counterfactual_index if is_primary else None),
            excluded_both_index=(excluded_both_index if is_primary else None),
        )
        _, _, sources = materialize_stochastic_sources(condition_protocol, observations)
        baseline_runset = _bind_runset_to_manifest(
            sources[0],
            manifest,
            include_provider_response_ids=real_provider_execution,
        )
        counterfactual_runset = _bind_runset_to_manifest(
            sources[1],
            manifest,
            include_provider_response_ids=real_provider_execution,
        )
        if real_provider_execution:
            baseline_runset, counterfactual_runset = _attach_execution_attempt_journal(
                protocol=condition_protocol,
                manifest=manifest,
                baseline=baseline_runset,
                counterfactual=counterfactual_runset,
            )
        evidence_by_condition[condition_id] = _condition_evidence(
            manifest=manifest,
            binding=bindings[condition_id],
            protocol=condition_protocol,
            baseline_runset=baseline_runset,
            counterfactual_runset=counterfactual_runset,
        )
    protocol = protocols["a-synthetic-provider-model"]
    evidence = evidence_by_condition["a-synthetic-provider-model"]
    registration_review_receipt = StudyRegistrationReviewReceipt.build(
        receipt_id="synthetic-registration-review",
        study_id=manifest.study_id,
        study_manifest_digest=manifest.manifest_digest,
        registration_method=manifest.registration.method,
        registration_reference_id=manifest.registration.reference_id,
        registration_evidence_sha256=manifest.registration.evidence_digest,
        registered_at_utc=manifest.registration.registered_at_utc,
        reviewed_at_utc="2025-01-02T00:00:00Z",
        reviewer_pseudonym="synthetic-reviewer",
        registration_record_coverage_confirmed=True,
        pre_observation_ordering_confirmed=True,
        registration_reference_resolved=True,
        registration_record_digest_match_confirmed=True,
        registration_record_immutability_confirmed=True,
    )
    return StudyFixture(
        benchmark=benchmark,
        protocol=protocol,
        manifest=manifest,
        evidence=evidence,
        protocols=protocols,
        evidence_by_condition=evidence_by_condition,
        registration_record_bytes=_REGISTRATION_RECORD_BYTES,
        registration_review_receipt=registration_review_receipt,
    )


def _analyze(
    fixture: StudyFixture,
    evidence: StudyConditionEvidence | None = None,
) -> RealModelStudyReport:
    condition_id = fixture.manifest.conditions[0].condition_id
    evidence_by_condition = dict(fixture.evidence_by_condition)
    if evidence is not None:
        evidence_by_condition[condition_id] = evidence
    return analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence_by_condition,
    )


def _rebuild_manifest(
    manifest: RealModelStudyManifest,
    **overrides: Any,
) -> RealModelStudyManifest:
    payload = manifest.model_dump(mode="json")
    payload.pop("manifest_digest")
    payload.pop("protocol_set_digest")
    payload.pop("hypothesis_decision_rule_digest")
    payload.update(overrides)
    return RealModelStudyManifest.build(**payload)


def _rebuild_protocol(
    protocol: RepeatedEvidenceSensitivityProtocol,
    **overrides: Any,
) -> RepeatedEvidenceSensitivityProtocol:
    payload = protocol.model_dump(mode="json")
    payload.pop("protocol_digest")
    payload.pop("design_commitment_digest")
    payload.update(overrides)
    return RepeatedEvidenceSensitivityProtocol.build(**payload)


def _replace_runset_records(
    runset: RunSet,
    transform: Any,
) -> RunSet:
    payload = runset.model_dump(mode="json")
    payload["runs"] = tuple(
        AgentRunRecord.model_validate(transform(run.model_dump(mode="json"))) for run in runset.runs
    )
    return RunSet.model_validate(payload)


def _rebind_evidence_to_manifest(
    fixture: StudyFixture,
    manifest: RealModelStudyManifest,
) -> dict[str, StudyConditionEvidence]:
    bindings = {item.condition_id: item for item in manifest.conditions}
    rebound: dict[str, StudyConditionEvidence] = {}
    for condition_id, evidence in fixture.evidence_by_condition.items():
        baseline_runset = _bind_runset_to_manifest(evidence.baseline_runset, manifest)
        counterfactual_runset = _bind_runset_to_manifest(
            evidence.counterfactual_runset,
            manifest,
        )
        rebound[condition_id] = _condition_evidence(
            manifest=manifest,
            binding=bindings[condition_id],
            protocol=evidence.protocol,
            baseline_runset=baseline_runset,
            counterfactual_runset=counterfactual_runset,
        )
    return rebound


def test_manifest_validates_exact_benchmark_protocol_and_registration_commitments() -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id
    binding = fixture.manifest.conditions[0]

    assert (
        binding.knowledge_contract_digest == fixture.protocol.baseline_arm.knowledge_contract_digest
    )
    assert binding.knowledge_contract_digest != binding.study_knowledge_contract_digest

    validate_study_manifest_inputs(
        fixture.manifest,
        fixture.benchmark,
        fixture.protocols,
    )

    manifest_payload = fixture.manifest.model_dump(mode="json")
    manifest_payload["execution_window"]["start"] = "2024-12-01T00:00:00Z"
    with pytest.raises(ValidationError, match="registration must occur before"):
        RealModelStudyManifest.build(**manifest_payload)

    manifest_payload = fixture.manifest.model_dump(mode="json")
    manifest_payload["registration"]["registered_at_utc"] = fixture.manifest.execution_window.start
    with pytest.raises(ValidationError, match="registration must occur before"):
        RealModelStudyManifest.build(**manifest_payload)

    changed_benchmark = ProcessEquivalenceBenchmarkManifest.build(
        benchmark_id="different-benchmark",
        cases=fixture.benchmark.cases,
    )
    with pytest.raises(ValueError, match="does not bind the supplied benchmark"):
        validate_study_manifest_inputs(
            fixture.manifest,
            changed_benchmark,
            fixture.protocols,
        )

    with pytest.raises(ValueError, match="exactly cover"):
        validate_study_manifest_inputs(fixture.manifest, fixture.benchmark, {})

    manifest_payload = fixture.manifest.model_dump(mode="json")
    manifest_payload["conditions"][0]["study_knowledge_contract_digest"] = _digest(
        "different-study-semantics"
    )
    manifest_payload.pop("manifest_digest")
    with pytest.raises(ValidationError, match="semantic knowledge contract"):
        RealModelStudyManifest.build(**manifest_payload)

    drifted_protocol = _rebuild_protocol(
        fixture.protocol,
        limitations=("A changed protocol is not the preregistered protocol.",),
    )
    with pytest.raises(ValueError, match="protocol commitment mismatch"):
        validate_study_manifest_inputs(
            fixture.manifest,
            fixture.benchmark,
            {**fixture.protocols, condition_id: drifted_protocol},
        )


@pytest.mark.parametrize(
    "field_name",
    ("decision_boundary_rationale", "independence_justification"),
)
def test_manifest_requires_explicit_statistical_justifications(field_name: str) -> None:
    fixture = _fixture()
    rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    rule_payload.pop(field_name)

    with pytest.raises(ValidationError, match=field_name):
        StudyHypothesisDecisionRule.model_validate(rule_payload)


def test_manifest_requires_model_matched_invariant_controls() -> None:
    fixture = _fixture()
    conditions = list(fixture.manifest.conditions)
    control_index = next(
        index
        for index, condition in enumerate(conditions)
        if condition.analysis_role.value == "invariant_negative_control"
    )
    payload = conditions[control_index].model_dump(mode="json")
    payload["provider_region"] = "different-region"
    conditions[control_index] = StudyConditionBinding.model_validate(payload)

    with pytest.raises(ValidationError, match="model-matched invariant negative control"):
        _rebuild_manifest(fixture.manifest, conditions=tuple(conditions))


def test_manifest_rejects_overlapping_condition_benchmark_frames() -> None:
    fixture = _fixture()
    conditions = list(fixture.manifest.conditions)
    first_payload = conditions[0].model_dump(mode="json")
    first_payload["benchmark_case_ids"] = sorted(
        (*first_payload["benchmark_case_ids"], conditions[1].benchmark_case_ids[0])
    )
    conditions[0] = StudyConditionBinding.model_validate(first_payload)
    overlapping = _rebuild_manifest(fixture.manifest, conditions=tuple(conditions))

    with pytest.raises(ValueError, match="pairwise disjoint"):
        validate_study_manifest_inputs(
            overlapping,
            fixture.benchmark,
            fixture.protocols,
        )


def test_manifest_rejects_omitted_benchmark_cases() -> None:
    fixture = _fixture()
    conditions = list(fixture.manifest.conditions)
    first_payload = conditions[0].model_dump(mode="json")
    first_payload["benchmark_case_ids"] = first_payload["benchmark_case_ids"][1:]
    conditions[0] = StudyConditionBinding.model_validate(first_payload)
    incomplete = _rebuild_manifest(fixture.manifest, conditions=tuple(conditions))

    with pytest.raises(ValueError, match="exactly exhaust"):
        validate_study_manifest_inputs(
            incomplete,
            fixture.benchmark,
            fixture.protocols,
        )


def test_manifest_and_rule_self_digests_reject_post_commit_tampering() -> None:
    fixture = _fixture()
    payload = fixture.manifest.model_dump(mode="json")
    payload["conditions"][0]["expected_resolved_model"] = "silently-changed-model"

    with pytest.raises(ValidationError, match="manifest_digest"):
        RealModelStudyManifest.model_validate(payload)

    payload = fixture.manifest.model_dump(mode="json")
    payload["hypothesis_decision_rule"]["materiality_threshold"] = "0.400000"
    with pytest.raises(ValidationError, match="hypothesis_decision_rule_digest|manifest_digest"):
        RealModelStudyManifest.model_validate(payload)

    payload = fixture.manifest.model_dump(mode="json")
    payload["conditions"][0]["execution_origin"] = "real_provider"
    payload["conditions"][0]["execution_attempt_id"] = "post-commit-attempt"
    with pytest.raises(ValidationError, match="manifest_digest"):
        RealModelStudyManifest.model_validate(payload)


def test_complete_runset_prompt_digest_tampering_invalidates_study() -> None:
    fixture = _fixture()
    binding = fixture.manifest.conditions[0]

    def tamper(payload: dict[str, Any]) -> dict[str, Any]:
        if payload["case_id"] == binding.benchmark_case_ids[0]:
            provenance = dict(payload["provenance"])
            provenance["prompt_digest"] = _digest("tampered-provider-input")
            payload["provenance"] = provenance
        return payload

    baseline = _replace_runset_records(fixture.evidence.baseline_runset, tamper)
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=binding,
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=fixture.evidence.counterfactual_runset,
    )

    result = _analyze(fixture, evidence).conditions[0]

    assert result.state is StudyConditionState.invalidated
    assert "baseline_evidence-provider-input-manifest-mismatch" in result.deviation_codes


def test_condition_execution_origin_defaults_fail_closed_for_authoring() -> None:
    fixture = _fixture()
    payload = fixture.manifest.conditions[0].model_dump(mode="json")
    payload.pop("execution_origin")

    binding = StudyConditionBinding.model_validate(payload)

    assert binding.execution_origin is StudyExecutionOrigin.synthetic_fixture


def test_confirmatory_study_rejects_nonzero_protocol_exclusion_allowance() -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id
    protocol = _protocol(
        fixture.protocol.planned_case_ids,
        knowledge_contract_digest=_digest("executable-rag-knowledge-contract"),
        condition_id=condition_id,
        allowed_exclusion_reasons=("planned-exclusion",),
        maximum_exclusion_rate="0.500000",
    )
    protocols = {**fixture.protocols, condition_id: protocol}
    benchmark = _benchmark(protocols)
    manifest = _manifest(benchmark, protocols)

    with pytest.raises(ValueError, match="maximum_exclusion_rate to zero"):
        validate_study_manifest_inputs(
            manifest,
            benchmark,
            protocols,
        )


def test_study_rejects_benchmark_direction_that_disagrees_with_protocol_arms() -> None:
    fixture = _fixture()
    cases = tuple(
        ProcessEquivalenceBenchmarkCase.model_validate(
            {
                **item.model_dump(mode="json"),
                **(
                    {
                        "baseline_expected_decision": "deny",
                        "counterfactual_expected_decision": "approve",
                    }
                    if item.case_id == "case-a"
                    else {}
                ),
            }
        )
        for item in fixture.benchmark.cases
    )
    benchmark = ProcessEquivalenceBenchmarkManifest.build(
        benchmark_id=fixture.benchmark.benchmark_id,
        cases=cases,
    )
    manifest = _manifest(benchmark, fixture.protocols)

    with pytest.raises(ValueError, match="benchmark decision orientation mismatch"):
        validate_study_manifest_inputs(
            manifest,
            benchmark,
            fixture.protocols,
        )


@pytest.mark.parametrize(
    "tampered_field",
    (None, "input_digest", "source_digest", "fail_fast_on_excluded_response"),
)
def test_live_binding_uses_one_snapshot_and_binds_exact_benchmark_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tampered_field: str | None,
) -> None:
    fixture = _fixture()
    protocol = fixture.protocol
    case_ids = protocol.planned_case_ids
    prompts = {case_id: f"exact UTF-8 prompt for {case_id}" for case_id in case_ids}
    contract_bytes = b"exact knowledge contract bytes"
    source_digest = sha256(contract_bytes).hexdigest()
    base_benchmark = fixture.benchmark
    cases: list[ProcessEquivalenceBenchmarkCase] = []
    for item in base_benchmark.cases:
        if item.case_id not in case_ids:
            cases.append(item)
            continue
        case_id = item.case_id
        input_digest = sha256(prompts[case_id].encode("utf-8")).hexdigest()
        case_source_digest = source_digest
        if case_id == "case-a" and tampered_field == "input_digest":
            input_digest = _digest("different-input")
        if case_id == "case-a" and tampered_field == "source_digest":
            case_source_digest = _digest("different-source")
        cases.append(
            ProcessEquivalenceBenchmarkCase.model_validate(
                {
                    **item.model_dump(mode="json"),
                    "source_digest": case_source_digest,
                    "input_digest": input_digest,
                }
            )
        )
    benchmark = ProcessEquivalenceBenchmarkManifest.build(
        benchmark_id="synthetic-process-equivalence",
        cases=tuple(cases),
    )
    manifest = _manifest(benchmark, fixture.protocols)
    conditions = list(manifest.conditions)
    baseline_binding = conditions[0].model_dump(mode="json")
    baseline_binding["baseline_provider_input_manifest_digest"] = (
        calculate_provider_input_manifest_digest(
            {case_id: sha256_hexdigest({"prompt": prompts[case_id]}) for case_id in case_ids}
        )
    )
    conditions[0] = StudyConditionBinding.model_validate(baseline_binding)
    manifest = _rebuild_manifest(manifest, conditions=tuple(conditions))
    config = LiveRunConfig(
        variant_id="baseline",
        pipeline_id=protocol.baseline_arm.pipeline_id,
        tool_schema_digest=protocol.baseline_arm.tool_schema_digest,
        policy_bundle_digest=protocol.baseline_arm.policy_bundle_digest,
        retrieval_corpus_digest=protocol.baseline_arm.corpus_digest,
        knowledge_contract_digest=protocol.baseline_arm.knowledge_contract_digest,
        evidence_sensitivity_design_digest=protocol.design_commitment_digest,
        adapter=LiveAdapterConfig(
            adapter_id=protocol.baseline_arm.adapter_id,
            provider=protocol.baseline_arm.provider,
            model=protocol.baseline_arm.requested_model,
        ),
        cases=tuple(
            LivePromptCase(
                case_id=case_id,
                prompt_path=f"{case_id}.txt",
                input_summary="synthetic benchmark input",
            )
            for case_id in case_ids
        ),
        max_requests=len(case_ids),
        fail_fast_on_excluded_response=(tampered_field != "fail_fast_on_excluded_response"),
    )
    snapshot = LiveExecutionSnapshot(
        prompts=tuple((case_id, prompts[case_id]) for case_id in case_ids),
        prompt_digests=tuple(
            (
                case_id,
                sha256_hexdigest({"prompt": prompts[case_id]}),
            )
            for case_id in case_ids
        ),
        governing_evidence=None,
        governing_evidence_digest=None,
        rendered_governing_evidence_message=None,
        rendered_governing_evidence_message_digest=None,
        corpus_snapshot=None,
        corpus_snapshot_digest=None,
        knowledge_contract=None,
        knowledge_contract_file_content=contract_bytes,
        knowledge_contract_file_sha256=source_digest,
        case_authority_bindings=protocol.case_authority_bindings,
        case_authority_manifest_digest=None,
        adapter_resource=None,
    )
    prepared: list[LiveExecutionSnapshot] = []
    prebound: list[LiveExecutionSnapshot] = []

    def prepare(
        compiled: CompiledSuite,
        live_config: LiveRunConfig,
        *,
        config_dir: Path,
    ) -> LiveExecutionSnapshot:
        del compiled, live_config, config_dir
        prepared.append(snapshot)
        return snapshot

    def prebind(**values: object) -> None:
        observed = values["execution_snapshot"]
        assert isinstance(observed, LiveExecutionSnapshot)
        prebound.append(observed)

    monkeypatch.setattr(study_analysis_module, "prepare_live_execution_snapshot", prepare)
    monkeypatch.setattr(study_analysis_module, "validate_live_arm_prebinding", prebind)

    def call() -> LiveRunConfig:
        return bind_study_manifest_to_live_config(
            manifest=manifest,
            benchmark=benchmark,
            condition_id=manifest.conditions[0].condition_id,
            protocol=protocol,
            arm_id="baseline_evidence",
            compiled=cast(CompiledSuite, object()),
            config=config,
            config_dir=tmp_path,
        )

    if tampered_field is None:
        bound = call()
        assert bound.study_manifest_digest == manifest.manifest_digest
    else:
        with pytest.raises(ValueError, match=tampered_field):
            call()
    expected_snapshots = [] if tampered_field == "fail_fast_on_excluded_response" else [snapshot]
    assert prepared == expected_snapshots
    assert prebound == expected_snapshots


@pytest.mark.parametrize(
    ("threshold", "unreachable_branch"),
    (
        ("0.100000", "contradicted"),
        ("0.900000", "supported"),
    ),
)
def test_manifest_rejects_unreachable_interval_decision_branches(
    threshold: str,
    unreachable_branch: str,
) -> None:
    fixture = _fixture()
    rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    rule_payload["materiality_threshold"] = threshold

    with pytest.raises(ValidationError, match=rf"cannot reach the {unreachable_branch} branch"):
        _rebuild_manifest(
            fixture.manifest,
            hypothesis_decision_rule=StudyHypothesisDecisionRule.model_validate(rule_payload),
        )


def test_ten_percent_rule_requires_at_least_36_clusters_for_two_targets() -> None:
    fixture = _fixture()

    def build_with_clusters(clusters: int) -> RealModelStudyManifest:
        bindings = []
        for condition in fixture.manifest.conditions:
            binding_payload = condition.model_dump(mode="json")
            binding_payload["planned_pairs"] = clusters
            binding_payload["planned_independent_clusters"] = clusters
            bindings.append(StudyConditionBinding.model_validate(binding_payload))
        rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
        rule_payload.update(
            {
                "minimum_independent_clusters": clusters,
                "materiality_threshold": "0.100000",
                "familywise_alpha": "0.050000",
            }
        )
        return _rebuild_manifest(
            fixture.manifest,
            conditions=tuple(bindings),
            hypothesis_decision_rule=StudyHypothesisDecisionRule.model_validate(rule_payload),
        )

    with pytest.raises(ValidationError, match="cannot reach the contradicted branch"):
        build_with_clusters(35)
    assert build_with_clusters(36).conditions[0].planned_independent_clusters == 36


def test_static_replay_is_exact_privacy_safe_and_source_preserving() -> None:
    fixture = _fixture(responses=(False, False, True, True))
    before = (
        fixture.evidence.baseline_runset.model_dump_json(),
        fixture.evidence.counterfactual_runset.model_dump_json(),
    )

    first = _analyze(fixture)
    second = _analyze(fixture)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.report_digest == second.report_digest
    assert before == (
        fixture.evidence.baseline_runset.model_dump_json(),
        fixture.evidence.counterfactual_runset.model_dump_json(),
    )
    result = first.conditions[0]
    assert result.state is StudyConditionState.analyzed
    assert result.actual_pairs == result.included_pairs == 4
    assert result.missing_pairs == result.excluded_pairs == result.invalid_pairs == 0
    assert result.sufficiency_report is not None
    assert tuple(
        item.study_manifest_digest for item in result.sufficiency_report.source_runsets
    ) == (
        fixture.manifest.manifest_digest,
        fixture.manifest.manifest_digest,
    )


def test_operational_cost_is_exact_under_hostile_decimal_context() -> None:
    fixture = _fixture()

    def set_cost(payload: dict[str, Any]) -> dict[str, Any]:
        payload["estimated_cost_usd"] = "0.012345"
        payload["cost_budget_committed_usd"] = "0.012345"
        return payload

    baseline = _replace_runset_records(
        fixture.evidence.baseline_runset,
        set_cost,
    )
    counterfactual = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        set_cost,
    )
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )
    with localcontext() as context:
        context.prec = 1
        context.Emin = -5
        context.Emax = 5
        context.rounding = ROUND_DOWN
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        report = _analyze(fixture, evidence)

    assert report.conditions[0].operational_summary.total_estimated_cost_microusd == 98_760


def test_budget_overrun_emits_constructible_invalidated_evidence() -> None:
    fixture = _fixture()
    manifest = _rebuild_manifest(
        fixture.manifest,
        budget=StudyBudget(maximum_estimated_cost_microusd=50_000),
    )

    def raise_committed_retry_cost(payload: dict[str, Any]) -> dict[str, Any]:
        payload["cost_budget_committed_usd"] = "0.020000"
        return payload

    evidence_by_condition = _rebind_evidence_to_manifest(fixture, manifest)
    condition_id = manifest.conditions[0].condition_id
    primary_evidence = evidence_by_condition[condition_id]
    baseline = _replace_runset_records(
        primary_evidence.baseline_runset,
        raise_committed_retry_cost,
    )
    counterfactual = _replace_runset_records(
        primary_evidence.counterfactual_runset,
        raise_committed_retry_cost,
    )
    evidence_by_condition[condition_id] = _condition_evidence(
        manifest=manifest,
        binding=manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )

    report = analyze_real_model_study(
        manifest=manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence_by_condition,
    )

    result = report.conditions[0]
    assert result.state is StudyConditionState.invalidated
    assert result.deviation_codes == ("study-budget-exceeded",)
    assert result.operational_summary.total_estimated_cost_microusd == 80_000
    assert result.operational_summary.total_cost_budget_committed_microusd == 160_000
    assert result.sufficiency_report is None
    assert result.expected_response_diagnostic is None
    assert report.deviations == ("study-budget-exceeded",)


def test_missing_latency_invalidates_real_provider_evidence() -> None:
    fixture = _fixture(real_provider_execution=True)

    def remove_latency(payload: dict[str, Any]) -> dict[str, Any]:
        payload.pop("latency_ms", None)
        return payload

    evidence_by_condition: dict[str, StudyConditionEvidence] = {}
    for binding in fixture.manifest.conditions:
        source = fixture.evidence_by_condition[binding.condition_id]
        baseline = _replace_runset_records(source.baseline_runset, remove_latency)
        counterfactual = _replace_runset_records(source.counterfactual_runset, remove_latency)
        evidence_by_condition[binding.condition_id] = _condition_evidence(
            manifest=fixture.manifest,
            binding=binding,
            protocol=source.protocol,
            baseline_runset=baseline,
            counterfactual_runset=counterfactual,
        )

    report = analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence_by_condition,
    )

    assert all(item.state is StudyConditionState.invalidated for item in report.conditions)
    assert all(
        "latency-accounting-incomplete" in item.deviation_codes for item in report.conditions
    )
    assert report.protocol_valid is False
    assert report.publication_eligible is False
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is report.publication_eligible is False


def test_missing_attempt_journal_invalidates_real_provider_provenance() -> None:
    fixture = _fixture(real_provider_execution=True)

    def without_journal(runset: RunSet) -> RunSet:
        payload = runset.model_dump(mode="json")
        for field_name in (
            "execution_attempt_id",
            "execution_attempt_journal_digest",
            "execution_attempt_journal",
        ):
            payload.pop(field_name, None)
        return RunSet.model_validate(payload)

    binding = fixture.manifest.conditions[0]
    source = fixture.evidence_by_condition[binding.condition_id]
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=binding,
        protocol=source.protocol,
        baseline_runset=without_journal(source.baseline_runset),
        counterfactual_runset=without_journal(source.counterfactual_runset),
    )

    report = _analyze(fixture, evidence)
    result = report.conditions[0]
    assert result.state is StudyConditionState.invalidated
    assert "execution-attempt-journal-invalid" in result.deviation_codes
    assert result.observed_execution_provenance is not None
    assert (
        result.observed_execution_provenance.observed_origin
        is StudyExecutionOrigin.synthetic_fixture
    )
    assert report.publication_eligible is False


@pytest.mark.parametrize(
    ("field_name", "unexpected_value"),
    (
        ("provider", "unexpected-provider"),
        ("model", "unexpected-requested-model"),
        ("resolved_model", "unexpected-model-revision"),
        ("pipeline_id", "unexpected-pipeline"),
    ),
)
def test_provider_or_model_mismatch_invalidates_without_statistics(
    field_name: str,
    unexpected_value: str,
) -> None:
    fixture = _fixture()

    def change_identity(payload: dict[str, Any]) -> dict[str, Any]:
        payload[field_name] = unexpected_value
        return payload

    counterfactual = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        change_identity,
    )
    mismatched = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=fixture.evidence.baseline_runset,
        counterfactual_runset=counterfactual,
    )
    report = _analyze(fixture, mismatched)
    result = report.conditions[0]

    assert result.state is StudyConditionState.invalidated
    assert "observed-provider-model-identity-mismatch" in result.deviation_codes
    assert "invalid-pair-binding" in result.deviation_codes
    assert "statistical-prerequisites-unmet" in result.deviation_codes
    assert result.actual_pairs == result.invalid_pairs == result.planned_pairs
    assert result.included_pairs == result.excluded_pairs == result.missing_pairs == 0
    assert report.protocol_valid is False
    assert report.statistical_sufficiency_satisfied is False
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False
    assert result.sufficiency_report is None
    assert result.expected_response_diagnostic is None
    assert not {
        "decision_response_cluster_count",
        "decision_inertia_cluster_count",
        "decision_inertia_descriptive_breakdown",
        "decision_response_rate",
        "decision_inertia_rate",
        "decision_inertia_interval",
    } & set(result.model_dump(mode="json"))


def test_pairing_audit_counts_missing_pairs_and_underpowered_state_exactly() -> None:
    fixture = _fixture(missing_counterfactual_index=1)
    report = _analyze(fixture)
    result = report.conditions[0]

    assert result.state is StudyConditionState.underpowered
    assert (result.planned_pairs, result.actual_pairs, result.included_pairs) == (4, 3, 3)
    assert (result.missing_pairs, result.excluded_pairs, result.invalid_pairs) == (1, 0, 0)
    assert (result.planned_clusters, result.actual_clusters, result.analyzable_clusters) == (
        4,
        3,
        3,
    )
    assert tuple((item.reason_code, item.count) for item in result.failure_summaries) == (
        ("counterfactual-pair-missing", 1),
    )
    assert result.deviation_codes == ()
    assert result.sufficiency_report is not None
    assert result.sufficiency_report.state.value == "inconclusive"
    assert report.protocol_valid is True
    assert report.statistical_sufficiency_satisfied is False
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.publication_eligible is False
    assert not {
        "decision_response_cluster_count",
        "decision_inertia_cluster_count",
        "decision_inertia_descriptive_breakdown",
        "decision_response_rate",
        "decision_inertia_rate",
        "decision_inertia_interval",
    } & set(result.model_dump(mode="json"))


def test_replay_failure_preserves_observed_pair_and_cluster_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(missing_counterfactual_index=1)

    def fail_replay(*args: object, **kwargs: object) -> object:
        raise ValueError("synthetic downstream replay failure")

    monkeypatch.setattr(
        study_analysis_module,
        "build_paired_runset_dependencies",
        fail_replay,
    )

    result = _analyze(fixture).conditions[0]

    assert result.state is StudyConditionState.invalidated
    assert (result.planned_pairs, result.actual_pairs, result.missing_pairs) == (4, 3, 1)
    assert (result.included_pairs, result.excluded_pairs, result.invalid_pairs) == (0, 0, 3)
    assert (result.planned_clusters, result.actual_clusters, result.analyzable_clusters) == (
        4,
        3,
        0,
    )
    assert tuple((item.reason_code, item.count) for item in result.failure_summaries) == (
        ("paired-observation-missing", 1),
        ("source-evidence-replay-failed", 3),
    )
    assert "source-evidence-replay-failed" in result.deviation_codes
    assert result.sufficiency_report is None
    assert result.expected_response_diagnostic is None


def test_confirmatory_pair_exclusion_invalidates_and_cannot_manufacture_support() -> None:
    fixture = _fixture(excluded_both_index=1)
    report = _analyze(fixture)
    result = report.conditions[0]

    assert result.state is StudyConditionState.invalidated
    assert (result.planned_pairs, result.actual_pairs, result.included_pairs) == (4, 4, 3)
    assert (result.missing_pairs, result.excluded_pairs, result.invalid_pairs) == (0, 1, 0)
    assert (result.planned_clusters, result.actual_clusters, result.analyzable_clusters) == (
        4,
        4,
        3,
    )
    assert tuple(
        (item.reason_code, item.count, item.example_case_ids) for item in result.failure_summaries
    ) == (("planned-exclusion", 1, ("case-b",)),)
    assert "confirmatory-pair-exclusion-observed" in result.deviation_codes
    assert result.sufficiency_report is None
    assert result.expected_response_diagnostic is None
    assert report.protocol_valid is False
    assert report.statistical_sufficiency_satisfied is False
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False
    assert not {
        "decision_response_cluster_count",
        "decision_inertia_cluster_count",
        "decision_inertia_descriptive_breakdown",
        "decision_response_rate",
        "decision_inertia_rate",
        "decision_inertia_interval",
    } & set(result.model_dump(mode="json"))


def test_not_executed_condition_is_non_verdict_and_omits_observed_evidence() -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[0].condition_id
    evidence_by_condition: dict[str, StudyConditionEvidence | None] = dict(
        fixture.evidence_by_condition
    )
    evidence_by_condition[condition_id] = None
    report = analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence_by_condition,
    )
    result = report.conditions[0]

    assert result.state is StudyConditionState.not_executed
    assert result.actual_pairs == result.included_pairs == 0
    assert result.missing_pairs == result.planned_pairs
    assert result.observed_model_identities == ()
    assert result.observed_execution_window is None
    assert result.sufficiency_report is None
    assert result.expected_response_diagnostic is None
    assert result.deviation_codes == ("study-condition-not-executed",)
    assert report.protocol_valid is False
    assert report.statistical_sufficiency_satisfied is False
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is report.publication_eligible is False


@pytest.mark.parametrize(
    ("responses", "expected"),
    (
        ((False, False, False, False), StudyHypothesisClassification.supported),
        ((False, False, True, True), StudyHypothesisClassification.inconclusive),
        ((True, True, True, True), StudyHypothesisClassification.contradicted),
    ),
)
def test_exact_interval_decision_rule_boundaries(
    responses: tuple[bool, bool, bool, bool],
    expected: StudyHypothesisClassification,
) -> None:
    report = _analyze(_fixture(responses=responses))
    result = report.conditions[0]
    interval = result.decision_inertia_interval

    assert result.state is StudyConditionState.analyzed
    assert interval is not None
    assert interval.method == "clopper_pearson_exact_one_sided"
    assert interval.multiplicity_method == "bonferroni"
    assert interval.family_size == 2
    assert interval.adjusted_alpha == "0.250000000000"
    assert report.hypothesis_classification is expected
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False


def test_canonical_n42_two_target_classification_boundaries_are_exact() -> None:
    adjusted_alpha = bonferroni_adjusted_alpha("0.050000", 2)
    assert adjusted_alpha == Decimal("0.025000")

    def canonical_interval(successes: int) -> StudyOneSidedInterval:
        lower = clopper_pearson_one_sided(
            successes,
            42,
            adjusted_alpha,
            side="lower",
        )
        upper = clopper_pearson_one_sided(
            successes,
            42,
            adjusted_alpha,
            side="upper",
        )
        return StudyOneSidedInterval(
            familywise_alpha="0.050000",
            family_size=2,
            adjusted_alpha=f"{adjusted_alpha:.12f}",
            trials=42,
            successes=successes,
            lower_bound=format_twelve_place_bound(lower.bound, rounding=ROUND_FLOOR),
            upper_bound=format_twelve_place_bound(upper.bound, rounding=ROUND_CEILING),
        )

    intervals = tuple(canonical_interval(successes) for successes in range(10))
    assert intervals[0].adjusted_alpha == "0.025000000000"
    assert intervals[0].upper_bound == "0.084083854941"
    assert intervals[8].lower_bound == "0.086005594455"
    assert intervals[9].lower_bound == "0.102959649897"

    fixture = _fixture()
    base_report = _analyze(fixture)
    rule = fixture.manifest.hypothesis_decision_rule.model_copy(
        update={
            "materiality_threshold": "0.100000",
            "familywise_alpha": "0.050000",
        }
    )
    canonical_manifest = fixture.manifest.model_copy(update={"hypothesis_decision_rule": rule})

    def classify(first_target_successes: int) -> StudyHypothesisClassification:
        target_intervals = iter((intervals[first_target_successes], intervals[0]))
        conditions = tuple(
            condition.model_copy(update={"decision_inertia_interval": next(target_intervals)})
            if condition.decision_inertia_interval is not None
            else condition
            for condition in base_report.conditions
        )
        return study_analysis_module._classify(canonical_manifest, conditions)

    assert classify(0) is StudyHypothesisClassification.contradicted
    assert all(
        classify(successes) is StudyHypothesisClassification.inconclusive
        for successes in range(1, 9)
    )
    assert classify(9) is StudyHypothesisClassification.supported


def test_bonferroni_family_contains_only_decision_flip_targets() -> None:
    fixture = _fixture()
    report = _analyze(fixture)

    assert fixture.manifest.hypothesis_decision_rule.multiplicity_family_scope == (
        "target_task_model_conditions_only"
    )
    assert len(fixture.manifest.hypothesis_decision_rule.target_task_model_conditions) == 2
    assert len(fixture.manifest.hypothesis_decision_rule.negative_control_conditions) == 2
    assert all(
        interval.family_size == 2 and interval.adjusted_alpha == "0.250000000000"
        for condition in report.conditions
        for interval in (
            condition.decision_inertia_interval,
            condition.control_unexpected_change_interval,
        )
        if interval is not None
    )

    condition_id = fixture.manifest.conditions[0].condition_id
    drifted = _protocol(
        fixture.protocol.planned_case_ids,
        knowledge_contract_digest=fixture.protocol.baseline_arm.knowledge_contract_digest,
        condition_id=condition_id,
        expected_relation=fixture.protocol.expected_relation,
        baseline_expected_decision=fixture.protocol.baseline_arm.expected_recommendation,
        counterfactual_expected_decision=(
            fixture.protocol.counterfactual_arm.expected_recommendation
        ),
        multiplicity_family_size=4,
    )
    rebound_bindings = []
    for binding in fixture.manifest.conditions:
        if binding.condition_id != condition_id:
            rebound_bindings.append(binding)
            continue
        payload = binding.model_dump(mode="json")
        payload["protocol_digest"] = drifted.protocol_digest
        payload["design_commitment_digest"] = drifted.design_commitment_digest
        rebound_bindings.append(StudyConditionBinding.model_validate(payload))
    drifted_manifest = _rebuild_manifest(
        fixture.manifest,
        conditions=tuple(rebound_bindings),
    )
    with pytest.raises(ValueError, match="analysis-plan mismatch"):
        validate_study_manifest_inputs(
            drifted_manifest,
            fixture.benchmark,
            {**fixture.protocols, condition_id: drifted},
        )


def test_complete_direct_provider_dispatch_remains_pending_bundle_review() -> None:
    report = _analyze(_fixture(real_provider_execution=True))

    assert all(
        condition.observed_execution_provenance is not None
        and condition.observed_execution_provenance.observed_origin
        is StudyExecutionOrigin.real_provider
        for condition in report.conditions
    )
    assert report.registration_evidence_verified is False
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False


def test_local_digest_registration_remains_analyzable_but_cannot_publish() -> None:
    fixture = _fixture()
    registration = StudyRegistration.model_validate(
        {
            **fixture.manifest.registration.model_dump(mode="json"),
            "method": "local_digest_commitment",
        }
    )
    local_manifest = _rebuild_manifest(fixture.manifest, registration=registration)

    report = analyze_real_model_study(
        manifest=local_manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=_rebind_evidence_to_manifest(fixture, local_manifest),
    )

    assert report.conditions[0].state is StudyConditionState.analyzed
    assert report.statistical_sufficiency_satisfied is True
    assert report.hypothesis_classification is not StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False


def test_interval_rate_and_report_aggregate_tampering_is_rejected() -> None:
    report = _analyze(_fixture(responses=(False, False, True, True)))
    result = report.conditions[0]
    assert result.decision_inertia_interval is not None

    interval_payload = result.decision_inertia_interval.model_dump(mode="json")
    interval_payload["lower_bound"] = "0.000000000000"
    with pytest.raises(ValidationError, match="must exactly derive"):
        StudyOneSidedInterval.model_validate(interval_payload)

    result_payload = result.model_dump(mode="json")
    result_payload["decision_inertia_rate"] = "0.750000"
    with pytest.raises(ValidationError, match="decision_inertia_rate must derive"):
        StudyConditionResult.model_validate(result_payload)

    report_payload = report.model_dump(mode="json")
    report_payload["total_actual_pairs"] = 1
    with pytest.raises(ValidationError, match="aggregate counts|report_digest"):
        RealModelStudyReport.model_validate(report_payload)


def test_post_observation_protocol_drift_invalidates_confirmatory_result() -> None:
    fixture = _fixture()
    drifted_protocol = _rebuild_protocol(
        fixture.protocol,
        limitations=("Protocol text changed after observation.",),
    )
    evidence = StudyConditionEvidence(
        protocol=drifted_protocol,
        baseline_runset=fixture.evidence.baseline_runset,
        counterfactual_runset=fixture.evidence.counterfactual_runset,
        observed_execution_provenance=fixture.evidence.observed_execution_provenance,
    )

    report = _analyze(fixture, evidence)

    assert report.conditions[0].state is StudyConditionState.invalidated
    assert "post-registration-protocol-drift" in report.conditions[0].deviation_codes
    assert "protocol-binding-mismatch" in report.conditions[0].deviation_codes
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is False


def test_post_observation_manifest_drift_is_detected_by_runset_backlinks() -> None:
    fixture = _fixture()
    drifted_manifest = _rebuild_manifest(
        fixture.manifest,
        study_id="synthetic-real-model-study-revision",
    )
    report = analyze_real_model_study(
        manifest=drifted_manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=fixture.evidence_by_condition,
    )

    assert report.conditions[0].state is StudyConditionState.invalidated
    assert "study-manifest-backlink-mismatch" in report.conditions[0].deviation_codes
    assert "study-manifest-record-backlink-mismatch" in report.conditions[0].deviation_codes
    assert report.protocol_valid is False
    assert report.publication_eligible is False


def test_post_observation_decision_rule_drift_is_detected_by_manifest_backlinks() -> None:
    fixture = _fixture()
    rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    rule_payload["materiality_threshold"] = "0.450000"
    drifted_manifest = _rebuild_manifest(
        fixture.manifest,
        hypothesis_decision_rule=StudyHypothesisDecisionRule.model_validate(rule_payload),
    )
    report = analyze_real_model_study(
        manifest=drifted_manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=fixture.evidence_by_condition,
    )

    assert (
        drifted_manifest.hypothesis_decision_rule_digest
        != fixture.manifest.hypothesis_decision_rule_digest
    )
    assert report.conditions[0].state is StudyConditionState.invalidated
    assert "study-manifest-backlink-mismatch" in report.conditions[0].deviation_codes
    assert "study-manifest-record-backlink-mismatch" in report.conditions[0].deviation_codes
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.confirmatory_conclusion_permitted is report.publication_eligible is False


def test_source_runsets_must_be_privacy_filtered_before_digest_bound_analysis() -> None:
    fixture = _fixture()

    def inject_raw_identifier(payload: dict[str, Any]) -> dict[str, Any]:
        payload["output_summary"] = "Contact alice@example.com for the raw response."
        return payload

    unsafe = StudyConditionEvidence(
        protocol=fixture.protocol,
        baseline_runset=_replace_runset_records(
            fixture.evidence.baseline_runset,
            inject_raw_identifier,
        ),
        counterfactual_runset=fixture.evidence.counterfactual_runset,
        observed_execution_provenance=fixture.evidence.observed_execution_provenance,
    )

    with pytest.raises(ValueError, match="must already be privacy-filtered"):
        _analyze(fixture, unsafe)


def test_study_rule_rejects_alpha_that_can_create_crossing_one_sided_bounds() -> None:
    fixture = _fixture()
    payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    payload["familywise_alpha"] = "0.500001"

    with pytest.raises(ValidationError, match="at most 0.5"):
        StudyHypothesisDecisionRule.model_validate(payload)


def test_underpowered_condition_coupling_must_derive_from_source_protocol() -> None:
    report = _analyze(_fixture(missing_counterfactual_index=1))
    result = report.conditions[0]
    assert result.state is StudyConditionState.underpowered
    payload = result.model_dump(mode="json")
    payload["coupling"] = None

    with pytest.raises(ValidationError, match="omitted instead of null"):
        StudyConditionResult.model_validate(payload)


@pytest.mark.parametrize(
    "field_name",
    (
        "decision_response_cluster_count",
        "decision_inertia_cluster_count",
        "decision_inertia_descriptive_breakdown",
        "decision_response_rate",
        "decision_inertia_rate",
        "decision_inertia_interval",
    ),
)
def test_inapplicable_condition_statistics_reject_explicit_null(field_name: str) -> None:
    result = _analyze(_fixture(missing_counterfactual_index=1)).conditions[0]
    payload = result.model_dump(mode="json")
    payload[field_name] = None

    with pytest.raises(ValidationError, match="omitted instead of null"):
        StudyConditionResult.model_validate(payload)


def test_invalidated_condition_rejects_nested_verdict_reports() -> None:
    result = _analyze(_fixture()).conditions[0]
    payload = result.model_dump(mode="json")
    payload["state"] = "invalidated"
    payload["deviation_codes"] = ["synthetic-invalidation"]
    for field_name in (
        "decision_response_cluster_count",
        "decision_inertia_cluster_count",
        "decision_wrong_direction_cluster_count",
        "decision_other_non_inertia_cluster_count",
        "decision_inertia_descriptive_breakdown",
        "decision_response_rate",
        "decision_inertia_rate",
        "decision_inertia_interval",
    ):
        payload.pop(field_name)

    with pytest.raises(ValidationError, match="cannot retain derived verdict reports"):
        StudyConditionResult.model_validate(payload)


def test_operational_summary_rejects_explicit_null() -> None:
    result = _analyze(_fixture()).conditions[0]
    payload = result.model_dump(mode="json")
    payload["operational_summary"]["total_estimated_cost_microusd"] = None

    with pytest.raises(ValidationError, match="omitted instead of null"):
        StudyConditionResult.model_validate(payload)


@pytest.mark.parametrize(
    ("started", "completed", "expected_code"),
    (
        (
            "2025-02-10T12:00:01Z",
            "2025-02-10T12:00:00Z",
            "execution-timestamp-order-invalid",
        ),
        (
            "2025-02-10T12:00:00Z",
            "2025-02-10T12:00:00Z",
            "observed-execution-window-degenerate",
        ),
    ),
)
def test_impossible_observed_execution_windows_invalidate_instead_of_publish(
    started: str,
    completed: str,
    expected_code: str,
) -> None:
    fixture = _fixture()

    def change_timestamps(payload: dict[str, Any]) -> dict[str, Any]:
        payload["started_at_utc"] = started
        payload["completed_at_utc"] = completed
        return payload

    baseline = _replace_runset_records(
        fixture.evidence.baseline_runset,
        change_timestamps,
    )
    counterfactual = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        change_timestamps,
    )
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )

    report = _analyze(fixture, evidence)
    result = report.conditions[0]
    assert result.state is StudyConditionState.invalidated
    assert expected_code in result.deviation_codes
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False


def test_corrupted_identity_cardinality_is_bounded_and_explicitly_invalidated() -> None:
    fixture = _fixture()
    payload = fixture.evidence.baseline_runset.model_dump(mode="json")
    template = fixture.evidence.baseline_runset.runs[0].model_dump(mode="json")
    extras: list[AgentRunRecord] = []
    for index in range(32):
        record = dict(template)
        record.update(
            {
                "run_id": f"extra-run-{index:02d}",
                "case_id": f"extra-case-{index:02d}",
                "observation_id": f"extra-observation-{index:02d}",
                "schedule_index": index + 10,
                "cluster_id": f"extra-cluster-{index:02d}",
                "provider": f"unexpected-provider-{index:02d}",
            }
        )
        extras.append(AgentRunRecord.model_validate(record))
    payload["runs"] = [*payload["runs"], *extras]
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=RunSet.model_validate(payload),
        counterfactual_runset=fixture.evidence.counterfactual_runset,
    )

    report = _analyze(fixture, evidence)
    result = report.conditions[0]
    assert result.state is StudyConditionState.invalidated
    assert len(result.observed_model_identities) == 32
    assert "observed-model-identity-cardinality-exceeded" in result.deviation_codes
    assert report.publication_eligible is False


def test_synthetic_execution_is_analyzable_but_never_publication_eligible() -> None:
    fixture = _fixture()
    with pytest.raises(
        ValueError,
        match="requires a registered execution_attempt_id and complete attempt journal",
    ):
        assemble_paired_observations(
            fixture.protocol,
            fixture.evidence.baseline_runset,
            fixture.evidence.counterfactual_runset,
        )

    report = _analyze(fixture)

    assert report.statistical_sufficiency_satisfied is True
    assert all(
        condition.observed_execution_provenance is not None
        and condition.observed_execution_provenance.observed_origin
        is StudyExecutionOrigin.synthetic_fixture
        for condition in report.conditions
    )
    assert report.confirmatory_conclusion_permitted is False
    assert report.publication_eligible is False


def test_real_provider_declaration_without_direct_dispatch_evidence_invalidates() -> None:
    fixture = _fixture()
    protocols = {
        condition_id: _rebuild_protocol(
            protocol,
            execution_attempt_id=f"{condition_id}-declared-attempt",
        )
        for condition_id, protocol in fixture.protocols.items()
    }
    manifest = _manifest(
        fixture.benchmark,
        protocols,
        execution_origin=StudyExecutionOrigin.real_provider,
    )
    evidence = _rebind_evidence_to_manifest(fixture, manifest)

    report = analyze_real_model_study(
        manifest=manifest,
        benchmark=fixture.benchmark,
        protocols=protocols,
        evidence=evidence,
    )

    assert all(item.state is StudyConditionState.invalidated for item in report.conditions)
    assert all(
        "provider-dispatch-provenance-incomplete" in item.deviation_codes
        and "observed-execution-origin-mismatch" in item.deviation_codes
        for item in report.conditions
    )
    assert report.publication_eligible is False


def test_missing_or_self_asserted_observed_provenance_invalidates() -> None:
    fixture = _fixture()
    complete_provider_fixture = _fixture(real_provider_execution=True)
    missing = StudyConditionEvidence(
        protocol=fixture.protocol,
        baseline_runset=fixture.evidence.baseline_runset,
        counterfactual_runset=fixture.evidence.counterfactual_runset,
        observed_execution_provenance=None,
    )
    forged = StudyConditionEvidence(
        protocol=fixture.protocol,
        baseline_runset=fixture.evidence.baseline_runset,
        counterfactual_runset=fixture.evidence.counterfactual_runset,
        observed_execution_provenance=(
            complete_provider_fixture.evidence.observed_execution_provenance
        ),
    )

    missing_result = _analyze(fixture, missing).conditions[0]
    forged_result = _analyze(fixture, forged).conditions[0]

    assert missing_result.state is StudyConditionState.invalidated
    assert "observed-execution-provenance-missing" in missing_result.deviation_codes
    assert forged_result.state is StudyConditionState.invalidated
    assert "observed-execution-provenance-mismatch" in forged_result.deviation_codes


@pytest.mark.parametrize("adapter_id", ("static-jsonl", "external-script"))
def test_replay_and_external_script_records_cannot_prove_provider_dispatch(
    adapter_id: str,
) -> None:
    fixture = _fixture(real_provider_execution=True)

    def replace_adapter(payload: dict[str, Any]) -> dict[str, Any]:
        payload["adapter_id"] = adapter_id
        return payload

    baseline = _replace_runset_records(
        fixture.evidence.baseline_runset,
        replace_adapter,
    )
    counterfactual = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        replace_adapter,
    )
    provenance = derive_study_observed_execution_provenance(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )

    assert provenance.observed_origin is StudyExecutionOrigin.synthetic_fixture
    assert provenance.approved_adapter_run_records == 0
    assert provenance.adapter_ids == (adapter_id,)


def test_provider_response_ids_must_be_complete_and_unique_across_arms() -> None:
    fixture = _fixture(real_provider_execution=True)

    def duplicate_baseline_response_id(payload: dict[str, Any]) -> dict[str, Any]:
        payload["provider_response_id"] = f"provider-response-baseline-{payload['case_id']}"
        return payload

    counterfactual = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        duplicate_baseline_response_id,
    )
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=fixture.evidence.baseline_runset,
        counterfactual_runset=counterfactual,
    )
    result = _analyze(fixture, evidence).conditions[0]

    assert result.state is StudyConditionState.invalidated
    assert result.observed_execution_provenance is not None
    assert (
        result.observed_execution_provenance.distinct_provider_response_ids
        < result.observed_execution_provenance.run_records
    )
    assert "provider-dispatch-provenance-incomplete" in result.deviation_codes


@pytest.mark.parametrize("finish_reason", (None, "length"))
def test_provider_normal_termination_is_required_for_real_provider_provenance(
    finish_reason: str | None,
) -> None:
    fixture = _fixture(real_provider_execution=True)

    def replace_finish_reason(payload: dict[str, Any]) -> dict[str, Any]:
        if finish_reason is None:
            payload.pop("provider_finish_reason", None)
        else:
            payload["provider_finish_reason"] = finish_reason
        return payload

    baseline = _replace_runset_records(
        fixture.evidence.baseline_runset,
        replace_finish_reason,
    )
    counterfactual = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        replace_finish_reason,
    )
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )
    provenance = evidence.observed_execution_provenance
    assert provenance is not None
    assert provenance.observed_origin is StudyExecutionOrigin.synthetic_fixture
    assert provenance.normal_termination_run_records == 0
    assert provenance.provider_response_metadata_records == 0

    result = _analyze(fixture, evidence).conditions[0]
    assert result.state is StudyConditionState.invalidated
    assert "provider-normal-termination-unverified" in result.deviation_codes
    assert "provider-dispatch-provenance-incomplete" in result.deviation_codes


def test_direct_inertia_counts_same_decision_at_counterfactual_authority() -> None:
    fixture = _fixture()

    def choose_deny(payload: dict[str, Any]) -> dict[str, Any]:
        payload["recommendation"] = "deny"
        payload["outcome"] = "denied"
        return payload

    baseline = _replace_runset_records(
        fixture.evidence.baseline_runset,
        choose_deny,
    )
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=fixture.evidence.counterfactual_runset,
    )
    result = _analyze(fixture, evidence).conditions[0]

    assert result.state is StudyConditionState.analyzed
    assert result.decision_inertia_cluster_count == result.planned_clusters == 4
    assert result.decision_response_cluster_count == 0
    assert result.decision_wrong_direction_cluster_count == 0
    assert result.decision_other_non_inertia_cluster_count == 0


def test_wrong_direction_flip_is_non_inertia_but_not_expected_response() -> None:
    fixture = _fixture()

    def reverse_expected_decision(payload: dict[str, Any]) -> dict[str, Any]:
        if payload["run_id"].startswith("baseline-"):
            payload["recommendation"] = "deny"
            payload["outcome"] = "denied"
        else:
            payload["recommendation"] = "approve"
            payload["outcome"] = "approved"
        return payload

    baseline = _replace_runset_records(
        fixture.evidence.baseline_runset,
        reverse_expected_decision,
    )
    counterfactual = _replace_runset_records(
        fixture.evidence.counterfactual_runset,
        reverse_expected_decision,
    )
    evidence = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[0],
        protocol=fixture.protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )
    report = _analyze(fixture, evidence)
    result = report.conditions[0]

    assert result.state is StudyConditionState.analyzed
    assert result.decision_response_cluster_count == 0
    assert result.decision_inertia_cluster_count == 0
    assert result.decision_wrong_direction_cluster_count == result.planned_clusters == 4
    assert report.hypothesis_classification is StudyHypothesisClassification.contradicted


def test_invariant_arm_change_is_retained_as_a_control_failure_gate() -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[2].condition_id
    condition_protocol = fixture.protocols[condition_id]
    original = fixture.evidence_by_condition[condition_id]

    def choose_deny(payload: dict[str, Any]) -> dict[str, Any]:
        payload["recommendation"] = "deny"
        payload["outcome"] = "denied"
        return payload

    counterfactual = _replace_runset_records(
        original.counterfactual_runset,
        choose_deny,
    )
    changed = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[2],
        protocol=condition_protocol,
        baseline_runset=original.baseline_runset,
        counterfactual_runset=counterfactual,
    )
    evidence = {**fixture.evidence_by_condition, condition_id: changed}
    report = analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
    )
    result = report.conditions[2]

    assert result.state is StudyConditionState.control_failed
    assert result.deviation_codes == ("invariant-control-violation-observed",)
    assert result.control_expected_stability_cluster_count == 0
    assert result.control_unexpected_change_cluster_count == result.planned_clusters == 4
    assert result.control_unexpected_change_rate == "1.000000"
    assert result.control_unexpected_change_interval is not None
    assert report.statistical_sufficiency_satisfied is True
    assert report.invariant_controls_satisfied is False
    assert report.hypothesis_classification is StudyHypothesisClassification.not_measured
    assert report.publication_eligible is False


def test_invariant_stable_but_wrong_output_invalidates_the_condition() -> None:
    fixture = _fixture()
    condition_id = fixture.manifest.conditions[2].condition_id
    condition_protocol = fixture.protocols[condition_id]
    original = fixture.evidence_by_condition[condition_id]

    def choose_deny(payload: dict[str, Any]) -> dict[str, Any]:
        payload["recommendation"] = "deny"
        payload["outcome"] = "denied"
        return payload

    baseline = _replace_runset_records(original.baseline_runset, choose_deny)
    counterfactual = _replace_runset_records(
        original.counterfactual_runset,
        choose_deny,
    )
    wrong = _condition_evidence(
        manifest=fixture.manifest,
        binding=fixture.manifest.conditions[2],
        protocol=condition_protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )
    report = analyze_real_model_study(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence={**fixture.evidence_by_condition, condition_id: wrong},
    )

    assert report.conditions[2].state is StudyConditionState.invalidated
    assert "invariant-control-output-invalid" in report.conditions[2].deviation_codes
    assert report.invariant_controls_satisfied is False


def test_frozen_rule_membership_must_match_manifest_condition_roles() -> None:
    fixture = _fixture()
    rule_payload = fixture.manifest.hypothesis_decision_rule.model_dump(mode="json")
    rule_payload["target_task_model_conditions"] = tuple(
        sorted(
            (
                fixture.manifest.conditions[1].condition_id,
                fixture.manifest.conditions[2].condition_id,
            )
        )
    )
    rule_payload["negative_control_conditions"] = tuple(
        sorted(
            (
                fixture.manifest.conditions[0].condition_id,
                fixture.manifest.conditions[3].condition_id,
            )
        )
    )

    with pytest.raises(ValidationError, match="roles must exactly match"):
        _rebuild_manifest(
            fixture.manifest,
            hypothesis_decision_rule=StudyHypothesisDecisionRule.model_validate(rule_payload),
        )
