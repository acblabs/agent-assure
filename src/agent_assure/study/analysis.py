"""Fail-closed orchestration for preregistered real-model studies.

This module does not dispatch providers. It validates a frozen study plan,
binds that plan to live configurations before execution, and deterministically
reconstructs study results from privacy-filtered paired RunSet snapshots.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from pathlib import Path
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.config import LiveRunConfig
from agent_assure.live.runner import (
    LiveExecutionSnapshot,
    calculate_provider_input_manifest_digest,
    calculate_snapshot_provider_input_manifest_digest,
    prepare_live_execution_snapshot,
)
from agent_assure.privacy.redaction import (
    assert_runset_payload_safe_for_persistence,
    redact_runset_payload,
)
from agent_assure.rag.repeated_sensitivity import (
    _assemble_paired_observations_for_verified_synthetic_study,
    assemble_paired_observations,
    build_paired_runset_dependencies,
    validate_live_arm_prebinding,
    validate_paired_attempt_journal,
)
from agent_assure.rag.sensitivity_statistics import (
    build_stochastic_sensitivity_report,
    evaluate_statistical_sufficiency,
    validate_binary_paired_design_plan,
)
from agent_assure.schema.benchmark import (
    ProcessEquivalenceBenchmarkCase,
    ProcessEquivalenceBenchmarkManifest,
)
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.sensitivity import EvidenceSensitivityExpectedRelation
from agent_assure.schema.stochastic_sensitivity import (
    CONFIRMATORY_STOCHASTIC_ADAPTER_IDS,
    PairDisposition,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    SensitivityArmBinding,
    SensitivityExecutionMode,
    SensitivityInterpretation,
    SufficiencyState,
)
from agent_assure.schema.study import (
    MAX_STUDY_OBSERVED_MODEL_IDENTITIES,
    RealModelStudyManifest,
    RealModelStudyReport,
    StudyConditionAnalysisRole,
    StudyConditionBinding,
    StudyConditionResult,
    StudyConditionState,
    StudyDecisionInertiaDescriptiveBreakdown,
    StudyExecutionOrigin,
    StudyExecutionWindow,
    StudyExpectedResponseDiagnostic,
    StudyFailureSummary,
    StudyHypothesisClassification,
    StudyObservedExecutionProvenance,
    StudyObservedModelIdentity,
    StudyOneSidedInterval,
    StudyOperationalSummary,
    _study_condition_execution_identity,
    derive_study_cluster_endpoint_counts,
    derive_study_inertia_descriptive_counts,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.statistics.binomial_intervals import clopper_pearson_one_sided
from agent_assure.statistics.study_serialization import (
    bonferroni_adjusted_alpha,
    format_six_place_rate,
    format_twelve_place_bound,
)
from agent_assure.timestamps import parse_rfc3339_timestamp

_INVALIDATING_DISPOSITIONS = frozenset(
    {
        PairDisposition.identity_mismatch,
        PairDisposition.invalid_baseline,
        PairDisposition.invalid_counterfactual,
        PairDisposition.invalid_both,
        PairDisposition.undeclared_arm_difference,
    }
)
_DEFAULT_REPORT_LIMITATIONS = (
    (
        "Findings apply only to the preregistered benchmark, provider identity, "
        "model, configurations, execution window, and protocol."
    ),
    (
        "Decision-inertia intervals treat the frozen case-cluster frame as the "
        "inferential population and do not establish causal or general provider "
        "quality claims."
    ),
    (
        "Each condition executes the complete baseline arm before the complete "
        "counterfactual arm; temporal drift is therefore confounded with arm and "
        "the report does not claim an arm-isolated causal effect."
    ),
    (
        "Raw prompts, raw completions, credentials, and credential digests are "
        "outside the persisted study evidence boundary."
    ),
    (
        "Observed execution provenance is deterministically derived from privacy-filtered "
        "local runner records and response metadata and digest-bound to the exact source "
        "RunSets; it is not cryptographic provider authentication or independent human-"
        "provenance attestation."
    ),
    (
        "The report does not itself verify preregistration record bytes or reviewer "
        "identity; release readiness requires the closed bundle's exact registration "
        "record and human-operator review receipt, with reviewer identity authenticated "
        "out of band."
    ),
)
_DRIFT_BOUNDARY = (
    "Any model, provider API, SDK, region, reported provider serving fingerprint, "
    "adapter, pipeline, configuration, benchmark, protocol, decision-rule, "
    "execution-origin, or execution-window drift invalidates the affected confirmatory "
    "condition or model-matched condition group."
)


@dataclass(frozen=True, slots=True)
class StudyConditionEvidence:
    """The complete replay input for one preregistered condition."""

    protocol: RepeatedEvidenceSensitivityProtocol
    baseline_runset: RunSet
    counterfactual_runset: RunSet
    observed_execution_provenance: StudyObservedExecutionProvenance | None


@dataclass(frozen=True, slots=True)
class _ReplayFailureAudit:
    actual_pairs: int
    missing_pairs: int
    invalid_pairs: int
    actual_clusters: int
    failure_summaries: tuple[StudyFailureSummary, ...]


def derive_study_observed_execution_provenance(
    *,
    manifest: RealModelStudyManifest,
    binding: StudyConditionBinding,
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline_runset: RunSet,
    counterfactual_runset: RunSet,
) -> StudyObservedExecutionProvenance:
    """Derive bounded local dispatch evidence from two exact source RunSets."""

    manifest = _copy_manifest(manifest)
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    baseline = _unchanged_privacy_safe_runset(baseline_runset)
    counterfactual = _unchanged_privacy_safe_runset(counterfactual_runset)
    runsets = (baseline, counterfactual)
    arm_bindings = (protocol.baseline_arm, protocol.counterfactual_arm)
    arm_ids = ("baseline_evidence", "counterfactual_evidence")
    records = tuple(run for runset in runsets for run in runset.runs)
    planned_cells = {
        (case_id, repetition)
        for case_id in protocol.planned_case_ids
        for repetition in range(protocol.repetitions_per_arm)
    }
    expected_clusters = {item.case_id: item.cluster_id for item in protocol.case_cluster_bindings}

    live_runsets = sum(runset.execution_mode is ExecutionMode.live for runset in runsets)
    complete_runsets = sum(
        runset.completion_status == "complete"
        and {
            (run.case_id, run.repetition_index)
            for run in runset.runs
            if run.repetition_index is not None
        }
        == planned_cells
        and len(runset.runs) == len(planned_cells)
        for runset in runsets
    )
    binding_consistent_runsets = sum(
        _runset_supports_observed_provenance(
            runset,
            arm,
            manifest=manifest,
            binding=binding,
        )
        for runset, arm in zip(runsets, arm_bindings, strict=True)
    )
    live_run_records = sum(record.execution_mode is ExecutionMode.live for record in records)
    included_run_records = sum(record.observation_status == "included" for record in records)
    approved_adapter_run_records = sum(
        record.adapter_id in CONFIRMATORY_STOCHASTIC_ADAPTER_IDS for record in records
    )
    binding_consistent_run_records = sum(
        _record_supports_observed_provenance(
            record,
            arm,
            protocol=protocol,
            manifest=manifest,
            expected_clusters=expected_clusters,
        )
        for runset, arm in zip(runsets, arm_bindings, strict=True)
        for record in runset.runs
    )
    timing_complete_run_records = sum(
        _record_has_complete_study_timing(record, manifest) for record in records
    )
    provider_response_id_entries = tuple(
        sorted(
            (
                arm_id,
                record.run_id,
                record.provider_response_id,
            )
            for arm_id, runset in zip(arm_ids, runsets, strict=True)
            for record in runset.runs
            if _usable_provider_response_id(record.provider_response_id)
        )
    )
    provider_serving_fingerprint_entries = tuple(
        sorted(
            (
                arm_id,
                record.run_id,
                record.provider_serving_fingerprint,
            )
            for arm_id, runset in zip(arm_ids, runsets, strict=True)
            for record in runset.runs
            if _usable_provider_metadata(record.provider_serving_fingerprint)
        )
    )
    provider_serving_fingerprints = tuple(
        sorted(
            {
                fingerprint
                for _, _, fingerprint in provider_serving_fingerprint_entries
                if fingerprint is not None
            }
        )
    )
    provider_response_metadata_records = sum(
        record.observation_status == "included"
        and _usable_provider_response_id(record.provider_response_id)
        and record.provider_finish_reason == "stop"
        and all(
            _usable_provider_metadata(value)
            for value in (record.provider, record.model, record.resolved_model)
        )
        for record in records
    )
    normal_termination_run_records = sum(
        record.provider_finish_reason == "stop" for record in records
    )
    adapter_values = tuple(
        sorted({record.adapter_id for record in records if record.adapter_id is not None})
    )
    adapter_ids = (
        adapter_values
        if len(adapter_values) <= 16
        else (*adapter_values[:15], "adapter-cardinality-exceeded")
    )
    run_records = len(records)
    planned_run_records = 2 * protocol.planned_pairs
    distinct_provider_response_ids = len({entry[2] for entry in provider_response_id_entries})
    distinct_provider_serving_fingerprints = len(provider_serving_fingerprints)
    fingerprint_policy_satisfied = (not provider_serving_fingerprint_entries) or (
        len(provider_serving_fingerprint_entries) == run_records
        and distinct_provider_serving_fingerprints == 1
    )
    attempt_journal_verified = _paired_attempt_journal_is_valid(
        protocol,
        baseline,
        counterfactual,
    )
    supports_real_provider = (
        live_runsets == 2
        and complete_runsets == 2
        and binding_consistent_runsets == 2
        and run_records == planned_run_records
        and included_run_records == run_records
        and live_run_records == run_records
        and approved_adapter_run_records == run_records
        and binding_consistent_run_records == run_records
        and timing_complete_run_records == run_records
        and len(provider_response_id_entries) == run_records
        and provider_response_metadata_records == run_records
        and fingerprint_policy_satisfied
        and normal_termination_run_records == run_records
        and distinct_provider_response_ids == run_records
        and attempt_journal_verified
        and bool(adapter_ids)
        and set(adapter_ids) <= CONFIRMATORY_STOCHASTIC_ADAPTER_IDS
    )
    return StudyObservedExecutionProvenance.build(
        condition_id=binding.condition_id,
        study_manifest_digest=manifest.manifest_digest,
        declared_origin=binding.execution_origin,
        observed_origin=(
            StudyExecutionOrigin.real_provider
            if supports_real_provider
            else StudyExecutionOrigin.synthetic_fixture
        ),
        baseline_runset_id=baseline.runset_id,
        baseline_runset_digest=sha256_hexdigest(baseline.model_dump(mode="json")),
        counterfactual_runset_id=counterfactual.runset_id,
        counterfactual_runset_digest=sha256_hexdigest(counterfactual.model_dump(mode="json")),
        planned_run_records=planned_run_records,
        run_records=run_records,
        included_run_records=included_run_records,
        live_runsets=live_runsets,
        complete_runsets=complete_runsets,
        binding_consistent_runsets=binding_consistent_runsets,
        execution_attempt_journal_verified=attempt_journal_verified,
        live_run_records=live_run_records,
        approved_adapter_run_records=approved_adapter_run_records,
        binding_consistent_run_records=binding_consistent_run_records,
        timing_complete_run_records=timing_complete_run_records,
        provider_response_id_records=len(provider_response_id_entries),
        provider_response_metadata_records=provider_response_metadata_records,
        provider_serving_fingerprint_records=len(provider_serving_fingerprint_entries),
        distinct_provider_serving_fingerprints=(distinct_provider_serving_fingerprints),
        provider_serving_fingerprint_set_digest=(
            sha256_hexdigest(
                {
                    "purpose": "study-provider-serving-fingerprints/v1",
                    "fingerprints": provider_serving_fingerprints,
                }
            )
            if provider_serving_fingerprint_entries
            else None
        ),
        normal_termination_run_records=normal_termination_run_records,
        distinct_provider_response_ids=distinct_provider_response_ids,
        provider_response_id_set_digest=(
            sha256_hexdigest(
                {
                    "purpose": "study-provider-response-identities/v1",
                    "records": provider_response_id_entries,
                }
            )
            if provider_response_id_entries
            else None
        ),
        adapter_ids=adapter_ids,
    )


def validate_study_manifest_inputs(
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
) -> None:
    """Validate every frozen manifest commitment without provider dispatch."""

    manifest = _copy_manifest(manifest)
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(
        benchmark.model_dump(mode="json")
    )
    if (
        manifest.benchmark_id,
        manifest.benchmark_version,
        manifest.benchmark_digest,
    ) != (
        benchmark.benchmark_id,
        benchmark.benchmark_version,
        benchmark.benchmark_digest,
    ):
        raise ValueError("study manifest does not bind the supplied benchmark")
    expected_ids = tuple(item.condition_id for item in manifest.conditions)
    if tuple(sorted(protocols)) != expected_ids:
        raise ValueError("study protocols must exactly cover the frozen condition IDs")
    _validate_benchmark_condition_frames(manifest, benchmark)
    benchmark_by_case = {item.case_id: item for item in benchmark.cases}
    for binding in manifest.conditions:
        protocol = RepeatedEvidenceSensitivityProtocol.model_validate(
            protocols[binding.condition_id].model_dump(mode="json")
        )
        _validate_condition_protocol(
            manifest=manifest,
            binding=binding,
            protocol=protocol,
            benchmark_by_case=benchmark_by_case,
        )
    relation_by_condition = {
        condition_id: RepeatedEvidenceSensitivityProtocol.model_validate(
            protocol.model_dump(mode="json")
        ).expected_relation
        for condition_id, protocol in protocols.items()
    }
    inertia_condition_ids = tuple(
        sorted(
            condition_id
            for condition_id, relation in relation_by_condition.items()
            if relation is EvidenceSensitivityExpectedRelation.decision_flip
        )
    )
    negative_control_ids = tuple(
        sorted(
            condition_id
            for condition_id, relation in relation_by_condition.items()
            if relation is EvidenceSensitivityExpectedRelation.decision_invariant
        )
    )
    rule = manifest.hypothesis_decision_rule
    if not inertia_condition_ids:
        raise ValueError("real-model study requires at least one inertia-estimand condition")
    if rule.target_task_model_conditions != inertia_condition_ids:
        raise ValueError("frozen inertia targets must exactly match decision-flip protocols")
    if rule.negative_control_conditions != negative_control_ids:
        raise ValueError("frozen negative controls must exactly match decision-invariant protocols")


def bind_study_manifest_to_live_config(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    condition_id: str,
    protocol: RepeatedEvidenceSensitivityProtocol,
    arm_id: str,
    compiled: CompiledSuite,
    config: LiveRunConfig,
    config_dir: Path,
) -> LiveRunConfig:
    """Validate an exact arm and add the manifest backlink without dispatching it."""

    manifest = _copy_manifest(manifest)
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(
        benchmark.model_dump(mode="json")
    )
    if (
        manifest.benchmark_id,
        manifest.benchmark_version,
        manifest.benchmark_digest,
    ) != (
        benchmark.benchmark_id,
        benchmark.benchmark_version,
        benchmark.benchmark_digest,
    ):
        raise ValueError("study manifest does not bind the supplied benchmark")
    _validate_benchmark_condition_frames(manifest, benchmark)
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    binding = _manifest_condition(manifest, condition_id)
    benchmark_by_case = {item.case_id: item for item in benchmark.cases}
    _validate_condition_protocol(
        manifest=manifest,
        binding=binding,
        protocol=protocol,
        benchmark_by_case=benchmark_by_case,
    )
    if (binding.protocol_digest, binding.design_commitment_digest) != (
        protocol.protocol_digest,
        protocol.design_commitment_digest,
    ):
        raise ValueError("live configuration protocol is not the frozen study condition")
    if arm_id == "baseline_evidence":
        arm = protocol.baseline_arm
        expected_configuration_digest = binding.baseline_configuration_digest
        expected_provider_input_manifest_digest = binding.baseline_provider_input_manifest_digest
    elif arm_id == "counterfactual_evidence":
        arm = protocol.counterfactual_arm
        expected_configuration_digest = binding.counterfactual_configuration_digest
        expected_provider_input_manifest_digest = (
            binding.counterfactual_provider_input_manifest_digest
        )
    else:
        raise ValueError("arm_id must be baseline_evidence or counterfactual_evidence")
    if arm.configuration_digest != expected_configuration_digest:
        raise ValueError("study condition arm does not bind the declared configuration")
    existing = config.study_manifest_digest
    if existing is not None and existing != manifest.manifest_digest:
        raise ValueError("live configuration is already bound to another study manifest")
    bound = LiveRunConfig.model_validate(
        {**config.model_dump(mode="json"), "study_manifest_digest": manifest.manifest_digest}
    )
    if tuple(sorted(item.case_id for item in bound.cases)) != binding.benchmark_case_ids:
        raise ValueError("live study config cases do not exactly match the benchmark frame")
    execution_snapshot = prepare_live_execution_snapshot(
        compiled,
        bound,
        config_dir=config_dir,
    )
    validate_live_arm_prebinding(
        compiled=compiled,
        config=bound,
        config_dir=config_dir,
        binding=arm,
        case_authority_bindings=protocol.case_authority_bindings,
        execution_snapshot=execution_snapshot,
    )
    _validate_benchmark_execution_binding(
        benchmark_by_case=benchmark_by_case,
        binding=binding,
        protocol=protocol,
        config=bound,
        execution_snapshot=execution_snapshot,
    )
    observed_provider_input_manifest_digest = calculate_snapshot_provider_input_manifest_digest(
        execution_snapshot
    )
    if observed_provider_input_manifest_digest != expected_provider_input_manifest_digest:
        raise ValueError(
            "live study provider-input manifest does not match the preregistered arm commitment"
        )
    return bound


def _validate_benchmark_execution_binding(
    *,
    benchmark_by_case: Mapping[str, ProcessEquivalenceBenchmarkCase],
    binding: StudyConditionBinding,
    protocol: RepeatedEvidenceSensitivityProtocol,
    config: LiveRunConfig,
    execution_snapshot: LiveExecutionSnapshot,
) -> None:
    """Bind benchmark descriptors to the exact bytes and authority sent live."""

    configured_case_ids = tuple(sorted(item.case_id for item in config.cases))
    if configured_case_ids != binding.benchmark_case_ids:
        raise ValueError("live study config cases do not exactly match the benchmark frame")
    prompts_by_case = execution_snapshot.prompt_by_case()
    authority_by_case = {item.case_id: item for item in execution_snapshot.case_authority_bindings}
    if tuple(sorted(prompts_by_case)) != binding.benchmark_case_ids:
        raise ValueError(
            "live execution prompt snapshot does not exactly cover the benchmark frame"
        )
    if tuple(sorted(authority_by_case)) != binding.benchmark_case_ids:
        raise ValueError(
            "live execution authority snapshot does not exactly cover the benchmark frame"
        )

    for case_id in binding.benchmark_case_ids:
        benchmark_case = benchmark_by_case.get(case_id)
        if benchmark_case is None:
            raise ValueError(f"live study benchmark case {case_id} is unavailable")
        try:
            input_digest = hashlib.sha256(prompts_by_case[case_id].encode("utf-8")).hexdigest()
        except UnicodeEncodeError as exc:
            raise ValueError(f"live study prompt for case {case_id} is not valid UTF-8") from exc
        if input_digest != benchmark_case.input_digest:
            raise ValueError(
                f"live study prompt bytes do not match benchmark input_digest for case {case_id}"
            )
        if execution_snapshot.knowledge_contract_file_sha256 is None:
            raise ValueError("live study snapshot lacks exact knowledge-contract source bytes")
        if execution_snapshot.knowledge_contract_file_sha256 != benchmark_case.source_digest:
            raise ValueError(
                f"live study knowledge-contract bytes do not match benchmark source_digest "
                f"for case {case_id} ({benchmark_case.authority_contract_id})"
            )


def analyze_real_model_study(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    evidence: Mapping[str, StudyConditionEvidence | None],
) -> RealModelStudyReport:
    """Recompute the preregistered study from exact privacy-safe source evidence."""

    manifest = _copy_manifest(manifest)
    validate_study_manifest_inputs(manifest, benchmark, protocols)
    expected_ids = tuple(item.condition_id for item in manifest.conditions)
    if tuple(sorted(evidence)) != expected_ids:
        raise ValueError("study evidence must exactly cover the frozen condition IDs")

    # Bonferroni correction covers only inferential decision-flip targets.
    # Negative controls are evaluated by the exact zero-change gate and do not
    # spend alpha, although their descriptive intervals retain the frozen
    # target-family alpha for a consistent uncertainty reference.
    family_size = len(manifest.hypothesis_decision_rule.target_task_model_conditions)
    adjusted_alpha = bonferroni_adjusted_alpha(
        manifest.hypothesis_decision_rule.familywise_alpha,
        family_size,
    )
    results = tuple(
        _analyze_condition(
            manifest=manifest,
            binding=binding,
            protocol=protocols[binding.condition_id],
            evidence=evidence[binding.condition_id],
            adjusted_alpha=adjusted_alpha,
            family_size=family_size,
        )
        for binding in manifest.conditions
    )
    results = _invalidate_inconsistent_provider_serving_fingerprint_groups(
        manifest,
        results,
    )
    reported_estimated_cost = sum(
        item.operational_summary.total_estimated_cost_microusd or 0 for item in results
    )
    reported_committed_cost = sum(
        item.operational_summary.total_cost_budget_committed_microusd or 0 for item in results
    )
    if (
        max(reported_estimated_cost, reported_committed_cost)
        > manifest.budget.maximum_estimated_cost_microusd
    ):
        results = tuple(
            _invalidate_condition_result(item, "study-budget-exceeded")
            if item.operational_summary.run_records
            else item
            for item in results
        )
    sufficient = all(
        item.state in {StudyConditionState.analyzed, StudyConditionState.control_failed}
        for item in results
    )
    invariant_controls_satisfied = all(
        item.state is StudyConditionState.analyzed
        and item.control_unexpected_change_cluster_count == 0
        for item in results
        if item.analysis_role is StudyConditionAnalysisRole.invariant_negative_control
    )
    protocol_valid = all(
        item.state not in {StudyConditionState.invalidated, StudyConditionState.not_executed}
        for item in results
    )
    classification = (
        _classify(manifest, results)
        if sufficient and invariant_controls_satisfied
        else StudyHypothesisClassification.not_measured
    )
    # A report can replay the analysis, but cannot authenticate the external
    # registration record or its human reviewer. Those claims remain closed
    # until the factory-only bundle verifier checks the exact record and receipt.
    permitted: Literal[False] = False
    deviations = tuple(sorted({code for item in results for code in item.deviation_codes}))
    limitations = tuple(sorted(set((*manifest.limitations, *_DEFAULT_REPORT_LIMITATIONS))))
    return RealModelStudyReport.build(
        report_id=f"{manifest.study_id}/report",
        manifest=manifest,
        manifest_digest=manifest.manifest_digest,
        benchmark_digest=manifest.benchmark_digest,
        protocol_set_digest=manifest.protocol_set_digest,
        hypothesis_decision_rule_digest=manifest.hypothesis_decision_rule_digest,
        conditions=results,
        protocol_valid=protocol_valid,
        statistical_sufficiency_satisfied=sufficient,
        invariant_controls_satisfied=invariant_controls_satisfied,
        hypothesis_classification=classification,
        confirmatory_conclusion_permitted=permitted,
        publication_eligible=permitted,
        total_planned_pairs=sum(item.planned_pairs for item in results),
        total_actual_pairs=sum(item.actual_pairs for item in results),
        total_included_pairs=sum(item.included_pairs for item in results),
        total_missing_pairs=sum(item.missing_pairs for item in results),
        total_excluded_pairs=sum(item.excluded_pairs for item in results),
        total_invalid_pairs=sum(item.invalid_pairs for item in results),
        total_planned_clusters=sum(item.planned_clusters for item in results),
        total_analyzable_clusters=sum(item.analyzable_clusters for item in results),
        deviations=deviations,
        limitations=limitations,
        drift_boundary=_DRIFT_BOUNDARY,
    )


def _validate_benchmark_condition_frames(
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
) -> None:
    condition_case_ids = tuple(
        case_id for condition in manifest.conditions for case_id in condition.benchmark_case_ids
    )
    if len(condition_case_ids) != len(set(condition_case_ids)):
        raise ValueError("study condition benchmark frames must be pairwise disjoint")
    benchmark_case_ids = {item.case_id for item in benchmark.cases}
    if set(condition_case_ids) != benchmark_case_ids:
        raise ValueError(
            "study condition benchmark frames must exactly exhaust supplied benchmark cases"
        )


def _validate_condition_protocol(
    *,
    manifest: RealModelStudyManifest,
    binding: StudyConditionBinding,
    protocol: RepeatedEvidenceSensitivityProtocol,
    benchmark_by_case: Mapping[str, ProcessEquivalenceBenchmarkCase],
) -> None:
    validate_binary_paired_design_plan(protocol)
    if protocol.execution_mode is not SensitivityExecutionMode.stochastic_live:
        raise ValueError(f"condition {binding.condition_id} is not stochastic_live")
    if protocol.interpretation is not SensitivityInterpretation.confirmatory:
        raise ValueError(f"condition {binding.condition_id} is not confirmatory")
    if binding.analysis_role is not _analysis_role(protocol):
        raise ValueError(
            f"condition {binding.condition_id} analysis role does not match its protocol relation"
        )
    if Decimal(protocol.design.maximum_exclusion_rate) != Decimal("0"):
        raise ValueError(
            f"condition {binding.condition_id} confirmatory study protocol must set "
            "maximum_exclusion_rate to zero"
        )
    if (
        protocol.protocol_id,
        protocol.execution_attempt_id
        if binding.execution_origin is StudyExecutionOrigin.real_provider
        else None,
        protocol.protocol_digest,
        protocol.design_commitment_digest,
    ) != (
        binding.protocol_id,
        binding.execution_attempt_id,
        binding.protocol_digest,
        binding.design_commitment_digest,
    ):
        raise ValueError(f"condition {binding.condition_id} protocol commitment mismatch")
    if protocol.planned_case_ids != binding.benchmark_case_ids:
        raise ValueError(f"condition {binding.condition_id} benchmark case frame mismatch")
    if any(case_id not in benchmark_by_case for case_id in binding.benchmark_case_ids):
        raise ValueError(f"condition {binding.condition_id} references an unknown benchmark case")
    task_ids = tuple(
        sorted({benchmark_by_case[case_id].task_id for case_id in binding.benchmark_case_ids})
    )
    if task_ids != binding.task_ids:
        raise ValueError(f"condition {binding.condition_id} task frame mismatch")
    authority_query_families = {
        item.case_id: item.query_family_id for item in protocol.case_authority_bindings
    }
    if any(
        authority_query_families.get(case_id) != benchmark_by_case[case_id].query_family_id
        for case_id in binding.benchmark_case_ids
    ):
        raise ValueError(f"condition {binding.condition_id} query-family binding mismatch")
    if any(
        (
            benchmark_by_case[case_id].expected_relation != protocol.expected_relation
            or benchmark_by_case[case_id].baseline_expected_decision
            != protocol.baseline_arm.expected_recommendation
            or benchmark_by_case[case_id].counterfactual_expected_decision
            != protocol.counterfactual_arm.expected_recommendation
        )
        for case_id in binding.benchmark_case_ids
    ):
        raise ValueError(
            f"condition {binding.condition_id} benchmark decision orientation mismatch"
        )
    baseline = protocol.baseline_arm
    counterfactual = protocol.counterfactual_arm
    observed_identity = (
        baseline.provider,
        baseline.requested_model,
        baseline.resolved_model,
        baseline.provider_api_version,
        baseline.provider_sdk,
        baseline.provider_region,
        baseline.adapter_id,
        baseline.pipeline_id,
        baseline.knowledge_contract_digest,
        baseline.configuration_digest,
        counterfactual.configuration_digest,
        protocol.planned_pairs,
        len(protocol.planned_cluster_ids),
    )
    expected_identity = (
        binding.provider,
        binding.requested_model,
        binding.expected_resolved_model,
        binding.provider_api_version,
        binding.provider_sdk,
        binding.provider_region,
        binding.adapter_id,
        binding.pipeline_id,
        binding.knowledge_contract_digest,
        binding.baseline_configuration_digest,
        binding.counterfactual_configuration_digest,
        binding.planned_pairs,
        binding.planned_independent_clusters,
    )
    if observed_identity != expected_identity:
        raise ValueError(f"condition {binding.condition_id} frozen identity mismatch")
    rule = manifest.hypothesis_decision_rule
    if (
        protocol.multiplicity_method != "bonferroni"
        or protocol.multiplicity_family_size != len(rule.target_task_model_conditions)
        or protocol.design.familywise_alpha != rule.familywise_alpha
        or protocol.design.planned_inferential_clusters != binding.planned_independent_clusters
        or binding.planned_independent_clusters < rule.minimum_independent_clusters
    ):
        raise ValueError(f"condition {binding.condition_id} analysis-plan mismatch")


def _analysis_role(
    protocol: RepeatedEvidenceSensitivityProtocol,
) -> StudyConditionAnalysisRole:
    return (
        StudyConditionAnalysisRole.inertia_estimand
        if protocol.expected_relation is EvidenceSensitivityExpectedRelation.decision_flip
        else StudyConditionAnalysisRole.invariant_negative_control
    )


def _analyze_condition(
    *,
    manifest: RealModelStudyManifest,
    binding: StudyConditionBinding,
    protocol: RepeatedEvidenceSensitivityProtocol,
    evidence: StudyConditionEvidence | None,
    adjusted_alpha: Decimal,
    family_size: int,
) -> StudyConditionResult:
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    if evidence is None:
        return _empty_condition_result(
            binding,
            state=StudyConditionState.not_executed,
            deviations=("study-condition-not-executed",),
            analysis_role=_analysis_role(protocol),
        )

    source_protocol = RepeatedEvidenceSensitivityProtocol.model_validate(
        evidence.protocol.model_dump(mode="json")
    )
    baseline = _unchanged_privacy_safe_runset(evidence.baseline_runset)
    counterfactual = _unchanged_privacy_safe_runset(evidence.counterfactual_runset)
    deviations: set[str] = set()
    observed_provenance = derive_study_observed_execution_provenance(
        manifest=manifest,
        binding=binding,
        protocol=protocol,
        baseline_runset=baseline,
        counterfactual_runset=counterfactual,
    )
    supplied_provenance = evidence.observed_execution_provenance
    if supplied_provenance is None:
        deviations.add("observed-execution-provenance-missing")
    else:
        supplied_provenance = StudyObservedExecutionProvenance.model_validate(
            supplied_provenance.model_dump(mode="json")
        )
        if supplied_provenance != observed_provenance:
            deviations.add("observed-execution-provenance-mismatch")
    if observed_provenance.observed_origin is not binding.execution_origin:
        deviations.add("observed-execution-origin-mismatch")
    if (
        binding.execution_origin is StudyExecutionOrigin.real_provider
        and observed_provenance.observed_origin is not StudyExecutionOrigin.real_provider
    ):
        deviations.add("provider-dispatch-provenance-incomplete")
    if source_protocol != protocol:
        deviations.add("post-registration-protocol-drift")
    if (
        source_protocol.protocol_digest != binding.protocol_digest
        or source_protocol.design_commitment_digest != binding.design_commitment_digest
    ):
        deviations.add("protocol-binding-mismatch")

    runsets = (baseline, counterfactual)
    records = tuple(run for runset in runsets for run in runset.runs)
    deviations.update(_runset_binding_deviations(manifest, binding, protocol, runsets))
    if (
        binding.execution_origin is StudyExecutionOrigin.real_provider
        and not _paired_attempt_journal_is_valid(protocol, baseline, counterfactual)
    ):
        deviations.add("execution-attempt-journal-invalid")
    deviations.update(_record_identity_deviations(binding, records))
    if binding.execution_origin is StudyExecutionOrigin.real_provider and any(
        record.provider_finish_reason != "stop" for record in records
    ):
        deviations.add("provider-normal-termination-unverified")
    deviations.update(_execution_window_deviations(manifest, records))
    operational = _operational_summary(records)
    if operational.cost_reported_records != operational.run_records:
        deviations.add("cost-accounting-incomplete")
    if operational.cost_budget_committed_records != operational.run_records:
        deviations.add("committed-cost-accounting-incomplete")
    if (
        binding.execution_origin is StudyExecutionOrigin.real_provider
        and operational.latency_reported_records != operational.run_records
    ):
        deviations.add("latency-accounting-incomplete")
    try:
        if (
            binding.execution_origin is StudyExecutionOrigin.synthetic_fixture
            and observed_provenance.observed_origin is StudyExecutionOrigin.synthetic_fixture
        ):
            observations = _assemble_paired_observations_for_verified_synthetic_study(
                protocol,
                baseline,
                counterfactual,
            )
        else:
            observations = assemble_paired_observations(
                protocol,
                baseline,
                counterfactual,
            )
        dependencies = build_paired_runset_dependencies(protocol, baseline, counterfactual)
        sufficiency = evaluate_statistical_sufficiency(
            protocol,
            observations,
            source_runsets=dependencies,
        )
        stochastic = build_stochastic_sensitivity_report(sufficiency)
    except (TypeError, ValueError):
        deviations.add("source-evidence-replay-failed")
        replay_audit = _audit_replay_failure(protocol, baseline, counterfactual)
        return _empty_condition_result(
            binding,
            state=StudyConditionState.invalidated,
            deviations=tuple(sorted(deviations)),
            operational=operational,
            identities=_observed_identities(records),
            observed_window=_observed_window(records),
            observed_provenance=observed_provenance,
            analysis_role=_analysis_role(protocol),
            actual_pairs=replay_audit.actual_pairs,
            missing_pairs=replay_audit.missing_pairs,
            invalid_pairs=replay_audit.invalid_pairs,
            actual_clusters=replay_audit.actual_clusters,
            failure_summaries=replay_audit.failure_summaries,
        )

    deviations.update(_observation_deviations(observations))
    if sufficiency.excluded_pairs:
        deviations.add("confirmatory-pair-exclusion-observed")
    if sufficiency.state is SufficiencyState.prerequisites_unmet:
        deviations.add("statistical-prerequisites-unmet")
    endpoint_counts = derive_study_cluster_endpoint_counts(sufficiency)
    invalid_endpoint_count = endpoint_counts[6]
    if invalid_endpoint_count:
        deviations.add(
            "inertia-endpoint-unclassified"
            if protocol.expected_relation is EvidenceSensitivityExpectedRelation.decision_flip
            else "invariant-control-output-invalid"
        )
    control_failed = (
        not deviations
        and sufficiency.state is SufficiencyState.satisfied
        and protocol.expected_relation is EvidenceSensitivityExpectedRelation.decision_invariant
        and endpoint_counts[5] > 0
    )
    if control_failed:
        deviations.add("invariant-control-violation-observed")
    state = (
        StudyConditionState.control_failed
        if control_failed
        else StudyConditionState.invalidated
        if deviations
        else StudyConditionState.underpowered
        if sufficiency.state is SufficiencyState.inconclusive
        else StudyConditionState.analyzed
    )
    response_count: int | None = None
    inertia_count: int | None = None
    wrong_direction_count: int | None = None
    other_non_inertia_count: int | None = None
    inertia_breakdown: StudyDecisionInertiaDescriptiveBreakdown | None = None
    response_rate: str | None = None
    inertia_rate: str | None = None
    inertia_interval: StudyOneSidedInterval | None = None
    control_stability_count: int | None = None
    control_change_count: int | None = None
    control_change_rate: str | None = None
    control_change_interval: StudyOneSidedInterval | None = None
    if state in {StudyConditionState.analyzed, StudyConditionState.control_failed}:
        analysis = sufficiency.analysis
        if analysis is None:
            raise ValueError("satisfied live study condition is missing exact analysis")
        if protocol.expected_relation is EvidenceSensitivityExpectedRelation.decision_flip:
            (
                response_count,
                inertia_count,
                wrong_direction_count,
                other_non_inertia_count,
            ) = endpoint_counts[:4]
            (
                baseline_correct_inertia_count,
                baseline_incorrect_inertia_count,
                mixed_baseline_correctness_inertia_count,
            ) = derive_study_inertia_descriptive_counts(sufficiency)
            inertia_breakdown = StudyDecisionInertiaDescriptiveBreakdown(
                planned_clusters=binding.planned_independent_clusters,
                baseline_correct_same_decision_cluster_count=(baseline_correct_inertia_count),
                baseline_incorrect_same_decision_cluster_count=(baseline_incorrect_inertia_count),
                mixed_baseline_correctness_same_decision_cluster_count=(
                    mixed_baseline_correctness_inertia_count
                ),
                baseline_correct_same_decision_rate=format_six_place_rate(
                    baseline_correct_inertia_count,
                    binding.planned_independent_clusters,
                ),
                baseline_incorrect_same_decision_rate=format_six_place_rate(
                    baseline_incorrect_inertia_count,
                    binding.planned_independent_clusters,
                ),
                mixed_baseline_correctness_same_decision_rate=format_six_place_rate(
                    mixed_baseline_correctness_inertia_count,
                    binding.planned_independent_clusters,
                ),
            )
            lower = clopper_pearson_one_sided(
                inertia_count,
                binding.planned_independent_clusters,
                adjusted_alpha,
                side="lower",
            )
            upper = clopper_pearson_one_sided(
                inertia_count,
                binding.planned_independent_clusters,
                adjusted_alpha,
                side="upper",
            )
            response_rate = format_six_place_rate(
                response_count,
                binding.planned_independent_clusters,
            )
            inertia_rate = format_six_place_rate(
                inertia_count,
                binding.planned_independent_clusters,
            )
            inertia_interval = StudyOneSidedInterval(
                familywise_alpha=manifest.hypothesis_decision_rule.familywise_alpha,
                family_size=family_size,
                adjusted_alpha=f"{adjusted_alpha:.12f}",
                trials=binding.planned_independent_clusters,
                successes=inertia_count,
                lower_bound=format_twelve_place_bound(lower.bound, rounding=ROUND_FLOOR),
                upper_bound=format_twelve_place_bound(upper.bound, rounding=ROUND_CEILING),
            )
        else:
            control_stability_count, control_change_count = endpoint_counts[4:6]
            control_lower = clopper_pearson_one_sided(
                control_change_count,
                binding.planned_independent_clusters,
                adjusted_alpha,
                side="lower",
            )
            control_upper = clopper_pearson_one_sided(
                control_change_count,
                binding.planned_independent_clusters,
                adjusted_alpha,
                side="upper",
            )
            control_change_rate = format_six_place_rate(
                control_change_count,
                binding.planned_independent_clusters,
            )
            control_change_interval = StudyOneSidedInterval(
                familywise_alpha=manifest.hypothesis_decision_rule.familywise_alpha,
                family_size=family_size,
                adjusted_alpha=f"{adjusted_alpha:.12f}",
                trials=binding.planned_independent_clusters,
                successes=control_change_count,
                lower_bound=format_twelve_place_bound(control_lower.bound, rounding=ROUND_FLOOR),
                upper_bound=format_twelve_place_bound(control_upper.bound, rounding=ROUND_CEILING),
            )
    invalid_pairs = (
        sufficiency.actual_pairs - sufficiency.included_pairs - sufficiency.excluded_pairs
    )
    observed_window = _observed_window(records)
    result_payload: dict[str, object] = {
        "condition_id": binding.condition_id,
        "state": state,
        "analysis_role": _analysis_role(protocol),
        "protocol_digest": binding.protocol_digest,
        "design_commitment_digest": binding.design_commitment_digest,
        "observed_model_identities": _observed_identities(records),
        "observed_execution_provenance": observed_provenance,
        "planned_pairs": binding.planned_pairs,
        "actual_pairs": sufficiency.actual_pairs,
        "included_pairs": sufficiency.included_pairs,
        "missing_pairs": sufficiency.missing_pairs,
        "excluded_pairs": sufficiency.excluded_pairs,
        "invalid_pairs": invalid_pairs,
        "planned_clusters": binding.planned_independent_clusters,
        "actual_clusters": sufficiency.actual_clusters,
        "analyzable_clusters": sufficiency.analyzable_clusters,
        "coupling": protocol.coupling,
        "operational_summary": operational,
        "failure_summaries": _failure_summaries(observations),
        "deviation_codes": tuple(sorted(deviations)),
    }
    if observed_window is not None:
        result_payload["observed_execution_window"] = observed_window
    if state is not StudyConditionState.invalidated:
        result_payload["sufficiency_report"] = sufficiency
        result_payload["expected_response_diagnostic"] = (
            StudyExpectedResponseDiagnostic.from_source_report(stochastic)
        )
    if state in {StudyConditionState.analyzed, StudyConditionState.control_failed}:
        if protocol.expected_relation is EvidenceSensitivityExpectedRelation.decision_flip:
            result_payload.update(
                {
                    "decision_response_cluster_count": response_count,
                    "decision_inertia_cluster_count": inertia_count,
                    "decision_wrong_direction_cluster_count": wrong_direction_count,
                    "decision_other_non_inertia_cluster_count": other_non_inertia_count,
                    "decision_inertia_descriptive_breakdown": inertia_breakdown,
                    "decision_response_rate": response_rate,
                    "decision_inertia_rate": inertia_rate,
                    "decision_inertia_interval": inertia_interval,
                }
            )
        else:
            result_payload.update(
                {
                    "control_expected_stability_cluster_count": control_stability_count,
                    "control_unexpected_change_cluster_count": control_change_count,
                    "control_unexpected_change_rate": control_change_rate,
                    "control_unexpected_change_interval": control_change_interval,
                }
            )
    return StudyConditionResult.model_validate(result_payload)


def _observed_provider_input_manifest_digest(
    runset: RunSet,
    expected_case_ids: tuple[str, ...],
) -> str | None:
    digests_by_case: dict[str, set[str]] = {}
    expected = set(expected_case_ids)
    for record in runset.runs:
        prompt_digest = record.provenance.prompt_digest
        if record.case_id not in expected or prompt_digest is None:
            return None
        digests_by_case.setdefault(record.case_id, set()).add(prompt_digest)
    if set(digests_by_case) != expected or any(
        len(digests) != 1 for digests in digests_by_case.values()
    ):
        return None
    return calculate_provider_input_manifest_digest(
        {case_id: next(iter(digests_by_case[case_id])) for case_id in expected_case_ids}
    )


def _paired_attempt_journal_is_valid(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> bool:
    try:
        validate_paired_attempt_journal(protocol, baseline, counterfactual)
    except (TypeError, ValueError):
        return False
    return True


def _runset_binding_deviations(
    manifest: RealModelStudyManifest,
    binding: StudyConditionBinding,
    protocol: RepeatedEvidenceSensitivityProtocol,
    runsets: tuple[RunSet, RunSet],
) -> set[str]:
    deviations: set[str] = set()
    expected = (
        (
            protocol.baseline_arm.configuration_digest,
            "baseline_evidence",
            binding.baseline_provider_input_manifest_digest,
        ),
        (
            protocol.counterfactual_arm.configuration_digest,
            "counterfactual_evidence",
            binding.counterfactual_provider_input_manifest_digest,
        ),
    )
    for runset, (configuration_digest, arm_id, provider_input_digest) in zip(
        runsets, expected, strict=True
    ):
        if runset.study_manifest_digest != manifest.manifest_digest:
            deviations.add("study-manifest-backlink-mismatch")
        if runset.evidence_sensitivity_design_digest != binding.design_commitment_digest:
            deviations.add("design-commitment-backlink-mismatch")
        if any(run.provenance.configuration_digest != configuration_digest for run in runset.runs):
            deviations.add(f"{arm_id}-configuration-mismatch")
        if any(
            run.provenance.study_manifest_digest != manifest.manifest_digest for run in runset.runs
        ):
            deviations.add("study-manifest-record-backlink-mismatch")
        observed_provider_input_digest = _observed_provider_input_manifest_digest(
            runset, binding.benchmark_case_ids
        )
        if (
            observed_provider_input_digest is not None
            and observed_provider_input_digest != provider_input_digest
        ) or (runset.completion_status == "complete" and observed_provider_input_digest is None):
            deviations.add(f"{arm_id}-provider-input-manifest-mismatch")
    return deviations


def _runset_supports_observed_provenance(
    runset: RunSet,
    arm: SensitivityArmBinding,
    *,
    manifest: RealModelStudyManifest,
    binding: StudyConditionBinding,
) -> bool:
    if arm.configuration_digest == binding.baseline_configuration_digest:
        expected_provider_input_digest = binding.baseline_provider_input_manifest_digest
    elif arm.configuration_digest == binding.counterfactual_configuration_digest:
        expected_provider_input_digest = binding.counterfactual_provider_input_manifest_digest
    else:
        return False
    return (
        runset.execution_mode is ExecutionMode.live
        and runset.fixture_manifest_digest == arm.configuration_digest
        and runset.evidence_sensitivity_design_digest == binding.design_commitment_digest
        and runset.study_manifest_digest == manifest.manifest_digest
        and runset.protocol_id is not None
        and runset.protocol_digest is not None
        and _observed_provider_input_manifest_digest(runset, binding.benchmark_case_ids)
        == expected_provider_input_digest
    )


def _record_supports_observed_provenance(
    record: AgentRunRecord,
    arm: SensitivityArmBinding,
    *,
    protocol: RepeatedEvidenceSensitivityProtocol,
    manifest: RealModelStudyManifest,
    expected_clusters: Mapping[str, str],
) -> bool:
    repetition = record.repetition_index
    expected_cluster = expected_clusters.get(record.case_id)
    if (
        record.execution_mode is not ExecutionMode.live
        or record.case_id not in protocol.planned_case_ids
        or repetition is None
        or not 0 <= repetition < protocol.repetitions_per_arm
        or expected_cluster is None
        or record.cluster_id != expected_cluster
        or record.observation_id is None
        or record.schedule_index is None
        or record.randomization_block_id is None
    ):
        return False
    if protocol.cluster_by == "source_group_id" and record.source_group_id != expected_cluster:
        return False
    observed_identity = (
        record.provider,
        record.model,
        record.resolved_model,
        record.provider_api_version,
        record.provider_sdk,
        record.provider_region,
        record.adapter_id,
        record.pipeline_id,
    )
    expected_identity = (
        arm.provider,
        arm.requested_model,
        arm.resolved_model,
        arm.provider_api_version,
        arm.provider_sdk,
        arm.provider_region,
        arm.adapter_id,
        arm.pipeline_id,
    )
    if observed_identity != expected_identity:
        return False
    provenance = record.provenance
    return (
        provenance.configuration_digest == arm.configuration_digest
        and provenance.retrieval_corpus_digest == arm.corpus_digest
        and provenance.tool_schema_digest == arm.tool_schema_digest
        and provenance.policy_bundle_digest == arm.policy_bundle_digest
        and provenance.evidence_sensitivity_design_digest == protocol.design_commitment_digest
        and provenance.study_manifest_digest == manifest.manifest_digest
        and provenance.model_identifier == arm.requested_model
    )


def _record_has_complete_study_timing(
    record: AgentRunRecord,
    manifest: RealModelStudyManifest,
) -> bool:
    if record.started_at_utc is None or record.completed_at_utc is None:
        return False
    try:
        started = parse_rfc3339_timestamp(record.started_at_utc, field_name="record.started_at_utc")
        completed = parse_rfc3339_timestamp(
            record.completed_at_utc, field_name="record.completed_at_utc"
        )
        window_start = parse_rfc3339_timestamp(
            manifest.execution_window.start, field_name="manifest.execution_window.start"
        )
        window_end = parse_rfc3339_timestamp(
            manifest.execution_window.end, field_name="manifest.execution_window.end"
        )
    except ValueError:
        return False
    return window_start <= started < completed <= window_end


def _usable_provider_metadata(value: str | None) -> bool:
    return (
        value is not None
        and bool(value.strip())
        and len(value) <= 1_024
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _usable_provider_response_id(value: str | None) -> bool:
    return _usable_provider_metadata(value)


def _record_identity_deviations(
    binding: StudyConditionBinding,
    records: tuple[AgentRunRecord, ...],
) -> set[str]:
    deviations: set[str] = set()
    expected = (
        binding.provider,
        binding.requested_model,
        binding.expected_resolved_model,
        binding.provider_api_version,
        binding.provider_sdk,
        binding.provider_region,
        binding.adapter_id,
        binding.pipeline_id,
    )
    for record in records:
        observed = (
            record.provider,
            record.model,
            record.resolved_model,
            record.provider_api_version,
            record.provider_sdk,
            record.provider_region,
            record.adapter_id,
            record.pipeline_id,
        )
        if observed != expected:
            deviations.add("observed-provider-model-identity-mismatch")
        if record.provenance.model_identifier != binding.requested_model:
            deviations.add("provenance-model-identity-mismatch")
        if record.provenance.evidence_sensitivity_design_digest != (
            binding.design_commitment_digest
        ):
            deviations.add("provenance-design-commitment-mismatch")
    serving_fingerprints = tuple(
        record.provider_serving_fingerprint
        for record in records
        if record.provider_serving_fingerprint is not None
    )
    if serving_fingerprints and len(serving_fingerprints) != len(records):
        deviations.add("provider-serving-fingerprint-incomplete")
    if len(set(serving_fingerprints)) > 1:
        deviations.add("provider-serving-fingerprint-drift")
    if len(_observed_identity_keys(records)) > MAX_STUDY_OBSERVED_MODEL_IDENTITIES:
        deviations.add("observed-model-identity-cardinality-exceeded")
    return deviations


def _execution_window_deviations(
    manifest: RealModelStudyManifest,
    records: tuple[AgentRunRecord, ...],
) -> set[str]:
    deviations: set[str] = set()
    window_start = parse_rfc3339_timestamp(
        manifest.execution_window.start, field_name="manifest.execution_window.start"
    )
    window_end = parse_rfc3339_timestamp(
        manifest.execution_window.end, field_name="manifest.execution_window.end"
    )
    for record in records:
        if record.started_at_utc is None or record.completed_at_utc is None:
            deviations.add("execution-timestamp-missing")
            continue
        started = parse_rfc3339_timestamp(record.started_at_utc, field_name="record.started_at_utc")
        completed = parse_rfc3339_timestamp(
            record.completed_at_utc, field_name="record.completed_at_utc"
        )
        if completed < started:
            deviations.add("execution-timestamp-order-invalid")
        if started < window_start or completed > window_end:
            deviations.add("execution-outside-preregistered-window")
    if (
        records
        and "execution-timestamp-missing" not in deviations
        and _observed_window(records) is None
    ):
        deviations.add("observed-execution-window-degenerate")
    return deviations


def _observation_deviations(
    observations: tuple[PairedSensitivityObservation, ...],
) -> set[str]:
    return {
        "invalid-pair-binding"
        for item in observations
        if item.disposition in _INVALIDATING_DISPOSITIONS
    }


def _operational_summary(
    records: tuple[AgentRunRecord, ...],
) -> StudyOperationalSummary:
    cost_values = tuple(
        _usd_to_microusd(record.estimated_cost_usd)
        for record in records
        if record.estimated_cost_usd is not None and record.estimated_cost_source != "not_reported"
    )
    committed_cost_values = tuple(
        _usd_to_microusd(record.cost_budget_committed_usd)
        for record in records
        if record.cost_budget_committed_usd is not None
    )
    latency_values = tuple(record.latency_ms for record in records if record.latency_ms is not None)
    return StudyOperationalSummary(
        run_records=len(records),
        cost_reported_records=len(cost_values),
        cost_budget_committed_records=len(committed_cost_values),
        latency_reported_records=len(latency_values),
        **({"total_estimated_cost_microusd": sum(cost_values)} if cost_values else {}),
        **(
            {"total_cost_budget_committed_microusd": sum(committed_cost_values)}
            if committed_cost_values
            else {}
        ),
        **(
            {
                "total_latency_ms": sum(latency_values),
                "minimum_latency_ms": min(latency_values),
                "maximum_latency_ms": max(latency_values),
            }
            if latency_values
            else {}
        ),
    )


def _observed_identities(
    records: tuple[AgentRunRecord, ...],
) -> tuple[StudyObservedModelIdentity, ...]:
    values = _observed_identity_keys(records)
    return tuple(
        StudyObservedModelIdentity(
            provider=item[0],
            requested_model=item[1],
            resolved_model=item[2],
            provider_api_version=item[3],
            provider_sdk=item[4],
            provider_region=item[5],
            provider_serving_fingerprint=item[6],
            adapter_id=item[7],
            pipeline_id=item[8],
        )
        for item in values[:MAX_STUDY_OBSERVED_MODEL_IDENTITIES]
    )


def _observed_identity_keys(
    records: tuple[AgentRunRecord, ...],
) -> tuple[
    tuple[
        str,
        str,
        str | None,
        str | None,
        str | None,
        str | None,
        str | None,
        str,
        str,
    ],
    ...,
]:
    values = {
        (
            record.provider,
            record.model,
            record.resolved_model,
            record.provider_api_version,
            record.provider_sdk,
            record.provider_region,
            record.provider_serving_fingerprint,
            record.adapter_id,
            record.pipeline_id,
        )
        for record in records
        if record.provider is not None
        and record.model is not None
        and record.adapter_id is not None
        and record.pipeline_id is not None
    }
    return tuple(sorted(values, key=lambda item: tuple(value or "" for value in item)))


def _observed_window(
    records: tuple[AgentRunRecord, ...],
) -> StudyExecutionWindow | None:
    if not records or any(
        record.started_at_utc is None or record.completed_at_utc is None for record in records
    ):
        return None
    starts = tuple(record.started_at_utc for record in records if record.started_at_utc)
    ends = tuple(record.completed_at_utc for record in records if record.completed_at_utc)

    def timestamp_key(value: str) -> datetime:
        return parse_rfc3339_timestamp(
            value,
            field_name="observed execution timestamp",
        )

    start = min(starts, key=timestamp_key)
    end = max(ends, key=timestamp_key)
    if parse_rfc3339_timestamp(
        start, field_name="observed_execution_window.start"
    ) >= parse_rfc3339_timestamp(end, field_name="observed_execution_window.end"):
        return None
    return StudyExecutionWindow(start=start, end=end)


def _failure_summaries(
    observations: tuple[PairedSensitivityObservation, ...],
) -> tuple[StudyFailureSummary, ...]:
    grouped: dict[str, list[str]] = {}
    counts = Counter(
        item.disposition_reason or item.disposition.value
        for item in observations
        if item.disposition is not PairDisposition.included
    )
    for item in observations:
        if item.disposition is PairDisposition.included:
            continue
        reason = item.disposition_reason or item.disposition.value
        grouped.setdefault(reason, []).append(item.case_id)
    return tuple(
        StudyFailureSummary(
            reason_code=reason,
            count=counts[reason],
            example_case_ids=tuple(sorted(set(grouped[reason])))[:3],
        )
        for reason in sorted(counts)
    )


def _audit_replay_failure(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> _ReplayFailureAudit:
    """Preserve bounded structural evidence when semantic replay cannot complete."""

    planned_cells = {
        (case_id, repetition)
        for case_id in protocol.planned_case_ids
        for repetition in range(protocol.repetitions_per_arm)
    }

    def observed_cells(runset: RunSet) -> set[tuple[str, int]]:
        return {
            (record.case_id, record.repetition_index)
            for record in runset.runs
            if record.repetition_index is not None
            and (record.case_id, record.repetition_index) in planned_cells
        }

    paired_cells = observed_cells(baseline) & observed_cells(counterfactual)
    missing_cells = planned_cells - paired_cells
    cluster_by_case = {item.case_id: item.cluster_id for item in protocol.case_cluster_bindings}
    actual_clusters = len({cluster_by_case[case_id] for case_id, _ in paired_cells})
    summaries: list[StudyFailureSummary] = []
    if missing_cells:
        summaries.append(
            StudyFailureSummary(
                reason_code="paired-observation-missing",
                count=len(missing_cells),
                example_case_ids=tuple(sorted({case_id for case_id, _ in missing_cells}))[:3],
            )
        )
    if paired_cells:
        summaries.append(
            StudyFailureSummary(
                reason_code="source-evidence-replay-failed",
                count=len(paired_cells),
                example_case_ids=tuple(sorted({case_id for case_id, _ in paired_cells}))[:3],
            )
        )
    return _ReplayFailureAudit(
        actual_pairs=len(paired_cells),
        missing_pairs=len(missing_cells),
        invalid_pairs=len(paired_cells),
        actual_clusters=actual_clusters,
        failure_summaries=tuple(sorted(summaries, key=lambda item: item.reason_code)),
    )


def _empty_condition_result(
    binding: StudyConditionBinding,
    *,
    state: StudyConditionState,
    deviations: tuple[str, ...],
    analysis_role: StudyConditionAnalysisRole,
    operational: StudyOperationalSummary | None = None,
    identities: tuple[StudyObservedModelIdentity, ...] = (),
    observed_window: StudyExecutionWindow | None = None,
    observed_provenance: StudyObservedExecutionProvenance | None = None,
    actual_pairs: int = 0,
    missing_pairs: int | None = None,
    invalid_pairs: int = 0,
    actual_clusters: int = 0,
    failure_summaries: tuple[StudyFailureSummary, ...] = (),
) -> StudyConditionResult:
    if missing_pairs is None:
        missing_pairs = binding.planned_pairs
    result_payload: dict[str, object] = {
        "condition_id": binding.condition_id,
        "state": state,
        "analysis_role": analysis_role,
        "protocol_digest": binding.protocol_digest,
        "design_commitment_digest": binding.design_commitment_digest,
        "observed_model_identities": identities,
        "planned_pairs": binding.planned_pairs,
        "actual_pairs": actual_pairs,
        "included_pairs": 0,
        "missing_pairs": missing_pairs,
        "excluded_pairs": 0,
        "invalid_pairs": invalid_pairs,
        "planned_clusters": binding.planned_independent_clusters,
        "actual_clusters": actual_clusters,
        "analyzable_clusters": 0,
        "operational_summary": operational
        or StudyOperationalSummary(
            run_records=0,
            cost_reported_records=0,
            cost_budget_committed_records=0,
            latency_reported_records=0,
        ),
        "failure_summaries": failure_summaries,
        "deviation_codes": deviations,
    }
    if observed_window is not None:
        result_payload["observed_execution_window"] = observed_window
    if observed_provenance is not None:
        result_payload["observed_execution_provenance"] = observed_provenance
    return StudyConditionResult.model_validate(result_payload)


def _invalidate_condition_result(
    result: StudyConditionResult,
    reason_code: str,
) -> StudyConditionResult:
    payload = result.model_dump(mode="json")
    payload["state"] = StudyConditionState.invalidated.value
    payload["deviation_codes"] = sorted({*result.deviation_codes, reason_code})
    for field_name in (
        "decision_response_cluster_count",
        "decision_inertia_cluster_count",
        "decision_wrong_direction_cluster_count",
        "decision_other_non_inertia_cluster_count",
        "decision_inertia_descriptive_breakdown",
        "decision_response_rate",
        "decision_inertia_rate",
        "decision_inertia_interval",
        "control_expected_stability_cluster_count",
        "control_unexpected_change_cluster_count",
        "control_unexpected_change_rate",
        "control_unexpected_change_interval",
        "sufficiency_report",
        "expected_response_diagnostic",
    ):
        payload.pop(field_name, None)
    return StudyConditionResult.model_validate(payload)


def _invalidate_inconsistent_provider_serving_fingerprint_groups(
    manifest: RealModelStudyManifest,
    results: tuple[StudyConditionResult, ...],
) -> tuple[StudyConditionResult, ...]:
    """Invalidate otherwise valid model-matched groups with incomparable serving metadata."""

    eligible_states = {
        StudyConditionState.analyzed,
        StudyConditionState.control_failed,
        StudyConditionState.underpowered,
    }
    members_by_identity: dict[
        tuple[
            StudyExecutionOrigin,
            str,
            str,
            str,
            str | None,
            str | None,
            str | None,
            str,
            str,
        ],
        list[int],
    ] = {}
    for index, (binding, result) in enumerate(zip(manifest.conditions, results, strict=True)):
        if (
            binding.execution_origin is not StudyExecutionOrigin.real_provider
            or result.state not in eligible_states
            or len(result.observed_model_identities) != 1
        ):
            continue
        members_by_identity.setdefault(
            _study_condition_execution_identity(binding),
            [],
        ).append(index)

    invalidations: dict[int, str] = {}
    for indices in members_by_identity.values():
        fingerprints = tuple(
            results[index].observed_model_identities[0].provider_serving_fingerprint
            for index in indices
        )
        reported = tuple(value for value in fingerprints if value is not None)
        reason: str | None = None
        if reported and len(reported) != len(fingerprints):
            reason = "provider-serving-fingerprint-group-incomplete"
        elif len(set(reported)) > 1:
            reason = "provider-serving-fingerprint-group-drift"
        if reason is not None:
            invalidations.update({index: reason for index in indices})

    return tuple(
        _invalidate_condition_result(result, invalidations[index])
        if index in invalidations
        else result
        for index, result in enumerate(results)
    )


def _classify(
    manifest: RealModelStudyManifest,
    results: tuple[StudyConditionResult, ...],
) -> StudyHypothesisClassification:
    threshold = Decimal(manifest.hypothesis_decision_rule.materiality_threshold)
    intervals = tuple(
        item.decision_inertia_interval
        for item in results
        if item.analysis_role is StudyConditionAnalysisRole.inertia_estimand
    )
    if not intervals:
        raise ValueError("analyzed study is missing an inertia-estimand condition")
    if any(item is None for item in intervals):
        raise ValueError("analyzed study is missing a preregistered interval")
    lower = tuple(Decimal(item.lower_bound) for item in intervals if item is not None)
    upper = tuple(Decimal(item.upper_bound) for item in intervals if item is not None)
    if any(value > threshold for value in lower):
        return StudyHypothesisClassification.supported
    if all(value <= threshold for value in upper):
        return StudyHypothesisClassification.contradicted
    return StudyHypothesisClassification.inconclusive


def _usd_to_microusd(value: str) -> int:
    whole, separator, fractional = value.partition(".")
    if (
        separator != "."
        or not whole
        or not whole.isascii()
        or not whole.isdecimal()
        or len(fractional) != 6
        or not fractional.isascii()
        or not fractional.isdecimal()
    ):
        raise ValueError("cost must be exactly representable in micro-USD")
    return int(whole) * 1_000_000 + int(fractional)


def _unchanged_privacy_safe_runset(value: RunSet) -> RunSet:
    runset = RunSet.model_validate(value.model_dump(mode="json"))
    original = runset.model_dump(mode="json", warnings="error")
    filtered = redact_runset_payload(original)
    assert_runset_payload_safe_for_persistence(filtered)
    if filtered != original:
        raise ValueError(
            "study source RunSets must already be privacy-filtered because redaction "
            "would invalidate their cryptographic dependencies"
        )
    return runset


def _manifest_condition(
    manifest: RealModelStudyManifest,
    condition_id: str,
) -> StudyConditionBinding:
    matches = tuple(item for item in manifest.conditions if item.condition_id == condition_id)
    if len(matches) != 1:
        raise ValueError("condition_id is not present exactly once in the study manifest")
    return matches[0]


def _copy_manifest(value: RealModelStudyManifest) -> RealModelStudyManifest:
    return RealModelStudyManifest.model_validate(value.model_dump(mode="json"))


__all__ = [
    "StudyConditionEvidence",
    "analyze_real_model_study",
    "bind_study_manifest_to_live_config",
    "validate_study_manifest_inputs",
]
