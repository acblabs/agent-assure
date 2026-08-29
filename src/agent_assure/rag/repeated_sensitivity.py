from __future__ import annotations

import re
from decimal import Decimal
from pathlib import Path
from typing import Literal, cast

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    read_text_bounded_from_filesystem_root,
)
from agent_assure.live.adapters import TrustedLiveExecution
from agent_assure.live.config import LiveRunConfig, live_sdk_identifier
from agent_assure.live.runner import (
    LiveExecutionSnapshot,
    calculate_live_execution_configuration_digest,
    calculate_live_prompt_manifest_digest,
    prepare_live_execution_snapshot,
    run_live_suite,
    validate_live_execution_snapshot,
)
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_PATTERN,
    ExecutionMode,
    GateState,
    ReasonCode,
    Severity,
)
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.stochastic_sensitivity import (
    CONFIRMATORY_STOCHASTIC_ADAPTER_IDS,
    PairDisposition,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    RunRecordArtifactDependency,
    RunSetArtifactDependency,
    SensitivityArmBinding,
    SensitivityExecutionMode,
    SensitivityInterpretation,
    derive_expected_decision_response,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
)

_LIVE_OPERATIONAL_EXCLUSION_REASONS = frozenset(
    {
        "budget_accounting_unavailable",
        "budget_exhausted",
        "cost_accounting_unavailable",
        "cost_budget_exhausted_before_attempt",
        "cost_budget_exceeded_after_response",
        "generated_token_budget_exhausted",
        "generated_token_budget_exhausted_before_attempt",
        "generated_token_budget_exceeded_after_response",
        "rate_limit_budget_exhausted",
        "request_budget_exhausted",
        "runtime-failed",
        "terminal_policy_stop",
        "token_accounting_unavailable",
        "token_budget_exhausted",
        "token_budget_exhausted_before_attempt",
        "token_budget_exceeded_after_response",
    }
)
_POST_RESPONSE_IDENTITY_FIELDS = (
    "resolved_model",
    "provider_api_version",
    "provider_sdk",
    "provider_region",
)


def load_repeated_sensitivity_protocol(
    path: Path,
) -> RepeatedEvidenceSensitivityProtocol:
    if path.suffix.lower() == ".json":
        payload = load_validated_artifact_payload(
            path,
            "repeated-evidence-sensitivity-protocol",
            label="repeated evidence-sensitivity protocol",
        )
        return project_validated_artifact_payload(
            payload,
            RepeatedEvidenceSensitivityProtocol,
            kind="repeated-evidence-sensitivity-protocol",
        )
    text = read_text_bounded_from_filesystem_root(
        path,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="repeated evidence-sensitivity protocol YAML",
    )
    payload = safe_load_yaml_text(
        text,
        label="repeated evidence-sensitivity protocol YAML",
    )
    if not isinstance(payload, dict):
        raise TypeError("repeated evidence-sensitivity protocol must be a mapping")
    return RepeatedEvidenceSensitivityProtocol.model_validate(payload)


def calculate_case_manifest_digest(config: LiveRunConfig) -> str:
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    return sha256_hexdigest(
        {
            "cases": [
                item.model_dump(mode="json")
                for item in sorted(config.cases, key=lambda case: case.case_id)
            ]
        }
    )


def validate_live_arm_prebinding(
    *,
    compiled: CompiledSuite,
    config: LiveRunConfig,
    config_dir: Path,
    binding: SensitivityArmBinding,
    case_authority_bindings: tuple[object, ...],
    execution_snapshot: LiveExecutionSnapshot | None = None,
) -> None:
    """Reject an unbound live arm before constructing an adapter."""
    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    binding = SensitivityArmBinding.model_validate(binding.model_dump(mode="json"))
    snapshot = (
        prepare_live_execution_snapshot(compiled, config, config_dir=config_dir)
        if execution_snapshot is None
        else validate_live_execution_snapshot(compiled, config, execution_snapshot)
    )
    observed = calculate_live_arm_binding_facts(
        compiled=compiled,
        config=config,
        config_dir=config_dir,
        execution_snapshot=snapshot,
    )
    observed_authority = observed.pop("case_authority_bindings")
    if observed_authority != tuple(case_authority_bindings):
        raise ValueError("live arm does not match its pre-bound per-case authority projection")
    expected = {
        field_name: getattr(binding, field_name)
        for field_name in observed
        if field_name not in {"expected_recommendation", "expected_outcome"}
    }
    expected["expected_recommendation"] = binding.expected_recommendation
    expected["expected_outcome"] = binding.expected_outcome
    mismatches = tuple(
        field_name for field_name, value in observed.items() if value != expected[field_name]
    )
    if mismatches:
        raise ValueError(
            "live arm does not match its pre-bound protocol identity: " + ", ".join(mismatches)
        )


def calculate_live_arm_binding_facts(
    *,
    compiled: CompiledSuite,
    config: LiveRunConfig,
    config_dir: Path,
    execution_snapshot: LiveExecutionSnapshot | None = None,
) -> dict[str, object]:
    """Resolve exact arm-binding facts without constructing or dispatching an adapter."""
    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    snapshot = (
        prepare_live_execution_snapshot(compiled, config, config_dir=config_dir)
        if execution_snapshot is None
        else validate_live_execution_snapshot(compiled, config, execution_snapshot)
    )
    if snapshot.knowledge_contract is None:
        raise ValueError("live sensitivity arm requires a bound knowledge-authority contract")
    if config.retrieval_corpus_digest is None:
        raise ValueError("live sensitivity arm requires a bound governing corpus")
    assignments = tuple(
        next(
            (
                item
                for item in case_binding.assignments
                if item.corpus_digest == config.retrieval_corpus_digest
            ),
            None,
        )
        for case_binding in snapshot.case_authority_bindings
    )
    if not assignments or any(item is None for item in assignments):
        raise ValueError(
            "knowledge-authority contract has incomplete case assignments for the live arm corpus"
        )
    expected_outputs = {
        (item.expected_decision, item.expected_outcome) for item in assignments if item is not None
    }
    if len(expected_outputs) != 1:
        raise ValueError(
            "v1 repeated sensitivity requires one coherent arm expectation across all planned cases"
        )
    expected_recommendation, expected_outcome = next(iter(expected_outputs))
    return {
        "configuration_digest": calculate_live_execution_configuration_digest(
            compiled,
            config,
            config_dir=config_dir,
            execution_snapshot=snapshot,
        ),
        "corpus_digest": config.retrieval_corpus_digest,
        "prompt_manifest_digest": calculate_live_prompt_manifest_digest(
            compiled,
            config,
            config_dir=config_dir,
            execution_snapshot=snapshot,
        ),
        "case_manifest_digest": calculate_case_manifest_digest(config),
        "knowledge_contract_digest": config.knowledge_contract_digest,
        "provider": config.adapter.provider,
        "requested_model": config.adapter.model,
        "provider_api_version": config.adapter.api_version,
        "provider_sdk": _sdk_label(config),
        "provider_region": config.adapter.region,
        "adapter_id": config.adapter.adapter_id,
        "pipeline_id": config.pipeline_id,
        "tool_schema_digest": config.tool_schema_digest,
        "policy_bundle_digest": config.policy_bundle_digest,
        "expected_recommendation": expected_recommendation,
        "expected_outcome": expected_outcome,
        "case_authority_bindings": snapshot.case_authority_bindings,
    }


def run_repeated_live_study(
    *,
    compiled: CompiledSuite,
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline_config: LiveRunConfig,
    counterfactual_config: LiveRunConfig,
    operational_protocol: LiveProtocolRecord,
    baseline_config_dir: Path,
    counterfactual_config_dir: Path,
    baseline_trust: TrustedLiveExecution | None = None,
    counterfactual_trust: TrustedLiveExecution | None = None,
) -> tuple[RunSet, RunSet]:
    """Execute two pre-bound arms through the existing trusted live adapters."""
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    baseline_config = LiveRunConfig.model_validate(baseline_config.model_dump(mode="json"))
    counterfactual_config = LiveRunConfig.model_validate(
        counterfactual_config.model_dump(mode="json")
    )
    if protocol.execution_mode is not SensitivityExecutionMode.stochastic_live:
        raise ValueError("live study execution requires stochastic_live mode")
    for arm_name, config in (
        ("baseline", baseline_config),
        ("counterfactual", counterfactual_config),
    ):
        if (
            getattr(config, "evidence_sensitivity_design_digest", None)
            != protocol.design_commitment_digest
        ):
            raise ValueError(
                f"{arm_name} live config does not carry the exact pre-execution design commitment"
            )
        if config.retrieval_corpus_dir is None:
            raise ValueError(f"{arm_name} live config must bind retrieval_corpus_dir")
        if config.knowledge_contract_path is None:
            raise ValueError(f"{arm_name} live config must bind knowledge_contract_path")
    if protocol.interpretation is SensitivityInterpretation.confirmatory:
        configured = {
            baseline_config.adapter.adapter_id,
            counterfactual_config.adapter.adapter_id,
        }
        if not configured <= CONFIRMATORY_STOCHASTIC_ADAPTER_IDS:
            raise ValueError(
                "confirmatory stochastic sensitivity requires a supported "
                "stochastic network adapter"
            )
    compiled = CompiledSuite.model_validate(compiled.model_dump(mode="json"))
    operational_protocol = LiveProtocolRecord.model_validate(
        operational_protocol.model_dump(mode="json")
    )
    _validate_operational_protocol_binding(
        protocol,
        operational_protocol,
        baseline_config,
        counterfactual_config,
    )
    # Capture both arms before the first dispatch. The exact prompt, corpus,
    # authority, and file-backed adapter bytes are then reused for execution.
    baseline_snapshot = prepare_live_execution_snapshot(
        compiled,
        baseline_config,
        config_dir=baseline_config_dir,
    )
    counterfactual_snapshot = prepare_live_execution_snapshot(
        compiled,
        counterfactual_config,
        config_dir=counterfactual_config_dir,
    )
    validate_live_arm_prebinding(
        compiled=compiled,
        config=baseline_config,
        config_dir=baseline_config_dir,
        binding=protocol.baseline_arm,
        case_authority_bindings=protocol.case_authority_bindings,
        execution_snapshot=baseline_snapshot,
    )
    validate_live_arm_prebinding(
        compiled=compiled,
        config=counterfactual_config,
        config_dir=counterfactual_config_dir,
        binding=protocol.counterfactual_arm,
        case_authority_bindings=protocol.case_authority_bindings,
        execution_snapshot=counterfactual_snapshot,
    )
    _validate_live_pair_schedule(
        protocol,
        baseline_config,
        counterfactual_config,
        baseline_snapshot,
        counterfactual_snapshot,
    )
    baseline = run_live_suite(
        compiled,
        baseline_config,
        protocol=operational_protocol,
        config_dir=baseline_config_dir,
        trust=baseline_trust,
        execution_snapshot=baseline_snapshot,
    )
    counterfactual = run_live_suite(
        compiled,
        counterfactual_config,
        protocol=operational_protocol,
        config_dir=counterfactual_config_dir,
        trust=counterfactual_trust,
        execution_snapshot=counterfactual_snapshot,
    )
    return baseline, counterfactual


def assemble_paired_observations(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> tuple[PairedSensitivityObservation, ...]:
    """Outer-join exact planned cells and preserve every missing/excluded pair."""
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    baseline = RunSet.model_validate(baseline.model_dump(mode="json"))
    counterfactual = RunSet.model_validate(counterfactual.model_dump(mode="json"))
    baseline_index, baseline_duplicates, baseline_extra = _index_runs(protocol, baseline)
    counter_index, counter_duplicates, counter_extra = _index_runs(protocol, counterfactual)
    global_mismatch = bool(
        baseline_duplicates
        or counter_duplicates
        or baseline_extra
        or counter_extra
        or not _runset_source_identifiers_are_machine_safe(protocol, baseline)
        or not _runset_source_identifiers_are_machine_safe(protocol, counterfactual)
        or not _runset_matches_binding(protocol, baseline, protocol.baseline_arm)
        or not _runset_matches_binding(
            protocol,
            counterfactual,
            protocol.counterfactual_arm,
        )
    )
    observations: list[PairedSensitivityObservation] = []
    for case_id in protocol.planned_case_ids:
        for repetition_index in range(protocol.repetitions_per_arm):
            key = (case_id, repetition_index)
            baseline_run = baseline_index.get(key)
            counterfactual_run = counter_index.get(key)
            if global_mismatch:
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=baseline_run,
                        counterfactual=counterfactual_run,
                        disposition=PairDisposition.undeclared_arm_difference,
                        reason="unplanned-arm-identity-difference",
                    )
                )
                continue
            baseline_binding_mismatch = baseline_run is not None and not (
                _record_matches_planned_arm(
                    protocol,
                    baseline_run,
                    protocol.baseline_arm,
                )
            )
            counterfactual_binding_mismatch = counterfactual_run is not None and not (
                _record_matches_planned_arm(
                    protocol,
                    counterfactual_run,
                    protocol.counterfactual_arm,
                )
            )
            if baseline_binding_mismatch or counterfactual_binding_mismatch:
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=baseline_run,
                        counterfactual=counterfactual_run,
                        disposition=PairDisposition.identity_mismatch,
                        reason="record-arm-binding-mismatch",
                    )
                )
                continue
            if baseline_run is None and counterfactual_run is None:
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=None,
                        counterfactual=None,
                        disposition=PairDisposition.missing_both,
                        reason="both-arm-pair-missing",
                    )
                )
                continue
            if baseline_run is None:
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=None,
                        counterfactual=counterfactual_run,
                        disposition=PairDisposition.missing_baseline,
                        reason="baseline-pair-missing",
                    )
                )
                continue
            if counterfactual_run is None:
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=baseline_run,
                        counterfactual=None,
                        disposition=PairDisposition.missing_counterfactual,
                        reason="counterfactual-pair-missing",
                    )
                )
                continue
            if not _present_response_identities_match(
                baseline_run,
                counterfactual_run,
            ):
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=baseline_run,
                        counterfactual=counterfactual_run,
                        disposition=PairDisposition.identity_mismatch,
                        reason="paired-record-response-identity-mismatch",
                    )
                )
                continue
            baseline_invalid = _pairing_invalid_record_reason(protocol, baseline_run)
            counterfactual_invalid = _pairing_invalid_record_reason(
                protocol,
                counterfactual_run,
            )
            if baseline_invalid is not None or counterfactual_invalid is not None:
                disposition = (
                    PairDisposition.invalid_both
                    if baseline_invalid is not None and counterfactual_invalid is not None
                    else PairDisposition.invalid_baseline
                    if baseline_invalid is not None
                    else PairDisposition.invalid_counterfactual
                )
                reasons = tuple(
                    reason
                    for reason in (baseline_invalid, counterfactual_invalid)
                    if reason is not None
                )
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=baseline_run,
                        counterfactual=counterfactual_run,
                        disposition=disposition,
                        reason=_reason_code(
                            "-".join(reasons),
                            fallback="invalid-live-record",
                        ),
                    )
                )
                continue
            baseline_excluded = baseline_run.observation_status == "excluded"
            counterfactual_excluded = counterfactual_run.observation_status == "excluded"
            if baseline_excluded or counterfactual_excluded:
                disposition = (
                    PairDisposition.excluded_both
                    if baseline_excluded and counterfactual_excluded
                    else PairDisposition.excluded_baseline
                    if baseline_excluded
                    else PairDisposition.excluded_counterfactual
                )
                baseline_exclusion_reason = (
                    baseline_run.exclusion_reason if baseline_excluded else None
                )
                counterfactual_exclusion_reason = (
                    counterfactual_run.exclusion_reason if counterfactual_excluded else None
                )
                reasons = tuple(
                    value
                    for value in (
                        baseline_exclusion_reason,
                        counterfactual_exclusion_reason,
                    )
                    if value
                )
                summary_reason = (
                    reasons[0]
                    if len(set(reasons)) == 1
                    else "mixed-arm-exclusions"
                    if reasons
                    else "paired-run-excluded"
                )
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=baseline_run,
                        counterfactual=counterfactual_run,
                        disposition=disposition,
                        reason=_reason_code(
                            summary_reason,
                            fallback="paired-run-excluded",
                        ),
                        baseline_exclusion_reason=baseline_exclusion_reason,
                        counterfactual_exclusion_reason=counterfactual_exclusion_reason,
                    )
                )
                continue
            if not _records_are_comparable(
                protocol,
                baseline_run,
                counterfactual_run,
                protocol.baseline_arm,
                protocol.counterfactual_arm,
            ):
                observations.append(
                    _nonincluded_observation(
                        protocol,
                        case_id=case_id,
                        repetition_index=repetition_index,
                        baseline=baseline_run,
                        counterfactual=counterfactual_run,
                        disposition=PairDisposition.identity_mismatch,
                        reason="paired-record-identity-mismatch",
                    )
                )
                continue
            cluster_id = _paired_cluster_id(
                protocol,
                baseline_run,
                counterfactual_run,
            )
            endpoint_value: Literal[0, 1] = derive_expected_decision_response(
                baseline_recommendation=baseline_run.recommendation,
                baseline_outcome=baseline_run.outcome,
                counterfactual_recommendation=counterfactual_run.recommendation,
                counterfactual_outcome=counterfactual_run.outcome,
                baseline_expected_recommendation=(protocol.baseline_arm.expected_recommendation),
                baseline_expected_outcome=protocol.baseline_arm.expected_outcome,
                counterfactual_expected_recommendation=(
                    protocol.counterfactual_arm.expected_recommendation
                ),
                counterfactual_expected_outcome=(protocol.counterfactual_arm.expected_outcome),
            )
            observations.append(
                PairedSensitivityObservation(
                    case_id=case_id,
                    repetition_index=repetition_index,
                    cluster_id=cluster_id,
                    disposition=PairDisposition.included,
                    baseline_recommendation=baseline_run.recommendation,
                    baseline_outcome=baseline_run.outcome,
                    counterfactual_recommendation=counterfactual_run.recommendation,
                    counterfactual_outcome=counterfactual_run.outcome,
                    baseline_expected_recommendation=(
                        protocol.baseline_arm.expected_recommendation
                    ),
                    baseline_expected_outcome=protocol.baseline_arm.expected_outcome,
                    counterfactual_expected_recommendation=(
                        protocol.counterfactual_arm.expected_recommendation
                    ),
                    counterfactual_expected_outcome=(protocol.counterfactual_arm.expected_outcome),
                    baseline_run_id=_source_artifact_identifier(
                        baseline_run.run_id,
                        namespace="run",
                    ),
                    baseline_run_digest=sha256_hexdigest(baseline_run.model_dump(mode="json")),
                    counterfactual_run_id=_source_artifact_identifier(
                        counterfactual_run.run_id,
                        namespace="run",
                    ),
                    counterfactual_run_digest=sha256_hexdigest(
                        counterfactual_run.model_dump(mode="json")
                    ),
                    endpoint_value=endpoint_value,
                )
            )
    return tuple(observations)


def build_paired_runset_dependencies(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> tuple[RunSetArtifactDependency, RunSetArtifactDependency]:
    """Bind analysis to the exact persisted arm RunSets and design commitment."""
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    baseline = RunSet.model_validate(baseline.model_dump(mode="json"))
    counterfactual = RunSet.model_validate(counterfactual.model_dump(mode="json"))
    planned_cells = {
        (case_id, repetition_index)
        for case_id in protocol.planned_case_ids
        for repetition_index in range(protocol.repetitions_per_arm)
    }
    dependencies: list[RunSetArtifactDependency] = []
    for arm_id, runset, binding in (
        ("baseline_evidence", baseline, protocol.baseline_arm),
        ("counterfactual_evidence", counterfactual, protocol.counterfactual_arm),
    ):
        if not _runset_matches_binding(protocol, runset, binding):
            raise ValueError(f"{arm_id} RunSet does not match the protocol binding")
        if runset.protocol_id is None or runset.protocol_digest is None:
            raise ValueError(f"{arm_id} RunSet lacks its operational protocol binding")
        design_digest = getattr(
            runset,
            "evidence_sensitivity_design_digest",
            None,
        )
        if design_digest != protocol.design_commitment_digest:
            raise ValueError(f"{arm_id} RunSet lacks the exact pre-execution design commitment")
        if any(run.repetition_index is None for run in runset.runs):
            raise ValueError(
                f"{arm_id} RunSet contains a record without paired repetition identity"
            )
        indexed_runs, duplicate_cells, extra_cells = _index_runs(protocol, runset)
        if duplicate_cells or extra_cells:
            raise ValueError(
                f"{arm_id} RunSet contains duplicate or unplanned case/repetition cells"
            )
        if runset.completion_status == "complete" and set(indexed_runs) != planned_cells:
            raise ValueError(
                f"complete {arm_id} RunSet must exactly cover the frozen planned cell manifest"
            )
        dependencies.append(
            RunSetArtifactDependency(
                arm_id=cast(
                    Literal["baseline_evidence", "counterfactual_evidence"],
                    arm_id,
                ),
                runset_id=_source_artifact_identifier(
                    runset.runset_id,
                    namespace="runset",
                ),
                runset_digest=sha256_hexdigest(runset.model_dump(mode="json")),
                execution_configuration_digest=binding.configuration_digest,
                operational_protocol_id=_source_artifact_identifier(
                    runset.protocol_id,
                    namespace="protocol",
                ),
                operational_protocol_digest=runset.protocol_digest,
                evidence_sensitivity_design_digest=design_digest,
                completion_status=runset.completion_status,
                stop_reasons=tuple(
                    sorted(
                        {
                            _source_artifact_identifier(reason, namespace="stop-reason")
                            for reason in runset.stop_reasons
                        }
                    )
                ),
                records=tuple(
                    RunRecordArtifactDependency(
                        case_id=run.case_id,
                        repetition_index=run.repetition_index,
                        run_id=_source_artifact_identifier(
                            run.run_id,
                            namespace="run",
                        ),
                        run_digest=sha256_hexdigest(run.model_dump(mode="json")),
                    )
                    for run in sorted(
                        runset.runs,
                        key=lambda item: (
                            item.case_id,
                            (item.repetition_index if item.repetition_index is not None else -1),
                            item.run_id,
                        ),
                    )
                    if run.repetition_index is not None
                ),
            )
        )
    return dependencies[0], dependencies[1]


def _validate_live_pair_schedule(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: LiveRunConfig,
    counterfactual: LiveRunConfig,
    baseline_snapshot: LiveExecutionSnapshot,
    counterfactual_snapshot: LiveExecutionSnapshot,
) -> None:
    baseline = LiveRunConfig.model_validate(baseline.model_dump(mode="json"))
    counterfactual = LiveRunConfig.model_validate(counterfactual.model_dump(mode="json"))
    if baseline.repetitions != protocol.repetitions_per_arm:
        raise ValueError("baseline repetitions do not match the paired protocol")
    if counterfactual.repetitions != protocol.repetitions_per_arm:
        raise ValueError("counterfactual repetitions do not match the paired protocol")
    baseline_cases = tuple(sorted(item.case_id for item in baseline.cases))
    counterfactual_cases = tuple(sorted(item.case_id for item in counterfactual.cases))
    if baseline_cases != protocol.planned_case_ids or counterfactual_cases != (
        protocol.planned_case_ids
    ):
        raise ValueError("live arm cases do not match the predeclared pair manifest")
    if _controlled_live_config_projection(
        baseline,
        baseline_snapshot,
    ) != _controlled_live_config_projection(
        counterfactual,
        counterfactual_snapshot,
    ):
        raise ValueError(
            "live arm configuration contains an undeclared difference outside "
            "the evidence intervention"
        )


def _validate_operational_protocol_binding(
    protocol: RepeatedEvidenceSensitivityProtocol,
    operational: LiveProtocolRecord,
    baseline: LiveRunConfig,
    counterfactual: LiveRunConfig,
) -> None:
    if operational.cluster_by != protocol.cluster_by:
        raise ValueError("operational cluster_by does not match the repeated protocol")
    if tuple(operational.allowed_exclusion_reasons) != tuple(protocol.allowed_exclusion_reasons):
        raise ValueError("operational exclusion reasons do not match the repeated protocol")
    if Decimal(operational.max_exclusion_rate) != Decimal(protocol.design.maximum_exclusion_rate):
        raise ValueError("operational maximum exclusion rate does not match the repeated protocol")
    expected_clusters = {item.case_id: item.cluster_id for item in protocol.case_cluster_bindings}
    for arm_name, config in (("baseline", baseline), ("counterfactual", counterfactual)):
        observed_clusters = {
            item.case_id: (
                item.source_group_id
                if operational.cluster_by == "source_group_id"
                else item.case_id
            )
            for item in config.cases
        }
        if observed_clusters != expected_clusters:
            raise ValueError(
                f"{arm_name} live source-group mapping does not match the repeated protocol"
            )


def _index_runs(
    protocol: RepeatedEvidenceSensitivityProtocol,
    runset: RunSet,
) -> tuple[
    dict[tuple[str, int], AgentRunRecord],
    frozenset[tuple[str, int]],
    frozenset[tuple[str, int]],
]:
    expected = {
        (case_id, repetition)
        for case_id in protocol.planned_case_ids
        for repetition in range(protocol.repetitions_per_arm)
    }
    index: dict[tuple[str, int], AgentRunRecord] = {}
    duplicates: set[tuple[str, int]] = set()
    extra: set[tuple[str, int]] = set()
    for run in runset.runs:
        repetition = run.repetition_index
        if (
            repetition is None
            and protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
        ):
            repetition = 0
        if repetition is None:
            extra.add((run.case_id, -1))
            continue
        key = (run.case_id, repetition)
        if key not in expected:
            extra.add(key)
            continue
        if key in index:
            duplicates.add(key)
            continue
        index[key] = run
    return index, frozenset(duplicates), frozenset(extra)


def _runset_matches_binding(
    protocol: RepeatedEvidenceSensitivityProtocol,
    runset: RunSet,
    binding: SensitivityArmBinding,
) -> bool:
    expected_mode = (
        ExecutionMode.live
        if protocol.execution_mode is SensitivityExecutionMode.stochastic_live
        else ExecutionMode.fixture
    )
    return (
        runset.execution_mode is expected_mode
        and runset.fixture_manifest_digest == binding.configuration_digest
        and (
            protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
            or getattr(runset, "evidence_sensitivity_design_digest", None)
            == protocol.design_commitment_digest
        )
    )


def _records_are_comparable(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: AgentRunRecord,
    counterfactual: AgentRunRecord,
    baseline_binding: SensitivityArmBinding,
    counterfactual_binding: SensitivityArmBinding,
) -> bool:
    if (
        baseline.case_id,
        baseline.repetition_index,
        baseline.cluster_id,
        baseline.source_group_id,
    ) != (
        counterfactual.case_id,
        counterfactual.repetition_index,
        counterfactual.cluster_id,
        counterfactual.source_group_id,
    ):
        return False
    if protocol.execution_mode is SensitivityExecutionMode.stochastic_live and (
        baseline.repetition_index is None
        or baseline.cluster_id is None
        or baseline.randomization_block_id is None
        or baseline.schedule_index is None
        or counterfactual.repetition_index is None
        or counterfactual.cluster_id is None
        or counterfactual.randomization_block_id is None
        or counterfactual.schedule_index is None
    ):
        return False
    expected_cluster_id = next(
        item.cluster_id
        for item in protocol.case_cluster_bindings
        if item.case_id == baseline.case_id
    )
    if baseline.cluster_id != expected_cluster_id or counterfactual.cluster_id != (
        expected_cluster_id
    ):
        return False
    # A null protocol binding is a wildcard only for matching an observation to
    # its predeclared arm. It must not permit the two arms to resolve to
    # different provider identities after dispatch, because that would make the
    # observed difference inseparable from a model/version/region confound.
    if any(
        getattr(baseline, field_name) != getattr(counterfactual, field_name)
        for field_name in _POST_RESPONSE_IDENTITY_FIELDS
    ):
        return False
    return _record_matches_binding(
        baseline,
        baseline_binding,
        design_commitment_digest=protocol.design_commitment_digest,
        require_model_provenance=(
            protocol.execution_mode is SensitivityExecutionMode.stochastic_live
        ),
    ) and _record_matches_binding(
        counterfactual,
        counterfactual_binding,
        design_commitment_digest=protocol.design_commitment_digest,
        require_model_provenance=(
            protocol.execution_mode is SensitivityExecutionMode.stochastic_live
        ),
    )


def _record_matches_binding(
    record: AgentRunRecord,
    binding: SensitivityArmBinding,
    *,
    design_commitment_digest: str,
    require_model_provenance: bool,
    allow_missing_response_identity: bool = False,
) -> bool:
    if require_model_provenance and record.provenance.model_identifier != record.model:
        return False
    observed = {
        "configuration_digest": record.provenance.configuration_digest,
        "corpus_digest": record.provenance.retrieval_corpus_digest,
        "provider": record.provider,
        "requested_model": record.model,
        "resolved_model": record.resolved_model,
        "provider_api_version": record.provider_api_version,
        "provider_sdk": record.provider_sdk,
        "provider_region": record.provider_region,
        "adapter_id": record.adapter_id,
        "pipeline_id": record.pipeline_id,
        "tool_schema_digest": record.provenance.tool_schema_digest,
        "policy_bundle_digest": record.provenance.policy_bundle_digest,
        "evidence_sensitivity_design_digest": getattr(
            record.provenance,
            "evidence_sensitivity_design_digest",
            None,
        ),
    }
    post_response_optional = {
        "resolved_model",
        "provider_api_version",
        "provider_sdk",
        "provider_region",
    }
    for field_name, value in observed.items():
        expected = (
            design_commitment_digest
            if field_name == "evidence_sensitivity_design_digest"
            else getattr(binding, field_name)
        )
        if field_name in post_response_optional:
            if expected is None:
                continue
            if allow_missing_response_identity and value is None:
                continue
        if value != expected:
            return False
    return True


def _record_matches_planned_arm(
    protocol: RepeatedEvidenceSensitivityProtocol,
    record: AgentRunRecord,
    binding: SensitivityArmBinding,
) -> bool:
    if not _is_machine_identifier(record.run_id):
        return False
    if protocol.execution_mode is SensitivityExecutionMode.stochastic_live and (
        record.repetition_index is None
        or record.schedule_index is None
        or record.randomization_block_id is None
        or record.cluster_id is None
    ):
        return False
    if record.cluster_id is not None and not _is_machine_identifier(record.cluster_id):
        return False
    expected_cluster_id = next(
        item.cluster_id for item in protocol.case_cluster_bindings if item.case_id == record.case_id
    )
    if record.cluster_id != expected_cluster_id:
        return False
    if protocol.cluster_by == "source_group_id" and record.source_group_id != expected_cluster_id:
        return False
    return _record_matches_binding(
        record,
        binding,
        design_commitment_digest=protocol.design_commitment_digest,
        require_model_provenance=(
            protocol.execution_mode is SensitivityExecutionMode.stochastic_live
        ),
        allow_missing_response_identity=record.observation_status == "excluded",
    )


def _paired_cluster_id(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: AgentRunRecord,
    counterfactual: AgentRunRecord,
) -> str:
    expected_cluster_id = next(
        item.cluster_id
        for item in protocol.case_cluster_bindings
        if item.case_id == baseline.case_id
    )
    # Record/arm comparability is checked before this helper. Returning the
    # frozen identity prevents late data mismatches from becoming exceptions.
    return expected_cluster_id


def _invalid_record_reason(record: AgentRunRecord) -> str | None:
    failed_runtime_policy = any(
        result.state is GateState.fail
        and (result.severity is Severity.blocker or result.policy_id == "runtime.live")
        for result in record.policy_results
    )
    if failed_runtime_policy:
        return "blocking-runtime-policy-failure"
    if not record.recommendation.strip() or not record.outcome.strip():
        return "empty-structured-decision"
    if record.recommendation.casefold() == "error" or record.outcome.casefold() in {
        "error",
        "runtime_error",
    }:
        return "runtime-error-sentinel"
    return None


def _pairing_invalid_record_reason(
    protocol: RepeatedEvidenceSensitivityProtocol,
    record: AgentRunRecord,
) -> str | None:
    if (
        record.observation_status == "excluded"
        and record.exclusion_reason in _LIVE_OPERATIONAL_EXCLUSION_REASONS
    ):
        return (
            None
            if _is_valid_operational_exclusion(protocol, record)
            else "invalid-operational-exclusion-provenance"
        )
    return _invalid_record_reason(record)


def _is_valid_operational_exclusion(
    protocol: RepeatedEvidenceSensitivityProtocol,
    record: AgentRunRecord,
) -> bool:
    reason = record.exclusion_reason
    if (
        record.observation_status != "excluded"
        or reason not in protocol.allowed_exclusion_reasons
        or reason not in _LIVE_OPERATIONAL_EXCLUSION_REASONS
    ):
        return False
    expected_reason_code = (
        ReasonCode.RUNTIME_FAILED if reason == "runtime-failed" else ReasonCode.POLICY_FAILED
    )
    expected_outcome = "runtime_error" if reason == "runtime-failed" else "excluded"
    if record.recommendation != "error" or record.outcome != expected_outcome:
        return False
    if len(record.policy_results) != 1:
        return False
    policy = record.policy_results[0]
    return (
        policy.policy_id == "runtime.live"
        and policy.state is GateState.fail
        and policy.severity is Severity.blocker
        and policy.reason_codes == (expected_reason_code,)
    )


def _present_response_identities_match(
    baseline: AgentRunRecord,
    counterfactual: AgentRunRecord,
) -> bool:
    for field_name in _POST_RESPONSE_IDENTITY_FIELDS:
        baseline_value = getattr(baseline, field_name)
        counterfactual_value = getattr(counterfactual, field_name)
        if (
            baseline_value is not None
            and counterfactual_value is not None
            and baseline_value != counterfactual_value
        ):
            return False
    return True


def _nonincluded_observation(
    protocol: RepeatedEvidenceSensitivityProtocol,
    *,
    case_id: str,
    repetition_index: int,
    baseline: AgentRunRecord | None,
    counterfactual: AgentRunRecord | None,
    disposition: PairDisposition,
    reason: str,
    baseline_exclusion_reason: str | None = None,
    counterfactual_exclusion_reason: str | None = None,
) -> PairedSensitivityObservation:
    expected_cluster_id = next(
        item.cluster_id for item in protocol.case_cluster_bindings if item.case_id == case_id
    )
    return PairedSensitivityObservation(
        case_id=case_id,
        repetition_index=repetition_index,
        # Nonincluded observations use the frozen frame identity. Untrusted
        # observed cluster strings are represented by the typed disposition,
        # never copied into a MachineIdentifier field.
        cluster_id=expected_cluster_id,
        disposition=disposition,
        disposition_reason=_reason_code(reason, fallback="pair-not-included"),
        baseline_exclusion_reason=(
            _reason_code(
                baseline_exclusion_reason,
                fallback="baseline-run-excluded",
            )
            if baseline_exclusion_reason is not None
            else None
        ),
        counterfactual_exclusion_reason=(
            _reason_code(
                counterfactual_exclusion_reason,
                fallback="counterfactual-run-excluded",
            )
            if counterfactual_exclusion_reason is not None
            else None
        ),
        baseline_recommendation=None,
        baseline_outcome=None,
        counterfactual_recommendation=None,
        counterfactual_outcome=None,
        baseline_run_id=(
            _source_artifact_identifier(baseline.run_id, namespace="run")
            if baseline is not None
            else None
        ),
        baseline_run_digest=(
            sha256_hexdigest(baseline.model_dump(mode="json")) if baseline is not None else None
        ),
        counterfactual_run_id=(
            _source_artifact_identifier(counterfactual.run_id, namespace="run")
            if counterfactual is not None
            else None
        ),
        counterfactual_run_digest=(
            sha256_hexdigest(counterfactual.model_dump(mode="json"))
            if counterfactual is not None
            else None
        ),
        endpoint_value=None,
    )


def _controlled_live_config_projection(
    config: LiveRunConfig,
    snapshot: LiveExecutionSnapshot,
) -> dict[str, object]:
    payload = config.model_dump(mode="json")
    payload["variant_id"] = "<arm>"
    payload["retrieval_corpus_digest"] = "<governing-corpus>"
    payload["retrieval_corpus_dir"] = "<governing-corpus-path>"
    payload["knowledge_contract_path"] = "<knowledge-contract-path>"
    payload["bound_knowledge_contract_file_sha256"] = snapshot.knowledge_contract_file_sha256
    payload["bound_adapter_resource_sha256"] = (
        snapshot.adapter_resource.content_sha256 if snapshot.adapter_resource is not None else None
    )
    adapter = payload.get("adapter")
    if isinstance(adapter, dict):
        if config.adapter.adapter_id == "static-jsonl":
            adapter["response_jsonl_path"] = "<arm-rehearsal-resource>"
            adapter["response_jsonl_sha256"] = "<arm-rehearsal-resource>"
            payload["bound_adapter_resource_sha256"] = "<arm-rehearsal-resource>"
        elif config.adapter.adapter_id == "external-script":
            adapter["script_path"] = "<adapter-resource-path>"
            adapter["script_sha256"] = (
                snapshot.adapter_resource.content_sha256
                if (snapshot.adapter_resource is not None)
                else None
            )
    cases = payload.get("cases")
    if isinstance(cases, list):
        payload["cases"] = sorted(
            (
                {
                    **item,
                    "prompt_path": "<arm-prompt>",
                }
                for item in cases
                if isinstance(item, dict)
            ),
            key=lambda item: str(item.get("case_id")),
        )
    return payload


def _sdk_label(config: LiveRunConfig) -> str | None:
    return live_sdk_identifier(config.adapter)


def _reason_code(value: str, *, fallback: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._:/-]+", "-", value.strip()).strip("-")
    safe_fallback = re.sub(r"[^A-Za-z0-9._:/-]+", "-", fallback.strip()).strip("-")
    if normalized and not normalized[0].isalnum():
        normalized = f"reason-{normalized}"
    if safe_fallback and not safe_fallback[0].isalnum():
        safe_fallback = f"reason-{safe_fallback}"
    safe_fallback = safe_fallback or "reason-unavailable"
    return (normalized or safe_fallback)[:256]


def _is_machine_identifier(value: str) -> bool:
    return (
        len(value) <= MACHINE_IDENTIFIER_MAX_CHARS
        and re.fullmatch(MACHINE_IDENTIFIER_PATTERN, value) is not None
    )


def _runset_source_identifiers_are_machine_safe(
    protocol: RepeatedEvidenceSensitivityProtocol,
    runset: RunSet,
) -> bool:
    if not all(_is_machine_identifier(run.run_id) for run in runset.runs):
        return False
    if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture:
        return True
    return (
        _is_machine_identifier(runset.runset_id)
        and runset.protocol_id is not None
        and _is_machine_identifier(runset.protocol_id)
        and all(_is_machine_identifier(reason) for reason in runset.stop_reasons)
    )


def _source_artifact_identifier(value: str, *, namespace: str) -> str:
    unsafe_prefix = f"{namespace}-unsafe-"
    escaped_prefix = f"{namespace}-escaped-"
    value_is_safe = _is_machine_identifier(value)
    if value_is_safe and not value.startswith((unsafe_prefix, escaped_prefix)):
        return value
    transformation = "escaped" if value_is_safe else "unsafe"
    digest = sha256_hexdigest(
        {
            "kind": f"source-identifier-{transformation}",
            "namespace": namespace,
            "value": value,
        }
    )
    return f"{namespace}-{transformation}-{digest}"


__all__ = [
    "assemble_paired_observations",
    "build_paired_runset_dependencies",
    "calculate_case_manifest_digest",
    "calculate_live_arm_binding_facts",
    "load_repeated_sensitivity_protocol",
    "run_repeated_live_study",
    "validate_live_arm_prebinding",
]
