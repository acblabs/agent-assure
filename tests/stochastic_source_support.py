from __future__ import annotations

from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.rag.repeated_sensitivity import build_paired_runset_dependencies
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    LiveExecutionAttemptEvent,
    LiveExecutionAttemptJournal,
    LiveNetworkAuthorityReceipt,
    RunSet,
)
from agent_assure.schema.sensitivity import (
    EvidenceSensitivityExpectedRelation,
    RAGSensitivityAuthorityAssignment,
    RAGSensitivityCaseAuthorityBinding,
)
from agent_assure.schema.stochastic_sensitivity import (
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    RunSetArtifactDependency,
    SensitivityArmBinding,
)


def build_case_authority_bindings(
    case_ids: tuple[str, ...],
    baseline: SensitivityArmBinding,
    counterfactual: SensitivityArmBinding,
    *,
    expected_relation: EvidenceSensitivityExpectedRelation | None = None,
) -> tuple[RAGSensitivityCaseAuthorityBinding, ...]:
    """Build exact two-arm authority fixtures for a frozen case frame."""

    return tuple(
        RAGSensitivityCaseAuthorityBinding(
            case_id=case_id,
            query_family_id="synthetic-query-family",
            expected_relation=expected_relation,
            assignments=tuple(
                sorted(
                    (
                        RAGSensitivityAuthorityAssignment(
                            corpus_digest=baseline.corpus_digest,
                            expected_decision=baseline.expected_recommendation,
                            expected_outcome=baseline.expected_outcome,
                            governing_source_id=f"authority-{case_id}",
                            governing_ref_id=f"ref-{case_id}",
                            governing_content_digest=sha256_hexdigest(
                                f"baseline-authority-{case_id}"
                            ),
                            claim_id=f"claim-{case_id}",
                        ),
                        RAGSensitivityAuthorityAssignment(
                            corpus_digest=counterfactual.corpus_digest,
                            expected_decision=counterfactual.expected_recommendation,
                            expected_outcome=counterfactual.expected_outcome,
                            governing_source_id=f"authority-{case_id}",
                            governing_ref_id=f"ref-{case_id}",
                            governing_content_digest=sha256_hexdigest(
                                f"counterfactual-authority-{case_id}"
                            ),
                            claim_id=f"claim-{case_id}",
                        ),
                    ),
                    key=lambda item: item.corpus_digest,
                )
            ),
        )
        for case_id in case_ids
    )


def materialize_stochastic_sources(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
) -> tuple[
    tuple[PairedSensitivityObservation, ...],
    tuple[RunSetArtifactDependency, RunSetArtifactDependency],
    tuple[RunSet, RunSet],
]:
    """Build exact privacy-safe RunSets and bind observations to their records."""

    sources: list[RunSet] = []
    runs_by_arm: dict[str, dict[tuple[str, int], AgentRunRecord]] = {}
    excluded_by_arm = {
        "baseline_evidence": {"excluded_baseline", "excluded_both"},
        "counterfactual_evidence": {"excluded_counterfactual", "excluded_both"},
    }
    for arm_id, binding, id_field, recommendation_field, outcome_field in (
        (
            "baseline_evidence",
            protocol.baseline_arm,
            "baseline_run_id",
            "baseline_recommendation",
            "baseline_outcome",
        ),
        (
            "counterfactual_evidence",
            protocol.counterfactual_arm,
            "counterfactual_run_id",
            "counterfactual_recommendation",
            "counterfactual_outcome",
        ),
    ):
        runs: list[AgentRunRecord] = []
        for schedule_index, observation in enumerate(observations):
            run_id = getattr(observation, id_field)
            if run_id is None:
                continue
            excluded = observation.disposition.value in excluded_by_arm[arm_id]
            recommendation = getattr(observation, recommendation_field) or "not-observed"
            outcome = getattr(observation, outcome_field) or "not-observed"
            run = AgentRunRecord(
                run_id=run_id,
                case_id=observation.case_id,
                execution_mode=ExecutionMode.live,
                pipeline_id=binding.pipeline_id,
                recommendation=recommendation,
                outcome=outcome,
                input_summary="privacy-safe synthetic request",
                output_summary="privacy-safe synthetic decision",
                observation_status="excluded" if excluded else "included",
                exclusion_reason=(observation.disposition_reason if excluded else None),
                observation_id=f"obs-{arm_id}-{observation.case_id}-r{observation.repetition_index}",
                repetition_index=observation.repetition_index,
                schedule_index=schedule_index,
                randomization_block_id=(
                    f"block-{observation.case_id}-r{observation.repetition_index}"
                ),
                cluster_id=observation.cluster_id,
                source_group_id=(
                    observation.cluster_id if protocol.cluster_by == "source_group_id" else None
                ),
                adapter_id=binding.adapter_id,
                provider=binding.provider,
                model=binding.requested_model,
                resolved_model=(
                    f"{binding.requested_model}-identity-mismatch"
                    if arm_id == "counterfactual_evidence"
                    and observation.disposition.value == "identity_mismatch"
                    else binding.resolved_model
                ),
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
            runs.append(run)
        completion_status: Literal["complete", "incomplete"] = (
            "complete" if len(runs) == protocol.planned_pairs else "incomplete"
        )
        source = RunSet(
            runset_id=f"{arm_id}-runset",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            suite_id="synthetic-stochastic-suite",
            suite_version="1.0.0",
            suite_digest=sha256_hexdigest("synthetic-stochastic-suite"),
            fixture_manifest_digest=binding.configuration_digest,
            execution_mode=ExecutionMode.live,
            protocol_id="synthetic-operational-protocol",
            protocol_digest=sha256_hexdigest("synthetic-operational-protocol"),
            evidence_sensitivity_design_digest=protocol.design_commitment_digest,
            completion_status=completion_status,
            stop_reasons=(
                () if completion_status == "complete" else ("source-records-incomplete",)
            ),
            network_authority_receipt=(
                LiveNetworkAuthorityReceipt(
                    endpoint_host="api.openai.com",
                    api_key_env="OPENAI_API_KEY",
                )
                if binding.adapter_id == "openai-chat-completions"
                else None
            ),
            runs=tuple(runs),
        )
        sources.append(source)
        runs_by_arm[arm_id] = {(run.case_id, run.repetition_index or 0): run for run in source.runs}

    rebound_observations: list[PairedSensitivityObservation] = []
    for observation in observations:
        cell = (observation.case_id, observation.repetition_index)
        baseline = runs_by_arm["baseline_evidence"].get(cell)
        counterfactual = runs_by_arm["counterfactual_evidence"].get(cell)
        payload = observation.model_dump(mode="json")
        payload.update(
            {
                "baseline_run_id": baseline.run_id if baseline is not None else None,
                "baseline_run_digest": (
                    sha256_hexdigest(baseline.model_dump(mode="json"))
                    if baseline is not None
                    else None
                ),
                "counterfactual_run_id": (
                    counterfactual.run_id if counterfactual is not None else None
                ),
                "counterfactual_run_digest": (
                    sha256_hexdigest(counterfactual.model_dump(mode="json"))
                    if counterfactual is not None
                    else None
                ),
            }
        )
        rebound_observations.append(PairedSensitivityObservation.model_validate(payload))

    typed_sources = (sources[0], sources[1])
    dependencies = build_paired_runset_dependencies(protocol, *typed_sources)
    return tuple(rebound_observations), dependencies, typed_sources


def bind_complete_attempt_journal(
    protocol: RepeatedEvidenceSensitivityProtocol,
    sources: tuple[RunSet, RunSet],
) -> tuple[RunSet, RunSet]:
    """Bind a complete synthetic attempt journal to current live test sources."""

    if protocol.execution_attempt_id is None:
        raise ValueError("journal-bound source fixture requires execution_attempt_id")

    def add_attempt_accounting(runset: RunSet) -> RunSet:
        return runset.model_copy(
            update={
                "runs": tuple(
                    run.model_copy(
                        update={
                            "attempt_count": 1,
                            "retry_count": 0,
                            "rate_limit_events": 0,
                            "provider_response_id": f"response-{run.run_id}",
                        }
                    )
                    for run in runset.runs
                )
            }
        )

    baseline = add_attempt_accounting(sources[0])
    counterfactual = add_attempt_accounting(sources[1])
    event_payloads: list[dict[str, object]] = []

    def append_event(event_type: str, **values: object) -> None:
        event_payloads.append(
            {
                "event_index": len(event_payloads),
                "event_type": event_type,
                "occurred_at_utc": "2026-09-05T12:00:00Z",
                **values,
            }
        )

    for arm_id, runset in (
        (protocol.baseline_arm.arm_id, baseline),
        (protocol.counterfactual_arm.arm_id, counterfactual),
    ):
        append_event("arm_started", arm_id=arm_id)
        for run in runset.runs:
            identity = {
                "arm_id": arm_id,
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
        append_event("arm_completed", arm_id=arm_id)
    append_event("attempt_completed")
    journal = LiveExecutionAttemptJournal.build(
        journal_version="1.0.0",
        execution_attempt_id=protocol.execution_attempt_id,
        repeated_protocol_digest=protocol.protocol_digest,
        operational_protocol_digest=baseline.protocol_digest,
        study_manifest_digest=None,
        baseline_configuration_digest=protocol.baseline_arm.configuration_digest,
        counterfactual_configuration_digest=protocol.counterfactual_arm.configuration_digest,
        status="complete",
        events=tuple(
            LiveExecutionAttemptEvent.model_validate(payload) for payload in event_payloads
        ),
    )

    def attach(runset: RunSet) -> RunSet:
        payload = runset.model_dump(mode="json")
        payload.update(
            {
                "execution_attempt_id": journal.execution_attempt_id,
                "execution_attempt_journal_digest": journal.journal_digest,
                "execution_attempt_journal": journal.model_dump(mode="json"),
            }
        )
        return RunSet.model_validate(payload)

    return attach(baseline), attach(counterfactual)
