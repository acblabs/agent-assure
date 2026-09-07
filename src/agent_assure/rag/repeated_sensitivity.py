from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal, cast

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    read_file_bounded_from_filesystem_root,
)
from agent_assure.live.adapters import TrustedLiveExecution
from agent_assure.live.config import LiveRunConfig, live_sdk_identifier
from agent_assure.live.runner import (
    LIVE_NEVER_ISSUED_EXCLUSION_REASONS,
    LIVE_RUNSET_STOP_REASONS_ALLOWING_UNISSUED_TAIL,
    LiveAttemptNotification,
    LiveExecutionSnapshot,
    calculate_live_execution_configuration_digest,
    calculate_live_prompt_manifest_digest,
    prepare_live_execution_snapshot,
    run_live_suite,
    validate_live_execution_snapshot,
)
from agent_assure.privacy.persistence import assert_persisted_payload_safe
from agent_assure.rooted_io import RootedDirectoryDescriptor, open_rooted_directory
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_PATTERN,
    ExecutionMode,
    GateState,
    ReasonCode,
    Severity,
)
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.run import (
    AgentRunRecord,
    LiveExecutionAttemptEvent,
    LiveExecutionAttemptJournal,
    RunSet,
)
from agent_assure.schema.sensitivity import EvidenceSensitivityExpectedRelation
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
    load_validated_artifact_payload_with_size,
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
    "provider_serving_fingerprint",
)

_ATTEMPT_JOURNAL_DIRECTORY = ".agent-assure-attempt-journals"
_ATTEMPT_JOURNAL_VERSION = "1.0.0"


class _DurableAttemptJournal:
    """Exclusive, append-only evidence written and synced around every dispatch."""

    def __init__(self, path: Path, header: dict[str, object]) -> None:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent = path.parent.resolve(strict=True)
        except OSError as exc:
            raise OSError("execution attempt registry cannot be prepared") from exc
        if not parent.is_dir() or path.name in {"", ".", ".."}:
            raise ValueError("execution attempt registry path is invalid")
        self._directory: RootedDirectoryDescriptor | None = None
        try:
            self._directory = open_rooted_directory(
                parent,
                ".",
                label="execution attempt registry",
            )
            self._descriptor = self._directory.open_regular_file_exclusive(path.name, mode=0o600)
        except FileExistsError as exc:
            if self._directory is not None:
                self._directory.close()
            raise ValueError(
                "registered execution attempt was already reserved; refusing provider dispatch"
            ) from exc
        except OSError as exc:
            if self._directory is not None:
                self._directory.close()
            raise OSError("execution attempt registry cannot be reserved") from exc
        candidate = self._directory.path / path.name
        self.path = candidate
        self.events: list[LiveExecutionAttemptEvent] = []
        try:
            self._append_payload(header)
            if self._directory.descriptor is not None:
                os.fsync(self._directory.descriptor)
        except BaseException:
            os.close(self._descriptor)
            self._descriptor = -1
            self._directory.close()
            self._directory = None
            raise

    def append(
        self,
        event_type: str,
        *,
        arm_id: str | None = None,
        notification: LiveAttemptNotification | None = None,
    ) -> None:
        self.append_event(
            self.prepare_event(
                event_type,
                arm_id=arm_id,
                notification=notification,
            )
        )

    def prepare_event(
        self,
        event_type: str,
        *,
        arm_id: str | None = None,
        notification: LiveAttemptNotification | None = None,
    ) -> LiveExecutionAttemptEvent:
        payload: dict[str, object] = {
            "event_index": len(self.events),
            "event_type": event_type,
            "occurred_at_utc": _attempt_utc_now(),
            "arm_id": arm_id,
        }
        if notification is not None:
            payload.update(
                {
                    "run_id": notification.request.run_id,
                    "observation_id": notification.request.observation_id,
                    "case_id": notification.request.case_id,
                    "repetition_index": notification.request.repetition_index,
                    "adapter_attempt_index": notification.adapter_attempt_index,
                    "provider_response_id_digest": (
                        sha256_hexdigest(
                            {
                                "purpose": "provider-response-id/v1",
                                "provider_response_id": notification.provider_response_id,
                            }
                        )
                        if notification.provider_response_id is not None
                        else None
                    ),
                    "retryable": notification.retryable,
                    "rate_limited": notification.rate_limited,
                }
            )
        return LiveExecutionAttemptEvent.model_validate(payload)

    def append_event(self, event: LiveExecutionAttemptEvent) -> None:
        if event.event_index != len(self.events):
            raise ValueError("execution attempt journal event index is not append-only")
        self._append_payload(event.model_dump(mode="json", exclude_none=True))
        self.events.append(event)

    def close(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._descriptor = -1
        directory = getattr(self, "_directory", None)
        if directory is not None:
            directory.close()
            self._directory = None

    def _append_payload(self, payload: dict[str, object]) -> None:
        assert_persisted_payload_safe(payload, owner="execution attempt journal event")
        encoded = (
            json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("utf-8")
        if len(encoded) > 16_384:
            raise ValueError("execution attempt journal event exceeds the byte limit")
        view = memoryview(encoded)
        written = 0
        while written < len(view):
            count = os.write(self._descriptor, view[written:])
            if count <= 0:
                raise OSError("execution attempt journal write did not make progress")
            written += count
        os.fsync(self._descriptor)


def execution_attempt_journal_path(
    protocol_path: Path,
    protocol: RepeatedEvidenceSensitivityProtocol,
) -> Path:
    """Return the output-independent registry location for one registered protocol."""

    if protocol.execution_attempt_id is None:
        raise ValueError("stochastic live protocol has no registered execution attempt identity")
    identity = sha256_hexdigest(
        {
            "purpose": "registered-execution-attempt-registry-path/v1",
            "protocol_digest": protocol.protocol_digest,
            "execution_attempt_id": protocol.execution_attempt_id,
        }
    )
    return protocol_path.parent / _ATTEMPT_JOURNAL_DIRECTORY / f"attempt-{identity}.jsonl"


def load_repeated_sensitivity_protocol(
    path: Path,
    *,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
) -> RepeatedEvidenceSensitivityProtocol:
    protocol, _ = load_repeated_sensitivity_protocol_with_size(
        path,
        max_bytes=max_bytes,
    )
    return protocol


def load_repeated_sensitivity_protocol_with_size(
    path: Path,
    *,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
) -> tuple[RepeatedEvidenceSensitivityProtocol, int]:
    if path.suffix.lower() == ".json":
        payload, size = load_validated_artifact_payload_with_size(
            path,
            "repeated-evidence-sensitivity-protocol",
            max_bytes=max_bytes,
            label="repeated evidence-sensitivity protocol",
        )
        return (
            project_validated_artifact_payload(
                payload,
                RepeatedEvidenceSensitivityProtocol,
                kind="repeated-evidence-sensitivity-protocol",
            ),
            size,
        )
    contents = read_file_bounded_from_filesystem_root(
        path,
        max_bytes=max_bytes,
        label="repeated evidence-sensitivity protocol YAML",
    )
    text = contents.data.decode("utf-8")
    payload = safe_load_yaml_text(
        text,
        label="repeated evidence-sensitivity protocol YAML",
    )
    if not isinstance(payload, dict):
        raise TypeError("repeated evidence-sensitivity protocol must be a mapping")
    return RepeatedEvidenceSensitivityProtocol.model_validate(payload), contents.size


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
    registered_protocol_path: Path | None = None,
) -> tuple[RunSet, RunSet]:
    """Execute two pre-bound arms through the existing trusted live adapters."""
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    baseline_config = LiveRunConfig.model_validate(baseline_config.model_dump(mode="json"))
    counterfactual_config = LiveRunConfig.model_validate(
        counterfactual_config.model_dump(mode="json")
    )
    if baseline_config.study_manifest_digest != counterfactual_config.study_manifest_digest:
        raise ValueError(
            "paired live configs must carry the same study manifest commitment, including absence"
        )
    if protocol.execution_mode is not SensitivityExecutionMode.stochastic_live:
        raise ValueError("live study execution requires stochastic_live mode")
    if protocol.execution_attempt_id is None:
        raise ValueError("paired live protocol has no registered execution attempt identity")
    if registered_protocol_path is None:
        raise ValueError("paired live execution requires its exact registered protocol path")
    registered_protocol_path = registered_protocol_path.resolve(strict=True)
    registered_protocol = load_repeated_sensitivity_protocol(registered_protocol_path)
    if registered_protocol != protocol:
        raise ValueError("registered protocol path does not contain the exact execution protocol")
    attempt_journal_path = execution_attempt_journal_path(
        registered_protocol_path,
        protocol,
    )
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
    operational_protocol_digest = sha256_hexdigest(operational_protocol)
    journal = _DurableAttemptJournal(
        attempt_journal_path,
        {
            "event_type": "attempt_reserved",
            "journal_version": _ATTEMPT_JOURNAL_VERSION,
            "execution_attempt_id": protocol.execution_attempt_id,
            "repeated_protocol_digest": protocol.protocol_digest,
            "operational_protocol_digest": operational_protocol_digest,
            "study_manifest_digest": baseline_config.study_manifest_digest,
            "baseline_configuration_digest": protocol.baseline_arm.configuration_digest,
            "counterfactual_configuration_digest": (
                protocol.counterfactual_arm.configuration_digest
            ),
        },
    )
    completed = False
    terminal_written = False
    try:
        journal.append("arm_started", arm_id=protocol.baseline_arm.arm_id)
        baseline = run_live_suite(
            compiled,
            baseline_config,
            protocol=operational_protocol,
            config_dir=baseline_config_dir,
            trust=baseline_trust,
            execution_snapshot=baseline_snapshot,
            attempt_observer=lambda notification: journal.append(
                f"request_{notification.phase}",
                arm_id=protocol.baseline_arm.arm_id,
                notification=notification,
            ),
        )
        journal.append("arm_completed", arm_id=protocol.baseline_arm.arm_id)
        journal.append("arm_started", arm_id=protocol.counterfactual_arm.arm_id)
        counterfactual = run_live_suite(
            compiled,
            counterfactual_config,
            protocol=operational_protocol,
            config_dir=counterfactual_config_dir,
            trust=counterfactual_trust,
            execution_snapshot=counterfactual_snapshot,
            attempt_observer=lambda notification: journal.append(
                f"request_{notification.phase}",
                arm_id=protocol.counterfactual_arm.arm_id,
                notification=notification,
            ),
        )
        journal.append("arm_completed", arm_id=protocol.counterfactual_arm.arm_id)
        terminal_event = journal.prepare_event("attempt_completed")
        embedded = LiveExecutionAttemptJournal.build(
            journal_version=_ATTEMPT_JOURNAL_VERSION,
            execution_attempt_id=protocol.execution_attempt_id,
            repeated_protocol_digest=protocol.protocol_digest,
            operational_protocol_digest=operational_protocol_digest,
            study_manifest_digest=baseline_config.study_manifest_digest,
            baseline_configuration_digest=protocol.baseline_arm.configuration_digest,
            counterfactual_configuration_digest=(protocol.counterfactual_arm.configuration_digest),
            status="complete",
            events=(*journal.events, terminal_event),
        )
        journal.append_event(terminal_event)
        terminal_written = True
        baseline = _bind_attempt_journal(baseline, embedded)
        counterfactual = _bind_attempt_journal(counterfactual, embedded)
        completed = True
        return baseline, counterfactual
    finally:
        if not completed and not terminal_written:
            try:
                journal.append("attempt_abandoned")
            except (OSError, TypeError, ValueError):
                pass
        journal.close()


def _bind_attempt_journal(
    runset: RunSet,
    journal: LiveExecutionAttemptJournal,
) -> RunSet:
    payload = runset.model_dump(mode="json")
    payload.update(
        {
            "execution_attempt_id": journal.execution_attempt_id,
            "execution_attempt_journal_digest": journal.journal_digest,
            "execution_attempt_journal": journal.model_dump(mode="json"),
        }
    )
    return RunSet.model_validate(payload)


def assemble_paired_observations(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> tuple[PairedSensitivityObservation, ...]:
    """Outer-join exact planned cells and preserve every missing/excluded pair."""

    return _assemble_paired_observations(
        protocol,
        baseline,
        counterfactual,
        allow_verified_synthetic_study=False,
    )


def _assemble_paired_observations_for_verified_synthetic_study(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> tuple[PairedSensitivityObservation, ...]:
    """Replay synthetic study evidence after its origin is independently verified."""

    return _assemble_paired_observations(
        protocol,
        baseline,
        counterfactual,
        allow_verified_synthetic_study=True,
    )


def _assemble_paired_observations(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
    *,
    allow_verified_synthetic_study: bool,
) -> tuple[PairedSensitivityObservation, ...]:
    protocol = RepeatedEvidenceSensitivityProtocol.model_validate(protocol.model_dump(mode="json"))
    baseline = RunSet.model_validate(baseline.model_dump(mode="json"))
    counterfactual = RunSet.model_validate(counterfactual.model_dump(mode="json"))
    if allow_verified_synthetic_study:
        _validate_unjournaled_synthetic_study_inputs(protocol, baseline, counterfactual)
    else:
        validate_paired_attempt_journal(protocol, baseline, counterfactual)
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
                expected_relation=protocol.expected_relation,
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
                    expected_relation=(
                        protocol.expected_relation
                        if protocol.expected_relation
                        is EvidenceSensitivityExpectedRelation.decision_invariant
                        else None
                    ),
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
                study_manifest_digest=runset.study_manifest_digest,
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


def validate_paired_attempt_journal(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> None:
    has_journal_metadata = any(
        value is not None
        for runset in (baseline, counterfactual)
        for value in (
            runset.execution_attempt_id,
            runset.execution_attempt_journal_digest,
            runset.execution_attempt_journal,
        )
    )
    if (
        protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
        or protocol.schema_version == "0.6.5"
    ):
        if has_journal_metadata:
            raise ValueError(
                "legacy and deterministic protocols cannot consume execution attempt "
                "journal metadata"
            )
        return
    if protocol.execution_attempt_id is None:
        raise ValueError(
            "current paired live analysis requires a registered execution_attempt_id "
            "and complete attempt journal"
        )
    baseline_journal = baseline.execution_attempt_journal
    counterfactual_journal = counterfactual.execution_attempt_journal
    if baseline_journal is None or counterfactual_journal is None:
        raise ValueError("current paired live analysis requires the complete attempt journal")
    if baseline_journal != counterfactual_journal:
        raise ValueError("paired RunSets do not carry the exact same attempt journal")
    journal = baseline_journal
    if (
        journal.status != "complete"
        or journal.execution_attempt_id != protocol.execution_attempt_id
        or journal.repeated_protocol_digest != protocol.protocol_digest
        or journal.operational_protocol_digest != baseline.protocol_digest
        or journal.operational_protocol_digest != counterfactual.protocol_digest
        or journal.study_manifest_digest != baseline.study_manifest_digest
        or journal.study_manifest_digest != counterfactual.study_manifest_digest
        or journal.baseline_configuration_digest != protocol.baseline_arm.configuration_digest
        or journal.counterfactual_configuration_digest
        != protocol.counterfactual_arm.configuration_digest
        or baseline.fixture_manifest_digest != journal.baseline_configuration_digest
        or counterfactual.fixture_manifest_digest != journal.counterfactual_configuration_digest
    ):
        raise ValueError("execution attempt journal commitments do not match paired inputs")
    observed_arm_lifecycle = tuple(
        (event.event_type, event.arm_id)
        for event in journal.events
        if event.event_type in {"arm_started", "arm_completed"}
    )
    expected_arm_lifecycle = (
        ("arm_started", protocol.baseline_arm.arm_id),
        ("arm_completed", protocol.baseline_arm.arm_id),
        ("arm_started", protocol.counterfactual_arm.arm_id),
        ("arm_completed", protocol.counterfactual_arm.arm_id),
    )
    if observed_arm_lifecycle != expected_arm_lifecycle:
        raise ValueError(
            "execution attempt journal arm lifecycle does not match the registered order"
        )
    observed_schedules: dict[str, tuple[tuple[object, ...], ...]] = {}
    for arm_id, runset in (
        (protocol.baseline_arm.arm_id, baseline),
        (protocol.counterfactual_arm.arm_id, counterfactual),
    ):
        if any(run.schedule_index is None for run in runset.runs):
            raise ValueError("journal-bound live runs require schedule_index")
        ordered_runs = tuple(sorted(runset.runs, key=lambda item: item.schedule_index or 0))
        schedule_indexes = tuple(run.schedule_index for run in ordered_runs)
        if schedule_indexes != tuple(range(len(ordered_runs))):
            raise ValueError(
                "journal-bound live run schedule indexes must be contiguous and zero-based"
            )
        observed_schedules[arm_id] = tuple(
            (
                run.case_id,
                run.repetition_index,
                run.schedule_index,
                run.randomization_block_id,
            )
            for run in ordered_runs
        )
        scheduled_cells = tuple((arm_id, run.case_id, run.repetition_index) for run in ordered_runs)
        issued_cells = tuple(
            (event.arm_id, event.case_id, event.repetition_index)
            for event in journal.events
            if event.event_type == "request_issued" and event.arm_id == arm_id
        )
        first_issued_cells = tuple(dict.fromkeys(issued_cells))
        if first_issued_cells != scheduled_cells[: len(first_issued_cells)]:
            raise ValueError(
                "execution attempt journal first-issue order does not match the RunSet schedule"
            )
        skipped_records = ordered_runs[len(first_issued_cells) :]
        if skipped_records and (
            runset.completion_status != "incomplete"
            or not _runset_has_budget_stop_reason(runset)
            or any(not _is_never_issued_budget_stop_record(run) for run in skipped_records)
        ):
            raise ValueError(
                "journal-unissued schedule tail is not an authentic budget-stop exclusion"
            )
        closed_cells: set[tuple[str | None, str | None, int | None]] = set()
        active_cell: tuple[str | None, str | None, int | None] | None = None
        for cell in issued_cells:
            if cell == active_cell:
                continue
            if cell in closed_cells:
                raise ValueError("execution attempt retries must remain contiguous within a cell")
            if active_cell is not None:
                closed_cells.add(active_cell)
            active_cell = cell
    if (
        observed_schedules[protocol.baseline_arm.arm_id]
        != observed_schedules[protocol.counterfactual_arm.arm_id]
    ):
        raise ValueError("paired journal-bound RunSets must carry the exact same schedule")

    expected_cells = {
        (arm_id, case_id, repetition_index)
        for arm_id in (protocol.baseline_arm.arm_id, protocol.counterfactual_arm.arm_id)
        for case_id in protocol.planned_case_ids
        for repetition_index in range(protocol.repetitions_per_arm)
    }
    run_by_cell: dict[tuple[str, str, int], AgentRunRecord] = {}
    for arm_id, runset in (
        (protocol.baseline_arm.arm_id, baseline),
        (protocol.counterfactual_arm.arm_id, counterfactual),
    ):
        for run in runset.runs:
            if run.repetition_index is None:
                raise ValueError("journal-bound live run is missing repetition_index")
            run_key = (arm_id, run.case_id, run.repetition_index)
            if run_key in run_by_cell:
                raise ValueError("journal-bound live inputs contain a duplicate planned cell")
            run_by_cell[run_key] = run
    if set(run_by_cell) != expected_cells:
        raise ValueError("journal-bound live inputs do not exactly cover planned cells")

    issued: dict[tuple[str, str, int], list[LiveExecutionAttemptEvent]] = {}
    terminal: dict[tuple[str, str, int], list[LiveExecutionAttemptEvent]] = {}
    for event in journal.events:
        if event.event_type not in {
            "request_issued",
            "request_succeeded",
            "request_failed",
        }:
            continue
        assert event.arm_id is not None
        assert event.case_id is not None
        assert event.repetition_index is not None
        event_key = (event.arm_id, event.case_id, event.repetition_index)
        target = issued if event.event_type == "request_issued" else terminal
        target.setdefault(event_key, []).append(event)
    if set(issued) != set(terminal) or not set(issued) <= expected_cells:
        raise ValueError("execution attempt journal omits a terminal or adds an unplanned cell")

    for key, run in run_by_cell.items():
        if key not in issued:
            if not _is_never_issued_budget_stop_record(run):
                raise ValueError("execution attempt journal omits an issued planned cell")
            continue
        cell_issued = issued[key]
        cell_terminal = terminal[key]
        if run.attempt_count is None or run.retry_count is None or run.rate_limit_events is None:
            raise ValueError("journal-bound live run is missing attempt accounting")
        expected_indexes = list(range(1, run.attempt_count + 1))
        issued_indexes = [event.adapter_attempt_index for event in cell_issued]
        terminal_indexes = [event.adapter_attempt_index for event in cell_terminal]
        if issued_indexes != expected_indexes or terminal_indexes != expected_indexes:
            raise ValueError("execution attempt indexes are not contiguous or complete")
        if run.retry_count != run.attempt_count - 1:
            raise ValueError("live run retry_count does not match its attempt journal")
        if run.rate_limit_events != sum(event.rate_limited is True for event in cell_terminal):
            raise ValueError("live run rate-limit count does not match its attempt journal")
        for event in cell_terminal:
            if event.event_type == "request_failed" and (
                event.retryable is None or event.rate_limited is None
            ):
                raise ValueError(
                    "failed request events require explicit retryable and rate-limited accounting"
                )
        if any(event.event_type != "request_failed" for event in cell_terminal[:-1]):
            raise ValueError("every non-final request terminal event must be a failure")
        if any(event.retryable is not True for event in cell_terminal[:-1]):
            raise ValueError("every non-final failed request attempt must be retryable")
        for event in (*cell_issued, *cell_terminal):
            if (
                event.run_id != run.run_id
                or event.observation_id != run.observation_id
                or event.case_id != run.case_id
                or event.repetition_index != run.repetition_index
            ):
                raise ValueError(
                    "execution attempt event identity does not match its RunSet record"
                )
        final = cell_terminal[-1]
        if run.observation_status == "included" and final.event_type != "request_succeeded":
            raise ValueError("included live run requires a final successful request event")
        if final.event_type == "request_succeeded":
            expected_response_digest = (
                sha256_hexdigest(
                    {
                        "purpose": "provider-response-id/v1",
                        "provider_response_id": run.provider_response_id,
                    }
                )
                if run.provider_response_id is not None
                else None
            )
            if final.provider_response_id_digest != expected_response_digest:
                raise ValueError("provider response identity does not match attempt journal")
        elif run.provider_response_id is not None:
            raise ValueError("failed provider attempt cannot yield a persisted response identity")


def _validate_unjournaled_synthetic_study_inputs(
    protocol: RepeatedEvidenceSensitivityProtocol,
    baseline: RunSet,
    counterfactual: RunSet,
) -> None:
    if (
        protocol.schema_version != "0.6.6"
        or protocol.execution_mode is not SensitivityExecutionMode.stochastic_live
        or protocol.execution_attempt_id is not None
    ):
        raise ValueError(
            "synthetic study replay exemption requires an unregistered current live protocol"
        )
    if any(
        value is not None
        for runset in (baseline, counterfactual)
        for value in (
            runset.execution_attempt_id,
            runset.execution_attempt_journal_digest,
            runset.execution_attempt_journal,
        )
    ):
        raise ValueError("synthetic study replay cannot consume execution attempt metadata")


def _runset_has_budget_stop_reason(runset: RunSet) -> bool:
    return bool(set(runset.stop_reasons) & LIVE_RUNSET_STOP_REASONS_ALLOWING_UNISSUED_TAIL)


def _is_never_issued_budget_stop_record(run: AgentRunRecord) -> bool:
    runtime_policy_failures = tuple(
        result
        for result in run.policy_results
        if result.policy_id == "runtime.live"
        and result.state is GateState.fail
        and result.severity is Severity.blocker
        and result.reason_codes == (ReasonCode.POLICY_FAILED,)
    )
    timing_absent = (
        run.started_at_utc is None and run.completed_at_utc is None and run.latency_ms is None
    )
    pre_attempt_timing_complete = bool(
        run.exclusion_reason
        in {
            "cost_budget_exhausted_before_attempt",
            "generated_token_budget_exhausted_before_attempt",
            "token_budget_exhausted_before_attempt",
        }
        and run.started_at_utc is not None
        and run.completed_at_utc is not None
        and run.latency_ms is not None
    )
    return bool(
        run.observation_status == "excluded"
        and run.exclusion_reason in LIVE_NEVER_ISSUED_EXCLUSION_REASONS
        and run.recommendation == "error"
        and run.outcome == "excluded"
        and run.attempt_count in {None, 0}
        and run.retry_count in {None, 0}
        and run.rate_limit_events in {None, 0}
        and run.provider_response_id is None
        and run.provider_finish_reason is None
        and run.provider_serving_fingerprint is None
        and run.provider_created_unix_seconds is None
        and (timing_absent or pre_attempt_timing_complete)
        and run.estimated_cost_usd == "0.000000"
        and run.cost_budget_committed_usd == "0.000000"
        and run.generated_token_budget_committed == 0
        and run.total_token_budget_committed == 0
        and len(runtime_policy_failures) == 1
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
        expected_relation=(
            protocol.expected_relation
            if protocol.expected_relation is EvidenceSensitivityExpectedRelation.decision_invariant
            else None
        ),
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


def _attempt_utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


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
    "execution_attempt_journal_path",
    "load_repeated_sensitivity_protocol",
    "load_repeated_sensitivity_protocol_with_size",
    "run_repeated_live_study",
    "validate_live_arm_prebinding",
    "validate_paired_attempt_journal",
]
