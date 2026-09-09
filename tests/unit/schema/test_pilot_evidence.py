from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping, Sequence
from typing import Literal
from urllib.parse import quote

import pytest
from pydantic import ValidationError

from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    ExternalPilotIndependenceReviewReceipt,
    PilotArtifactContentScope,
    PilotArtifactDigest,
    PilotArtifactRole,
    PilotAttemptStatus,
    PilotClassification,
    PilotCommandExecution,
    PilotConsentStatus,
    PilotEnvironment,
    PilotEnvironmentComponent,
    PilotEnvironmentControl,
    PilotExecutionContext,
    PilotFrictionCategory,
    PilotFrictionFinding,
    PilotInputBoundary,
    PilotInputIdentityKind,
    PilotInputKind,
    PilotInputManifestEntry,
    PilotInputOrigin,
    PilotPrivacyBoundary,
    PilotPublication,
    PilotPublicationScope,
    PilotRemediationArea,
    PilotRemediationDisposition,
    PilotRemediationReference,
    PilotSubject,
    PilotWorkflowRunReview,
    pilot_workflow_input_arguments,
)


def _controls_campaign_argv(*extra: str) -> tuple[str, ...]:
    return (
        "agent-assure",
        "controls",
        "mutate",
        "--suite",
        "pilot-suite.yaml",
        "--runset",
        "pilot-runset.json",
        "--out",
        "pilot-output",
        "--catalog",
        "core/v1",
        *extra,
    )


def _rag_sensitivity_argv(*extra: str) -> tuple[str, ...]:
    return (
        "agent-assure",
        "rag",
        "sensitivity",
        "--suite",
        "pilot-suite.yaml",
        "--baseline-corpus",
        "baseline-corpus",
        "--counterfactual-corpus",
        "counterfactual-corpus",
        "--knowledge-contract",
        "contract.yaml",
        "--expected-relation",
        "decision_flip",
        "--out",
        "pilot-output",
        *extra,
    )


def test_controls_workflow_input_graph_includes_every_repeatable_waiver() -> None:
    argv = _controls_campaign_argv(
        "--waiver",
        "first-waiver.yaml",
        "--waiver",
        "second-waiver.json",
    )

    assert pilot_workflow_input_arguments(argv, "controls-mutate") == (
        (PilotInputKind.configuration, "suite", "pilot-suite.yaml"),
        (PilotInputKind.data, "runset", "pilot-runset.json"),
        (PilotInputKind.configuration, "waiver", "first-waiver.yaml"),
        (PilotInputKind.configuration, "waiver", "second-waiver.json"),
    )


def _artifact(
    artifact_id: str,
    role: PilotArtifactRole,
    digest_character: str,
    *,
    schema_contract: str | None = None,
) -> PilotArtifactDigest:
    return PilotArtifactDigest(
        artifact_id=artifact_id,
        path=f"{artifact_id}.json",
        role=role,
        sha256=digest_character * 64,
        content_scope=(
            PilotArtifactContentScope.distribution_binary
            if role is PilotArtifactRole.tested_distribution
            else PilotArtifactContentScope.privacy_filtered
        ),
        schema_validated=schema_contract is not None,
        schema_contract=schema_contract,
        producing_command_id=("mutate" if role is PilotArtifactRole.assurance_output else None),
    )


def _artifacts(
    *,
    output_contract: str = "AssuranceMutationCampaign/v1",
) -> tuple[PilotArtifactDigest, ...]:
    return (
        _artifact("artifact-consent", PilotArtifactRole.consent_record, "a"),
        _artifact("artifact-control", PilotArtifactRole.environment_control_evidence, "3"),
        _artifact("artifact-distribution", PilotArtifactRole.tested_distribution, "1"),
        _artifact("artifact-environment", PilotArtifactRole.environment_manifest, "2"),
        _artifact("artifact-execution", PilotArtifactRole.execution_evidence, "6"),
        _artifact("artifact-friction", PilotArtifactRole.friction_assessment, "8"),
        _artifact(
            "artifact-input",
            PilotArtifactRole.input_manifest,
            "5",
            schema_contract="PilotInputManifest/v1",
        ),
        _artifact(
            "artifact-output",
            PilotArtifactRole.assurance_output,
            "7",
            schema_contract=output_contract,
        ),
        _artifact("artifact-remediation", PilotArtifactRole.remediation_record, "9"),
    )


def _values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "pilot_id": "external-controls-pilot-001",
        "workflow_id": "controls-mutate",
        "participant_pseudonym": "participant-001",
        "classification": "external",
        "attempt_status": "attempted",
        "qualifies_as_external_attempt": True,
        "subject": PilotSubject(
            implementation_id="agent-assure",
            implementation_version="0.6.6",
            source_revision="0123456789abcdef",
            distribution_artifact_id="artifact-distribution",
            distribution_digest="1" * 64,
        ),
        "environment": PilotEnvironment(
            environment_id="external-ci-001",
            execution_context=PilotExecutionContext.continuous_integration,
            control=PilotEnvironmentControl.independently_controlled_non_maintainer,
            platform="linux-x86_64",
            components=(
                PilotEnvironmentComponent(component_id="agent-assure", version="0.6.6"),
                PilotEnvironmentComponent(component_id="python", version="3.11.9"),
            ),
            environment_manifest_artifact_id="artifact-environment",
            environment_manifest_digest="2" * 64,
            control_evidence_artifact_id="artifact-control",
        ),
        "inputs": PilotInputBoundary(
            configuration_origin=PilotInputOrigin.non_bundled,
            configuration_digest="4" * 64,
            data_origin=PilotInputOrigin.non_bundled,
            data_digest="b" * 64,
            input_manifest_artifact_id="artifact-input",
            input_manifest_digest="5" * 64,
        ),
        "commands": (
            PilotCommandExecution(
                command_id="mutate",
                sequence=1,
                argv=_controls_campaign_argv(),
                working_directory_id="external-repository-root",
                environment_variable_names=("AGENT_ASSURE_CONFIG", "CI"),
                credential_values_persisted=False,
                raw_output_persisted=False,
                tested_distribution_artifact_id="artifact-distribution",
                tested_distribution_digest="1" * 64,
                implementation_source_revision="0123456789abcdef",
                input_manifest_artifact_id="artifact-input",
                consumed_input_entry_ids=("input-runset", "input-suite"),
                started_at="2026-09-01T14:00:00Z",
                finished_at="2026-09-01T14:02:00Z",
                exit_code=1,
                execution_evidence_artifact_id="artifact-execution",
                execution_evidence_digest="6" * 64,
            ),
        ),
        "artifacts": tuple(
            item for item in _artifacts() if item.role is not PilotArtifactRole.assurance_output
        ),
        "friction_assessment": "friction_observed",
        "friction_assessment_artifact_id": "artifact-friction",
        "friction_findings": (
            PilotFrictionFinding(
                friction_id="doctor-missing-ci-hint",
                category=PilotFrictionCategory.diagnostics,
                summary="The diagnostic did not identify the missing CI environment setting.",
                evidence_artifact_ids=("artifact-friction",),
                remediation_ids=("doctor-ci-hint",),
            ),
        ),
        "remediations": (
            PilotRemediationReference(
                remediation_id="doctor-ci-hint",
                areas=(PilotRemediationArea.diagnostics,),
                disposition=PilotRemediationDisposition.applied,
                remediation_artifact_id="artifact-remediation",
                remediation_digest="9" * 64,
            ),
        ),
        "publication": PilotPublication(
            consent_status=PilotConsentStatus.granted,
            publication_scope=PilotPublicationScope.privacy_filtered_record,
            consent_artifact_id="artifact-consent",
            consent_digest="a" * 64,
            published_artifact_ids=tuple(
                item.artifact_id
                for item in _artifacts()
                if item.role is not PilotArtifactRole.assurance_output
            ),
        ),
        "privacy": PilotPrivacyBoundary(
            raw_inputs_persisted=False,
            raw_outputs_persisted=False,
            credential_values_persisted=False,
            participant_direct_identifiers_persisted=False,
            persisted_content="digests_and_privacy_filtered_metadata_only",
        ),
        "recorded_at": "2026-09-01T14:05:00Z",
        "limitations": (
            "This record describes one pre-candidate adoption exercise and no release gate.",
        ),
        "evidence_phase": "pre_candidate",
        "evidence_use": "learning_and_remediation_only",
        "clean_reproduction_gate_eligible": False,
        "exact_candidate_gate_eligible": False,
        "ci_integration_gate_eligible": False,
    }
    values.update(overrides)
    return values


def _external_evidence(**overrides: object) -> ExternalPilotEvidence:
    return ExternalPilotEvidence.build(**_values(**overrides))


def test_independent_non_bundled_ci_attempt_is_classified_as_external() -> None:
    evidence = _external_evidence()

    assert evidence.classification is PilotClassification.external
    assert evidence.attempt_status is PilotAttemptStatus.attempted
    assert evidence.qualifies_as_external_attempt is True
    assert evidence.commands[0].argv == _controls_campaign_argv()
    assert evidence.environment.environment_manifest_digest == "2" * 64
    assert evidence.clean_reproduction_gate_eligible is False
    assert evidence.exact_candidate_gate_eligible is False
    assert evidence.ci_integration_gate_eligible is False


def test_pilot_command_rejects_reversed_submicrosecond_times_instead_of_truncating() -> None:
    command = _values()["commands"][0]
    assert isinstance(command, PilotCommandExecution)
    payload = command.model_dump(mode="python")
    payload.update(
        started_at="2026-09-01T14:00:00.0000009Z",
        finished_at="2026-09-01T14:00:00.0000001Z",
    )

    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        PilotCommandExecution.model_validate(payload)


@pytest.mark.parametrize(
    ("workflow_id", "argv"),
    (
        (
            "controls-mutate",
            (
                "/opt/agent-assure/bin/agent-assure.exe",
                *_controls_campaign_argv()[1:],
            ),
        ),
        (
            "rag-sensitivity",
            _rag_sensitivity_argv(),
        ),
        (
            "controls-mutate",
            (
                "python",
                "-m",
                "agent_assure.cli.main",
                *_controls_campaign_argv()[1:],
            ),
        ),
        (
            "rag-sensitivity",
            ("python3", "-m", "agent_assure.cli.main", *_rag_sensitivity_argv()[1:]),
        ),
        (
            "controls-mutate",
            (
                "py",
                "-m",
                "agent_assure.cli.main",
                *_controls_campaign_argv()[1:],
            ),
        ),
    ),
)
def test_external_attempt_requires_a_direct_matching_signature_workflow_invocation(
    workflow_id: str,
    argv: tuple[str, ...],
) -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    command = PilotCommandExecution.model_validate(
        {**original.model_dump(mode="json"), "argv": argv}
    )

    evidence = _external_evidence(workflow_id=workflow_id, commands=(command,))

    assert evidence.qualifies_as_external_attempt is True
    assert evidence.commands[0].argv == argv


@pytest.mark.parametrize(
    ("overrides", "error"),
    (
        ({"tested_distribution_digest": "f" * 64}, "tested distribution"),
        ({"implementation_source_revision": "different-revision"}, "source revision"),
        ({"input_manifest_artifact_id": "different-manifest"}, "exact pilot input manifest"),
        ({"consumed_input_entry_ids": ()}, "bind every consumed input"),
    ),
)
def test_pilot_workflow_command_must_bind_subject_distribution_and_inputs(
    overrides: dict[str, object],
    error: str,
) -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    command = PilotCommandExecution.model_validate(
        {**original.model_dump(mode="json"), **overrides}
    )

    with pytest.raises(ValidationError, match=error):
        _external_evidence(commands=(command,))


@pytest.mark.parametrize(
    ("workflow_id", "argv"),
    (
        (
            "controls-mutate",
            ("agent-assure", "rag", "sensitivity", "run"),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "controls", "mutate", "--suite", "suite.yaml"),
        ),
        (
            "controls-mutate",
            ("python", "-m", "pip", "install", "agent-assure"),
        ),
        (
            "controls-mutate",
            ("wrapper", "agent-assure", "controls", "mutate"),
        ),
        (
            "controls-mutate",
            ("python", "-m", "agent_assure", "controls", "mutate"),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "rag", "sensitivity", "plan"),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "rag", "sensitivity", "finalize"),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "rag", "sensitivity", "analyze"),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "rag", "sensitivity", "run", "--protocol", "protocol.json"),
        ),
        (
            "controls-mutate",
            ("agent-assure", "controls", "mutate"),
        ),
        (
            "controls-mutate",
            ("agent-assure", "controls", "mutate", "--help"),
        ),
        (
            "controls-mutate",
            ("agent-assure", "controls", "mutate", "--version"),
        ),
        (
            "controls-mutate",
            (
                "agent-assure",
                "controls",
                "mutate",
                "--suite",
                "suite.yaml",
                "--runset",
                "runset.json",
                "--out",
                "out",
            ),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "rag", "sensitivity"),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "rag", "sensitivity", "--help"),
        ),
        (
            "rag-sensitivity",
            ("agent-assure", "rag", "sensitivity", "--knowledge-contract", "contract.yaml"),
        ),
        (
            "rag-sensitivity",
            (*_rag_sensitivity_argv(), "--unsupported", "value"),
        ),
        (
            "rag-sensitivity",
            tuple(
                "--SUITE" if argument == "--suite" else argument
                for argument in _rag_sensitivity_argv()
            ),
        ),
        (
            "controls-mutate",
            _controls_campaign_argv("--full-report", "--fail-fast"),
        ),
        (
            "controls-mutate",
            _controls_campaign_argv("--seed", "not-an-integer"),
        ),
    ),
)
def test_external_attempt_rejects_missing_or_mismatched_workflow_invocation(
    workflow_id: str,
    argv: tuple[str, ...],
) -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    command = PilotCommandExecution.model_validate(
        {**original.model_dump(mode="json"), "argv": argv}
    )

    with pytest.raises(ValidationError, match="direct Agent Assure invocation"):
        _external_evidence(workflow_id=workflow_id, commands=(command,))


def test_external_attempt_allows_setup_commands_alongside_matching_workflow() -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    setup = PilotCommandExecution.model_validate(
        {
            **original.model_dump(mode="json"),
            "command_id": "setup",
            "sequence": 1,
            "argv": ("python", "-m", "pip", "install", "agent-assure"),
        }
    )
    workflow = PilotCommandExecution.model_validate(
        {
            **original.model_dump(mode="json"),
            "command_id": "workflow",
            "sequence": 2,
        }
    )

    evidence = _external_evidence(commands=(setup, workflow))

    assert evidence.qualifies_as_external_attempt is True
    assert tuple(command.command_id for command in evidence.commands) == ("setup", "workflow")


def test_pilot_workflow_id_is_closed_to_the_two_signature_workflows() -> None:
    with pytest.raises(ValidationError, match="workflow_id"):
        _external_evidence(workflow_id="unrelated-workflow")


@pytest.mark.parametrize("classification", ("internal_dogfood", "synthetic"))
def test_internal_and_synthetic_activity_cannot_claim_external_attempt(
    classification: str,
) -> None:
    environment = _values()["environment"]
    assert isinstance(environment, PilotEnvironment)
    environment_payload = environment.model_dump(mode="json")
    environment_payload["control"] = {
        "internal_dogfood": "maintainer_controlled",
        "synthetic": "synthetic_harness",
    }[classification]
    classified_environment = PilotEnvironment.model_validate(environment_payload)

    activity = _external_evidence(
        classification=classification,
        environment=classified_environment,
        qualifies_as_external_attempt=False,
    )

    assert activity.classification.value == classification
    assert activity.qualifies_as_external_attempt is False
    with pytest.raises(ValidationError, match="qualifies_as_external_attempt"):
        _external_evidence(
            classification=classification,
            environment=classified_environment,
        )


def test_external_attempt_rejects_non_independent_or_bundled_evidence() -> None:
    environment = _values()["environment"]
    assert isinstance(environment, PilotEnvironment)
    environment_payload = environment.model_dump(mode="json")
    environment_payload["control"] = "maintainer_controlled"
    maintainer_environment = PilotEnvironment.model_validate(environment_payload)

    with pytest.raises(ValidationError, match="independently controlled non-maintainer"):
        _external_evidence(environment=maintainer_environment)

    bundled_inputs = PilotInputBoundary(
        configuration_origin=PilotInputOrigin.bundled,
        configuration_digest="4" * 64,
        data_origin=PilotInputOrigin.absent,
        data_digest=None,
        input_manifest_artifact_id="artifact-input",
        input_manifest_digest="5" * 64,
    )
    with pytest.raises(ValidationError, match="non-bundled configuration or data"):
        _external_evidence(inputs=bundled_inputs)


def test_mixed_bundled_non_bundled_boundary_qualifies_but_is_aggregate_only() -> None:
    mixed_inputs = PilotInputBoundary(
        configuration_origin=PilotInputOrigin.mixed_bundled_non_bundled,
        configuration_digest="4" * 64,
        data_origin=PilotInputOrigin.bundled,
        data_digest="b" * 64,
        input_manifest_artifact_id="artifact-input",
        input_manifest_digest="5" * 64,
    )

    evidence = _external_evidence(inputs=mixed_inputs)

    assert evidence.inputs.has_non_bundled_source is True
    with pytest.raises(ValidationError, match="one concrete, non-absent origin"):
        PilotInputManifestEntry(
            entry_id="input-suite",
            input_kind=PilotInputKind.configuration,
            origin=PilotInputOrigin.mixed_bundled_non_bundled,
            option_name="suite",
            option_value="pilot-suite.yaml",
            content_sha256="1" * 64,
            semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
            semantic_identity_digest="2" * 64,
        )


def test_input_manifest_entry_hashes_exact_immutable_execution_bytes() -> None:
    content = b"suite_id: pilot-suite\n"

    entry = PilotInputManifestEntry.from_content_bytes(
        content=content,
        entry_id="input-suite",
        input_kind=PilotInputKind.configuration,
        origin=PilotInputOrigin.non_bundled,
        option_name="suite",
        option_value="pilot-suite.yaml",
        semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
        semantic_identity_digest="2" * 64,
    )

    assert entry.content_sha256 == hashlib.sha256(content).hexdigest()
    with pytest.raises(TypeError, match="immutable bytes"):
        PilotInputManifestEntry.from_content_bytes(
            content=bytearray(content),  # type: ignore[arg-type]
            entry_id="input-suite",
            input_kind=PilotInputKind.configuration,
            origin=PilotInputOrigin.non_bundled,
            option_name="suite",
            option_value="pilot-suite.yaml",
            semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
            semantic_identity_digest="2" * 64,
        )


def test_distribution_binary_content_scope_is_role_specific() -> None:
    with pytest.raises(ValidationError, match="require distribution_binary"):
        PilotArtifactDigest(
            artifact_id="distribution",
            path="agent_assure-0.6.6-py3-none-any.whl",
            role=PilotArtifactRole.tested_distribution,
            sha256="1" * 64,
            content_scope=PilotArtifactContentScope.metadata_only,
            schema_validated=False,
            schema_contract=None,
        )
    with pytest.raises(ValidationError, match="only for tested distributions"):
        PilotArtifactDigest(
            artifact_id="environment",
            path="environment.json",
            role=PilotArtifactRole.environment_manifest,
            sha256="2" * 64,
            content_scope=PilotArtifactContentScope.distribution_binary,
            schema_validated=False,
            schema_contract=None,
        )


def test_completed_pilot_requires_schema_valid_assurance_output() -> None:
    completed = _external_evidence(
        attempt_status="completed",
        artifacts=_artifacts(),
    )

    assert completed.attempt_status is PilotAttemptStatus.completed
    unvalidated_output = _artifact(
        "artifact-output",
        PilotArtifactRole.assurance_output,
        "7",
    )
    without_valid_output = tuple(
        unvalidated_output if item.role is PilotArtifactRole.assurance_output else item
        for item in _artifacts()
    )
    with pytest.raises(ValidationError, match="schema-valid assurance output"):
        _external_evidence(attempt_status="completed", artifacts=without_valid_output)


@pytest.mark.parametrize(
    ("workflow_id", "argv", "output_contract"),
    (
        (
            "controls-mutate",
            _controls_campaign_argv(),
            "AssuranceMutationCampaign/v1",
        ),
        (
            "controls-mutate",
            (
                "agent-assure",
                "controls",
                "mutate",
                "--suite",
                "pilot-suite.yaml",
                "--runset",
                "pilot-runset.json",
                "--out",
                "pilot-output",
                "--operator",
                "decision-output-override",
            ),
            "AssuranceMutationResult/v1",
        ),
        (
            "rag-sensitivity",
            _rag_sensitivity_argv(),
            "RAGSensitivityReport/v1",
        ),
    ),
)
def test_completed_pilot_binds_output_contract_to_exact_executed_workflow(
    workflow_id: str,
    argv: tuple[str, ...],
    output_contract: str,
) -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    command = PilotCommandExecution.model_validate(
        {**original.model_dump(mode="json"), "argv": argv}
    )

    completed = _external_evidence(
        workflow_id=workflow_id,
        attempt_status="completed",
        commands=(command,),
        artifacts=_artifacts(output_contract=output_contract),
    )

    assert completed.attempt_status is PilotAttemptStatus.completed


@pytest.mark.parametrize(
    ("workflow_id", "argv", "output_contract"),
    (
        ("controls-mutate", _controls_campaign_argv(), "AssuranceArtifact/v1"),
        ("controls-mutate", _controls_campaign_argv(), "RAGSensitivityReport/v1"),
        ("rag-sensitivity", _rag_sensitivity_argv(), "AssuranceMutationCampaign/v1"),
    ),
)
def test_completed_pilot_rejects_arbitrary_or_cross_workflow_output_contracts(
    workflow_id: str,
    argv: tuple[str, ...],
    output_contract: str,
) -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    command = PilotCommandExecution.model_validate(
        {**original.model_dump(mode="json"), "argv": argv}
    )

    with pytest.raises(ValidationError, match="exact executed workflow contract"):
        _external_evidence(
            workflow_id=workflow_id,
            attempt_status="completed",
            commands=(command,),
            artifacts=_artifacts(output_contract=output_contract),
        )


def test_not_attempted_external_readiness_is_not_external_attempt_evidence() -> None:
    artifacts = tuple(
        item
        for item in _artifacts()
        if item.role
        not in {
            PilotArtifactRole.execution_evidence,
            PilotArtifactRole.assurance_output,
            PilotArtifactRole.friction_assessment,
            PilotArtifactRole.remediation_record,
        }
    )
    evidence = _external_evidence(
        attempt_status="not_attempted",
        qualifies_as_external_attempt=False,
        commands=(),
        artifacts=artifacts,
        friction_assessment="not_assessed",
        friction_assessment_artifact_id=None,
        friction_findings=(),
        remediations=(),
        publication=PilotPublication(
            consent_status=PilotConsentStatus.not_requested,
            publication_scope=PilotPublicationScope.private_record,
            consent_artifact_id=None,
            consent_digest=None,
            published_artifact_ids=(),
        ),
    )

    assert evidence.attempt_status is PilotAttemptStatus.not_attempted
    assert evidence.qualifies_as_external_attempt is False


@pytest.mark.parametrize(
    ("field_name", "forbidden_value"),
    (
        ("evidence_phase", "exact_candidate"),
        ("evidence_use", "release_gate"),
        ("clean_reproduction_gate_eligible", True),
        ("exact_candidate_gate_eligible", True),
        ("ci_integration_gate_eligible", True),
    ),
)
def test_pre_candidate_evidence_cannot_be_presented_as_release_gate_evidence(
    field_name: str,
    forbidden_value: object,
) -> None:
    with pytest.raises(ValidationError):
        _external_evidence(**{field_name: forbidden_value})


def test_pilot_evidence_rejects_digest_tampering() -> None:
    payload = _external_evidence().model_dump(mode="json")
    payload["workflow_id"] = "rag-sensitivity"
    payload["commands"][0]["argv"] = ["agent-assure", "rag", "sensitivity"]

    with pytest.raises(ValidationError, match="pilot_evidence_digest"):
        ExternalPilotEvidence.model_validate(payload)


def test_pilot_evidence_is_privacy_safe_by_construction() -> None:
    evidence = _external_evidence()
    payload = evidence.model_dump(mode="json")
    keys = set(_nested_keys(payload))

    assert {
        "raw_prompt",
        "raw_completion",
        "credential_value",
        "participant_name",
        "participant_email",
        "repository_url",
    }.isdisjoint(keys)
    assert payload["privacy"] == {
        "raw_inputs_persisted": False,
        "raw_outputs_persisted": False,
        "credential_values_persisted": False,
        "participant_direct_identifiers_persisted": False,
        "persisted_content": "digests_and_privacy_filtered_metadata_only",
    }
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ExternalPilotEvidence.build(**_values(raw_completion="sensitive model output"))


def test_pilot_evidence_rejects_sensitive_values_inside_allowed_free_text() -> None:
    with pytest.raises(
        ValidationError,
        match="only privacy-filtered metadata",
    ):
        _external_evidence(
            limitations=("Contact alice@example.com for the raw pilot evidence.",),
        )


def test_pilot_command_rejects_credential_value_options_but_allows_env_indirection() -> None:
    command = _values()["commands"]
    assert isinstance(command, tuple)
    original = command[0]
    assert isinstance(original, PilotCommandExecution)
    payload = original.model_dump(mode="json")
    payload["argv"] = [*original.argv, "--api-key", "benign-looking-value"]

    with pytest.raises(ValidationError, match="credential material"):
        PilotCommandExecution.model_validate(payload)

    payload["argv"] = [*original.argv, "--api-key-env", "PILOT_API_KEY"]
    indirect = PilotCommandExecution.model_validate(payload)
    assert indirect.argv[-2:] == ("--api-key-env", "PILOT_API_KEY")


@pytest.mark.parametrize(
    "argv",
    (
        ("curl", "-u", "pilot-user:pilot-password", "https://example.test"),
        ("curl", "-upilot-user:pilot-password", "https://example.test"),
        ("curl", "--user=pilot-user:pilot-password", "https://example.test"),
        (
            "curl",
            "--header",
            "Authorization: Bearer pilot-token-value",
            "https://example.test",
        ),
        ("curl", "--header", "X-Auth-Token: abc123", "https://example.test"),
        ("curl", "--header", "XAuthToken: x", "https://example.test"),
        ("curl", "--header", "X-Goog-Api-Key: abc123", "https://example.test"),
        ("curl", "--header", "Api-Key: abc123", "https://example.test"),
        (
            "curl",
            "-HAuthorization: Bearer pilot-token-value",
            "https://example.test",
        ),
        ("curl", "https://pilot-user:pilot-password@example.test/resource"),
        ("curl", "//pilot-user:pilot-password@internal/resource"),
        ("curl", "//pilot-user:pilot-password@["),
        ("curl", "///pilot-user:pilot-password@internal/resource"),
        ("curl", r"https:\\pilot-user:pilot-password@internal\resource"),
        ("curl", r"https:/\\pilot-user:pilot-password@internal/resource"),
        (
            "curl",
            "https\uff1a\uff0f\uff0fpilot-user\uff1apilot-password\uff20internal\uff0fresource",
        ),
        (
            "curl",
            "\uff0f\uff0fpilot-user\uff1apilot-password\uff20internal\uff0fresource",
        ),
        ("curl", "https://pilot-user\uff1apilot-password\uff20internal/resource"),
        ("curl", "--url=https://pilot-user:pilot-password@example.test/resource"),
        ("curl", "https://example.test/resource?api_key=pilot-token-value"),
        ("curl", "https://example.test/resource?X-Amz-Signature=pilot-signature"),
        ("curl", "https://example.test/resource#api_key=abc123"),
        ("curl", "https://safe.example/path?subscriptionKey=short"),
        ("curl", "https://safe.example/path;sig=short"),
        ("curl", "https://safe.example/path/token=short"),
        ("agent-assure", "pilot", "callback?token=abc123"),
        ("agent-assure", "pilot", "callback#api_key=abc123"),
        ("agent-assure", "pilot", "callback?x=1;token=abc123"),
        ("agent-assure", "pilot", "callback?%2573%2569%2567=abc123"),
        (
            "agent-assure",
            "pilot",
            "callback?redirect=https%3A%2F%2Fuser%3Apassword%40internal%2F",
        ),
        (
            "agent-assure",
            "pilot",
            "callback?redirect=https%3A%2F%2Finternal%2F%3Ftoken%3Dabc123",
        ),
        ("curl", "--oauth2-bearer", "pilot-token-value", "https://example.test"),
        ("provider-cli", "OPENAI_API_KEY=pilot-token-value"),
        (
            "provider-cli",
            "DATABASE_URL=postgresql://pilot-user:pilot-password@example.test/database",
        ),
        ("provider-cli", "--endpoint=https://example.test?token=pilot-token-value"),
        ("provider-cli", "--aws-secret-access-key", "pilot-token-value"),
        ("provider-cli", "--clientSecret", "short"),
        ("provider-cli", "clientSecret=short"),
        ("provider-cli", "sk-1234567890abcdefghijklmnop"),
        (
            "provider-cli",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwaWxvdCJ9.abcdefghijklmnop",
        ),
    ),
)
def test_pilot_command_rejects_common_argv_credential_encodings(
    argv: tuple[str, ...],
) -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    payload = {**original.model_dump(mode="json"), "argv": argv}

    with pytest.raises(ValidationError, match="credential material"):
        PilotCommandExecution.model_validate(payload)


def test_pilot_root_rechecks_credential_argv_on_preconstructed_command() -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    unsafe = original.model_copy(
        update={"argv": (*original.argv, "--waiver", "callback?token=short")}
    )

    with pytest.raises(ValidationError, match="credential material"):
        _external_evidence(commands=(unsafe,))


@pytest.mark.parametrize(
    "secret_reference",
    (
        "https://safe.example/path?subscriptionKey=short",
        "clientSecret=short",
        "XAuthToken: x",
        r"https:\\user:pw@internal\path",
        r"https:/\\user:pw@internal/path",
        "https\uff1a\uff0f\uff0fuser\uff1apw\uff20internal\uff0fpath",
        "\uff0f\uff0fuser\uff1apw\uff20internal\uff0fpath",
        "https://user\uff1apw\uff20internal/path",
    ),
)
def test_pilot_root_rechecks_compact_credential_names_in_full_evidence(
    secret_reference: str,
) -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    argv = list(original.argv)
    argv[argv.index("--suite") + 1] = secret_reference
    unsafe = original.model_copy(update={"argv": tuple(argv)})

    with pytest.raises(ValidationError, match="credential material"):
        _external_evidence(commands=(unsafe,))


def test_pilot_command_fails_closed_when_nested_uri_scan_budget_is_exhausted() -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)
    nested = "https://internal/path?sig=short"
    for _ in range(4):
        nested = f"https://safe.example/path?redirect={quote(nested, safe='')}"
    payload = {**original.model_dump(mode="json"), "argv": ("agent-assure", nested)}

    with pytest.raises(ValidationError, match="credential material"):
        PilotCommandExecution.model_validate(payload)


def test_pilot_command_allows_non_sensitive_header_and_secret_indirection() -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    original = commands[0]
    assert isinstance(original, PilotCommandExecution)

    safe_header = PilotCommandExecution.model_validate(
        {
            **original.model_dump(mode="json"),
            "argv": ("curl", "-H", "Accept: application/json", "https://example.test"),
        }
    )
    safe_indirection = PilotCommandExecution.model_validate(
        {
            **original.model_dump(mode="json"),
            "argv": ("provider-cli", "--client-secret-env", "PILOT_CLIENT_SECRET"),
        }
    )
    safe_powershell_switch = PilotCommandExecution.model_validate(
        {
            **original.model_dump(mode="json"),
            "argv": ("powershell", "-UseBasicParsing", "-Uri", "https://example.test"),
        }
    )

    assert safe_header.argv[2] == "Accept: application/json"
    assert safe_indirection.argv[-1] == "PILOT_CLIENT_SECRET"
    assert safe_powershell_switch.argv[1:3] == ("-UseBasicParsing", "-Uri")


def test_pilot_evidence_requires_canonical_artifact_ordering() -> None:
    reversed_artifacts = tuple(reversed(_artifacts()))

    with pytest.raises(ValidationError, match="canonical artifact-ID ordering"):
        _external_evidence(artifacts=reversed_artifacts)


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "../artifact.json",
        "nested/artifact.json",
        r"nested\artifact.json",
        "/artifact.json",
        "C:/artifact.json",
        "CON.json",
    ),
)
def test_pilot_artifact_paths_are_canonical_portable_bundle_children(
    unsafe_path: str,
) -> None:
    payload = _artifacts()[0].model_dump(mode="json")
    payload["path"] = unsafe_path

    with pytest.raises(ValidationError, match="bundle-root child|rooted file path"):
        PilotArtifactDigest.model_validate(payload)


def test_pilot_artifact_paths_are_unique_under_portable_case_matching() -> None:
    artifacts = list(_values()["artifacts"])
    assert all(isinstance(item, PilotArtifactDigest) for item in artifacts)
    first_payload = artifacts[0].model_dump(mode="json")
    second_payload = artifacts[1].model_dump(mode="json")
    first_payload["path"] = "same-name.json"
    second_payload["path"] = "SAME-NAME.JSON"
    artifacts[0] = PilotArtifactDigest.model_validate(first_payload)
    artifacts[1] = PilotArtifactDigest.model_validate(second_payload)

    with pytest.raises(ValidationError, match="case-insensitive"):
        _external_evidence(artifacts=tuple(artifacts))


@pytest.mark.parametrize(
    "secret_reference",
    (
        "https://example.invalid/path?sig=x",
        "https://example.invalid/#subscriptionKey=short",
        "clientSecret=short",
        "Authorization: short",
    ),
)
@pytest.mark.parametrize("field_name", ("limitations", "platform", "friction_summary"))
def test_pilot_root_scans_every_durable_free_text_field(
    field_name: str,
    secret_reference: str,
) -> None:
    overrides: dict[str, object] = {}
    if field_name == "limitations":
        overrides["limitations"] = (secret_reference,)
    elif field_name == "platform":
        environment = _values()["environment"]
        assert isinstance(environment, PilotEnvironment)
        overrides["environment"] = PilotEnvironment.model_validate(
            {**environment.model_dump(mode="json"), "platform": secret_reference}
        )
    else:
        finding = _values()["friction_findings"]
        assert isinstance(finding, tuple)
        overrides["friction_findings"] = (
            PilotFrictionFinding.model_validate(
                {**finding[0].model_dump(mode="json"), "summary": secret_reference}
            ),
        )

    with pytest.raises(ValidationError, match="privacy-filtered metadata"):
        _external_evidence(**overrides)


def test_completed_output_binds_a_completed_evidence_bearing_command() -> None:
    commands = _values()["commands"]
    assert isinstance(commands, tuple)
    invalid_completion = PilotCommandExecution.model_validate(
        {**commands[0].model_dump(mode="json"), "exit_code": 2}
    )

    with pytest.raises(ValidationError, match="completed evidence-bearing exit code"):
        _external_evidence(
            attempt_status="completed",
            commands=(invalid_completion,),
            artifacts=_artifacts(),
        )


def test_assurance_output_producer_reference_must_resolve() -> None:
    artifacts = list(_artifacts())
    output_index = next(
        index
        for index, artifact in enumerate(artifacts)
        if artifact.role is PilotArtifactRole.assurance_output
    )
    output_payload = artifacts[output_index].model_dump(mode="json")
    output_payload["producing_command_id"] = "unrelated-command"
    artifacts[output_index] = PilotArtifactDigest.model_validate(output_payload)

    with pytest.raises(ValidationError, match="producing command must resolve"):
        _external_evidence(
            attempt_status="completed",
            artifacts=tuple(artifacts),
        )


def _workflow_run(stage: Literal["capture", "finalize"]) -> PilotWorkflowRunReview:
    if stage == "capture":
        inputs = {
            "attest_independent_non_maintainer": "true",
            "consent_to_temporary_actions_storage": "true",
            "participant_pseudonym": "participant-001",
        }
        run_id = "4004"
        head = "a" * 40
        workflow_hash = "d" * 64
    else:
        inputs = {
            "capture_run_attempt": "1",
            "capture_run_id": "4004",
            "friction_assessment": "friction_observed",
            "friction_category": "diagnostics",
            "grant_privacy_filtered_publication": "true",
            "prior_candidate_evidence_digest": "f" * 64,
            "reattest_independent_non_maintainer": "true",
            "remediation_disposition": "applied",
            "remediation_source_revision": "d" * 40,
        }
        run_id = "5005"
        head = "b" * 40
        workflow_hash = "e" * 64
    return PilotWorkflowRunReview.build(
        stage=stage,
        run_url=f"https://github.com/example/agent-assure/actions/runs/{run_id}/attempts/1",
        run_attempt=1,
        run_head_sha=head,
        trusted_workflow_revision="c" * 40,
        execution_source_revision="9" * 40,
        workflow_path=f".github/workflows/external-pilot-{stage}.yml",
        run_head_workflow_sha256=workflow_hash,
        trusted_workflow_sha256=workflow_hash,
        workflow_bytes_match_trusted_revision=True,
        public_inputs=tuple(
            {"name": name, "value": value} for name, value in sorted(inputs.items())
        ),
    )


def _review_receipt(**overrides: object) -> ExternalPilotIndependenceReviewReceipt:
    values: dict[str, object] = {
        "receipt_id": "pilot-review-001",
        "pilot_id": "external-controls-pilot-001",
        "pilot_participant_pseudonym": "participant-001",
        "pilot_evidence_digest": "1" * 64,
        "pilot_evidence_file_sha256": "2" * 64,
        "artifact_manifest_digest": "3" * 64,
        "environment_control_evidence_artifact_id": "artifact-control",
        "environment_control_evidence_sha256": "4" * 64,
        "publication_consent_artifact_id": "artifact-consent",
        "publication_consent_sha256": "5" * 64,
        "pilot_execution_source_revision": "9" * 40,
        "pilot_friction_assessment": "friction_observed",
        "pilot_friction_categories": ("diagnostics",),
        "pilot_remediation_dispositions": ("applied",),
        "pilot_remediation_source_revision": "d" * 40,
        "prior_planned_candidate_evidence_digest": "f" * 64,
        "capture_workflow_run": _workflow_run("capture"),
        "finalize_workflow_run": _workflow_run("finalize"),
        "expected_release_line": "0.6.6",
        "reviewer_pseudonym": "release-reviewer-001",
        "manual_approval_is_trust_root": True,
        "reviewer_independent_of_pilot_execution": True,
        "reviewer_independence_rationale": (
            "The release reviewer did not execute or author the recorded pilot."
        ),
        "environment_control_evidence_reviewed": True,
        "artifact_inventory_reviewed": True,
        "tested_distribution_provenance_reviewed": True,
        "command_input_bindings_reviewed": True,
        "execution_time_input_content_digests_reviewed": True,
        "input_semantic_identities_reviewed": True,
        "complete_bundle_publication_consent_reviewed": True,
        "run_head_shas_reviewed": True,
        "workflow_run_urls_reviewed": True,
        "trusted_workflow_bytes_reviewed": True,
        "execution_source_pins_reviewed": True,
        "public_workflow_inputs_reviewed": True,
        "friction_and_remediation_disposition_reviewed": True,
        "friction_category_and_remediation_bindings_reviewed": True,
        "privacy_boundary_reviewed": True,
        "review_outcome": "approved_for_empirical_checkpoint",
        "reviewed_at": "2026-09-02T10:00:00Z",
    }
    values.update(overrides)
    return ExternalPilotIndependenceReviewReceipt.build(**values)


def test_workflow_run_review_binds_exact_trusted_bytes_and_complete_public_inputs() -> None:
    reviewed = _workflow_run("capture")

    assert reviewed.run_id == "4004"
    assert reviewed.run_attempt == 1
    assert reviewed.repository == "example/agent-assure"
    assert len(reviewed.public_inputs_sha256) == 64

    mismatched = reviewed.model_dump(mode="python")
    mismatched.pop("public_inputs_sha256")
    mismatched["trusted_workflow_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="must match the trusted workflow bytes"):
        PilotWorkflowRunReview.build(**mismatched)

    incomplete = reviewed.model_dump(mode="python")
    incomplete.pop("public_inputs_sha256")
    incomplete["public_inputs"] = incomplete["public_inputs"][:-1]
    with pytest.raises(ValidationError, match="exactly cover the reviewed stage"):
        PilotWorkflowRunReview.build(**incomplete)

    unscoped_url = reviewed.model_dump(mode="python")
    unscoped_url.pop("public_inputs_sha256")
    unscoped_url["run_url"] = "https://github.com/example/agent-assure/actions/runs/4004"
    with pytest.raises(ValidationError, match="attempt-specific"):
        PilotWorkflowRunReview.build(**unscoped_url)

    wrong_attempt = reviewed.model_dump(mode="python")
    wrong_attempt.pop("public_inputs_sha256")
    wrong_attempt["run_attempt"] = 2
    with pytest.raises(ValidationError, match="attempt must match"):
        PilotWorkflowRunReview.build(**wrong_attempt)


def test_review_receipt_rejects_cross_fork_or_misbound_run_inputs() -> None:
    other_fork = _workflow_run("finalize").model_dump(mode="python")
    other_fork.pop("public_inputs_sha256")
    other_fork["run_url"] = "https://github.com/other/agent-assure/actions/runs/5005/attempts/1"
    with pytest.raises(ValidationError, match="same fork"):
        _review_receipt(finalize_workflow_run=PilotWorkflowRunReview.build(**other_fork))

    wrong_capture = _workflow_run("finalize").model_dump(mode="python")
    wrong_capture.pop("public_inputs_sha256")
    wrong_capture["public_inputs"] = tuple(
        {
            "name": candidate["name"],
            "value": "9999" if candidate["name"] == "capture_run_id" else candidate["value"],
        }
        for candidate in wrong_capture["public_inputs"]
    )
    with pytest.raises(ValidationError, match="do not bind the capture run URL"):
        _review_receipt(finalize_workflow_run=PilotWorkflowRunReview.build(**wrong_capture))

    wrong_attempt_input = _workflow_run("finalize").model_dump(mode="python")
    wrong_attempt_input.pop("public_inputs_sha256")
    wrong_attempt_input["public_inputs"] = tuple(
        {
            "name": candidate["name"],
            "value": ("2" if candidate["name"] == "capture_run_attempt" else candidate["value"]),
        }
        for candidate in wrong_attempt_input["public_inputs"]
    )
    with pytest.raises(ValidationError, match="do not bind the capture run attempt"):
        _review_receipt(finalize_workflow_run=PilotWorkflowRunReview.build(**wrong_attempt_input))

    wrong_category = _workflow_run("finalize").model_dump(mode="python")
    wrong_category.pop("public_inputs_sha256")
    wrong_category["public_inputs"] = tuple(
        {
            "name": candidate["name"],
            "value": "runtime" if candidate["name"] == "friction_category" else candidate["value"],
        }
        for candidate in wrong_category["public_inputs"]
    )
    with pytest.raises(ValidationError, match="friction category does not match"):
        _review_receipt(finalize_workflow_run=PilotWorkflowRunReview.build(**wrong_category))

    wrong_source = _workflow_run("finalize").model_dump(mode="python")
    wrong_source.pop("public_inputs_sha256")
    wrong_source["execution_source_revision"] = "8" * 40
    with pytest.raises(ValidationError, match="execution-source pins must match"):
        _review_receipt(finalize_workflow_run=PilotWorkflowRunReview.build(**wrong_source))

    wrong_remediation = _workflow_run("finalize").model_dump(mode="python")
    wrong_remediation.pop("public_inputs_sha256")
    wrong_remediation["public_inputs"] = tuple(
        {
            "name": candidate["name"],
            "value": (
                "e" * 40
                if candidate["name"] == "remediation_source_revision"
                else candidate["value"]
            ),
        }
        for candidate in wrong_remediation["public_inputs"]
    )
    with pytest.raises(ValidationError, match="applied-remediation inputs do not match"):
        _review_receipt(finalize_workflow_run=PilotWorkflowRunReview.build(**wrong_remediation))


def test_pilot_review_receipt_makes_operator_attested_trust_boundary_explicit() -> None:
    receipt = _review_receipt()

    assert receipt.review_method == "human_operator_attestation"
    assert receipt.reviewer_identity_authentication == "out_of_band_not_machine_verified"
    assert receipt.manual_approval_is_trust_root is True
    assert receipt.execution_time_input_content_digests_reviewed is True
    assert receipt.input_semantic_identities_reviewed is True
    assert receipt.complete_bundle_publication_consent_reviewed is True


def test_pilot_review_rejects_submicrosecond_time_instead_of_losing_ordering() -> None:
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        _review_receipt(reviewed_at="2026-09-01T14:04:59.9999999Z")


def test_pilot_review_receipt_rejects_self_review_and_sensitive_rationale() -> None:
    with pytest.raises(ValidationError, match="distinct from the pilot participant"):
        _review_receipt(reviewer_pseudonym="PARTICIPANT-001")
    with pytest.raises(ValidationError, match="privacy-filtered metadata"):
        _review_receipt(reviewer_independence_rationale="https://example.invalid/review?sig=x")


def test_gate_fields_are_hard_constants_in_json_schema() -> None:
    properties = ExternalPilotEvidence.model_json_schema()["properties"]

    assert properties["evidence_phase"]["const"] == "pre_candidate"
    assert properties["evidence_use"]["const"] == "learning_and_remediation_only"
    for field_name in (
        "clean_reproduction_gate_eligible",
        "exact_candidate_gate_eligible",
        "ci_integration_gate_eligible",
    ):
        assert properties[field_name]["const"] is False


def _nested_keys(value: object) -> Iterator[str]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _nested_keys(item)
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            yield from _nested_keys(item)
