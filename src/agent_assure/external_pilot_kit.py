"""Two-stage, privacy-filtered authoring for a fork-operated external CI pilot.

The first stage executes one deterministic signature workflow and persists only
the exact wheel plus privacy-safe metadata.  The second stage runs after the
participant has seen the result, records friction and publication consent, and
builds a closed bundle suitable for the separate human review step.

This module deliberately cannot authenticate repository control, participant
identity, or consent authority.  Those facts remain the review receipt's manual
trust root.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator

from agent_assure import __version__
from agent_assure.artifact_io import git_file_bytes, git_output
from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.cli._publication import bounded_model_json
from agent_assure.cli.waivers import load_waivers
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_CONFIG_TEXT_BYTES,
    load_json_bytes_bounded,
    read_bytes_bounded_from_filesystem_root,
)
from agent_assure.mutation.execution import mutation_waiver_set_digest
from agent_assure.onboarding.controls_mutation import (
    RUNSET_FILENAME,
    SUITE_FILENAME,
    scaffold_controls_mutation,
)
from agent_assure.onboarding.diagnostics import bounded_error
from agent_assure.pilot_bundle import (
    MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
    MAX_PILOT_BUNDLE_FILES,
    MAX_PILOT_BUNDLE_TOTAL_BYTES,
    load_external_pilot_review_inputs,
    validate_external_pilot_artifact_bytes,
)
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.reporting.campaign import MUTATION_CAMPAIGN_FILENAME
from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.campaign import AssuranceMutationCampaign
from agent_assure.schema.common import (
    STRICT_RFC3339_TIMESTAMP_PATTERN,
    DigestHex,
    MachineIdentifier,
)
from agent_assure.schema.mutation import SelfDigestedArtifact
from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    PilotArtifactContentScope,
    PilotArtifactDigest,
    PilotArtifactRole,
    PilotCommandExecution,
    PilotConsentStatus,
    PilotEnvironment,
    PilotEnvironmentComponent,
    PilotEnvironmentControl,
    PilotExecutionContext,
    PilotFrictionAssessmentState,
    PilotFrictionCategory,
    PilotFrictionFinding,
    PilotInputBoundary,
    PilotInputIdentityKind,
    PilotInputKind,
    PilotInputManifest,
    PilotInputManifestEntry,
    PilotInputOrigin,
    PilotPrivacyBoundary,
    PilotPublication,
    PilotPublicationScope,
    PilotRemediationArea,
    PilotRemediationDisposition,
    PilotRemediationReference,
    PilotSubject,
)
from agent_assure.schema.run import RunSet

CAPTURE_FILENAME = "external-pilot-capture.json"
EVIDENCE_FILENAME = "external-pilot-evidence.json"
REVIEW_RECEIPT_FILENAME = "external-pilot-independence-review.json"
ENVIRONMENT_MANIFEST_FILENAME = "environment-manifest.json"
ENVIRONMENT_CONTROL_FILENAME = "environment-control-evidence.json"
INPUT_MANIFEST_FILENAME = "input-manifest.json"
EXECUTION_EVIDENCE_FILENAME = "command-execution-evidence.json"
FRICTION_ASSESSMENT_FILENAME = "friction-assessment.json"
REMEDIATION_RECORD_FILENAME = "remediation-record.json"
CONSENT_RECORD_FILENAME = "publication-consent.json"

_EXPECTED_PARENT_REPOSITORY = "acblabs/agent-assure"
_EXPECTED_MAINTAINER_OWNER = "acblabs"
_FULL_GIT_REVISION = re.compile(r"^[a-f0-9]{40}$")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
_PARTICIPANT_PSEUDONYM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")
_PARTICIPANT_INPUT_PREFIX = "agent-assure-pilot/"
_PARTICIPANT_INPUT_FILENAME = "participant-waiver.yaml"
_PARTICIPANT_RATIONALE_PLACEHOLDER = "replace-with-a-short-benign-participant-rationale"
_PARTICIPANT_RATIONALE_MAX_CHARS = 256
_BENIGN_WAIVER_EXPIRY = date(2099, 12, 31)
_PACKAGE_CODE_SUFFIXES = (".py", ".pyi")
_PILOT_COMMAND_ID = "mutate"
_ZERO_DIGEST = "0" * 64


class _CIIdentityDigests(FrozenStrictModel):
    repository: DigestHex
    owner: DigestHex
    actor: DigestHex
    run: DigestHex


class ExternalPilotCapture(SelfDigestedArtifact):
    """Internal, self-digested handoff between the two participant stages."""

    _digest_field = "capture_digest"

    artifact_kind: Literal["external-pilot-capture"] = "external-pilot-capture"
    schema_version: Literal["0.6.6"] = "0.6.6"
    schema_name: Literal["external-pilot-capture"] = "external-pilot-capture"
    contract_id: Literal["ExternalPilotCapture/v1"] = "ExternalPilotCapture/v1"
    contract_version: Literal["1.0.0"] = "1.0.0"
    capture_digest: DigestHex
    pilot_id: MachineIdentifier
    participant_pseudonym: MachineIdentifier
    opaque_pilot_binding: DigestHex
    temporary_storage_consent_granted: Literal[True]
    participant_repository_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    participant_input_repository_path: str = Field(min_length=1, max_length=255)
    ci_identity_digests: _CIIdentityDigests
    subject: PilotSubject
    environment: PilotEnvironment
    inputs: PilotInputBoundary
    command: PilotCommandExecution
    artifacts: tuple[PilotArtifactDigest, ...] = Field(min_length=5, max_length=6)
    captured_at: str = Field(pattern=STRICT_RFC3339_TIMESTAMP_PATTERN)
    privacy: PilotPrivacyBoundary

    @field_validator("artifacts", mode="before")
    @classmethod
    def _coerce_artifacts(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(value)
        return value

    @field_validator("participant_input_repository_path")
    @classmethod
    def _validate_participant_path(cls, value: str) -> str:
        _validate_participant_repository_path(value)
        return value

    @field_validator("participant_pseudonym")
    @classmethod
    def _validate_pseudonym(cls, value: str) -> str:
        return _validate_participant_pseudonym(value)

    @model_validator(mode="after")
    def _validate_capture(self) -> Self:
        payload = self.model_dump(mode="json", warnings="error")
        if redact_packet_payload(payload) != payload:
            raise ValueError("external pilot capture must contain only privacy-filtered metadata")
        if self.artifacts != tuple(sorted(self.artifacts, key=lambda item: item.artifact_id)):
            raise ValueError("external pilot capture artifacts must use canonical ordering")
        if len({item.artifact_id for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("external pilot capture artifact IDs must be unique")
        if len({item.path.casefold() for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("external pilot capture artifact paths must be unique")
        by_role: dict[PilotArtifactRole, list[PilotArtifactDigest]] = {}
        for artifact in self.artifacts:
            by_role.setdefault(artifact.role, []).append(artifact)
        required_roles = {
            PilotArtifactRole.tested_distribution,
            PilotArtifactRole.environment_manifest,
            PilotArtifactRole.environment_control_evidence,
            PilotArtifactRole.input_manifest,
            PilotArtifactRole.execution_evidence,
        }
        if set(by_role) - (required_roles | {PilotArtifactRole.assurance_output}):
            raise ValueError("external pilot capture contains an unsupported artifact role")
        if any(len(by_role.get(role, ())) != 1 for role in required_roles):
            raise ValueError("external pilot capture requires one artifact for every base role")
        outputs = by_role.get(PilotArtifactRole.assurance_output, [])
        if len(outputs) > 1:
            raise ValueError("external pilot capture permits at most one assurance output")
        if bool(outputs) != (self.command.exit_code in {0, 1}):
            raise ValueError(
                "external pilot capture must persist a campaign output exactly for exit 0 or 1"
            )
        if outputs and (
            outputs[0].schema_contract != "AssuranceMutationCampaign/v1"
            or outputs[0].producing_command_id != self.command.command_id
        ):
            raise ValueError("external pilot capture output does not bind the campaign command")
        if self.subject.distribution_artifact_id not in {
            item.artifact_id for item in by_role[PilotArtifactRole.tested_distribution]
        }:
            raise ValueError("external pilot capture subject does not bind its wheel")
        if self.command.implementation_source_revision != self.subject.source_revision:
            raise ValueError("external pilot capture command source revision mismatch")
        return self


@dataclass(frozen=True, slots=True)
class _CIIdentity:
    raw_repository_id: str
    raw_owner_id: str
    raw_actor_id: str
    raw_run_id: str
    raw_run_attempt: str
    digests: _CIIdentityDigests


def capture_external_pilot(
    *,
    capture_root: Path,
    participant_repository_root: Path,
    participant_input_repository_path: str,
    participant_input_template: Path,
    wheel_path: Path,
    source_revision: str,
    participant_pseudonym: str,
    temporary_storage_consent_granted: bool,
    non_maintainer_control_attested: bool,
    environment: Mapping[str, str] | None = None,
) -> ExternalPilotCapture:
    """Execute and capture one externally controlled CI attempt without raw streams."""

    if temporary_storage_consent_granted is not True:
        raise ValueError("temporary capture storage consent was not granted")
    participant_pseudonym = _validate_participant_pseudonym(participant_pseudonym)
    if not non_maintainer_control_attested:
        raise ValueError("non-maintainer environment control must be explicitly attested")
    if _FULL_GIT_REVISION.fullmatch(source_revision) is None:
        raise ValueError("source revision must be one full lowercase Git commit")
    ci_environment = dict(os.environ if environment is None else environment)
    ci_identity = _validated_external_ci_identity(ci_environment)
    _validate_pseudonym_not_ci_identifier(participant_pseudonym, ci_environment)
    _require_new_directory_target(capture_root, label="external pilot capture")

    participant_path = _validate_participant_repository_path(participant_input_repository_path)
    participant_revision, participant_bytes = _read_committed_participant_input(
        participant_repository_root,
        participant_path,
    )
    template_bytes = read_bytes_bounded_from_filesystem_root(
        participant_input_template,
        max_bytes=MAX_CONFIG_TEXT_BYTES,
        label="external pilot participant input template",
    )
    if participant_bytes == template_bytes:
        raise ValueError("participant input must be personalized before the pilot")

    wheel_bytes = read_bytes_bounded_from_filesystem_root(
        wheel_path,
        max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
        label="external pilot tested wheel",
    )
    expected_wheel_name = f"agent_assure-{__version__}-py3-none-any.whl"
    if wheel_path.name != expected_wheel_name:
        raise ValueError("tested wheel filename does not match the installed Agent Assure version")
    distribution_artifact = _artifact(
        "artifact-distribution",
        expected_wheel_name,
        PilotArtifactRole.tested_distribution,
        wheel_bytes,
        content_scope=PilotArtifactContentScope.distribution_binary,
    )
    validate_external_pilot_artifact_bytes(
        distribution_artifact,
        wheel_bytes,
        implementation_id="agent-assure",
        implementation_version=__version__,
    )
    _validate_running_agent_assure_code_matches_wheel(wheel_bytes)
    opaque_pilot_binding = secrets.token_hex(32)

    capture_root.mkdir(mode=0o700)
    wheel_output = capture_root / expected_wheel_name
    _write_new_bytes(wheel_output, wheel_bytes)

    environment_bytes = _json_bytes(
        _environment_manifest_payload(ci_environment, source_revision=source_revision)
    )
    control_bytes = _json_bytes(
        _environment_control_payload(
            opaque_pilot_binding=opaque_pilot_binding,
            participant_input_repository_path=participant_path,
            source_revision=source_revision,
        )
    )
    _write_new_bytes(capture_root / ENVIRONMENT_MANIFEST_FILENAME, environment_bytes)
    _write_new_bytes(capture_root / ENVIRONMENT_CONTROL_FILENAME, control_bytes)

    with tempfile.TemporaryDirectory(
        prefix="agent-assure-external-pilot-",
        dir=capture_root.parent,
    ) as temporary:
        work_root = Path(temporary)
        scaffold_root = work_root / "scaffold"
        scaffold_controls_mutation(scaffold_root)
        participant_work_path = work_root / _PARTICIPANT_INPUT_FILENAME
        _write_new_bytes(participant_work_path, participant_bytes)
        waivers = load_waivers((participant_work_path,))
        _validate_benign_participant_waiver(
            waivers,
            participant_pseudonym=participant_pseudonym,
        )

        suite_path = scaffold_root / SUITE_FILENAME
        runset_path = scaffold_root / RUNSET_FILENAME
        suite_bytes = read_bytes_bounded_from_filesystem_root(
            suite_path,
            max_bytes=MAX_CONFIG_TEXT_BYTES,
            label="external pilot suite",
        )
        runset_bytes = read_bytes_bounded_from_filesystem_root(
            runset_path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="external pilot RunSet",
        )
        compiled = compile_suite(suite_path)
        runset_payload = load_json_bytes_bounded(
            runset_bytes,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="external pilot RunSet",
        )
        runset = RunSet.model_validate(runset_payload)
        input_manifest = PilotInputManifest.build(
            workflow_id="controls-mutate",
            entries=(
                PilotInputManifestEntry.from_content_bytes(
                    content=suite_bytes,
                    entry_id="input-suite",
                    input_kind=PilotInputKind.configuration,
                    origin=PilotInputOrigin.bundled,
                    option_name="suite",
                    option_value="scaffold/suite.yaml",
                    semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
                    semantic_identity_digest=compiled_suite_digest(compiled),
                ),
                PilotInputManifestEntry.from_content_bytes(
                    content=participant_bytes,
                    entry_id="input-waiver",
                    input_kind=PilotInputKind.configuration,
                    origin=PilotInputOrigin.non_bundled,
                    option_name="waiver",
                    option_value=_PARTICIPANT_INPUT_FILENAME,
                    semantic_identity_kind=PilotInputIdentityKind.waiver_set,
                    semantic_identity_digest=mutation_waiver_set_digest(waivers),
                ),
                PilotInputManifestEntry.from_content_bytes(
                    content=runset_bytes,
                    entry_id="input-runset",
                    input_kind=PilotInputKind.data,
                    origin=PilotInputOrigin.bundled,
                    option_name="runset",
                    option_value="scaffold/runset.json",
                    semantic_identity_kind=PilotInputIdentityKind.run_set,
                    semantic_identity_digest=sha256_hexdigest(
                        runset.model_dump(mode="json", warnings="error")
                    ),
                ),
            ),
        )
        input_manifest_bytes = _json_bytes(input_manifest)
        _write_new_bytes(capture_root / INPUT_MANIFEST_FILENAME, input_manifest_bytes)

        launcher = Path(sys.executable).name
        command_argv = (
            launcher,
            "-m",
            "agent_assure.cli.main",
            "controls",
            "mutate",
            "--suite",
            "scaffold/suite.yaml",
            "--runset",
            "scaffold/runset.json",
            "--catalog",
            "core/v1",
            "--operator",
            "drop-material-evidence-link",
            "--seed",
            "0",
            "--waiver",
            _PARTICIPANT_INPUT_FILENAME,
            "--out",
            "mutation-output",
        )
        command_environment = _signature_command_environment(ci_environment)
        started_at = _utc_now()
        exit_code = _run_signature_command(
            command_argv,
            cwd=work_root,
            environment=command_environment,
        )
        finished_at = _utc_now()

        input_manifest_digest = _sha256(input_manifest_bytes)
        wheel_digest = _sha256(wheel_bytes)
        execution_bytes = _json_bytes(
            {
                "artifact_kind": "external-pilot-command-execution-evidence",
                "contract_id": "ExternalPilotCommandExecutionEvidence/v1",
                "command_id": _PILOT_COMMAND_ID,
                "opaque_pilot_binding": opaque_pilot_binding,
                "implementation_source_revision": source_revision,
                "tested_distribution_sha256": wheel_digest,
                "input_manifest_sha256": input_manifest_digest,
                "started_at": started_at,
                "finished_at": finished_at,
                "exit_code": exit_code,
                "stdout": "discarded_at_capture_boundary",
                "stderr": "discarded_at_capture_boundary",
                "raw_output_persisted": False,
            }
        )
        _write_new_bytes(capture_root / EXECUTION_EVIDENCE_FILENAME, execution_bytes)

        output_bytes: bytes | None = None
        if exit_code in {0, 1}:
            output_path = work_root / "mutation-output" / MUTATION_CAMPAIGN_FILENAME
            output_bytes = read_bytes_bounded_from_filesystem_root(
                output_path,
                max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
                label="external pilot assurance output",
            )
            output_payload = load_json_bytes_bounded(
                output_bytes,
                max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
                label="external pilot assurance output",
            )
            AssuranceMutationCampaign.model_validate(output_payload)
            _write_new_bytes(capture_root / MUTATION_CAMPAIGN_FILENAME, output_bytes)

    artifacts = _capture_artifacts(
        wheel_name=expected_wheel_name,
        wheel_bytes=wheel_bytes,
        environment_bytes=environment_bytes,
        control_bytes=control_bytes,
        input_manifest_bytes=input_manifest_bytes,
        execution_bytes=execution_bytes,
        output_bytes=output_bytes,
    )
    artifact_by_id = {item.artifact_id: item for item in artifacts}
    pilot_id = f"external-controls-{opaque_pilot_binding[:24]}"
    subject = PilotSubject(
        implementation_id="agent-assure",
        implementation_version=__version__,
        source_revision=source_revision,
        distribution_artifact_id="artifact-distribution",
        distribution_digest=artifact_by_id["artifact-distribution"].sha256,
    )
    environment_model = PilotEnvironment(
        environment_id=f"github-actions-{opaque_pilot_binding[:20]}",
        execution_context=PilotExecutionContext.continuous_integration,
        control=PilotEnvironmentControl.independently_controlled_non_maintainer,
        platform=_platform_description(ci_environment),
        components=(
            PilotEnvironmentComponent(component_id="agent-assure", version=__version__),
            PilotEnvironmentComponent(component_id="github-actions", version="github-hosted"),
            PilotEnvironmentComponent(component_id="python", version=platform.python_version()),
        ),
        environment_manifest_artifact_id="artifact-environment",
        environment_manifest_digest=artifact_by_id["artifact-environment"].sha256,
        control_evidence_artifact_id="artifact-control",
    )
    inputs = PilotInputBoundary(
        configuration_origin=PilotInputOrigin.mixed_bundled_non_bundled,
        configuration_digest=input_manifest.configuration_digest,
        data_origin=PilotInputOrigin.bundled,
        data_digest=input_manifest.data_digest,
        input_manifest_artifact_id="artifact-input",
        input_manifest_digest=artifact_by_id["artifact-input"].sha256,
    )
    command = PilotCommandExecution(
        command_id=_PILOT_COMMAND_ID,
        sequence=1,
        argv=command_argv,
        working_directory_id="external-ci-ephemeral-workspace",
        environment_variable_names=tuple(sorted(command_environment)),
        credential_values_persisted=False,
        raw_output_persisted=False,
        tested_distribution_artifact_id="artifact-distribution",
        tested_distribution_digest=artifact_by_id["artifact-distribution"].sha256,
        implementation_source_revision=source_revision,
        input_manifest_artifact_id="artifact-input",
        consumed_input_entry_ids=("input-runset", "input-suite", "input-waiver"),
        started_at=started_at,
        finished_at=finished_at,
        exit_code=exit_code,
        execution_evidence_artifact_id="artifact-execution",
        execution_evidence_digest=artifact_by_id["artifact-execution"].sha256,
    )
    capture = ExternalPilotCapture.build(
        pilot_id=pilot_id,
        participant_pseudonym=participant_pseudonym,
        opaque_pilot_binding=opaque_pilot_binding,
        temporary_storage_consent_granted=True,
        participant_repository_revision=participant_revision,
        participant_input_repository_path=participant_path,
        ci_identity_digests=ci_identity.digests,
        subject=subject,
        environment=environment_model,
        inputs=inputs,
        command=command,
        artifacts=artifacts,
        captured_at=_utc_now(),
        privacy=_privacy_boundary(),
    )
    _write_new_bytes(capture_root / CAPTURE_FILENAME, _json_bytes(capture))
    _verify_capture_directory(capture_root, capture)
    return capture


def finalize_external_pilot_capture(
    *,
    capture_root: Path,
    bundle_root: Path,
    expected_source_revision: str,
    capture_run_id: str,
    capture_run_attempt: str,
    friction_assessment: PilotFrictionAssessmentState | str,
    friction_category: PilotFrictionCategory | str,
    publication_consent_granted: bool,
    non_maintainer_control_attested: bool,
    environment: Mapping[str, str] | None = None,
) -> ExternalPilotEvidence:
    """Add participant-observed friction and consent, then verify a closed bundle."""

    if not publication_consent_granted:
        raise ValueError("publication consent was not granted; no public bundle was written")
    if not non_maintainer_control_attested:
        raise ValueError("non-maintainer environment control must be explicitly re-attested")
    if _FULL_GIT_REVISION.fullmatch(expected_source_revision) is None:
        raise ValueError("expected source revision must be one full lowercase Git commit")
    if _POSITIVE_INTEGER.fullmatch(capture_run_id) is None:
        raise ValueError("capture run ID must be a positive integer")
    if _POSITIVE_INTEGER.fullmatch(capture_run_attempt) is None:
        raise ValueError("capture run attempt must be a positive integer")
    ci_environment = dict(os.environ if environment is None else environment)
    finalization_identity = _validated_external_ci_identity(ci_environment)
    capture = _load_verified_capture(capture_root)
    if capture.subject.source_revision != expected_source_revision:
        raise ValueError("pilot capture does not match the pinned expected source revision")
    _validate_finalization_identity(
        capture,
        finalization_identity,
        capture_run_id=capture_run_id,
        capture_run_attempt=capture_run_attempt,
    )
    _require_new_directory_target(bundle_root, label="external pilot candidate bundle")

    assessment = PilotFrictionAssessmentState(friction_assessment)
    category = PilotFrictionCategory(friction_category)
    if assessment is PilotFrictionAssessmentState.not_assessed:
        raise ValueError("external pilot finalization requires an assessed friction state")
    if (
        assessment is PilotFrictionAssessmentState.no_friction_observed
        and capture.command.exit_code not in {0, 1}
    ):
        raise ValueError("a non-completing pilot command cannot claim no friction")

    bundle_root.mkdir(mode=0o700)
    for artifact in capture.artifacts:
        data = read_bytes_bounded_from_filesystem_root(
            capture_root / artifact.path,
            max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
            label="external pilot captured artifact",
        )
        if _sha256(data) != artifact.sha256:
            raise ValueError("captured artifact digest changed before finalization")
        _write_new_bytes(bundle_root / artifact.path, data)

    finalized_at = _utc_now()
    friction_bytes = _json_bytes(
        {
            "artifact_kind": "external-pilot-friction-assessment",
            "contract_id": "ExternalPilotFrictionAssessment/v1",
            "pilot_id": capture.pilot_id,
            "participant_pseudonym": capture.participant_pseudonym,
            "opaque_pilot_binding": capture.opaque_pilot_binding,
            "assessment": assessment.value,
            "category": category.value if assessment.value == "friction_observed" else None,
            "command_exit_code": capture.command.exit_code,
            "assessment_method": "post_attempt_participant_workflow_dispatch",
            "assessed_at": finalized_at,
        }
    )
    _write_new_bytes(bundle_root / FRICTION_ASSESSMENT_FILENAME, friction_bytes)
    artifacts = list(capture.artifacts)
    artifacts.append(
        _artifact(
            "artifact-friction",
            FRICTION_ASSESSMENT_FILENAME,
            PilotArtifactRole.friction_assessment,
            friction_bytes,
        )
    )

    friction_findings: tuple[PilotFrictionFinding, ...] = ()
    remediations: tuple[PilotRemediationReference, ...] = ()
    if assessment is PilotFrictionAssessmentState.friction_observed:
        remediation_bytes = _json_bytes(
            {
                "artifact_kind": "external-pilot-remediation-record",
                "contract_id": "ExternalPilotRemediationRecord/v1",
                "pilot_id": capture.pilot_id,
                "opaque_pilot_binding": capture.opaque_pilot_binding,
                "friction_category": category.value,
                "area": "onboarding",
                "disposition": "planned",
                "statement": (
                    "Maintainer follow-up is required; this record does not assert that a "
                    "remediation was applied."
                ),
                "recorded_at": finalized_at,
            }
        )
        _write_new_bytes(bundle_root / REMEDIATION_RECORD_FILENAME, remediation_bytes)
        remediation_artifact = _artifact(
            "artifact-remediation",
            REMEDIATION_RECORD_FILENAME,
            PilotArtifactRole.remediation_record,
            remediation_bytes,
        )
        artifacts.append(remediation_artifact)
        friction_findings = (
            PilotFrictionFinding(
                friction_id=f"participant-reported-{category.value.replace('_', '-')}",
                category=category,
                summary=f"Participant reported {category.value.replace('_', ' ')} friction.",
                evidence_artifact_ids=("artifact-friction",),
                remediation_ids=("participant-friction-follow-up",),
            ),
        )
        remediations = (
            PilotRemediationReference(
                remediation_id="participant-friction-follow-up",
                areas=(PilotRemediationArea.onboarding,),
                disposition=PilotRemediationDisposition.planned,
                remediation_artifact_id="artifact-remediation",
                remediation_digest=remediation_artifact.sha256,
            ),
        )

    prospective_artifacts = tuple(
        sorted(
            (
                *artifacts,
                PilotArtifactDigest(
                    artifact_id="artifact-consent",
                    path=CONSENT_RECORD_FILENAME,
                    role=PilotArtifactRole.consent_record,
                    sha256=_ZERO_DIGEST,
                    content_scope=PilotArtifactContentScope.metadata_only,
                    schema_validated=False,
                    schema_contract=None,
                    producing_command_id=None,
                ),
            ),
            key=lambda item: item.artifact_id,
        )
    )
    consent_bytes = _json_bytes(
        {
            "artifact_kind": "external-pilot-publication-consent",
            "contract_id": "ExternalPilotPublicationConsent/v1",
            "participant_pseudonym": capture.participant_pseudonym,
            "opaque_pilot_binding": capture.opaque_pilot_binding,
            "decision": "granted",
            "publication_scope": "privacy_filtered_record",
            "temporary_actions_storage_days": 14,
            "temporary_actions_storage_access": "participant_fork_repository_read_access",
            "cross_stage_correlation": "shared_opaque_pilot_binding",
            "public_fork_correlation": "committed_input_digests_can_match_public_bytes",
            "covered_bundle_files": [
                EVIDENCE_FILENAME,
                REVIEW_RECEIPT_FILENAME,
                *sorted(item.path for item in prospective_artifacts),
            ],
            "covered_artifacts": [
                {
                    "artifact_id": item.artifact_id,
                    "path": item.path,
                    "role": item.role.value,
                }
                for item in prospective_artifacts
            ],
            "statement": (
                "The participant prospectively authorizes publication of the complete "
                "privacy-filtered inventory listed here, its future evidence descriptor, and "
                "its future byte-bound human review receipt. This names the publication scope "
                "before those final bytes exist and does not claim the participant reviewed "
                "them. It also covers up to 14 days of candidate storage in the participant "
                "fork under GitHub repository read-access rules and the shared opaque binding "
                "that can correlate the two stages. The committed-input content and semantic "
                "digests can also be matched to bytes in the participant's public fork. This "
                "is learning evidence, not an endorsement or validation claim."
            ),
            "granted_at": finalized_at,
        }
    )
    _write_new_bytes(bundle_root / CONSENT_RECORD_FILENAME, consent_bytes)
    consent_artifact = _artifact(
        "artifact-consent",
        CONSENT_RECORD_FILENAME,
        PilotArtifactRole.consent_record,
        consent_bytes,
    )
    artifacts.append(consent_artifact)
    final_artifacts = tuple(sorted(artifacts, key=lambda item: item.artifact_id))

    output_present = any(
        item.role is PilotArtifactRole.assurance_output for item in final_artifacts
    )
    evidence = ExternalPilotEvidence.build(
        pilot_id=capture.pilot_id,
        workflow_id="controls-mutate",
        participant_pseudonym=capture.participant_pseudonym,
        classification="external",
        attempt_status="completed" if output_present else "attempted",
        qualifies_as_external_attempt=True,
        subject=capture.subject,
        environment=capture.environment,
        inputs=capture.inputs,
        commands=(capture.command,),
        artifacts=final_artifacts,
        friction_assessment=assessment,
        friction_assessment_artifact_id="artifact-friction",
        friction_findings=friction_findings,
        remediations=remediations,
        publication=PilotPublication(
            consent_status=PilotConsentStatus.granted,
            publication_scope=PilotPublicationScope.privacy_filtered_record,
            consent_artifact_id="artifact-consent",
            consent_digest=consent_artifact.sha256,
            published_artifact_ids=tuple(item.artifact_id for item in final_artifacts),
        ),
        privacy=_privacy_boundary(),
        recorded_at=finalized_at,
        limitations=tuple(
            sorted(
                (
                    "This pre-candidate pilot records onboarding learning only and is not an "
                    "exact-candidate release gate.",
                    "Repository control, participant identity, and consent authority require "
                    "separate human review.",
                    "Raw command streams and authored input bytes are excluded from the public "
                    "bundle.",
                )
            )
        ),
        evidence_phase="pre_candidate",
        evidence_use="learning_and_remediation_only",
        clean_reproduction_gate_eligible=False,
        exact_candidate_gate_eligible=False,
        ci_integration_gate_eligible=False,
    )
    _write_new_bytes(bundle_root / EVIDENCE_FILENAME, _json_bytes(evidence))
    verified = load_external_pilot_review_inputs(
        bundle_root,
        evidence_path=EVIDENCE_FILENAME,
    )
    if verified.evidence != evidence:
        raise RuntimeError("external pilot candidate did not verify exactly")
    return evidence


def _capture_artifacts(
    *,
    wheel_name: str,
    wheel_bytes: bytes,
    environment_bytes: bytes,
    control_bytes: bytes,
    input_manifest_bytes: bytes,
    execution_bytes: bytes,
    output_bytes: bytes | None,
) -> tuple[PilotArtifactDigest, ...]:
    artifacts = [
        _artifact(
            "artifact-control",
            ENVIRONMENT_CONTROL_FILENAME,
            PilotArtifactRole.environment_control_evidence,
            control_bytes,
        ),
        _artifact(
            "artifact-distribution",
            wheel_name,
            PilotArtifactRole.tested_distribution,
            wheel_bytes,
            content_scope=PilotArtifactContentScope.distribution_binary,
        ),
        _artifact(
            "artifact-environment",
            ENVIRONMENT_MANIFEST_FILENAME,
            PilotArtifactRole.environment_manifest,
            environment_bytes,
        ),
        _artifact(
            "artifact-execution",
            EXECUTION_EVIDENCE_FILENAME,
            PilotArtifactRole.execution_evidence,
            execution_bytes,
        ),
        _artifact(
            "artifact-input",
            INPUT_MANIFEST_FILENAME,
            PilotArtifactRole.input_manifest,
            input_manifest_bytes,
            schema_contract="PilotInputManifest/v1",
        ),
    ]
    if output_bytes is not None:
        artifacts.append(
            _artifact(
                "artifact-output",
                MUTATION_CAMPAIGN_FILENAME,
                PilotArtifactRole.assurance_output,
                output_bytes,
                content_scope=PilotArtifactContentScope.privacy_filtered,
                schema_contract="AssuranceMutationCampaign/v1",
                producing_command_id=_PILOT_COMMAND_ID,
            )
        )
    return tuple(sorted(artifacts, key=lambda item: item.artifact_id))


def _artifact(
    artifact_id: str,
    path: str,
    role: PilotArtifactRole,
    data: bytes,
    *,
    content_scope: PilotArtifactContentScope = PilotArtifactContentScope.metadata_only,
    schema_contract: str | None = None,
    producing_command_id: str | None = None,
) -> PilotArtifactDigest:
    return PilotArtifactDigest(
        artifact_id=artifact_id,
        path=path,
        role=role,
        sha256=_sha256(data),
        content_scope=content_scope,
        schema_validated=schema_contract is not None,
        schema_contract=schema_contract,
        producing_command_id=producing_command_id,
    )


def _load_verified_capture(root: Path) -> ExternalPilotCapture:
    capture_bytes = read_bytes_bounded_from_filesystem_root(
        root / CAPTURE_FILENAME,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="external pilot capture manifest",
    )
    payload = load_json_bytes_bounded(
        capture_bytes,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="external pilot capture manifest",
    )
    capture = ExternalPilotCapture.model_validate(payload)
    _verify_capture_directory(root, capture)
    distribution = next(
        item for item in capture.artifacts if item.role is PilotArtifactRole.tested_distribution
    )
    wheel_bytes = read_bytes_bounded_from_filesystem_root(
        root / distribution.path,
        max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
        label="external pilot captured tested wheel",
    )
    _validate_running_agent_assure_code_matches_wheel(wheel_bytes)
    return capture


def _verify_capture_directory(root: Path, capture: ExternalPilotCapture) -> None:
    expected = {CAPTURE_FILENAME, *(item.path for item in capture.artifacts)}
    observed = {item.name for item in root.iterdir()}
    if observed != expected or len(observed) > MAX_PILOT_BUNDLE_FILES:
        raise ValueError("external pilot capture inventory does not match its manifest")
    total = 0
    for artifact in capture.artifacts:
        data = read_bytes_bounded_from_filesystem_root(
            root / artifact.path,
            max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
            label="external pilot captured artifact",
        )
        total += len(data)
        validate_external_pilot_artifact_bytes(
            artifact,
            data,
            implementation_id=capture.subject.implementation_id,
            implementation_version=capture.subject.implementation_version,
        )
    total += (root / CAPTURE_FILENAME).stat().st_size
    if total > MAX_PILOT_BUNDLE_TOTAL_BYTES:
        raise ValueError("external pilot capture exceeds maximum supported size")


def _validate_finalization_identity(
    capture: ExternalPilotCapture,
    current: _CIIdentity,
    *,
    capture_run_id: str,
    capture_run_attempt: str,
) -> None:
    if (
        current.digests.repository != capture.ci_identity_digests.repository
        or current.digests.owner != capture.ci_identity_digests.owner
        or current.digests.actor != capture.ci_identity_digests.actor
    ):
        raise ValueError("pilot finalization must use the same fork owner and participant actor")
    expected_capture_run = _identity_digest(
        "run",
        current.raw_repository_id,
        capture_run_id,
        capture_run_attempt,
    )
    if expected_capture_run != capture.ci_identity_digests.run:
        raise ValueError("pilot finalization does not bind the requested capture run")


def _validated_external_ci_identity(environment: Mapping[str, str]) -> _CIIdentity:
    required = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "AGENT_ASSURE_PILOT_REPOSITORY_IS_FORK": "true",
        "AGENT_ASSURE_PILOT_PARENT_REPOSITORY": _EXPECTED_PARENT_REPOSITORY,
    }
    for name, expected in required.items():
        if environment.get(name, "").casefold() != expected.casefold():
            raise ValueError("external pilot kit requires the documented non-maintainer fork CI")
    if environment.get("GITHUB_REPOSITORY_OWNER", "").casefold() == (_EXPECTED_MAINTAINER_OWNER):
        raise ValueError("the upstream maintainer repository cannot operate an external pilot")
    github_actor = environment.get("GITHUB_ACTOR", "")
    triggering_actor = environment.get("GITHUB_TRIGGERING_ACTOR", "")
    if not github_actor or triggering_actor != github_actor:
        raise ValueError("external pilot reruns require the original GitHub actor")
    raw_values = {
        "repository": environment.get("GITHUB_REPOSITORY_ID", ""),
        "owner": environment.get("GITHUB_REPOSITORY_OWNER_ID", ""),
        "actor": environment.get("GITHUB_ACTOR_ID", ""),
        "run": environment.get("GITHUB_RUN_ID", ""),
        "attempt": environment.get("GITHUB_RUN_ATTEMPT", ""),
    }
    if any(_POSITIVE_INTEGER.fullmatch(value) is None for value in raw_values.values()):
        raise ValueError("external pilot CI identity fields must be positive integers")
    digests = _CIIdentityDigests(
        repository=_identity_digest("repository", raw_values["repository"]),
        owner=_identity_digest("owner", raw_values["owner"]),
        actor=_identity_digest("actor", raw_values["actor"]),
        run=_identity_digest(
            "run",
            raw_values["repository"],
            raw_values["run"],
            raw_values["attempt"],
        ),
    )
    return _CIIdentity(
        raw_repository_id=raw_values["repository"],
        raw_owner_id=raw_values["owner"],
        raw_actor_id=raw_values["actor"],
        raw_run_id=raw_values["run"],
        raw_run_attempt=raw_values["attempt"],
        digests=digests,
    )


def _identity_digest(identity_kind: str, *values: str) -> str:
    return sha256_hexdigest(
        {
            "contract_id": "ExternalPilotCIIdentity/v1",
            "identity_kind": identity_kind,
            "values": values,
        }
    )


def _read_committed_participant_input(
    repository_root: Path,
    repository_path: str,
) -> tuple[str, bytes]:
    revision = git_output(repository_root, "rev-parse", "HEAD")
    if revision is None or _FULL_GIT_REVISION.fullmatch(revision) is None:
        raise ValueError("participant repository must have one readable immutable HEAD")
    filesystem_bytes = read_bytes_bounded_from_filesystem_root(
        repository_root / Path(repository_path),
        max_bytes=MAX_CONFIG_TEXT_BYTES,
        label="external pilot participant input",
    )
    committed_bytes = git_file_bytes(repository_root, revision, repository_path)
    if len(committed_bytes) > MAX_CONFIG_TEXT_BYTES:
        raise ValueError("external pilot participant input exceeds maximum supported size")
    if committed_bytes != filesystem_bytes:
        raise ValueError("participant input must exactly match its committed HEAD bytes")
    return revision, committed_bytes


def _validate_participant_pseudonym(value: str) -> str:
    if (
        not isinstance(value, str)
        or _PARTICIPANT_PSEUDONYM.fullmatch(value) is None
        or value.startswith("replace-")
    ):
        raise ValueError(
            "participant pseudonym must be 1-64 machine-identifier characters and replace "
            "the template placeholder"
        )
    return value


def _validate_pseudonym_not_ci_identifier(
    value: str,
    environment: Mapping[str, str],
) -> None:
    known_identifiers = {
        environment.get(name, "").casefold()
        for name in (
            "GITHUB_ACTOR",
            "GITHUB_ACTOR_ID",
            "GITHUB_REPOSITORY",
            "GITHUB_REPOSITORY_ID",
            "GITHUB_REPOSITORY_OWNER",
            "GITHUB_REPOSITORY_OWNER_ID",
        )
        if environment.get(name, "")
    }
    if value.casefold() in known_identifiers:
        raise ValueError(
            "participant pseudonym must not equal a GitHub account or repository identifier"
        )


def _validate_participant_repository_path(value: str) -> str:
    parts = portable_relative_path_parts(value)
    if (
        len(parts) != 2
        or parts[0] != _PARTICIPANT_INPUT_PREFIX.rstrip("/")
        or parts[1] != _PARTICIPANT_INPUT_FILENAME
        or "/".join(parts) != value
    ):
        raise ValueError("participant input must be agent-assure-pilot/participant-waiver.yaml")
    return value


def _validate_benign_participant_waiver(
    waivers: Sequence[object],
    *,
    participant_pseudonym: str,
) -> None:
    if len(waivers) != 1:
        raise ValueError("external pilot participant input must contain exactly one waiver")
    waiver = waivers[0]
    expected_id = f"external-pilot-{participant_pseudonym}"
    rationale = getattr(waiver, "rationale", None)
    if (
        getattr(waiver, "waiver_id", None) != expected_id
        or getattr(waiver, "owner", None) != participant_pseudonym
        or getattr(waiver, "reviewer", None) != participant_pseudonym
        or getattr(getattr(waiver, "reason_code", None), "value", None) != "FORBIDDEN_TOOL"
        or getattr(waiver, "finding_id", None) != "pilot-nonmatching-finding"
        or getattr(waiver, "artifact_digest", None) != _ZERO_DIGEST
        or getattr(waiver, "expires_on", date.min) != _BENIGN_WAIVER_EXPIRY
    ):
        raise ValueError(
            "participant waiver must retain the documented benign non-matching boundary"
        )
    if (
        not isinstance(rationale, str)
        or rationale == _PARTICIPANT_RATIONALE_PLACEHOLDER
        or rationale != rationale.strip()
        or not rationale.isprintable()
        or len(rationale) > _PARTICIPANT_RATIONALE_MAX_CHARS
    ):
        raise ValueError(
            "participant waiver rationale must be participant-authored, printable, and at "
            "most 256 characters"
        )


def _validate_running_agent_assure_code_matches_wheel(wheel_bytes: bytes) -> None:
    """Bind the executing package tree to the code preserved in the wheel."""

    package_root = Path(__file__).resolve().parent
    running_code: dict[str, bytes] = {}
    for candidate in package_root.rglob("*"):
        if candidate.suffix not in _PACKAGE_CODE_SUFFIXES:
            continue
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("running Agent Assure package contains an unsafe code path")
        relative_name = candidate.relative_to(package_root).as_posix()
        wheel_name = f"agent_assure/{relative_name}"
        running_code[wheel_name] = read_bytes_bounded_from_filesystem_root(
            candidate,
            max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
            label="running Agent Assure package code",
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(wheel_bytes))
    except (
        OSError,
        zipfile.BadZipFile,
    ) as exc:  # pragma: no cover - strong validation precedes this
        raise ValueError("tested wheel could not be reopened for runtime binding") from exc
    with archive:
        wheel_code_names = {
            info.filename
            for info in archive.infolist()
            if not info.is_dir()
            and info.filename.startswith("agent_assure/")
            and info.filename.endswith(_PACKAGE_CODE_SUFFIXES)
        }
        if wheel_code_names != set(running_code):
            raise ValueError(
                "running Agent Assure package code inventory does not match tested wheel"
            )
        for name in sorted(wheel_code_names):
            try:
                wheel_code = archive.read(name)
            except (EOFError, RuntimeError, zipfile.BadZipFile) as exc:  # pragma: no cover
                raise ValueError("tested wheel code could not be read for runtime binding") from exc
            if wheel_code != running_code[name]:
                raise ValueError(
                    "running Agent Assure package code bytes do not match tested wheel"
                )


def _environment_manifest_payload(
    environment: Mapping[str, str],
    *,
    source_revision: str,
) -> dict[str, object]:
    return {
        "artifact_kind": "external-pilot-environment-manifest",
        "contract_id": "ExternalPilotEnvironmentManifest/v1",
        "execution_context": "continuous_integration",
        "ci_provider": "github-actions",
        "runner_environment": "github-hosted",
        "runner_os": environment.get("RUNNER_OS", "unknown").casefold(),
        "runner_arch": environment.get("RUNNER_ARCH", "unknown").casefold(),
        "python_implementation": platform.python_implementation().casefold(),
        "python_version": platform.python_version(),
        "agent_assure_version": __version__,
        "implementation_source_revision": source_revision,
        "credential_values_persisted": False,
    }


def _environment_control_payload(
    *,
    opaque_pilot_binding: str,
    participant_input_repository_path: str,
    source_revision: str,
) -> dict[str, object]:
    return {
        "artifact_kind": "external-pilot-environment-control-evidence",
        "contract_id": "ExternalPilotEnvironmentControlEvidence/v1",
        "classification": "independently_controlled_non_maintainer",
        "repository_is_direct_upstream_fork": True,
        "upstream_maintainer_operated_run": False,
        "participant_control_attested": True,
        "opaque_pilot_binding": opaque_pilot_binding,
        "participant_input_repository_path": participant_input_repository_path,
        "implementation_source_revision": source_revision,
        "identity_authentication": "out_of_band_not_machine_verified",
        "manual_review_required": True,
    }


def _platform_description(environment: Mapping[str, str]) -> str:
    runner_os = environment.get("RUNNER_OS", "unknown").casefold()
    runner_arch = environment.get("RUNNER_ARCH", "unknown").casefold()
    return f"github-hosted-actions-{runner_os}-{runner_arch}"


def _signature_command_environment(environment: Mapping[str, str]) -> dict[str, str]:
    # Preserve a virtual-environment launcher path. Resolving it can follow the
    # launcher to a base interpreter that does not have the tested wheel.
    executable_directory = str(Path(os.path.abspath(sys.executable)).parent)
    existing_path = environment.get("PATH", os.environ.get("PATH", ""))
    command_environment = {
        "NO_COLOR": "1",
        "PATH": executable_directory + (os.pathsep + existing_path if existing_path else ""),
        "PYTHONUTF8": "1",
        "TZ": "UTC",
    }
    if os.name == "nt":
        for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR"):
            value = environment.get(name, os.environ.get(name, ""))
            if value:
                command_environment[name] = value
    return command_environment


def _run_signature_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> int:
    try:
        completed = subprocess.run(
            list(argv),
            executable=sys.executable,
            cwd=cwd,
            env=dict(environment),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return 124
    return completed.returncode


def _privacy_boundary() -> PilotPrivacyBoundary:
    return PilotPrivacyBoundary(
        raw_inputs_persisted=False,
        raw_outputs_persisted=False,
        credential_values_persisted=False,
        participant_direct_identifiers_persisted=False,
        persisted_content="digests_and_privacy_filtered_metadata_only",
    )


def _json_bytes(value: object) -> bytes:
    if isinstance(value, BaseModel):
        rendered = bounded_model_json(value, label="external pilot kit artifact")
    else:
        rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
        if len(rendered.encode("utf-8")) > MAX_ARTIFACT_JSON_BYTES:
            raise ValueError("external pilot kit artifact exceeds maximum supported size")
    return rendered.encode("utf-8")


def _write_new_bytes(path: Path, data: bytes) -> None:
    if type(data) is not bytes:
        raise TypeError("external pilot kit writes require immutable bytes")
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _require_new_directory_target(path: Path, *, label: str) -> None:
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} path cannot be safely resolved") from exc
    if resolved == Path(resolved.anchor):
        raise ValueError(f"{label} cannot be a filesystem root")
    if path.exists() or path.is_symlink():
        raise ValueError(f"{label} already exists")
    if not path.parent.is_dir():
        raise ValueError(f"{label} parent directory must already exist")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    capture = subparsers.add_parser("capture", help="Run and capture the signature workflow.")
    capture.add_argument("--capture-root", type=Path, required=True)
    capture.add_argument("--participant-repository-root", type=Path, required=True)
    capture.add_argument("--participant-input", required=True)
    capture.add_argument("--participant-input-template", type=Path, required=True)
    capture.add_argument("--wheel", type=Path, required=True)
    capture.add_argument("--source-revision", required=True)
    capture.add_argument("--participant-pseudonym", required=True)
    capture.add_argument("--temporary-storage-consent-granted", action="store_true")
    capture.add_argument("--non-maintainer-control-attested", action="store_true")

    finalize = subparsers.add_parser(
        "finalize", help="Record post-attempt friction and publication consent."
    )
    finalize.add_argument("--capture-root", type=Path, required=True)
    finalize.add_argument("--bundle-root", type=Path, required=True)
    finalize.add_argument("--expected-source-revision", required=True)
    finalize.add_argument("--capture-run-id", required=True)
    finalize.add_argument("--capture-run-attempt", required=True)
    finalize.add_argument(
        "--friction-assessment",
        choices=("no_friction_observed", "friction_observed"),
        required=True,
    )
    finalize.add_argument(
        "--friction-category",
        choices=tuple(item.value for item in PilotFrictionCategory),
        default="other",
    )
    finalize.add_argument("--publication-consent-granted", action="store_true")
    finalize.add_argument("--non-maintainer-control-attested", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.operation == "capture":
            capture = capture_external_pilot(
                capture_root=args.capture_root,
                participant_repository_root=args.participant_repository_root,
                participant_input_repository_path=args.participant_input,
                participant_input_template=args.participant_input_template,
                wheel_path=args.wheel,
                source_revision=args.source_revision,
                participant_pseudonym=args.participant_pseudonym,
                temporary_storage_consent_granted=(args.temporary_storage_consent_granted),
                non_maintainer_control_attested=args.non_maintainer_control_attested,
            )
            print(f"external pilot capture digest: {capture.capture_digest}")
            print(f"external pilot capture: {args.capture_root}")
        else:
            evidence = finalize_external_pilot_capture(
                capture_root=args.capture_root,
                bundle_root=args.bundle_root,
                expected_source_revision=args.expected_source_revision,
                capture_run_id=args.capture_run_id,
                capture_run_attempt=args.capture_run_attempt,
                friction_assessment=args.friction_assessment,
                friction_category=args.friction_category,
                publication_consent_granted=args.publication_consent_granted,
                non_maintainer_control_attested=args.non_maintainer_control_attested,
            )
            print(f"external pilot evidence digest: {evidence.pilot_evidence_digest}")
            print(f"external pilot candidate bundle: {args.bundle_root}")
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"external pilot kit failed: {bounded_error(exc)}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
