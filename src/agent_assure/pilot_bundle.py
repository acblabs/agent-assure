"""Fail-closed verification for external-pilot evidence bundles."""

from __future__ import annotations

import ast
import base64
import binascii
import csv
import hashlib
import io
import re
import stat
import zipfile
import zlib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from pathlib import Path

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bytes_bounded,
    loads_json_bounded,
    open_directory_at,
)
from agent_assure.privacy.credential_uri import (
    PERSISTED_CREDENTIAL_NAMES,
    PERSISTED_CREDENTIAL_SUFFIXES,
    contains_persisted_credential,
)
from agent_assure.privacy.distribution import (
    validate_distribution_member_privacy,
    validate_zip_metadata_absent,
)
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.rooted_io import PinnedDirectoryFile, portable_relative_path_parts
from agent_assure.schema.common import PACKAGE_RELEASE_VERSION_PATTERN
from agent_assure.schema.pilot import (
    MAX_PILOT_ARTIFACTS,
    ExternalPilotEvidence,
    ExternalPilotIndependenceReviewReceipt,
    PilotArtifactDigest,
    PilotArtifactRole,
    PilotInputIdentityKind,
    PilotInputKind,
    PilotInputManifest,
    PilotInputManifestEntry,
    PilotInputOrigin,
    pilot_workflow_input_arguments,
)
from agent_assure.schema.validation import (
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)
from agent_assure.timestamps import parse_rfc3339_timestamp

MAX_PILOT_BUNDLE_ARTIFACT_BYTES = MAX_ARTIFACT_JSON_BYTES
MAX_PILOT_BUNDLE_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PILOT_BUNDLE_FILES = MAX_PILOT_ARTIFACTS + 2
MAX_PILOT_WHEEL_MEMBERS = 4_096
MAX_PILOT_WHEEL_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_PILOT_WHEEL_METADATA_BYTES = 1 * 1024 * 1024
MAX_PILOT_WHEEL_COMPRESSED_TAGS = 64
MAX_PILOT_WHEEL_STRUCTURAL_SCAN_LINES = 500_000
MAX_PILOT_WHEEL_PYTHON_MEMBER_BYTES = 2 * 1024 * 1024
MAX_PILOT_WHEEL_PYTHON_MEMBER_LINES = 25_000
MAX_PILOT_WHEEL_PYTHON_MEMBER_TOKENS = 200_000
_WHEEL_FORBIDDEN_BASENAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ed25519",
        "id_rsa",
        "secret.json",
        "secrets.json",
    }
)
_WHEEL_FORBIDDEN_SUFFIXES = (".jks", ".key", ".keystore", ".p12", ".pem", ".pfx")

_SUPPORTED_SCHEMA_CONTRACTS = {
    "AssuranceMutationCampaign/v1": "assurance-mutation-campaign",
    "AssuranceMutationResult/v1": "assurance-mutation-result",
    "RAGSensitivityReport/v1": "evidence-sensitivity-report",
}
_VERIFIED_BUNDLE_MARKER = object()
_VERIFIED_REVIEW_INPUTS_MARKER = object()


@dataclass(frozen=True, slots=True, init=False)
class ValidatedExternalPilotReviewInputs:
    """Pinned, closed pilot evidence issued for human-review finalization."""

    evidence: ExternalPilotEvidence
    pilot_evidence_file_sha256: str
    artifact_manifest_digest: str
    environment_control_evidence_artifact_id: str
    environment_control_evidence_sha256: str
    total_bytes: int
    _verification_marker: object = field(repr=False, compare=False)

    def __new__(cls) -> ValidatedExternalPilotReviewInputs:
        raise TypeError(
            "ValidatedExternalPilotReviewInputs instances are issued only by "
            "load_external_pilot_review_inputs"
        )

    @property
    def is_mechanically_verified(self) -> bool:
        return getattr(self, "_verification_marker", None) is _VERIFIED_REVIEW_INPUTS_MARKER

    @classmethod
    def _from_verified_bytes(
        cls,
        *,
        evidence: ExternalPilotEvidence,
        pilot_evidence_file_sha256: str,
        artifact_manifest_digest: str,
        environment_control_evidence_artifact_id: str,
        environment_control_evidence_sha256: str,
        total_bytes: int,
    ) -> ValidatedExternalPilotReviewInputs:
        instance = object.__new__(cls)
        object.__setattr__(instance, "evidence", evidence)
        object.__setattr__(
            instance,
            "pilot_evidence_file_sha256",
            pilot_evidence_file_sha256,
        )
        object.__setattr__(instance, "artifact_manifest_digest", artifact_manifest_digest)
        object.__setattr__(
            instance,
            "environment_control_evidence_artifact_id",
            environment_control_evidence_artifact_id,
        )
        object.__setattr__(
            instance,
            "environment_control_evidence_sha256",
            environment_control_evidence_sha256,
        )
        object.__setattr__(instance, "total_bytes", total_bytes)
        object.__setattr__(
            instance,
            "_verification_marker",
            _VERIFIED_REVIEW_INPUTS_MARKER,
        )
        return instance


@dataclass(frozen=True, slots=True)
class _ValidatedPilotMaterials:
    evidence: ExternalPilotEvidence
    evidence_file_sha256: str
    artifact_manifest_digest: str
    artifact_by_id: Mapping[str, PilotArtifactDigest]
    review_receipt: ExternalPilotIndependenceReviewReceipt | None
    total_bytes: int


@dataclass(frozen=True, slots=True, init=False)
class VerifiedExternalPilotBundle:
    """Mechanically verified bytes plus an explicit human-review trust boundary.

    Instances are issued only by :func:`load_verified_external_pilot_bundle`.
    The factory-only construction prevents a bare ``ExternalPilotEvidence``
    object from being accidentally promoted to release-readiness evidence.
    It is not a security boundary against Python code that can modify this
    module; such code is already inside the release gate's trust boundary.
    """

    evidence: ExternalPilotEvidence
    review_receipt: ExternalPilotIndependenceReviewReceipt
    artifact_manifest_digest: str
    total_bytes: int
    _verification_marker: object = field(repr=False, compare=False)

    def __new__(cls) -> VerifiedExternalPilotBundle:
        raise TypeError(
            "VerifiedExternalPilotBundle instances are issued only by "
            "load_verified_external_pilot_bundle"
        )

    @property
    def is_mechanically_verified(self) -> bool:
        return getattr(self, "_verification_marker", None) is _VERIFIED_BUNDLE_MARKER

    @classmethod
    def _from_verified_bytes(
        cls,
        *,
        evidence: ExternalPilotEvidence,
        review_receipt: ExternalPilotIndependenceReviewReceipt,
        artifact_manifest_digest: str,
        total_bytes: int,
    ) -> VerifiedExternalPilotBundle:
        instance = object.__new__(cls)
        object.__setattr__(instance, "evidence", evidence)
        object.__setattr__(instance, "review_receipt", review_receipt)
        object.__setattr__(instance, "artifact_manifest_digest", artifact_manifest_digest)
        object.__setattr__(instance, "total_bytes", total_bytes)
        object.__setattr__(instance, "_verification_marker", _VERIFIED_BUNDLE_MARKER)
        return instance


def pilot_artifact_manifest_digest(
    artifacts: Sequence[PilotArtifactDigest],
) -> str:
    """Bind the complete ordered artifact descriptor inventory."""

    return sha256_hexdigest(
        {
            "contract_id": "ExternalPilotBundleArtifactManifest/v1",
            "artifacts": [
                artifact.model_dump(mode="json", warnings="error") for artifact in artifacts
            ],
        }
    )


def validate_external_pilot_artifact_bytes(
    artifact: PilotArtifactDigest,
    data: bytes,
    *,
    implementation_id: str,
    implementation_version: str,
) -> Mapping[str, object] | None:
    """Apply the publication verifier's byte-local checks to one artifact.

    Inventory, aggregate-size, input-manifest, and cross-artifact bindings stay
    with the closed-bundle verifier. This smaller surface lets capture tooling
    fail before upload while reusing the exact digest, schema, privacy, and
    tested-wheel rules used by the release gate.
    """

    if type(data) is not bytes:
        raise TypeError("external pilot artifact validation requires immutable bytes")
    if len(data) > MAX_PILOT_BUNDLE_ARTIFACT_BYTES:
        raise ValueError("external pilot bundle artifact exceeds maximum supported size")
    if hashlib.sha256(data).hexdigest() != artifact.sha256:
        raise ValueError("external pilot bundle artifact digest mismatch")
    if artifact.role is PilotArtifactRole.tested_distribution:
        _validate_tested_distribution(
            artifact,
            data,
            implementation_id=implementation_id,
            implementation_version=implementation_version,
        )
    validated_payload = _validate_declared_schema_contract(artifact, data)
    if artifact.role is PilotArtifactRole.assurance_output and validated_payload is None:
        raise ValueError("external pilot assurance outputs require a supported schema contract")
    _validate_privacy_safe_artifact(artifact, data)
    return validated_payload


def _load_validated_pilot_materials(
    bundle_root: Path,
    *,
    evidence_path: str | Path,
    review_receipt_path: str | Path | None,
    expected_release: str | None,
    review_receipt_optional: bool = False,
) -> _ValidatedPilotMaterials:
    """Verify shared pilot evidence bytes for review authoring or final gating."""

    evidence_name = _direct_child_name(evidence_path, label="pilot evidence")
    receipt_name = (
        None
        if review_receipt_path is None
        else _direct_child_name(review_receipt_path, label="pilot review receipt")
    )
    if review_receipt_optional and receipt_name is None:
        raise TypeError("an optional pilot review receipt path must be supplied")
    if not review_receipt_optional and (receipt_name is None) != (expected_release is None):
        raise TypeError("pilot review receipt and expected release must be supplied together")
    if receipt_name is not None and evidence_name.casefold() == receipt_name.casefold():
        raise ValueError("pilot evidence and review receipt paths must be distinct")

    with (
        open_directory_at(bundle_root, ".", label="external pilot bundle") as bundle,
        ExitStack() as opened_stack,
    ):
        initial_entries = bundle.entry_names(
            max_entries=MAX_PILOT_BUNDLE_FILES,
            label="external pilot bundle",
        )
        if len({name.casefold() for name in initial_entries}) != len(initial_entries):
            raise ValueError("external pilot bundle contains case-colliding paths")

        opened_files: list[PinnedDirectoryFile] = []
        total_bytes = 0

        def read_child(
            name: str,
            *,
            max_bytes: int,
            label: str,
        ) -> bytes:
            nonlocal total_bytes
            remaining = MAX_PILOT_BUNDLE_TOTAL_BYTES - total_bytes
            if remaining < 0:
                raise ValueError("external pilot bundle exceeds maximum supported size")
            opened = opened_stack.enter_context(
                bundle.open_file_bounded(
                    name,
                    max_bytes=min(max_bytes, remaining),
                    label=label,
                    require_single_link=True,
                )
            )
            opened_files.append(opened)
            total_bytes += opened.contents.size
            return opened.contents.data

        evidence_bytes = read_child(
            evidence_name,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="external pilot evidence",
        )
        evidence_payload = load_json_bytes_bounded(
            evidence_bytes,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="external pilot evidence",
        )
        validate_loaded_artifact_payload(evidence_payload, "external-pilot-evidence")
        evidence = project_validated_artifact_payload(
            evidence_payload,
            ExternalPilotEvidence,
            kind="external-pilot-evidence",
        )
        evidence_file_sha256 = opened_files[0].contents.sha256

        artifact_names = tuple(artifact.path for artifact in evidence.artifacts)
        entries_without_receipt = (evidence_name, *artifact_names)
        entries_with_receipt = (
            () if receipt_name is None else (evidence_name, receipt_name, *artifact_names)
        )
        if review_receipt_optional:
            if _inventory_matches(initial_entries, entries_without_receipt):
                receipt_present = False
                expected_entries = entries_without_receipt
            elif _inventory_matches(initial_entries, entries_with_receipt):
                receipt_present = True
                expected_entries = entries_with_receipt
            else:
                raise ValueError("external pilot bundle inventory does not match its descriptor")
        else:
            receipt_present = receipt_name is not None
            expected_entries = entries_with_receipt if receipt_present else entries_without_receipt
        _require_exact_inventory(initial_entries, expected_entries)

        artifact_by_id = {artifact.artifact_id: artifact for artifact in evidence.artifacts}
        input_manifest: PilotInputManifest | None = None
        validated_output_payloads: dict[str, Mapping[str, object]] = {}
        for artifact in evidence.artifacts:
            artifact_bytes = read_child(
                artifact.path,
                max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
                label="external pilot bundle artifact",
            )
            validated_payload = validate_external_pilot_artifact_bytes(
                artifact,
                artifact_bytes,
                implementation_id=evidence.subject.implementation_id,
                implementation_version=evidence.subject.implementation_version,
            )
            if artifact.role is PilotArtifactRole.input_manifest:
                if input_manifest is not None:
                    raise ValueError("external pilot bundle contains multiple input manifests")
                input_manifest = _validate_input_manifest(
                    artifact,
                    artifact_bytes,
                    evidence=evidence,
                )
            if artifact.role is PilotArtifactRole.assurance_output:
                if validated_payload is None:  # pragma: no cover - shared validator guards this
                    raise RuntimeError("external pilot assurance output was not validated")
                validated_output_payloads[artifact.artifact_id] = validated_payload

        if input_manifest is None:
            raise ValueError("external pilot bundle has no typed input manifest")
        _validate_command_input_bindings(evidence, input_manifest)
        _validate_assurance_output_input_bindings(
            evidence,
            input_manifest,
            validated_output_payloads,
        )

        manifest_digest = pilot_artifact_manifest_digest(evidence.artifacts)
        receipt = None
        if receipt_present:
            if receipt_name is None:  # pragma: no cover - guarded above
                raise RuntimeError("pilot review receipt path is unavailable")
            receipt_bytes = read_child(
                receipt_name,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="external pilot independence review receipt",
            )
            receipt_payload = load_json_bytes_bounded(
                receipt_bytes,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="external pilot independence review receipt",
            )
            validate_loaded_artifact_payload(
                receipt_payload,
                "external-pilot-independence-review",
            )
            receipt = project_validated_artifact_payload(
                receipt_payload,
                ExternalPilotIndependenceReviewReceipt,
                kind="external-pilot-independence-review",
            )
            _validate_review_binding(
                receipt,
                evidence,
                pilot_evidence_file_sha256=evidence_file_sha256,
                artifact_manifest_digest=manifest_digest,
                artifact_by_id=artifact_by_id,
                expected_release=(expected_release or evidence.subject.implementation_version),
            )

        for opened in opened_files:
            opened.revalidate()
        final_entries = bundle.entry_names(
            max_entries=MAX_PILOT_BUNDLE_FILES,
            label="external pilot bundle",
        )
        _require_exact_inventory(final_entries, expected_entries)

    return _ValidatedPilotMaterials(
        evidence=evidence,
        evidence_file_sha256=evidence_file_sha256,
        artifact_manifest_digest=manifest_digest,
        artifact_by_id=artifact_by_id,
        review_receipt=receipt,
        total_bytes=total_bytes,
    )


def load_external_pilot_review_inputs(
    bundle_root: Path,
    *,
    evidence_path: str | Path,
    review_receipt_path: str | Path | None = None,
) -> ValidatedExternalPilotReviewInputs:
    """Validate and pin an exact pilot bundle before human review authoring.

    The bundle must contain exactly the evidence descriptor and every artifact
    it declares. When a review-receipt path is supplied, an absent receipt or
    an already-valid receipt at that exact path is accepted to support exact
    idempotent finalization.
    """

    materials = _load_validated_pilot_materials(
        bundle_root,
        evidence_path=evidence_path,
        review_receipt_path=review_receipt_path,
        expected_release=None,
        review_receipt_optional=review_receipt_path is not None,
    )
    evidence = materials.evidence
    if not evidence.qualifies_as_external_attempt:
        raise ValueError("pilot evidence does not qualify as an external attempt")
    control_id = evidence.environment.control_evidence_artifact_id
    if control_id is None:
        raise ValueError("external pilot bundle has no environment-control evidence")
    control_artifact = materials.artifact_by_id.get(control_id)
    if control_artifact is None:  # pragma: no cover - evidence validation guards this
        raise ValueError("external pilot environment-control artifact is unavailable")
    return ValidatedExternalPilotReviewInputs._from_verified_bytes(
        evidence=evidence,
        pilot_evidence_file_sha256=materials.evidence_file_sha256,
        artifact_manifest_digest=materials.artifact_manifest_digest,
        environment_control_evidence_artifact_id=control_id,
        environment_control_evidence_sha256=control_artifact.sha256,
        total_bytes=materials.total_bytes,
    )


def build_external_pilot_review_receipt(
    review_inputs: ValidatedExternalPilotReviewInputs,
    *,
    receipt_id: str,
    reviewer_pseudonym: str,
    manual_approval_is_trust_root: bool,
    reviewer_independent_of_pilot_execution: bool,
    reviewer_independence_rationale: str,
    environment_control_evidence_reviewed: bool,
    artifact_inventory_reviewed: bool,
    tested_distribution_provenance_reviewed: bool,
    command_input_bindings_reviewed: bool,
    execution_time_input_content_digests_reviewed: bool,
    input_semantic_identities_reviewed: bool,
    complete_bundle_publication_consent_reviewed: bool,
    privacy_boundary_reviewed: bool,
    review_outcome: str,
    reviewed_at: str,
) -> ExternalPilotIndependenceReviewReceipt:
    """Build a receipt whose machine-verifiable fields cannot be self-declared."""

    if (
        type(review_inputs) is not ValidatedExternalPilotReviewInputs
        or not review_inputs.is_mechanically_verified
    ):
        raise TypeError("pilot review receipt construction requires validated review inputs")
    evidence = review_inputs.evidence
    receipt = ExternalPilotIndependenceReviewReceipt.build(
        receipt_id=receipt_id,
        pilot_id=evidence.pilot_id,
        pilot_participant_pseudonym=evidence.participant_pseudonym,
        pilot_evidence_digest=evidence.pilot_evidence_digest,
        pilot_evidence_file_sha256=review_inputs.pilot_evidence_file_sha256,
        artifact_manifest_digest=review_inputs.artifact_manifest_digest,
        environment_control_evidence_artifact_id=(
            review_inputs.environment_control_evidence_artifact_id
        ),
        environment_control_evidence_sha256=(review_inputs.environment_control_evidence_sha256),
        expected_release_line=_release_base(evidence.subject.implementation_version),
        reviewer_pseudonym=reviewer_pseudonym,
        manual_approval_is_trust_root=manual_approval_is_trust_root,
        reviewer_independent_of_pilot_execution=(reviewer_independent_of_pilot_execution),
        reviewer_independence_rationale=reviewer_independence_rationale,
        environment_control_evidence_reviewed=(environment_control_evidence_reviewed),
        artifact_inventory_reviewed=artifact_inventory_reviewed,
        tested_distribution_provenance_reviewed=(tested_distribution_provenance_reviewed),
        command_input_bindings_reviewed=command_input_bindings_reviewed,
        execution_time_input_content_digests_reviewed=(
            execution_time_input_content_digests_reviewed
        ),
        input_semantic_identities_reviewed=input_semantic_identities_reviewed,
        complete_bundle_publication_consent_reviewed=(complete_bundle_publication_consent_reviewed),
        privacy_boundary_reviewed=privacy_boundary_reviewed,
        review_outcome=review_outcome,
        reviewed_at=reviewed_at,
    )
    if parse_rfc3339_timestamp(
        receipt.reviewed_at,
        field_name="pilot review reviewed_at",
    ) < parse_rfc3339_timestamp(
        evidence.recorded_at,
        field_name="pilot evidence recorded_at",
    ):
        raise ValueError("external pilot independence review predates the pilot evidence")
    return receipt


def load_verified_external_pilot_bundle(
    bundle_root: Path,
    *,
    evidence_path: str | Path,
    review_receipt_path: str | Path,
    expected_release: str,
) -> VerifiedExternalPilotBundle:
    """Verify a complete, closed external-pilot evidence bundle."""

    materials = _load_validated_pilot_materials(
        bundle_root,
        evidence_path=evidence_path,
        review_receipt_path=review_receipt_path,
        expected_release=expected_release,
    )
    receipt = materials.review_receipt
    if receipt is None:  # pragma: no cover - guarded by the loader contract
        raise RuntimeError("external pilot review receipt is unavailable")
    return VerifiedExternalPilotBundle._from_verified_bytes(
        evidence=materials.evidence,
        review_receipt=receipt,
        artifact_manifest_digest=materials.artifact_manifest_digest,
        total_bytes=materials.total_bytes,
    )


def _direct_child_name(value: str | Path, *, label: str) -> str:
    raw = str(value)
    parts = portable_relative_path_parts(raw)
    if len(parts) != 1 or parts[0] != raw:
        raise ValueError(f"{label} path must be one canonical portable bundle-root child")
    return raw


def _require_exact_inventory(
    observed: Sequence[str],
    expected: Sequence[str],
) -> None:
    if not _inventory_matches(observed, expected):
        raise ValueError("external pilot bundle inventory does not match its descriptor")


def _inventory_matches(
    observed: Sequence[str],
    expected: Sequence[str],
) -> bool:
    return (
        len(observed) == len(expected)
        and len({item.casefold() for item in expected}) == len(expected)
        and set(observed) == set(expected)
    )


def _validate_input_manifest(
    artifact: PilotArtifactDigest,
    data: bytes,
    *,
    evidence: ExternalPilotEvidence,
) -> PilotInputManifest:
    payload = load_json_bytes_bounded(
        data,
        max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
        label="external pilot input manifest",
    )
    manifest = PilotInputManifest.model_validate(payload)
    if artifact.schema_contract != manifest.contract_id:
        raise ValueError("external pilot input manifest contract does not match its descriptor")
    if manifest.workflow_id != evidence.workflow_id:
        raise ValueError("external pilot input manifest targets a different workflow")
    if (manifest.configuration_digest, manifest.data_digest) != (
        evidence.inputs.configuration_digest,
        evidence.inputs.data_digest,
    ):
        raise ValueError("external pilot input manifest digests do not match the pilot boundary")
    boundaries = (
        (
            PilotInputKind.configuration,
            evidence.inputs.configuration_origin,
            evidence.inputs.configuration_digest,
        ),
        (PilotInputKind.data, evidence.inputs.data_origin, evidence.inputs.data_digest),
    )
    for input_kind, origin, digest in boundaries:
        entries = tuple(entry for entry in manifest.entries if entry.input_kind is input_kind)
        if origin is PilotInputOrigin.absent:
            if entries or digest is not None:
                raise ValueError("absent pilot input kind cannot have manifest entries")
            continue
        if not entries or digest is None:
            raise ValueError("pilot input manifest origins do not match the pilot boundary")
        entry_origins = {entry.origin for entry in entries}
        if origin is PilotInputOrigin.mixed_bundled_non_bundled:
            expected_origins = {
                PilotInputOrigin.bundled,
                PilotInputOrigin.non_bundled,
            }
            if entry_origins != expected_origins:
                raise ValueError(
                    "mixed pilot input boundary requires bundled and non-bundled entries"
                )
        elif entry_origins != {origin}:
            raise ValueError("pilot input manifest origins do not match the pilot boundary")
    return manifest


def _validate_command_input_bindings(
    evidence: ExternalPilotEvidence,
    manifest: PilotInputManifest,
) -> None:
    entries_by_id = {entry.entry_id: entry for entry in manifest.entries}
    consumed_workflow_entries: set[str] = set()
    workflow_commands = 0
    for command in evidence.commands:
        command_entries = []
        for entry_id in command.consumed_input_entry_ids:
            entry = entries_by_id.get(entry_id)
            if entry is None:
                raise ValueError("pilot command references an unknown input manifest entry")
            command_entries.append(entry)
        invocation = pilot_workflow_input_arguments(command.argv, evidence.workflow_id)
        if invocation is None:
            if command_entries:
                raise ValueError("non-workflow pilot commands cannot claim workflow inputs")
            continue
        workflow_commands += 1
        expected = set(invocation)
        observed = {
            (entry.input_kind, entry.option_name, entry.option_value) for entry in command_entries
        }
        if observed != expected:
            raise ValueError(
                "pilot workflow command input bindings do not exactly match its argv inputs"
            )
        consumed_workflow_entries.update(entry.entry_id for entry in command_entries)
    if workflow_commands and consumed_workflow_entries != set(entries_by_id):
        raise ValueError("pilot input manifest contains entries unused by its workflow commands")


def _validate_assurance_output_input_bindings(
    evidence: ExternalPilotEvidence,
    manifest: PilotInputManifest,
    output_payloads: Mapping[str, Mapping[str, object]],
) -> None:
    """Bind each supported output's typed identities to its producing command inputs."""

    entries_by_id = {entry.entry_id: entry for entry in manifest.entries}
    commands_by_id = {command.command_id: command for command in evidence.commands}
    for artifact in evidence.artifacts:
        if artifact.role is not PilotArtifactRole.assurance_output:
            continue
        producer_id = artifact.producing_command_id
        if producer_id is None:  # pragma: no cover - evidence schema guards this
            raise ValueError("external pilot assurance output has no producing command")
        command = commands_by_id[producer_id]
        entries = tuple(entries_by_id[entry_id] for entry_id in command.consumed_input_entry_ids)
        payload = output_payloads.get(artifact.artifact_id)
        if payload is None:
            raise ValueError("external pilot assurance output was not schema validated")
        if artifact.schema_contract == "AssuranceMutationCampaign/v1":
            _validate_campaign_output_input_bindings(payload, entries)
        elif artifact.schema_contract == "RAGSensitivityReport/v1":
            _validate_rag_output_input_bindings(payload, entries)
        elif artifact.schema_contract == "AssuranceMutationResult/v1":
            raise ValueError(
                "AssuranceMutationResult/v1 does not expose the consumed suite identity; "
                "use the campaign output for a bindable external pilot"
            )
        else:  # pragma: no cover - closed schema-contract allowlist guards this
            raise ValueError("external pilot assurance output contract is not bindable")


def _entries_for_option(
    entries: Sequence[PilotInputManifestEntry],
    option_name: str,
    identity_kind: PilotInputIdentityKind,
    *,
    required: bool = True,
) -> tuple[PilotInputManifestEntry, ...]:
    selected = tuple(entry for entry in entries if entry.option_name == option_name)
    if required and len(selected) != 1:
        raise ValueError(
            f"external pilot output binding requires exactly one --{option_name} input"
        )
    if any(entry.semantic_identity_kind is not identity_kind for entry in selected):
        raise ValueError("external pilot output binding has an unexpected semantic identity kind")
    return selected


def _require_output_digest(
    payload: Mapping[str, object],
    field_name: str,
    *,
    label: str,
) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str):  # pragma: no cover - typed artifact validation guards this
        raise ValueError(f"external pilot {label} output digest is unavailable")
    return value


def _require_output_mapping(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):  # pragma: no cover - typed validation guards this
        raise ValueError(f"external pilot {label} output binding is unavailable")
    return value


def _validate_campaign_output_input_bindings(
    payload: Mapping[str, object],
    entries: Sequence[PilotInputManifestEntry],
) -> None:
    suite = _entries_for_option(
        entries,
        "suite",
        PilotInputIdentityKind.compiled_suite,
    )[0]
    runset = _entries_for_option(
        entries,
        "runset",
        PilotInputIdentityKind.run_set,
    )[0]
    if (
        _require_output_digest(payload, "suite_digest", label="campaign suite")
        != suite.semantic_identity_digest
        or _require_output_digest(payload, "source_digest", label="campaign RunSet")
        != runset.semantic_identity_digest
    ):
        raise ValueError(
            "external pilot campaign output semantic identities do not match command inputs"
        )
    waivers = _entries_for_option(
        entries,
        "waiver",
        PilotInputIdentityKind.waiver_set,
        required=False,
    )
    if not waivers:
        return
    expected_waiver_digest = waivers[0].semantic_identity_digest
    if any(entry.semantic_identity_digest != expected_waiver_digest for entry in waivers):
        raise ValueError("external pilot waiver inputs disagree on their aggregate identity")
    raw_results = payload.get("operator_results")
    if not isinstance(raw_results, Sequence) or isinstance(raw_results, str | bytes):
        raise ValueError("external pilot campaign operator results are unavailable")
    observed_waiver_digests = {
        _require_output_digest(
            _require_output_mapping(
                _require_output_mapping(result, label="campaign result").get("result"),
                label="campaign nested result",
            ),
            "waiver_set_digest",
            label="campaign waiver set",
        )
        for result in raw_results
    }
    if observed_waiver_digests != {expected_waiver_digest}:
        raise ValueError(
            "external pilot campaign output waiver identity does not match command inputs"
        )


def _validate_rag_output_input_bindings(
    payload: Mapping[str, object],
    entries: Sequence[PilotInputManifestEntry],
) -> None:
    protocol = _require_output_mapping(payload.get("protocol"), label="RAG protocol")
    expected = (
        (
            "suite",
            PilotInputIdentityKind.compiled_suite,
            "suite_digest",
        ),
        (
            "knowledge-contract",
            PilotInputIdentityKind.knowledge_contract,
            "knowledge_contract_digest",
        ),
        (
            "baseline-corpus",
            PilotInputIdentityKind.rag_corpus,
            "baseline_corpus_digest",
        ),
        (
            "counterfactual-corpus",
            PilotInputIdentityKind.rag_corpus,
            "counterfactual_corpus_digest",
        ),
    )
    for option_name, identity_kind, output_field in expected:
        entry = _entries_for_option(entries, option_name, identity_kind)[0]
        if (
            _require_output_digest(protocol, output_field, label=f"RAG {option_name}")
            != entry.semantic_identity_digest
        ):
            raise ValueError(
                "external pilot RAG output semantic identities do not match command inputs"
            )
    attestations = _entries_for_option(
        entries,
        "synthetic-data-attestation",
        PilotInputIdentityKind.synthetic_data_attestation,
        required=False,
    )
    if len(attestations) > 1:
        raise ValueError(
            "external pilot output binding requires at most one synthetic-data attestation"
        )
    if attestations and (
        _require_output_digest(
            protocol,
            "synthetic_data_attestation_digest",
            label="RAG synthetic-data attestation",
        )
        != attestations[0].semantic_identity_digest
    ):
        raise ValueError(
            "external pilot RAG output semantic identities do not match command inputs"
        )


def _validate_declared_schema_contract(
    artifact: PilotArtifactDigest,
    data: bytes,
) -> Mapping[str, object] | None:
    contract = artifact.schema_contract
    if contract is None:
        return None
    if contract == "PilotInputManifest/v1":
        if artifact.role is not PilotArtifactRole.input_manifest:
            raise ValueError("PilotInputManifest/v1 is valid only for the input manifest role")
        return None
    kind = _SUPPORTED_SCHEMA_CONTRACTS.get(contract)
    if kind is None:
        raise ValueError("external pilot artifact declares an unsupported schema contract")
    payload = load_json_bytes_bounded(
        data,
        max_bytes=MAX_PILOT_BUNDLE_ARTIFACT_BYTES,
        label="external pilot schema-validated artifact",
    )
    validate_loaded_artifact_payload(payload, kind)
    if payload.get("contract_id") != contract:
        raise ValueError("external pilot artifact schema contract does not match its bytes")
    return payload


def _validate_privacy_safe_artifact(
    artifact: PilotArtifactDigest,
    data: bytes,
) -> None:
    # The tested wheel/sdist is the sole intentionally binary evidence role.
    # Every other artifact claims metadata-only/privacy-filtered content and
    # therefore must be inspectable as bounded UTF-8 before publication.
    if artifact.role is PilotArtifactRole.tested_distribution:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("external pilot metadata artifact must be UTF-8 text") from exc
    if not text.strip():
        raise ValueError("external pilot metadata artifact must not be empty")
    try:
        payload = loads_json_bounded(text, label="external pilot metadata artifact")
    except ValueError:
        lines = text.splitlines() or [text]
        if _contains_sensitive_scalar(text) or any(
            _contains_sensitive_scalar(line) for line in lines
        ):
            raise ValueError("external pilot artifact failed privacy review") from None
        return
    if redact_packet_payload(payload) != payload or any(
        _contains_sensitive_scalar(value) for value in _string_values(payload)
    ):
        raise ValueError("external pilot artifact failed privacy review")


def _validate_tested_distribution(
    artifact: PilotArtifactDigest,
    data: bytes,
    *,
    implementation_id: str,
    implementation_version: str,
) -> None:
    """Verify a bounded wheel snapshot and its exact project/version identity."""

    filename_identity, filename_tags = _wheel_filename_contract(artifact.path)
    expected_identity = (
        _normalize_project_name(implementation_id),
        implementation_version,
    )
    if expected_identity[0] != "agent-assure" or filename_identity != expected_identity:
        raise ValueError("external pilot tested distribution identity mismatch")

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError("external pilot tested distribution is not a valid wheel") from exc
    with archive:
        try:
            validate_zip_metadata_absent(archive)
        except ValueError as exc:
            raise ValueError(f"external pilot wheel: {exc}") from exc
        infos = archive.infolist()
        if not infos or len(infos) > MAX_PILOT_WHEEL_MEMBERS:
            raise ValueError("external pilot wheel has an invalid member count")
        names = [info.filename for info in infos]
        if len(set(names)) != len(names) or len({name.casefold() for name in names}) != len(names):
            raise ValueError("external pilot wheel contains duplicate member paths")
        expanded_bytes = 0
        regular_names: set[str] = set()
        for info in infos:
            _validate_wheel_member_path(info.filename)
            if info.flag_bits & 0x1:
                raise ValueError("external pilot wheel contains an encrypted member")
            expanded_bytes += info.file_size
            if expanded_bytes > MAX_PILOT_WHEEL_EXPANDED_BYTES:
                raise ValueError("external pilot wheel exceeds expanded-size limit")
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            if info.is_dir():
                if file_type not in {0, stat.S_IFDIR}:
                    raise ValueError("external pilot wheel has an invalid directory member")
                continue
            if file_type not in {0, stat.S_IFREG}:
                raise ValueError("external pilot wheel contains a non-regular member")
            regular_names.add(info.filename)

        metadata_names = sorted(
            name for name in regular_names if name.endswith(".dist-info/METADATA")
        )
        wheel_names = sorted(name for name in regular_names if name.endswith(".dist-info/WHEEL"))
        record_names = sorted(name for name in regular_names if name.endswith(".dist-info/RECORD"))
        if len(metadata_names) != 1 or len(wheel_names) != 1 or len(record_names) != 1:
            raise ValueError(
                "external pilot wheel requires one METADATA, one WHEEL, and one RECORD"
            )
        metadata_name = metadata_names[0]
        wheel_name = wheel_names[0]
        record_name = record_names[0]
        dist_info = metadata_name.rsplit("/", 1)[0]
        if (
            "/" in dist_info
            or wheel_name.rsplit("/", 1)[0] != dist_info
            or record_name.rsplit("/", 1)[0] != dist_info
            or not dist_info.endswith(".dist-info")
        ):
            raise ValueError("external pilot wheel has an invalid dist-info layout")
        for name in regular_names:
            _validate_wheel_distribution_member_path(name, dist_info=dist_info)
        layout_identity = _distribution_stem_identity(dist_info.removesuffix(".dist-info"))
        metadata_bytes = _read_wheel_member(
            archive,
            metadata_name,
            max_bytes=MAX_PILOT_WHEEL_METADATA_BYTES,
        )
        metadata_identity = _core_metadata_identity(metadata_bytes)
        if layout_identity != expected_identity or metadata_identity != expected_identity:
            raise ValueError("external pilot wheel metadata identity mismatch")
        _validate_wheel_metadata(
            _read_wheel_member(
                archive,
                wheel_name,
                max_bytes=MAX_PILOT_WHEEL_METADATA_BYTES,
            ),
            expected_tags=filename_tags,
        )
        _validate_wheel_record(archive, frozenset(regular_names), record_name)


def _validate_wheel_member_path(name: str) -> None:
    candidate = name.rstrip("/")
    if (
        not name
        or "\\" in name
        or "\x00" in name
        or "//" in name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
    ):
        raise ValueError("external pilot wheel contains an unsafe member path")
    try:
        parts = portable_relative_path_parts(candidate)
    except ValueError as exc:
        raise ValueError("external pilot wheel contains an unsafe member path") from exc
    if "/".join(parts) != candidate:
        raise ValueError("external pilot wheel contains a non-canonical member path")


def _wheel_filename_contract(path: str) -> tuple[tuple[str, str], frozenset[str]]:
    if not path.endswith(".whl"):
        raise ValueError("external pilot tested distribution must be a wheel")
    parts = path.removesuffix(".whl").split("-")
    if len(parts) not in {5, 6}:
        raise ValueError("external pilot tested distribution has an invalid wheel filename")
    if len(parts) == 6 and re.fullmatch(r"[0-9][A-Za-z0-9_]*", parts[2]) is None:
        raise ValueError("external pilot tested distribution has an invalid build tag")
    tag_components: list[tuple[str, ...]] = []
    for compressed in parts[-3:]:
        values = tuple(compressed.split("."))
        if any(not value or re.fullmatch(r"[A-Za-z0-9_]+", value) is None for value in values):
            raise ValueError("external pilot tested distribution has invalid compatibility tags")
        tag_components.append(values)
    python_tags, abi_tags, platform_tags = tag_components
    expanded_count = len(python_tags) * len(abi_tags) * len(platform_tags)
    if expanded_count > MAX_PILOT_WHEEL_COMPRESSED_TAGS:
        raise ValueError("external pilot tested distribution has too many compatibility tags")
    expanded_tags = frozenset(
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in python_tags
        for abi_tag in abi_tags
        for platform_tag in platform_tags
    )
    return (_normalize_project_name(parts[0]), parts[1]), expanded_tags


def _read_wheel_member(
    archive: zipfile.ZipFile,
    name: str,
    *,
    max_bytes: int,
) -> bytes:
    try:
        info = archive.getinfo(name)
        if info.file_size > max_bytes:
            raise ValueError("external pilot wheel member exceeds maximum supported size")
        with archive.open(info) as handle:
            data = handle.read(max_bytes + 1)
    except (EOFError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise ValueError("external pilot wheel member is malformed") from exc
    if len(data) != info.file_size or len(data) > max_bytes:
        raise ValueError("external pilot wheel member size mismatch")
    return data


def _core_metadata_identity(data: bytes) -> tuple[str, str]:
    fields = _message_fields(data, label="METADATA")
    metadata_versions = fields.get("metadata-version", [])
    if (
        len(metadata_versions) != 1
        or re.fullmatch(r"[1-9][0-9]*\.[0-9]+", metadata_versions[0]) is None
    ):
        raise ValueError("external pilot wheel METADATA has invalid Metadata-Version")
    identities: list[str] = []
    for field_name in ("name", "version"):
        values = fields.get(field_name, [])
        if len(values) != 1 or not values[0]:
            raise ValueError("external pilot wheel METADATA has invalid identity fields")
        identities.append(values[0])
    return _normalize_project_name(identities[0]), identities[1]


def _validate_wheel_metadata(
    data: bytes,
    *,
    expected_tags: frozenset[str],
) -> None:
    fields = _message_fields(data, label="WHEEL")
    wheel_versions = fields.get("wheel-version", [])
    purelib_values = fields.get("root-is-purelib", [])
    tags = fields.get("tag", [])
    if wheel_versions != ["1.0"]:
        raise ValueError("external pilot wheel has an unsupported Wheel-Version")
    if len(purelib_values) != 1 or purelib_values[0].casefold() not in {"true", "false"}:
        raise ValueError("external pilot wheel has an invalid Root-Is-Purelib field")
    if (
        not tags
        or len(set(tags)) != len(tags)
        or any(
            re.fullmatch(r"[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+", tag) is None
            for tag in tags
        )
    ):
        raise ValueError("external pilot wheel has invalid compatibility tags")
    if frozenset(tags) != expected_tags:
        raise ValueError("external pilot wheel filename and WHEEL compatibility tags differ")


def _message_fields(data: bytes, *, label: str) -> dict[str, list[str]]:
    try:
        message = BytesParser(policy=policy.strict).parsebytes(data)
    except Exception as exc:
        raise ValueError(f"external pilot wheel {label} is malformed") from exc
    if message.defects:
        raise ValueError(f"external pilot wheel {label} is malformed")
    fields: dict[str, list[str]] = {}
    for field_name, value in message.raw_items():
        fields.setdefault(field_name.casefold(), []).append(value.strip())
    return fields


def _distribution_stem_identity(stem: str) -> tuple[str, str]:
    try:
        name, version = stem.rsplit("-", 1)
    except ValueError as exc:
        raise ValueError("external pilot wheel has an invalid dist-info identity") from exc
    if not name or not version:
        raise ValueError("external pilot wheel has an invalid dist-info identity")
    return _normalize_project_name(name), version


def _normalize_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _validate_wheel_record(
    archive: zipfile.ZipFile,
    regular_names: frozenset[str],
    record_name: str,
) -> None:
    record_bytes = _read_wheel_member(
        archive,
        record_name,
        max_bytes=MAX_PILOT_WHEEL_METADATA_BYTES,
    )
    try:
        rows = tuple(csv.reader(io.StringIO(record_bytes.decode("utf-8"))))
    except (csv.Error, UnicodeDecodeError) as exc:
        raise ValueError("external pilot wheel RECORD is malformed") from exc
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not row[0] or row[0] in records:
            raise ValueError("external pilot wheel RECORD has an invalid row")
        _validate_wheel_member_path(row[0])
        records[row[0]] = (row[1], row[2])
    if set(records) != set(regular_names):
        raise ValueError("external pilot wheel RECORD inventory mismatch")
    remaining_structural_scan_lines = MAX_PILOT_WHEEL_STRUCTURAL_SCAN_LINES
    for name in sorted(regular_names):
        digest_text, size_text = records[name]
        if name == record_name:
            if digest_text or size_text:
                raise ValueError("external pilot wheel RECORD must omit its own hash and size")
            continue
        member = _read_wheel_member(
            archive,
            name,
            max_bytes=MAX_PILOT_WHEEL_EXPANDED_BYTES,
        )
        scanned_lines = _validate_wheel_member_privacy(
            name,
            member,
            max_structural_scan_lines=remaining_structural_scan_lines,
        )
        remaining_structural_scan_lines -= scanned_lines
        if size_text != str(len(member)) or not digest_text.startswith("sha256="):
            raise ValueError("external pilot wheel RECORD member metadata mismatch")
        encoded_digest = digest_text.removeprefix("sha256=")
        try:
            expected_digest = base64.b64decode(
                encoded_digest + ("=" * (-len(encoded_digest) % 4)),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, binascii.Error) as exc:
            raise ValueError("external pilot wheel RECORD digest is malformed") from exc
        if expected_digest != hashlib.sha256(member).digest():
            raise ValueError("external pilot wheel RECORD digest mismatch")


def _validate_wheel_distribution_member_path(name: str, *, dist_info: str) -> None:
    parts = name.split("/")
    if parts[0] not in {"agent_assure", dist_info}:
        raise ValueError("external pilot wheel contains a member outside approved package roots")
    folded_parts = tuple(part.casefold() for part in parts)
    basename = folded_parts[-1]
    if (
        any(part in {".git", ".hg", ".svn"} for part in folded_parts)
        or basename in _WHEEL_FORBIDDEN_BASENAMES
        or basename.startswith(".env.")
        or basename.endswith(_WHEEL_FORBIDDEN_SUFFIXES)
    ):
        raise ValueError("external pilot wheel contains a credential-bearing member path")


def _validate_wheel_member_privacy(
    name: str,
    data: bytes,
    *,
    max_structural_scan_lines: int,
) -> int:
    try:
        return validate_distribution_member_privacy(
            name,
            data,
            max_structural_scan_lines=max_structural_scan_lines,
            max_python_member_bytes=MAX_PILOT_WHEEL_PYTHON_MEMBER_BYTES,
            max_python_member_lines=MAX_PILOT_WHEEL_PYTHON_MEMBER_LINES,
            max_python_member_tokens=MAX_PILOT_WHEEL_PYTHON_MEMBER_TOKENS,
            strict_python_source=True,
            ast_parser=ast.parse,
        )
    except ValueError as exc:
        raise ValueError(f"external pilot wheel {exc}") from exc


def _string_values(value: object) -> Iterator[str]:
    pending = [value]
    while pending:
        candidate = pending.pop()
        if isinstance(candidate, str):
            yield candidate
        elif isinstance(candidate, Mapping):
            pending.extend(candidate.keys())
            pending.extend(candidate.values())
        elif isinstance(candidate, Sequence) and not isinstance(
            candidate,
            bytes | bytearray,
        ):
            pending.extend(candidate)


def _contains_sensitive_scalar(value: str) -> bool:
    return contains_persisted_credential(
        value,
        exact_names=PERSISTED_CREDENTIAL_NAMES,
        suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
    )


def _validate_review_binding(
    receipt: ExternalPilotIndependenceReviewReceipt,
    evidence: ExternalPilotEvidence,
    *,
    pilot_evidence_file_sha256: str,
    artifact_manifest_digest: str,
    artifact_by_id: Mapping[str, PilotArtifactDigest],
    expected_release: str,
) -> None:
    if _release_base(evidence.subject.implementation_version) != _release_base(expected_release):
        raise ValueError("external pilot evidence targets a different release line")
    control_id = evidence.environment.control_evidence_artifact_id
    if control_id is None:
        raise ValueError("external pilot bundle has no environment-control evidence")
    control_artifact = artifact_by_id.get(control_id)
    if control_artifact is None:
        raise ValueError("external pilot environment-control artifact is unavailable")
    if (
        receipt.pilot_id != evidence.pilot_id
        or receipt.pilot_participant_pseudonym != evidence.participant_pseudonym
        or receipt.pilot_evidence_digest != evidence.pilot_evidence_digest
        or receipt.pilot_evidence_file_sha256 != pilot_evidence_file_sha256
        or receipt.artifact_manifest_digest != artifact_manifest_digest
        or receipt.environment_control_evidence_artifact_id != control_id
        or receipt.environment_control_evidence_sha256 != control_artifact.sha256
        or receipt.expected_release_line != _release_base(expected_release)
    ):
        raise ValueError("external pilot independence review does not bind the exact bundle")
    if parse_rfc3339_timestamp(
        receipt.reviewed_at,
        field_name="pilot review reviewed_at",
    ) < parse_rfc3339_timestamp(
        evidence.recorded_at,
        field_name="pilot evidence recorded_at",
    ):
        raise ValueError("external pilot independence review predates the pilot evidence")


def _release_base(version: str) -> str:
    import re

    if re.fullmatch(PACKAGE_RELEASE_VERSION_PATTERN, version) is None:
        raise ValueError("expected release must be a stable or rc package release")
    return version.split("rc", 1)[0]


__all__ = [
    "MAX_PILOT_BUNDLE_ARTIFACT_BYTES",
    "MAX_PILOT_BUNDLE_FILES",
    "MAX_PILOT_BUNDLE_TOTAL_BYTES",
    "ValidatedExternalPilotReviewInputs",
    "VerifiedExternalPilotBundle",
    "build_external_pilot_review_receipt",
    "load_external_pilot_review_inputs",
    "load_verified_external_pilot_bundle",
    "pilot_artifact_manifest_digest",
    "validate_external_pilot_artifact_bytes",
]
