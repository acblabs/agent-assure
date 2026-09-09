from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import struct
import zipfile
from pathlib import Path

import pytest

import agent_assure.pilot_bundle as pilot_bundle
from agent_assure.pilot_bundle import (
    ValidatedExternalPilotReviewInputs,
    VerifiedExternalPilotBundle,
    build_external_pilot_review_receipt,
    load_external_pilot_review_inputs,
    load_verified_external_pilot_bundle,
    pilot_artifact_manifest_digest,
    validate_external_pilot_artifact_bytes,
)
from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    ExternalPilotIndependenceReviewReceipt,
    PilotArtifactContentScope,
    PilotArtifactDigest,
    PilotArtifactRole,
    PilotCommandExecution,
    PilotEnvironment,
    PilotInputBoundary,
    PilotInputIdentityKind,
    PilotInputKind,
    PilotInputManifest,
    PilotInputManifestEntry,
    PilotInputOrigin,
    PilotPublication,
    PilotRemediationReference,
    PilotSubject,
)
from tests.unit.mutation.test_campaign import _campaign as _mutation_campaign
from tests.unit.mutation.test_campaign import _fixture as _mutation_fixture
from tests.unit.schema.test_pilot_evidence import (
    _artifacts,
    _external_evidence,
    _values,
    _workflow_run,
)

EVIDENCE_NAME = "external-pilot-evidence.json"
RECEIPT_NAME = "external-pilot-independence-review.json"
WHEEL_NAME = "agent_assure-0.6.6-py3-none-any.whl"


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode(
        "ascii"
    ).rstrip("=")


def _wheel_bytes(
    *,
    project_name: str = "agent-assure",
    version: str = "0.6.6",
    compression: int = zipfile.ZIP_DEFLATED,
    wheel_tag: str = "py3-none-any",
    extra_members: dict[str, bytes] | None = None,
    metadata_kind: str | None = None,
) -> bytes:
    dist_info_name = project_name.replace("-", "_")
    dist_info = f"{dist_info_name}-{version}.dist-info"
    members = {
        "agent_assure/__init__.py": b'__version__ = "0.6.6"\n',
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.4\nName: {project_name}\nVersion: {version}\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n" + f"Tag: {wheel_tag}\n".encode()
        ),
    }
    members.update(extra_members or {})
    record_name = f"{dist_info}/RECORD"
    rows = [f"{name},{_record_hash(data)},{len(data)}" for name, data in sorted(members.items())]
    rows.append(f"{record_name},,")
    members[record_name] = ("\n".join(rows) + "\n").encode("utf-8")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, data in sorted(members.items()):
            if name == "agent_assure/__init__.py" and metadata_kind in {
                "member-comment",
                "member-extra",
            }:
                info = zipfile.ZipInfo(name)
                info.compress_type = compression
                if metadata_kind == "member-comment":
                    info.comment = b"sk-proj-abcdefghijklmnopqrstuvwxyz"
                else:
                    secret = b"sk-proj-abcdefghijklmnopqrstuvwxyz"
                    info.extra = struct.pack("<HH", 0xCAFE, len(secret)) + secret
                archive.writestr(info, data)
            else:
                archive.writestr(name, data)
        if metadata_kind == "archive-comment":
            archive.comment = b"sk-proj-abcdefghijklmnopqrstuvwxyz"
    return output.getvalue()


def _write_bundle(
    root: Path,
    *,
    distribution_bytes: bytes | None = None,
    artifact_content_overrides: dict[str, bytes] | None = None,
    artifact_contract_overrides: dict[str, str] | None = None,
    receipt_overrides: dict[str, object] | None = None,
    input_manifest_override: PilotInputManifest | None = None,
) -> tuple[ExternalPilotEvidence, ExternalPilotIndependenceReviewReceipt]:
    root.mkdir()
    values = _values()
    input_manifest = input_manifest_override or PilotInputManifest.build(
        workflow_id="controls-mutate",
        entries=(
            PilotInputManifestEntry(
                entry_id="input-suite",
                input_kind=PilotInputKind.configuration,
                origin=PilotInputOrigin.non_bundled,
                option_name="suite",
                option_value="pilot-suite.yaml",
                content_sha256="c" * 64,
                semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
                semantic_identity_digest="c" * 64,
            ),
            PilotInputManifestEntry(
                entry_id="input-runset",
                input_kind=PilotInputKind.data,
                origin=PilotInputOrigin.non_bundled,
                option_name="runset",
                option_value="pilot-runset.json",
                content_sha256="d" * 64,
                semantic_identity_kind=PilotInputIdentityKind.run_set,
                semantic_identity_digest="d" * 64,
            ),
        ),
    )
    input_manifest_bytes = _json_bytes(input_manifest.model_dump(mode="json"))
    source_artifacts = values["artifacts"]
    assert isinstance(source_artifacts, tuple)
    content_overrides = artifact_content_overrides or {}
    contract_overrides = artifact_contract_overrides or {}
    artifacts: list[PilotArtifactDigest] = []
    data_by_id: dict[str, bytes] = {}
    for source in source_artifacts:
        assert isinstance(source, PilotArtifactDigest)
        if source.role is PilotArtifactRole.tested_distribution:
            path = WHEEL_NAME
            data = distribution_bytes if distribution_bytes is not None else _wheel_bytes()
        else:
            path = f"{source.artifact_id}.json"
            default_data = (
                _json_bytes(
                    {
                        "artifact_kind": "external-pilot-remediation-record",
                        "contract_id": "ExternalPilotRemediationRecord/v1",
                        "pilot_id": values["pilot_id"],
                        "friction_category": "diagnostics",
                        "disposition": "applied",
                        "remediation_source_revision": "d" * 40,
                        "prior_planned_candidate_evidence_digest": "f" * 64,
                    }
                )
                if source.role is PilotArtifactRole.remediation_record
                else _json_bytes({"artifact_id": source.artifact_id, "state": "recorded"})
            )
            data = content_overrides.get(
                source.artifact_id,
                input_manifest_bytes
                if source.role is PilotArtifactRole.input_manifest
                else default_data,
            )
        contract = contract_overrides.get(source.artifact_id, source.schema_contract)
        artifact = PilotArtifactDigest(
            artifact_id=source.artifact_id,
            path=path,
            role=source.role,
            sha256=hashlib.sha256(data).hexdigest(),
            content_scope=source.content_scope,
            schema_validated=contract is not None,
            schema_contract=contract,
            producing_command_id=source.producing_command_id,
        )
        artifacts.append(artifact)
        data_by_id[artifact.artifact_id] = data
        (root / path).write_bytes(data)
    artifact_by_id = {artifact.artifact_id: artifact for artifact in artifacts}

    subject = values["subject"]
    environment = values["environment"]
    inputs = values["inputs"]
    commands = values["commands"]
    remediations = values["remediations"]
    publication = values["publication"]
    assert isinstance(subject, PilotSubject)
    assert isinstance(environment, PilotEnvironment)
    assert isinstance(inputs, PilotInputBoundary)
    assert isinstance(commands, tuple) and isinstance(commands[0], PilotCommandExecution)
    assert isinstance(remediations, tuple) and isinstance(
        remediations[0],
        PilotRemediationReference,
    )
    assert isinstance(publication, PilotPublication)
    consent_id = publication.consent_artifact_id
    assert consent_id is not None
    values["subject"] = PilotSubject.model_validate(
        {
            **subject.model_dump(mode="json"),
            "source_revision": "9" * 40,
            "distribution_digest": artifact_by_id[subject.distribution_artifact_id].sha256,
        }
    )
    values["environment"] = PilotEnvironment.model_validate(
        {
            **environment.model_dump(mode="json"),
            "environment_manifest_digest": artifact_by_id[
                environment.environment_manifest_artifact_id
            ].sha256,
        }
    )
    values["inputs"] = PilotInputBoundary.model_validate(
        {
            **inputs.model_dump(mode="json"),
            "configuration_digest": input_manifest.configuration_digest,
            "data_digest": input_manifest.data_digest,
            "input_manifest_digest": artifact_by_id[inputs.input_manifest_artifact_id].sha256,
        }
    )
    values["commands"] = (
        PilotCommandExecution.model_validate(
            {
                **commands[0].model_dump(mode="json"),
                "implementation_source_revision": "9" * 40,
                "tested_distribution_digest": artifact_by_id[
                    commands[0].tested_distribution_artifact_id
                ].sha256,
                "execution_evidence_digest": artifact_by_id[
                    commands[0].execution_evidence_artifact_id
                ].sha256,
            }
        ),
    )
    values["remediations"] = tuple(
        PilotRemediationReference.model_validate(
            {
                **remediation.model_dump(mode="json"),
                "remediation_digest": artifact_by_id[remediation.remediation_artifact_id].sha256,
            }
        )
        for remediation in remediations
    )
    values["publication"] = PilotPublication.model_validate(
        {
            **publication.model_dump(mode="json"),
            "consent_digest": artifact_by_id[publication.consent_artifact_id].sha256,
        }
    )
    values["artifacts"] = tuple(artifacts)
    evidence = ExternalPilotEvidence.build(**values)
    evidence_bytes = _json_bytes(evidence.model_dump(mode="json"))
    (root / EVIDENCE_NAME).write_bytes(evidence_bytes)

    control_id = evidence.environment.control_evidence_artifact_id
    assert control_id is not None
    receipt_values: dict[str, object] = {
        "receipt_id": "pilot-review-001",
        "pilot_id": evidence.pilot_id,
        "pilot_participant_pseudonym": evidence.participant_pseudonym,
        "pilot_evidence_digest": evidence.pilot_evidence_digest,
        "pilot_evidence_file_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "artifact_manifest_digest": pilot_artifact_manifest_digest(evidence.artifacts),
        "environment_control_evidence_artifact_id": control_id,
        "environment_control_evidence_sha256": artifact_by_id[control_id].sha256,
        "publication_consent_artifact_id": consent_id,
        "publication_consent_sha256": artifact_by_id[consent_id].sha256,
        "pilot_execution_source_revision": "9" * 40,
        "pilot_friction_assessment": evidence.friction_assessment,
        "pilot_friction_categories": tuple(
            finding.category for finding in evidence.friction_findings
        ),
        "pilot_remediation_dispositions": tuple(
            remediation.disposition for remediation in evidence.remediations
        ),
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
    if receipt_overrides:
        receipt_values.update(receipt_overrides)
    receipt = ExternalPilotIndependenceReviewReceipt.build(**receipt_values)
    (root / RECEIPT_NAME).write_bytes(_json_bytes(receipt.model_dump(mode="json")))
    return evidence, receipt


def _load(root: Path, *, expected_release: str = "0.6.6rc1") -> object:
    return load_verified_external_pilot_bundle(
        root,
        evidence_path=EVIDENCE_NAME,
        review_receipt_path=RECEIPT_NAME,
        expected_release=expected_release,
    )


def test_verified_bundle_binds_exact_bytes_inventory_distribution_and_review(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    evidence, receipt = _write_bundle(root)

    verified = _load(root)

    assert verified.evidence == evidence
    assert verified.review_receipt == receipt
    assert verified.artifact_manifest_digest == receipt.artifact_manifest_digest
    assert verified.total_bytes == sum(path.stat().st_size for path in root.iterdir())


def test_verified_bundle_cannot_be_constructed_directly() -> None:
    with pytest.raises(TypeError, match="load_verified_external_pilot_bundle"):
        VerifiedExternalPilotBundle()


def test_review_inputs_are_factory_only_and_derive_exact_receipt_bindings(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    evidence, expected_receipt = _write_bundle(root)
    (root / RECEIPT_NAME).unlink()

    with pytest.raises(TypeError, match="load_external_pilot_review_inputs"):
        ValidatedExternalPilotReviewInputs()

    review_inputs = load_external_pilot_review_inputs(
        root,
        evidence_path=EVIDENCE_NAME,
        review_receipt_path=RECEIPT_NAME,
    )
    receipt = build_external_pilot_review_receipt(
        review_inputs,
        receipt_id=expected_receipt.receipt_id,
        reviewer_pseudonym=expected_receipt.reviewer_pseudonym,
        manual_approval_is_trust_root=True,
        reviewer_independent_of_pilot_execution=True,
        reviewer_independence_rationale=(expected_receipt.reviewer_independence_rationale),
        environment_control_evidence_reviewed=True,
        artifact_inventory_reviewed=True,
        tested_distribution_provenance_reviewed=True,
        command_input_bindings_reviewed=True,
        execution_time_input_content_digests_reviewed=True,
        input_semantic_identities_reviewed=True,
        complete_bundle_publication_consent_reviewed=True,
        capture_workflow_run=expected_receipt.capture_workflow_run,
        finalize_workflow_run=expected_receipt.finalize_workflow_run,
        run_head_shas_reviewed=True,
        workflow_run_urls_reviewed=True,
        trusted_workflow_bytes_reviewed=True,
        execution_source_pins_reviewed=True,
        public_workflow_inputs_reviewed=True,
        friction_and_remediation_disposition_reviewed=True,
        friction_category_and_remediation_bindings_reviewed=True,
        privacy_boundary_reviewed=True,
        review_outcome="approved_for_empirical_checkpoint",
        reviewed_at=expected_receipt.reviewed_at,
    )

    assert review_inputs.is_mechanically_verified is True
    assert review_inputs.evidence == evidence
    assert review_inputs.remediation_source_revision == "d" * 40
    assert review_inputs.prior_planned_candidate_evidence_digest == "f" * 64
    assert receipt.pilot_execution_source_revision == evidence.subject.source_revision
    assert receipt.pilot_friction_categories == tuple(
        finding.category for finding in evidence.friction_findings
    )
    assert receipt == expected_receipt


def test_review_receipt_builder_rejects_unissued_inputs() -> None:
    malformed = object.__new__(ValidatedExternalPilotReviewInputs)

    with pytest.raises(TypeError, match="validated review inputs"):
        build_external_pilot_review_receipt(
            malformed,
            receipt_id="pilot-review-001",
            reviewer_pseudonym="release-reviewer-001",
            manual_approval_is_trust_root=True,
            reviewer_independent_of_pilot_execution=True,
            reviewer_independence_rationale="Independent human review completed.",
            environment_control_evidence_reviewed=True,
            artifact_inventory_reviewed=True,
            tested_distribution_provenance_reviewed=True,
            command_input_bindings_reviewed=True,
            execution_time_input_content_digests_reviewed=True,
            input_semantic_identities_reviewed=True,
            complete_bundle_publication_consent_reviewed=True,
            capture_workflow_run=_workflow_run("capture"),
            finalize_workflow_run=_workflow_run("finalize"),
            run_head_shas_reviewed=True,
            workflow_run_urls_reviewed=True,
            trusted_workflow_bytes_reviewed=True,
            execution_source_pins_reviewed=True,
            public_workflow_inputs_reviewed=True,
            friction_and_remediation_disposition_reviewed=True,
            friction_category_and_remediation_bindings_reviewed=True,
            privacy_boundary_reviewed=True,
            review_outcome="approved_for_empirical_checkpoint",
            reviewed_at="2026-09-02T10:00:00Z",
        )


def test_review_inputs_accept_only_an_exact_existing_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    _evidence, _receipt = _write_bundle(root)

    assert load_external_pilot_review_inputs(
        root,
        evidence_path=EVIDENCE_NAME,
        review_receipt_path=RECEIPT_NAME,
    ).is_mechanically_verified

    (root / RECEIPT_NAME).write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        load_external_pilot_review_inputs(
            root,
            evidence_path=EVIDENCE_NAME,
            review_receipt_path=RECEIPT_NAME,
        )


def test_missing_artifact_and_fake_digest_metadata_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    evidence, _receipt = _write_bundle(root)
    missing = evidence.artifacts[0]
    (root / missing.path).unlink()

    with pytest.raises(ValueError, match="inventory"):
        _load(root)


def test_digest_mismatch_and_undeclared_extra_file_fail_closed(tmp_path: Path) -> None:
    mismatch_root = tmp_path / "mismatch"
    evidence, _receipt = _write_bundle(mismatch_root)
    target = next(
        artifact
        for artifact in evidence.artifacts
        if artifact.role is PilotArtifactRole.environment_manifest
    )
    (mismatch_root / target.path).write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest mismatch"):
        _load(mismatch_root)

    extra_root = tmp_path / "extra"
    _write_bundle(extra_root)
    (extra_root / "undeclared.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory"):
        _load(extra_root)


def test_bundle_paths_are_root_confined(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root)

    for path in ("../external-pilot-evidence.json", "/external-pilot-evidence.json"):
        with pytest.raises(ValueError, match="bundle-root child|rooted file path"):
            load_verified_external_pilot_bundle(
                root,
                evidence_path=path,
                review_receipt_path=RECEIPT_NAME,
                expected_release="0.6.6",
            )


def test_symlink_artifact_fails_closed(tmp_path: Path) -> None:
    symlink_root = tmp_path / "symlink"
    evidence, _receipt = _write_bundle(symlink_root)
    target = next(
        artifact
        for artifact in evidence.artifacts
        if artifact.role is PilotArtifactRole.environment_manifest
    )
    external = tmp_path / "external.json"
    external.write_bytes((symlink_root / target.path).read_bytes())
    (symlink_root / target.path).unlink()
    try:
        os.symlink(external, symlink_root / target.path)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises((OSError, ValueError)):
        _load(symlink_root)


def test_hardlink_artifact_fails_closed(tmp_path: Path) -> None:
    hardlink_root = tmp_path / "hardlink"
    hardlink_evidence, _receipt = _write_bundle(hardlink_root)
    hardlink_target = next(
        artifact
        for artifact in hardlink_evidence.artifacts
        if artifact.role is PilotArtifactRole.environment_manifest
    )
    hardlink_source = tmp_path / "hardlink-source.json"
    hardlink_source.write_bytes((hardlink_root / hardlink_target.path).read_bytes())
    (hardlink_root / hardlink_target.path).unlink()
    os.link(hardlink_source, hardlink_root / hardlink_target.path)
    with pytest.raises((OSError, ValueError)):
        _load(hardlink_root)


def test_bundle_aggregate_size_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root)
    monkeypatch.setattr(pilot_bundle, "MAX_PILOT_BUNDLE_TOTAL_BYTES", 16)

    with pytest.raises(ValueError, match="maximum supported size"):
        _load(root)


def test_unknown_schema_contract_and_sensitive_text_fail_closed(tmp_path: Path) -> None:
    contract_root = tmp_path / "contract"
    _write_bundle(
        contract_root,
        artifact_contract_overrides={"artifact-control": "UnknownContract/v1"},
    )
    with pytest.raises(ValueError, match="unsupported schema contract"):
        _load(contract_root)

    privacy_root = tmp_path / "privacy"
    _write_bundle(
        privacy_root,
        artifact_content_overrides={"artifact-control": b"https://example.invalid/control?sig=x\n"},
    )
    with pytest.raises(ValueError, match="privacy review"):
        _load(privacy_root)

    key_privacy_root = tmp_path / "key-privacy"
    _write_bundle(
        key_privacy_root,
        artifact_content_overrides={
            "artifact-control": _json_bytes(
                {
                    "nested": {
                        "https://example.invalid/control?sig=x": "benign",
                    }
                }
            )
        },
    )
    with pytest.raises(ValueError, match="privacy review"):
        _load(key_privacy_root)

    multiline_privacy_root = tmp_path / "multiline-privacy"
    _write_bundle(
        multiline_privacy_root,
        artifact_content_overrides={"artifact-control": b"api_key\n=\nhunter2\n"},
    )
    with pytest.raises(ValueError, match="privacy review"):
        _load(multiline_privacy_root)


def test_empty_metadata_evidence_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(
        root,
        artifact_content_overrides={"artifact-control": b"\n\t"},
    )

    with pytest.raises(ValueError, match="must not be empty"):
        _load(root)


def test_arbitrary_bytes_cannot_claim_to_be_tested_distribution(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, distribution_bytes=b"not-a-wheel")

    with pytest.raises(ValueError, match="valid wheel"):
        _load(root)


def test_shared_artifact_validator_applies_strong_wheel_privacy_rules() -> None:
    wheel = _wheel_bytes(extra_members={"agent_assure/leaked.py": b'api_key = "hunter2-value"\n'})
    artifact = PilotArtifactDigest(
        artifact_id="artifact-distribution",
        path=WHEEL_NAME,
        role=PilotArtifactRole.tested_distribution,
        sha256=hashlib.sha256(wheel).hexdigest(),
        content_scope=PilotArtifactContentScope.distribution_binary,
        schema_validated=False,
        schema_contract=None,
        producing_command_id=None,
    )

    with pytest.raises(ValueError, match="privacy review"):
        validate_external_pilot_artifact_bytes(
            artifact,
            wheel,
            implementation_id="agent-assure",
            implementation_version="0.6.6",
        )


def test_shared_artifact_validator_applies_metadata_privacy_rules() -> None:
    metadata = b"https://example.invalid/control?sig=x\n"
    artifact = PilotArtifactDigest(
        artifact_id="artifact-control",
        path="control.txt",
        role=PilotArtifactRole.environment_control_evidence,
        sha256=hashlib.sha256(metadata).hexdigest(),
        content_scope=PilotArtifactContentScope.metadata_only,
        schema_validated=False,
        schema_contract=None,
        producing_command_id=None,
    )

    with pytest.raises(ValueError, match="privacy review"):
        validate_external_pilot_artifact_bytes(
            artifact,
            metadata,
            implementation_id="agent-assure",
            implementation_version="0.6.6",
        )


def test_corrupt_wheel_member_fails_with_normalized_validation_error(
    tmp_path: Path,
) -> None:
    wheel = bytearray(_wheel_bytes(compression=zipfile.ZIP_STORED))
    metadata_offset = wheel.index(b"Metadata-Version")
    wheel[metadata_offset] ^= 1
    root = tmp_path / "bundle"
    _write_bundle(root, distribution_bytes=bytes(wheel))

    with pytest.raises(ValueError, match="malformed"):
        _load(root)


def test_corrupt_deflate_stream_fails_with_normalized_validation_error(
    tmp_path: Path,
) -> None:
    wheel = bytearray(_wheel_bytes(compression=zipfile.ZIP_DEFLATED))
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        metadata = archive.getinfo("agent_assure-0.6.6.dist-info/METADATA")
        name_length, extra_length = struct.unpack_from("<HH", wheel, metadata.header_offset + 26)
        compressed_offset = metadata.header_offset + 30 + name_length + extra_length
    wheel[compressed_offset] ^= 0xFF
    root = tmp_path / "bundle"
    _write_bundle(root, distribution_bytes=bytes(wheel))

    with pytest.raises(ValueError, match="wheel member is malformed"):
        _load(root)


def test_wheel_metadata_tags_must_match_filename(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, distribution_bytes=_wheel_bytes(wheel_tag="cp311-none-any"))

    with pytest.raises(ValueError, match="compatibility tags differ"):
        _load(root)


@pytest.mark.parametrize(
    ("member_name", "error"),
    (
        ("agent_assure/.env", "credential-bearing member path"),
        ("agent_assure/leaked.py", "privacy review"),
        ("unapproved_package/backdoor.py", "outside approved package roots"),
    ),
)
def test_wheel_members_are_confined_and_cannot_carry_secret_files(
    tmp_path: Path,
    member_name: str,
    error: str,
) -> None:
    root = tmp_path / member_name.replace("/", "-").replace(".", "-")
    wheel = _wheel_bytes(extra_members={member_name: b'api_key = "hunter2-value"\n'})
    _write_bundle(root, distribution_bytes=wheel)

    with pytest.raises(ValueError, match=error):
        _load(root)


def test_wheel_scanner_allows_credential_handling_code_and_schema_vocabulary(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    wheel = _wheel_bytes(
        extra_members={
            "agent_assure/credential_handler.py": (
                b"expected_token = hmac_sha256_token(value, key=key, context=context)\n"
            ),
            "agent_assure/schema_resources/example.schema.json": (
                b'{"properties":{"api_key":{"type":"string"}},"type":"object"}\n'
            ),
        }
    )
    _write_bundle(root, distribution_bytes=wheel)

    assert isinstance(_load(root), VerifiedExternalPilotBundle)


def test_external_pilot_wheel_rejects_unknown_undecodable_binary_member(
    tmp_path: Path,
) -> None:
    root = tmp_path / "binary-leak"
    wheel = _wheel_bytes(
        extra_members={
            "agent_assure/provider-response.bin": b"api_key=hunter2-value\xff",
        }
    )
    _write_bundle(root, distribution_bytes=wheel)

    with pytest.raises(ValueError, match="closed text inventory|unsupported binary"):
        _load(root)


def test_external_pilot_wheel_rejects_credential_literal_in_member_name(
    tmp_path: Path,
) -> None:
    root = tmp_path / "credential-name-leak"
    wheel = _wheel_bytes(
        extra_members={
            "agent_assure/sk-proj-abcdefghijklmnopqrstuvwxyz.py": b"pass\n",
        }
    )
    _write_bundle(root, distribution_bytes=wheel)

    with pytest.raises(ValueError, match="credential-literal privacy review"):
        _load(root)


@pytest.mark.parametrize(
    "metadata_kind",
    ("archive-comment", "member-comment", "member-extra"),
)
def test_external_pilot_wheel_rejects_unscanned_metadata_channels(
    tmp_path: Path,
    metadata_kind: str,
) -> None:
    root = tmp_path / metadata_kind
    _write_bundle(root, distribution_bytes=_wheel_bytes(metadata_kind=metadata_kind))

    with pytest.raises(ValueError, match="comments|extra fields"):
        _load(root)


def test_wheel_structural_privacy_scan_has_an_aggregate_line_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pilot_bundle, "MAX_PILOT_WHEEL_STRUCTURAL_SCAN_LINES", 3)
    root = tmp_path / "line-budget"
    wheel = _wheel_bytes(extra_members={"agent_assure/metadata.txt": b"one\ntwo\nthree\nfour\n"})
    _write_bundle(root, distribution_bytes=wheel)

    with pytest.raises(ValueError, match="privacy-scan line limit"):
        _load(root)


def test_python_wheel_members_are_charged_to_the_aggregate_line_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pilot_bundle, "MAX_PILOT_WHEEL_STRUCTURAL_SCAN_LINES", 1)
    root = tmp_path / "python-line-budget"
    _write_bundle(root)

    with pytest.raises(ValueError, match="structural privacy-scan line limit"):
        _load(root)


@pytest.mark.parametrize(
    ("limit_name", "limit", "source", "error"),
    (
        ("MAX_PILOT_WHEEL_PYTHON_MEMBER_BYTES", 1, b"x = 1\n", "byte limit"),
        ("MAX_PILOT_WHEEL_PYTHON_MEMBER_LINES", 1, b"x = 1\n", "line limit"),
        ("MAX_PILOT_WHEEL_PYTHON_MEMBER_TOKENS", 1, b"x = 1\n", "token limit"),
    ),
)
def test_python_wheel_member_resource_limits_apply_before_ast_parse(
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
    source: bytes,
    error: str,
) -> None:
    ast_called = False

    def unexpected_ast_parse(_source: str) -> object:
        nonlocal ast_called
        ast_called = True
        raise AssertionError("AST parsing must occur only after resource checks")

    monkeypatch.setattr(pilot_bundle, limit_name, limit)
    monkeypatch.setattr(pilot_bundle.ast, "parse", unexpected_ast_parse)

    with pytest.raises(ValueError, match=error):
        pilot_bundle._validate_wheel_member_privacy(
            "agent_assure/large.py",
            source,
            max_structural_scan_lines=100,
        )

    assert ast_called is False


def test_workflow_argv_must_match_the_exact_typed_input_manifest(tmp_path: Path) -> None:
    manifest = PilotInputManifest.build(
        workflow_id="controls-mutate",
        entries=(
            PilotInputManifestEntry(
                entry_id="input-suite",
                input_kind=PilotInputKind.configuration,
                origin=PilotInputOrigin.non_bundled,
                option_name="suite",
                option_value="different-suite.yaml",
                content_sha256="c" * 64,
                semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
                semantic_identity_digest="c" * 64,
            ),
            PilotInputManifestEntry(
                entry_id="input-runset",
                input_kind=PilotInputKind.data,
                origin=PilotInputOrigin.non_bundled,
                option_name="runset",
                option_value="pilot-runset.json",
                content_sha256="d" * 64,
                semantic_identity_kind=PilotInputIdentityKind.run_set,
                semantic_identity_digest="d" * 64,
            ),
        ),
    )
    root = tmp_path / "input-mismatch"
    _write_bundle(root, input_manifest_override=manifest)

    with pytest.raises(ValueError, match="do not exactly match its argv inputs"):
        _load(root)


def test_mixed_origin_boundary_exactly_matches_concrete_manifest_entries() -> None:
    manifest = PilotInputManifest.build(
        workflow_id="controls-mutate",
        entries=(
            PilotInputManifestEntry(
                entry_id="input-suite",
                input_kind=PilotInputKind.configuration,
                origin=PilotInputOrigin.bundled,
                option_name="suite",
                option_value="pilot-suite.yaml",
                content_sha256="c" * 64,
                semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
                semantic_identity_digest="c" * 64,
            ),
            PilotInputManifestEntry(
                entry_id="input-waiver",
                input_kind=PilotInputKind.configuration,
                origin=PilotInputOrigin.non_bundled,
                option_name="waiver",
                option_value="pilot-waiver.yaml",
                content_sha256="e" * 64,
                semantic_identity_kind=PilotInputIdentityKind.waiver_set,
                semantic_identity_digest="e" * 64,
            ),
            PilotInputManifestEntry(
                entry_id="input-runset",
                input_kind=PilotInputKind.data,
                origin=PilotInputOrigin.non_bundled,
                option_name="runset",
                option_value="pilot-runset.json",
                content_sha256="d" * 64,
                semantic_identity_kind=PilotInputIdentityKind.run_set,
                semantic_identity_digest="d" * 64,
            ),
        ),
    )
    values = _values()
    commands = values["commands"]
    assert isinstance(commands, tuple) and isinstance(commands[0], PilotCommandExecution)
    command = PilotCommandExecution.model_validate(
        {
            **commands[0].model_dump(mode="json"),
            "argv": (*commands[0].argv, "--waiver", "pilot-waiver.yaml"),
            "consumed_input_entry_ids": (
                "input-runset",
                "input-suite",
                "input-waiver",
            ),
        }
    )
    values["commands"] = (command,)
    values["inputs"] = PilotInputBoundary(
        configuration_origin=PilotInputOrigin.mixed_bundled_non_bundled,
        configuration_digest=manifest.configuration_digest,
        data_origin=PilotInputOrigin.non_bundled,
        data_digest=manifest.data_digest,
        input_manifest_artifact_id="artifact-input",
        input_manifest_digest="5" * 64,
    )
    evidence = ExternalPilotEvidence.build(**values)
    artifact = next(
        item for item in evidence.artifacts if item.role is PilotArtifactRole.input_manifest
    )

    assert (
        pilot_bundle._validate_input_manifest(
            artifact,
            _json_bytes(manifest.model_dump(mode="json")),
            evidence=evidence,
        )
        == manifest
    )

    bad_inputs = PilotInputBoundary.model_validate(
        {
            **evidence.inputs.model_dump(mode="json"),
            "configuration_origin": "non_bundled",
        }
    )
    bad_evidence = ExternalPilotEvidence.build(
        **{
            **values,
            "inputs": bad_inputs,
        }
    )
    with pytest.raises(ValueError, match="origins do not match"):
        pilot_bundle._validate_input_manifest(
            artifact,
            _json_bytes(manifest.model_dump(mode="json")),
            evidence=bad_evidence,
        )


def _campaign_input_manifest(
    *,
    suite_digest: str,
    runset_digest: str,
) -> PilotInputManifest:
    return PilotInputManifest.build(
        workflow_id="controls-mutate",
        entries=(
            PilotInputManifestEntry(
                entry_id="input-suite",
                input_kind=PilotInputKind.configuration,
                origin=PilotInputOrigin.non_bundled,
                option_name="suite",
                option_value="pilot-suite.yaml",
                content_sha256="c" * 64,
                semantic_identity_kind=PilotInputIdentityKind.compiled_suite,
                semantic_identity_digest=suite_digest,
            ),
            PilotInputManifestEntry(
                entry_id="input-runset",
                input_kind=PilotInputKind.data,
                origin=PilotInputOrigin.non_bundled,
                option_name="runset",
                option_value="pilot-runset.json",
                content_sha256="d" * 64,
                semantic_identity_kind=PilotInputIdentityKind.run_set,
                semantic_identity_digest=runset_digest,
            ),
        ),
    )


def test_campaign_output_must_bind_exact_semantic_input_identities() -> None:
    suite, source = _mutation_fixture()
    campaign = _mutation_campaign(suite, source, seed=17).campaign
    evidence = _external_evidence(
        attempt_status="completed",
        artifacts=_artifacts(),
    )
    matching = _campaign_input_manifest(
        suite_digest=campaign.suite_digest,
        runset_digest=campaign.source_digest,
    )
    output_payloads = {"artifact-output": campaign.model_dump(mode="json")}

    pilot_bundle._validate_assurance_output_input_bindings(
        evidence,
        matching,
        output_payloads,
    )

    unrelated = _campaign_input_manifest(
        suite_digest="f" * 64,
        runset_digest=campaign.source_digest,
    )
    with pytest.raises(ValueError, match="do not match command inputs"):
        pilot_bundle._validate_assurance_output_input_bindings(
            evidence,
            unrelated,
            output_payloads,
        )


def test_single_mutation_result_fails_closed_when_suite_identity_is_unexposed() -> None:
    suite, source = _mutation_fixture()
    campaign = _mutation_campaign(suite, source, seed=17).campaign
    result = campaign.operator_results[0].result
    values = _values()
    commands = values["commands"]
    assert isinstance(commands, tuple) and isinstance(commands[0], PilotCommandExecution)
    original_argv = commands[0].argv
    catalog_index = original_argv.index("--catalog")
    single_operator_argv = (
        *original_argv[:catalog_index],
        *original_argv[catalog_index + 2 :],
        "--operator",
        result.operator_id,
    )
    command = PilotCommandExecution.model_validate(
        {
            **commands[0].model_dump(mode="json"),
            "argv": single_operator_argv,
        }
    )
    evidence = _external_evidence(
        attempt_status="completed",
        commands=(command,),
        artifacts=_artifacts(output_contract="AssuranceMutationResult/v1"),
    )
    manifest = _campaign_input_manifest(
        suite_digest=campaign.suite_digest,
        runset_digest=campaign.source_digest,
    )

    with pytest.raises(ValueError, match="does not expose the consumed suite identity"):
        pilot_bundle._validate_assurance_output_input_bindings(
            evidence,
            manifest,
            {"artifact-output": result.model_dump(mode="json")},
        )


def test_remediation_record_source_and_prior_digest_are_bound_to_the_receipt(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    _write_bundle(
        root,
        artifact_content_overrides={
            "artifact-remediation": _json_bytes(
                {
                    "artifact_kind": "external-pilot-remediation-record",
                    "contract_id": "ExternalPilotRemediationRecord/v1",
                    "pilot_id": "external-controls-pilot-001",
                    "friction_category": "diagnostics",
                    "disposition": "applied",
                    "remediation_source_revision": "e" * 40,
                    "prior_planned_candidate_evidence_digest": "a" * 64,
                }
            )
        },
    )

    with pytest.raises(ValueError, match="does not bind the exact bundle"):
        _load(root)


def test_remediation_record_category_is_bound_to_its_friction_finding(
    tmp_path: Path,
) -> None:
    root = tmp_path / "bundle"
    _write_bundle(
        root,
        artifact_content_overrides={
            "artifact-remediation": _json_bytes(
                {
                    "artifact_kind": "external-pilot-remediation-record",
                    "contract_id": "ExternalPilotRemediationRecord/v1",
                    "pilot_id": "external-controls-pilot-001",
                    "friction_category": "runtime",
                    "disposition": "applied",
                    "remediation_source_revision": "d" * 40,
                    "prior_planned_candidate_evidence_digest": "f" * 64,
                }
            )
        },
    )

    with pytest.raises(ValueError, match="category does not match its finding"):
        _load(root)


@pytest.mark.parametrize(
    "receipt_overrides",
    (
        {"pilot_id": "wrong-pilot"},
        {"expected_release_line": "0.6.5"},
        {"artifact_manifest_digest": "f" * 64},
        {"environment_control_evidence_sha256": "e" * 64},
        {"publication_consent_sha256": "d" * 64},
        {"reviewed_at": "2026-08-31T23:59:59Z"},
    ),
)
def test_stale_or_misbound_review_receipt_fails_closed(
    tmp_path: Path,
    receipt_overrides: dict[str, object],
) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, receipt_overrides=receipt_overrides)

    with pytest.raises(ValueError, match="does not bind|predates"):
        _load(root)


def test_retained_file_pins_detect_swap_after_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "bundle"
    evidence, _receipt = _write_bundle(root)
    target = next(
        artifact
        for artifact in evidence.artifacts
        if artifact.role is PilotArtifactRole.environment_manifest
    )
    original = pilot_bundle._validate_review_binding

    def swap_after_review(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)
        (root / target.path).write_bytes(b"swapped-after-review")

    monkeypatch.setattr(pilot_bundle, "_validate_review_binding", swap_after_review)
    with pytest.raises((OSError, ValueError)):
        _load(root)
