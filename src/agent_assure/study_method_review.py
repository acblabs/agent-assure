"""Verification for qualified, independent statistical-method review."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.privacy.persistence import assert_persisted_payload_safe
from agent_assure.schema.benchmark import (
    ProcessEquivalenceBenchmarkManifest,
    registered_confirmatory_benchmark_bar_reason,
)
from agent_assure.schema.stochastic_sensitivity import RepeatedEvidenceSensitivityProtocol
from agent_assure.schema.study import (
    RealModelStudyManifest,
    StudyExecutionOrigin,
    StudyFixedFrameDescriptiveRule,
    StudyHypothesisDecisionRule,
    StudyInferenceScope,
    StudyMethodReviewApprovalDisposition,
    StudyRegistrationReviewReceipt,
    StudyReviewerQualificationBasisType,
    StudyStatisticalMethodReviewCondition,
    StudyStatisticalMethodReviewReceipt,
    require_resolved_independence_justification,
)
from agent_assure.study_artifact_serialization import (
    published_model_json_bytes,
    require_published_model_json_bytes,
)
from agent_assure.study_registration import validate_study_registration
from agent_assure.timestamps import parse_rfc3339_timestamp

STUDY_INDEPENDENCE_AUDIT_FILENAME = "study-independence-audit.md"


def _study_design_audit_binding(
    manifest: RealModelStudyManifest,
) -> tuple[str, object, object, str, str]:
    rule = manifest.hypothesis_decision_rule
    if isinstance(rule, StudyHypothesisDecisionRule):
        justification = rule.independence_justification
        require_resolved_independence_justification(justification)
        digest = justification.design_audit_artifact_sha256
        if digest is None:  # pragma: no cover - resolved model invariant
            raise ValueError("study design audit bytes were supplied without a manifest commitment")
        return (
            digest,
            justification.design_basis,
            justification.semantic_near_duplicate_disposition,
            justification.independence_basis,
            justification.dependence_risks_and_mitigations,
        )
    if isinstance(rule, StudyFixedFrameDescriptiveRule):
        acknowledgement = rule.dependence_acknowledgement
        return (
            acknowledgement.dependence_audit_artifact_sha256,
            acknowledgement.design_basis,
            acknowledgement.semantic_near_duplicate_disposition,
            acknowledgement.dependence_basis,
            acknowledgement.dependence_risks_and_mitigations,
        )
    raise TypeError("unsupported study decision-rule type")


@dataclass(frozen=True, slots=True)
class ValidatedStudyIndependenceAuditArtifact:
    """Exact, privacy-checked audit bytes bound by the study manifest.

    Validation establishes byte identity and persistence safety only. It does
    not establish that the audit's reasoning or independence claim is true.
    """

    data: bytes
    text: str
    artifact_sha256: str


def validate_study_independence_audit_artifact(
    *,
    manifest: RealModelStudyManifest,
    artifact_bytes: bytes | None,
) -> ValidatedStudyIndependenceAuditArtifact | None:
    """Validate the exact persisted audit artifact committed by ``manifest``."""

    expected_digest = _study_design_audit_binding(manifest)[0]
    if artifact_bytes is None:
        raise ValueError("study manifest requires the digest-bound independence audit bytes")
    if type(artifact_bytes) is not bytes:
        raise TypeError("study independence audit artifact must be supplied as exact bytes")
    if not artifact_bytes:
        raise ValueError("study independence audit artifact must not be empty")
    if len(artifact_bytes) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError("study independence audit artifact exceeds the supported byte limit")
    try:
        text = artifact_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("study independence audit artifact must be valid UTF-8") from exc
    if not text.strip():
        raise ValueError("study independence audit artifact must contain substantive text")
    assert_persisted_payload_safe(
        {"content": text},
        owner="study independence audit artifact",
    )
    artifact_sha256 = sha256(artifact_bytes).hexdigest()
    if artifact_sha256 != expected_digest:
        raise ValueError("study independence audit artifact digest does not match the manifest")
    return ValidatedStudyIndependenceAuditArtifact(
        data=artifact_bytes,
        text=text,
        artifact_sha256=artifact_sha256,
    )


@dataclass(frozen=True, slots=True)
class ValidatedStudyStatisticalMethodReview:
    """A receipt proven to bind the exact preregistered design artifacts."""

    receipt: StudyStatisticalMethodReviewReceipt


def statistical_method_review_explicitly_approves_confirmatory_benchmark(
    *,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    review_receipt: StudyStatisticalMethodReviewReceipt,
    benchmark_bytes: bytes | None = None,
) -> bool:
    """Return whether one positive review decision binds the exact benchmark.

    This is a byte-and-field consistency decision, not reviewer authentication.
    The reviewer identity authentication field is intentionally fixed by the
    receipt schema to out_of_band_not_machine_verified. A repository-governed
    caller must separately establish that the receipt came from its trusted path.
    """

    exact_benchmark_bytes = require_published_model_json_bytes(
        benchmark_bytes,
        benchmark,
        label="confirmatory benchmark",
    )
    return bool(
        registered_confirmatory_benchmark_bar_reason(benchmark) is None
        and review_receipt.approved_inference_scope
        is StudyInferenceScope.confirmatory_independent_clusters
        and review_receipt.approval_disposition
        is StudyMethodReviewApprovalDisposition.approved_confirmatory_independent_clusters
        and review_receipt.benchmark_digest == benchmark.benchmark_digest
        and review_receipt.benchmark_sha256 == sha256(exact_benchmark_bytes).hexdigest()
        and review_receipt.design_audit_artifact_sha256 is not None
        and review_receipt.design_basis_reviewed_and_accepted
        and review_receipt.semantic_near_duplicate_audit_reviewed
        and review_receipt.semantic_near_duplicate_pseudoreplication_rejected
        and review_receipt.independence_and_exchangeability_assumptions_reviewed is True
        and review_receipt.multiplicity_and_interval_method_reviewed is True
        and review_receipt.combined_directional_decision_error_control_reviewed is True
        and review_receipt.power_and_decision_boundary_reachability_reviewed is True
        and review_receipt.reviewer_identity_authentication == "out_of_band_not_machine_verified"
    )


def build_study_statistical_method_review_receipt(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    registration_record_bytes: bytes,
    registration_review_receipt: StudyRegistrationReviewReceipt,
    independence_audit_artifact_bytes: bytes,
    receipt_id: str,
    reviewed_at_utc: str,
    reviewer_pseudonym: str,
    reviewer_statistical_qualification_confirmed: Literal[True],
    reviewer_qualification_basis_types: tuple[StudyReviewerQualificationBasisType, ...],
    reviewer_qualification_evidence_digest: str,
    reviewer_qualification_basis: str,
    reviewer_independent_of_design_execution_and_analysis: Literal[True],
    reviewer_independence_rationale: str,
    design_basis_reviewed_and_accepted: Literal[True],
    design_review_rationale: str,
    semantic_near_duplicate_audit_reviewed: Literal[True],
    semantic_near_duplicate_pseudoreplication_rejected: Literal[True],
    semantic_near_duplicate_review_rationale: str,
    benchmark_cluster_assignments_reviewed: Literal[True],
    independence_and_exchangeability_assumptions_reviewed: Literal[True] | None = None,
    sampling_frame_and_estimand_reviewed: Literal[True],
    multiplicity_and_interval_method_reviewed: Literal[True] | None = None,
    combined_directional_decision_error_control_reviewed: Literal[True] | None = None,
    power_and_decision_boundary_reachability_reviewed: Literal[True] | None = None,
    fixed_frame_completeness_reviewed: Literal[True] | None = None,
    descriptive_count_and_rate_derivation_reviewed: Literal[True] | None = None,
    population_inference_prohibition_reviewed: Literal[True] | None = None,
    negative_control_design_reviewed: Literal[True],
) -> StudyStatisticalMethodReviewReceipt:
    """Build a self-digested approval bound to the exact registered design."""

    (
        _expected_audit_digest,
        design_basis,
        duplicate_disposition,
        _author_design_basis,
        _author_dependence_risks,
    ) = _study_design_audit_binding(manifest)
    registration = validate_study_registration(
        manifest=manifest,
        registration_record_bytes=registration_record_bytes,
        review_receipt=registration_review_receipt,
    )
    inference_scope = manifest.hypothesis_decision_rule.inference_scope
    validated_audit = validate_study_independence_audit_artifact(
        manifest=manifest,
        artifact_bytes=independence_audit_artifact_bytes,
    )
    if validated_audit is None:  # pragma: no cover - resolved schema invariant
        raise ValueError("statistical-method review requires a digest-bound independence audit")
    audit_digest = validated_audit.artifact_sha256
    approval_disposition = (
        StudyMethodReviewApprovalDisposition.approved_confirmatory_independent_clusters
        if inference_scope is StudyInferenceScope.confirmatory_independent_clusters
        else StudyMethodReviewApprovalDisposition.approved_fixed_frame_descriptive_conformance
    )
    scope_attestations: dict[str, object]
    if inference_scope is StudyInferenceScope.confirmatory_independent_clusters:
        if any(
            value is not None
            for value in (
                fixed_frame_completeness_reviewed,
                descriptive_count_and_rate_derivation_reviewed,
                population_inference_prohibition_reviewed,
            )
        ):
            raise ValueError("confirmatory review cannot include descriptive-only attestations")
        scope_attestations = {
            "independence_and_exchangeability_assumptions_reviewed": (
                independence_and_exchangeability_assumptions_reviewed
            ),
            "multiplicity_and_interval_method_reviewed": (
                multiplicity_and_interval_method_reviewed
            ),
            "combined_directional_decision_error_control_reviewed": (
                combined_directional_decision_error_control_reviewed
            ),
            "power_and_decision_boundary_reachability_reviewed": (
                power_and_decision_boundary_reachability_reviewed
            ),
        }
    else:
        if any(
            value is not None
            for value in (
                independence_and_exchangeability_assumptions_reviewed,
                multiplicity_and_interval_method_reviewed,
                combined_directional_decision_error_control_reviewed,
                power_and_decision_boundary_reachability_reviewed,
            )
        ):
            raise ValueError("descriptive review cannot include confirmatory attestations")
        scope_attestations = {
            "fixed_frame_completeness_reviewed": fixed_frame_completeness_reviewed,
            "descriptive_count_and_rate_derivation_reviewed": (
                descriptive_count_and_rate_derivation_reviewed
            ),
            "population_inference_prohibition_reviewed": (
                population_inference_prohibition_reviewed
            ),
        }
    receipt = StudyStatisticalMethodReviewReceipt.build(
        receipt_id=receipt_id,
        study_id=manifest.study_id,
        study_manifest_digest=manifest.manifest_digest,
        registration_review_receipt_digest=(registration.review_receipt.review_receipt_digest),
        study_manifest_sha256=sha256(published_model_json_bytes(manifest)).hexdigest(),
        benchmark_digest=benchmark.benchmark_digest,
        benchmark_sha256=sha256(published_model_json_bytes(benchmark)).hexdigest(),
        protocol_set_digest=manifest.protocol_set_digest,
        hypothesis_decision_rule_digest=manifest.hypothesis_decision_rule_digest,
        registered_at_utc=manifest.registration.registered_at_utc,
        execution_window_start_utc=manifest.execution_window.start,
        reviewed_at_utc=reviewed_at_utc,
        reviewer_pseudonym=reviewer_pseudonym,
        reviewer_statistical_qualification_confirmed=(reviewer_statistical_qualification_confirmed),
        reviewer_qualification_basis_types=reviewer_qualification_basis_types,
        reviewer_qualification_evidence_digest=reviewer_qualification_evidence_digest,
        reviewer_qualification_basis=reviewer_qualification_basis,
        reviewer_independent_of_design_execution_and_analysis=(
            reviewer_independent_of_design_execution_and_analysis
        ),
        reviewer_independence_rationale=reviewer_independence_rationale,
        approved_inference_scope=inference_scope,
        design_basis=design_basis,
        design_audit_artifact_sha256=audit_digest,
        design_basis_reviewed_and_accepted=(design_basis_reviewed_and_accepted),
        design_review_rationale=design_review_rationale,
        semantic_near_duplicate_disposition=duplicate_disposition,
        semantic_near_duplicate_audit_reviewed=semantic_near_duplicate_audit_reviewed,
        semantic_near_duplicate_pseudoreplication_rejected=(
            semantic_near_duplicate_pseudoreplication_rejected
        ),
        semantic_near_duplicate_review_rationale=semantic_near_duplicate_review_rationale,
        conditions=_expected_conditions(manifest=manifest, protocols=protocols),
        benchmark_cluster_assignments_reviewed=benchmark_cluster_assignments_reviewed,
        sampling_frame_and_estimand_reviewed=sampling_frame_and_estimand_reviewed,
        negative_control_design_reviewed=negative_control_design_reviewed,
        approval_disposition=approval_disposition,
        **scope_attestations,
    )
    validate_study_statistical_method_review(
        manifest=manifest,
        benchmark=benchmark,
        protocols=protocols,
        registration_record_bytes=registration_record_bytes,
        registration_review_receipt=registration.review_receipt,
        review_receipt=receipt,
        independence_audit_artifact_bytes=validated_audit.data,
    )
    return receipt


def validate_study_statistical_method_review(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    registration_record_bytes: bytes,
    registration_review_receipt: StudyRegistrationReviewReceipt,
    review_receipt: StudyStatisticalMethodReviewReceipt,
    independence_audit_artifact_bytes: bytes,
    manifest_bytes: bytes | None = None,
    benchmark_bytes: bytes | None = None,
    registered_protocol_bytes: Mapping[str, bytes] | None = None,
) -> ValidatedStudyStatisticalMethodReview:
    """Verify that a human approval names the exact frozen statistical design.

    Mechanical validation proves byte identity, design closure, and temporal
    ordering. It deliberately cannot authenticate the reviewer or independently
    verify the human assertions about qualifications and independence.
    """

    from agent_assure.study.analysis import validate_study_manifest_inputs

    registration = validate_study_registration(
        manifest=manifest,
        registration_record_bytes=registration_record_bytes,
        review_receipt=registration_review_receipt,
    )
    receipt = StudyStatisticalMethodReviewReceipt.model_validate(
        review_receipt.model_dump(mode="json", warnings="error")
    )
    assert_persisted_payload_safe(
        receipt.model_dump(mode="json", warnings="error"),
        owner="study statistical-method review receipt",
    )
    manifest = RealModelStudyManifest.model_validate(
        manifest.model_dump(mode="json", warnings="error")
    )
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(
        benchmark.model_dump(mode="json", warnings="error")
    )
    protocols = {
        condition_id: RepeatedEvidenceSensitivityProtocol.model_validate(
            protocol.model_dump(mode="json", warnings="error")
        )
        for condition_id, protocol in protocols.items()
    }
    (
        _expected_audit_digest,
        design_basis,
        duplicate_disposition,
        author_design_basis,
        author_dependence_risks,
    ) = _study_design_audit_binding(manifest)
    validated_audit = validate_study_independence_audit_artifact(
        manifest=manifest,
        artifact_bytes=independence_audit_artifact_bytes,
    )
    if validated_audit is None:  # pragma: no cover - resolved schema invariant
        raise ValueError("statistical-method review requires a digest-bound independence audit")
    audit_digest = validated_audit.artifact_sha256
    expected_approval_disposition = (
        StudyMethodReviewApprovalDisposition.approved_confirmatory_independent_clusters
        if manifest.hypothesis_decision_rule.inference_scope
        is StudyInferenceScope.confirmatory_independent_clusters
        else StudyMethodReviewApprovalDisposition.approved_fixed_frame_descriptive_conformance
    )
    if receipt.design_review_rationale == author_design_basis:
        raise ValueError(
            "qualified review rationale must add independent analysis, not copy the author basis"
        )
    if receipt.semantic_near_duplicate_review_rationale == author_dependence_risks:
        raise ValueError(
            "near-duplicate review rationale must add independent analysis, not copy author prose"
        )
    validate_study_manifest_inputs(manifest, benchmark, protocols)
    expected_conditions = _expected_conditions(
        manifest=manifest,
        protocols=protocols,
        registered_protocol_bytes=registered_protocol_bytes,
    )
    expected_manifest_sha256 = sha256(
        require_published_model_json_bytes(
            manifest_bytes,
            manifest,
            label="study manifest",
        )
    ).hexdigest()
    expected_benchmark_sha256 = sha256(
        require_published_model_json_bytes(
            benchmark_bytes,
            benchmark,
            label="study benchmark",
        )
    ).hexdigest()
    if (
        receipt.study_id,
        receipt.study_manifest_digest,
        receipt.registration_review_receipt_digest,
        receipt.study_manifest_sha256,
        receipt.benchmark_digest,
        receipt.benchmark_sha256,
        receipt.protocol_set_digest,
        receipt.hypothesis_decision_rule_digest,
        receipt.registered_at_utc,
        receipt.execution_window_start_utc,
        receipt.approved_inference_scope,
        receipt.design_basis,
        receipt.design_audit_artifact_sha256,
        receipt.semantic_near_duplicate_disposition,
        receipt.approval_disposition,
        receipt.conditions,
    ) != (
        manifest.study_id,
        manifest.manifest_digest,
        registration.review_receipt.review_receipt_digest,
        expected_manifest_sha256,
        benchmark.benchmark_digest,
        expected_benchmark_sha256,
        manifest.protocol_set_digest,
        manifest.hypothesis_decision_rule_digest,
        manifest.registration.registered_at_utc,
        manifest.execution_window.start,
        manifest.hypothesis_decision_rule.inference_scope,
        design_basis,
        audit_digest,
        duplicate_disposition,
        expected_approval_disposition,
        expected_conditions,
    ):
        raise ValueError(
            "statistical-method review receipt does not exactly bind the manifest, "
            "registration review, benchmark, and registered protocol designs"
        )
    registration_reviewed_at = parse_rfc3339_timestamp(
        registration.review_receipt.reviewed_at_utc,
        field_name="study registration review reviewed_at_utc",
    )
    method_reviewed_at = parse_rfc3339_timestamp(
        receipt.reviewed_at_utc,
        field_name="study statistical-method review reviewed_at_utc",
    )
    if registration_reviewed_at >= method_reviewed_at:
        raise ValueError("study statistical-method review must occur after registration review")
    if (
        manifest.benchmark_digest != benchmark.benchmark_digest
        or manifest.benchmark_id != benchmark.benchmark_id
        or manifest.benchmark_version != benchmark.benchmark_version
    ):
        raise ValueError("statistical-method review benchmark does not match the manifest")
    return ValidatedStudyStatisticalMethodReview(receipt=receipt)


def _expected_conditions(
    *,
    manifest: RealModelStudyManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    registered_protocol_bytes: Mapping[str, bytes] | None = None,
) -> tuple[StudyStatisticalMethodReviewCondition, ...]:
    condition_ids = tuple(item.condition_id for item in manifest.conditions)
    if tuple(sorted(protocols)) != condition_ids:
        raise ValueError("statistical-method review requires the exact manifest condition set")
    if registered_protocol_bytes is not None and (
        tuple(sorted(registered_protocol_bytes)) != condition_ids
    ):
        raise ValueError(
            "statistical-method review protocol-byte inventory does not match study conditions"
        )
    expected: list[StudyStatisticalMethodReviewCondition] = []
    for binding in manifest.conditions:
        protocol = RepeatedEvidenceSensitivityProtocol.model_validate(
            protocols[binding.condition_id].model_dump(mode="json", warnings="error")
        )
        if (
            protocol.execution_attempt_id
            if binding.execution_origin is StudyExecutionOrigin.real_provider
            else None,
            protocol.protocol_digest,
            protocol.design_commitment_digest,
            len(protocol.planned_cluster_ids),
        ) != (
            binding.execution_attempt_id,
            binding.protocol_digest,
            binding.design_commitment_digest,
            binding.planned_clusters,
        ):
            raise ValueError(
                "statistical-method review protocol does not match its manifest binding"
            )
        protocol_bytes = require_published_model_json_bytes(
            (
                registered_protocol_bytes[binding.condition_id]
                if registered_protocol_bytes is not None
                else None
            ),
            protocol,
            label=f"registered protocol {binding.condition_id}",
        )
        expected.append(
            StudyStatisticalMethodReviewCondition(
                condition_id=binding.condition_id,
                analysis_role=binding.analysis_role,
                execution_attempt_id=binding.execution_attempt_id,
                protocol_digest=protocol.protocol_digest,
                design_commitment_digest=protocol.design_commitment_digest,
                registered_protocol_sha256=sha256(protocol_bytes).hexdigest(),
                planned_clusters=binding.planned_clusters,
            )
        )
    return tuple(expected)


__all__ = [
    "STUDY_INDEPENDENCE_AUDIT_FILENAME",
    "ValidatedStudyIndependenceAuditArtifact",
    "ValidatedStudyStatisticalMethodReview",
    "build_study_statistical_method_review_receipt",
    "statistical_method_review_explicitly_approves_confirmatory_benchmark",
    "validate_study_independence_audit_artifact",
    "validate_study_statistical_method_review",
]
