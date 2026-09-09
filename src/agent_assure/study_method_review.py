"""Verification for qualified, independent statistical-method review."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from agent_assure.privacy.persistence import assert_persisted_payload_safe
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.stochastic_sensitivity import RepeatedEvidenceSensitivityProtocol
from agent_assure.schema.study import (
    RealModelStudyManifest,
    StudyExecutionOrigin,
    StudyInferenceScope,
    StudyMethodReviewApprovalDisposition,
    StudyReviewerQualificationBasisType,
    StudyStatisticalMethodReviewCondition,
    StudyStatisticalMethodReviewReceipt,
    require_resolved_independence_justification,
)
from agent_assure.study_artifact_serialization import (
    published_model_json_bytes,
    require_published_model_json_bytes,
)


@dataclass(frozen=True, slots=True)
class ValidatedStudyStatisticalMethodReview:
    """A receipt proven to bind the exact preregistered design artifacts."""

    receipt: StudyStatisticalMethodReviewReceipt


def build_study_statistical_method_review_receipt(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    receipt_id: str,
    reviewed_at_utc: str,
    reviewer_pseudonym: str,
    reviewer_statistical_qualification_confirmed: Literal[True],
    reviewer_qualification_basis_types: tuple[StudyReviewerQualificationBasisType, ...],
    reviewer_qualification_evidence_digest: str,
    reviewer_qualification_basis: str,
    reviewer_independent_of_design_execution_and_analysis: Literal[True],
    reviewer_independence_rationale: str,
    independence_design_basis_reviewed_and_accepted: Literal[True],
    independence_acceptance_rationale: str,
    semantic_near_duplicate_audit_reviewed: Literal[True],
    semantic_near_duplicate_pseudoreplication_rejected: Literal[True],
    semantic_near_duplicate_review_rationale: str,
    benchmark_cluster_assignments_reviewed: Literal[True],
    independence_and_exchangeability_assumptions_reviewed: Literal[True],
    sampling_frame_and_estimand_reviewed: Literal[True],
    multiplicity_and_interval_method_reviewed: Literal[True],
    power_and_decision_boundary_reachability_reviewed: Literal[True],
    negative_control_design_reviewed: Literal[True],
) -> StudyStatisticalMethodReviewReceipt:
    """Build a self-digested approval bound to the exact registered design."""

    justification = manifest.hypothesis_decision_rule.independence_justification
    require_resolved_independence_justification(justification)
    inference_scope = manifest.hypothesis_decision_rule.inference_scope
    audit_digest = justification.independence_audit_artifact_sha256
    if audit_digest is None:
        raise ValueError("statistical-method review requires a digest-bound independence audit")
    approval_disposition = (
        StudyMethodReviewApprovalDisposition.approved_confirmatory_independent_clusters
        if inference_scope is StudyInferenceScope.confirmatory_independent_clusters
        else StudyMethodReviewApprovalDisposition.approved_fixed_frame_descriptive_conformance
    )
    receipt = StudyStatisticalMethodReviewReceipt.build(
        receipt_id=receipt_id,
        study_id=manifest.study_id,
        study_manifest_digest=manifest.manifest_digest,
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
        independence_design_basis=justification.design_basis,
        independence_audit_artifact_sha256=audit_digest,
        independence_design_basis_reviewed_and_accepted=(
            independence_design_basis_reviewed_and_accepted
        ),
        independence_acceptance_rationale=independence_acceptance_rationale,
        semantic_near_duplicate_disposition=(justification.semantic_near_duplicate_disposition),
        semantic_near_duplicate_audit_reviewed=semantic_near_duplicate_audit_reviewed,
        semantic_near_duplicate_pseudoreplication_rejected=(
            semantic_near_duplicate_pseudoreplication_rejected
        ),
        semantic_near_duplicate_review_rationale=semantic_near_duplicate_review_rationale,
        conditions=_expected_conditions(manifest=manifest, protocols=protocols),
        benchmark_cluster_assignments_reviewed=benchmark_cluster_assignments_reviewed,
        independence_and_exchangeability_assumptions_reviewed=(
            independence_and_exchangeability_assumptions_reviewed
        ),
        sampling_frame_and_estimand_reviewed=sampling_frame_and_estimand_reviewed,
        multiplicity_and_interval_method_reviewed=multiplicity_and_interval_method_reviewed,
        power_and_decision_boundary_reachability_reviewed=(
            power_and_decision_boundary_reachability_reviewed
        ),
        negative_control_design_reviewed=negative_control_design_reviewed,
        approval_disposition=approval_disposition,
    )
    validate_study_statistical_method_review(
        manifest=manifest,
        benchmark=benchmark,
        protocols=protocols,
        review_receipt=receipt,
    )
    return receipt


def validate_study_statistical_method_review(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    review_receipt: StudyStatisticalMethodReviewReceipt,
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
    require_resolved_independence_justification(
        manifest.hypothesis_decision_rule.independence_justification
    )
    justification = manifest.hypothesis_decision_rule.independence_justification
    audit_digest = justification.independence_audit_artifact_sha256
    if audit_digest is None:
        raise ValueError("statistical-method review requires a digest-bound independence audit")
    expected_approval_disposition = (
        StudyMethodReviewApprovalDisposition.approved_confirmatory_independent_clusters
        if manifest.hypothesis_decision_rule.inference_scope
        is StudyInferenceScope.confirmatory_independent_clusters
        else StudyMethodReviewApprovalDisposition.approved_fixed_frame_descriptive_conformance
    )
    if receipt.independence_acceptance_rationale == justification.independence_basis:
        raise ValueError(
            "qualified review rationale must add independent analysis, not copy the author basis"
        )
    if (
        receipt.semantic_near_duplicate_review_rationale
        == justification.dependence_risks_and_mitigations
    ):
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
        receipt.study_manifest_sha256,
        receipt.benchmark_digest,
        receipt.benchmark_sha256,
        receipt.protocol_set_digest,
        receipt.hypothesis_decision_rule_digest,
        receipt.registered_at_utc,
        receipt.execution_window_start_utc,
        receipt.approved_inference_scope,
        receipt.independence_design_basis,
        receipt.independence_audit_artifact_sha256,
        receipt.semantic_near_duplicate_disposition,
        receipt.approval_disposition,
        receipt.conditions,
    ) != (
        manifest.study_id,
        manifest.manifest_digest,
        expected_manifest_sha256,
        benchmark.benchmark_digest,
        expected_benchmark_sha256,
        manifest.protocol_set_digest,
        manifest.hypothesis_decision_rule_digest,
        manifest.registration.registered_at_utc,
        manifest.execution_window.start,
        manifest.hypothesis_decision_rule.inference_scope,
        justification.design_basis,
        audit_digest,
        justification.semantic_near_duplicate_disposition,
        expected_approval_disposition,
        expected_conditions,
    ):
        raise ValueError(
            "statistical-method review receipt does not exactly bind the manifest, "
            "benchmark, and registered protocol designs"
        )
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
            binding.planned_independent_clusters,
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
                planned_independent_clusters=binding.planned_independent_clusters,
            )
        )
    return tuple(expected)


__all__ = [
    "ValidatedStudyStatisticalMethodReview",
    "build_study_statistical_method_review_receipt",
    "validate_study_statistical_method_review",
]
