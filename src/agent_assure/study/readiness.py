"""Derived readiness for the empirical study and external-pilot checkpoint."""

from __future__ import annotations

import re
from dataclasses import dataclass

from agent_assure import __version__
from agent_assure.pilot_bundle import VerifiedExternalPilotBundle
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.common import PACKAGE_RELEASE_VERSION_PATTERN
from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    PilotConsentStatus,
    PilotFrictionAssessmentState,
    PilotPublicationScope,
    PilotRemediationArea,
    PilotRemediationDisposition,
)
from agent_assure.schema.study import (
    RealModelStudyReport,
    StudyExecutionOrigin,
)
from agent_assure.study_bundle import ValidatedStudyBundle

EMPIRICAL_CHECKPOINT_IMPLEMENTATION_ID = "agent-assure"


def _release_base(version: str) -> str:
    """Return the stable release line for the project's constrained PEP 440 grammar."""

    if re.fullmatch(PACKAGE_RELEASE_VERSION_PATTERN, version) is None:
        raise ValueError("expected release must be a stable or rc package release")
    return version.split("rc", 1)[0]


EMPIRICAL_CHECKPOINT_RELEASE_LINE = _release_base(__version__)

_LEARNING_REMEDIATION_AREAS = frozenset(
    {
        PilotRemediationArea.onboarding,
        PilotRemediationArea.initialization,
        PilotRemediationArea.diagnostics,
        PilotRemediationArea.roadmap,
    }
)


@dataclass(frozen=True, slots=True)
class EmpiricalReadinessAssessment:
    """A non-persisted, reproducible projection over digest-bound source artifacts."""

    study_bundle_verified: bool
    study_bundle_file_count: int
    study_bundle_bytes_verified: int
    study_registration_evidence_verified: bool
    study_statistical_method_review_verified: bool
    study_execution_review_verified: bool
    study_evidence_satisfied: bool
    study_real_provider_origin_satisfied: bool
    canonical_benchmark_satisfied: bool
    external_pilot_bundle_verified: bool
    external_pilot_attempt_satisfied: bool
    external_pilot_publication_authorized: bool
    pilot_subject_implementation_satisfied: bool
    pilot_subject_version_satisfied: bool
    pilot_learning_captured: bool
    checkpoint_ready: bool
    exact_candidate_gate_eligible: bool
    clean_reproduction_gate_eligible: bool
    ci_integration_gate_eligible: bool
    blocking_reasons: tuple[str, ...]


def assess_empirical_readiness(
    study_bundle: ValidatedStudyBundle | None,
    verified_pilot: VerifiedExternalPilotBundle | None,
    canonical_benchmark: ProcessEquivalenceBenchmarkManifest | None = None,
    expected_release: str = EMPIRICAL_CHECKPOINT_RELEASE_LINE,
) -> EmpiricalReadinessAssessment:
    """Fail closed unless exact study, benchmark, and verified pilot bytes agree.

    Parsed study-report or external-pilot objects are deliberately insufficient:
    callers must supply both factory-only bounded bundle-verifier results.
    """

    expected_release_base = _release_base(expected_release)
    if study_bundle is not None and (
        type(study_bundle) is not ValidatedStudyBundle or not study_bundle.is_mechanically_verified
    ):
        raise TypeError(
            "empirical readiness requires a ValidatedStudyBundle returned by "
            "load_and_validate_study_bundle"
        )
    if verified_pilot is not None and (
        type(verified_pilot) is not VerifiedExternalPilotBundle
        or not verified_pilot.is_mechanically_verified
    ):
        raise TypeError(
            "empirical readiness requires a VerifiedExternalPilotBundle returned "
            "by load_verified_external_pilot_bundle"
        )
    report: RealModelStudyReport | None = None
    bundled_benchmark: ProcessEquivalenceBenchmarkManifest | None = None
    if study_bundle is not None:
        report = RealModelStudyReport.model_validate(
            study_bundle.report.model_dump(mode="json", warnings="error")
        )
        bundled_benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(
            study_bundle.benchmark.model_dump(mode="json", warnings="error")
        )
    pilot: ExternalPilotEvidence | None = None
    if verified_pilot is not None:
        pilot = ExternalPilotEvidence.model_validate(
            verified_pilot.evidence.model_dump(mode="json", warnings="error")
        )
    if canonical_benchmark is not None:
        canonical_benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(
            canonical_benchmark.model_dump(mode="json", warnings="error")
        )
    study_bundle_verified = study_bundle is not None
    registration_ok = bool(
        study_bundle is not None
        and study_bundle.registration_evidence_verified
        and study_bundle.registration_record_sha256
        == study_bundle.manifest.registration.evidence_digest
    )
    execution_review_ok = bool(
        study_bundle is not None
        and study_bundle.execution_review_verified
        and study_bundle.execution_review_receipt is not None
    )
    statistical_method_review_ok = bool(
        study_bundle is not None
        and study_bundle.statistical_method_review_verified
        and study_bundle.statistical_method_review_receipt is not None
    )
    real_provider_ok = bool(
        report is not None
        and all(
            binding.execution_origin is StudyExecutionOrigin.real_provider
            and result.observed_execution_provenance is not None
            and result.observed_execution_provenance.observed_origin
            is StudyExecutionOrigin.real_provider
            for binding, result in zip(
                report.manifest.conditions,
                report.conditions,
                strict=True,
            )
        )
    )
    study_ok = bool(study_bundle is not None and study_bundle.is_publication_ready)
    benchmark_ok = bool(
        report is not None
        and bundled_benchmark is not None
        and canonical_benchmark is not None
        and bundled_benchmark == canonical_benchmark
        and (
            report.manifest.benchmark_id,
            report.manifest.benchmark_version,
            report.manifest.benchmark_digest,
            report.benchmark_digest,
        )
        == (
            canonical_benchmark.benchmark_id,
            canonical_benchmark.benchmark_version,
            canonical_benchmark.benchmark_digest,
            canonical_benchmark.benchmark_digest,
        )
        and _manifest_exactly_covers_benchmark(report, canonical_benchmark)
    )
    bundle_verified = verified_pilot is not None
    pilot_ok = bool(bundle_verified and pilot is not None and pilot.qualifies_as_external_attempt)
    pilot_publication_ok = _pilot_publication_authorized(pilot)
    pilot_implementation_ok = bool(
        pilot is not None
        and pilot.subject.implementation_id == EMPIRICAL_CHECKPOINT_IMPLEMENTATION_ID
    )
    pilot_version_ok = bool(
        pilot is not None
        and _release_base(pilot.subject.implementation_version) == expected_release_base
    )
    learning_ok = _pilot_learning_captured(pilot)
    reasons: list[str] = []
    if not study_bundle_verified:
        reasons.append("real-model-study-bundle-not-verified")
    if not registration_ok:
        reasons.append("real-model-study-registration-evidence-not-verified")
    if not execution_review_ok:
        reasons.append("real-model-study-execution-review-not-verified")
    if not statistical_method_review_ok:
        reasons.append("real-model-study-statistical-method-review-not-verified")
    if not study_ok:
        reasons.append("real-model-study-not-satisfied")
    if report is not None and not real_provider_ok:
        reasons.append("real-model-study-real-provider-origin-not-satisfied")
    if canonical_benchmark is None:
        reasons.append("canonical-process-equivalence-benchmark-not-supplied")
    elif not benchmark_ok:
        reasons.append("real-model-study-canonical-benchmark-mismatch")
    if not bundle_verified:
        reasons.append("external-pilot-bundle-not-verified")
    if not pilot_ok:
        reasons.append("external-ci-pilot-not-attempted")
    if not pilot_publication_ok:
        reasons.append("external-pilot-publication-not-authorized")
    if pilot is not None and not pilot_implementation_ok:
        reasons.append("pilot-subject-implementation-id-mismatch")
    if pilot is not None and not pilot_version_ok:
        reasons.append("pilot-subject-implementation-version-mismatch")
    if not learning_ok:
        reasons.append("pilot-friction-learning-not-captured")
    checkpoint_ready = bool(
        study_ok
        and real_provider_ok
        and benchmark_ok
        and bundle_verified
        and pilot_ok
        and pilot_publication_ok
        and pilot_implementation_ok
        and pilot_version_ok
        and learning_ok
    )
    return EmpiricalReadinessAssessment(
        study_bundle_verified=study_bundle_verified,
        study_bundle_file_count=(study_bundle.file_count if study_bundle is not None else 0),
        study_bundle_bytes_verified=(study_bundle.total_bytes if study_bundle is not None else 0),
        study_registration_evidence_verified=registration_ok,
        study_statistical_method_review_verified=statistical_method_review_ok,
        study_execution_review_verified=execution_review_ok,
        study_evidence_satisfied=study_ok,
        study_real_provider_origin_satisfied=real_provider_ok,
        canonical_benchmark_satisfied=benchmark_ok,
        external_pilot_bundle_verified=bundle_verified,
        external_pilot_attempt_satisfied=pilot_ok,
        external_pilot_publication_authorized=pilot_publication_ok,
        pilot_subject_implementation_satisfied=pilot_implementation_ok,
        pilot_subject_version_satisfied=pilot_version_ok,
        pilot_learning_captured=learning_ok,
        checkpoint_ready=checkpoint_ready,
        # Pre-candidate evidence is deliberately ineligible for later release gates.
        exact_candidate_gate_eligible=False,
        clean_reproduction_gate_eligible=False,
        ci_integration_gate_eligible=False,
        blocking_reasons=tuple(reasons),
    )


def _manifest_exactly_covers_benchmark(
    report: RealModelStudyReport,
    benchmark: ProcessEquivalenceBenchmarkManifest,
) -> bool:
    condition_case_ids = tuple(
        case_id
        for condition in report.manifest.conditions
        for case_id in condition.benchmark_case_ids
    )
    benchmark_case_ids = {case.case_id for case in benchmark.cases}
    return (
        len(condition_case_ids) == len(set(condition_case_ids))
        and set(condition_case_ids) == benchmark_case_ids
    )


def _pilot_learning_captured(pilot: ExternalPilotEvidence | None) -> bool:
    if pilot is None:
        return False
    if pilot.friction_assessment is PilotFrictionAssessmentState.no_friction_observed:
        return True
    if pilot.friction_assessment is not PilotFrictionAssessmentState.friction_observed:
        return False
    linked_remediation_ids = {
        remediation_id
        for finding in pilot.friction_findings
        for remediation_id in finding.remediation_ids
    }
    return any(
        remediation.remediation_id in linked_remediation_ids
        and remediation.disposition is PilotRemediationDisposition.applied
        and bool(set(remediation.areas) & _LEARNING_REMEDIATION_AREAS)
        for remediation in pilot.remediations
    )


def _pilot_publication_authorized(pilot: ExternalPilotEvidence | None) -> bool:
    """Require consent to publish every file present in the repository bundle."""

    if pilot is None:
        return False
    publication = pilot.publication
    return (
        publication.publication_scope is PilotPublicationScope.privacy_filtered_record
        and publication.consent_status is PilotConsentStatus.granted
        and publication.consent_artifact_id is not None
        and publication.consent_digest is not None
        and publication.published_artifact_ids
        == tuple(artifact.artifact_id for artifact in pilot.artifacts)
    )


__all__ = [
    "EMPIRICAL_CHECKPOINT_IMPLEMENTATION_ID",
    "EMPIRICAL_CHECKPOINT_RELEASE_LINE",
    "EmpiricalReadinessAssessment",
    "assess_empirical_readiness",
]
