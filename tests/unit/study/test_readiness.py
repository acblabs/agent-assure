from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_assure import __version__
from agent_assure.pilot_bundle import (
    VerifiedExternalPilotBundle,
    pilot_artifact_manifest_digest,
)
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.pilot import (
    ExternalPilotEvidence,
    PilotConsentStatus,
    PilotEnvironment,
    PilotPublication,
    PilotPublicationScope,
    PilotRemediationArea,
    PilotRemediationDisposition,
    PilotRemediationReference,
    PilotSubject,
)
from agent_assure.schema.study import RealModelStudyReport, StudyExecutionOrigin
from agent_assure.study.analysis import analyze_real_model_study
from agent_assure.study.readiness import (
    EMPIRICAL_CHECKPOINT_RELEASE_LINE,
    EmpiricalReadinessAssessment,
    assess_empirical_readiness,
)
from agent_assure.study_bundle import ValidatedStudyBundle
from agent_assure.study_execution_review import build_study_execution_review_receipt
from agent_assure.study_method_review import build_study_statistical_method_review_receipt
from tests.unit.schema.test_pilot_evidence import (
    _external_evidence,
    _review_receipt,
    _values,
)
from tests.unit.study.test_real_model_study import (
    StudyFixture,
    _analyze,
    _fixture,
    _manifest,
    _rebind_evidence_to_manifest,
)
from tests.unit.study.test_study_semantic_hardening import _fixed_frame_manifest


def _ready_inputs() -> tuple[
    ValidatedStudyBundle,
    VerifiedExternalPilotBundle,
    ProcessEquivalenceBenchmarkManifest,
]:
    fixture = _fixture(real_provider_execution=True)
    return _verified_study(fixture), _verified_pilot(_external_evidence()), fixture.benchmark


def _verified_study(
    fixture: StudyFixture,
    *,
    report: RealModelStudyReport | None = None,
    manifest: object | None = None,
    evidence: object | None = None,
    registration_evidence_verified: bool = True,
    include_execution_review: bool = True,
    include_statistical_method_review: bool = True,
) -> ValidatedStudyBundle:
    actual_manifest = manifest or fixture.manifest  # type: ignore[attr-defined]
    actual_report = report or _analyze(fixture)  # type: ignore[arg-type]
    actual_evidence = evidence or fixture.evidence_by_condition  # type: ignore[attr-defined]
    fixed_frame = (
        actual_manifest.hypothesis_decision_rule.inference_scope.value
        == "fixed_frame_descriptive_conformance"
    )
    independence_acceptance_rationale = (
        "Independent audit review confirms the shared-template parameter grid cannot "
        "support independent-cluster inference and requires descriptive scope."
        if fixed_frame
        else "Independent audit review supports the synthetic generator's separate "
        "cluster construction for this bounded deterministic test design."
    )
    near_duplicate_review_rationale = (
        "The digest-bound audit identified shared-template semantic dependence and "
        "the approved fixed-frame downscope prevents pseudoreplicated inference."
        if fixed_frame
        else "Every synthetic cluster was compared and the audit found no unhandled "
        "semantic duplicate counted as a separate unit."
    )
    execution_review_receipt = None
    statistical_method_review_receipt = None
    if include_statistical_method_review and all(
        binding.execution_origin is StudyExecutionOrigin.real_provider
        for binding in actual_manifest.conditions
    ):
        statistical_method_review_receipt = build_study_statistical_method_review_receipt(
            manifest=actual_manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            receipt_id="synthetic-statistical-method-review",
            reviewed_at_utc="2025-01-15T00:00:00Z",
            reviewer_pseudonym="independent-synthetic-statistician",
            reviewer_statistical_qualification_confirmed=True,
            reviewer_qualification_basis_types=("professional_statistical_practice",),
            reviewer_qualification_evidence_digest="0123456789abcdef" * 4,
            reviewer_qualification_basis=(
                "Training and applied experience in clustered exact binomial inference."
            ),
            reviewer_independent_of_design_execution_and_analysis=True,
            reviewer_independence_rationale=(
                "The test reviewer did not design, execute, or analyze this study."
            ),
            independence_design_basis_reviewed_and_accepted=True,
            independence_acceptance_rationale=independence_acceptance_rationale,
            semantic_near_duplicate_audit_reviewed=True,
            semantic_near_duplicate_pseudoreplication_rejected=True,
            semantic_near_duplicate_review_rationale=near_duplicate_review_rationale,
            benchmark_cluster_assignments_reviewed=True,
            independence_and_exchangeability_assumptions_reviewed=True,
            sampling_frame_and_estimand_reviewed=True,
            multiplicity_and_interval_method_reviewed=True,
            power_and_decision_boundary_reachability_reviewed=True,
            negative_control_design_reviewed=True,
        )
    if include_execution_review and all(
        binding.execution_origin is StudyExecutionOrigin.real_provider
        for binding in actual_manifest.conditions
    ):
        execution_review_receipt = build_study_execution_review_receipt(
            manifest=actual_manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            report=actual_report,
            evidence=actual_evidence,
            receipt_id="synthetic-execution-review",
            reviewed_at_utc="2025-04-01T00:00:00Z",
            reviewer_pseudonym="independent-synthetic-reviewer",
            reviewer_independent_of_execution=True,
            reviewer_independence_rationale=(
                "The deterministic test reviewer did not operate the provider execution."
            ),
            provider_log_review_scope=(
                "The reviewer inspected every synthetic provider log event across the full "
                "registered execution window and all request classes."
            ),
            provider_log_evidence_digest="1234567890abcdef" * 4,
            provider_account_review_scope=(
                "The reviewer reconciled the synthetic account usage ledger for the full "
                "execution window against every dispatched request."
            ),
            provider_account_evidence_digest="abcdef0123456789" * 4,
            provider_log_and_account_review_confirmed=True,
            provider_log_time_window_coverage_confirmed=True,
            provider_account_usage_reconciled=True,
            exhaustive_attempt_failure_retry_accounting_confirmed=True,
            provider_response_id_matches_confirmed=True,
            exact_runset_artifact_digest_matches_confirmed=True,
            provider_serving_fingerprint_availability_reviewed=True,
        )
    return ValidatedStudyBundle._from_verified_bytes(
        manifest=actual_manifest,
        benchmark=fixture.benchmark,  # type: ignore[attr-defined]
        protocols=fixture.protocols,  # type: ignore[attr-defined]
        evidence=actual_evidence,
        report=actual_report,
        registration_review_receipt=fixture.registration_review_receipt,
        statistical_method_review_receipt=statistical_method_review_receipt,
        execution_review_receipt=execution_review_receipt,
        registration_record_sha256=actual_manifest.registration.evidence_digest,
        registration_evidence_verified=registration_evidence_verified,
        statistical_method_review_verified=statistical_method_review_receipt is not None,
        execution_review_verified=execution_review_receipt is not None,
        file_count=8 + 5 * len(actual_manifest.conditions),
        total_bytes=1,
    )


def _verified_pilot(pilot: ExternalPilotEvidence) -> VerifiedExternalPilotBundle:
    control_id = pilot.environment.control_evidence_artifact_id
    assert control_id is not None
    artifact_by_id = {artifact.artifact_id: artifact for artifact in pilot.artifacts}
    receipt = _review_receipt(
        pilot_id=pilot.pilot_id,
        pilot_participant_pseudonym=pilot.participant_pseudonym,
        pilot_evidence_digest=pilot.pilot_evidence_digest,
        artifact_manifest_digest=pilot_artifact_manifest_digest(pilot.artifacts),
        environment_control_evidence_artifact_id=control_id,
        environment_control_evidence_sha256=artifact_by_id[control_id].sha256,
    )
    return VerifiedExternalPilotBundle._from_verified_bytes(
        evidence=pilot,
        review_receipt=receipt,
        artifact_manifest_digest=receipt.artifact_manifest_digest,
        total_bytes=1,
    )


def _pilot_with_subject(**overrides: str) -> VerifiedExternalPilotBundle:
    pilot = _external_evidence()
    subject_payload = pilot.subject.model_dump(mode="json")
    subject_payload.update(overrides)
    evidence_overrides: dict[str, object] = {
        "subject": PilotSubject.model_validate(subject_payload)
    }
    if "source_revision" in overrides:
        evidence_overrides["commands"] = tuple(
            command.model_copy(
                update={"implementation_source_revision": overrides["source_revision"]}
            )
            for command in pilot.commands
        )
    return _verified_pilot(_external_evidence(**evidence_overrides))


def _assert_later_release_gates_closed(
    assessment: EmpiricalReadinessAssessment,
) -> None:
    assert assessment.exact_candidate_gate_eligible is False
    assert assessment.clean_reproduction_gate_eligible is False
    assert assessment.ci_integration_gate_eligible is False


def test_readiness_without_study_or_pilot_evidence_fails_every_gate_closed() -> None:
    assessment = assess_empirical_readiness(None, None)

    assert assessment.study_evidence_satisfied is False
    assert assessment.study_bundle_verified is False
    assert assessment.study_registration_evidence_verified is False
    assert assessment.study_execution_review_verified is False
    assert assessment.study_statistical_method_review_verified is False
    assert assessment.study_real_provider_origin_satisfied is False
    assert assessment.canonical_benchmark_satisfied is False
    assert assessment.external_pilot_bundle_verified is False
    assert assessment.external_pilot_attempt_satisfied is False
    assert assessment.external_pilot_publication_authorized is False
    assert assessment.pilot_subject_implementation_satisfied is False
    assert assessment.pilot_subject_version_satisfied is False
    assert assessment.pilot_learning_captured is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == (
        "real-model-study-bundle-not-verified",
        "real-model-study-registration-evidence-not-verified",
        "real-model-study-execution-review-not-verified",
        "real-model-study-statistical-method-review-not-verified",
        "real-model-study-not-satisfied",
        "canonical-process-equivalence-benchmark-not-supplied",
        "external-pilot-bundle-not-verified",
        "external-ci-pilot-not-attempted",
        "external-pilot-publication-not-authorized",
        "pilot-friction-learning-not-captured",
    )
    _assert_later_release_gates_closed(assessment)


def test_publication_eligible_study_and_external_attempt_satisfy_checkpoint_only() -> None:
    report, pilot, benchmark = _ready_inputs()
    assessment = assess_empirical_readiness(report, pilot, benchmark)

    assert assessment.study_evidence_satisfied is True
    assert assessment.study_registration_evidence_verified is True
    assert assessment.study_execution_review_verified is True
    assert assessment.study_statistical_method_review_verified is True
    assert assessment.study_real_provider_origin_satisfied is True
    assert assessment.canonical_benchmark_satisfied is True
    assert assessment.external_pilot_bundle_verified is True
    assert assessment.external_pilot_attempt_satisfied is True
    assert assessment.external_pilot_publication_authorized is True
    assert assessment.pilot_subject_implementation_satisfied is True
    assert assessment.pilot_subject_version_satisfied is True
    assert assessment.pilot_learning_captured is True
    assert assessment.checkpoint_ready is True
    assert assessment.blocking_reasons == ()
    _assert_later_release_gates_closed(assessment)


def test_fixed_frame_descriptive_bundle_can_never_satisfy_sprint7_checkpoint() -> None:
    fixture = _fixture(real_provider_execution=True)
    manifest = _fixed_frame_manifest(fixture)
    evidence = _rebind_evidence_to_manifest(fixture, manifest)
    report = analyze_real_model_study(
        manifest=manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=evidence,
    )
    bundle = _verified_study(
        fixture,
        manifest=manifest,
        report=report,
        evidence=evidence,
    )

    assert bundle.is_scoped_descriptive_publication_ready is True
    assert bundle.is_publication_ready is False

    assessment = assess_empirical_readiness(
        bundle,
        _verified_pilot(_external_evidence()),
        fixture.benchmark,
    )

    assert assessment.study_inference_scope == "fixed_frame_descriptive_conformance"
    assert assessment.study_inferential_statistics_applicable is False
    assert assessment.study_scoped_descriptive_publication_ready is True
    assert assessment.study_confirmatory_inference_satisfied is False
    assert assessment.study_evidence_satisfied is False
    assert assessment.checkpoint_ready is False
    assert "real-model-study-fixed-frame-descriptive-only" in assessment.blocking_reasons
    assert "real-model-study-not-satisfied" in assessment.blocking_reasons


@pytest.mark.parametrize(
    "publication",
    (
        PilotPublication(
            consent_status=PilotConsentStatus.not_requested,
            publication_scope=PilotPublicationScope.private_record,
            consent_artifact_id=None,
            consent_digest=None,
            published_artifact_ids=(),
        ),
        PilotPublication(
            consent_status=PilotConsentStatus.withheld,
            publication_scope=PilotPublicationScope.private_record,
            consent_artifact_id="artifact-consent",
            consent_digest="a" * 64,
            published_artifact_ids=(),
        ),
        PilotPublication(
            consent_status=PilotConsentStatus.granted,
            publication_scope=PilotPublicationScope.aggregate_summary,
            consent_artifact_id="artifact-consent",
            consent_digest="a" * 64,
            published_artifact_ids=(),
        ),
        PilotPublication(
            consent_status=PilotConsentStatus.granted,
            publication_scope=PilotPublicationScope.privacy_filtered_record,
            consent_artifact_id="artifact-consent",
            consent_digest="a" * 64,
            published_artifact_ids=("artifact-friction",),
        ),
    ),
    ids=("private", "withheld", "aggregate", "partial-inventory"),
)
def test_repo_release_requires_consent_for_the_complete_pilot_bundle(
    publication: PilotPublication,
) -> None:
    study_bundle, _pilot, benchmark = _ready_inputs()
    assessment = assess_empirical_readiness(
        study_bundle,
        _verified_pilot(_external_evidence(publication=publication)),
        benchmark,
    )

    assert assessment.external_pilot_attempt_satisfied is True
    assert assessment.external_pilot_publication_authorized is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == ("external-pilot-publication-not-authorized",)


def test_unverified_registration_receipt_blocks_an_otherwise_ready_study() -> None:
    fixture = _fixture(real_provider_execution=True)
    assessment = assess_empirical_readiness(
        _verified_study(fixture, registration_evidence_verified=False),
        _verified_pilot(_external_evidence()),
        fixture.benchmark,
    )

    assert assessment.study_bundle_verified is True
    assert assessment.study_registration_evidence_verified is False
    assert assessment.study_evidence_satisfied is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == (
        "real-model-study-registration-evidence-not-verified",
        "real-model-study-not-satisfied",
    )


def test_missing_execution_review_blocks_an_otherwise_ready_study() -> None:
    fixture = _fixture(real_provider_execution=True)
    assessment = assess_empirical_readiness(
        _verified_study(fixture, include_execution_review=False),
        _verified_pilot(_external_evidence()),
        fixture.benchmark,
    )

    assert assessment.study_bundle_verified is True
    assert assessment.study_registration_evidence_verified is True
    assert assessment.study_execution_review_verified is False
    assert assessment.study_evidence_satisfied is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == (
        "real-model-study-execution-review-not-verified",
        "real-model-study-not-satisfied",
    )


def test_missing_statistical_method_review_blocks_an_otherwise_ready_study() -> None:
    fixture = _fixture(real_provider_execution=True)
    assessment = assess_empirical_readiness(
        _verified_study(fixture, include_statistical_method_review=False),
        _verified_pilot(_external_evidence()),
        fixture.benchmark,
    )

    assert assessment.study_bundle_verified is True
    assert assessment.study_statistical_method_review_verified is False
    assert assessment.study_evidence_satisfied is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == (
        "real-model-study-statistical-method-review-not-verified",
        "real-model-study-not-satisfied",
    )


def test_synthetic_execution_origin_cannot_publish_or_satisfy_readiness() -> None:
    fixture = _fixture()
    synthetic_manifest = _manifest(
        fixture.benchmark,
        fixture.protocols,
        execution_origin=StudyExecutionOrigin.synthetic_fixture,
    )
    report = analyze_real_model_study(
        manifest=synthetic_manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        evidence=_rebind_evidence_to_manifest(fixture, synthetic_manifest),
    )

    assert report.publication_eligible is False
    assessment = assess_empirical_readiness(
        _verified_study(
            fixture,
            report=report,
            manifest=synthetic_manifest,
            evidence=_rebind_evidence_to_manifest(fixture, synthetic_manifest),
        ),
        _verified_pilot(_external_evidence()),
        fixture.benchmark,
    )

    assert assessment.study_real_provider_origin_satisfied is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == (
        "real-model-study-execution-review-not-verified",
        "real-model-study-statistical-method-review-not-verified",
        "real-model-study-not-satisfied",
        "real-model-study-real-provider-origin-not-satisfied",
    )
    _assert_later_release_gates_closed(assessment)


def test_unrelated_canonical_benchmark_is_a_stable_distinct_blocker() -> None:
    report, pilot, benchmark = _ready_inputs()
    unrelated = ProcessEquivalenceBenchmarkManifest.build(
        benchmark_id="unrelated-process-equivalence-benchmark",
        cases=benchmark.cases,
    )

    assessment = assess_empirical_readiness(report, pilot, unrelated)

    assert assessment.study_evidence_satisfied is True
    assert assessment.canonical_benchmark_satisfied is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == ("real-model-study-canonical-benchmark-mismatch",)


@pytest.mark.parametrize(
    ("subject_overrides", "reason"),
    (
        (
            {"implementation_id": "unrelated-implementation"},
            "pilot-subject-implementation-id-mismatch",
        ),
        (
            {"implementation_version": "0.6.5"},
            "pilot-subject-implementation-version-mismatch",
        ),
    ),
)
def test_unrelated_pilot_subject_identity_has_stable_distinct_reason(
    subject_overrides: dict[str, str],
    reason: str,
) -> None:
    report, _, benchmark = _ready_inputs()

    assessment = assess_empirical_readiness(
        report,
        _pilot_with_subject(**subject_overrides),
        benchmark,
    )

    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == (reason,)


@pytest.mark.parametrize(
    ("pilot_version", "expected_release"),
    (
        ("0.6.6", "0.6.6rc1"),
        ("0.6.6rc2", "0.6.6"),
        ("0.6.6rc2", "0.6.6rc3"),
    ),
)
def test_pilot_subject_version_matches_rc_and_stable_within_release_line(
    pilot_version: str,
    expected_release: str,
) -> None:
    report, _, benchmark = _ready_inputs()

    assessment = assess_empirical_readiness(
        report,
        _pilot_with_subject(implementation_version=pilot_version),
        benchmark,
        expected_release,
    )

    assert assessment.pilot_subject_version_satisfied is True
    assert assessment.checkpoint_ready is True
    assert assessment.blocking_reasons == ()


def test_release_line_is_derived_from_package_version() -> None:
    assert EMPIRICAL_CHECKPOINT_RELEASE_LINE == __version__.split("rc", 1)[0]


def test_package_version_matches_project_metadata() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    project = tomllib.loads((repository_root / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["version"] == __version__


def test_explicit_expected_release_can_validate_another_release_line() -> None:
    report, _, benchmark = _ready_inputs()

    assessment = assess_empirical_readiness(
        report,
        _pilot_with_subject(implementation_version="0.6.7"),
        benchmark,
        expected_release="0.6.7rc1",
    )

    assert assessment.pilot_subject_version_satisfied is True
    assert assessment.checkpoint_ready is True
    assert assessment.blocking_reasons == ()


def test_pre_candidate_source_revision_is_not_compared_to_release_head() -> None:
    report, _, benchmark = _ready_inputs()
    pilot = _pilot_with_subject(
        source_revision="different-tested-pre-candidate",
    )

    assessment = assess_empirical_readiness(report, pilot, benchmark)

    assert assessment.checkpoint_ready is True
    assert assessment.exact_candidate_gate_eligible is False
    assert assessment.blocking_reasons == ()


def test_no_friction_assessment_counts_as_captured_learning_without_remediation() -> None:
    pilot = _external_evidence(
        friction_assessment="no_friction_observed",
        friction_findings=(),
        remediations=(),
    )

    fixture = _fixture(real_provider_execution=True)
    assessment = assess_empirical_readiness(
        _verified_study(fixture),
        _verified_pilot(pilot),
        fixture.benchmark,
    )

    assert assessment.external_pilot_attempt_satisfied is True
    assert assessment.pilot_learning_captured is True
    assert assessment.checkpoint_ready is True
    assert assessment.blocking_reasons == ()
    _assert_later_release_gates_closed(assessment)


@pytest.mark.parametrize(
    ("area", "disposition"),
    (
        (PilotRemediationArea.diagnostics, PilotRemediationDisposition.planned),
        (PilotRemediationArea.onboarding, PilotRemediationDisposition.deferred),
        (
            PilotRemediationArea.initialization,
            PilotRemediationDisposition.no_change_required,
        ),
        (PilotRemediationArea.other, PilotRemediationDisposition.applied),
    ),
)
def test_observed_friction_requires_applied_onboarding_relevant_remediation(
    area: PilotRemediationArea,
    disposition: PilotRemediationDisposition,
) -> None:
    remediation = PilotRemediationReference(
        remediation_id="doctor-ci-hint",
        areas=(area,),
        disposition=disposition,
        remediation_artifact_id="artifact-remediation",
        remediation_digest="9" * 64,
    )
    pilot = _external_evidence(remediations=(remediation,))

    fixture = _fixture(real_provider_execution=True)
    assessment = assess_empirical_readiness(
        _verified_study(fixture),
        _verified_pilot(pilot),
        fixture.benchmark,
    )

    assert assessment.external_pilot_attempt_satisfied is True
    assert assessment.pilot_learning_captured is False
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == ("pilot-friction-learning-not-captured",)
    _assert_later_release_gates_closed(assessment)


def test_applied_roadmap_remediation_counts_as_captured_learning() -> None:
    remediation = PilotRemediationReference(
        remediation_id="doctor-ci-hint",
        areas=(PilotRemediationArea.roadmap,),
        disposition=PilotRemediationDisposition.applied,
        remediation_artifact_id="artifact-remediation",
        remediation_digest="9" * 64,
    )
    pilot = _external_evidence(remediations=(remediation,))

    fixture = _fixture(real_provider_execution=True)
    assessment = assess_empirical_readiness(
        _verified_study(fixture),
        _verified_pilot(pilot),
        fixture.benchmark,
    )

    assert assessment.pilot_learning_captured is True
    assert assessment.checkpoint_ready is True
    assert assessment.blocking_reasons == ()
    _assert_later_release_gates_closed(assessment)


def test_internal_attempt_captures_learning_but_cannot_satisfy_external_gate() -> None:
    environment = _values()["environment"]
    assert isinstance(environment, PilotEnvironment)
    payload = environment.model_dump(mode="json")
    payload["control"] = "maintainer_controlled"
    internal = _external_evidence(
        classification="internal_dogfood",
        environment=PilotEnvironment.model_validate(payload),
        qualifies_as_external_attempt=False,
    )

    fixture = _fixture(real_provider_execution=True)
    assessment = assess_empirical_readiness(
        _verified_study(fixture),
        _verified_pilot(internal),
        fixture.benchmark,
    )

    assert assessment.study_evidence_satisfied is True
    assert assessment.external_pilot_attempt_satisfied is False
    assert assessment.pilot_learning_captured is True
    assert assessment.checkpoint_ready is False
    assert assessment.blocking_reasons == ("external-ci-pilot-not-attempted",)
    _assert_later_release_gates_closed(assessment)


def test_readiness_revalidates_self_digests_before_using_gate_flags() -> None:
    fixture = _fixture(missing_counterfactual_index=1)
    insufficient = _analyze(fixture)
    assert insufficient.publication_eligible is False
    tampered = insufficient.model_copy(update={"publication_eligible": True})

    with pytest.raises(ValidationError):
        assess_empirical_readiness(
            _verified_study(fixture, report=tampered),
            _verified_pilot(_external_evidence()),
            _fixture().benchmark,
        )


def test_bare_external_pilot_evidence_cannot_satisfy_readiness_api() -> None:
    study_bundle, _verified, benchmark = _ready_inputs()

    with pytest.raises(TypeError, match="VerifiedExternalPilotBundle"):
        assess_empirical_readiness(
            study_bundle,
            _external_evidence(),  # type: ignore[arg-type]
            benchmark,
        )


def test_uninitialized_verified_bundle_cannot_satisfy_readiness_api() -> None:
    study_bundle, _verified, benchmark = _ready_inputs()
    malformed = object.__new__(VerifiedExternalPilotBundle)

    with pytest.raises(TypeError, match="VerifiedExternalPilotBundle"):
        assess_empirical_readiness(study_bundle, malformed, benchmark)


def test_bare_study_report_cannot_satisfy_readiness_api() -> None:
    study_bundle, pilot, benchmark = _ready_inputs()

    with pytest.raises(TypeError, match="ValidatedStudyBundle"):
        assess_empirical_readiness(
            study_bundle.report,  # type: ignore[arg-type]
            pilot,
            benchmark,
        )


def test_uninitialized_study_bundle_cannot_satisfy_readiness_api() -> None:
    _study_bundle, pilot, benchmark = _ready_inputs()
    malformed = object.__new__(ValidatedStudyBundle)

    with pytest.raises(TypeError, match="ValidatedStudyBundle"):
        assess_empirical_readiness(malformed, pilot, benchmark)
