from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

import agent_assure.study_method_review as method_review_module
from agent_assure.schema.study import (
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.study_artifact_serialization import published_model_json_bytes
from agent_assure.study_method_review import (
    build_study_statistical_method_review_receipt,
    statistical_method_review_explicitly_approves_confirmatory_benchmark,
    validate_study_independence_audit_artifact,
    validate_study_statistical_method_review,
)
from tests.unit.study.test_real_model_study import _fixture
from tests.unit.study.test_study_semantic_hardening import (
    _fixed_frame_manifest,
    _fixed_frame_protocol,
)


def _review(**overrides: object) -> StudyStatisticalMethodReviewReceipt:
    fixture = _fixture(real_provider_execution=True)
    values: dict[str, object] = {
        "manifest": fixture.manifest,
        "manifest_bytes": published_model_json_bytes(fixture.manifest),
        "benchmark": fixture.benchmark,
        "benchmark_bytes": published_model_json_bytes(fixture.benchmark),
        "protocols": fixture.protocols,
        "registered_protocol_bytes": {
            condition_id: published_model_json_bytes(protocol)
            for condition_id, protocol in fixture.protocols.items()
        },
        "registration_record_bytes": fixture.registration_record_bytes,
        "registration_review_receipt": fixture.registration_review_receipt,
        "independence_audit_artifact_bytes": fixture.independence_audit_artifact_bytes,
        "receipt_id": "statistical-method-review",
        "reviewed_at_utc": "2025-01-15T00:00:00Z",
        "reviewer_pseudonym": "independent-statistician",
        "reviewer_statistical_qualification_confirmed": True,
        "reviewer_qualification_basis_types": ("professional_statistical_practice",),
        "reviewer_qualification_evidence_digest": "0123456789abcdef" * 4,
        "reviewer_qualification_basis": (
            "Graduate training and applied work in clustered exact binomial inference."
        ),
        "reviewer_independent_of_design_execution_and_analysis": True,
        "reviewer_independence_rationale": (
            "The reviewer did not design, execute, select, or analyze study observations."
        ),
        "design_basis_reviewed_and_accepted": True,
        "design_review_rationale": (
            "Independent inspection found the synthetic cluster generator creates "
            "separate bound units under the declared test-only inferential scope."
        ),
        "semantic_near_duplicate_audit_reviewed": True,
        "semantic_near_duplicate_pseudoreplication_rejected": True,
        "semantic_near_duplicate_review_rationale": (
            "The digest-bound audit compared every synthetic cluster and found no "
            "unhandled semantic duplicate counted as a separate inferential unit."
        ),
        "benchmark_cluster_assignments_reviewed": True,
        "independence_and_exchangeability_assumptions_reviewed": True,
        "sampling_frame_and_estimand_reviewed": True,
        "multiplicity_and_interval_method_reviewed": True,
        "combined_directional_decision_error_control_reviewed": True,
        "power_and_decision_boundary_reachability_reviewed": True,
        "negative_control_design_reviewed": True,
    }
    values.update(overrides)
    return build_study_statistical_method_review_receipt(**values)  # type: ignore[arg-type]


def _fixed_review() -> StudyStatisticalMethodReviewReceipt:
    fixture = _fixture()
    protocols = {
        condition_id: _fixed_frame_protocol(protocol)
        for condition_id, protocol in fixture.protocols.items()
    }
    manifest = _fixed_frame_manifest(fixture, protocols)
    registration = manifest.registration
    registration_review = StudyRegistrationReviewReceipt.build(
        receipt_id="fixed-frame-registration-review",
        study_id=manifest.study_id,
        study_manifest_digest=manifest.manifest_digest,
        registration_method=registration.method,
        registration_reference_id=registration.reference_id,
        registration_evidence_sha256=registration.evidence_digest,
        registered_at_utc=registration.registered_at_utc,
        reviewed_at_utc="2025-01-02T00:00:00Z",
        reviewer_pseudonym="fixed-frame-registration-reviewer",
        registration_record_coverage_confirmed=True,
        pre_observation_ordering_confirmed=True,
        registration_reference_resolved=True,
        registration_record_digest_match_confirmed=True,
        registration_record_immutability_confirmed=True,
    )
    return build_study_statistical_method_review_receipt(
        manifest=manifest,
        manifest_bytes=published_model_json_bytes(manifest),
        benchmark=fixture.benchmark,
        benchmark_bytes=published_model_json_bytes(fixture.benchmark),
        protocols=protocols,
        registered_protocol_bytes={
            condition_id: published_model_json_bytes(protocol)
            for condition_id, protocol in protocols.items()
        },
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=registration_review,
        independence_audit_artifact_bytes=fixture.independence_audit_artifact_bytes,
        receipt_id="fixed-frame-statistical-method-review",
        reviewed_at_utc="2025-01-15T00:00:00Z",
        reviewer_pseudonym="independent-descriptive-method-reviewer",
        reviewer_statistical_qualification_confirmed=True,
        reviewer_qualification_basis_types=("professional_statistical_practice",),
        reviewer_qualification_evidence_digest="0123456789abcdef" * 4,
        reviewer_qualification_basis=(
            "Applied statistical practice reviewing finite-frame descriptive "
            "summaries and completeness requirements."
        ),
        reviewer_independent_of_design_execution_and_analysis=True,
        reviewer_independence_rationale=(
            "The reviewer did not design, execute, select, or analyze these "
            "frozen-frame observations."
        ),
        design_basis_reviewed_and_accepted=True,
        design_review_rationale=(
            "Independent inspection accepted the shared-template frame solely "
            "for exact finite-frame descriptive reporting."
        ),
        semantic_near_duplicate_audit_reviewed=True,
        semantic_near_duplicate_pseudoreplication_rejected=True,
        semantic_near_duplicate_review_rationale=(
            "Shared structure and near-duplicate risks were reviewed and barred "
            "from supporting any independent-unit or population claim."
        ),
        benchmark_cluster_assignments_reviewed=True,
        sampling_frame_and_estimand_reviewed=True,
        fixed_frame_completeness_reviewed=True,
        descriptive_count_and_rate_derivation_reviewed=True,
        population_inference_prohibition_reviewed=True,
        negative_control_design_reviewed=True,
    )


def test_fixed_frame_review_has_only_descriptive_scope_attestations() -> None:
    receipt = _fixed_review()
    payload = receipt.model_dump(mode="json")

    assert receipt.approved_inference_scope.value == "fixed_frame_descriptive_conformance"
    assert receipt.approval_disposition.value == ("approved_fixed_frame_descriptive_conformance")
    assert payload["fixed_frame_completeness_reviewed"] is True
    assert payload["descriptive_count_and_rate_derivation_reviewed"] is True
    assert payload["population_inference_prohibition_reviewed"] is True
    for field_name in (
        "independence_and_exchangeability_assumptions_reviewed",
        "multiplicity_and_interval_method_reviewed",
        "combined_directional_decision_error_control_reviewed",
        "power_and_decision_boundary_reachability_reviewed",
    ):
        assert field_name not in payload


@pytest.mark.parametrize(
    "field_name",
    (
        "independence_and_exchangeability_assumptions_reviewed",
        "multiplicity_and_interval_method_reviewed",
        "combined_directional_decision_error_control_reviewed",
        "power_and_decision_boundary_reachability_reviewed",
    ),
)
def test_fixed_frame_review_rejects_confirmatory_attestation_presence(
    field_name: str,
) -> None:
    payload = _fixed_review().model_dump(mode="json")
    payload[field_name] = None

    with pytest.raises(ValidationError, match="inapplicable attestations"):
        StudyStatisticalMethodReviewReceipt.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            StudyStatisticalMethodReviewReceipt.model_json_schema(mode="validation")
        ).validate(payload)


def test_confirmatory_review_rejects_descriptive_attestation_presence() -> None:
    payload = _review().model_dump(mode="json")
    payload["fixed_frame_completeness_reviewed"] = None

    with pytest.raises(ValidationError, match="inapplicable attestations"):
        StudyStatisticalMethodReviewReceipt.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            StudyStatisticalMethodReviewReceipt.model_json_schema(mode="validation")
        ).validate(payload)


@pytest.mark.parametrize(
    "field_name",
    (
        "independence_and_exchangeability_assumptions_reviewed",
        "multiplicity_and_interval_method_reviewed",
        "combined_directional_decision_error_control_reviewed",
        "power_and_decision_boundary_reachability_reviewed",
    ),
)
def test_confirmatory_review_rejects_explicit_null_attestation(field_name: str) -> None:
    payload = _review().model_dump(mode="json")
    payload[field_name] = None

    with pytest.raises(ValidationError, match="must set scope-specific attestations to true"):
        StudyStatisticalMethodReviewReceipt.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            StudyStatisticalMethodReviewReceipt.model_json_schema(mode="validation")
        ).validate(payload)


@pytest.mark.parametrize(
    "field_name",
    (
        "fixed_frame_completeness_reviewed",
        "descriptive_count_and_rate_derivation_reviewed",
        "population_inference_prohibition_reviewed",
    ),
)
def test_fixed_frame_review_rejects_explicit_null_attestation(field_name: str) -> None:
    payload = _fixed_review().model_dump(mode="json")
    payload[field_name] = None

    with pytest.raises(ValidationError, match="must set scope-specific attestations to true"):
        StudyStatisticalMethodReviewReceipt.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            StudyStatisticalMethodReviewReceipt.model_json_schema(mode="validation")
        ).validate(payload)


@pytest.mark.parametrize(
    "field_name",
    (
        "independence_and_exchangeability_assumptions_reviewed",
        "multiplicity_and_interval_method_reviewed",
        "combined_directional_decision_error_control_reviewed",
        "power_and_decision_boundary_reachability_reviewed",
    ),
)
def test_confirmatory_benchmark_approval_defends_against_unvalidated_null_attestation(
    field_name: str,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    receipt = _review()
    tampered = receipt.model_copy(update={field_name: None})

    assert not statistical_method_review_explicitly_approves_confirmatory_benchmark(
        benchmark=fixture.benchmark,
        benchmark_bytes=published_model_json_bytes(fixture.benchmark),
        review_receipt=tampered,
    )


def test_statistical_method_review_binds_exact_preregistered_design() -> None:
    fixture = _fixture(real_provider_execution=True)
    receipt = _review()

    validated = validate_study_statistical_method_review(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        registration_record_bytes=fixture.registration_record_bytes,
        registration_review_receipt=fixture.registration_review_receipt,
        review_receipt=receipt,
        independence_audit_artifact_bytes=fixture.independence_audit_artifact_bytes,
    )

    assert validated.receipt == receipt
    assert (
        receipt.registration_review_receipt_digest
        == fixture.registration_review_receipt.review_receipt_digest
    )
    assert receipt.unresolved_methodological_concerns == ()


def test_statistical_method_review_binds_one_exact_registration_review() -> None:
    fixture = _fixture(real_provider_execution=True)
    receipt = _review()
    sibling_values = fixture.registration_review_receipt.model_dump(
        mode="python",
        exclude={"review_receipt_digest"},
    )
    sibling_values["reviewer_pseudonym"] = "second-registration-reviewer"
    sibling_review = StudyRegistrationReviewReceipt.build(**sibling_values)

    with pytest.raises(ValueError, match="does not exactly bind.*registration review"):
        validate_study_statistical_method_review(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=sibling_review,
            review_receipt=receipt,
            independence_audit_artifact_bytes=fixture.independence_audit_artifact_bytes,
        )


def test_statistical_method_review_requires_strict_causal_review_order() -> None:
    fixture = _fixture(real_provider_execution=True)

    with pytest.raises(ValueError, match="must occur after registration review"):
        _review(reviewed_at_utc=fixture.registration_review_receipt.reviewed_at_utc)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("reviewer_qualification_basis", "x"),
        ("reviewer_independence_rationale", " " * 40),
    ),
)
def test_statistical_method_review_rejects_non_substantive_attestations(
    field_name: str,
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        _review(**{field_name: value})


@pytest.mark.parametrize(
    "field_name",
    ("design_review_rationale", "semantic_near_duplicate_review_rationale"),
)
def test_statistical_method_review_rejects_placeholder_method_prose(
    field_name: str,
) -> None:
    with pytest.raises(ValidationError, match="unresolved authoring token"):
        _review(
            **{field_name: ("TODO: replace this placeholder with a real qualified review basis.")}
        )


def test_statistical_method_review_rejects_copied_author_independence_basis() -> None:
    fixture = _fixture(real_provider_execution=True)

    with pytest.raises(ValueError, match="must add independent analysis"):
        _review(
            design_review_rationale=(
                fixture.manifest.hypothesis_decision_rule.independence_justification.independence_basis
            )
        )


@pytest.mark.parametrize(
    ("field_name", "author_field"),
    (
        ("design_review_rationale", "independence_basis"),
        (
            "semantic_near_duplicate_review_rationale",
            "dependence_risks_and_mitigations",
        ),
    ),
)
@pytest.mark.parametrize("presentation_variant", ("case", "whitespace", "unicode"))
def test_statistical_method_review_rejects_presentation_only_author_prose_changes(
    field_name: str,
    author_field: str,
    presentation_variant: str,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    justification = fixture.manifest.hypothesis_decision_rule.independence_justification
    author_prose = getattr(justification, author_field)
    if presentation_variant == "case":
        copied_prose = author_prose.swapcase()
    elif presentation_variant == "whitespace":
        copied_prose = " \n\t".join(author_prose.split())
    else:
        copied_prose = "".join(
            chr(ord(character) + 0xFEE0)
            if index < 3 and 0x21 <= ord(character) <= 0x7E
            else character
            for index, character in enumerate(author_prose)
        )

    with pytest.raises(ValueError, match="must add independent analysis"):
        _review(**{field_name: copied_prose})


def test_statistical_method_review_rejects_placeholder_qualification_digest() -> None:
    with pytest.raises(ValidationError, match="commit to actual evidence bytes"):
        _review(reviewer_qualification_evidence_digest="0" * 64)


def test_statistical_method_review_must_precede_execution() -> None:
    with pytest.raises(ValidationError, match="before execution"):
        _review(reviewed_at_utc="2025-02-01T00:00:00Z")


@pytest.mark.parametrize(
    "byte_input",
    ("manifest_bytes", "benchmark_bytes", "registered_protocol_bytes"),
)
def test_statistical_method_review_builder_rejects_bytes_for_different_models(
    byte_input: str,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    supplied: object = b"{}\n"
    if byte_input == "registered_protocol_bytes":
        supplied = {condition_id: b"{}\n" for condition_id in fixture.protocols}

    with pytest.raises(ValueError, match="bytes do not exactly encode the supplied model"):
        _review(**{byte_input: supplied})


@pytest.mark.parametrize(
    "byte_input",
    ("manifest_bytes", "benchmark_bytes", "registered_protocol_bytes"),
)
def test_statistical_method_review_rejects_bytes_for_different_models(
    byte_input: str,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    supplied: dict[str, object] = {byte_input: b"{}\n"}
    if byte_input == "registered_protocol_bytes":
        supplied[byte_input] = {condition_id: b"{}\n" for condition_id in fixture.protocols}

    with pytest.raises(ValueError, match="bytes do not exactly encode the supplied model"):
        validate_study_statistical_method_review(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=fixture.registration_review_receipt,
            review_receipt=_review(),
            independence_audit_artifact_bytes=fixture.independence_audit_artifact_bytes,
            **supplied,  # type: ignore[arg-type]
        )


def test_statistical_method_review_requires_exact_independence_audit_bytes() -> None:
    fixture = _fixture(real_provider_execution=True)

    with pytest.raises(ValueError, match="digest does not match"):
        validate_study_statistical_method_review(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            registration_record_bytes=fixture.registration_record_bytes,
            registration_review_receipt=fixture.registration_review_receipt,
            review_receipt=_review(),
            independence_audit_artifact_bytes=b"different-audit-bytes",
        )


@pytest.mark.parametrize(
    ("artifact_bytes", "message"),
    (
        (None, "requires the digest-bound independence audit bytes"),
        (b"\xff", "must be valid UTF-8"),
        (b"AWS_SECRET_ACCESS_KEY=very-secret-test-value", "credential material"),
    ),
)
def test_independence_audit_rejects_missing_malformed_or_sensitive_bytes(
    artifact_bytes: bytes | None,
    message: str,
) -> None:
    fixture = _fixture()

    with pytest.raises(ValueError, match=message):
        validate_study_independence_audit_artifact(
            manifest=fixture.manifest,
            artifact_bytes=artifact_bytes,
        )


def test_independence_audit_rejects_oversize_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()
    monkeypatch.setattr(method_review_module, "MAX_ARTIFACT_JSON_BYTES", 1)

    with pytest.raises(ValueError, match="exceeds the supported byte limit"):
        validate_study_independence_audit_artifact(
            manifest=fixture.manifest,
            artifact_bytes=fixture.independence_audit_artifact_bytes,
        )


def test_independence_audit_rejects_bytes_without_a_manifest_commitment() -> None:
    fixture = _fixture()
    justification = fixture.manifest.hypothesis_decision_rule.independence_justification.model_copy(
        update={"design_audit_artifact_sha256": None}
    )
    rule = fixture.manifest.hypothesis_decision_rule.model_copy(
        update={"independence_justification": justification}
    )
    uncommitted_manifest = fixture.manifest.model_copy(update={"hypothesis_decision_rule": rule})

    with pytest.raises(ValueError, match="supplied without a manifest commitment"):
        validate_study_independence_audit_artifact(
            manifest=uncommitted_manifest,
            artifact_bytes=fixture.independence_audit_artifact_bytes,
        )
