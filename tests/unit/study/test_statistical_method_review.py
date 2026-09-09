from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_assure.schema.study import StudyStatisticalMethodReviewReceipt
from agent_assure.study_method_review import (
    build_study_statistical_method_review_receipt,
    validate_study_statistical_method_review,
)
from tests.unit.study.test_real_model_study import _fixture


def _review(**overrides: object) -> StudyStatisticalMethodReviewReceipt:
    fixture = _fixture(real_provider_execution=True)
    values: dict[str, object] = {
        "manifest": fixture.manifest,
        "benchmark": fixture.benchmark,
        "protocols": fixture.protocols,
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
        "independence_design_basis_reviewed_and_accepted": True,
        "independence_acceptance_rationale": (
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
        "power_and_decision_boundary_reachability_reviewed": True,
        "negative_control_design_reviewed": True,
    }
    values.update(overrides)
    return build_study_statistical_method_review_receipt(**values)  # type: ignore[arg-type]


def test_statistical_method_review_binds_exact_preregistered_design() -> None:
    fixture = _fixture(real_provider_execution=True)
    receipt = _review()

    validated = validate_study_statistical_method_review(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        review_receipt=receipt,
    )

    assert validated.receipt == receipt
    assert receipt.unresolved_methodological_concerns == ()


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
    ("independence_acceptance_rationale", "semantic_near_duplicate_review_rationale"),
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
            independence_acceptance_rationale=(
                fixture.manifest.hypothesis_decision_rule.independence_justification.independence_basis
            )
        )


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
            review_receipt=_review(),
            **supplied,  # type: ignore[arg-type]
        )
