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
        "reviewer_qualification_basis": (
            "Graduate training and applied work in clustered exact binomial inference."
        ),
        "reviewer_independent_of_design_execution_and_analysis": True,
        "reviewer_independence_rationale": (
            "The reviewer did not design, execute, select, or analyze study observations."
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
