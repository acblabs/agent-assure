from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import (
    ComparisonSummary,
    comparison_evaluation_binding_error,
)
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.export import writer_json_schema
from agent_assure.schema.validation import validate_artifact_payload


def _comparison() -> ComparisonSummary:
    return ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        baseline_runset_digest="a" * 64,
        candidate_runset_digest="b" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
    )


@pytest.mark.parametrize("field_name", ("baseline_runset_digest", "candidate_runset_digest"))
def test_v064_comparison_writer_schema_requires_authenticated_runset_digests(
    field_name: str,
) -> None:
    payload = _comparison().model_dump(mode="json")
    validator = Draft202012Validator(writer_json_schema(ComparisonSummary))
    validator.validate(payload)
    payload.pop(field_name)

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(payload)


@pytest.mark.parametrize("field_name", ("baseline_runset_digest", "candidate_runset_digest"))
def test_v064_comparison_writer_schema_rejects_null_runset_digests(
    field_name: str,
) -> None:
    payload = _comparison().model_dump(mode="json")
    payload[field_name] = None

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(ComparisonSummary)).validate(payload)


def test_current_comparison_model_rejects_digest_free_payload() -> None:
    payload = _comparison().model_dump(mode="json")
    payload.pop("baseline_runset_digest")
    payload.pop("candidate_runset_digest")

    with pytest.raises(
        ValidationError,
        match="require authenticated baseline and candidate RunSet",
    ):
        ComparisonSummary.model_validate(payload)


def test_pinned_v064_comparison_contract_keeps_requiring_digests() -> None:
    payload = _comparison().model_dump(mode="json")
    payload["schema_version"] = "0.6.4"
    payload.pop("baseline_runset_digest")
    payload.pop("candidate_runset_digest")

    with pytest.raises(
        ValidationError,
        match="schema_version=0.6.4 require authenticated baseline and candidate RunSet",
    ):
        ComparisonSummary.model_validate(payload)


def test_v064_comparison_model_round_trips_through_the_writer_contract() -> None:
    payload = _comparison().model_dump(mode="json")

    assert validate_artifact_payload(payload, "comparison-summary") == "pydantic+jsonschema"


def test_legacy_comparison_can_be_projected_without_synthesized_runset_digests() -> None:
    payload = _comparison().model_dump(mode="json")
    payload["schema_version"] = "0.6.3"
    payload.pop("baseline_runset_digest")
    payload.pop("candidate_runset_digest")

    assert validate_artifact_payload(payload, "comparison-summary") == "frozen-jsonschema"
    projected = ComparisonSummary.model_validate(payload)
    assert projected.baseline_runset_digest is None
    assert projected.candidate_runset_digest is None


def test_legacy_comparison_rejects_v064_runset_digest_fields() -> None:
    payload = _comparison().model_dump(mode="json")
    payload["schema_version"] = "0.6.3"

    with pytest.raises(ValidationError, match="does not support authenticated RunSet digests"):
        ComparisonSummary.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_artifact_payload(payload, "comparison-summary")


def test_comparison_rejects_a_partial_runset_digest_identity() -> None:
    payload = _comparison().model_dump(mode="json")
    payload.pop("candidate_runset_digest")

    with pytest.raises(ValidationError, match="must either both be present or both be absent"):
        ComparisonSummary.model_validate(payload)


def test_authenticated_comparison_rejects_unbound_evaluation_identity() -> None:
    comparison = _comparison()
    evaluation = EvaluationSummary(
        runset_id=comparison.candidate_runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )

    assert comparison_evaluation_binding_error(
        comparison,
        evaluation,
        role="candidate",
    ) == ("comparison candidate_runset_digest requires an authenticated evaluation runset_digest")


def test_digestless_legacy_comparison_preserves_legacy_evaluation_compatibility() -> None:
    payload = _comparison().model_dump(mode="json")
    payload["schema_version"] = "0.6.3"
    payload.pop("baseline_runset_digest")
    payload.pop("candidate_runset_digest")
    comparison = ComparisonSummary.model_validate(payload)
    evaluation = EvaluationSummary(
        runset_id=comparison.candidate_runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )

    assert (
        comparison_evaluation_binding_error(
            comparison,
            evaluation,
            role="candidate",
        )
        is None
    )
