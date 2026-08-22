from __future__ import annotations

from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.export import writer_json_schema


def _assert_current_model_and_writer_schema_reject(
    model: type[BaseModel],
    payload: dict[str, Any],
) -> None:
    with pytest.raises(PydanticValidationError):
        model.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(model)).validate(payload)


@pytest.mark.parametrize("schema_version", ("0.6.3", SCHEMA_VERSION))
def test_current_evaluation_summary_rejects_empty_graph_source_identity(
    schema_version: str,
) -> None:
    _assert_current_model_and_writer_schema_reject(
        EvaluationSummary,
        {
            "artifact_kind": "evaluation-summary",
            "schema_version": schema_version,
            "runset_id": "",
            "privacy_profile_id": PRIVACY_PROFILE_ID,
            "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
            "state": "pass",
            "findings": [],
        },
    )


@pytest.mark.parametrize("field_name", ("baseline_runset_id", "candidate_runset_id"))
@pytest.mark.parametrize("schema_version", ("0.6.3", SCHEMA_VERSION))
def test_current_comparison_summary_rejects_empty_graph_source_identity(
    field_name: str,
    schema_version: str,
) -> None:
    payload = {
        "artifact_kind": "comparison-summary",
        "schema_version": schema_version,
        "baseline_runset_id": "baseline",
        "candidate_runset_id": "candidate",
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "classification": "not_evaluated",
    }
    payload[field_name] = ""

    _assert_current_model_and_writer_schema_reject(ComparisonSummary, payload)


@pytest.mark.parametrize("schema_version", ("0.6.3", SCHEMA_VERSION))
def test_current_evaluation_finding_rejects_empty_graph_source_identity(
    schema_version: str,
) -> None:
    payload = {
        "artifact_kind": "finding",
        "schema_version": schema_version,
        "finding_id": "finding",
        "case_id": "case",
        "state": "fail",
        "reason_code": "RUNTIME_FAILED",
        "message": "Synthetic finding.",
    }
    payload["finding_id"] = ""

    _assert_current_model_and_writer_schema_reject(Finding, payload)


def test_current_evaluation_finding_allows_unscoped_case_identity() -> None:
    payload = {
        "artifact_kind": "finding",
        "schema_version": SCHEMA_VERSION,
        "finding_id": "finding-unscoped",
        "case_id": "",
        "state": "fail",
        "reason_code": "RUNTIME_FAILED",
        "message": "Synthetic unscoped finding.",
    }

    finding = Finding.model_validate(payload)
    Draft202012Validator(writer_json_schema(Finding)).validate(payload)

    assert finding.case_id == ""


def test_legacy_source_models_retain_historical_empty_identifier_contract() -> None:
    finding_payload = {
        "artifact_kind": "finding",
        "schema_version": "0.6.2",
        "finding_id": "",
        "case_id": "",
        "state": "fail",
        "reason_code": "RUNTIME_FAILED",
        "message": "Legacy finding.",
    }
    evaluation_payload = {
        "artifact_kind": "evaluation-summary",
        "schema_version": "0.6.2",
        "runset_id": "",
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "state": "pass",
        "findings": [],
    }
    comparison_payload = {
        "artifact_kind": "comparison-summary",
        "schema_version": "0.6.2",
        "baseline_runset_id": "",
        "candidate_runset_id": "",
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "classification": "not_evaluated",
    }

    for model, payload in (
        (Finding, finding_payload),
        (EvaluationSummary, evaluation_payload),
        (ComparisonSummary, comparison_payload),
    ):
        model.model_validate(payload)
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
