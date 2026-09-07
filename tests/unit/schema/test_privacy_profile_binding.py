from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.run import RunSet

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "schema_version",
    ("0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"),
)
def test_machine_id_era_artifact_schemas_require_privacy_profile_pair(
    schema_version: str,
) -> None:
    artifacts = (
        (
            RunSet,
            {
                "runset_id": "runset-001",
                "suite_id": "suite-001",
                "suite_version": "0.1.0",
                "suite_digest": "0" * 64,
                "fixture_manifest_digest": "1" * 64,
                "runs": [],
            },
        ),
        (
            EvaluationSummary,
            {"runset_id": "runset-001", "state": "pass"},
        ),
        (
            ComparisonSummary,
            {
                "baseline_runset_id": "baseline",
                "candidate_runset_id": "candidate",
                "classification": "unchanged",
            },
        ),
    )
    for model, payload in artifacts:
        identified_payload = {
            **payload,
            "artifact_kind": model.model_fields["artifact_kind"].default,
            "schema_version": schema_version,
        }
        if model is ComparisonSummary and schema_version in {"0.6.4", "0.6.5", "0.6.6"}:
            identified_payload.update(
                {
                    "baseline_runset_digest": "2" * 64,
                    "candidate_runset_digest": "3" * 64,
                }
            )
        if model is EvaluationSummary and schema_version in {"0.6.5", "0.6.6"}:
            identified_payload["runset_digest"] = "4" * 64
        validator = Draft202012Validator(model.model_json_schema())
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(identified_payload)
        validator.validate(
            {
                **identified_payload,
                "privacy_profile_id": PRIVACY_PROFILE_ID,
                "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
            }
        )


def test_legacy_summary_dumps_remain_valid_against_frozen_schemas() -> None:
    evaluation = EvaluationSummary.model_validate(
        {
            "schema_version": "0.4.3",
            "runset_id": "candidate",
            "state": "pass",
        }
    )
    comparison = ComparisonSummary.model_validate(
        {
            "schema_version": "0.4.3",
            "baseline_runset_id": "baseline",
            "candidate_runset_id": "candidate",
            "classification": "provenance_only_change",
        }
    )

    for artifact, schema_name in (
        (evaluation, "evaluation-summary.schema.json"),
        (comparison, "comparison-summary.schema.json"),
    ):
        payload = artifact.model_dump(mode="json")
        assert "privacy_profile_id" not in payload
        assert "privacy_profile_digest" not in payload
        schema = json.loads((ROOT / "schemas" / "v0.4.3" / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(payload)
