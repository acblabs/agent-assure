from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.schema.export import SCHEMA_MODELS
from agent_assure.schema.validation import validate_artifact


def test_valid_artifacts_match_pydantic_and_jsonschema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = compile_suite(__import__("pathlib").Path("examples/prior_auth_synthetic/suite.yaml"))
    payload = compiled.model_dump(mode="json")
    model = SCHEMA_MODELS["compiled-suite"]
    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    path = tmp_path / "compiled.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_artifact(path, "compiled-suite") == "pydantic+jsonschema"


def test_invalid_artifact_rejected_by_both_validators() -> None:
    payload = {
        "artifact_kind": "compiled-suite",
        "schema_version": "0.1.0",
        "suite_id": "demo",
        "suite_version": "0.1.0",
        "cases": [],
        "resolved_expectations": [],
        "source_digest": "0" * 64,
        "extra": "nope",
    }
    model = SCHEMA_MODELS["compiled-suite"]
    with pytest.raises(PydanticValidationError):
        model.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
