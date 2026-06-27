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


def test_live_protocol_artifact_matches_pydantic_and_jsonschema(tmp_path) -> None:  # type: ignore[no-untyped-def]
    payload = {
        "artifact_kind": "live-protocol-record",
        "schema_version": "0.1.0",
        "protocol_id": "protocol-live-001",
        "suite_id": "expense-approval-minimal",
        "suite_version": "0.1.0",
        "suite_digest": "0" * 64,
        "baseline_mode": "concurrent_paired",
        "hypothesis_family": "governance_control_non_inferiority",
        "primary_endpoint": "expectation_pass_rate",
        "analysis_method": "paired_cluster_t_interval",
        "baseline_group_id": "overall",
        "candidate_group_id": "overall",
        "confidence_level": "0.950000",
        "non_inferiority_margin": "0.050000",
        "cluster_by": "case_id",
        "planned_observations": 6,
        "planned_clusters": 3,
        "planned_observations_per_cluster": "2.000000",
        "assumed_intraclass_correlation": "0.200000",
        "design_effect": "1.200000",
        "planned_effective_n": "5.000000",
        "sample_size_rationale": "schema parity fixture",
        "planned_repetitions": 2,
        "randomization_seed": 17,
        "randomization_blocking": "balanced_case_blocks",
        "max_requests": 6,
        "max_total_cost_usd": "10.000000",
        "max_cost_per_observation_usd": "1.000000",
        "max_retries": 2,
        "retry_initial_backoff_seconds": "1.000000",
        "retry_max_backoff_seconds": "8.000000",
        "exclusion_policy": "only pre-provider configuration exclusions are allowed",
        "allowed_exclusion_reasons": ["budget_exhausted"],
        "max_exclusion_rate": "0.000000",
        "provider_version_capture": ["resolved_model", "provider_api_version", "provider_sdk"],
        "stopping_rules": ["stop on sensitive persistence"],
        "tool_schema_digest": "2" * 64,
        "policy_bundle_digest": "3" * 64,
        "analysis_digest": "1" * 64,
        "approved_data_boundary": "synthetic local prompts only",
        "safety_limits": ["stop if sensitive content is persisted"],
    }
    model = SCHEMA_MODELS["live-protocol-record"]
    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    path = tmp_path / "live-protocol.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_artifact(path, "live-protocol-record") == "pydantic+jsonschema"


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
