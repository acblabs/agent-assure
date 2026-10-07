from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_SCHEMA_VERSION,
    MACHINE_IDENTIFIER_SCHEMA_VERSIONS,
    V063_CONTRACT_SCHEMA_VERSIONS,
)
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.export import writer_json_schema
from agent_assure.schema.live import (
    AdvancedAnalysisPlan,
    LiveEvaluationReport,
    LiveGroupSummary,
    LiveObservationResult,
    LiveProtocolRecord,
    StatisticalEndpointPlan,
)
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import (
    project_validated_artifact_payload,
    validate_artifact_payload,
)

IdentifierPayloadFactory = Callable[[str, str], tuple[type[BaseModel], dict[str, Any]]]


def _expectation_required_payload(
    value: str,
    schema_version: str,
) -> tuple[type[BaseModel], dict[str, Any]]:
    return (
        Expectation,
        {
            "artifact_kind": "expectation",
            "schema_version": schema_version,
            "expectation_id": "expectation-1",
            "case_id": "case-1",
            "required_evidence_refs": [value],
        },
    )


def _expectation_claim_payload(
    value: str,
    schema_version: str,
) -> tuple[type[BaseModel], dict[str, Any]]:
    return (
        Expectation,
        {
            "artifact_kind": "expectation",
            "schema_version": schema_version,
            "expectation_id": "expectation-1",
            "case_id": "case-1",
            "material_claim_ids": [value],
        },
    )


def _evidence_ref_claim_payload(
    value: str,
    schema_version: str,
) -> tuple[type[BaseModel], dict[str, Any]]:
    return (
        EvidenceRef,
        {
            "artifact_kind": "evidence-ref",
            "schema_version": schema_version,
            "ref_id": "ref-1",
            "source_id": "source-1",
            "claim_ids": [value],
        },
    )


def _claim_record_payload(
    value: str,
    schema_version: str,
) -> tuple[type[BaseModel], dict[str, Any]]:
    return (
        ClaimRecord,
        {
            "artifact_kind": "claim-record",
            "schema_version": schema_version,
            "claim_id": value,
        },
    )


def _claim_link_claim_payload(
    value: str,
    schema_version: str,
) -> tuple[type[BaseModel], dict[str, Any]]:
    return (
        ClaimEvidenceLink,
        {
            "artifact_kind": "claim-evidence-link",
            "schema_version": schema_version,
            "claim_id": value,
            "evidence_ref_id": "ref-1",
        },
    )


def _claim_link_ref_payload(
    value: str,
    schema_version: str,
) -> tuple[type[BaseModel], dict[str, Any]]:
    return (
        ClaimEvidenceLink,
        {
            "artifact_kind": "claim-evidence-link",
            "schema_version": schema_version,
            "claim_id": "claim-1",
            "evidence_ref_id": value,
        },
    )


IDENTIFIER_PAYLOAD_FACTORIES: tuple[
    tuple[str, IdentifierPayloadFactory],
    ...,
] = (
    ("expectation-required-evidence", _expectation_required_payload),
    ("expectation-material-claim", _expectation_claim_payload),
    ("evidence-ref-claim", _evidence_ref_claim_payload),
    ("claim-record", _claim_record_payload),
    ("claim-link-claim", _claim_link_claim_payload),
    ("claim-link-ref", _claim_link_ref_payload),
)


@pytest.mark.parametrize(
    "invalid_value",
    (
        pytest.param("unsafe\x1b[2Kidentifier\u202e", id="terminal-and-bidi-control"),
        pytest.param("identifier-with-trailing-newline\n", id="trailing-newline"),
        pytest.param("x" * (MACHINE_IDENTIFIER_MAX_CHARS + 1), id="oversized"),
    ),
)
@pytest.mark.parametrize(
    ("case_name", "payload_factory"),
    IDENTIFIER_PAYLOAD_FACTORIES,
    ids=[case_name for case_name, _ in IDENTIFIER_PAYLOAD_FACTORIES],
)
@pytest.mark.parametrize("schema_version", MACHINE_IDENTIFIER_SCHEMA_VERSIONS)
def test_current_evidence_graph_identifiers_have_model_and_schema_parity(
    case_name: str,
    payload_factory: IdentifierPayloadFactory,
    invalid_value: str,
    schema_version: str,
) -> None:
    del case_name
    model, payload = payload_factory(invalid_value, schema_version)

    with pytest.raises(PydanticValidationError):
        model.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    if schema_version == MACHINE_IDENTIFIER_SCHEMA_VERSION:
        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(writer_json_schema(model)).validate(payload)


@pytest.mark.parametrize(
    ("case_name", "payload_factory"),
    IDENTIFIER_PAYLOAD_FACTORIES,
    ids=[case_name for case_name, _ in IDENTIFIER_PAYLOAD_FACTORIES],
)
@pytest.mark.parametrize("schema_version", MACHINE_IDENTIFIER_SCHEMA_VERSIONS)
def test_current_evidence_graph_identifier_boundary_is_accepted(
    case_name: str,
    payload_factory: IdentifierPayloadFactory,
    schema_version: str,
) -> None:
    del case_name
    model, payload = payload_factory(
        "x" * MACHINE_IDENTIFIER_MAX_CHARS,
        schema_version,
    )

    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    if schema_version == MACHINE_IDENTIFIER_SCHEMA_VERSION:
        Draft202012Validator(writer_json_schema(model)).validate(payload)


@pytest.mark.parametrize(
    ("case_name", "payload_factory"),
    IDENTIFIER_PAYLOAD_FACTORIES,
    ids=[case_name for case_name, _ in IDENTIFIER_PAYLOAD_FACTORIES],
)
def test_legacy_evidence_graph_identifier_projection_remains_compatible(
    case_name: str,
    payload_factory: IdentifierPayloadFactory,
) -> None:
    del case_name
    model, payload = payload_factory("legacy\x1b[2Kidentifier\u202e", "0.6.0")

    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)


def test_current_expectation_artifact_rejects_hostile_identifier() -> None:
    _, payload = _expectation_required_payload(
        "unsafe\x1b[2Kref\u202e",
        MACHINE_IDENTIFIER_SCHEMA_VERSION,
    )

    with pytest.raises(JsonSchemaValidationError):
        validate_artifact_payload(payload, "expectation")


def test_frozen_v061_expectation_retains_machine_identifier_defense() -> None:
    _, payload = _expectation_required_payload("unsafe\x1b[2Kref\u202e", "0.6.1")

    with pytest.raises(JsonSchemaValidationError):
        validate_artifact_payload(payload, "expectation")


def test_v065_remains_in_machine_identifier_schema_generation() -> None:
    """Advancing the writer must not drop the immediately prior contract."""

    assert MACHINE_IDENTIFIER_SCHEMA_VERSIONS == (
        "0.6.1",
        "0.6.2",
        "0.6.3",
        "0.6.4",
        "0.6.5",
        "0.6.6",
    )

    model, payload = _evidence_ref_claim_payload(
        "unsafe identifier with spaces",
        "0.6.5",
    )
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)


def test_frozen_v064_machine_identifier_defense_is_independent_of_version_catalog() -> None:
    model, payload = _evidence_ref_claim_payload(
        "unsafe identifier with spaces",
        "0.6.4",
    )

    with pytest.raises(PydanticValidationError):
        model.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)


def test_frozen_expectation_artifact_retains_legacy_identifier_compatibility() -> None:
    _, payload = _expectation_required_payload("legacy\x1b[2Kref\u202e", "0.6.0")

    assert validate_artifact_payload(payload, "expectation") == "frozen-jsonschema+semantic-replay"


def _member_payloads(schema_version: str) -> tuple[tuple[str, dict[str, Any]], ...]:
    return (
        (
            "evidence_refs",
            {
                "artifact_kind": "evidence-ref",
                "schema_version": schema_version,
                "ref_id": "ref-1",
                "source_id": "source-1",
            },
        ),
        (
            "evidence_items",
            {
                "artifact_kind": "evidence-item",
                "schema_version": schema_version,
                "ref_id": "ref-1",
                "source_id": "source-1",
                "content_digest": "0" * 64,
            },
        ),
        (
            "claims",
            {
                "artifact_kind": "claim-record",
                "schema_version": schema_version,
                "claim_id": "claim-1",
            },
        ),
        (
            "claim_evidence_links",
            {
                "artifact_kind": "claim-evidence-link",
                "schema_version": schema_version,
                "claim_id": "claim-1",
                "evidence_ref_id": "ref-1",
            },
        ),
    )


def _run_record_payload(
    *,
    schema_version: str,
    member_field: str,
    member_payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        "artifact_kind": "agent-run-record",
        "schema_version": schema_version,
        "run_id": "run-1",
        "case_id": "case-1",
        "pipeline_id": "pipeline-1",
        "recommendation": "approve",
        "outcome": "approved",
        "input_summary": "redacted input",
        "output_summary": "redacted output",
        member_field: [member_payload],
    }


@pytest.mark.parametrize(
    ("member_field", "member_payload"),
    _member_payloads("0.6.0"),
    ids=[field_name for field_name, _ in _member_payloads("0.6.0")],
)
@pytest.mark.parametrize("schema_version", MACHINE_IDENTIFIER_SCHEMA_VERSIONS)
def test_current_run_record_rejects_legacy_evidence_graph_members(
    member_field: str,
    member_payload: dict[str, Any],
    schema_version: str,
) -> None:
    payload = _run_record_payload(
        schema_version=schema_version,
        member_field=member_field,
        member_payload=member_payload,
    )

    with pytest.raises(
        PydanticValidationError,
        match="current-version evidence graph members",
    ):
        AgentRunRecord.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(AgentRunRecord.model_json_schema(mode="validation")).validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_artifact_payload(payload, "agent-run-record")


@pytest.mark.parametrize(
    ("member_field", "member_payload"),
    _member_payloads("0.6.0"),
    ids=[field_name for field_name, _ in _member_payloads("0.6.0")],
)
def test_matching_legacy_run_record_evidence_graph_projection_remains_valid(
    member_field: str,
    member_payload: dict[str, Any],
) -> None:
    payload = _run_record_payload(
        schema_version="0.6.0",
        member_field=member_field,
        member_payload=member_payload,
    )

    AgentRunRecord.model_validate(payload)
    Draft202012Validator(AgentRunRecord.model_json_schema(mode="validation")).validate(payload)
    assert (
        validate_artifact_payload(payload, "agent-run-record")
        == "frozen-jsonschema+semantic-replay"
    )


_RUNSET_EVIDENCE_IDENTIFIER_FIELDS = (
    ("evidence_refs", "ref_id"),
    ("evidence_refs", "source_id"),
    ("evidence_refs", "claim_ids"),
    ("evidence_items", "ref_id"),
    ("evidence_items", "source_id"),
    ("claims", "claim_id"),
    ("claim_evidence_links", "claim_id"),
    ("claim_evidence_links", "evidence_ref_id"),
)
_MALFORMED_NESTED_IDENTIFIERS = (
    "identifier with spaces",
    "identifier\x1b[2Kwith-control",
    "identifier-with-trailing-newline\n",
)


def _runset_payload(
    parent_schema_version: str | None,
    *,
    run_payload: dict[str, Any],
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "artifact_kind": "run-set",
        "runset_id": "runset-evidence-defense",
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "suite_id": "suite-1",
        "suite_version": "1.0.0",
        "suite_digest": "2" * 64,
        "fixture_manifest_digest": "3" * 64,
        "runs": [run_payload],
    }
    if parent_schema_version is not None:
        payload["schema_version"] = parent_schema_version
    return payload


def _runset_validation_schema(*, default_parent_version: bool = False) -> dict[str, Any]:
    schema = RunSet.model_json_schema(mode="validation")
    if default_parent_version:
        schema["required"] = [
            field_name for field_name in schema["required"] if field_name != "schema_version"
        ]
    return schema


def _runset_with_legacy_evidence_identifier(
    parent_schema_version: str | None,
    *,
    member_field: str,
    identifier_field: str,
    identifier_value: str,
) -> dict[str, Any]:
    member_payloads = dict(_member_payloads("0.5.0"))
    member_payload = member_payloads[member_field]
    if identifier_field == "claim_ids":
        member_payload[identifier_field] = [identifier_value]
    else:
        member_payload[identifier_field] = identifier_value
    run_payload = _run_record_payload(
        schema_version="0.5.0",
        member_field=member_field,
        member_payload=member_payload,
    )
    return _runset_payload(parent_schema_version, run_payload=run_payload)


@pytest.mark.parametrize(
    ("member_field", "identifier_field"),
    _RUNSET_EVIDENCE_IDENTIFIER_FIELDS,
    ids=[
        f"{member_field}-{identifier_field}"
        for member_field, identifier_field in _RUNSET_EVIDENCE_IDENTIFIER_FIELDS
    ],
)
@pytest.mark.parametrize(
    "identifier_value",
    _MALFORMED_NESTED_IDENTIFIERS,
    ids=("spaces", "control", "trailing-newline"),
)
def test_current_runset_reapplies_identifier_grammar_to_legacy_evidence_graph(
    member_field: str,
    identifier_field: str,
    identifier_value: str,
) -> None:
    payload = _runset_with_legacy_evidence_identifier(
        "0.6.6",
        member_field=member_field,
        identifier_field=identifier_field,
        identifier_value=identifier_value,
    )

    with pytest.raises(PydanticValidationError, match="machine-identifier"):
        RunSet.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(_runset_validation_schema()).validate(payload)


def test_default_runset_reapplies_identifier_grammar_to_legacy_evidence_graph() -> None:
    payload = _runset_with_legacy_evidence_identifier(
        None,
        member_field="evidence_refs",
        identifier_field="claim_ids",
        identifier_value="claim-with-trailing-newline\n",
    )

    with pytest.raises(PydanticValidationError, match="machine-identifier"):
        RunSet.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(_runset_validation_schema(default_parent_version=True)).validate(
            payload
        )


@pytest.mark.parametrize(
    ("member_field", "identifier_field"),
    _RUNSET_EVIDENCE_IDENTIFIER_FIELDS,
    ids=[
        f"{member_field}-{identifier_field}"
        for member_field, identifier_field in _RUNSET_EVIDENCE_IDENTIFIER_FIELDS
    ],
)
@pytest.mark.parametrize(
    "identifier_value",
    _MALFORMED_NESTED_IDENTIFIERS,
    ids=("spaces", "control", "trailing-newline"),
)
def test_legacy_runset_retains_legacy_evidence_identifier_compatibility(
    member_field: str,
    identifier_field: str,
    identifier_value: str,
) -> None:
    payload = _runset_with_legacy_evidence_identifier(
        "0.5.0",
        member_field=member_field,
        identifier_field=identifier_field,
        identifier_value=identifier_value,
    )

    RunSet.model_validate(payload)
    Draft202012Validator(_runset_validation_schema()).validate(payload)


def _runset_with_legacy_evidence_content_conflict(
    parent_schema_version: str | None,
) -> dict[str, Any]:
    first_item = dict(_member_payloads("0.5.0"))["evidence_items"]
    second_item = first_item | {"content_digest": "1" * 64}
    run_payload = _run_record_payload(
        schema_version="0.5.0",
        member_field="evidence_items",
        member_payload=first_item,
    )
    run_payload["evidence_items"] = [first_item, second_item]
    return _runset_payload(parent_schema_version, run_payload=run_payload)


@pytest.mark.parametrize("parent_schema_version", ("0.6.6", None), ids=("explicit", "default"))
def test_current_runset_revalidates_legacy_evidence_item_content_identity(
    parent_schema_version: str | None,
) -> None:
    payload = _runset_with_legacy_evidence_content_conflict(parent_schema_version)

    with pytest.raises(PydanticValidationError, match="one content_digest"):
        RunSet.model_validate(payload)

    schema = _runset_validation_schema(
        default_parent_version=parent_schema_version is None,
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)
    assert "compound-key functional dependencies" in json.dumps(schema)


def test_legacy_runset_retains_legacy_evidence_content_identity_compatibility() -> None:
    payload = _runset_with_legacy_evidence_content_conflict("0.5.0")

    RunSet.model_validate(payload)
    Draft202012Validator(_runset_validation_schema()).validate(payload)


@pytest.mark.parametrize("schema_version", ("0.3.1", "0.4.3", "0.6.5"))
def test_historical_run_record_provider_metadata_retains_frozen_vocabulary(
    schema_version: str,
) -> None:
    payload = {
        "artifact_kind": "agent-run-record",
        "schema_version": schema_version,
        "run_id": "run-1",
        "case_id": "case-1",
        "pipeline_id": "pipeline-1",
        "recommendation": "approve",
        "outcome": "approved",
        "input_summary": "redacted input",
        "output_summary": "redacted output",
        "provider": "legacy vendor",
    }

    assert (
        validate_artifact_payload(payload, "agent-run-record")
        == "frozen-jsonschema+semantic-replay"
    )
    projected = project_validated_artifact_payload(
        payload,
        AgentRunRecord,
        kind="agent-run-record",
    )
    assert projected.provider == "legacy vendor"


@pytest.mark.parametrize(
    "field_name",
    (
        "provider",
        "model",
        "resolved_model",
        "provider_api_version",
        "provider_sdk",
        "provider_region",
        "provider_response_id",
    ),
)
@pytest.mark.parametrize(
    "invalid_value",
    ("unsafe metadata with spaces", "unsafe-metadata\n"),
)
def test_current_run_record_provider_metadata_has_model_schema_parity(
    field_name: str,
    invalid_value: str,
) -> None:
    payload = {
        "artifact_kind": "agent-run-record",
        "schema_version": "0.6.6",
        "run_id": "run-1",
        "case_id": "case-1",
        "pipeline_id": "pipeline-1",
        "recommendation": "approve",
        "outcome": "approved",
        "input_summary": "redacted input",
        "output_summary": "redacted output",
        field_name: invalid_value,
    }

    with pytest.raises(PydanticValidationError):
        AgentRunRecord.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(AgentRunRecord.model_json_schema(mode="validation")).validate(payload)


def test_current_run_record_scopes_vertex_version_separator_to_model_fields() -> None:
    vertex_model = "claude-sonnet-4@20250514"
    payload = {
        "artifact_kind": "agent-run-record",
        "schema_version": "0.6.6",
        "run_id": "run-1",
        "case_id": "case-1",
        "pipeline_id": "pipeline-1",
        "recommendation": "approve",
        "outcome": "approved",
        "input_summary": "redacted input",
        "output_summary": "redacted output",
        "provider": "anthropic",
        "model": vertex_model,
        "resolved_model": vertex_model,
        "provenance": {
            "artifact_kind": "provenance",
            "schema_version": "0.6.6",
            "model_identifier": vertex_model,
        },
    }
    schema = AgentRunRecord.model_json_schema(mode="validation")

    record = AgentRunRecord.model_validate(payload)
    Draft202012Validator(schema).validate(payload)

    assert record.model == vertex_model
    assert record.provenance.model_identifier == vertex_model
    invalid_provider = payload | {"provider": "anthropic@vertex"}
    with pytest.raises(PydanticValidationError):
        AgentRunRecord.model_validate(invalid_provider)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(invalid_provider)


def _live_observation_payload(schema_version: str) -> dict[str, Any]:
    return {
        "artifact_kind": "live-observation-result",
        "schema_version": schema_version,
        "observation_id": "observation-1",
        "run_id": "run-1",
        "case_id": "case-1",
        "repetition_index": 0,
        "schedule_index": 0,
        "randomization_block_id": "block-1",
        "prompt_digest": "0" * 64,
        "pipeline_id": "pipeline-1",
        "cluster_id": "cluster-1",
        "tool_schema_digest": "1" * 64,
        "policy_bundle_digest": "2" * 64,
        "state": "pass",
    }


def _live_rate_payload(schema_version: str, *, passed: bool) -> dict[str, Any]:
    value = "1.000000" if passed else "0.000000"
    return {
        "artifact_kind": "live-rate",
        "schema_version": schema_version,
        "label": "rate",
        "numerator": int(passed),
        "denominator": 1,
        "cluster_count": 1,
        "effective_n": "1.000000",
        "design_effect": "1.000000",
        "largest_cluster_size": 1,
        "largest_cluster_design_effect": "1.000000",
        "largest_cluster_effective_n": "1.000000",
        "assumed_intraclass_correlation": "0.000000",
        "analysis_method": "descriptive",
        "exploratory": True,
        "rate": value,
        "cluster_mean_rate": value,
        "interval_center_value": value,
        "ci_lower": value,
        "ci_upper": value,
    }


def _live_group_payload(schema_version: str) -> dict[str, Any]:
    return {
        "artifact_kind": "live-group-summary",
        "schema_version": schema_version,
        "group_id": "group-1",
        "pipeline_id": "pipeline-1",
        "observations": 1,
        "included_observations": 1,
        "excluded_observations": 0,
        "cluster_count": 1,
        "effective_n": "1.000000",
        "design_effect": "1.000000",
        "exclusion_rate": _live_rate_payload(schema_version, passed=False),
        "expectation_pass_rate": _live_rate_payload(schema_version, passed=True),
        "latency_ms": {
            "artifact_kind": "live-distribution",
            "schema_version": schema_version,
            "metric": "latency_ms",
            "count": 0,
        },
        "estimated_cost_usd": {
            "artifact_kind": "live-distribution",
            "schema_version": schema_version,
            "metric": "estimated_cost_usd",
            "count": 0,
        },
    }


@pytest.mark.parametrize(
    ("model", "payload"),
    (
        (LiveObservationResult, _live_observation_payload("0.6.5")),
        (LiveGroupSummary, _live_group_payload("0.6.5")),
    ),
)
def test_historical_live_metadata_retains_frozen_vocabulary(
    model: type[BaseModel],
    payload: dict[str, Any],
) -> None:
    payload["provider"] = "legacy vendor"

    projected = model.model_validate(payload)
    assert projected.provider == "legacy vendor"
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)


@pytest.mark.parametrize(
    ("model", "payload", "field_names"),
    (
        (
            LiveObservationResult,
            _live_observation_payload("0.6.6"),
            (
                "provider",
                "model",
                "resolved_model",
                "provider_api_version",
                "provider_sdk",
                "provider_region",
                "adapter_id",
            ),
        ),
        (
            LiveGroupSummary,
            _live_group_payload("0.6.6"),
            ("provider", "model", "adapter_id"),
        ),
    ),
)
@pytest.mark.parametrize(
    "invalid_value",
    ("unsafe metadata with spaces", "vendor-safe\n"),
    ids=("spaces", "trailing-newline"),
)
def test_current_live_metadata_has_model_schema_parity(
    model: type[BaseModel],
    payload: dict[str, Any],
    field_names: tuple[str, ...],
    invalid_value: str,
) -> None:
    schema = model.model_json_schema(mode="validation")
    for field_name in field_names:
        malformed = payload | {field_name: invalid_value}
        with pytest.raises(PydanticValidationError):
            model.model_validate(malformed)
        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(malformed)


@pytest.mark.parametrize(
    ("model", "payload", "field_names"),
    (
        (
            LiveObservationResult,
            _live_observation_payload("0.6.6"),
            ("model", "resolved_model"),
        ),
        (
            LiveGroupSummary,
            _live_group_payload("0.6.6"),
            ("model",),
        ),
    ),
)
def test_current_live_model_metadata_accepts_vertex_version_separator(
    model: type[BaseModel],
    payload: dict[str, Any],
    field_names: tuple[str, ...],
) -> None:
    schema = model.model_json_schema(mode="validation")
    for field_name in field_names:
        candidate = payload | {field_name: "claude-sonnet-4@20250514"}
        model.model_validate(candidate)
        Draft202012Validator(schema).validate(candidate)


_LIVE_REPORT_NESTED_METADATA_FIELDS = (
    ("observation", "provider"),
    ("observation", "model"),
    ("observation", "resolved_model"),
    ("observation", "provider_api_version"),
    ("observation", "provider_sdk"),
    ("observation", "provider_region"),
    ("observation", "adapter_id"),
    ("overall", "provider"),
    ("overall", "model"),
    ("overall", "adapter_id"),
    ("group", "provider"),
    ("group", "model"),
    ("group", "adapter_id"),
)


def _live_evaluation_report_payload(
    parent_schema_version: str | None,
    *,
    nested_schema_version: str,
) -> dict[str, Any]:
    current_parent = parent_schema_version in {None, "0.6.6"}
    observation = _live_observation_payload(nested_schema_version) | {
        "provider": "vendor-safe",
        "model": "model-safe",
        "resolved_model": "model-resolved-safe",
        "provider_api_version": "api-v1",
        "provider_sdk": "sdk-v1",
        "provider_region": "us-east-1",
        "adapter_id": "adapter-safe",
    }
    if current_parent:
        observation.update(
            {
                "randomization_block_id": "repetition:0",
                "cluster_id": "case-1",
                "outcome": "approved",
            }
        )

    def group_payload(group_id: str) -> dict[str, Any]:
        group = _live_group_payload(nested_schema_version) | {
            "group_id": group_id,
            "provider": "vendor-safe",
            "model": "model-safe",
            "adapter_id": "adapter-safe",
        }
        group["exclusion_rate"]["label"] = "exclusion"
        group["expectation_pass_rate"]["label"] = "expectation_pass"
        if current_parent:
            for rate in (group["exclusion_rate"], group["expectation_pass_rate"]):
                rate["analysis_method"] = "exploratory_cluster_t_interval"
                rate["exploratory"] = True
                rate["ci_lower"] = "0.000000"
                rate["ci_upper"] = "1.000000"
            outcome_rate = _live_rate_payload(nested_schema_version, passed=True)
            outcome_rate.update(
                {
                    "label": "outcome:approved",
                    "analysis_method": "exploratory_cluster_t_interval",
                    "exploratory": True,
                    "ci_lower": "0.000000",
                    "ci_upper": "1.000000",
                }
            )
            group["outcome_rates"] = [outcome_rate]
        return group

    payload: dict[str, Any] = {
        "artifact_kind": "live-evaluation-report",
        "runset_id": "runset-1",
        "suite_id": "suite-1",
        "suite_version": "1.0.0",
        "suite_digest": "3" * 64,
        "configuration_digest": "4" * 64,
        "state": "pass",
        "observations": [observation],
        "overall": group_payload("overall"),
        "groups": [
            group_payload(
                "provider=vendor-safe|model=model-safe|adapter=adapter-safe|pipeline=pipeline-1"
            )
        ],
    }
    if current_parent:
        protocol = LiveProtocolRecord(
            protocol_id="protocol-1",
            suite_id="suite-1",
            suite_version="1.0.0",
            suite_digest="3" * 64,
            analysis_method="exploratory",
            non_inferiority_margin="0.050000",
            planned_observations=1,
            planned_clusters=1,
            planned_observations_per_cluster="1.000000",
            assumed_intraclass_correlation="0.000000",
            design_effect="1.000000",
            planned_effective_n="1.000000",
            sample_size_rationale="identifier-defense fixture",
            planned_repetitions=1,
            randomization_seed=17,
            max_requests=1,
            max_total_cost_usd="1.000000",
            max_cost_per_observation_usd="1.000000",
            exclusion_policy="no exclusions",
            tool_schema_digest="1" * 64,
            policy_bundle_digest="2" * 64,
            analysis_digest="5" * 64,
            approved_data_boundary="synthetic test data",
        )
        payload.update(
            {
                "source_runset_digest": "6" * 64,
                "source_completion_status": "complete",
                "protocol_id": protocol.protocol_id,
                "protocol_digest": sha256_hexdigest(protocol),
                "protocol": protocol.model_dump(mode="json"),
                "baseline_mode": protocol.baseline_mode,
                "analysis_method": protocol.analysis_method,
                "exploratory": True,
                "cluster_by": protocol.cluster_by,
                "planned_repetitions": protocol.planned_repetitions,
                "planned_observations": protocol.planned_observations,
                "planned_clusters": protocol.planned_clusters,
            }
        )
    if parent_schema_version is not None:
        payload["schema_version"] = parent_schema_version
    return payload


def _replace_live_report_nested_metadata(
    payload: dict[str, Any],
    *,
    scope: str,
    field_name: str,
    value: str = "unsafe metadata with spaces",
) -> None:
    if scope == "observation":
        observation = payload["observations"][0]
        observation[field_name] = value
        if field_name in {"provider", "model", "adapter_id"}:
            payload["groups"][0]["group_id"] = (
                f"provider={observation['provider']}|model={observation['model']}|"
                f"adapter={observation['adapter_id']}|pipeline={observation['pipeline_id']}"
            )
        return
    summary = payload["overall"] if scope == "overall" else payload["groups"][0]
    summary[field_name] = value


def test_current_live_evaluation_parent_rejects_safe_legacy_nested_downgrade() -> None:
    payload = _live_evaluation_report_payload("0.6.6", nested_schema_version="0.6.5")

    with pytest.raises(PydanticValidationError, match="observation-derived evidence"):
        LiveEvaluationReport.model_validate(payload)


def test_current_live_report_accepts_vertex_ids_in_nested_model_fields() -> None:
    payload = _live_evaluation_report_payload("0.6.6", nested_schema_version="0.6.6")
    vertex_model = "claude-sonnet-4@20250514"
    payload["observations"][0]["model"] = vertex_model
    payload["observations"][0]["resolved_model"] = vertex_model
    payload["overall"]["model"] = vertex_model
    payload["groups"][0]["model"] = vertex_model
    payload["groups"][0]["group_id"] = (
        f"provider=vendor-safe|model={vertex_model}|adapter=adapter-safe|pipeline=pipeline-1"
    )
    schema = LiveEvaluationReport.model_json_schema(mode="validation")

    LiveEvaluationReport.model_validate(payload)
    Draft202012Validator(schema).validate(payload)


@pytest.mark.parametrize(
    ("scope", "field_name"),
    _LIVE_REPORT_NESTED_METADATA_FIELDS,
    ids=[f"{scope}-{field_name}" for scope, field_name in _LIVE_REPORT_NESTED_METADATA_FIELDS],
)
def test_current_live_evaluation_parent_rejects_legacy_nested_metadata_downgrade(
    scope: str,
    field_name: str,
) -> None:
    payload = _live_evaluation_report_payload("0.6.6", nested_schema_version="0.6.5")
    _replace_live_report_nested_metadata(payload, scope=scope, field_name=field_name)

    with pytest.raises(PydanticValidationError, match="machine-identifier"):
        LiveEvaluationReport.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveEvaluationReport.model_json_schema(mode="validation")).validate(
            payload
        )


def test_default_live_evaluation_parent_rejects_legacy_nested_metadata_downgrade() -> None:
    payload = _live_evaluation_report_payload(None, nested_schema_version="0.6.5")
    _replace_live_report_nested_metadata(payload, scope="observation", field_name="provider")

    with pytest.raises(PydanticValidationError, match="machine-identifier"):
        LiveEvaluationReport.model_validate(payload)


def test_current_live_evaluation_parent_rejects_legacy_nested_trailing_newline() -> None:
    payload = _live_evaluation_report_payload("0.6.6", nested_schema_version="0.6.5")
    _replace_live_report_nested_metadata(
        payload,
        scope="observation",
        field_name="provider",
        value="vendor-safe\n",
    )

    with pytest.raises(PydanticValidationError, match="machine-identifier"):
        LiveEvaluationReport.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveEvaluationReport.model_json_schema(mode="validation")).validate(
            payload
        )


@pytest.mark.parametrize(
    ("scope", "field_name"),
    _LIVE_REPORT_NESTED_METADATA_FIELDS,
    ids=[f"{scope}-{field_name}" for scope, field_name in _LIVE_REPORT_NESTED_METADATA_FIELDS],
)
def test_historical_live_evaluation_parent_reconciles_legacy_nested_metadata(
    scope: str,
    field_name: str,
) -> None:
    payload = _live_evaluation_report_payload("0.6.5", nested_schema_version="0.6.5")
    _replace_live_report_nested_metadata(payload, scope=scope, field_name=field_name)

    summarized_identity = scope != "observation" or field_name in {
        "provider",
        "model",
        "adapter_id",
    }
    if summarized_identity:
        with pytest.raises(
            PydanticValidationError,
            match="identity does not match|group summaries do not match",
        ):
            LiveEvaluationReport.model_validate(payload)
    else:
        LiveEvaluationReport.model_validate(payload)
    Draft202012Validator(LiveEvaluationReport.model_json_schema(mode="validation")).validate(
        payload
    )


@pytest.mark.parametrize("parent_schema_version", ("0.6.6", None), ids=("explicit", "default"))
@pytest.mark.parametrize(
    "field_name",
    ("prompt_digest", "schedule_index", "randomization_block_id"),
)
@pytest.mark.parametrize("mutation", ("missing", "null"))
def test_current_live_evaluation_parent_requires_legacy_nested_pairing_identity(
    parent_schema_version: str | None,
    field_name: str,
    mutation: str,
) -> None:
    payload = _live_evaluation_report_payload(
        parent_schema_version,
        nested_schema_version="0.6.5",
    )
    if mutation == "missing":
        payload["observations"][0].pop(field_name)
    else:
        payload["observations"][0][field_name] = None

    with pytest.raises(PydanticValidationError, match="prompt, schedule, and randomization"):
        LiveEvaluationReport.model_validate(payload)
    schema = LiveEvaluationReport.model_json_schema(mode="validation")
    if parent_schema_version is None:
        schema["required"] = [
            required_field
            for required_field in schema["required"]
            if required_field != "schema_version"
        ]
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(payload)


def test_historical_live_evaluation_parent_rejects_unsupported_nested_version() -> None:
    payload = _live_evaluation_report_payload("0.6.5", nested_schema_version="0.5.0")
    for field_name in ("prompt_digest", "schedule_index", "randomization_block_id"):
        payload["observations"][0].pop(field_name)

    with pytest.raises(
        PydanticValidationError, match="not supported by the live artifact contract"
    ):
        LiveEvaluationReport.model_validate(payload)
    Draft202012Validator(LiveEvaluationReport.model_json_schema(mode="validation")).validate(
        payload
    )


@pytest.mark.parametrize(
    ("model", "payload"),
    (
        (
            AgentRunRecord,
            {
                "artifact_kind": "agent-run-record",
                "run_id": "run-1",
                "case_id": "case-1",
                "pipeline_id": "pipeline-1",
                "recommendation": "approve",
                "outcome": "approved",
                "input_summary": "redacted input",
                "output_summary": "redacted output",
            },
        ),
        (LiveObservationResult, _live_observation_payload("0.6.6")),
    ),
)
def test_omitted_version_defaults_to_current_provider_metadata_contract(
    model: type[BaseModel],
    payload: dict[str, Any],
) -> None:
    payload.pop("schema_version", None)
    malformed = payload | {"provider": "unsafe metadata with spaces"}

    with pytest.raises(PydanticValidationError, match="machine-identifier"):
        model.model_validate(malformed)
    schema = model.model_json_schema(mode="validation")
    schema["required"] = [
        field_name for field_name in schema["required"] if field_name != "schema_version"
    ]
    Draft202012Validator(schema).validate(payload | {"provider": "vendor-safe"})
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(malformed)


def _poisson_endpoint_payload(schema_version: str | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "artifact_kind": "statistical-endpoint-plan",
        "endpoint_id": "rare-runtime-failure",
        "label": "Rare runtime failure",
        "endpoint_kind": "critical_event_rate",
        "analysis_method": "poisson_upper_bound",
        "reason_codes": ["RUNTIME_FAILED"],
        "exposure_unit": "observation",
    }
    if schema_version is not None:
        payload["schema_version"] = schema_version
    return payload


def _exact_binomial_endpoint_payload(schema_version: str | None) -> dict[str, Any]:
    return _poisson_endpoint_payload(schema_version) | {
        "analysis_method": "clopper_pearson_exact_one_sided"
    }


def test_v065_poisson_observation_exposure_remains_projectable() -> None:
    payload = _poisson_endpoint_payload("0.6.5")
    root = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "schemas"
            / "v0.6.5"
            / "live-protocol-record.schema.json"
        ).read_text(encoding="utf-8")
    )
    frozen_endpoint_schema = {
        "$schema": root["$schema"],
        "$defs": root["$defs"],
        "$ref": "#/$defs/StatisticalEndpointPlan",
    }

    Draft202012Validator(frozen_endpoint_schema).validate(payload)
    endpoint = StatisticalEndpointPlan.model_validate(payload)
    assert endpoint.exposure_unit == "observation"
    Draft202012Validator(StatisticalEndpointPlan.model_json_schema(mode="validation")).validate(
        payload
    )


@pytest.mark.parametrize("schema_version", ("0.6.6", None))
def test_current_exact_binomial_cluster_exposure_has_model_schema_parity(
    schema_version: str | None,
) -> None:
    payload = _exact_binomial_endpoint_payload(schema_version)

    with pytest.raises(PydanticValidationError, match="independence_cluster"):
        StatisticalEndpointPlan.model_validate(payload)
    schema = StatisticalEndpointPlan.model_json_schema(mode="validation")
    if schema_version is None:
        schema["required"] = [
            field_name for field_name in schema["required"] if field_name != "schema_version"
        ]
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(payload)

    corrected = payload | {"exposure_unit": "independence_cluster"}
    StatisticalEndpointPlan.model_validate(corrected)
    Draft202012Validator(schema).validate(corrected)


def _poisson_advanced_plan_payload(
    parent_schema_version: str | None,
    *,
    endpoint_schema_version: str,
) -> dict[str, Any]:
    endpoint = _poisson_endpoint_payload(endpoint_schema_version) | {"role": "primary"}
    payload: dict[str, Any] = {
        "artifact_kind": "advanced-analysis-plan",
        "endpoints": [endpoint],
    }
    if parent_schema_version is not None:
        payload["schema_version"] = parent_schema_version
    return payload


@pytest.mark.parametrize("parent_schema_version", ("0.6.6", None), ids=("explicit", "default"))
def test_current_advanced_plan_rejects_legacy_poisson_exposure_downgrade(
    parent_schema_version: str | None,
) -> None:
    payload = _poisson_advanced_plan_payload(
        parent_schema_version,
        endpoint_schema_version="0.6.5",
    )

    with pytest.raises(PydanticValidationError, match="clopper_pearson_exact_one_sided"):
        AdvancedAnalysisPlan.model_validate(payload)
    schema = AdvancedAnalysisPlan.model_json_schema(mode="validation")
    if parent_schema_version is None:
        schema["required"] = [
            field_name for field_name in schema["required"] if field_name != "schema_version"
        ]
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(payload)

    corrected = payload.copy()
    corrected["endpoints"] = [
        payload["endpoints"][0]
        | {
            "analysis_method": "clopper_pearson_exact_one_sided",
            "exposure_unit": "independence_cluster",
        }
    ]
    AdvancedAnalysisPlan.model_validate(corrected)
    Draft202012Validator(schema).validate(corrected)


def test_historical_advanced_plan_reads_legacy_poisson_observation_exposure() -> None:
    payload = _poisson_advanced_plan_payload("0.6.5", endpoint_schema_version="0.6.5")

    plan = AdvancedAnalysisPlan.model_validate(payload)
    assert plan.endpoints[0].exposure_unit == "observation"
    Draft202012Validator(AdvancedAnalysisPlan.model_json_schema(mode="validation")).validate(
        payload
    )


def _advanced_analysis_plan_payload(
    schema_version: str | None,
    *,
    familywise_alpha: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "artifact_kind": "advanced-analysis-plan",
        "multiplicity_method": "bonferroni",
        "familywise_alpha": familywise_alpha,
        "endpoints": [],
    }
    if schema_version is not None:
        payload["schema_version"] = schema_version
    endpoints = payload["endpoints"]
    assert isinstance(endpoints, list)
    for index in range(3):
        endpoint: dict[str, Any] = {
            "artifact_kind": "statistical-endpoint-plan",
            "endpoint_id": f"endpoint-{index + 1}",
            "label": f"Endpoint {index + 1}",
            "endpoint_kind": "expectation_pass_rate",
            "role": "primary" if index == 0 else "secondary",
            "interpretation": "confirmatory",
        }
        if schema_version is not None:
            endpoint["schema_version"] = schema_version
        endpoints.append(endpoint)
    return payload


def test_v065_bonferroni_half_even_projection_remains_valid() -> None:
    payload = _advanced_analysis_plan_payload("0.6.5", familywise_alpha="0.000002")
    root = json.loads(
        (
            Path(__file__).resolve().parents[3]
            / "schemas"
            / "v0.6.5"
            / "live-protocol-record.schema.json"
        ).read_text(encoding="utf-8")
    )
    frozen_plan_schema = {
        "$schema": root["$schema"],
        "$defs": root["$defs"],
        "$ref": "#/$defs/AdvancedAnalysisPlan",
    }

    Draft202012Validator(frozen_plan_schema).validate(payload)
    plan = AdvancedAnalysisPlan.model_validate(payload)
    assert plan.familywise_alpha == "0.000002"
    Draft202012Validator(AdvancedAnalysisPlan.model_json_schema(mode="validation")).validate(
        payload
    )


@pytest.mark.parametrize("schema_version", ("0.6.6", None))
def test_current_bonferroni_uses_floor_at_persisted_precision(
    schema_version: str | None,
) -> None:
    payload = _advanced_analysis_plan_payload(
        schema_version,
        familywise_alpha="0.000002",
    )

    with pytest.raises(PydanticValidationError, match="below the persisted six-decimal precision"):
        AdvancedAnalysisPlan.model_validate(payload)

    corrected = _advanced_analysis_plan_payload(
        schema_version,
        familywise_alpha="0.000003",
    )
    AdvancedAnalysisPlan.model_validate(corrected)


@pytest.mark.parametrize("schema_version", ("0.6.6", None))
def test_current_bonferroni_zero_alpha_has_model_schema_parity(
    schema_version: str | None,
) -> None:
    payload = _advanced_analysis_plan_payload(
        schema_version,
        familywise_alpha="0.000000",
    )
    schema = AdvancedAnalysisPlan.model_json_schema(mode="validation")
    if schema_version is None:
        schema["required"] = [
            field_name for field_name in schema["required"] if field_name != "schema_version"
        ]

    with pytest.raises(PydanticValidationError, match="greater than zero"):
        AdvancedAnalysisPlan.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(payload)

    assert "cannot express division" in schema["$comment"]
    assert "runtime" in schema["$comment"]


def _compiled_suite_payload(
    *,
    suite_schema_version: str,
    expectation_schema_version: str,
    required_evidence_ref: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "artifact_kind": "compiled-suite",
        "schema_version": suite_schema_version,
        "suite_id": "suite-1",
        "suite_version": "1",
        "cases": [
            {
                "artifact_kind": "suite-case",
                "schema_version": suite_schema_version,
                "case_id": "case-1",
                "title": "Case 1",
                "expectation_id": "expectation-1",
            }
        ],
        "resolved_expectations": [
            {
                "artifact_kind": "expectation",
                "schema_version": expectation_schema_version,
                "expectation_id": "expectation-1",
                "case_id": "case-1",
                "required_evidence_refs": [required_evidence_ref],
            }
        ],
        "source_digest": "0" * 64,
    }
    if suite_schema_version in V063_CONTRACT_SCHEMA_VERSIONS:
        payload["defaults"] = {"runner_id": "test.runner"}
    return payload


@pytest.mark.parametrize("schema_version", MACHINE_IDENTIFIER_SCHEMA_VERSIONS)
def test_current_compiled_suite_rejects_legacy_expectation_member(
    schema_version: str,
) -> None:
    payload = _compiled_suite_payload(
        suite_schema_version=schema_version,
        expectation_schema_version="0.6.0",
        required_evidence_ref="legacy\x1b[2Kref\u202e",
    )

    with pytest.raises(
        PydanticValidationError,
        match="machine-ID-era compiled suites",
    ):
        CompiledSuite.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(CompiledSuite.model_json_schema(mode="validation")).validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_artifact_payload(payload, "compiled-suite")


def test_matching_legacy_compiled_suite_projection_remains_valid() -> None:
    payload = _compiled_suite_payload(
        suite_schema_version="0.6.0",
        expectation_schema_version="0.6.0",
        required_evidence_ref="legacy\x1b[2Kref\u202e",
    )

    CompiledSuite.model_validate(payload)
    Draft202012Validator(CompiledSuite.model_json_schema(mode="validation")).validate(payload)
    assert (
        validate_artifact_payload(payload, "compiled-suite") == "frozen-jsonschema+semantic-replay"
    )
