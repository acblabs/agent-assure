from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError

from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_SCHEMA_VERSION,
    MACHINE_IDENTIFIER_SCHEMA_VERSIONS,
    V063_CONTRACT_SCHEMA_VERSIONS,
)
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.export import writer_json_schema
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceRef,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import validate_artifact_payload

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

    assert validate_artifact_payload(payload, "expectation") == "frozen-jsonschema"


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
    assert validate_artifact_payload(payload, "agent-run-record") == "frozen-jsonschema"


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
    assert validate_artifact_payload(payload, "compiled-suite") == "frozen-jsonschema"
