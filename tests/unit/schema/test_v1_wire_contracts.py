"""Field-level evidence for implemented v1 values, not complete-set acceptance."""

from __future__ import annotations

import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from agent_assure.schema.v1_identity import SourceEventIdentity

COMPONENTS = ("run_id", "producer_id", "producer_epoch", "event_id")
IDENTITY = {
    "identity_contract_id": "source-event-identity/v1",
    "run_id": "run",
    "producer_id": "producer",
    "producer_epoch": "epoch",
    "event_id": "event",
}
IDENTITY_SCHEMA = SourceEventIdentity.model_json_schema()


def _assert_rejected_by_model_and_schema(value: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SourceEventIdentity.model_validate(value)
    assert not Draft202012Validator(IDENTITY_SCHEMA).is_valid(value)


def test_source_identity_schema_exposes_only_the_exact_required_value_fields() -> None:
    Draft202012Validator.check_schema(IDENTITY_SCHEMA)
    assert IDENTITY_SCHEMA["type"] == "object"
    assert IDENTITY_SCHEMA["additionalProperties"] is False
    assert set(IDENTITY_SCHEMA["properties"]) == set(IDENTITY)
    assert set(IDENTITY_SCHEMA["required"]) == set(IDENTITY)
    discriminator = IDENTITY_SCHEMA["properties"]["identity_contract_id"]
    assert discriminator["const"] == "source-event-identity/v1"
    assert "default" not in discriminator
    for field in COMPONENTS:
        declaration = IDENTITY_SCHEMA["properties"][field]
        assert declaration["type"] == "string"
        assert declaration["minLength"] == 1
        assert declaration["maxLength"] == 512


@pytest.mark.parametrize("field", tuple(IDENTITY))
def test_source_identity_never_supplies_a_missing_component(field: str) -> None:
    value = {key: item for key, item in IDENTITY.items() if key != field}
    _assert_rejected_by_model_and_schema(value)


@pytest.mark.parametrize("invalid", [None, True, 1, "source-event-identity/v2", ""])
def test_source_identity_requires_the_exact_discriminator(invalid: Any) -> None:
    _assert_rejected_by_model_and_schema({**IDENTITY, "identity_contract_id": invalid})


@pytest.mark.parametrize("field", COMPONENTS)
@pytest.mark.parametrize("invalid", [None, False, True, 0, 1.5, b"id", ["id"], {"id": "value"}])
def test_source_identity_components_are_strict_strings(field: str, invalid: Any) -> None:
    _assert_rejected_by_model_and_schema({**IDENTITY, field: invalid})


@pytest.mark.parametrize("field", COMPONENTS)
@pytest.mark.parametrize("text", ["", "x" * 513, "\U0001f9ea" * 513])
def test_source_identity_rejects_empty_or_oversized_components(field: str, text: str) -> None:
    _assert_rejected_by_model_and_schema({**IDENTITY, field: text})


@pytest.mark.parametrize("field", COMPONENTS)
@pytest.mark.parametrize("text", ["x", "x" * 512, "\U0001f9ea" * 512])
def test_source_identity_bounds_count_characters_without_byte_truncation(
    field: str, text: str
) -> None:
    value = {**IDENTITY, field: text}
    parsed = SourceEventIdentity.model_validate(value)
    assert parsed.model_dump(mode="json") == value
    assert Draft202012Validator(IDENTITY_SCHEMA).is_valid(value)
    assert json.loads(parsed.model_dump_json()) == value


@pytest.mark.parametrize("field", ["artifact_kind", "schema_version", "self_digest", "signature"])
def test_source_identity_rejects_artifact_envelope_fields(field: str) -> None:
    _assert_rejected_by_model_and_schema({**IDENTITY, field: "not-part-of-this-identity"})


def test_source_identity_is_immutable_after_validation() -> None:
    parsed = SourceEventIdentity.model_validate(IDENTITY)
    with pytest.raises(ValidationError) as rejected:
        parsed.run_id = "replacement"
    assert rejected.value.errors()[0]["type"] == "frozen_instance"
    assert parsed.model_dump(mode="json") == IDENTITY


def test_source_identity_preserves_case_whitespace_and_non_normalized_unicode() -> None:
    value = {
        "identity_contract_id": "source-event-identity/v1",
        "run_id": " \tRun:|/ ",
        "producer_id": "\u00e9",
        "producer_epoch": "e\u0301",
        "event_id": "  ",
    }
    parsed = SourceEventIdentity.model_validate(value)
    assert parsed.producer_id != parsed.producer_epoch
    assert parsed.model_dump(mode="json") == value
    assert json.loads(parsed.model_dump_json()) == value
    assert Draft202012Validator(IDENTITY_SCHEMA).is_valid(value)
    assert parsed != SourceEventIdentity.model_validate(
        {**value, "run_id": value["run_id"].lower()}
    )


def test_source_identity_keeps_delimiter_collisions_distinct() -> None:
    first = SourceEventIdentity.model_validate({**IDENTITY, "run_id": "a:b", "producer_id": "c"})
    second = SourceEventIdentity.model_validate({**IDENTITY, "run_id": "a", "producer_id": "b:c"})
    assert ":".join([first.run_id, first.producer_id]) == ":".join(
        [second.run_id, second.producer_id]
    )
    assert first != second
    assert first.model_dump(mode="json") != second.model_dump(mode="json")


def test_source_identity_parses_json_without_normalizing_or_defaulting_fields() -> None:
    value = {**IDENTITY, "run_id": "e\u0301", "event_id": "\U0001f9ea" * 512}
    parsed = SourceEventIdentity.model_validate_json(json.dumps(value))
    assert parsed.model_dump(mode="json") == value
    missing = {key: item for key, item in value.items() if key != "identity_contract_id"}
    with pytest.raises(ValidationError):
        SourceEventIdentity.model_validate_json(json.dumps(missing))


@pytest.mark.parametrize("field", COMPONENTS)
@pytest.mark.parametrize("invalid", [None, True, 1, "", "x" * 513])
def test_source_identity_json_input_retains_strict_component_bounds(
    field: str, invalid: Any
) -> None:
    value = {**IDENTITY, field: invalid}
    with pytest.raises(ValidationError):
        SourceEventIdentity.model_validate_json(json.dumps(value))
    assert not Draft202012Validator(IDENTITY_SCHEMA).is_valid(value)
