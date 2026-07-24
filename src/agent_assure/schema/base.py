from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, GetJsonSchemaHandler, model_validator
from pydantic_core import CoreSchema

SCHEMA_VERSION = "0.6.0"
SchemaVersion = Literal["0.2.0", "0.3.1", "0.4.3", "0.5.0", "0.6.0"]
RFC8785_SAFE_INTEGER_MAX = (1 << 53) - 1
RFC8785_SAFE_INTEGER_MIN = -RFC8785_SAFE_INTEGER_MAX


def validate_rfc8785_safe_integers(value: object, *, owner: str) -> None:
    """Reject integer values that RFC 8785 cannot represent exactly."""
    pending: list[tuple[str, object]] = [("$", value)]
    while pending:
        path, candidate = pending.pop()
        if isinstance(candidate, bool) or candidate is None:
            continue
        if isinstance(candidate, int):
            if not RFC8785_SAFE_INTEGER_MIN <= candidate <= RFC8785_SAFE_INTEGER_MAX:
                raise ValueError(
                    f"{owner} integer at {path} exceeds the RFC 8785 safe integer domain"
                )
            continue
        if isinstance(candidate, Mapping):
            pending.extend(
                (f"{path}.{key}", nested) for key, nested in candidate.items()
            )
            continue
        if isinstance(candidate, Sequence) and not isinstance(
            candidate, str | bytes | bytearray
        ):
            pending.extend(
                (f"{path}[{index}]", nested)
                for index, nested in enumerate(candidate)
            )


class StrictModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        validate_assignment=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


class FrozenStrictModel(StrictModel):
    """Strict value object whose validated fields cannot be reassigned."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        validate_assignment=True,
        frozen=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


class PersistedArtifact(FrozenStrictModel):
    # Frozen persisted artifacts cannot be assigned after validation, but keep
    # validate_assignment aligned with StrictModel so future config diffs are
    # deliberate rather than accidental.
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        validate_assignment=True,
        frozen=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )

    schema_version: SchemaVersion = "0.6.0"

    @model_validator(mode="before")
    @classmethod
    def _validate_safe_integer_domain(cls, value: object) -> object:
        validate_rfc8785_safe_integers(value, owner=cls.__name__)
        return value

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> dict[str, Any]:
        schema = super().__get_pydantic_json_schema__(core_schema, handler)
        properties = schema.get("properties", {})
        required = list(schema.get("required", ()))
        for field_name in ("artifact_kind", "schema_version"):
            if field_name in properties and field_name not in required:
                required.append(field_name)
        schema["required"] = required
        return schema


class RootArtifact(PersistedArtifact):
    artifact_kind: str = Field(min_length=1)
