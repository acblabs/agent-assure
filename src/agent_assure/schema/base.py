from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, GetJsonSchemaHandler
from pydantic_core import CoreSchema

SCHEMA_VERSION = "0.6.0"
SchemaVersion = Literal["0.2.0", "0.3.1", "0.4.3", "0.5.0", "0.6.0"]


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
