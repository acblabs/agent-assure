from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "0.5.0"
SchemaVersion = Literal["0.2.0", "0.3.1", "0.4.3", "0.5.0"]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        validate_assignment=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


class PersistedArtifact(StrictModel):
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

    schema_version: SchemaVersion = "0.5.0"


class RootArtifact(PersistedArtifact):
    artifact_kind: str = Field(min_length=1)
