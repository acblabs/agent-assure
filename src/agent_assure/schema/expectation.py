from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_SCHEMA_VERSIONS,
    DigestHex,
    coerce_tuple,
    current_machine_identifier_json_schema_extra,
    validate_machine_identifier,
)


class Expectation(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=current_machine_identifier_json_schema_extra(
            sequence_fields=("required_evidence_refs", "material_claim_ids"),
        )
    )

    artifact_kind: Literal["expectation"] = "expectation"
    expectation_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    expectation_digest: DigestHex | None = None
    expected_recommendation: str | None = None
    allowed_outcomes: tuple[str, ...] = ()
    forbidden_outcomes: tuple[str, ...] = ()
    required_evidence_refs: tuple[str, ...] = ()
    material_claim_ids: tuple[str, ...] = ()
    allowed_providers: tuple[str, ...] = ()
    forbidden_providers: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    allowed_tools_override: bool = False
    forbidden_tools: tuple[str, ...] = ()
    required_human_review: bool = False

    @field_validator(
        "allowed_outcomes",
        "forbidden_outcomes",
        "required_evidence_refs",
        "material_claim_ids",
        "allowed_providers",
        "forbidden_providers",
        "allowed_tools",
        "forbidden_tools",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _exclusive_outcome_shortcuts(self) -> Expectation:
        if self.expected_recommendation is not None and self.allowed_outcomes:
            raise ValueError("expected_recommendation conflicts with allowed_outcomes")
        if self.schema_version in MACHINE_IDENTIFIER_SCHEMA_VERSIONS:
            for field_name in ("required_evidence_refs", "material_claim_ids"):
                for index, value in enumerate(getattr(self, field_name)):
                    validate_machine_identifier(
                        value,
                        field_name=f"{field_name}[{index}]",
                    )
        return self


class ExpectationChangeRecord(PersistedArtifact):
    artifact_kind: Literal["expectation-change-record"] = "expectation-change-record"
    expectation_id: str
    change_type: Literal["added", "removed", "modified"]
    before_digest: DigestHex | None = None
    after_digest: DigestHex | None = None
    changed_fields: tuple[str, ...] = ()
    author: str
    reviewer: str
    rationale: str
    reviewed_on: str
    fixture_impact: str

    @field_validator("changed_fields", mode="before")
    @classmethod
    def _coerce_changed_fields(cls, value: object) -> object:
        return coerce_tuple(value)
