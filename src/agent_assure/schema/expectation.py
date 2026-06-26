from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import coerce_tuple


class Expectation(PersistedArtifact):
    artifact_kind: Literal["expectation"] = "expectation"
    expectation_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    expected_recommendation: str | None = None
    allowed_outcomes: tuple[str, ...] = ()
    forbidden_outcomes: tuple[str, ...] = ()
    required_evidence_refs: tuple[str, ...] = ()
    material_claim_ids: tuple[str, ...] = ()
    required_human_review: bool = False

    @field_validator(
        "allowed_outcomes",
        "forbidden_outcomes",
        "required_evidence_refs",
        "material_claim_ids",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _exclusive_outcome_shortcuts(self) -> Expectation:
        if self.expected_recommendation is not None and self.allowed_outcomes:
            raise ValueError("expected_recommendation conflicts with allowed_outcomes")
        return self


class ExpectationChangeRecord(PersistedArtifact):
    artifact_kind: Literal["expectation-change-record"] = "expectation-change-record"
    expectation_id: str
    change_type: Literal["added", "removed", "modified"]
    rationale: str
