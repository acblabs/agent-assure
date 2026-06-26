from __future__ import annotations

from typing import Literal

from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    ComparisonClassification,
    GateState,
    coerce_enum,
    coerce_tuple,
)


class ComparisonSummary(PersistedArtifact):
    artifact_kind: Literal["comparison-summary"] = "comparison-summary"
    baseline_runset_id: str
    candidate_runset_id: str
    classification: ComparisonClassification
    fixture_equivalence_state: GateState = GateState.not_evaluated
    baseline_state: GateState = GateState.not_evaluated
    candidate_state: GateState = GateState.not_evaluated
    provenance_changes: tuple[str, ...] = ()
    verdict_findings: tuple[str, ...] = ()

    @field_validator("classification", mode="before")
    @classmethod
    def _coerce_classification(cls, value: object) -> ComparisonClassification:
        return coerce_enum(ComparisonClassification, value)

    @field_validator(
        "fixture_equivalence_state",
        "baseline_state",
        "candidate_state",
        mode="before",
    )
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("provenance_changes", "verdict_findings", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)
