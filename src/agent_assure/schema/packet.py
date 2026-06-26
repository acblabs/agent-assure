from __future__ import annotations

from typing import Literal

from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import coerce_tuple
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary


class EvidencePacket(PersistedArtifact):
    artifact_kind: Literal["evidence-packet"] = "evidence-packet"
    packet_id: str
    evaluation: EvaluationSummary
    comparison: ComparisonSummary | None = None
    limitations: tuple[str, ...]

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)
