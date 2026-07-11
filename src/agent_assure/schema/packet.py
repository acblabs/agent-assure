from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex, coerce_tuple
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.release import ReleaseArtifactManifest
from agent_assure.schema.usage import (
    UsageSummary,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)

PacketArtifactRole = Literal["evaluation-summary", "comparison-summary"]
_EVIDENCE_PACKET_USAGE_FIELD_PATHS = (
    ("usage_summary",),
    ("evaluation", "usage_summary"),
    ("comparison", "baseline_usage_summary"),
    ("comparison", "candidate_usage_summary"),
    ("comparison", "usage_delta"),
)


class PacketArtifactDigest(PersistedArtifact):
    artifact_kind: Literal["packet-artifact-digest"] = "packet-artifact-digest"
    role: PacketArtifactRole
    sha256: DigestHex


class EvidencePacket(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=usage_container_json_schema_extra(
            *_EVIDENCE_PACKET_USAGE_FIELD_PATHS
        )
    )

    artifact_kind: Literal["evidence-packet"] = "evidence-packet"
    packet_id: str
    interpretation: tuple[str, ...]
    evaluation: EvaluationSummary
    comparison: ComparisonSummary | None = None
    environment: EnvironmentInfo | None = None
    release_manifest: ReleaseArtifactManifest | None = None
    usage_summary: UsageSummary | None = Field(default=None, exclude_if=lambda value: value is None)
    artifact_digests: tuple[PacketArtifactDigest, ...] = ()
    limitations: tuple[str, ...]

    @field_validator("interpretation", "artifact_digests", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> EvidencePacket:
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="evidence packet",
            root=self,
            field_paths=_EVIDENCE_PACKET_USAGE_FIELD_PATHS,
        )
        return self
