from __future__ import annotations

from typing import Literal

from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex, coerce_tuple
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.release import ReleaseArtifactManifest

PacketArtifactRole = Literal["evaluation-summary", "comparison-summary"]


class PacketArtifactDigest(PersistedArtifact):
    artifact_kind: Literal["packet-artifact-digest"] = "packet-artifact-digest"
    role: PacketArtifactRole
    sha256: DigestHex


class EvidencePacket(PersistedArtifact):
    artifact_kind: Literal["evidence-packet"] = "evidence-packet"
    packet_id: str
    interpretation: tuple[str, ...]
    evaluation: EvaluationSummary
    comparison: ComparisonSummary | None = None
    environment: EnvironmentInfo | None = None
    release_manifest: ReleaseArtifactManifest | None = None
    artifact_digests: tuple[PacketArtifactDigest, ...] = ()
    limitations: tuple[str, ...]

    @field_validator("interpretation", "artifact_digests", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)
