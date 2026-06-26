from __future__ import annotations

from typing import Literal

from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex, coerce_tuple
from agent_assure.schema.environment import EnvironmentInfo


class ReleaseArtifact(PersistedArtifact):
    artifact_kind: Literal["release-artifact"] = "release-artifact"
    role: str
    path: str
    sha256: DigestHex


class ReleaseArtifactManifest(PersistedArtifact):
    artifact_kind: Literal["release-artifact-manifest"] = "release-artifact-manifest"
    manifest_id: str
    artifacts: tuple[ReleaseArtifact, ...]
    environment: EnvironmentInfo
    limitations: tuple[str, ...] = (
        "release artifact manifests record deterministic file digests only; "
        "they are not signatures or attestations",
    )

    @field_validator("artifacts", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)
