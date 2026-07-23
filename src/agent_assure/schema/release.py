from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, Self

from pydantic.functional_validators import field_validator, model_validator

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

    @model_validator(mode="after")
    def _require_unique_artifact_identities(self) -> Self:
        _require_unique_roles_and_paths(
            ((artifact.role, artifact.path) for artifact in self.artifacts),
            label="release artifact manifest",
        )
        return self


ReplayDigestMode = Literal["raw-sha256", "replay-stable-json-sha256"]


class ReleaseReplayArtifact(PersistedArtifact):
    artifact_kind: Literal["release-replay-artifact"] = "release-replay-artifact"
    role: str
    path: str
    sha256: DigestHex
    digest_mode: ReplayDigestMode = "raw-sha256"


class ReleaseDigestReplay(PersistedArtifact):
    artifact_kind: Literal["release-digest-replay"] = "release-digest-replay"
    source_commit: str | None = None
    source_ref: str | None = None
    artifacts: tuple[ReleaseReplayArtifact, ...]
    limitations: tuple[str, ...] = (
        "release digest replay records raw file digests for replay-stable source "
        "artifacts and stable JSON projection digests for environment-bearing "
        "review artifacts; it is not a signature, attestation, safety certification, "
        "or compliance certification",
    )

    @field_validator("artifacts", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _require_unique_artifact_identities(self) -> Self:
        _require_unique_roles_and_paths(
            ((artifact.role, artifact.path) for artifact in self.artifacts),
            label="release digest replay",
        )
        return self


def _require_unique_roles_and_paths(
    identities: Iterable[tuple[str, str]],
    *,
    label: str,
) -> None:
    seen_roles: set[str] = set()
    seen_paths: set[str] = set()
    for role, path in identities:
        if role in seen_roles:
            raise ValueError(f"{label} contains duplicate artifact role: {role}")
        if path in seen_paths:
            raise ValueError(f"{label} contains duplicate artifact path: {path}")
        seen_roles.add(role)
        seen_paths.add(path)
