from __future__ import annotations

from typing import Literal

from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex, coerce_tuple


class InstalledPackage(PersistedArtifact):
    artifact_kind: Literal["installed-package"] = "installed-package"
    name: str
    version: str


class EnvironmentInfo(PersistedArtifact):
    artifact_kind: Literal["environment-info"] = "environment-info"
    platform: str
    python_version: str
    git_commit: str | None = None
    git_dirty: bool | None = None
    lockfile_path: str | None = None
    lockfile_digest: DigestHex | None = None
    dependency_inventory_path: str | None = None
    dependency_inventory_digest: DigestHex | None = None
    installed_packages: tuple[InstalledPackage, ...] = ()

    @field_validator("installed_packages", mode="before")
    @classmethod
    def _coerce_installed_packages(cls, value: object) -> object:
        return coerce_tuple(value)
