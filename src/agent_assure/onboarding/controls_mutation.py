from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from agent_assure.io_limits import (
    BoundedFileContents,
)
from agent_assure.onboarding.path_safety import (
    confined_config_input_directory as confined_config_input_directory,
)
from agent_assure.onboarding.path_safety import (
    confined_config_input_file as confined_config_input_file,
)
from agent_assure.onboarding.path_safety import (
    read_confined_config_input_file as read_confined_config_input_file,
)
from agent_assure.onboarding.path_safety import (
    require_confined_input_directory as require_confined_input_directory,
)
from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.campaign import CORE_MUTATION_CATALOG_ID
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_SCHEMA_VERSION,
    PACKAGE_RELEASE_VERSION_PATTERN,
)
from agent_assure.schema.efficacy import (
    ControlEfficacyGateProfile,
)
from agent_assure.schema.mutation import MachineIdentifier

DEFAULT_SCAFFOLD_DIRECTORY = Path("agent-assure-controls-mutation")
CONFIG_FILENAME = "controls-mutation.yaml"
SUITE_FILENAME = "suite.yaml"
RUNSET_FILENAME = "runset.json"
THREAT_MANIFEST_FILENAME = "threat-applicability.yaml"
MUTATION_OUTPUT_DIRECTORY = "mutation-results"
DEFAULT_ONBOARDING_OPERATOR_ID = "drop-material-evidence-link"
MANAGED_FILENAMES = (
    CONFIG_FILENAME,
    SUITE_FILENAME,
    RUNSET_FILENAME,
    THREAT_MANIFEST_FILENAME,
)

_CONFIG_ARTIFACT_KIND: Literal["controls-mutation-onboarding-config"] = (
    "controls-mutation-onboarding-config"
)
_MAX_ONBOARDING_PATH_CHARS = 512
_MAX_PORTABLE_PATH_COMPONENT_CHARS = 255
_PORTABLE_PATH_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-"
)
_WINDOWS_RESERVED_PATH_COMPONENTS = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)


class ScaffoldConflictError(ValueError):
    """Raised when managed onboarding paths are only partly present or differ."""


class ControlsMutationOnboardingConfig(PersistedArtifact):
    artifact_kind: Literal["controls-mutation-onboarding-config"] = _CONFIG_ARTIFACT_KIND
    package_version: str = Field(pattern=PACKAGE_RELEASE_VERSION_PATTERN)
    catalog_id: MachineIdentifier
    suite_path: str = Field(min_length=1, max_length=_MAX_ONBOARDING_PATH_CHARS)
    runset_path: str = Field(min_length=1, max_length=_MAX_ONBOARDING_PATH_CHARS)
    output_dir: str = Field(min_length=1, max_length=_MAX_ONBOARDING_PATH_CHARS)
    threat_applicability_manifest: str = Field(
        min_length=1,
        max_length=_MAX_ONBOARDING_PATH_CHARS,
    )
    operator_ids: tuple[MachineIdentifier, ...] = Field(min_length=1)
    control_efficacy: ControlEfficacyGateProfile

    @field_validator("operator_ids", mode="before")
    @classmethod
    def _coerce_operator_ids(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            items = tuple(value)
            if all(isinstance(item, str) for item in items):
                return tuple(sorted(items))
            return items
        return value

    @field_validator(
        "suite_path",
        "runset_path",
        "output_dir",
        "threat_applicability_manifest",
    )
    @classmethod
    def _validate_portable_relative_path(cls, value: str) -> str:
        if any(character not in _PORTABLE_PATH_CHARACTERS for character in value):
            raise ValueError("onboarding paths must be portable relative POSIX paths")
        if "\\" in value or "\x00" in value or ":" in value:
            raise ValueError("onboarding paths must be portable relative POSIX paths")
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("onboarding paths must be confined relative paths")
        if path.as_posix() != value:
            raise ValueError("onboarding paths must use canonical POSIX spelling")
        for component in path.parts:
            if len(component) > _MAX_PORTABLE_PATH_COMPONENT_CHARS:
                raise ValueError(
                    "onboarding path components must be at most "
                    f"{_MAX_PORTABLE_PATH_COMPONENT_CHARS} characters"
                )
            if component.endswith((".", " ")):
                raise ValueError("onboarding path components must not end with a dot or space")
            device_stem = component.split(".", 1)[0].upper()
            if device_stem in _WINDOWS_RESERVED_PATH_COMPONENTS:
                raise ValueError("onboarding paths must not use reserved Windows device names")
        return value

    @model_validator(mode="after")
    def _validate_configuration_links(self) -> ControlsMutationOnboardingConfig:
        if self.schema_version != MACHINE_IDENTIFIER_SCHEMA_VERSION:
            raise ValueError(
                "schema_version must match the installed onboarding schema: "
                f"{MACHINE_IDENTIFIER_SCHEMA_VERSION}"
            )
        if self.catalog_id != CORE_MUTATION_CATALOG_ID:
            raise ValueError(f"catalog_id must be {CORE_MUTATION_CATALOG_ID!r}")
        if self.control_efficacy.required_catalog != self.catalog_id:
            raise ValueError("control_efficacy.required_catalog must match catalog_id")
        if self.operator_ids != tuple(dict.fromkeys(self.operator_ids)):
            raise ValueError("operator_ids must be unique")
        missing = sorted(set(self.control_efficacy.required_operators) - set(self.operator_ids))
        if missing:
            raise ValueError(
                "required_operators must be selected in operator_ids: " + ", ".join(missing)
            )
        input_paths = {self.suite_path, self.runset_path, self.threat_applicability_manifest}
        if len(input_paths) != 3 or self.output_dir in input_paths:
            raise ValueError("suite, runset, threat manifest, and output paths must be distinct")
        return self


@dataclass(frozen=True)
class ScaffoldResult:
    status: Literal["created", "unchanged"]
    directory: Path
    paths: tuple[Path, ...]


@dataclass(frozen=True)
class ControlsMutationInputBinding:
    """Canonical identities for the exact configured suite and RunSet snapshots."""

    suite_path: Path
    runset_path: Path
    suite_digest: str
    source_digest: str


class DiagnosticStatus(StrEnum):
    passed = "PASS"
    failed = "FAIL"
    skipped = "SKIP"


@dataclass(frozen=True)
class DoctorDiagnostic:
    code: str
    status: DiagnosticStatus
    message: str
    action: str | None = None


@dataclass(frozen=True)
class DoctorReport:
    diagnostics: tuple[DoctorDiagnostic, ...]

    @property
    def exit_code(self) -> int:
        return 2 if any(item.status is DiagnosticStatus.failed for item in self.diagnostics) else 0

    @property
    def ready(self) -> bool:
        return self.exit_code == 0


class DoctorCode:
    CONFIG_PATH = "CM_CONFIG_PATH"
    CONFIG_SCHEMA = "CM_CONFIG_SCHEMA"
    PACKAGE_VERSION = "CM_PACKAGE_VERSION"
    SUITE_PATH = "CM_SUITE_PATH"
    RUNSET_PATH = "CM_RUNSET_PATH"
    THREAT_MANIFEST_PATH = "CM_THREAT_MANIFEST_PATH"
    THREAT_MANIFEST_SCHEMA = "CM_THREAT_MANIFEST_SCHEMA"
    OUTPUT_PATH = "CM_OUTPUT_PATH"
    SCHEMA_VERSIONS = "CM_SCHEMA_VERSIONS"
    INPUT_BINDING = "CM_INPUT_BINDING"
    CATALOG_IDENTITY = "CM_CATALOG_IDENTITY"
    OPERATOR_CONFIGURATION = "CM_OPERATOR_CONFIGURATION"
    THREAT_SCOPE = "CM_THREAT_SCOPE"
    OPERATOR_APPLICABILITY = "CM_OPERATOR_APPLICABILITY"
    OFFLINE_READINESS = "CM_OFFLINE_READINESS"


def scaffold_controls_mutation(directory: Path) -> ScaffoldResult:
    """Create or safely resume the deterministic scaffold without replacing a path."""
    from agent_assure.onboarding.controls_mutation_scaffold import (
        scaffold_controls_mutation as _scaffold_controls_mutation,
    )

    return _scaffold_controls_mutation(directory)


def expected_scaffold_files() -> dict[str, bytes]:
    """Return the complete byte-stable managed generation."""
    from agent_assure.onboarding.controls_mutation_scaffold import (
        expected_scaffold_files as _expected_scaffold_files,
    )

    return _expected_scaffold_files()


def load_controls_mutation_config(path: Path) -> ControlsMutationOnboardingConfig:
    from agent_assure.onboarding.controls_mutation_config import (
        load_controls_mutation_config as _load_controls_mutation_config,
    )

    return _load_controls_mutation_config(path)


def load_controls_mutation_config_snapshot(
    path: Path,
) -> tuple[ControlsMutationOnboardingConfig, BoundedFileContents]:
    """Load and hash one confined configuration from the same validated descriptor."""
    from agent_assure.onboarding.controls_mutation_config import (
        load_controls_mutation_config_snapshot as _load_controls_mutation_config_snapshot,
    )

    return _load_controls_mutation_config_snapshot(path)


def parse_controls_mutation_config(data: bytes) -> ControlsMutationOnboardingConfig:
    """Parse bounded controls-mutation configuration bytes without another file read."""
    from agent_assure.onboarding.controls_mutation_config import (
        parse_controls_mutation_config as _parse_controls_mutation_config,
    )

    return _parse_controls_mutation_config(data)


def load_controls_mutation_input_binding(
    config: ControlsMutationOnboardingConfig,
    *,
    root: Path,
) -> ControlsMutationInputBinding:
    """Load and canonically identify the suite and RunSet named by configuration."""
    from agent_assure.onboarding.controls_mutation_config import (
        load_controls_mutation_input_binding as _load_controls_mutation_input_binding,
    )

    return _load_controls_mutation_input_binding(config, root=root)


def diagnose_controls_mutate(config_path: Path) -> DoctorReport:
    """Perform a deterministic, read-only preflight for the offline workflow."""
    from agent_assure.onboarding.controls_mutation_doctor import (
        diagnose_controls_mutate as _diagnose_controls_mutate,
    )

    return _diagnose_controls_mutate(config_path)
