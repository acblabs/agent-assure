"""Closed values for an explicitly supplied immutable compatibility matrix.

This module contains no dispatch registry. The trusted reader dispatch remains
``FROZEN_ROOT_VALIDATION_POLICY`` in ``schema.validation``. A matrix disposition
describes compatibility only; it cannot supply qualification or authorization.
"""

from __future__ import annotations

import hashlib
import re
from bisect import bisect_left
from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import (
    Field,
    GetJsonSchemaHandler,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import CoreSchema

from agent_assure.io_limits import load_json_bytes_bounded
from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.common import harden_json_schema_pattern_ends

MAX_COMPATIBILITY_CELLS = 4096
MAX_COMPATIBILITY_MATRIX_BYTES = 1024 * 1024
MAX_COMPATIBILITY_SCHEMA_BYTES = 1024 * 1024
_VERSION_COMPONENT = r"(?:0|[1-9][0-9]{0,8})"
_EXACT_VERSION_PATTERN = (
    rf"{_VERSION_COMPONENT}\.{_VERSION_COMPONENT}\.{_VERSION_COMPONENT}"
    rf"(?:(a|b|rc)({_VERSION_COMPONENT}))?"
)
_EXACT_VERSION = re.compile(_EXACT_VERSION_PATTERN, flags=re.ASCII)
_VERSION_PHASE = {"a": 0, "b": 1, "rc": 2, None: 3}

ExactVersion: TypeAlias = Annotated[
    str,
    StringConstraints(min_length=5, max_length=64, pattern=rf"^{_EXACT_VERSION_PATTERN}$"),
]
ArtifactKind: TypeAlias = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$"),
]
ResourceDigest: TypeAlias = Annotated[
    str, StringConstraints(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")
]
ReplayIdentity: TypeAlias = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    ),
]
CompatibilityAnnotation: TypeAlias = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512, pattern=r"^[^\x00-\x1f\x7f]+$"),
]
CompatibilityTuple: TypeAlias = tuple[str, str, str, str]
CompatibilityDisposition: TypeAlias = Literal[
    "semantic_replay_and_authorization_eligible",
    "shape_and_integrity_only",
    "unsupported",
]
CompatibilityFailure: TypeAlias = Literal[
    "SCHEMA_COMPATIBILITY_CELL_ABSENT",
    "SCHEMA_COMPATIBILITY_CELL_UNSUPPORTED",
    "SCHEMA_COMPATIBILITY_MATRIX_UNAVAILABLE",
    "SCHEMA_COMPATIBILITY_MATRIX_DIGEST_MISMATCH",
    "SCHEMA_COMPATIBILITY_MATRIX_INVALID",
    "SCHEMA_COMPATIBILITY_POLICY_MISMATCH",
    "SCHEMA_MINIMUM_READER_UNSATISFIED",
    "SCHEMA_RESOURCE_UNAVAILABLE",
    "SCHEMA_RESOURCE_TOO_LARGE",
    "SCHEMA_RESOURCE_DIGEST_MISMATCH",
    "SCHEMA_RESOURCE_INVALID",
    "SCHEMA_SEMANTIC_REPLAY_UNAVAILABLE",
    "SCHEMA_MIGRATION_UNSUPPORTED",
]


def version_order(value: str) -> tuple[int, int, int, int, int]:
    """Order the bounded, canonical version labels supported by this matrix.

    This is deliberately not a general PEP 440 parser. No normalization,
    ranges, epochs, local labels, or dev/post releases are supported. Exact
    identities are still matched as strings, never through this ordering.
    """
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("compatibility version must be a bounded canonical string")
    match = _EXACT_VERSION.fullmatch(value)
    if match is None:
        raise ValueError("unsupported canonical compatibility version")
    base = value.split(match.group(1), 1)[0] if match.group(1) is not None else value
    major, minor, patch = (int(component) for component in base.split("."))
    return (
        major,
        minor,
        patch,
        _VERSION_PHASE[match.group(1)],
        int(match.group(2)) if match.group(2) is not None else 0,
    )


class _CompatibilityModel(FrozenStrictModel):
    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> dict[str, Any]:
        schema = super().__get_pydantic_json_schema__(core_schema, handler)
        harden_json_schema_pattern_ends(schema)
        return schema


class CompatibilityKey(_CompatibilityModel):
    """The four exact identities of a cell; none is a range or wildcard."""

    producer_package_version: ExactVersion
    writer_schema_version: ExactVersion
    artifact_kind: ArtifactKind
    reader_package_version: ExactVersion

    @field_validator("producer_package_version", "writer_schema_version", "reader_package_version")
    @classmethod
    def _canonical_version(cls, value: str) -> str:
        version_order(value)
        return value

    @field_validator("artifact_kind")
    @classmethod
    def _canonical_kind(cls, value: str) -> str:
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value, flags=re.ASCII) is None:
            raise ValueError("artifact kind must be an exact canonical discriminator")
        return value

    def as_tuple(self) -> CompatibilityTuple:
        return (
            self.producer_package_version,
            self.writer_schema_version,
            self.artifact_kind,
            self.reader_package_version,
        )


class CompatibilityCell(CompatibilityKey):
    """One reviewed cell, including explicit null migration/replay identities."""

    disposition: CompatibilityDisposition
    minimum_reader_version: ExactVersion
    schema_resource_digest: ResourceDigest
    semantic_replay_identity: ReplayIdentity | None
    migration_identity: ReplayIdentity | None
    losses: Annotated[tuple[CompatibilityAnnotation, ...], Field(max_length=128)]
    authorization_restrictions: Annotated[
        tuple[CompatibilityAnnotation, ...], Field(min_length=1, max_length=128)
    ]

    @field_validator("minimum_reader_version")
    @classmethod
    def _canonical_minimum_reader(cls, value: str) -> str:
        version_order(value)
        return value

    @field_validator("schema_resource_digest")
    @classmethod
    def _exact_resource_digest(cls, value: str) -> str:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", value, flags=re.ASCII) is None:
            raise ValueError("schema resource digest must be exact lowercase SHA-256")
        return value

    @field_validator("semantic_replay_identity", "migration_identity")
    @classmethod
    def _exact_replay_identity(cls, value: str | None) -> str | None:
        if (
            value is not None
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", value, flags=re.ASCII) is None
        ):
            raise ValueError("replay and migration identities must be exact identifiers")
        return value

    @field_validator("losses", "authorization_restrictions")
    @classmethod
    def _canonical_annotations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("compatibility annotations must be sorted and unique")
        if any(
            any(ord(character) < 32 or ord(character) == 127 for character in value)
            for value in values
        ):
            raise ValueError("compatibility annotations cannot contain control characters")
        try:
            for value in values:
                value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("compatibility annotations require Unicode scalar values") from exc
        return values

    @model_validator(mode="after")
    def _require_semantic_replay(self) -> CompatibilityCell:
        if (
            self.disposition == "semantic_replay_and_authorization_eligible"
            and self.semantic_replay_identity is None
        ):
            raise ValueError("semantic compatibility requires an exact semantic replay identity")
        return self

    @property
    def schema_resource_path(self) -> str:
        return f"v{self.writer_schema_version}/{self.artifact_kind}.schema.json"


class CompatibilityMatrix(_CompatibilityModel):
    """A bounded, canonically ordered value, not an ambient dispatch registry.

    Use ``load_compatibility_matrix`` for untrusted resource bytes. Pydantic's
    direct JSON parser does not reject duplicate object keys.
    """

    format: Literal["agent-assure-compatibility-matrix/v1"]
    cells: Annotated[
        tuple[CompatibilityCell, ...], Field(min_length=1, max_length=MAX_COMPATIBILITY_CELLS)
    ]

    @model_validator(mode="after")
    def _unique_ordered_cells(self) -> CompatibilityMatrix:
        keys = tuple(cell.as_tuple() for cell in self.cells)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("compatibility cells must have unique, lexicographically ordered keys")
        return self

    def as_mapping(self) -> Mapping[CompatibilityTuple, CompatibilityCell]:
        return MappingProxyType({cell.as_tuple(): cell for cell in self.cells})

    def lookup(self, key: CompatibilityKey) -> CompatibilityCell | None:
        """No nearest reader, producer, writer, artifact, or wildcard fallback."""
        exact_key = key.as_tuple()
        index = bisect_left(self.cells, exact_key, key=CompatibilityCell.as_tuple)
        if index < len(self.cells) and self.cells[index].as_tuple() == exact_key:
            return self.cells[index]
        return None


class CompatibilityDecision(_CompatibilityModel):
    """Compatibility evidence with an explicitly absent authorization effect."""

    key: CompatibilityKey
    disposition: CompatibilityDisposition
    reason: CompatibilityFailure | None
    minimum_reader_satisfied: bool
    schema_integrity_verified: bool
    authorization_effect: Literal["none"]

    @model_validator(mode="after")
    def _consistent_disposition(self) -> CompatibilityDecision:
        if self.disposition == "unsupported":
            if self.reason is None:
                raise ValueError("unsupported compatibility requires an explicit reason")
        elif (
            self.reason is not None
            or not self.minimum_reader_satisfied
            or not self.schema_integrity_verified
        ):
            raise ValueError("supported compatibility requires all compatibility prerequisites")
        return self

    @property
    def semantic_compatibility_eligible(self) -> bool:
        """A necessary compatibility condition, never method admission/authority."""
        return self.disposition == "semantic_replay_and_authorization_eligible"


def load_compatibility_matrix(data: bytes) -> CompatibilityMatrix:
    """Parse one bounded, duplicate-free resource into immutable closed values.

    JSON arrays have one deliberate representation change to tuples in the
    three declared collection fields. Scalars and unknown fields are never
    coerced. Direct Python model validation continues to require tuples.
    """
    payload = load_json_bytes_bounded(
        data,
        max_bytes=MAX_COMPATIBILITY_MATRIX_BYTES,
        label="compatibility matrix JSON",
    )
    cells = payload.get("cells")
    if isinstance(cells, list):
        for cell in cells:
            if isinstance(cell, dict):
                for field_name in ("losses", "authorization_restrictions"):
                    value = cell.get(field_name)
                    if isinstance(value, list):
                        cell[field_name] = tuple(value)
        payload["cells"] = tuple(cells)
    return CompatibilityMatrix.model_validate(payload)


def assess_compatibility(
    matrix: CompatibilityMatrix,
    key: CompatibilityKey,
    *,
    schema_resource: bytes | None,
    available_semantic_replays: frozenset[str] = frozenset(),
    available_migrations: frozenset[str] = frozenset(),
) -> CompatibilityDecision:
    """Check exact identity and minimum reader before resource/semantic work.

    The caller supplies independently resolved immutable resource bytes and
    reader-owned implementation identities. This function neither discovers
    resources nor trusts a candidate's claimed reader or replay availability.
    It does not parse/project an artifact or execute a migration/replay.
    A matching digest alone does not prove a schema's root vocabulary: the
    trusted dispatcher must also verify its exact discriminator and version.
    """
    cell = matrix.lookup(key)
    minimum_reader_satisfied = False
    integrity_verified = False

    def unsupported(reason: CompatibilityFailure) -> CompatibilityDecision:
        return CompatibilityDecision(
            key=key,
            disposition="unsupported",
            reason=reason,
            minimum_reader_satisfied=minimum_reader_satisfied,
            schema_integrity_verified=integrity_verified,
            authorization_effect="none",
        )

    if cell is None:
        return unsupported("SCHEMA_COMPATIBILITY_CELL_ABSENT")
    if version_order(key.reader_package_version) < version_order(cell.minimum_reader_version):
        return unsupported("SCHEMA_MINIMUM_READER_UNSATISFIED")
    minimum_reader_satisfied = True
    if cell.disposition == "unsupported":
        return unsupported("SCHEMA_COMPATIBILITY_CELL_UNSUPPORTED")
    if schema_resource is None:
        return unsupported("SCHEMA_RESOURCE_UNAVAILABLE")
    if not isinstance(schema_resource, bytes):
        raise TypeError("immutable schema resource must be exact bytes")
    if len(schema_resource) > MAX_COMPATIBILITY_SCHEMA_BYTES:
        return unsupported("SCHEMA_RESOURCE_TOO_LARGE")
    if f"sha256:{hashlib.sha256(schema_resource).hexdigest()}" != cell.schema_resource_digest:
        return unsupported("SCHEMA_RESOURCE_DIGEST_MISMATCH")
    integrity_verified = True
    if cell.migration_identity is not None and cell.migration_identity not in available_migrations:
        return unsupported("SCHEMA_MIGRATION_UNSUPPORTED")
    if (
        cell.disposition == "semantic_replay_and_authorization_eligible"
        and cell.semantic_replay_identity not in available_semantic_replays
    ):
        return unsupported("SCHEMA_SEMANTIC_REPLAY_UNAVAILABLE")
    return CompatibilityDecision(
        key=key,
        disposition=cell.disposition,
        reason=None,
        minimum_reader_satisfied=True,
        schema_integrity_verified=True,
        authorization_effect="none",
    )
