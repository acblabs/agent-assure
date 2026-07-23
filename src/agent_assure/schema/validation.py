from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from referencing import Registry

from agent_assure.io_limits import load_json_bounded, loads_json_bounded
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.export import (
    model_for_kind,
    persisted_identity_fields_for_kind,
    require_persisted_identity_in_schema,
)
from agent_assure.source_layout import source_checkout_component

MAX_FROZEN_SCHEMA_BYTES = 1 * 1024 * 1024
FROZEN_SCHEMA_VERSIONS = frozenset(
    {
        "0.1.0",
        "0.2.0",
        "0.3.1",
        "0.4.3",
        "0.5.0",
    }
)
_DRAFT_2020_12_URI = "https://json-schema.org/draft/2020-12/schema"
_NO_REMOTE_SCHEMA_REGISTRY: Registry[Any] = Registry()


def load_json(path: Path) -> dict[str, Any]:
    return load_json_bounded(path)


def validate_artifact(path: Path, kind: str) -> str:
    payload = load_json(path)
    return validate_artifact_payload(payload, kind)


def validate_artifact_payload(payload: dict[str, Any], kind: str) -> str:
    # Resolve the requested kind before any artifact-controlled value is used
    # to select a frozen schema filename.
    model = model_for_kind(kind)
    legacy_result = _validate_legacy_frozen_schema(payload, kind)
    if legacy_result is not None:
        return legacy_result
    _require_raw_persisted_identity(payload, kind)
    schema = model.model_json_schema(mode="validation")
    require_persisted_identity_in_schema(schema, kind)
    schema["$schema"] = _DRAFT_2020_12_URI
    _validate_json_schema(schema, payload)
    parsed = model.model_validate(payload)
    artifact_kind = getattr(parsed, "artifact_kind", None)
    if artifact_kind != kind:
        raise ValueError(f"artifact_kind {artifact_kind!r} does not match requested kind {kind!r}")
    return "pydantic+jsonschema"


def _require_raw_persisted_identity(payload: dict[str, Any], kind: str) -> None:
    required = persisted_identity_fields_for_kind(kind)
    missing = [field_name for field_name in required if field_name not in payload]
    if missing:
        raise ValueError(
            "persisted artifact requires explicit identity fields before parsing: "
            + ", ".join(missing)
        )


def _validate_legacy_frozen_schema(payload: dict[str, Any], kind: str) -> str | None:
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str) or schema_version == SCHEMA_VERSION:
        return None
    if schema_version not in FROZEN_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported frozen schema_version {schema_version!r}")
    schema = _legacy_frozen_schema(schema_version, kind)
    if schema is None:
        raise ValueError(
            f"no frozen schema is available for artifact kind {kind!r} "
            f"at schema_version {schema_version!r}"
        )
    _prepare_frozen_schema(schema, schema_version=schema_version, kind=kind)
    _validate_json_schema(schema, payload)
    return "frozen-jsonschema"


def _legacy_frozen_schema(schema_version: str, kind: str) -> dict[str, Any] | None:
    if schema_version not in FROZEN_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported frozen schema_version {schema_version!r}")
    # model_for_kind is an explicit allowlist for the filename component.
    model_for_kind(kind)
    relative_path = f"schemas/v{schema_version}/{kind}.schema.json"
    schema_path = source_checkout_component(__file__, relative_path)
    if schema_path is not None and schema_path.is_file():
        return load_json_bounded(
            schema_path,
            max_bytes=MAX_FROZEN_SCHEMA_BYTES,
            label="frozen JSON Schema",
        )
    try:
        resource = files("agent_assure.schema_resources").joinpath(
            f"v{schema_version}", f"{kind}.schema.json"
        )
    except ModuleNotFoundError:
        return None
    if not resource.is_file():
        return None
    try:
        with resource.open("rb") as handle:
            raw = handle.read(MAX_FROZEN_SCHEMA_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > MAX_FROZEN_SCHEMA_BYTES:
        raise ValueError("frozen JSON Schema exceeds maximum supported size")
    loaded = loads_json_bounded(raw.decode("utf-8"), label="frozen JSON Schema")
    if not isinstance(loaded, dict):
        raise ValueError("frozen JSON Schema root must be an object")
    return cast(dict[str, Any], loaded)


def _prepare_frozen_schema(
    schema: dict[str, Any],
    *,
    schema_version: str,
    kind: str,
) -> None:
    expected_id = (
        f"https://acblabs.github.io/agent-assure/schemas/v{schema_version}/{kind}.schema.json"
    )
    if schema.get("$schema") != _DRAFT_2020_12_URI:
        raise ValueError("frozen schema has an unexpected JSON Schema dialect")
    if schema.get("$id") != expected_id:
        raise ValueError("frozen schema has an unexpected canonical identity")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("frozen schema has no root properties")
    _require_property_accepts_identity(properties, "artifact_kind", kind)
    _require_property_accepts_identity(properties, "schema_version", schema_version)
    _reject_nonlocal_schema_references(schema)


def _require_property_accepts_identity(
    properties: dict[str, Any],
    field_name: str,
    expected: str,
) -> None:
    declaration = properties.get(field_name)
    if not isinstance(declaration, dict) or not _schema_declaration_accepts_identity(
        declaration, expected
    ):
        raise ValueError(f"frozen schema has an invalid {field_name} identity constraint")


def _schema_declaration_accepts_identity(declaration: dict[str, Any], expected: str) -> bool:
    if declaration.get("const") == expected:
        return True
    enum = declaration.get("enum")
    if isinstance(enum, list) and expected in enum:
        return True
    for keyword in ("anyOf", "oneOf"):
        alternatives = declaration.get(keyword)
        if isinstance(alternatives, list) and any(
            isinstance(alternative, dict)
            and _schema_declaration_accepts_identity(alternative, expected)
            for alternative in alternatives
        ):
            return True
    return False


def _reject_nonlocal_schema_references(schema: object) -> None:
    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"$ref", "$dynamicRef"} and (
                    not isinstance(child, str) or not child.startswith("#")
                ):
                    raise ValueError("frozen schema contains a non-local schema reference")
                pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)


def _validate_json_schema(schema: dict[str, Any], payload: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)
    # Supplying an explicit empty registry prevents jsonschema's deprecated
    # network retrieval fallback. Frozen schemas are intentionally self-contained.
    Draft202012Validator(
        schema,
        registry=_NO_REMOTE_SCHEMA_REGISTRY,
    ).validate(payload)
