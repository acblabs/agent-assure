from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any, TypeVar, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel
from pydantic import ValidationError as PydanticValidationError
from referencing import Registry

from agent_assure.io_limits import load_json_bounded, loads_json_bounded
from agent_assure.schema.base import SCHEMA_VERSION, validate_rfc8785_safe_integers
from agent_assure.source_layout import source_checkout_component

MAX_FROZEN_SCHEMA_BYTES = 1 * 1024 * 1024
FROZEN_SCHEMA_VERSIONS = frozenset(
    {
        "0.1.0",
        "0.2.0",
        "0.3.1",
        "0.4.3",
        "0.5.0",
        "0.6.0",
        "0.6.1",
        "0.6.2",
        "0.6.3",
    }
)
_DRAFT_2020_12_URI = "https://json-schema.org/draft/2020-12/schema"
_NO_REMOTE_SCHEMA_REGISTRY: Registry[Any] = Registry()
ArtifactModelT = TypeVar("ArtifactModelT", bound=BaseModel)
_V060_SEMANTIC_ARTIFACT_KINDS = frozenset(
    {
        "assurance-evidence-descriptor",
        "assurance-mutation-operator",
        "assurance-mutation-result",
        "expected-detection-contract",
    }
)
_V061_SEMANTIC_ARTIFACT_KINDS = _V060_SEMANTIC_ARTIFACT_KINDS | {
    "assurance-mutation-catalog",
    "assurance-mutation-campaign",
}
_V062_SEMANTIC_ARTIFACT_KINDS = _V061_SEMANTIC_ARTIFACT_KINDS | {
    "control-efficacy-report",
    "threat-applicability-manifest",
}
_V063_SEMANTIC_ARTIFACT_KINDS = _V062_SEMANTIC_ARTIFACT_KINDS | {
    "assurance-evidence-graph",
}
_LEGACY_SEMANTIC_ARTIFACT_KINDS = {
    "0.6.0": _V060_SEMANTIC_ARTIFACT_KINDS,
    "0.6.1": _V061_SEMANTIC_ARTIFACT_KINDS,
    "0.6.2": _V062_SEMANTIC_ARTIFACT_KINDS,
    "0.6.3": _V063_SEMANTIC_ARTIFACT_KINDS,
}


def load_json(path: Path) -> dict[str, Any]:
    return load_json_bounded(path)


def validate_artifact(path: Path, kind: str) -> str:
    payload = load_json(path)
    return validate_artifact_payload(payload, kind)


def load_validated_artifact_payload(
    path: Path,
    kind: str,
    *,
    max_bytes: int | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    """Load and validate persisted bytes before any current-model projection."""
    load_kwargs: dict[str, Any] = {}
    if max_bytes is not None:
        load_kwargs["max_bytes"] = max_bytes
    if label is not None:
        load_kwargs["label"] = label
    payload = load_json_bounded(path, **load_kwargs)
    validate_loaded_artifact_payload(payload, kind)
    return payload


def validate_loaded_artifact_payload(payload: dict[str, Any], kind: str) -> str:
    """Validate a loaded artifact and normalize data errors for runtime callers."""
    try:
        return validate_artifact_payload(payload, kind)
    except JsonSchemaValidationError as exc:
        raise ValueError(f"{kind} artifact failed JSON Schema validation") from exc


def project_validated_artifact_payload(
    payload: dict[str, Any],
    model: type[ArtifactModelT],
    *,
    kind: str,
) -> ArtifactModelT:
    """Project frozen-schema-valid bytes without exposing Pydantic input values."""
    try:
        return model.model_validate(payload)
    except PydanticValidationError as exc:
        raise ValueError(f"{kind} artifact failed model validation") from exc


def validate_artifact_payload(payload: dict[str, Any], kind: str) -> str:
    from agent_assure.schema.export import (
        model_for_kind,
        require_persisted_identity_in_schema,
        writer_json_schema,
    )

    # Resolve the requested kind before any artifact-controlled value is used
    # to select a frozen schema filename.
    model = model_for_kind(kind)
    validate_rfc8785_safe_integers(payload, owner=f"{kind} artifact")
    legacy_result = _validate_legacy_frozen_schema(payload, kind)
    if legacy_result is not None:
        _validate_legacy_semantics(payload, model, kind=kind)
        return legacy_result
    _require_raw_persisted_identity(payload, kind)
    schema = writer_json_schema(model)
    require_persisted_identity_in_schema(schema, kind)
    schema["$schema"] = _DRAFT_2020_12_URI
    _validate_json_schema(schema, payload)
    parsed = project_validated_artifact_payload(payload, model, kind=kind)
    artifact_kind = getattr(parsed, "artifact_kind", None)
    if artifact_kind != kind:
        raise ValueError(f"artifact_kind {artifact_kind!r} does not match requested kind {kind!r}")
    return "pydantic+jsonschema"


def _validate_legacy_semantics(
    payload: dict[str, Any],
    model: type[ArtifactModelT],
    *,
    kind: str,
) -> None:
    """Apply compatible v0.6 semantic checks after immutable shape validation.

    Evidence-carrying roots introduced from v0.6.0 through v0.6.3 are
    shape-compatible with their current projection for values admitted by the
    corresponding frozen schema. Projecting only after frozen validation
    retains each historical vocabulary while restoring self-digest and
    relational checks that JSON Schema cannot express. Older artifact families
    retain their established loader-specific compatibility projections.
    """
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str):
        return
    semantic_kinds = _LEGACY_SEMANTIC_ARTIFACT_KINDS.get(schema_version)
    if semantic_kinds is None or kind not in semantic_kinds:
        return
    parsed = project_validated_artifact_payload(payload, model, kind=kind)
    artifact_kind = getattr(parsed, "artifact_kind", None)
    if artifact_kind != kind:
        raise ValueError(f"artifact_kind {artifact_kind!r} does not match requested kind {kind!r}")


def _require_raw_persisted_identity(payload: dict[str, Any], kind: str) -> None:
    from agent_assure.schema.export import persisted_identity_fields_for_kind

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
    from agent_assure.schema.export import model_for_kind

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
