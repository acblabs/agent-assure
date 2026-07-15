from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from agent_assure.io_limits import load_json_bounded
from agent_assure.schema.export import model_for_kind


def load_json(path: Path) -> dict[str, Any]:
    return load_json_bounded(path)


def validate_artifact(path: Path, kind: str) -> str:
    payload = load_json(path)
    legacy_result = _validate_legacy_frozen_schema(payload, kind)
    if legacy_result is not None:
        return legacy_result
    model = model_for_kind(kind)
    parsed = model.model_validate(payload)
    schema = model.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator(schema).validate(payload)
    artifact_kind = getattr(parsed, "artifact_kind", None)
    if artifact_kind != kind:
        raise ValueError(f"artifact_kind {artifact_kind!r} does not match requested kind {kind!r}")
    return "pydantic+jsonschema"


def _validate_legacy_frozen_schema(payload: dict[str, Any], kind: str) -> str | None:
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str) or schema_version == "0.5.0":
        return None
    schema = _legacy_frozen_schema(schema_version, kind)
    if schema is None:
        return None
    Draft202012Validator(schema).validate(payload)
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind != kind:
        raise ValueError(f"artifact_kind {artifact_kind!r} does not match requested kind {kind!r}")
    return "frozen-jsonschema"


def _legacy_frozen_schema(schema_version: str, kind: str) -> dict[str, Any] | None:
    schema_path = _repo_root() / "schemas" / f"v{schema_version}" / f"{kind}.schema.json"
    if schema_path.exists():
        return cast(dict[str, Any], json.loads(schema_path.read_text(encoding="utf-8")))
    try:
        resource = files("agent_assure.schema_resources").joinpath(
            f"v{schema_version}", f"{kind}.schema.json"
        )
    except ModuleNotFoundError:
        return None
    if not resource.is_file():
        return None
    try:
        with resource.open("r", encoding="utf-8") as handle:
            return cast(dict[str, Any], json.load(handle))
    except FileNotFoundError:
        return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]
