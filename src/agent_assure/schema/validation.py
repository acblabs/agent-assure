from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from agent_assure.schema.export import model_for_kind


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("artifact JSON root must be an object")
    return value


def validate_artifact(path: Path, kind: str) -> str:
    payload = load_json(path)
    model = model_for_kind(kind)
    parsed = model.model_validate(payload)
    schema = model.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator(schema).validate(payload)
    artifact_kind = getattr(parsed, "artifact_kind", None)
    if artifact_kind != kind:
        raise ValueError(f"artifact_kind {artifact_kind!r} does not match requested kind {kind!r}")
    return "pydantic+jsonschema"
