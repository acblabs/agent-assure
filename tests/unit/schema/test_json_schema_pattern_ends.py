from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from agent_assure.schema.common import (
    DigestHex,
    harden_json_schema_pattern_ends,
    strict_json_schema_pattern_end,
)
from agent_assure.schema.export import SCHEMA_MODELS, writer_json_schema
from agent_assure.schema.validation import FROZEN_SCHEMA_VERSIONS

_FINAL_LINE_TERMINATORS = ("\n", "\r", "\r\n", "\u2028", "\u2029")


def _patterns(value: object) -> tuple[str, ...]:
    found: list[str] = []
    pending = [value]
    while pending:
        candidate = pending.pop()
        if isinstance(candidate, dict):
            pattern = candidate.get("pattern")
            if isinstance(pattern, str):
                found.append(pattern)
            pattern_properties = candidate.get("patternProperties")
            if isinstance(pattern_properties, dict):
                found.extend(pattern for pattern in pattern_properties if isinstance(pattern, str))
            pending.extend(candidate.values())
        elif isinstance(candidate, list):
            pending.extend(candidate)
    return tuple(found)


def test_strict_end_rewrite_distinguishes_escaped_terminal_dollars() -> None:
    assert strict_json_schema_pattern_end(r"^value$") == r"^value(?![\s\S])"
    assert strict_json_schema_pattern_end(r"^literal\$") == r"^literal\$"
    assert strict_json_schema_pattern_end(r"^slash\\$") == r"^slash\\(?![\s\S])"
    assert strict_json_schema_pattern_end(r"^already(?![\s\S])") == (r"^already(?![\s\S])")


def test_recursive_rewrite_changes_patterns_only() -> None:
    schema: dict[str, object] = {
        "pattern": r"^root$",
        "description": r"^prose$",
        "$defs": {
            "nested": {"pattern": r"^nested$"},
            "literal": {"pattern": r"^literal\$"},
        },
        "patternProperties": {
            r"^property$": {"type": "string"},
            r"^literal-property\$": {"type": "integer"},
        },
    }

    harden_json_schema_pattern_ends(schema)

    assert schema == {
        "pattern": r"^root(?![\s\S])",
        "description": r"^prose$",
        "$defs": {
            "nested": {"pattern": r"^nested(?![\s\S])"},
            "literal": {"pattern": r"^literal\$"},
        },
        "patternProperties": {
            r"^property(?![\s\S])": {"type": "string"},
            r"^literal-property\$": {"type": "integer"},
        },
    }


@pytest.mark.parametrize("terminator", _FINAL_LINE_TERMINATORS)
def test_strict_end_rejects_every_ecma_line_terminator(terminator: str) -> None:
    schema: dict[str, object] = {
        "type": "string",
        "pattern": r"^[a-f0-9]{64}$",
    }
    harden_json_schema_pattern_ends(schema)
    validator = Draft202012Validator(schema)
    runtime = TypeAdapter(DigestHex)
    digest = "a" * 64

    validator.validate(digest)
    assert runtime.validate_python(digest, strict=True) == digest
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(digest + terminator)
    with pytest.raises(PydanticValidationError):
        runtime.validate_python(digest + terminator, strict=True)


@pytest.mark.parametrize("terminator", _FINAL_LINE_TERMINATORS)
def test_pattern_property_strict_end_rejects_line_terminators(
    terminator: str,
) -> None:
    schema: dict[str, object] = {
        "type": "object",
        "patternProperties": {r"^[a-f0-9]{64}$": {"type": "integer"}},
        "additionalProperties": False,
    }
    harden_json_schema_pattern_ends(schema)
    validator = Draft202012Validator(schema)
    digest = "a" * 64

    validator.validate({digest: 1})
    with pytest.raises(JsonSchemaValidationError):
        validator.validate({digest + terminator: 1})


@pytest.mark.parametrize(("artifact_kind", "model"), tuple(SCHEMA_MODELS.items()))
def test_current_writer_schemas_have_no_unescaped_terminal_dollar(
    artifact_kind: str,
    model: type,
) -> None:
    remaining = sorted(
        pattern
        for pattern in _patterns(writer_json_schema(model))
        if strict_json_schema_pattern_end(pattern) != pattern
    )

    assert remaining == [], f"{artifact_kind} retains terminal-dollar patterns: {remaining}"


def test_v066_exported_schemas_have_no_unescaped_terminal_dollar() -> None:
    schema_root = Path(__file__).resolve().parents[3] / "schemas" / "v0.6.6"
    schema_paths = tuple(sorted(schema_root.glob("*.schema.json")))
    assert schema_paths
    remaining: list[tuple[str, str]] = []
    for schema_path in schema_paths:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        remaining.extend(
            (schema_path.name, pattern)
            for pattern in _patterns(schema)
            if strict_json_schema_pattern_end(pattern) != pattern
        )

    assert remaining == []


@pytest.mark.parametrize("schema_version", sorted(FROZEN_SCHEMA_VERSIONS))
def test_frozen_schemas_have_no_terminal_dollar_after_in_memory_hardening(
    schema_version: str,
) -> None:
    schema_root = Path(__file__).resolve().parents[3] / "schemas" / f"v{schema_version}"
    schema_paths = tuple(sorted(schema_root.glob("*.schema.json")))
    assert schema_paths
    remaining: list[tuple[str, str]] = []
    for schema_path in schema_paths:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        harden_json_schema_pattern_ends(schema)
        remaining.extend(
            (schema_path.name, pattern)
            for pattern in _patterns(schema)
            if strict_json_schema_pattern_end(pattern) != pattern
        )

    assert remaining == []
