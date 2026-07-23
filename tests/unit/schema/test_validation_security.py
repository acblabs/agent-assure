from __future__ import annotations

from pathlib import Path

import pytest
from referencing.exceptions import Unresolvable

from agent_assure.schema import validation


def test_legacy_schema_version_cannot_traverse_schema_root() -> None:
    payload = {
        "artifact_kind": "run-set",
        "schema_version": "0.1.0/../../attacker",
    }

    with pytest.raises(ValueError, match="unsupported frozen schema_version"):
        validation.validate_artifact_payload(payload, "run-set")


def test_frozen_schema_requires_expected_self_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        validation,
        "_legacy_frozen_schema",
        lambda _version, _kind: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://attacker.example/permissive.schema.json",
            "type": "object",
            "properties": {
                "artifact_kind": {"const": "run-set"},
                "schema_version": {"const": "0.1.0"},
            },
        },
    )

    with pytest.raises(ValueError, match="unexpected canonical identity"):
        validation.validate_artifact_payload(
            {"artifact_kind": "run-set", "schema_version": "0.1.0"},
            "run-set",
        )


def test_frozen_schema_rejects_remote_references(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        validation,
        "_legacy_frozen_schema",
        lambda _version, _kind: {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": ("https://acblabs.github.io/agent-assure/schemas/v0.1.0/run-set.schema.json"),
            "type": "object",
            "properties": {
                "artifact_kind": {"const": "run-set"},
                "schema_version": {"const": "0.1.0"},
                "runs": {"$ref": "https://attacker.example/schema.json"},
            },
        },
    )

    with pytest.raises(ValueError, match="non-local schema reference"):
        validation.validate_artifact_payload(
            {"artifact_kind": "run-set", "schema_version": "0.1.0"},
            "run-set",
        )


def test_frozen_schema_file_read_is_bounded(tmp_path: Path) -> None:
    schema = tmp_path / "oversized.schema.json"
    schema.write_bytes(b"{" + b" " * validation.MAX_FROZEN_SCHEMA_BYTES + b"}")

    with pytest.raises(ValueError, match="exceeds maximum supported size"):
        validation.load_json_bounded(
            schema,
            max_bytes=validation.MAX_FROZEN_SCHEMA_BYTES,
            label="frozen JSON Schema",
        )


def test_explicit_empty_registry_does_not_retrieve_remote_ref() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "https://attacker.invalid/never-fetch.json",
    }

    with pytest.raises(Unresolvable):
        validation._validate_json_schema(schema, {})
