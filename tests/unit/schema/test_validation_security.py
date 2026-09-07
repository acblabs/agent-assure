from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from referencing.exceptions import Unresolvable

from agent_assure.ci import load_gate_artifact
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.release_evidence import load_digest_replay
from agent_assure.schema import validation
from agent_assure.schema.base import SCHEMA_VERSION


@pytest.mark.parametrize(
    ("kind", "expected_max"),
    (
        ("run-set", MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES),
        ("compiled-suite", MAX_ARTIFACT_JSON_BYTES),
    ),
)
def test_generic_validation_selects_only_the_bounded_runset_size_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    expected_max: int,
) -> None:
    path = tmp_path / "artifact.json"
    path.write_text("{}", encoding="utf-8")
    observed: dict[str, object] = {}

    def capture_load(
        loaded_path: Path,
        *,
        max_bytes: int,
        label: str,
    ) -> dict[str, object]:
        observed.update(path=loaded_path, max_bytes=max_bytes, label=label)
        return {}

    monkeypatch.setattr(validation, "load_json_bounded_from_filesystem_root", capture_load)
    monkeypatch.setattr(
        validation,
        "validate_artifact_payload",
        lambda _payload, _kind: "bounded-test-validator",
    )

    assert validation.validate_artifact(path, kind) == "bounded-test-validator"
    assert observed == {
        "path": path,
        "max_bytes": expected_max,
        "label": f"{kind} artifact JSON",
    }


def test_legacy_schema_version_cannot_traverse_schema_root() -> None:
    payload = {
        "artifact_kind": "run-set",
        "schema_version": "0.1.0/../../attacker",
    }

    with pytest.raises(ValueError, match="unsupported frozen schema_version"):
        validation.validate_artifact_payload(payload, "run-set")


def test_frozen_runset_preserves_optional_artifact_kind_contract() -> None:
    payload = {
        "schema_version": "0.5.0",
        "runset_id": "runset-legacy",
        "suite_id": "suite-legacy",
        "suite_version": "0.5.0",
        "suite_digest": "0" * 64,
        "fixture_manifest_digest": "1" * 64,
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "runs": [],
    }

    assert validation.validate_artifact_payload(payload, "run-set") == "frozen-jsonschema"

    payload["artifact_kind"] = "compiled-suite"
    with pytest.raises(JsonSchemaValidationError):
        validation.validate_artifact_payload(payload, "run-set")


def test_v060_runset_routes_through_immutable_frozen_schema() -> None:
    payload = {
        "artifact_kind": "run-set",
        "schema_version": "0.6.0",
        "runset_id": "runset-v060",
        "suite_id": "suite-v060",
        "suite_version": "0.6.0",
        "suite_digest": "0" * 64,
        "fixture_manifest_digest": "1" * 64,
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "runs": [],
    }

    assert "0.6.0" in validation.FROZEN_SCHEMA_VERSIONS
    assert validation.validate_artifact_payload(payload, "run-set") == "frozen-jsonschema"


def test_latest_released_schema_is_frozen_while_current_writer_is_not() -> None:
    assert "0.6.5" in validation.FROZEN_SCHEMA_VERSIONS
    assert SCHEMA_VERSION == "0.6.6"
    assert SCHEMA_VERSION not in validation.FROZEN_SCHEMA_VERSIONS


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


def test_json_schema_compilation_cache_is_exact_and_mutation_sensitive() -> None:
    validation._compiled_json_schema_validator.cache_clear()
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
    }

    validation._validate_json_schema(schema, {})
    validation._validate_json_schema(schema, {})
    cache_info = validation._compiled_json_schema_validator.cache_info()
    assert cache_info.misses == 1
    assert cache_info.hits == 1

    schema["required"] = ["required-after-mutation"]
    with pytest.raises(JsonSchemaValidationError):
        validation._validate_json_schema(schema, {})
    mutated_cache_info = validation._compiled_json_schema_validator.cache_info()
    assert mutated_cache_info.misses == 2
    validation._compiled_json_schema_validator.cache_clear()


def test_runtime_schema_validation_error_does_not_echo_instance_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "patient-secret-should-not-appear"
    payload = {
        "artifact_kind": "run-set",
        "schema_version": SCHEMA_VERSION,
    }

    def reject(_schema: dict[str, object], _payload: dict[str, object]) -> None:
        raise JsonSchemaValidationError(f"{secret!r} is not permitted")

    monkeypatch.setattr(validation, "_validate_json_schema", reject)
    with pytest.raises(ValueError) as exc_info:
        validation.validate_loaded_artifact_payload(payload, "run-set")

    assert secret not in str(exc_info.value)
    assert str(exc_info.value) == "run-set artifact failed JSON Schema validation"


def test_runtime_model_validation_error_does_not_echo_instance_values() -> None:
    secret = "patient-secret-duplicate-role"
    payload = {
        "artifact_kind": "release-digest-replay",
        "schema_version": SCHEMA_VERSION,
        "artifacts": [
            {
                "artifact_kind": "release-replay-artifact",
                "schema_version": SCHEMA_VERSION,
                "role": secret,
                "path": "first.json",
                "sha256": "0" * 64,
            },
            {
                "artifact_kind": "release-replay-artifact",
                "schema_version": SCHEMA_VERSION,
                "role": secret,
                "path": "second.json",
                "sha256": "1" * 64,
            },
        ],
    }

    with pytest.raises(ValueError) as exc_info:
        validation.validate_loaded_artifact_payload(payload, "release-digest-replay")

    assert secret not in str(exc_info.value)
    assert str(exc_info.value) == "release-digest-replay artifact failed model validation"


def test_frozen_projection_error_does_not_echo_instance_values(tmp_path: Path) -> None:
    secret = "patient-secret-legacy-duplicate-role"
    payload = {
        "artifact_kind": "release-digest-replay",
        "schema_version": "0.1.0",
        "artifacts": [
            {
                "artifact_kind": "release-replay-artifact",
                "schema_version": "0.1.0",
                "role": secret,
                "path": "first.json",
                "sha256": "0" * 64,
            },
            {
                "artifact_kind": "release-replay-artifact",
                "schema_version": "0.1.0",
                "role": secret,
                "path": "second.json",
                "sha256": "1" * 64,
            },
        ],
    }
    path = tmp_path / "legacy-replay.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        load_digest_replay(path)

    assert secret not in str(exc_info.value)
    assert str(exc_info.value) == "release-digest-replay artifact failed model validation"


def test_ci_gate_unknown_artifact_kind_error_is_value_free(tmp_path: Path) -> None:
    secret = "patient-secret-misplaced-as-kind"
    path = tmp_path / "unknown-kind.json"
    path.write_text(json.dumps({"artifact_kind": secret}), encoding="utf-8")

    with pytest.raises(ValueError) as exc_info:
        load_gate_artifact(path)

    assert secret not in str(exc_info.value)
    assert str(exc_info.value) == (
        "CI gate expects artifact_kind evaluation-summary, comparison-summary, "
        "control-efficacy-report, or evidence-packet"
    )
