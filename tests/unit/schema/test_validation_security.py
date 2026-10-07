from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
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
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.live import LiveComparisonReport
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.run import RunSet


def _v065_live_rate(*, label: str, numerator: int, rate: str) -> dict[str, object]:
    return {
        "artifact_kind": "live-rate",
        "schema_version": "0.6.5",
        "label": label,
        "numerator": numerator,
        "denominator": 1,
        "cluster_count": 1,
        "effective_n": "1.000000",
        "design_effect": "1.000000",
        "largest_cluster_size": 1,
        "largest_cluster_design_effect": "1.000000",
        "largest_cluster_effective_n": "1.000000",
        "assumed_intraclass_correlation": "0.000000",
        "analysis_method": "paired_cluster_t_interval",
        "exploratory": True,
        "rate": rate,
        "cluster_mean_rate": rate,
        "interval_center_value": rate,
        "ci_lower": rate,
        "ci_upper": rate,
    }


def _v065_live_comparison_payload() -> dict[str, object]:
    return {
        "artifact_kind": "live-comparison-report",
        "schema_version": "0.6.5",
        "baseline_runset_id": "baseline-runset",
        "candidate_runset_id": "candidate-runset",
        "suite_id": "suite-v065",
        "suite_version": "0.6.5",
        "baseline_group_id": "overall",
        "candidate_group_id": "overall",
        "protocol_id": "protocol-v065",
        "protocol_digest": "0" * 64,
        "baseline_mode": "concurrent_paired",
        "analysis_method": "paired_cluster_t_interval",
        "exploratory": True,
        "state": "not_evaluated",
        "non_inferiority_margin": "0.000000",
        "baseline_pass_rate": _v065_live_rate(
            label="expectation_pass",
            numerator=0,
            rate="0.000000",
        ),
        "candidate_pass_rate": _v065_live_rate(
            label="expectation_pass",
            numerator=1,
            rate="1.000000",
        ),
        "pass_rate_difference": "1.000000",
        "difference_ci_lower": "1.000000",
        "difference_ci_upper": "1.000000",
        "compared_clusters": 1,
        "effective_n": "1.000000",
    }


def _set_mapping_path(
    payload: dict[str, object],
    path: tuple[str, ...],
    value: str,
) -> None:
    target = payload
    for component in path[:-1]:
        nested = target[component]
        assert isinstance(nested, dict)
        target = nested
    target[path[-1]] = value


def _schema_pattern_values(value: object) -> set[str]:
    patterns: set[str] = set()
    pending = [value]
    while pending:
        candidate = pending.pop()
        if isinstance(candidate, dict):
            pattern = candidate.get("pattern")
            if isinstance(pattern, str):
                patterns.add(pattern)
            pending.extend(candidate.values())
        elif isinstance(candidate, list):
            pending.extend(candidate)
    return patterns


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

    assert (
        validation.validate_artifact_payload(payload, "run-set")
        == "frozen-jsonschema+semantic-replay"
    )

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
    assert (
        validation.validate_artifact_payload(payload, "run-set")
        == "frozen-jsonschema+semantic-replay"
    )


def test_latest_released_and_feature_frozen_candidate_schemas_are_frozen() -> None:
    assert "0.6.5" in validation.FROZEN_SCHEMA_VERSIONS
    assert SCHEMA_VERSION == "0.6.6"
    assert SCHEMA_VERSION in validation.FROZEN_SCHEMA_VERSIONS


def test_frozen_decimal_hardening_replaces_only_exact_known_patterns() -> None:
    fraction_six = r"^0\.[0-9]{6}$"
    nonnegative_six = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
    signed_decimal_six = r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$"
    unsigned_six = r"^(0|1)\.[0-9]{6}$"
    already_bounded_unsigned_six = r"^(0\.[0-9]{6}|1\.000000)$"
    signed_six = r"^-?(0|1)\.[0-9]{6}$"
    unsigned_twelve = r"^(0|1)\.[0-9]{12}$"
    near_match = r"^(0|1)\.[0-9]{5}$"
    schema: dict[str, object] = {
        "pattern": unsigned_six,
        "$defs": {
            "fraction": {"pattern": fraction_six},
            "nonnegative": {"pattern": nonnegative_six},
            "signed_decimal": {"pattern": signed_decimal_six},
            "already_bounded": {"pattern": already_bounded_unsigned_six},
            "signed": {"pattern": signed_six},
            "twelve": {"pattern": unsigned_twelve},
            "near": {"pattern": near_match},
        },
        "description": unsigned_six,
    }

    validation._harden_frozen_decimal_patterns(schema)

    assert schema["pattern"] == r"^(?:0\.[0-9]{6}|1\.000000)(?![\s\S])"
    assert schema["$defs"] == {
        "fraction": {"pattern": r"^0\.[0-9]{6}(?![\s\S])"},
        "nonnegative": {"pattern": r"^(?:0|[1-9][0-9]*)\.[0-9]{6}(?![\s\S])"},
        "signed_decimal": {"pattern": r"^-?(?:0|[1-9][0-9]*)\.[0-9]{6}(?![\s\S])"},
        "already_bounded": {"pattern": r"^(?:0\.[0-9]{6}|1\.000000)(?![\s\S])"},
        "signed": {"pattern": r"^-?(?:0\.[0-9]{6}|1\.000000)(?![\s\S])"},
        "twelve": {"pattern": r"^(?:0\.[0-9]{12}|1\.000000000000)(?![\s\S])"},
        "near": {"pattern": near_match},
    }
    assert schema["description"] == unsigned_six


@pytest.mark.parametrize(
    "schema_version",
    ("0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5", "0.6.6"),
)
def test_all_v06_frozen_fixed_decimal_patterns_are_exact_ended_in_memory(
    schema_version: str,
) -> None:
    schema_root = Path(__file__).resolve().parents[3] / "schemas" / f"v{schema_version}"
    vulnerable_patterns = set(validation._FROZEN_DECIMAL_PATTERN_REPLACEMENTS)

    for schema_path in schema_root.glob("*.schema.json"):
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validation._harden_frozen_decimal_patterns(schema)
        remaining = _schema_pattern_values(schema) & vulnerable_patterns
        assert remaining == set(), f"{schema_path.name} retains {sorted(remaining)}"


def test_v065_frozen_fixed_decimal_boundaries_remain_valid() -> None:
    positive_boundary = _v065_live_comparison_payload()
    assert (
        validation.validate_artifact_payload(positive_boundary, "live-comparison-report")
        == "frozen-jsonschema+semantic-replay"
    )

    negative_boundary = copy.deepcopy(positive_boundary)
    negative_boundary["baseline_pass_rate"] = _v065_live_rate(
        label="expectation_pass",
        numerator=1,
        rate="1.000000",
    )
    negative_boundary["candidate_pass_rate"] = _v065_live_rate(
        label="expectation_pass",
        numerator=0,
        rate="0.000000",
    )
    negative_boundary["pass_rate_difference"] = "-1.000000"
    negative_boundary["difference_ci_lower"] = "-1.000000"
    negative_boundary["difference_ci_upper"] = "-1.000000"
    negative_boundary["state"] = "fail"
    assert (
        validation.validate_artifact_payload(negative_boundary, "live-comparison-report")
        == "frozen-jsonschema+semantic-replay"
    )


def test_bounded_model_loader_reuses_frozen_semantic_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _v065_live_comparison_payload()
    path = tmp_path / "live-comparison-report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    original_projection = validation.project_validated_artifact_payload
    projection_kinds: list[str] = []

    def counting_projection(*args: object, **kwargs: object) -> object:
        kind = kwargs.get("kind")
        assert isinstance(kind, str)
        projection_kinds.append(kind)
        return original_projection(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        validation,
        "project_validated_artifact_payload",
        counting_projection,
    )

    loaded = validation.load_validated_artifact_model(
        path,
        LiveComparisonReport,
        kind="live-comparison-report",
    )

    assert loaded.schema_version == "0.6.5"
    assert projection_kinds == ["live-comparison-report"]


@pytest.mark.parametrize(
    ("path", "invalid_value"),
    (
        (("candidate_pass_rate", "rate"), "1.999999"),
        (("pass_rate_difference",), "-1.000001"),
        (("candidate_pass_rate", "rate"), "1.000000\n"),
        (("non_inferiority_margin",), "0.000000\n"),
        (("effective_n",), "1.000000\n"),
    ),
)
def test_v065_frozen_decimal_hardening_rejects_invalid_values(
    path: tuple[str, ...],
    invalid_value: str,
) -> None:
    payload = _v065_live_comparison_payload()
    _set_mapping_path(payload, path, invalid_value)

    with pytest.raises(JsonSchemaValidationError):
        validation.validate_artifact_payload(payload, "live-comparison-report")


@pytest.mark.parametrize("terminator", ("\n", "\r", "\r\n", "\u2028", "\u2029"))
def test_v065_frozen_schema_hardening_rejects_digest_line_terminators(
    terminator: str,
) -> None:
    payload = _v065_live_comparison_payload()
    payload["protocol_digest"] = "0" * 64 + terminator

    with pytest.raises(JsonSchemaValidationError):
        validation.validate_artifact_payload(payload, "live-comparison-report")


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
        validation._validate_legacy_frozen_schema(
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
        validation._validate_legacy_frozen_schema(
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


def test_current_writer_cache_is_trusted_and_semantics_replay_for_every_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import agent_assure.schema.export as schema_export

    artifacts = (
        ReleaseArtifact(role="first", path="first.json", sha256="a" * 64),
        ReleaseArtifact(role="second", path="second.json", sha256="b" * 64),
    )
    manifest = ReleaseArtifactManifest(
        manifest_id="manifest-cache-contract",
        artifacts=artifacts,
        environment=EnvironmentInfo(platform="test", python_version="3.12"),
    )
    payload = manifest.model_dump(mode="json")
    schema_calls = 0
    projection_calls = 0
    original_writer = schema_export.writer_json_schema
    original_projection = validation.project_validated_artifact_payload

    def tracked_writer(model: type[object]) -> dict[str, object]:
        nonlocal schema_calls
        schema_calls += 1
        return original_writer(model)  # type: ignore[arg-type]

    def tracked_projection(
        candidate: dict[str, object],
        model: type[object],
        *,
        kind: str,
    ) -> object:
        nonlocal projection_calls
        projection_calls += 1
        return original_projection(candidate, model, kind=kind)  # type: ignore[arg-type,return-value]

    validation._current_writer_schema_validator.cache_clear()
    monkeypatch.setattr(schema_export, "writer_json_schema", tracked_writer)
    monkeypatch.setattr(validation, "project_validated_artifact_payload", tracked_projection)
    try:
        first = validation.validate_loaded_artifact_model(
            payload,
            ReleaseArtifactManifest,
            kind="release-artifact-manifest",
        )
        second = validation.validate_loaded_artifact_model(
            payload,
            ReleaseArtifactManifest,
            kind="release-artifact-manifest",
        )

        assert first == manifest
        assert second == manifest
        assert schema_calls == 1
        assert projection_calls == 2

        duplicate_role = copy.deepcopy(payload)
        duplicate_role["artifacts"][1]["role"] = "first"  # type: ignore[index]
        with pytest.raises(ValueError, match="model validation"):
            validation.validate_loaded_artifact_model(
                duplicate_role,
                ReleaseArtifactManifest,
                kind="release-artifact-manifest",
            )

        wrong_kind = copy.deepcopy(payload)
        wrong_kind["artifact_kind"] = "environment-info"
        with pytest.raises(ValueError, match="JSON Schema validation"):
            validation.validate_loaded_artifact_model(
                wrong_kind,
                ReleaseArtifactManifest,
                kind="release-artifact-manifest",
            )

        wrong_version = copy.deepcopy(payload)
        wrong_version["schema_version"] = "9.9.9"
        with pytest.raises(ValueError, match="unsupported frozen schema_version"):
            validation.validate_loaded_artifact_model(
                wrong_version,
                ReleaseArtifactManifest,
                kind="release-artifact-manifest",
            )

        with pytest.raises(ValueError, match="model does not match registered artifact kind"):
            validation._current_writer_schema_validator("release-artifact-manifest", RunSet)
    finally:
        validation._current_writer_schema_validator.cache_clear()


def test_warm_current_writer_validator_is_safe_for_concurrent_validation() -> None:
    payload = EnvironmentInfo(platform="test", python_version="3.12").model_dump(mode="json")
    validation._current_writer_schema_validator.cache_clear()
    try:
        expected = validation.validate_loaded_artifact_model(
            payload,
            EnvironmentInfo,
            kind="environment-info",
        )
        with ThreadPoolExecutor(max_workers=8) as executor:
            observed = tuple(
                executor.map(
                    lambda _index: validation.validate_loaded_artifact_model(
                        payload,
                        EnvironmentInfo,
                        kind="environment-info",
                    ),
                    range(32),
                )
            )
        assert all(item == expected for item in observed)
    finally:
        validation._current_writer_schema_validator.cache_clear()


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
    assert str(exc_info.value) == (
        "release-digest-replay release-replay artifact failed integrity validation"
    )


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
