from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import agent_assure
import agent_assure.schema_resources as schema_resources
from agent_assure.schema import export as schema_export
from agent_assure.schema import validation as artifact_validation
from agent_assure.schema.v1_compatibility import (
    MAX_COMPATIBILITY_MATRIX_BYTES,
    MAX_COMPATIBILITY_SCHEMA_BYTES,
    CompatibilityCell,
    CompatibilityDecision,
    CompatibilityKey,
    CompatibilityMatrix,
    assess_compatibility,
    load_compatibility_matrix,
    version_order,
)

_RESOURCE = b'{"type":"object","additionalProperties":false}'
_REPLAY = "agent-assure:legacy/0.6.6/current-semantic"


def _key(**changes: Any) -> CompatibilityKey:
    values = {
        "producer_package_version": "0.7.0",
        "writer_schema_version": "0.6.6",
        "artifact_kind": "evidence-packet",
        "reader_package_version": "1.0.0a3",
    }
    return CompatibilityKey.model_validate(values | changes)


def _cell(**changes: Any) -> CompatibilityCell:
    values = _key().model_dump() | {
        "disposition": "semantic_replay_and_authorization_eligible",
        "minimum_reader_version": "1.0.0a1",
        "schema_resource_digest": f"sha256:{hashlib.sha256(_RESOURCE).hexdigest()}",
        "semantic_replay_identity": _REPLAY,
        "migration_identity": None,
        "losses": (),
        "authorization_restrictions": ("Compatibility supplies no v1 authorization.",),
    }
    return CompatibilityCell.model_validate(values | changes)


def _matrix(*cells: CompatibilityCell) -> CompatibilityMatrix:
    return CompatibilityMatrix(
        format="agent-assure-compatibility-matrix/v1", cells=cells or (_cell(),)
    )


@pytest.mark.parametrize(
    "value",
    [
        "1.0.0",
        "1.0.0a0",
        "1.0.0a3",
        "1.0.0b1",
        "1.0.0rc1",
        "0.6.6",
        "999999999.999999999.999999999rc999999999",
    ],
)
def test_canonical_finite_versions_are_accepted(value: str) -> None:
    assert _key(reader_package_version=value).reader_package_version == value


@pytest.mark.parametrize(
    "value",
    [
        "1.0",
        "1.0.0\n",
        "1.0.0 ",
        "v1.0.0",
        "01.0.0",
        "1.00.0",
        "1.0.00",
        "1.0.0a01",
        "1.0.0RC1",
        "1.0.0-a3",
        "1.0.0rc",
        "1.0.0a-1",
        "1.0.0+local",
        "1!1.0.0",
        "1.0.0.dev1",
        "1.0.0.post1",
        "1.0.0.*",
        ">=1.0.0",
        "1000000000.0.0",
        "1.0.0a1000000000",
        "١.0.0",
        "1.0.0" + "0" * 65,
        True,
        1,
    ],
)
def test_unsupported_version_grammar_is_not_normalized(value: object) -> None:
    with pytest.raises(ValueError):
        version_order(value)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        _key(reader_package_version=value)


def test_finite_version_order_distinguishes_numeric_suffix_and_final() -> None:
    ordered = [
        "0.9.9",
        "1.0.0a2",
        "1.0.0a10",
        "1.0.0b0",
        "1.0.0rc1",
        "1.0.0",
        "1.0.1a0",
        "1.1.0a0",
        "2.0.0a0",
    ]
    assert sorted(reversed(ordered), key=version_order) == ordered


@pytest.mark.parametrize(
    "changes",
    [
        {"producer_package_version": "0.7.1"},
        {"writer_schema_version": "0.6.5"},
        {"artifact_kind": "authorization-artifact"},
        {"reader_package_version": "1.0.0a4"},
    ],
)
def test_each_exact_identity_is_required_without_nearest_cell_fallback(
    changes: dict[str, str],
) -> None:
    decision = assess_compatibility(_matrix(), _key(**changes), schema_resource=_RESOURCE)
    assert decision.disposition == "unsupported"
    assert decision.reason == "SCHEMA_COMPATIBILITY_CELL_ABSENT"
    assert decision.minimum_reader_satisfied is False
    assert decision.schema_integrity_verified is False


def test_released_reader_does_not_gain_new_writer_support() -> None:
    new_cell = _cell(
        producer_package_version="1.0.0a3",
        writer_schema_version="1.0.0rc1",
        artifact_kind="authorization-artifact",
        disposition="shape_and_integrity_only",
        semantic_replay_identity=None,
    )
    key = CompatibilityKey.model_validate(
        new_cell.model_dump(include=set(CompatibilityKey.model_fields))
        | {"reader_package_version": "0.7.0"}
    )
    decision = assess_compatibility(_matrix(new_cell), key, schema_resource=_RESOURCE)
    assert decision.reason == "SCHEMA_COMPATIBILITY_CELL_ABSENT"
    assert decision.authorization_effect == "none"


def test_minimum_reader_is_checked_before_resource_access() -> None:
    cell = _cell(minimum_reader_version="1.0.0rc1")
    # An invalid resource type would raise if resource processing occurred.
    decision = assess_compatibility(
        _matrix(cell),
        _key(),
        schema_resource=object(),  # type: ignore[arg-type]
    )
    assert decision.reason == "SCHEMA_MINIMUM_READER_UNSATISFIED"
    assert decision.schema_integrity_verified is False


@pytest.mark.parametrize(
    ("resource", "reason"),
    [
        (None, "SCHEMA_RESOURCE_UNAVAILABLE"),
        (_RESOURCE + b" ", "SCHEMA_RESOURCE_DIGEST_MISMATCH"),
        (b"x" * (MAX_COMPATIBILITY_SCHEMA_BYTES + 1), "SCHEMA_RESOURCE_TOO_LARGE"),
    ],
    ids=("missing", "tampered", "oversized"),
)
def test_missing_tampered_or_oversized_resource_is_unsupported(
    resource: bytes | None, reason: str
) -> None:
    decision = assess_compatibility(_matrix(), _key(), schema_resource=resource)
    assert decision.disposition == "unsupported"
    assert decision.reason == reason
    assert decision.minimum_reader_satisfied is True
    assert decision.schema_integrity_verified is False


def test_absent_replay_never_becomes_integrity_only_success() -> None:
    decision = assess_compatibility(_matrix(), _key(), schema_resource=_RESOURCE)
    assert decision.reason == "SCHEMA_SEMANTIC_REPLAY_UNAVAILABLE"
    assert decision.schema_integrity_verified is True
    assert decision.semantic_compatibility_eligible is False


def test_exact_supported_replay_is_compatibility_only() -> None:
    decision = assess_compatibility(
        _matrix(),
        _key(),
        schema_resource=_RESOURCE,
        available_semantic_replays=frozenset({_REPLAY}),
    )
    assert decision.disposition == "semantic_replay_and_authorization_eligible"
    assert decision.semantic_compatibility_eligible is True
    assert decision.authorization_effect == "none"
    assert decision.reason is None


def test_integrity_only_cell_is_never_promoted_by_available_replay() -> None:
    cell = _cell(disposition="shape_and_integrity_only", losses=("No authority replay.",))
    decision = assess_compatibility(
        _matrix(cell),
        _key(),
        schema_resource=_RESOURCE,
        available_semantic_replays=frozenset({_REPLAY}),
    )
    assert decision.disposition == "shape_and_integrity_only"
    assert decision.semantic_compatibility_eligible is False
    assert decision.authorization_effect == "none"


def test_explicit_unsupported_cell_cannot_be_promoted() -> None:
    cell = _cell(disposition="unsupported", semantic_replay_identity=None)
    decision = assess_compatibility(
        _matrix(cell),
        _key(),
        schema_resource=object(),  # type: ignore[arg-type]
    )
    assert decision.reason == "SCHEMA_COMPATIBILITY_CELL_UNSUPPORTED"


def test_unsupported_migration_does_not_use_available_semantic_replay() -> None:
    cell = _cell(migration_identity="inspection-only/v1")
    decision = assess_compatibility(
        _matrix(cell),
        _key(),
        schema_resource=_RESOURCE,
        available_semantic_replays=frozenset({_REPLAY}),
    )
    assert decision.reason == "SCHEMA_MIGRATION_UNSUPPORTED"


def test_exact_migration_identity_is_required() -> None:
    cell = _cell(migration_identity="inspection-only/v1", disposition="shape_and_integrity_only")
    decision = assess_compatibility(
        _matrix(cell),
        _key(),
        schema_resource=_RESOURCE,
        available_migrations=frozenset({"inspection-only/v1"}),
    )
    assert decision.disposition == "shape_and_integrity_only"
    assert decision.authorization_effect == "none"


def test_cell_matrix_and_returned_mapping_are_immutable() -> None:
    matrix = _matrix()
    with pytest.raises(ValidationError):
        matrix.cells[0].disposition = "unsupported"
    with pytest.raises(ValidationError):
        matrix.cells = ()
    with pytest.raises(TypeError):
        matrix.as_mapping()[_key().as_tuple()] = _cell()  # type: ignore[index]


def test_matrix_rejects_duplicate_and_unsorted_exact_cells() -> None:
    first = _cell(reader_package_version="1.0.0a2")
    second = _cell(reader_package_version="1.0.0a3")
    with pytest.raises(ValidationError, match="unique, lexicographically ordered"):
        _matrix(first, first)
    with pytest.raises(ValidationError, match="unique, lexicographically ordered"):
        _matrix(second, first)
    assert _matrix(first, second).lookup(_key()) == second


def test_exact_lookup_searches_immutable_cells_without_rebuilding_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cells = tuple(
        sorted(
            (_cell(reader_package_version=f"1.0.0a{index}") for index in range(17)),
            key=CompatibilityCell.as_tuple,
        )
    )
    matrix = _matrix(*cells)

    def forbidden_mapping(_self: CompatibilityMatrix) -> None:
        raise AssertionError("lookup rebuilt the matrix mapping")

    monkeypatch.setattr(CompatibilityMatrix, "as_mapping", forbidden_mapping)
    for cell in cells:
        assert matrix.lookup(_key(reader_package_version=cell.reader_package_version)) is cell
    assert matrix.lookup(_key(reader_package_version="1.0.0a17")) is None
    assert matrix.lookup(_key(reader_package_version="0.0.0")) is None
    assert matrix.lookup(_key(reader_package_version="9.0.0")) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"authorization_effect": "deployment"},
        {"minimum_reader_version": None},
        {"schema_resource_digest": "sha256:" + "A" * 64},
        {"schema_resource_digest": "sha256:" + "a" * 64 + "\n"},
        {"semantic_replay_identity": None},
        {"semantic_replay_identity": "replay/v1\n"},
        {"migration_identity": "https://example.test/schema?latest=1"},
        {"artifact_kind": "../evidence-packet"},
        {"artifact_kind": "evidence-packet\n"},
        {"losses": ("same", "same")},
        {"losses": ("z", "a")},
        {"losses": ("control\n",)},
        {"losses": ("\ud800",)},
        {"authorization_restrictions": ()},
        {"authorization_restrictions": ("x" * 513,)},
        {"losses": tuple(f"{index:04d}" for index in range(129))},
    ],
)
def test_cell_rejects_open_unbounded_or_ambiguous_values(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _cell(**changes)


@pytest.mark.parametrize("missing", ["migration_identity", "semantic_replay_identity", "losses"])
def test_required_nullability_is_distinct_from_absence(missing: str) -> None:
    payload = _cell().model_dump()
    del payload[missing]
    with pytest.raises(ValidationError):
        CompatibilityCell.model_validate(payload)


def test_matrix_json_round_trip_preserves_explicit_nulls_and_cells() -> None:
    matrix = _matrix()
    restored = CompatibilityMatrix.model_validate_json(matrix.model_dump_json())
    assert restored == matrix
    raw = json.loads(matrix.model_dump_json())
    assert raw["cells"][0]["migration_identity"] is None
    assert raw["cells"][0]["losses"] == []


def test_bounded_json_loader_only_converts_declared_json_arrays_to_tuples() -> None:
    matrix = _matrix()
    raw = matrix.model_dump_json().encode("utf-8")
    loaded = load_compatibility_matrix(raw)
    assert loaded == matrix
    assert isinstance(loaded.cells, tuple)
    assert isinstance(loaded.cells[0].losses, tuple)
    assert isinstance(loaded.cells[0].authorization_restrictions, tuple)
    with pytest.raises(ValidationError):
        CompatibilityMatrix.model_validate(json.loads(raw))
    payload = _cell().model_dump() | {"losses": []}
    with pytest.raises(ValidationError):
        CompatibilityCell.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    ["format", "reader_package_version", "losses"],
)
def test_bounded_json_loader_rejects_duplicate_keys_at_each_object_boundary(field: str) -> None:
    raw = _matrix().model_dump_json()
    needle = {
        "format": '"format":"agent-assure-compatibility-matrix/v1"',
        "reader_package_version": '"reader_package_version":"1.0.0a3"',
        "losses": '"losses":[]',
    }[field]
    assert raw.count(needle) == 1
    duplicate = raw.replace(needle, f"{needle},{needle}").encode("utf-8")
    with pytest.raises(ValueError, match="duplicate object keys"):
        load_compatibility_matrix(duplicate)


@pytest.mark.parametrize(
    "raw",
    [
        b" " * (MAX_COMPATIBILITY_MATRIX_BYTES + 1),
        b"\xff",
        b"\xef\xbb\xbf{}",
        b"[]",
        b'{"format":NaN}',
        b'{"unknown":' + (b"[" * 80) + b"0" + (b"]" * 80) + b"}",
    ],
    ids=("oversized", "invalid-utf8", "bom", "non-object", "nonfinite", "excessive-depth"),
)
def test_bounded_json_loader_rejects_oversize_invalid_encoding_and_hostile_json(raw: bytes) -> None:
    with pytest.raises(ValueError):
        load_compatibility_matrix(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"reader_package_version": 1},
        {"minimum_reader_version": True},
        {"semantic_replay_identity": 1},
        {"losses": [False]},
        {"authorization_restrictions": "not-an-array"},
        {"losses": ["\udfff"]},
    ],
)
def test_bounded_json_loader_never_coerces_scalars_or_invalid_unicode(
    changes: dict[str, object],
) -> None:
    payload = json.loads(_matrix().model_dump_json())
    payload["cells"][0].update(changes)
    with pytest.raises(ValidationError):
        load_compatibility_matrix(json.dumps(payload).encode("utf-8"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("producer_package_version", "0.7.0\n"),
        ("writer_schema_version", "0.6.6\n"),
        ("reader_package_version", "1.0.0a3\n"),
        ("minimum_reader_version", "1.0.0a1\n"),
        ("artifact_kind", "evidence-packet\n"),
        ("semantic_replay_identity", _REPLAY + "\n"),
        ("migration_identity", "inspection-only/v1\n"),
        ("losses", ["loss\n"]),
        ("authorization_restrictions", ["restriction\n"]),
    ],
)
def test_emitted_matrix_schema_rejects_trailing_newlines_like_runtime(
    field: str, value: object
) -> None:
    matrix = _matrix()
    schema = CompatibilityMatrix.model_json_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    payload = json.loads(matrix.model_dump_json())
    assert validator.is_valid(payload)
    payload["cells"][0][field] = value
    assert not validator.is_valid(payload)
    with pytest.raises(ValidationError):
        load_compatibility_matrix(json.dumps(payload).encode("utf-8"))


def test_closed_matrix_json_rejects_candidate_supplied_availability() -> None:
    payload = json.loads(_matrix().model_dump_json())
    payload["available_semantic_replays"] = [_REPLAY]
    with pytest.raises(ValidationError):
        CompatibilityMatrix.model_validate_json(json.dumps(payload))
    payload = json.loads(_matrix().model_dump_json())
    payload["cells"][0]["available_semantic_replays"] = [_REPLAY]
    with pytest.raises(ValidationError):
        CompatibilityMatrix.model_validate_json(json.dumps(payload))


def test_matrix_schema_closes_every_object_and_bounds_collections() -> None:
    schema = CompatibilityMatrix.model_json_schema()
    objects = [schema, *schema["$defs"].values()]
    for value in objects:
        if value.get("type") == "object":
            assert value["additionalProperties"] is False
    assert schema["properties"]["cells"]["maxItems"] == 4096
    cell = schema["$defs"]["CompatibilityCell"]
    assert cell["properties"]["losses"]["maxItems"] == 128


@pytest.mark.parametrize(
    "changes",
    [
        {"authorization_effect": "deployment"},
        {"minimum_reader_satisfied": 1},
        {"schema_integrity_verified": 0},
        {"disposition": "shape_and_integrity_only", "reason": None},
        {"reason": None},
    ],
)
def test_decision_cannot_claim_support_or_authority_without_prerequisites(
    changes: dict[str, object],
) -> None:
    decision = assess_compatibility(_matrix(), _key(), schema_resource=None)
    payload = deepcopy(decision.model_dump()) | changes
    with pytest.raises(ValidationError):
        CompatibilityDecision.model_validate(payload)


_MATRIX_PATH = "v1.0.0rc1/compatibility-matrix.json"


def _installed_case(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    **cell_changes: Any,
) -> tuple[CompatibilityCell, dict[str, bytes | None], list[str]]:
    kind = cell_changes.get("artifact_kind", "evidence-packet")
    wire = cell_changes.get("writer_schema_version", "0.6.6")
    schema = {
        "$id": f"https://acblabs.github.io/agent-assure/schemas/v{wire}/{kind}.schema.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "artifact_kind": {"const": kind},
            "schema_version": {"const": wire},
        },
        "required": ["artifact_kind", "schema_version"],
        "additionalProperties": False,
    }
    raw_schema = json.dumps(schema, sort_keys=True).encode("utf-8")
    replay = artifact_validation._frozen_root_semantic_replay_identity(kind, wire)
    cell = _cell(
        **(
            {
                "schema_resource_digest": f"sha256:{hashlib.sha256(raw_schema).hexdigest()}",
                "semantic_replay_identity": replay,
                "disposition": (
                    "semantic_replay_and_authorization_eligible"
                    if replay is not None
                    else "shape_and_integrity_only"
                ),
            }
            | cell_changes
        )
    )
    resources: dict[str, bytes | None] = {
        _MATRIX_PATH: _matrix(cell).model_dump_json().encode("utf-8"),
        cell.schema_resource_path: raw_schema,
    }
    identity = artifact_validation._InstalledReaderIdentity(
        "1.0.0a3",
        tmp_path / "installed" / "agent_assure" / "schema_resources",
        frozenset(f"agent_assure/schema_resources/{name}" for name in resources),
    )
    monkeypatch.setattr(artifact_validation, "_installed_reader_identity", lambda: identity)
    calls: list[str] = []

    def read_resource(
        reader: artifact_validation._InstalledReaderIdentity,
        relative: str,
        *,
        max_bytes: int,
    ) -> bytes | None:
        assert reader is identity
        assert max_bytes == 1024 * 1024
        calls.append(relative)
        return resources.get(relative)

    monkeypatch.setattr(
        artifact_validation, "_read_installed_compatibility_resource", read_resource
    )
    return cell, resources, calls


def _inspect_case(
    cell: CompatibilityCell,
    resources: dict[str, bytes | None],
    **changes: Any,
) -> CompatibilityDecision:
    raw_matrix = resources[_MATRIX_PATH]
    values = {
        "producer_package_version": cell.producer_package_version,
        "writer_schema_version": cell.writer_schema_version,
        "artifact_kind": cell.artifact_kind,
        "expected_matrix_digest": f"sha256:{hashlib.sha256(raw_matrix or b'').hexdigest()}",
    }
    return artifact_validation.inspect_installed_reader_compatibility(**(values | changes))


def test_installed_inspection_uses_resources_without_source_fallback_or_artifact_projection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(monkeypatch, tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("inspection used a source fallback or artifact projection")

    monkeypatch.setattr(artifact_validation, "source_checkout_component", forbidden)
    monkeypatch.setattr(artifact_validation, "_legacy_frozen_schema", forbidden)
    monkeypatch.setattr(artifact_validation, "project_validated_artifact_payload", forbidden)
    result = _inspect_case(cell, resources)
    assert calls == [_MATRIX_PATH, cell.schema_resource_path]
    assert result.disposition == "semantic_replay_and_authorization_eligible"
    assert result.authorization_effect == "none"
    assert result.key.reader_package_version == "1.0.0a3"


def test_matrix_digest_precedes_parsing_or_schema_access(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(monkeypatch, tmp_path)
    original = resources[_MATRIX_PATH]
    assert original is not None
    expected = f"sha256:{hashlib.sha256(original).hexdigest()}"
    resources[_MATRIX_PATH] = b"not JSON"

    def forbidden(_raw: bytes) -> CompatibilityMatrix:
        raise AssertionError("mismatching raw bytes reached the matrix parser")

    monkeypatch.setattr(artifact_validation, "load_compatibility_matrix", forbidden)
    result = _inspect_case(cell, resources, expected_matrix_digest=expected)
    assert result.reason == "SCHEMA_COMPATIBILITY_MATRIX_DIGEST_MISMATCH"
    assert calls == [_MATRIX_PATH]


@pytest.mark.parametrize("raw", [None, b"{}", b"not JSON"], ids=["missing", "closed", "invalid"])
def test_missing_or_malformed_matrix_is_unsupported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: bytes | None
) -> None:
    cell, resources, calls = _installed_case(monkeypatch, tmp_path)
    resources[_MATRIX_PATH] = raw
    result = _inspect_case(cell, resources)
    assert result.reason == (
        "SCHEMA_COMPATIBILITY_MATRIX_UNAVAILABLE"
        if raw is None
        else "SCHEMA_COMPATIBILITY_MATRIX_INVALID"
    )
    assert result.authorization_effect == "none"
    assert calls == [_MATRIX_PATH]


def test_installed_minimum_reader_fails_before_opening_the_schema(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(
        monkeypatch, tmp_path, minimum_reader_version="1.0.0rc1"
    )
    result = _inspect_case(cell, resources)
    assert result.reason == "SCHEMA_MINIMUM_READER_UNSATISFIED"
    assert calls == [_MATRIX_PATH]


def test_matrix_cannot_promote_an_archival_frozen_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(
        monkeypatch,
        tmp_path,
        producer_package_version="0.5.0",
        writer_schema_version="0.5.0",
        artifact_kind="evaluation-summary",
        disposition="semantic_replay_and_authorization_eligible",
        semantic_replay_identity="candidate-asserted-replay/v1",
    )
    result = _inspect_case(cell, resources)
    assert result.reason == "SCHEMA_COMPATIBILITY_POLICY_MISMATCH"
    assert calls == [_MATRIX_PATH]


def test_archival_resource_stays_integrity_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(
        monkeypatch,
        tmp_path,
        producer_package_version="0.5.0",
        writer_schema_version="0.5.0",
        artifact_kind="evaluation-summary",
    )
    result = _inspect_case(cell, resources)
    assert result.disposition == "shape_and_integrity_only"
    assert result.semantic_compatibility_eligible is False
    assert result.authorization_effect == "none"
    assert calls == [_MATRIX_PATH, cell.schema_resource_path]


def test_unknown_prospective_writer_cell_cannot_start_resource_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(
        monkeypatch,
        tmp_path,
        producer_package_version="1.0.0a3",
        writer_schema_version="1.0.0rc1",
        artifact_kind="authorization-artifact",
    )
    result = _inspect_case(cell, resources)
    assert result.reason == "SCHEMA_COMPATIBILITY_CELL_ABSENT"
    assert calls == [_MATRIX_PATH]


@pytest.mark.parametrize(
    "changes",
    [
        {"semantic_replay_identity": "candidate-asserted-replay/v1"},
        {"migration_identity": "future-migration/v1"},
    ],
    ids=["replay", "migration"],
)
def test_unimplemented_replay_or_migration_is_unsupported_before_schema_access(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changes: dict[str, str]
) -> None:
    cell, resources, calls = _installed_case(monkeypatch, tmp_path, **changes)
    result = _inspect_case(cell, resources)
    assert result.reason in {"SCHEMA_SEMANTIC_REPLAY_UNAVAILABLE", "SCHEMA_MIGRATION_UNSUPPORTED"}
    assert calls == [_MATRIX_PATH]


def test_declared_loss_cannot_gain_semantic_eligibility_with_a_null_migration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(
        monkeypatch,
        tmp_path,
        losses=("Original claim-relevant information was lost.",),
        migration_identity=None,
    )
    result = _inspect_case(cell, resources)
    assert result.reason == "SCHEMA_MIGRATION_UNSUPPORTED"
    assert result.semantic_compatibility_eligible is False
    assert result.authorization_effect == "none"
    assert calls == [_MATRIX_PATH]


def test_shape_only_inspection_can_retain_explicit_losses_without_a_migration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(
        monkeypatch,
        tmp_path,
        disposition="shape_and_integrity_only",
        losses=("Original claim-relevant information was lost.",),
        migration_identity=None,
    )
    result = _inspect_case(cell, resources)
    assert result.disposition == "shape_and_integrity_only"
    assert result.semantic_compatibility_eligible is False
    assert result.authorization_effect == "none"
    assert calls == [_MATRIX_PATH, cell.schema_resource_path]


@pytest.mark.parametrize(
    "mutation",
    [
        "identity",
        "version",
        "dialect",
        "remote-ref",
        "malformed",
        "root-string",
        "identity-not",
        "identity-allof",
        "root-allof",
        "root-not-object",
        "dangling-ref",
        "cyclic-ref",
    ],
)
def test_matching_schema_hash_is_insufficient_without_exact_schema_vocabulary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mutation: str
) -> None:
    cell, resources, calls = _installed_case(monkeypatch, tmp_path)
    original_schema = resources[cell.schema_resource_path]
    assert original_schema is not None
    schema = json.loads(original_schema)
    if mutation == "identity":
        schema["properties"]["artifact_kind"] = {"const": "wrong-kind"}
    elif mutation == "version":
        schema["properties"]["schema_version"] = {"const": "0.6.5"}
    elif mutation == "dialect":
        schema["$schema"] = "https://example.invalid/unknown-dialect"
    elif mutation == "remote-ref":
        schema["$ref"] = "https://example.invalid/schema"
    elif mutation == "malformed":
        schema["type"] = "not-a-schema-type"
    elif mutation == "root-string":
        schema["type"] = "string"
    elif mutation == "identity-not":
        schema["properties"]["schema_version"]["not"] = {"const": "0.6.6"}
    elif mutation == "identity-allof":
        schema["properties"]["schema_version"]["allOf"] = [{"not": {"const": "0.6.6"}}]
    elif mutation == "root-allof":
        schema["allOf"] = [{"properties": {"schema_version": {"not": {"const": "0.6.6"}}}}]
    elif mutation == "root-not-object":
        schema["not"] = {"type": "object"}
    elif mutation == "dangling-ref":
        schema["properties"]["schema_version"]["$ref"] = "#/$defs/absent"
    else:
        schema["properties"]["schema_version"]["$ref"] = "#/$defs/cycle"
        schema["$defs"] = {"cycle": {"$ref": "#/$defs/cycle"}}
    changed = json.dumps(schema).encode("utf-8")
    resources[cell.schema_resource_path] = changed
    changed_cell = _cell(
        **(
            cell.model_dump()
            | {"schema_resource_digest": f"sha256:{hashlib.sha256(changed).hexdigest()}"}
        )
    )
    resources[_MATRIX_PATH] = _matrix(changed_cell).model_dump_json().encode("utf-8")
    result = _inspect_case(changed_cell, resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.schema_integrity_verified is True
    assert calls == [_MATRIX_PATH, cell.schema_resource_path]


def test_identity_declaration_local_refs_resolve_in_the_full_offline_schema_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(monkeypatch, tmp_path)
    raw_schema = resources[cell.schema_resource_path]
    assert raw_schema is not None
    schema = json.loads(raw_schema)
    schema["$defs"] = {"version": {"enum": ["0.6.6"]}}
    schema["properties"]["schema_version"]["$ref"] = "#/$defs/version"
    changed = json.dumps(schema).encode("utf-8")
    resources[cell.schema_resource_path] = changed
    changed_cell = _cell(
        **(
            cell.model_dump()
            | {"schema_resource_digest": f"sha256:{hashlib.sha256(changed).hexdigest()}"}
        )
    )
    resources[_MATRIX_PATH] = _matrix(changed_cell).model_dump_json().encode("utf-8")
    result = _inspect_case(changed_cell, resources)
    assert result.disposition == "semantic_replay_and_authorization_eligible"
    assert result.authorization_effect == "none"
    assert calls == [_MATRIX_PATH, cell.schema_resource_path]


def _pin_inspection_schema(
    cell: CompatibilityCell,
    resources: dict[str, bytes | None],
    schema: dict[str, Any],
) -> CompatibilityCell:
    raw = json.dumps(schema, sort_keys=True).encode("utf-8")
    updated = _cell(
        **(
            cell.model_dump()
            | {"schema_resource_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}"}
        )
    )
    resources[cell.schema_resource_path] = raw
    resources[_MATRIX_PATH] = _matrix(updated).model_dump_json().encode("utf-8")
    return updated


@pytest.mark.parametrize(
    ("encoded", "decoded"),
    [
        ("v%65rsion", "version"),
        ("%76ersion", "version"),
        ("v%2565rsion", "v%65rsion"),
        ("v%7E1rsion", "v/rsion"),
    ],
)
def test_encoded_identity_references_cannot_select_a_different_literal_definition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, encoded: str, decoded: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["schema_version"] = {
        "enum": ["0.6.5", "0.6.6"],
        "$ref": f"#/$defs/{encoded}",
    }
    schema["$defs"] = {decoded: {"const": "0.6.5"}, encoded: {"const": "0.6.6"}}
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    assert validator.is_valid({"artifact_kind": "evidence-packet", "schema_version": "0.6.5"})
    assert not validator.is_valid({"artifact_kind": "evidence-packet", "schema_version": "0.6.6"})
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.semantic_compatibility_eligible is False
    assert result.authorization_effect == "none"


def _conditional_identity_schema(raw: bytes | None) -> dict[str, Any]:
    assert raw is not None
    schema: dict[str, Any] = json.loads(raw)
    schema["properties"]["schema_version"] = {"enum": ["0.6.5", "0.6.6"]}
    schema["properties"]["x"] = {"type": "boolean"}
    schema["required"].append("x")
    schema["allOf"] = [
        {
            "if": {"required": ["x"]},
            "then": {"properties": {"schema_version": {"not": {"const": "0.6.6"}}}},
        }
    ]
    return schema


@pytest.mark.parametrize("presence_source", ["root", "allof", "dependent", "reference"])
def test_mandatory_presence_cannot_hide_a_conditional_identity_exclusion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, presence_source: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    schema = _conditional_identity_schema(resources[cell.schema_resource_path])
    if presence_source != "root":
        schema["required"].remove("x")
    if presence_source == "allof":
        schema["allOf"].insert(0, {"required": ["x"]})
    elif presence_source == "dependent":
        schema["dependentSchemas"] = {"artifact_kind": {"required": ["x"]}}
    elif presence_source == "reference":
        schema["$defs"] = {"presence": {"required": ["x"]}}
        schema["allOf"].insert(0, {"$ref": "#/$defs/presence"})

    # This is a nonempty schema excluding the requested pair. A missing-payload
    # probe chooses the opposite branch and therefore is not a valid proof.
    validator = Draft202012Validator(schema)
    assert validator.is_valid(
        {"artifact_kind": "evidence-packet", "schema_version": "0.6.5", "x": False}
    )
    assert not validator.is_valid(
        {"artifact_kind": "evidence-packet", "schema_version": "0.6.6", "x": False}
    )
    pinned = _pin_inspection_schema(cell, resources, schema)
    result = _inspect_case(pinned, resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.schema_integrity_verified is True
    assert result.semantic_compatibility_eligible is False
    assert result.authorization_effect == "none"


@pytest.mark.parametrize("guard_location", ["then", "else", "dependent", "branch-local"])
def test_optional_or_unresolved_context_never_supplies_identity_admission(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, guard_location: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["x"] = {"type": "boolean", "default": False}
    rejecting = {"properties": {"schema_version": {"const": "0.6.5"}}}
    if guard_location == "dependent":
        schema["dependentSchemas"] = {"x": rejecting}
    elif guard_location == "branch-local":
        # Although the outer trigger is unknown, its branch's own presence
        # facts make the inner identity restriction necessarily active.
        schema["dependentSchemas"] = {
            "x": {
                "required": ["y"],
                "if": {"required": ["y"]},
                "then": rejecting,
            }
        }
    else:
        schema["if"] = {"required": ["x"]}
        schema[guard_location] = rejecting
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.semantic_compatibility_eligible is False


def test_identity_neutral_payload_conditions_do_not_require_a_payload_solver(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["payload"] = {"type": "string"}
    schema["if"] = {"properties": {"payload": {"pattern": "^[a-z]+$"}}, "required": ["payload"]}
    schema["then"] = {"properties": {"payload": {"minLength": 2}}}
    schema["else"] = {"properties": {"payload": {"maxLength": 5}}}
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.disposition == "semantic_replay_and_authorization_eligible"
    assert result.authorization_effect == "none"


@pytest.mark.parametrize(("fixed", "tested"), [(False, 0), (0, False), (True, 1), (1, True)])
def test_guard_literal_equality_distinguishes_booleans_from_numbers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fixed: object, tested: object
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["flag"] = {"const": fixed}
    schema["required"].append("flag")
    schema["if"] = {"properties": {"flag": {"const": tested}}, "required": ["flag"]}
    schema["then"] = {"properties": {"schema_version": {"const": "0.6.5"}}}
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.disposition == "semantic_replay_and_authorization_eligible"


def test_integral_json_numbers_activate_integer_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["flag"] = {"const": 1.0}
    schema["required"].append("flag")
    schema["if"] = {"properties": {"flag": {"type": "integer"}}, "required": ["flag"]}
    schema["then"] = {"properties": {"schema_version": {"const": "0.6.5"}}}
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"


def test_conflicting_active_literals_cannot_select_a_favorable_condition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["flag"] = {"const": False}
    schema["required"].append("flag")
    schema["allOf"] = [{"properties": {"flag": {"const": 0}}}]
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"


@pytest.mark.parametrize(
    "constraint",
    [
        {"patternProperties": {"^schema_version$": {"const": "0.6.5"}}},
        {"propertyNames": {"not": {"const": "schema_version"}}},
        {"unevaluatedProperties": False},
        {
            "$defs": {
                "nested": {"$id": "#nested", "properties": {"schema_version": {"const": "0.6.6"}}}
            },
            "$ref": "#/$defs/nested",
        },
    ],
)
def test_unproved_object_wide_and_resource_scope_constraints_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, constraint: dict[str, Any]
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["allOf"] = [constraint]
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"


@pytest.mark.parametrize(
    "cap",
    [
        "_MAX_IDENTITY_SCHEMA_NODES",
        "_MAX_IDENTITY_SCHEMA_DEPTH",
        "_MAX_IDENTITY_PROFILE_WORK",
        "_MAX_IDENTITY_PROFILE_REFERENCES",
        "_MAX_IDENTITY_PROFILE_FACTS",
    ],
)
def test_exhausted_identity_profile_limits_never_return_eligibility(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, cap: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["$defs"] = {"version": {"const": "0.6.6"}}
    schema["properties"]["schema_version"]["$ref"] = "#/$defs/version"
    pinned = _pin_inspection_schema(cell, resources, schema)
    monkeypatch.setattr(artifact_validation, cap, 0)
    result = _inspect_case(pinned, resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.schema_integrity_verified is True
    assert result.semantic_compatibility_eligible is False


@pytest.mark.parametrize(
    "amplification", ["enum", "references", "pointer-chars", "pointer-segments"]
)
def test_valid_but_expensive_identity_resources_exhaust_explicit_bounds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, amplification: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    if amplification == "enum":
        # An admitted identity at the last enum position requires charging
        # every element and its string comparison, not just one schema node.
        schema["properties"]["schema_version"]["enum"] = [
            f"unrelated-version-{index:04d}" for index in range(4_096)
        ] + ["0.6.6"]
    elif amplification == "references":
        schema["$defs"] = {"identity": {"properties": {"schema_version": {"const": "0.6.6"}}}}
        schema["allOf"] = [{"$ref": "#/$defs/identity"} for _ in range(520)]
    elif amplification == "pointer-chars":
        name = "v" * 4_097
        schema["$defs"] = {name: {"const": "0.6.6"}}
        schema["properties"]["schema_version"]["$ref"] = f"#/$defs/{name}"
    else:
        # A path may be short in bytes yet exceed the independent traversal
        # limit. Definitions nest without adding a candidate reference cycle.
        nested: dict[str, Any] = {"const": "0.6.6"}
        for _ in range(65):
            nested = {"$defs": {"x": nested}}
        schema["$defs"] = {"chain": nested}
        schema["properties"]["schema_version"]["$ref"] = "#/$defs/chain" + "/$defs/x" * 65
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.schema_integrity_verified is True
    assert result.semantic_compatibility_eligible is False


@pytest.mark.parametrize("restriction", ["direct", "identity-guard"])
def test_unknown_oneof_overlap_cannot_hide_an_identity_pair_exclusion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, restriction: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["schema_version"] = {"enum": ["0.6.5", "0.6.6"]}
    schema["properties"]["x"] = {"type": "boolean"}
    schema["required"].append("x")
    if restriction == "direct":
        schema["oneOf"] = [
            {"properties": {"schema_version": {"enum": ["0.6.5", "0.6.6"]}, "x": {"const": True}}},
            {"properties": {"schema_version": {"const": "0.6.6"}, "x": {"const": True}}},
        ]
    else:
        schema["oneOf"] = [
            {
                "if": {"properties": {"schema_version": {"const": "0.6.6"}}},
                "then": {"properties": {"x": {"const": True}}},
                "else": {"properties": {"x": {"const": False}}},
            },
            {"properties": {"x": {"const": True}}},
        ]
    validator = Draft202012Validator(schema)
    assert validator.is_valid(
        {"artifact_kind": "evidence-packet", "schema_version": "0.6.5", "x": True}
    )
    for x in (True, False):
        assert not validator.is_valid(
            {"artifact_kind": "evidence-packet", "schema_version": "0.6.6", "x": x}
        )
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.semantic_compatibility_eligible is False


def test_payload_only_oneof_remains_the_artifact_validators_responsibility(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["x"] = {"type": "boolean"}
    schema["required"].append("x")
    schema["oneOf"] = [
        {"properties": {"x": {"const": True}}},
        {"properties": {"x": {"const": False}}},
    ]
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.disposition == "semantic_replay_and_authorization_eligible"
    assert result.authorization_effect == "none"


def test_anyof_rejects_an_identity_excluded_by_every_possible_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["schema_version"] = {"enum": ["0.6.5", "0.6.6"]}
    schema["properties"]["x"] = {"type": "boolean"}
    schema["required"].append("x")
    schema["anyOf"] = [
        {"properties": {"schema_version": {"const": "0.6.5"}, "x": {"const": x}}}
        for x in (True, False)
    ]
    validator = Draft202012Validator(schema)
    assert validator.is_valid(
        {"artifact_kind": "evidence-packet", "schema_version": "0.6.5", "x": True}
    )
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.semantic_compatibility_eligible is False


@pytest.mark.parametrize("context", ["literal", "presence"])
@pytest.mark.parametrize("wrapper", ["direct", "conditional"])
def test_oneof_cannot_hide_identity_exclusion_through_propagated_payload_facts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, context: str, wrapper: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["schema_version"] = {"enum": ["0.6.5", "0.6.6"]}
    schema["properties"].update({name: {"type": "boolean"} for name in ("x", "y", "z")})
    schema["required"].extend(["y", "z"])
    by_version: dict[str, Any] = {"if": {"properties": {"schema_version": {"const": "0.6.6"}}}}
    if context == "literal":
        schema["required"].append("x")
        by_version["then"] = {"properties": {"x": {"const": True}}}
        by_version["else"] = {"properties": {"x": {"const": False}}}
        escape: dict[str, Any] = {"properties": {"x": {"const": False}}}
    else:
        by_version["then"] = {"required": ["x"]}
        escape = {"not": {"required": ["x"]}}
    choices = [
        {"properties": {"y": {"const": True}}},
        {"anyOf": [escape, {"properties": {"y": {"const": True}}}]},
    ]
    schema["allOf"] = [by_version]
    if wrapper == "direct":
        schema["oneOf"] = choices
    else:
        # All conforming objects satisfy this guard, but the presence/literal
        # fact domain leaves the nonliteral boolean value unknown. Nested
        # asserted oneOf must still be inspected in that outer branch.
        schema["allOf"].append(
            {
                "if": {"properties": {"z": {"type": "boolean"}}, "required": ["z"]},
                "then": {"oneOf": choices},
            }
        )
    witness = {
        "artifact_kind": "evidence-packet",
        "schema_version": "0.6.5",
        "y": False,
        "z": False,
    }
    if context == "literal":
        witness["x"] = False
    validator = Draft202012Validator(schema)
    assert validator.is_valid(witness)
    for x in (False, True):
        for y in (False, True):
            for z in (False, True):
                assert not validator.is_valid(
                    {
                        "artifact_kind": "evidence-packet",
                        "schema_version": "0.6.6",
                        "x": x,
                        "y": y,
                        "z": z,
                    }
                )
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"
    assert result.semantic_compatibility_eligible is False


@pytest.mark.parametrize("presence", ["global", "branch", "optional"])
def test_oneof_disjoint_scalar_sets_need_presence_in_any_joint_match(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, presence: str
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["status"] = {"type": "string"}
    schema["oneOf"] = [
        {"properties": {"status": {"enum": ["complete", "archived"]}}},
        {"properties": {"status": {"enum": ["incomplete", "pending"]}}},
    ]
    if presence == "global":
        schema["required"].append("status")
    elif presence == "branch":
        schema["oneOf"][1]["required"] = ["status"]
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    if presence == "optional":
        # Without a presence obligation both properties constraints permit an
        # omitted status, so their scalar sets do not certify exclusivity.
        assert result.reason == "SCHEMA_RESOURCE_INVALID"
    else:
        assert result.disposition == "semantic_replay_and_authorization_eligible"


def test_oneof_composite_enum_members_cannot_manufacture_scalar_disjointness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, _calls = _installed_case(monkeypatch, tmp_path)
    raw = resources[cell.schema_resource_path]
    assert raw is not None
    schema = json.loads(raw)
    schema["properties"]["payload"] = {}
    schema["required"].append("payload")
    schema["oneOf"] = [
        {"properties": {"payload": {"enum": [True, {}]}}},
        {"properties": {"payload": {"enum": [False, {}]}}},
    ]
    result = _inspect_case(_pin_inspection_schema(cell, resources, schema), resources)
    assert result.reason == "SCHEMA_RESOURCE_INVALID"


def test_schema_tamper_fails_before_schema_parsing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cell, resources, calls = _installed_case(monkeypatch, tmp_path)
    resources[cell.schema_resource_path] = b"tampered schema"

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("tampered schema reached root-vocabulary validation")

    monkeypatch.setattr(artifact_validation, "_prepare_frozen_schema", forbidden)
    result = _inspect_case(cell, resources)
    assert result.reason == "SCHEMA_RESOURCE_DIGEST_MISMATCH"
    assert calls == [_MATRIX_PATH, cell.schema_resource_path]


@pytest.mark.parametrize("digest", ["latest", "sha256:" + "A" * 64, "sha256:" + "a" * 64 + "\n"])
def test_malformed_expected_pin_fails_before_installed_identity_io(
    monkeypatch: pytest.MonkeyPatch, digest: str
) -> None:
    def forbidden() -> None:
        raise AssertionError("malformed expected pin reached installed identity discovery")

    monkeypatch.setattr(artifact_validation, "_installed_reader_identity", forbidden)
    with pytest.raises(ValueError, match="exact lowercase SHA-256"):
        artifact_validation.inspect_installed_reader_compatibility(
            producer_package_version="0.7.0",
            writer_schema_version="0.6.6",
            artifact_kind="evidence-packet",
            expected_matrix_digest=digest,
        )


class _DistributionFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._path = root / "agent_assure-1.0.0a3.dist-info"
        self._path.mkdir(parents=True)
        self.data = {
            "agent_assure/__init__.py": b"# inert package fixture\n",
            "agent_assure/schema/validation.py": b"# inert validation fixture\n",
            "agent_assure/schema_resources/__init__.py": b"# inert resource fixture\n",
            f"{self._path.name}/METADATA": (
                b"Metadata-Version: 2.4\nName: agent-assure\nVersion: 1.0.0a3\n\n"
            ),
        }
        self.extra_rows: list[tuple[str, str, str]] = []
        for relative, data in self.data.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.write_record()

    @property
    def metadata(self) -> None:
        raise AssertionError("unbounded stdlib metadata accessor was used")

    @property
    def files(self) -> None:
        raise AssertionError("stdlib files accessor may follow hostile RECORD paths")

    @property
    def version(self) -> None:
        raise AssertionError("unbounded stdlib version accessor was used")

    def read_text(self, _relative: str) -> None:
        raise AssertionError("unbounded stdlib read_text was used")

    @property
    def record_names(self) -> frozenset[str]:
        return (
            frozenset(self.data)
            | {f"{self._path.name}/RECORD"}
            | {row[0] for row in self.extra_rows}
        )

    def write_record(self, *, omit_modules: bool = False) -> None:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        for relative, data in self.data.items():
            if omit_modules and relative.startswith("agent_assure/"):
                continue
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            writer.writerow((relative, f"sha256={digest.decode('ascii')}", len(data)))
        writer.writerow((f"{self._path.name}/RECORD", "", ""))
        writer.writerows(self.extra_rows)
        (self._path / "RECORD").write_bytes(stream.getvalue().encode("utf-8"))

    def write_metadata(self, data: bytes) -> None:
        self.add_file(f"{self._path.name}/METADATA", data)

    def add_file(self, relative: str, data: bytes) -> None:
        self.data[relative] = data
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        self.write_record()


def _distribution_case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _DistributionFixture:
    installed = _DistributionFixture(tmp_path / "site-packages")
    monkeypatch.setattr(artifact_validation, "distribution", lambda _name: installed)
    monkeypatch.setattr(agent_assure, "__version__", "1.0.0a3")
    monkeypatch.setattr(
        agent_assure, "__file__", str(installed.root / "agent_assure" / "__init__.py")
    )
    monkeypatch.setattr(
        artifact_validation,
        "__file__",
        str(installed.root / "agent_assure" / "schema" / "validation.py"),
    )
    monkeypatch.setattr(
        schema_resources,
        "__file__",
        str(installed.root / "agent_assure" / "schema_resources" / "__init__.py"),
    )
    return installed


def test_installed_identity_binds_actual_version_and_three_owned_module_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    reader = artifact_validation._installed_reader_identity()
    assert reader.package_version == "1.0.0a3"
    assert reader.resource_root == installed.root / "agent_assure" / "schema_resources"
    assert reader.record_names == installed.record_names


@pytest.mark.parametrize(
    "problem",
    [
        "name",
        "stale-version",
        "noncanonical-version",
        "missing-record",
        "duplicate-record",
        "editable",
    ],
)
def test_untrusted_or_editable_installed_metadata_is_not_a_reader_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, problem: str
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    if problem == "name":
        installed.write_metadata(b"Name: different-project\nVersion: 1.0.0a3\n\n")
    elif problem == "stale-version":
        installed.write_metadata(b"Name: agent-assure\nVersion: 0.7.0\n\n")
    elif problem == "noncanonical-version":
        installed.write_metadata(b"Name: agent-assure\nVersion: 01.0.0\n\n")
    elif problem == "missing-record":
        (installed._path / "RECORD").write_bytes(b"")
    elif problem == "duplicate-record":
        record = installed._path / "RECORD"
        data = record.read_bytes()
        record.write_bytes(data + data.splitlines(keepends=True)[0])
    else:
        installed.write_record(omit_modules=True)
    with pytest.raises(ValueError):
        artifact_validation._installed_reader_identity()


@pytest.mark.parametrize("module", ["package", "validation", "resources"])
def test_distribution_cannot_claim_a_different_loaded_module_location(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, module: str
) -> None:
    _distribution_case(monkeypatch, tmp_path)
    selected = {
        "package": agent_assure,
        "validation": artifact_validation,
        "resources": schema_resources,
    }[module]
    monkeypatch.setattr(selected, "__file__", str(tmp_path / "source-checkout" / "unowned.py"))
    with pytest.raises(ValueError, match="own the loaded module"):
        artifact_validation._installed_reader_identity()


def test_missing_installed_distribution_cannot_invent_a_reader_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_name: str) -> None:
        raise artifact_validation.PackageNotFoundError("agent-assure")

    monkeypatch.setattr(artifact_validation, "distribution", missing)
    with pytest.raises(ValueError, match="distribution is unavailable"):
        artifact_validation._installed_reader_identity()


@pytest.mark.parametrize("kind", ["dir_info", "vcs_info"])
def test_directory_or_vcs_provenance_does_not_count_as_a_wheel_installation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    relative = "agent_assure-1.0.0a3.dist-info/direct_url.json"
    installed.add_file(
        relative, json.dumps({"url": "file:///inert-fixture", kind: {}}).encode("utf-8")
    )
    with pytest.raises(ValueError, match="not a wheel installation"):
        artifact_validation._installed_reader_identity()


@pytest.mark.parametrize("filename", ["METADATA", "RECORD"])
def test_installed_metadata_bytes_are_bounded_before_parsing_or_property_access(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, filename: str
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    (installed._path / filename).write_bytes(b"x" * (MAX_COMPATIBILITY_MATRIX_BYTES + 1))
    with pytest.raises(ValueError, match="maximum supported size"):
        artifact_validation._installed_reader_identity()


@pytest.mark.parametrize(
    "headers",
    [
        b"Name: agent-assure\nName: agent-assure\nVersion: 1.0.0a3\n\n",
        b"Name: agent-assure\nVersion: 1.0.0a3\nVersion: 1.0.0a3\n\n",
        b"Name: agent-assure\nVersion: 1.0.0a3\n folded\n\n",
        b"Name: agent-assure\nVersion: 1.0.0a3\n\xff\n",
    ],
    ids=["duplicate-name", "duplicate-version", "folded-version", "invalid-utf8"],
)
def test_installed_metadata_requires_one_exact_utf8_name_and_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, headers: bytes
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    installed.write_metadata(headers)
    with pytest.raises(ValueError):
        artifact_validation._installed_reader_identity()


@pytest.mark.parametrize(
    "problem",
    [
        "columns",
        "quotes",
        "duplicate",
        "empty-name",
        "path-length",
        "path-control",
        "path-backslash",
        "path-absolute",
        "digest",
        "size",
        "size-bound",
        "row-count",
        "byte-count",
        "encoding",
    ],
)
def test_raw_record_parser_rejects_malformed_duplicate_and_oversize_rows(problem: str) -> None:
    values = {
        "columns": b"only,two\n",
        "quotes": b'"unterminated,,\n',
        "duplicate": b"same,,\nsame,,\n",
        "empty-name": b",,\n",
        "path-length": b"x" * 513 + b",,\n",
        "path-control": b'"line\nbreak",,\n',
        "path-backslash": b"relative\\entry,,\n",
        "path-absolute": b"C:/outside/entry,,\n",
        "digest": b"entry,sha256=invalid,1\n",
        "size": b"entry,sha256=" + b"A" * 43 + b",0001\n",
        "size-bound": b"entry,sha256=" + b"A" * 43 + b",1000000000\n",
        "row-count": b"".join(f"entry-{index},,\n".encode("ascii") for index in range(10_001)),
        "byte-count": b"x" * (MAX_COMPATIBILITY_MATRIX_BYTES + 1),
        "encoding": b"\xff,,\n",
    }
    with pytest.raises(ValueError):
        artifact_validation._parse_installed_record(values[problem])


def test_irrelevant_parent_script_rows_are_opaque_and_never_opened(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    opaque = "../../../Scripts/inert-command.exe"
    installed.extra_rows.append((opaque, "", ""))
    installed.write_record()
    original = artifact_validation.read_file_bounded_at

    def guarded(root: Path, relative: str | Path, **kwargs: Any) -> Any:
        assert str(relative) != opaque
        return original(root, relative, **kwargs)

    monkeypatch.setattr(artifact_validation, "read_file_bounded_at", guarded)
    reader = artifact_validation._installed_reader_identity()
    assert opaque in reader.record_names


def test_foreign_distribution_provenance_is_rejected_before_it_can_be_opened(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    installed.extra_rows.append(("foreign-1.0.0.dist-info/direct_url.json", "", ""))
    installed.write_record()
    original = artifact_validation.read_file_bounded_at

    def guarded(root: Path, relative: str | Path, **kwargs: Any) -> Any:
        assert not str(relative).endswith("direct_url.json")
        return original(root, relative, **kwargs)

    monkeypatch.setattr(artifact_validation, "read_file_bounded_at", guarded)
    with pytest.raises(ValueError, match="does not belong"):
        artifact_validation._installed_reader_identity()


def test_loaded_module_bytes_must_match_the_owned_record_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    (installed.root / "agent_assure/__init__.py").write_bytes(b"tampered fixture module")
    with pytest.raises(ValueError, match="owned RECORD row"):
        artifact_validation._installed_reader_identity()


def test_metadata_anchor_must_identify_a_supported_unpacked_wheel(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    installed = _distribution_case(monkeypatch, tmp_path)
    installed._path = tmp_path / "foreign-1.0.0a3.dist-info"
    installed._path.mkdir()
    (installed._path / "METADATA").write_bytes(b"Name: agent-assure\nVersion: 1.0.0a3\n\n")
    with pytest.raises(ValueError, match="metadata anchor does not match"):
        artifact_validation._installed_reader_identity()


def test_resource_discovery_requires_record_membership_and_matching_installed_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resource_root = tmp_path / "installed-resources"
    resource = resource_root / _MATRIX_PATH
    resource.parent.mkdir(parents=True)
    resource.write_bytes(b"bounded fixture resource")
    names = frozenset({f"agent_assure/schema_resources/{_MATRIX_PATH}"})
    reader = artifact_validation._InstalledReaderIdentity("1.0.0a3", resource_root, names)
    monkeypatch.setattr(artifact_validation, "files", lambda _package: resource_root)
    assert (
        artifact_validation._read_installed_compatibility_resource(
            reader, _MATRIX_PATH, max_bytes=1024
        )
        == b"bounded fixture resource"
    )
    unlisted = artifact_validation._InstalledReaderIdentity("1.0.0a3", resource_root, frozenset())
    assert (
        artifact_validation._read_installed_compatibility_resource(
            unlisted, _MATRIX_PATH, max_bytes=1024
        )
        is None
    )
    monkeypatch.setattr(artifact_validation, "files", lambda _package: tmp_path / "checkout")
    with pytest.raises(ValueError, match="package identity does not match"):
        artifact_validation._read_installed_compatibility_resource(
            reader, _MATRIX_PATH, max_bytes=1024
        )


_EXPECTED_LEGACY_PRODUCERS: tuple[tuple[str, str], ...] = (
    ("0.1.0", "0.1.0"),
    ("0.2.0", "0.2.0"),
    ("0.3.0", "0.2.0"),
    ("0.3.1", "0.3.1"),
    ("0.4.2", "0.3.1"),
    ("0.4.4", "0.4.3"),
    ("0.5.0", "0.5.0"),
    ("0.6.0", "0.6.0"),
    ("0.6.1", "0.6.1"),
    ("0.6.2", "0.6.2"),
    ("0.6.3", "0.6.3"),
    ("0.6.4", "0.6.4"),
    ("0.6.5", "0.6.5"),
    ("0.7.0", "0.6.6"),
)


def _snapshot_schema_root() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas"


@pytest.fixture(scope="module")
def actual_legacy_matrix() -> CompatibilityMatrix:
    schema_root = _snapshot_schema_root()

    def hashes() -> dict[str, str]:
        return {
            path.relative_to(schema_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in schema_root.glob("v*/*.schema.json")
        }

    before = hashes()
    matrix = schema_export.build_legacy_compatibility_matrix(schema_root=schema_root)
    first = schema_export.compatibility_matrix_json_bytes(matrix)
    second = schema_export.compatibility_matrix_json_bytes(
        schema_export.build_legacy_compatibility_matrix(schema_root=schema_root)
    )
    assert first == second
    assert first.endswith(b"\n") and not first.endswith(b"\n\n")
    assert len(first) <= MAX_COMPATIBILITY_MATRIX_BYTES
    assert load_compatibility_matrix(first) == matrix
    assert hashes() == before
    return matrix


def test_generated_legacy_matrix_covers_exact_facts_and_the_sole_frozen_policy(
    actual_legacy_matrix: CompatibilityMatrix,
) -> None:
    facts = _EXPECTED_LEGACY_PRODUCERS
    if agent_assure.__version__ == "1.0.0a3":
        facts = (*facts, ("1.0.0a3", "0.6.6"))
    expected = {
        (producer, wire, kind, "1.0.0a3")
        for producer, wire in facts
        for kind, frozen_wire in artifact_validation.FROZEN_ROOT_VALIDATION_POLICY
        if frozen_wire == wire
    }
    assert {cell.as_tuple() for cell in actual_legacy_matrix.cells} == expected
    for cell in actual_legacy_matrix.cells:
        raw = (_snapshot_schema_root() / cell.schema_resource_path).read_bytes()
        assert cell.schema_resource_digest == f"sha256:{hashlib.sha256(raw).hexdigest()}"
        assert cell.minimum_reader_version == "1.0.0a3"
        assert cell.migration_identity is None
        assert cell.losses == ()
        assert "v1 action consumption" in " ".join(cell.authorization_restrictions)
        policy = artifact_validation.FROZEN_ROOT_VALIDATION_POLICY[
            (cell.artifact_kind, cell.writer_schema_version)
        ]
        if policy is artifact_validation.FrozenRootValidationPolicy.archival_only:
            assert cell.disposition == "shape_and_integrity_only"
            assert cell.semantic_replay_identity is None
        else:
            assert cell.disposition == "semantic_replay_and_authorization_eligible"
            assert cell.semantic_replay_identity == (
                artifact_validation._frozen_root_semantic_replay_identity(
                    cell.artifact_kind, cell.writer_schema_version
                )
            )


def test_every_released_matrix_resource_preserves_its_inspection_disposition(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    actual_legacy_matrix: CompatibilityMatrix,
) -> None:
    # Exercise actual resource bytes through the public inspector, including
    # usage-ledger's mutually exclusive old/new aggregation conditions. This
    # is resource-profile regression evidence, not an installed-wheel claim.
    matrix = actual_legacy_matrix
    resources: dict[str, bytes | None] = {
        _MATRIX_PATH: schema_export.compatibility_matrix_json_bytes(matrix),
    }
    cells = {cell.schema_resource_path: cell for cell in matrix.cells}
    for path in cells:
        resources[path] = (_snapshot_schema_root() / path).read_bytes()
    reader = artifact_validation._InstalledReaderIdentity(
        "1.0.0a3",
        tmp_path / "verified-resources",
        frozenset(f"agent_assure/schema_resources/{name}" for name in resources),
    )
    monkeypatch.setattr(artifact_validation, "_installed_reader_identity", lambda: reader)

    def read_resource(
        identity: artifact_validation._InstalledReaderIdentity,
        relative: str,
        *,
        max_bytes: int,
    ) -> bytes | None:
        assert identity is reader
        raw = resources.get(relative)
        assert raw is None or len(raw) <= max_bytes
        return raw

    monkeypatch.setattr(
        artifact_validation, "_read_installed_compatibility_resource", read_resource
    )
    assert "v0.6.6/usage-ledger.schema.json" in cells
    for path, cell in cells.items():
        result = _inspect_case(cell, resources)
        assert result.disposition == cell.disposition, (path, result.reason)
        assert result.schema_integrity_verified is True, path
        assert result.authorization_effect == "none", path
        assert (_snapshot_schema_root() / path).read_bytes() == resources[path], path


def test_generated_matrix_keeps_producer_writer_and_reader_versions_distinct(
    actual_legacy_matrix: CompatibilityMatrix,
) -> None:
    old = actual_legacy_matrix.lookup(
        _key(
            producer_package_version="0.3.0",
            writer_schema_version="0.2.0",
            artifact_kind="agent-run-record",
        )
    )
    assert old is not None
    assert old.schema_resource_path.startswith("v0.2.0/")
    assert (
        actual_legacy_matrix.lookup(
            _key(producer_package_version="0.3.0", writer_schema_version="0.3.0")
        )
        is None
    )
    assert actual_legacy_matrix.lookup(_key(reader_package_version="0.7.0")) is None
    assert actual_legacy_matrix.lookup(_key(reader_package_version="1.0.0a4")) is None
    assert (
        actual_legacy_matrix.lookup(
            _key(producer_package_version="0.4.1", writer_schema_version="0.3.1")
        )
        is None
    )
    assert all(cell.writer_schema_version != "1.0.0rc1" for cell in actual_legacy_matrix.cells)


def test_generated_matrix_bytes_round_trip_through_bounded_storage(
    actual_legacy_matrix: CompatibilityMatrix, tmp_path: Path
) -> None:
    raw = schema_export.compatibility_matrix_json_bytes(actual_legacy_matrix)
    path = tmp_path / "compatibility-matrix.json"
    assert path.write_bytes(raw) == len(raw)
    stored = artifact_validation.read_file_bounded_at(
        tmp_path,
        "compatibility-matrix.json",
        max_bytes=MAX_COMPATIBILITY_MATRIX_BYTES,
        label="prospective compatibility matrix",
    ).data
    assert stored == raw
    assert load_compatibility_matrix(stored) == actual_legacy_matrix


def _minimal_schema_bytes(relative: str) -> bytes:
    directory, filename = relative.split("/")
    wire = directory.removeprefix("v")
    kind = filename.removesuffix(".schema.json")
    return json.dumps(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://acblabs.github.io/agent-assure/schemas/v{wire}/{kind}.schema.json",
            "type": "object",
            "properties": {
                "artifact_kind": {"const": kind},
                "schema_version": {"const": wire},
            },
            "additionalProperties": False,
        },
        sort_keys=True,
    ).encode("utf-8")


def test_generator_reads_each_original_resource_once_with_no_writes_or_installed_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    reads: list[str] = []

    def read(root: Path, relative: str, *, max_bytes: int, label: str) -> SimpleNamespace:
        assert root == tmp_path
        assert max_bytes == artifact_validation.MAX_FROZEN_SCHEMA_BYTES
        assert label == "frozen compatibility schema"
        reads.append(relative)
        return SimpleNamespace(data=_minimal_schema_bytes(relative))

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("explicit-source matrix generation wrote or used installed fallback")

    monkeypatch.setattr(schema_export, "read_file_bounded_at", read)
    monkeypatch.setattr(schema_export, "write_text_atomic", forbidden)
    monkeypatch.setattr(artifact_validation, "_installed_reader_identity", forbidden)
    matrix = schema_export.build_legacy_compatibility_matrix(schema_root=tmp_path)
    expected = {
        f"v{wire}/{kind}.schema.json"
        for kind, wire in artifact_validation.FROZEN_ROOT_VALIDATION_POLICY
    }
    assert set(reads) == expected
    assert len(reads) == len(expected)
    assert matrix.cells


def test_generator_includes_preview_producer_only_after_the_actual_version_choice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def read(_root: Path, relative: str, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(data=_minimal_schema_bytes(relative))

    monkeypatch.setattr(schema_export, "read_file_bounded_at", read)
    monkeypatch.setattr(agent_assure, "__version__", "0.7.0")
    original = schema_export.build_legacy_compatibility_matrix(schema_root=tmp_path)
    assert all(cell.producer_package_version != "1.0.0a3" for cell in original.cells)
    monkeypatch.setattr(agent_assure, "__version__", "1.0.0a3")
    preview = schema_export.build_legacy_compatibility_matrix(schema_root=tmp_path)
    assert preview.lookup(_key(producer_package_version="1.0.0a3")) is not None
    assert all(
        cell.writer_schema_version == "0.6.6"
        for cell in preview.cells
        if cell.producer_package_version == "1.0.0a3"
    )
    monkeypatch.setattr(agent_assure, "__version__", "1.0.0a4")
    future = schema_export.build_legacy_compatibility_matrix(schema_root=tmp_path)
    assert all(cell.producer_package_version != "1.0.0a4" for cell in future.cells)


@pytest.mark.parametrize("problem", ["missing", "oversized", "wrong-vocabulary"])
def test_generator_stops_when_a_required_source_resource_is_unavailable_or_invalid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, problem: str
) -> None:
    def read(_root: Path, relative: str, **_kwargs: Any) -> SimpleNamespace:
        if problem == "missing":
            raise FileNotFoundError("inert missing resource fixture")
        if problem == "oversized":
            return SimpleNamespace(data=b"x" * (artifact_validation.MAX_FROZEN_SCHEMA_BYTES + 1))
        schema = json.loads(_minimal_schema_bytes(relative))
        schema["properties"]["artifact_kind"] = {"const": "different-kind"}
        return SimpleNamespace(data=json.dumps(schema).encode("utf-8"))

    monkeypatch.setattr(schema_export, "read_file_bounded_at", read)
    with pytest.raises((ValueError, FileNotFoundError)):
        schema_export.build_legacy_compatibility_matrix(schema_root=tmp_path)


def test_installed_matrix_generation_does_not_consult_an_explicit_source_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    reader = artifact_validation._InstalledReaderIdentity("1.0.0a3", tmp_path, frozenset())
    calls: list[str] = []
    monkeypatch.setattr(artifact_validation, "_installed_reader_identity", lambda: reader)

    def read(
        identity: artifact_validation._InstalledReaderIdentity,
        relative: str,
        *,
        max_bytes: int,
    ) -> bytes:
        assert identity is reader
        assert max_bytes == artifact_validation.MAX_FROZEN_SCHEMA_BYTES
        calls.append(relative)
        return _minimal_schema_bytes(relative)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("installed matrix generation used source files")

    monkeypatch.setattr(artifact_validation, "_read_installed_compatibility_resource", read)
    monkeypatch.setattr(schema_export, "read_file_bounded_at", forbidden)
    matrix = schema_export.build_legacy_compatibility_matrix()
    assert matrix.cells
    assert calls


def test_matrix_json_encoder_enforces_the_byte_budget_without_emitting_a_partial_result() -> None:
    restrictions = tuple(f"{index:03d}-" + "x" * 508 for index in range(128))
    cells = tuple(
        sorted(
            (
                _cell(
                    reader_package_version=f"1.0.0a{index}",
                    authorization_restrictions=restrictions,
                )
                for index in range(20)
            ),
            key=CompatibilityCell.as_tuple,
        )
    )
    with pytest.raises(ValueError, match="maximum supported size"):
        schema_export.compatibility_matrix_json_bytes(_matrix(*cells))
