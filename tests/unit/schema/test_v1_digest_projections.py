"""Exact source-identity projection evidence; no digest-registry claim."""

from __future__ import annotations

import json
from types import MappingProxyType
from typing import Any

import pytest

from agent_assure.canonical import v1 as canonical_v1
from agent_assure.canonical.v1 import source_event_identity_projection_bytes as project
from agent_assure.schema.v1_identity import SourceEventIdentity

IDENTITY = {
    "identity_contract_id": "source-event-identity/v1",
    "run_id": "r",
    "producer_id": "p",
    "producer_epoch": "e",
    "event_id": "v",
}
COMPONENTS = ("run_id", "producer_id", "producer_epoch", "event_id")
KNOWN_BYTES = (
    b'{"event_id":"v","identity_contract_id":"source-event-identity/v1",'
    b'"producer_epoch":"e","producer_id":"p","run_id":"r"}'
)


def test_source_identity_projection_matches_independently_written_canonical_bytes() -> None:
    assert project(IDENTITY) == KNOWN_BYTES
    reordered = dict(reversed(tuple(IDENTITY.items())))
    assert project(reordered) == KNOWN_BYTES
    assert IDENTITY == json.loads(KNOWN_BYTES)


def test_source_identity_projection_preserves_raw_unicode_case_whitespace_and_escapes() -> None:
    value = {
        **IDENTITY,
        "run_id": " Run ",
        "producer_id": "\u00e9",
        "producer_epoch": "e\u0301",
        "event_id": 'line\n"\\',
    }
    actual = project(value)
    expected = (
        r'{"event_id":"line\n\"\\","identity_contract_id":"source-event-identity/v1",'
        '"producer_epoch":"e\u0301","producer_id":"\u00e9","run_id":" Run "}'
    ).encode("utf-8")
    assert actual == expected
    assert json.loads(actual) == value
    assert actual != project({**value, "producer_epoch": "\u00e9"})
    assert actual != project({**value, "run_id": " run "})


def test_source_identity_projection_keeps_delimiter_collisions_distinct() -> None:
    first = {**IDENTITY, "run_id": "a:b", "producer_id": "c"}
    second = {**IDENTITY, "run_id": "a", "producer_id": "b:c"}
    assert ":".join((first["run_id"], first["producer_id"])) == ":".join(
        (second["run_id"], second["producer_id"])
    )
    assert project(first) != project(second)


@pytest.mark.parametrize("field", COMPONENTS)
def test_source_identity_projection_accepts_512_astral_characters_without_truncation(
    field: str,
) -> None:
    value = {**IDENTITY, field: "\U0001f9ea" * 512}
    assert json.loads(project(value)) == value


@pytest.mark.parametrize("missing", tuple(IDENTITY))
def test_source_identity_projection_never_supplies_missing_fields(missing: str) -> None:
    value = {key: item for key, item in IDENTITY.items() if key != missing}
    with pytest.raises(ValueError):
        project(value)


@pytest.mark.parametrize("extra", ["artifact_kind", "schema_version", "digest", "signature"])
def test_source_identity_projection_never_strips_extra_fields(extra: str) -> None:
    with pytest.raises(ValueError):
        project({**IDENTITY, extra: "unaccepted"})


@pytest.mark.parametrize("field", COMPONENTS)
@pytest.mark.parametrize("invalid", [None, True, 1, 1.5, b"x", [], {}, "", "x" * 513])
def test_source_identity_projection_rejects_hostile_components_before_serialization(
    monkeypatch: pytest.MonkeyPatch, field: str, invalid: Any
) -> None:
    def forbidden(_: object) -> bytes:
        raise AssertionError("invalid identity reached serialization")

    monkeypatch.setattr(canonical_v1, "canonical_bytes", forbidden)
    with pytest.raises(ValueError):
        project({**IDENTITY, field: invalid})


@pytest.mark.parametrize("invalid", [None, True, "source-event-identity/v2", "x" * 513])
def test_source_identity_projection_requires_the_exact_contract_discriminator(invalid: Any) -> None:
    with pytest.raises(ValueError):
        project({**IDENTITY, "identity_contract_id": invalid})


@pytest.mark.parametrize("field", COMPONENTS)
@pytest.mark.parametrize("invalid", ["\ud800", "\udfff", "\ud83d\ude00"])
def test_source_identity_projection_rejects_invalid_unicode_before_serialization(
    monkeypatch: pytest.MonkeyPatch, field: str, invalid: str
) -> None:
    def forbidden(_: object) -> bytes:
        raise AssertionError("invalid Unicode reached serialization")

    monkeypatch.setattr(canonical_v1, "canonical_bytes", forbidden)
    with pytest.raises(ValueError, match="invalid Unicode"):
        project({**IDENTITY, field: invalid})


def test_source_identity_projection_requires_plain_json_objects_and_strings() -> None:
    class HostileDict(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise AssertionError("custom mapping behavior must never execute")

    class StringSubclass(str):
        pass

    subclass_key = {key: value for key, value in IDENTITY.items() if key != "event_id"}
    subclass_key[StringSubclass("event_id")] = "v"
    for invalid in (
        None,
        list(IDENTITY.items()),
        MappingProxyType(IDENTITY),
        HostileDict(IDENTITY),
        SourceEventIdentity.model_validate(IDENTITY),
        {**IDENTITY, "event_id": StringSubclass("v")},
        subclass_key,
    ):
        with pytest.raises(ValueError):
            project(invalid)
