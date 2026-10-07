from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml
from yaml.nodes import MappingNode  # type: ignore[import-untyped]

from agent_assure.source_layout import source_checkout_component

MITRE_ATLAS_2026_06_RELEASE = "2026.06"
MITRE_ATLAS_2026_06_CATALOG_FILENAME = "mitre_atlas_2026_06_catalog.yaml"
MITRE_ATLAS_2026_06_CATALOG_SHA256 = (
    "792658d4fd3693ef926dd918220d40c90e77dcf5c6f749390584588c57d340bf"
)
_EXPECTED_SOURCE = (
    "https://github.com/mitre-atlas/atlas-data/releases/download/v2026.06/ATLAS-2026.06.yaml"
)
_EXPECTED_UPSTREAM_REPOSITORY = "https://github.com/mitre-atlas/atlas-data"
_EXPECTED_UPSTREAM_RELEASE_TAG = "v2026.06"
_EXPECTED_UPSTREAM_COMMIT = "651dad90d3c007e797c89356fa1f4d8732f90c8d"
_EXPECTED_UPSTREAM_ASSET_SHA256 = "b771de8b1489564b2838a709c7429849a9575dbd94073928817fe1a21661e70a"
_EXPECTED_RELEASE_DATE = "2026-06-30"
_EXPECTED_ARTIFACT_MODIFIED_DATE = "2026-05-27"
_EXPECTED_FORMAT_VERSION = "6.0.0"
_EXPECTED_RELEASE_ANNOUNCEMENT_TACTIC_COUNT = 16
_EXPECTED_RELEASE_ANNOUNCEMENT_TECHNIQUE_COUNT = 104
_EXPECTED_RELEASE_ANNOUNCEMENT_SUB_TECHNIQUE_COUNT = 69
_EXPECTED_VERIFIED_TACTIC_COUNT = 16
_EXPECTED_VERIFIED_BASE_TECHNIQUE_COUNT = 103
_EXPECTED_VERIFIED_SUB_TECHNIQUE_COUNT = 70
_EXPECTED_CATALOG_TECHNIQUE_ID_COUNT = 173
_CATALOG_KEYS = frozenset(
    {
        "source",
        "upstream_repository",
        "upstream_release_tag",
        "upstream_commit",
        "upstream_asset_sha256",
        "release",
        "release_date",
        "artifact_modified_date",
        "format_version",
        "release_announcement_tactic_count",
        "release_announcement_technique_count",
        "release_announcement_sub_technique_count",
        "verified_tactic_count",
        "verified_base_technique_count",
        "verified_sub_technique_count",
        "catalog_technique_id_count",
        "tactics",
        "techniques",
    }
)
_TACTIC_ID_PATTERN = re.compile(r"AML\.TA[0-9]{4}\Z")
_TECHNIQUE_ID_PATTERN = re.compile(r"AML\.T[0-9]{4}(?:\.[0-9]{3})?\Z")
_SUB_TECHNIQUE_ID_PATTERN = re.compile(r"AML\.T[0-9]{4}\.[0-9]{3}\Z")


class _UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Safe YAML loader that refuses silent duplicate-key replacement."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ValueError("MITRE ATLAS catalog contains an unhashable mapping key") from exc
        if duplicate:
            raise ValueError(f"MITRE ATLAS catalog contains duplicate key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class MitreAtlasCatalog:
    release: str
    tactic_ids: frozenset[str]
    technique_ids: frozenset[str]
    tactic_names: Mapping[str, str]
    technique_names: Mapping[str, str]
    digest: str
    source: str
    upstream_source: str
    upstream_repository: str
    upstream_release_tag: str
    upstream_commit: str
    upstream_asset_sha256: str
    release_announcement_tactic_count: int
    release_announcement_technique_count: int
    release_announcement_sub_technique_count: int
    verified_tactic_count: int
    verified_base_technique_count: int
    verified_sub_technique_count: int


@lru_cache(maxsize=1)
def load_mitre_atlas_2026_06_catalog() -> MitreAtlasCatalog:
    """Load and authenticate the production-packaged offline ATLAS catalog."""

    payload, source = _catalog_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != MITRE_ATLAS_2026_06_CATALOG_SHA256:
        raise ValueError(
            "MITRE ATLAS 2026.06 catalog digest does not match the pinned production digest"
        )
    loaded = yaml.load(payload.decode("utf-8"), Loader=_UniqueKeySafeLoader)
    if not isinstance(loaded, dict):
        raise ValueError("MITRE ATLAS 2026.06 catalog must contain a YAML object")
    data: dict[str, Any] = loaded
    if set(data) != _CATALOG_KEYS:
        raise ValueError("MITRE ATLAS 2026.06 catalog metadata fields do not match the pin")
    expected_metadata = {
        "source": _EXPECTED_SOURCE,
        "upstream_repository": _EXPECTED_UPSTREAM_REPOSITORY,
        "upstream_release_tag": _EXPECTED_UPSTREAM_RELEASE_TAG,
        "upstream_commit": _EXPECTED_UPSTREAM_COMMIT,
        "upstream_asset_sha256": _EXPECTED_UPSTREAM_ASSET_SHA256,
        "release": MITRE_ATLAS_2026_06_RELEASE,
        "release_date": _EXPECTED_RELEASE_DATE,
        "artifact_modified_date": _EXPECTED_ARTIFACT_MODIFIED_DATE,
        "format_version": _EXPECTED_FORMAT_VERSION,
        "release_announcement_tactic_count": (_EXPECTED_RELEASE_ANNOUNCEMENT_TACTIC_COUNT),
        "release_announcement_technique_count": (_EXPECTED_RELEASE_ANNOUNCEMENT_TECHNIQUE_COUNT),
        "release_announcement_sub_technique_count": (
            _EXPECTED_RELEASE_ANNOUNCEMENT_SUB_TECHNIQUE_COUNT
        ),
        "verified_tactic_count": _EXPECTED_VERIFIED_TACTIC_COUNT,
        "verified_base_technique_count": _EXPECTED_VERIFIED_BASE_TECHNIQUE_COUNT,
        "verified_sub_technique_count": _EXPECTED_VERIFIED_SUB_TECHNIQUE_COUNT,
        "catalog_technique_id_count": _EXPECTED_CATALOG_TECHNIQUE_ID_COUNT,
    }
    for field_name, expected in expected_metadata.items():
        if data[field_name] != expected:
            raise ValueError(f"MITRE ATLAS 2026.06 catalog {field_name} does not match the pin")
    tactic_names = _validated_identifier_name_map(
        data["tactics"],
        owner="tactic",
        pattern=_TACTIC_ID_PATTERN,
    )
    technique_names = _validated_identifier_name_map(
        data["techniques"],
        owner="technique",
        pattern=_TECHNIQUE_ID_PATTERN,
    )
    tactic_ids = frozenset(tactic_names)
    technique_ids = frozenset(technique_names)
    if len(tactic_ids) != _EXPECTED_VERIFIED_TACTIC_COUNT:
        raise ValueError("MITRE ATLAS 2026.06 tactic catalog count does not match the pin")
    if len(technique_ids) != _EXPECTED_CATALOG_TECHNIQUE_ID_COUNT:
        raise ValueError("MITRE ATLAS 2026.06 technique catalog count does not match the pin")
    sub_technique_count = sum(
        _SUB_TECHNIQUE_ID_PATTERN.fullmatch(identifier) is not None for identifier in technique_ids
    )
    base_technique_count = len(technique_ids) - sub_technique_count
    if base_technique_count != _EXPECTED_VERIFIED_BASE_TECHNIQUE_COUNT:
        raise ValueError("MITRE ATLAS 2026.06 base technique count does not match the pin")
    if sub_technique_count != _EXPECTED_VERIFIED_SUB_TECHNIQUE_COUNT:
        raise ValueError("MITRE ATLAS 2026.06 sub-technique count does not match the pin")
    return MitreAtlasCatalog(
        release=MITRE_ATLAS_2026_06_RELEASE,
        tactic_ids=tactic_ids,
        technique_ids=technique_ids,
        tactic_names=MappingProxyType(tactic_names),
        technique_names=MappingProxyType(technique_names),
        digest=digest,
        source=source,
        upstream_source=_EXPECTED_SOURCE,
        upstream_repository=_EXPECTED_UPSTREAM_REPOSITORY,
        upstream_release_tag=_EXPECTED_UPSTREAM_RELEASE_TAG,
        upstream_commit=_EXPECTED_UPSTREAM_COMMIT,
        upstream_asset_sha256=_EXPECTED_UPSTREAM_ASSET_SHA256,
        release_announcement_tactic_count=_EXPECTED_RELEASE_ANNOUNCEMENT_TACTIC_COUNT,
        release_announcement_technique_count=(_EXPECTED_RELEASE_ANNOUNCEMENT_TECHNIQUE_COUNT),
        release_announcement_sub_technique_count=(
            _EXPECTED_RELEASE_ANNOUNCEMENT_SUB_TECHNIQUE_COUNT
        ),
        verified_tactic_count=_EXPECTED_VERIFIED_TACTIC_COUNT,
        verified_base_technique_count=_EXPECTED_VERIFIED_BASE_TECHNIQUE_COUNT,
        verified_sub_technique_count=_EXPECTED_VERIFIED_SUB_TECHNIQUE_COUNT,
    )


def _validated_identifier_name_map(
    value: object,
    *,
    owner: str,
    pattern: re.Pattern[str],
) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"MITRE ATLAS 2026.06 {owner} catalog must be a non-empty object")
    names: dict[str, str] = {}
    for identifier, name in value.items():
        if not isinstance(identifier, str) or pattern.fullmatch(identifier) is None:
            raise ValueError(
                f"MITRE ATLAS 2026.06 {owner} catalog contains invalid identifier {identifier!r}"
            )
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"MITRE ATLAS 2026.06 {owner} {identifier!r} has an invalid name")
        names[identifier] = name
    identifiers = list(names)
    if identifiers != sorted(identifiers):
        raise ValueError(
            f"MITRE ATLAS 2026.06 {owner} identifiers must be lexicographically ordered"
        )
    return names


def _catalog_bytes() -> tuple[bytes, str]:
    packaged_source = f"agent_assure/mappings/{MITRE_ATLAS_2026_06_CATALOG_FILENAME}"
    try:
        resource = resources.files("agent_assure").joinpath(
            "mappings",
            MITRE_ATLAS_2026_06_CATALOG_FILENAME,
        )
        return resource.read_bytes(), packaged_source
    except (FileNotFoundError, ModuleNotFoundError, NotADirectoryError) as resource_exc:
        checkout_path = source_checkout_component(
            __file__,
            f"mappings/{MITRE_ATLAS_2026_06_CATALOG_FILENAME}",
        )
        if checkout_path is not None and checkout_path.is_file():
            return checkout_path.read_bytes(), str(checkout_path)
        raise FileNotFoundError(
            "production MITRE ATLAS 2026.06 catalog resource is unavailable"
        ) from resource_exc


def production_catalog_path() -> Path | None:
    """Return the source-checkout path for release/build verification, if present."""

    return source_checkout_component(
        __file__,
        f"mappings/{MITRE_ATLAS_2026_06_CATALOG_FILENAME}",
    )


__all__ = [
    "MITRE_ATLAS_2026_06_CATALOG_FILENAME",
    "MITRE_ATLAS_2026_06_CATALOG_SHA256",
    "MITRE_ATLAS_2026_06_RELEASE",
    "MitreAtlasCatalog",
    "load_mitre_atlas_2026_06_catalog",
    "production_catalog_path",
]
