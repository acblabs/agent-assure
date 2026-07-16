from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from typing import Annotated, Any, TypeAlias

from pydantic import Field
from pydantic.json_schema import SkipJsonSchema

from agent_assure.schema.base import SCHEMA_VERSION, SchemaVersion
from agent_assure.schema.common import DigestHex

PrivacyProfileId: TypeAlias = Annotated[str, Field(min_length=1)] | SkipJsonSchema[None]
PrivacyProfileDigest: TypeAlias = DigestHex | SkipJsonSchema[None]

_PRIVACY_PROFILE_FIELDS = ("privacy_profile_id", "privacy_profile_digest")


def privacy_profile_json_schema_extra(
    base_extra: Mapping[str, Any] | None = None,
) -> Callable[[dict[str, Any]], None]:
    """Require the profile pair only for current-version JSON artifacts."""

    def update_schema(schema: dict[str, Any]) -> None:
        required = schema.get("required")
        if isinstance(required, list):
            schema["required"] = [
                field_name
                for field_name in required
                if field_name not in _PRIVACY_PROFILE_FIELDS
            ]
        if base_extra is not None:
            for key, value in base_extra.items():
                if key == "allOf":
                    schema.setdefault("allOf", []).extend(deepcopy(value))
                else:
                    schema[key] = deepcopy(value)
        schema.setdefault("allOf", []).append(
            {
                "if": {
                    "anyOf": [
                        {"not": {"required": ["schema_version"]}},
                        {
                            "required": ["schema_version"],
                            "properties": {
                                "schema_version": {"const": SCHEMA_VERSION}
                            },
                        },
                    ]
                },
                "then": {"required": list(_PRIVACY_PROFILE_FIELDS)},
                "else": {
                    "not": {
                        "anyOf": [
                            {"required": [field_name]}
                            for field_name in _PRIVACY_PROFILE_FIELDS
                        ]
                    }
                },
            }
        )

    return update_schema


def prepare_privacy_profile_input(value: Any, *, owner: str) -> Any:
    """Inject runtime-only nulls for legacy artifacts without changing their schemas."""
    if not isinstance(value, Mapping):
        return value
    schema_version = value.get("schema_version", SCHEMA_VERSION)
    if schema_version == SCHEMA_VERSION:
        return value
    supplied = [field_name for field_name in _PRIVACY_PROFILE_FIELDS if field_name in value]
    if supplied:
        raise ValueError(
            f"{owner} schema version {schema_version!r} does not support: "
            + ", ".join(supplied)
        )
    prepared = dict(value)
    prepared.update({field_name: None for field_name in _PRIVACY_PROFILE_FIELDS})
    return prepared


def validate_privacy_profile_binding(
    schema_version: SchemaVersion,
    privacy_profile_id: str | None,
    privacy_profile_digest: str | None,
    *,
    owner: str,
) -> None:
    if schema_version == SCHEMA_VERSION:
        missing = [
            field_name
            for field_name, field_value in (
                ("privacy_profile_id", privacy_profile_id),
                ("privacy_profile_digest", privacy_profile_digest),
            )
            if field_value is None
        ]
        if missing:
            raise ValueError(f"{owner} requires: " + ", ".join(missing))
        return
    if privacy_profile_id is not None or privacy_profile_digest is not None:
        raise ValueError(
            f"{owner} schema version {schema_version!r} cannot bind a privacy profile"
        )
