"""Exact v1 projection bytes; no digest, writer registration or authority."""

from __future__ import annotations

from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.schema.v1_identity import SourceEventIdentity

_SOURCE_IDENTITY_FIELDS = (
    "identity_contract_id",
    "run_id",
    "producer_id",
    "producer_epoch",
    "event_id",
)


def source_event_identity_projection_bytes(value: object) -> bytes:
    """Validate a bounded plain JSON object and return its exact RFC 8785 bytes.

    ADR-V1-EVIDENCE and ADR-V1-SCHEMA require these five original fields without
    normalization or delimiter concatenation. These are projection bytes only;
    this function does not choose a digest domain or grant artifact eligibility.
    """
    if type(value) is not dict or len(value) != len(_SOURCE_IDENTITY_FIELDS):
        raise ValueError("source identity requires an exact five-field plain object")
    if any(type(key) is not str for key in value) or set(value) != set(_SOURCE_IDENTITY_FIELDS):
        raise ValueError("source identity contains missing or unknown field names")
    payload: dict[str, str] = {}
    for field in _SOURCE_IDENTITY_FIELDS:
        component = value[field]
        if type(component) is not str or not 1 <= len(component) <= 512:
            raise ValueError("source identity fields must be bounded nonempty plain strings")
        if any(0xD800 <= ord(character) <= 0xDFFF for character in component):
            raise ValueError("source identity contains invalid Unicode scalar values")
        payload[field] = component
    identity = SourceEventIdentity.model_validate(payload)
    return canonical_bytes(identity.model_dump(mode="json"))
