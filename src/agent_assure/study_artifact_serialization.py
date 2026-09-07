"""Canonical byte representation for published study model artifacts."""

from __future__ import annotations

import json

from pydantic import BaseModel


def published_model_json_bytes(model: BaseModel) -> bytes:
    """Return the one canonical human-readable JSON encoding used in bundles."""

    payload = model.model_dump(mode="json", warnings="error")
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def require_published_model_json_bytes(
    supplied: bytes | None,
    model: BaseModel,
    *,
    label: str,
) -> bytes:
    """Accept omitted bytes or require exact correspondence to the supplied model."""

    expected = published_model_json_bytes(model)
    if supplied is None:
        return expected
    if not isinstance(supplied, bytes) or supplied != expected:
        raise ValueError(f"{label} bytes do not exactly encode the supplied model")
    return supplied


__all__ = [
    "published_model_json_bytes",
    "require_published_model_json_bytes",
]
