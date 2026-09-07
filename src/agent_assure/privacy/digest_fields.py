"""Canonical recognition of digest-bearing durable-artifact fields."""

from __future__ import annotations

import re
from typing import Final

DIGEST_FIELD_SUFFIXES: Final = ("_digest", "_digests", "_sha256")
_SHA256_HEX_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")


def is_digest_field_name(value: object) -> bool:
    """Return whether a field uses the shared digest vocabulary."""

    return isinstance(value, str) and value.endswith(DIGEST_FIELD_SUFFIXES)


def is_sha256_hex_digest(value: object) -> bool:
    """Return whether a value is one lowercase hexadecimal SHA-256 digest."""

    return isinstance(value, str) and _SHA256_HEX_PATTERN.fullmatch(value) is not None


__all__ = [
    "DIGEST_FIELD_SUFFIXES",
    "is_digest_field_name",
    "is_sha256_hex_digest",
]
