"""Strict, timezone-aware timestamp parsing shared across trust boundaries."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Final

STRICT_RFC3339_TIMESTAMP_PATTERN: Final = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?"
    r"(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)


def parse_rfc3339_timestamp(value: str, *, field_name: str) -> datetime:
    """Parse RFC 3339 at exact microsecond precision with an explicit offset.

    Fractions beyond six digits are rejected instead of being silently truncated
    by :meth:`datetime.fromisoformat`, keeping trust-boundary ordering exact.
    """

    if not isinstance(value, str) or re.fullmatch(STRICT_RFC3339_TIMESTAMP_PATTERN, value) is None:
        raise ValueError(f"{field_name} must be a valid RFC 3339 timestamp with a UTC offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid RFC 3339 timestamp") from exc
    if parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return parsed


__all__ = [
    "STRICT_RFC3339_TIMESTAMP_PATTERN",
    "parse_rfc3339_timestamp",
]
