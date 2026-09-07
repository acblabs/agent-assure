from __future__ import annotations

from datetime import timedelta

import pytest

from agent_assure.timestamps import parse_rfc3339_timestamp


@pytest.mark.parametrize(
    ("value", "expected_offset"),
    (
        ("2026-09-05T12:34:56Z", timedelta(0)),
        ("2026-09-05T12:34:56.123456+05:30", timedelta(hours=5, minutes=30)),
        ("2026-09-05T12:34:56-04:00", -timedelta(hours=4)),
    ),
)
def test_strict_timestamp_accepts_z_and_explicit_offsets(
    value: str,
    expected_offset: timedelta,
) -> None:
    assert parse_rfc3339_timestamp(value, field_name="timestamp").utcoffset() == expected_offset


@pytest.mark.parametrize(
    "value",
    (
        "2026-09-05T12:34:56",
        "2026-02-30T12:34:56Z",
        "2026-09-05 12:34:56Z",
        "2026-09-05T12:34:56.0000001Z",
        "2026-09-05T12:34:56.1234567-04:00",
        "not-a-timestamp",
    ),
)
def test_strict_timestamp_rejects_missing_offsets_and_invalid_dates(value: str) -> None:
    with pytest.raises(ValueError, match="timestamp must be a valid RFC 3339 timestamp"):
        parse_rfc3339_timestamp(value, field_name="timestamp")
