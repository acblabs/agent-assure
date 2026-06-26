from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_assure.privacy.detectors import SENSITIVE_PATTERNS

REDACTION = "[REDACTED]"
RUN_RECORD_SUMMARY_FIELDS = ("input_summary", "output_summary")


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub(REDACTION, redacted)
    return redacted


def redact_run_record_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    for field_name in RUN_RECORD_SUMMARY_FIELDS:
        value = redacted.get(field_name)
        if isinstance(value, str):
            redacted[field_name] = redact_text(value)
    return redacted
