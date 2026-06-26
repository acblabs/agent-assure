from __future__ import annotations

from agent_assure.privacy.redaction import redact_text


def safe_attribute(value: str) -> str:
    return redact_text(value)
