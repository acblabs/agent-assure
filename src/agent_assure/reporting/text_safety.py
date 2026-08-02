from __future__ import annotations

import unicodedata

from agent_assure.privacy.redaction import redact_text


def sanitize_display_text(value: object) -> str:
    """Return redacted single-line text without Unicode control characters."""
    redacted = redact_text(str(value))
    without_controls = "".join(
        "" if unicodedata.category(character).startswith("C") else character
        for character in redacted
    )
    normalized = " ".join(without_controls.split())
    # Removing a control or format character can reassemble a sensitive value
    # that the first detector pass could not see.
    return redact_text(normalized)
