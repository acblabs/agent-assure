from __future__ import annotations

import unicodedata
from pathlib import Path

from agent_assure.privacy.redaction import redact_text

MAX_DIAGNOSTIC_CHARS = 512


def bounded_error(
    exc: BaseException,
    *,
    fallback: str = "bounded validation error",
) -> str:
    """Return one redacted, single-line, terminal-safe diagnostic summary."""
    return bounded_text(exc, fallback=fallback)


def bounded_text(
    value: object,
    *,
    fallback: str = "bounded diagnostic",
) -> str:
    """Return bounded terminal-safe text for a non-path diagnostic value."""

    return _safe_summary(str(value), fallback=fallback)


def display_path(path: Path) -> str:
    """Return a redacted, single-line, terminal-safe display path."""
    return bounded_text(path, fallback="<local-path>")


def _safe_summary(value: str, *, fallback: str) -> str:
    # Strip controls before the final detector pass. A format character can split
    # a sensitive token during the first scan and its removal can reconstruct the
    # token (for example an SSN containing a bidi override).
    without_controls = "".join(
        (
            " "
            if character.isspace()
            else ""
            if unicodedata.category(character).startswith("C")
            else character
        )
        for character in value
    )
    normalized = " ".join(without_controls.split())
    redacted = redact_text(normalized)
    return (redacted or fallback)[:MAX_DIAGNOSTIC_CHARS]
