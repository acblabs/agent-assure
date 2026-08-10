from __future__ import annotations

from pathlib import Path

from agent_assure.privacy.redaction import redact_text

MAX_DIAGNOSTIC_CHARS = 512


def bounded_error(
    exc: BaseException,
    *,
    fallback: str = "bounded validation error",
) -> str:
    """Return one redacted, single-line, terminal-safe diagnostic summary."""
    return _safe_summary(str(exc), fallback=fallback)


def display_path(path: Path) -> str:
    """Return a redacted, single-line, terminal-safe display path."""
    return _safe_summary(str(path), fallback="<local-path>")


def _safe_summary(value: str, *, fallback: str) -> str:
    normalized = " ".join(redact_text(value).split())
    printable = "".join(character for character in normalized if character.isprintable())
    return (printable or fallback)[:MAX_DIAGNOSTIC_CHARS]
