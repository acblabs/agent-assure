from __future__ import annotations

from agent_assure.privacy.redaction import redact_text

_MARKDOWN_SPECIAL_CHARS = frozenset("\\`*_{}[]!|<>")


def markdown_text(value: object) -> str:
    """Redact and escape text before placing it in Markdown prose."""
    text = " ".join(redact_text(str(value)).split())
    return "".join(_escape_markdown_char(char) for char in text)


def markdown_code(value: object) -> str:
    """Redact text for inline code spans without allowing span breakout."""
    text = " ".join(redact_text(str(value)).split())
    return (
        text.replace("`", "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def markdown_code_span(value: object) -> str:
    return f"`{markdown_code(value)}`"


def _escape_markdown_char(char: str) -> str:
    if char == "<":
        return "&lt;"
    if char == ">":
        return "&gt;"
    if char in _MARKDOWN_SPECIAL_CHARS:
        return "\\" + char
    return char
