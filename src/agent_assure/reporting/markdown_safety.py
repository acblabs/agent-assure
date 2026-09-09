from __future__ import annotations

import html

from agent_assure.reporting.text_safety import sanitize_display_text

_MARKDOWN_SPECIAL_CHARS = frozenset("\\`*_{}[]!|<>")


def markdown_text(value: object) -> str:
    """Redact and escape text before placing it in Markdown prose."""
    text = sanitize_display_text(value)
    return "".join(_escape_markdown_char(char) for char in text)


def markdown_code(value: object) -> str:
    """Redact text for inline code spans without allowing span breakout."""
    text = sanitize_display_text(value)
    return text.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def markdown_code_span(value: object) -> str:
    text = sanitize_display_text(value)
    if "|" in text:
        # CommonMark table parsing is not consistently code-span-aware. Use a
        # safe HTML code element only for values containing a cell delimiter;
        # the entity preserves the displayed pipe without leaving a literal
        # delimiter in the Markdown source.
        escaped = html.escape(text, quote=True).replace("|", "&#124;")
        return f"<code>{escaped}</code>"
    return f"`{markdown_code(text)}`"


def _escape_markdown_char(char: str) -> str:
    if char == "<":
        return "&lt;"
    if char == ">":
        return "&gt;"
    if char in _MARKDOWN_SPECIAL_CHARS:
        return "\\" + char
    return char
