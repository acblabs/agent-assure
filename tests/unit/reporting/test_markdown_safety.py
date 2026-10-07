from __future__ import annotations

import pytest

from agent_assure.reporting.markdown_safety import (
    markdown_code_span,
    markdown_sha256_code_span,
    markdown_text,
)


def test_markdown_text_escapes_links_html_and_newlines() -> None:
    rendered = markdown_text("[click](https://evil.test)\n<script>alert(1)</script>")

    assert "\n" not in rendered
    assert "[click](" not in rendered
    assert "<script>" not in rendered
    assert "\\[click\\]" in rendered
    assert "&lt;script&gt;" in rendered


def test_markdown_code_span_escapes_backticks_and_html() -> None:
    rendered = markdown_code_span("`breakout` <script>")

    assert rendered == "`'breakout' &lt;script&gt;`"


def test_markdown_code_span_cannot_break_out_of_a_table_cell() -> None:
    rendered = markdown_code_span("left | right <unsafe>")

    assert rendered == "<code>left &#124; right &lt;unsafe&gt;</code>"
    assert "|" not in rendered


def test_markdown_sha256_code_span_preserves_valid_card_shaped_digest() -> None:
    digest = "cd18620ee20204105499754aa35d7ff45d9c37483cfb06df8ab3b461571d7993"

    assert markdown_code_span(digest) == (
        "`cd18620ee[REDACTED]aa35d7ff45d9c37483cfb06df8ab3b461571d7993`"
    )
    assert markdown_sha256_code_span(digest) == f"`{digest}`"


def test_markdown_sha256_code_span_fails_closed_for_invalid_value() -> None:
    with pytest.raises(ValueError, match="lowercase 64-character hex"):
        markdown_sha256_code_span("A" * 64)
    assert markdown_sha256_code_span(None) == "`not_recorded`"


def test_markdown_rendering_preserves_ordinary_escaping() -> None:
    assert markdown_text("ordinary *safe* text") == "ordinary \\*safe\\* text"


def test_markdown_rendering_removes_controls_and_reredacts() -> None:
    rendered = markdown_text("[safe]\x1b[31m\x9b2J\u202e contact second@example\x00.com")

    assert rendered.startswith("\\[safe\\]\\[31m2J contact ")
    assert "\x1b" not in rendered
    assert "\x9b" not in rendered
    assert "\u202e" not in rendered
    assert "second@example.com" not in rendered
