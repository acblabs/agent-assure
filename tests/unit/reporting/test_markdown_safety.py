from __future__ import annotations

from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text


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
