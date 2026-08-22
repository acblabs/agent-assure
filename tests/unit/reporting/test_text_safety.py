from __future__ import annotations

import unicodedata

from agent_assure.reporting.text_safety import sanitize_display_text


def test_display_text_removes_terminal_and_bidi_controls() -> None:
    rendered = sanitize_display_text("prefix\x1b[31mred\x9b2J\u202espoof\u2066tail\nnext")

    assert "\x1b" not in rendered
    assert "\x9b" not in rendered
    assert "\u202e" not in rendered
    assert "\u2066" not in rendered
    assert "\n" not in rendered
    assert not any(unicodedata.category(character).startswith("C") for character in rendered)


def test_display_text_reredacts_secret_reassembled_after_control_removal() -> None:
    rendered = sanitize_display_text("contact second@example\x00.com")

    assert rendered == "contact [REDACTED]"
    assert "second@example.com" not in rendered
    assert "second@example" not in rendered


def test_display_text_over_limit_still_fails_closed_before_normalization() -> None:
    rendered = sanitize_display_text("\x00" * 16_385)

    assert rendered == "[REDACTED]"
