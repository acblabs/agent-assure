from __future__ import annotations

from io import StringIO
from types import SimpleNamespace

from rich.console import Console

from agent_assure.reporting.console import _console_text, _findings_table
from agent_assure.schema.common import GateState, ReasonCode


def test_console_text_redacts_and_renders_untrusted_text_literally() -> None:
    rendered = _console_text(
        "[bold red]literal[/]\x1b[31m\nspoof\u202e alice@example.com "
        "second@example\x00.com"
    )

    assert "[bold red]literal[/]" in rendered.plain
    assert "\x1b" not in rendered.plain
    assert "\n" not in rendered.plain
    assert "\u202e" not in rendered.plain
    assert "alice@example.com" not in rendered.plain
    assert "second@example.com" not in rendered.plain


def test_findings_table_cannot_inject_rich_markup_or_terminal_controls() -> None:
    finding = SimpleNamespace(
        case_id="[bold red]case[/]",
        control_id="evidence_provenance_identity",
        target="[/bogus]\x1b[31m\nforged-row",
        reason_code=ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
        state=GateState.fail,
        message="contact alice@example.com",
    )
    report = SimpleNamespace(
        candidate_vs_expectations=SimpleNamespace(findings=(finding,))
    )
    stream = StringIO()
    console = Console(
        file=stream,
        width=240,
        color_system=None,
        force_terminal=False,
    )

    console.print(_findings_table(report))

    output = stream.getvalue()
    assert "[bold red]case[/]" in output
    assert "[/bogus]" in output
    assert "\x1b" not in output
    assert "alice@example.com" not in output
    assert "forged-row" in output
