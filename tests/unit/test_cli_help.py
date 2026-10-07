from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_assure.cli.main import app

_RUNNER = CliRunner()
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "module_name",
    (
        "agent_assure.cli.compare_cmd",
        "agent_assure.cli.demo_cmd",
        "agent_assure.cli.diff_cmd",
        "agent_assure.cli.evaluate_cmd",
        "agent_assure.cli.live_cmd",
        "agent_assure.cli.otel_cmd",
        "agent_assure.cli.release_cmd",
        "agent_assure.cli.schema_cmd",
        "agent_assure.cli.stream_cmd",
        "agent_assure.cli.suite_cmd",
        "agent_assure.cli.validate_cmd",
    ),
)
def test_cli_consoles_never_interpret_untrusted_rich_markup(module_name: str) -> None:
    module = importlib.import_module(module_name)

    with module.console.capture() as capture:
        module.console.print("[bold]untrusted[/bold]")

    assert capture.get() == "[bold]untrusted[/bold]\n"


def test_top_level_help_describes_direct_commands_and_study_surface() -> None:
    result = _RUNNER.invoke(app, ["--help"])

    assert result.exit_code == 0, result.output
    for description in (
        "Validate one persisted artifact against its declared contract.",
        "Evaluate a RunSet against a compiled assurance suite.",
        "Compare baseline and candidate evaluation summaries.",
        "Build and gate a reproducible CI evidence packet.",
        "Preregistered real-model study authoring and offline analysis.",
    ):
        assert description in result.output


def test_study_is_available_at_top_level_and_under_historical_rag_route() -> None:
    for command in (["study", "--help"], ["rag", "study", "--help"]):
        result = _RUNNER.invoke(app, command)

        assert result.exit_code == 0, result.output
        assert "Preregistered real-model study authoring" in result.output


def test_cli_bad_parameters_never_forward_raw_exception_strings() -> None:
    for source_path in sorted((ROOT / "src" / "agent_assure" / "cli").glob("*.py")):
        source = source_path.read_text(encoding="utf-8")
        assert "typer.BadParameter(str(" not in source, source_path.name
