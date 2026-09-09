from __future__ import annotations

from typer.testing import CliRunner

from agent_assure.cli.main import app

_RUNNER = CliRunner()


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
