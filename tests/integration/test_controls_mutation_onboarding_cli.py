from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from agent_assure.cli import controls_cmd
from agent_assure.onboarding.controls_mutation import (
    CONFIG_FILENAME,
    scaffold_controls_mutation,
)

_RUNNER = CliRunner()


def test_generated_assets_run_as_an_offline_core_catalog_mutation(tmp_path: Path) -> None:
    out = tmp_path / "quickstart"
    scaffold_controls_mutation(out)
    mutation_out = out / "mutation-results"

    result = _RUNNER.invoke(
        controls_cmd.app,
        [
            "mutate",
            "--suite",
            str(out / "suite.yaml"),
            "--runset",
            str(out / "runset.json"),
            "--catalog",
            "core/v1",
            "--operator",
            "drop-material-evidence-link",
            "--out",
            str(mutation_out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "state=caught" in result.output
    assert (mutation_out / "assurance-mutation-campaign.json").is_file()
    assert (out / CONFIG_FILENAME).is_file()

    efficacy = _RUNNER.invoke(
        controls_cmd.app,
        ["efficacy", "--config", str(out / CONFIG_FILENAME)],
    )

    assert efficacy.exit_code == 0, efficacy.output
    assert "control efficacy gate state: pass" in efficacy.output
    assert (out / "control-efficacy" / "control-efficacy-report.json").is_file()
