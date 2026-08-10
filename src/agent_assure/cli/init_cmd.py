from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agent_assure.onboarding.controls_mutation import (
    CONFIG_FILENAME,
    DEFAULT_ONBOARDING_OPERATOR_ID,
    DEFAULT_SCAFFOLD_DIRECTORY,
    MUTATION_OUTPUT_DIRECTORY,
    RUNSET_FILENAME,
    SUITE_FILENAME,
    ScaffoldConflictError,
    scaffold_controls_mutation,
)
from agent_assure.onboarding.diagnostics import (
    bounded_error as _bounded_error,
)
from agent_assure.onboarding.diagnostics import (
    display_path as _display_path,
)

app = typer.Typer(help="Initialize project assets.")


@app.command("controls-mutation")
def controls_mutation(
    out_dir: Annotated[
        Path,
        typer.Option(
            "--out-dir",
            file_okay=False,
            help="Directory for the offline controls-mutation quickstart.",
        ),
    ] = DEFAULT_SCAFFOLD_DIRECTORY,
) -> None:
    """Create a minimal, deterministic controls-mutation workflow."""
    try:
        result = scaffold_controls_mutation(out_dir)
    except ScaffoldConflictError as exc:
        typer.echo(f"controls-mutation scaffold conflict: {_bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except (OSError, TypeError, ValueError) as exc:
        typer.echo(f"controls-mutation scaffold error: {_bounded_error(exc)}")
        raise typer.Exit(2) from exc

    directory = _display_path(result.directory)
    if result.status == "created":
        typer.echo(f"controls-mutation scaffold created: {directory}")
    else:
        typer.echo(f"controls-mutation scaffold unchanged: {directory}")
    for path in result.paths:
        typer.echo(f"scaffold asset: {_display_path(path)}")
    typer.echo(
        "next: agent-assure doctor controls-mutate --config "
        f'"{_display_path(result.directory / CONFIG_FILENAME)}"'
    )
    typer.echo(
        "run: agent-assure controls mutate "
        f'--suite "{_display_path(result.directory / SUITE_FILENAME)}" '
        f'--runset "{_display_path(result.directory / RUNSET_FILENAME)}" '
        f"--catalog core/v1 --operator {DEFAULT_ONBOARDING_OPERATOR_ID} "
        f'--out "{_display_path(result.directory / MUTATION_OUTPUT_DIRECTORY)}"'
    )
    typer.echo(
        "then: agent-assure controls efficacy --config "
        f'"{_display_path(result.directory / CONFIG_FILENAME)}"'
    )


@app.command("project")
def project() -> None:
    typer.echo("init project is reserved for a future release")
