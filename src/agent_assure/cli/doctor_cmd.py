from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agent_assure.onboarding.controls_mutation import (
    CONFIG_FILENAME,
    DEFAULT_SCAFFOLD_DIRECTORY,
    DiagnosticStatus,
    diagnose_controls_mutate,
)

app = typer.Typer(help="Run static, read-only workflow diagnostics.")


@app.callback()
def callback() -> None:
    """Diagnose local workflows without executing them."""


@app.command("controls-mutate")
def controls_mutate(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            help="Controls-mutation onboarding configuration YAML.",
        ),
    ] = DEFAULT_SCAFFOLD_DIRECTORY / CONFIG_FILENAME,
) -> None:
    """Check whether a controls-mutate workflow is ready to run offline."""
    report = diagnose_controls_mutate(config)
    for diagnostic in report.diagnostics:
        typer.echo(f"{diagnostic.status.value} {diagnostic.code}: {diagnostic.message}")
        if diagnostic.status is DiagnosticStatus.failed and diagnostic.action is not None:
            typer.echo(f"  action: {diagnostic.action}")
    if report.ready:
        typer.echo("controls-mutate doctor: ready (offline, static checks only)")
        return

    failed = sum(item.status is DiagnosticStatus.failed for item in report.diagnostics)
    skipped = sum(item.status is DiagnosticStatus.skipped for item in report.diagnostics)
    typer.echo(f"controls-mutate doctor: not ready ({failed} failed, {skipped} skipped; exit 2)")
    raise typer.Exit(report.exit_code)
