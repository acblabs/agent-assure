from __future__ import annotations

import typer

app = typer.Typer(help="Initialize project assets.")


@app.command("project")
def project() -> None:
    typer.echo("init project is reserved for a future release")
