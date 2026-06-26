from __future__ import annotations

import typer

from agent_assure import __version__
from agent_assure.cli import (
    ci_cmd,
    compare_cmd,
    evaluate_cmd,
    init_cmd,
    otel_cmd,
    packet_cmd,
    schema_cmd,
    suite_cmd,
    validate_cmd,
)

app = typer.Typer(help="Expectation-driven assurance for deterministic AI agent pipelines.")
app.add_typer(init_cmd.app, name="init")
app.command("validate")(validate_cmd.validate)
app.add_typer(schema_cmd.app, name="schema")
app.add_typer(suite_cmd.app, name="suite")
app.command("evaluate")(evaluate_cmd.evaluate)
app.command("compare")(compare_cmd.compare)
app.add_typer(ci_cmd.app, name="ci")
app.add_typer(packet_cmd.app, name="packet")
app.add_typer(otel_cmd.app, name="otel")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Run agent-assure commands."""


if __name__ == "__main__":
    app()
