from __future__ import annotations

import typer

from agent_assure import __version__
from agent_assure.cli import (
    ci_cmd,
    compare_cmd,
    controls_cmd,
    demo_cmd,
    diff_cmd,
    doctor_cmd,
    evaluate_cmd,
    graph_cmd,
    init_cmd,
    live_cmd,
    otel_cmd,
    packet_cmd,
    rag_cmd,
    release_cmd,
    schema_cmd,
    stream_cmd,
    study_cmd,
    suite_cmd,
    validate_cmd,
)

app = typer.Typer(help="Expectation-driven assurance for deterministic AI agent pipelines.")
app.add_typer(init_cmd.app, name="init")
app.add_typer(doctor_cmd.app, name="doctor")
app.command(
    "validate",
    help="Validate one persisted artifact against its declared contract.",
)(validate_cmd.validate)
app.add_typer(schema_cmd.app, name="schema")
app.add_typer(suite_cmd.app, name="suite")
app.add_typer(demo_cmd.app, name="demo")
app.add_typer(diff_cmd.app, name="diff")
app.command(
    "evaluate",
    help="Evaluate a RunSet against a compiled assurance suite.",
)(evaluate_cmd.evaluate)
app.add_typer(graph_cmd.app, name="graph")
app.command(
    "compare",
    help="Compare baseline and candidate evaluation summaries.",
)(compare_cmd.compare)
app.command(
    "ci",
    help="Build and gate a reproducible CI evidence packet.",
)(ci_cmd.ci)
app.add_typer(controls_cmd.app, name="controls")
app.add_typer(live_cmd.app, name="live")
app.add_typer(packet_cmd.app, name="packet")
app.add_typer(rag_cmd.app, name="rag")
# Preserve the historical ``rag study`` route while making the preregistered
# study surface visible to users who reasonably look for it at the top level.
app.add_typer(study_cmd.app, name="study")
app.add_typer(release_cmd.app, name="release")
app.add_typer(otel_cmd.app, name="otel")
app.add_typer(stream_cmd.app, name="stream")


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
