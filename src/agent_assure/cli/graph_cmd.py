from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from agent_assure.reporting.graph import load_evidence_graph

app = typer.Typer(help="Validate and inspect canonical assurance evidence graphs.")


@app.callback()
def callback() -> None:
    """Inspect AssuranceEvidenceGraph/v1 artifacts without changing them."""


@app.command("validate")
def validate(
    graph: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, help="Assurance evidence graph JSON."),
    ],
) -> None:
    try:
        loaded = load_evidence_graph(graph)
    except (OSError, UnicodeError, ValueError) as exc:
        raise typer.BadParameter("assurance evidence graph validation failed") from exc
    typer.echo(f"valid assurance-evidence-graph {loaded.contract_id} {loaded.graph_digest}")


@app.command("digest")
def digest(
    graph: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, help="Assurance evidence graph JSON."),
    ],
) -> None:
    try:
        loaded = load_evidence_graph(graph)
    except (OSError, UnicodeError, ValueError) as exc:
        raise typer.BadParameter("assurance evidence graph validation failed") from exc
    typer.echo(loaded.graph_digest)
