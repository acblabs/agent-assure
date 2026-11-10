from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.export import SchemaExportError, export_json_schemas

app = typer.Typer(help="JSON Schema utilities.")
console = Console(markup=False)


@app.command("export")
def export(
    out: Annotated[Path, typer.Option("--out", help="Output directory.")],
    writer_schema_version: Annotated[
        str,
        typer.Option(
            "--writer-schema-version",
            help="Exact writer version. The v1 writer requires its complete contract set.",
        ),
    ] = SCHEMA_VERSION,
) -> None:
    try:
        written = export_json_schemas(out, writer_schema_version=writer_schema_version)
    except SchemaExportError as exc:
        typer.echo(f"Schema export unavailable: {exc}", err=True)
        raise typer.Exit(code=2) from None
    for path in written:
        console.print(str(path))
