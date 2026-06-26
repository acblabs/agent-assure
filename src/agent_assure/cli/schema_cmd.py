from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.schema.export import export_json_schemas

app = typer.Typer(help="JSON Schema utilities.")
console = Console()


@app.command("export")
def export(out: Annotated[Path, typer.Option("--out", help="Output directory.")]) -> None:
    written = export_json_schemas(out)
    for path in written:
        console.print(str(path))
