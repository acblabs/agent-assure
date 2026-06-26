from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.schema.validation import validate_artifact

console = Console()


def validate(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    kind: Annotated[str, typer.Option("--kind", help="Artifact kind to validate.")],
) -> None:
    validator = validate_artifact(path, kind)
    console.print(f"valid {kind}: {path} (validator={validator})")
