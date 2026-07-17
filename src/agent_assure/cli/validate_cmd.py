from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from rich.console import Console

from agent_assure.schema.validation import validate_artifact

console = Console()


def validate(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    kind: Annotated[str, typer.Option("--kind", help="Artifact kind to validate.")],
) -> None:
    try:
        validator = validate_artifact(path, kind)
    except (JsonSchemaValidationError, KeyError, TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"valid {kind}: {path} (validator={validator})")
