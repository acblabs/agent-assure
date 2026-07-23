from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

import typer
from jsonschema.exceptions import (
    SchemaError as JsonSchemaSchemaError,
)
from jsonschema.exceptions import (
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError as PydanticValidationError
from rich.console import Console

from agent_assure.privacy.redaction import redact_text
from agent_assure.schema.validation import validate_artifact

console = Console()
MAX_VALIDATION_ERROR_CHARS = 500
_BAD_PARAMETER_PREFIX_ALLOWANCE = 32
_SAFE_RULE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def validate(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    kind: Annotated[str, typer.Option("--kind", help="Artifact kind to validate.")],
) -> None:
    try:
        validator = validate_artifact(path, kind)
    except (
        JsonSchemaSchemaError,
        JsonSchemaValidationError,
        KeyError,
        PydanticValidationError,
        TypeError,
        ValueError,
    ) as exc:
        raise typer.BadParameter(_safe_validation_error(exc)) from exc
    console.print(f"valid {kind}: {path} (validator={validator})")


def _safe_validation_error(exc: BaseException) -> str:
    if isinstance(exc, JsonSchemaSchemaError):
        message = "artifact validator schema is invalid"
    elif isinstance(exc, JsonSchemaValidationError):
        raw_rule = exc.validator
        rule = (
            raw_rule
            if isinstance(raw_rule, str) and _SAFE_RULE_NAME.fullmatch(raw_rule)
            else "unknown"
        )
        message = f"artifact failed JSON Schema validation (rule={rule})"
    elif isinstance(exc, PydanticValidationError):
        error_types = sorted(
            {
                str(error.get("type", "validation_error"))
                for error in exc.errors(
                    include_url=False, include_context=False, include_input=False
                )
                if _SAFE_RULE_NAME.fullmatch(str(error.get("type", "validation_error")))
            }
        )
        suffix = ",".join(error_types[:8]) or "validation_error"
        message = f"artifact failed model validation ({exc.error_count()} error(s); types={suffix})"
    else:
        message = redact_text(str(exc)[:4096]) or "artifact validation failed"
    return message[: MAX_VALIDATION_ERROR_CHARS - _BAD_PARAMETER_PREFIX_ALLOWANCE]
