from __future__ import annotations

from pathlib import Path

import pytest
import typer
from jsonschema import ValidationError as JsonSchemaValidationError

from agent_assure.cli import validate_cmd
from agent_assure.cli.validate_cmd import MAX_VALIDATION_ERROR_CHARS, validate
from agent_assure.io_limits import MAX_JSON_DEPTH


def test_validate_reports_over_depth_json_as_bad_parameter(tmp_path: Path) -> None:
    path = tmp_path / "artifact.json"
    path.write_text("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))

    with pytest.raises(typer.BadParameter, match="exceeds maximum supported nesting depth"):
        validate(path, "run-set")


def test_validate_does_not_echo_jsonschema_instance_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "not-a-pattern-but-still-private-9f8e7d6c"
    path = tmp_path / "artifact.json"
    path.write_text("{}", encoding="utf-8")

    def fail_validation(_path: Path, _kind: str) -> str:
        raise JsonSchemaValidationError(
            f"the complete invalid instance was {secret}",
            validator="required",
            instance={"private": secret},
        )

    monkeypatch.setattr(validate_cmd, "validate_artifact", fail_validation)

    with pytest.raises(typer.BadParameter) as raised:
        validate(path, "run-set")

    message = str(raised.value)
    assert secret not in message
    assert "rule=required" in message
    assert len(message) <= MAX_VALIDATION_ERROR_CHARS
