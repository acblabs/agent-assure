from __future__ import annotations

from pathlib import Path

import pytest
import typer

from agent_assure.cli.validate_cmd import validate
from agent_assure.io_limits import MAX_JSON_DEPTH


def test_validate_reports_over_depth_json_as_bad_parameter(tmp_path: Path) -> None:
    path = tmp_path / "artifact.json"
    path.write_text("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))

    with pytest.raises(typer.BadParameter, match="exceeds maximum supported nesting depth"):
        validate(path, "run-set")
