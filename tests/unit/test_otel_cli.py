from __future__ import annotations

from pathlib import Path

import pytest
import typer

from agent_assure.cli.otel_cmd import preview
from agent_assure.io_limits import MAX_JSON_DEPTH


def test_otel_preview_reports_over_depth_json_as_bad_parameter(tmp_path: Path) -> None:
    path = tmp_path / "record.json"
    path.write_text("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))

    with pytest.raises(typer.BadParameter, match="exceeds maximum supported nesting depth"):
        preview(path, out=None)
