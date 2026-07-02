from __future__ import annotations

import zipfile
from pathlib import Path

from scripts.check_wheel_contents import inspect_wheel, required_archive_paths


def test_required_archive_paths_include_every_v030_schema(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    (schema_root / "v0.3.0").mkdir(parents=True)
    (schema_root / "v0.3.0" / "agent-run-record.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (schema_root / "v0.3.0" / "evidence-packet.schema.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    required = required_archive_paths(
        schema_root=schema_root,
        schema_versions=("v0.3.0",),
    )

    assert "agent_assure/schema_resources/v0.3.0/agent-run-record.schema.json" in required
    assert "agent_assure/schema_resources/v0.3.0/evidence-packet.schema.json" in required


def test_inspect_wheel_reports_missing_frozen_schema_file(tmp_path: Path) -> None:
    wheel = tmp_path / "agent_assure-0.3.0-py3-none-any.whl"
    required = set(required_archive_paths())
    missing_schema = "agent_assure/schema_resources/v0.3.0/evidence-packet.schema.json"
    required.remove(missing_schema)
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in sorted(required):
            if path.endswith("/"):
                archive.writestr(f"{path}.keep", "")
            else:
                archive.writestr(path, "{}\n")

    missing, forbidden = inspect_wheel(wheel)

    assert missing_schema in missing
    assert forbidden == []
