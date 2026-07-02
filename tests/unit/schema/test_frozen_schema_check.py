from __future__ import annotations

from pathlib import Path

from agent_assure.schema.export import export_json_schemas
from scripts.check_frozen_schemas import check_frozen_schema_dir, compare_schema_dirs

ROOT = Path(__file__).resolve().parents[3]


def test_committed_v030_schema_snapshot_matches_exporter() -> None:
    assert check_frozen_schema_dir(ROOT / "schemas" / "v0.3.0") == []


def test_frozen_schema_compare_accepts_matching_export(tmp_path: Path) -> None:
    expected = tmp_path / "expected"
    actual = tmp_path / "actual"
    export_json_schemas(expected)
    export_json_schemas(actual)

    assert compare_schema_dirs(expected, actual) == []


def test_frozen_schema_compare_reports_missing_schema(tmp_path: Path) -> None:
    expected = tmp_path / "expected"
    actual = tmp_path / "actual"
    export_json_schemas(expected)
    export_json_schemas(actual)
    (actual / "agent-run-record.schema.json").unlink()

    failures = compare_schema_dirs(expected, actual)

    assert "missing frozen schema: agent-run-record.schema.json" in failures


def test_frozen_schema_compare_reports_stale_schema(tmp_path: Path) -> None:
    expected = tmp_path / "expected"
    actual = tmp_path / "actual"
    export_json_schemas(expected)
    export_json_schemas(actual)
    (actual / "stale.schema.json").write_text("{}\n", encoding="utf-8")

    failures = compare_schema_dirs(expected, actual)

    assert "stale frozen schema: stale.schema.json" in failures


def test_frozen_schema_compare_reports_drift(tmp_path: Path) -> None:
    expected = tmp_path / "expected"
    actual = tmp_path / "actual"
    export_json_schemas(expected)
    export_json_schemas(actual)
    (actual / "agent-run-record.schema.json").write_text("{}\n", encoding="utf-8")

    failures = compare_schema_dirs(expected, actual)

    assert "frozen schema drift: agent-run-record.schema.json" in failures
