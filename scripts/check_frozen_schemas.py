from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_assure.schema.export import export_json_schemas  # noqa: E402
from scripts.schema_versions import (  # noqa: E402
    active_schema_dir,
    schema_packaging_failures,
)

DEFAULT_SCHEMA_DIR = active_schema_dir()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    failures = [
        *check_frozen_schema_dir(_resolve_path(args.schema_dir)),
        *schema_packaging_failures(),
    ]
    if failures:
        for failure in failures:
            print(f"frozen-schemas: {failure}", file=sys.stderr)
        print("frozen-schemas: run `make schemas` to refresh the release snapshot", file=sys.stderr)
        return 1
    print(f"frozen-schemas: ok ({_display_path(_resolve_path(args.schema_dir))})")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify frozen release schemas match the current schema exporter."
    )
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=DEFAULT_SCHEMA_DIR,
        help="Frozen schema directory to compare. Defaults to the active schema version directory.",
    )
    return parser.parse_args(argv)


def check_frozen_schema_dir(schema_dir: Path) -> list[str]:
    if not schema_dir.exists():
        return [f"missing schema directory: {_display_path(schema_dir)}"]
    if not schema_dir.is_dir():
        return [f"schema path is not a directory: {_display_path(schema_dir)}"]

    with tempfile.TemporaryDirectory(prefix="agent-assure-frozen-schemas-") as temp:
        expected_dir = Path(temp) / "schemas"
        export_json_schemas(expected_dir)
        return compare_schema_dirs(expected_dir, schema_dir)


def compare_schema_dirs(expected_dir: Path, actual_dir: Path) -> list[str]:
    expected = _schema_files(expected_dir)
    actual = _schema_files(actual_dir)
    failures: list[str] = []
    for relative_path in sorted(expected - actual):
        failures.append(f"missing frozen schema: {relative_path}")
    for relative_path in sorted(actual - expected):
        failures.append(f"stale frozen schema: {relative_path}")
    for relative_path in sorted(expected & actual):
        expected_path = expected_dir / relative_path
        actual_path = actual_dir / relative_path
        if expected_path.read_bytes() != actual_path.read_bytes():
            failures.append(f"frozen schema drift: {relative_path}")
    return failures


def _schema_files(root: Path) -> set[Path]:
    return {
        path.relative_to(root)
        for path in root.rglob("*.schema.json")
        if path.is_file()
    }


def _resolve_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return ROOT / path


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
