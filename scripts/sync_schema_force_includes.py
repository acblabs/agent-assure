from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.schema_versions import (  # noqa: E402
    PYPROJECT,
    SCHEMA_ROOT,
    expected_schema_force_includes,
)

_HEADER = "[tool.hatch.build.targets.wheel.force-include]"
_STATIC_FORCE_INCLUDES = {
    "mappings": "agent_assure/mappings",
}


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    updated = sync_schema_force_includes(
        pyproject=args.pyproject,
        schema_root=args.schema_root,
        check=args.check,
    )
    if args.check and updated:
        print("schema-force-include: pyproject.toml is out of sync", file=sys.stderr)
        return 1
    if args.check:
        print("schema-force-include: ok")
    else:
        print(f"schema-force-include: updated {args.pyproject}")
    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Synchronize Hatch schema force-include entries with schemas/v*."
    )
    parser.add_argument("--pyproject", type=Path, default=PYPROJECT)
    parser.add_argument("--schema-root", type=Path, default=SCHEMA_ROOT)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def sync_schema_force_includes(
    *,
    pyproject: Path = PYPROJECT,
    schema_root: Path = SCHEMA_ROOT,
    check: bool = False,
) -> bool:
    original = pyproject.read_text(encoding="utf-8")
    updated = replace_force_include_block(original, schema_root=schema_root)
    changed = updated != original
    if changed and not check:
        pyproject.write_text(updated, encoding="utf-8", newline="\n")
    return changed


def replace_force_include_block(text: str, *, schema_root: Path = SCHEMA_ROOT) -> str:
    block = render_force_include_block(schema_root=schema_root)
    lines = text.splitlines()
    try:
        start = lines.index(_HEADER)
    except ValueError:
        suffix = "" if text.endswith("\n") else "\n"
        return f"{text}{suffix}\n{block}\n"
    end = start + 1
    while end < len(lines) and not lines[end].startswith("["):
        end += 1
    spacer = [""] if end < len(lines) else []
    new_lines = [*lines[:start], *block.splitlines(), *spacer, *lines[end:]]
    return "\n".join(new_lines) + "\n"


def render_force_include_block(*, schema_root: Path = SCHEMA_ROOT) -> str:
    entries = {**expected_schema_force_includes(schema_root), **_STATIC_FORCE_INCLUDES}
    lines = [_HEADER]
    lines.extend(f'"{source}" = "{target}"' for source, target in sorted(entries.items()))
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
