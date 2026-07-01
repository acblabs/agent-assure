from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.schema.export import export_json_schemas  # noqa: E402

DEFAULT_OUT = ROOT / "schemas" / "unreleased"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    written = export_json_schemas(args.out)
    schema_files = tuple(path for path in written if path.name.endswith(".schema.json"))
    if not schema_files:
        print(f"schema-staging: no schema files exported to {args.out}", file=sys.stderr)
        return 1
    print(
        "schema-staging: ok "
        f"({len(schema_files)} schemas exported to {args.out}; drift is not checked)"
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export development JSON Schemas to schemas/unreleased as a smoke check. "
            "This intentionally does not enforce drift for unreleased schemas."
        )
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Development schema export directory. Defaults to schemas/unreleased.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
