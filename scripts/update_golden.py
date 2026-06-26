from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.authoring.compiler import compile_suite  # noqa: E402
from agent_assure.fixtures.manifest import build_fixture_manifest  # noqa: E402

SUITE_YAML = ROOT / "examples" / "prior_auth_synthetic" / "suite.yaml"
SUITE_ROOT = SUITE_YAML.parent
GOLDEN_ROOT = ROOT / "tests" / "golden" / "compiled_suites"
GOLDENS = {
    GOLDEN_ROOT / "prior_auth_synthetic.compiled.json": lambda: compile_suite(
        SUITE_YAML
    ).model_dump(mode="json"),
    GOLDEN_ROOT / "prior_auth_synthetic.fixture-manifest.json": lambda: build_fixture_manifest(
        compile_suite(SUITE_YAML), SUITE_ROOT
    ).model_dump(mode="json"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check or update deterministic golden artifacts.")
    parser.add_argument(
        "--update-golden",
        action="store_true",
        help="Rewrite golden files instead of checking for drift.",
    )
    args = parser.parse_args()
    failures: list[str] = []
    for path, factory in GOLDENS.items():
        generated = _json_text(factory())
        if args.update_golden:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generated, encoding="utf-8", newline="\n")
            continue
        if not path.exists():
            failures.append(f"missing golden file: {path.relative_to(ROOT)}")
            continue
        existing = path.read_text(encoding="utf-8")
        if existing != generated:
            failures.append(f"golden drift: {path.relative_to(ROOT)}")
    if failures:
        for failure in failures:
            print(f"golden-check: {failure}", file=sys.stderr)
        print(
            "golden-check: run scripts/update_golden.py --update-golden intentionally",
            file=sys.stderr,
        )
        return 1
    action = "updated" if args.update_golden else "ok"
    print(f"golden-check: {action}")
    return 0


def _json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
