from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.onboarding.diagnostics import bounded_error, display_path  # noqa: E402
from agent_assure.reporting.sbom import load_and_validate_sbom  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the Agent Assure CycloneDX profile and verify referenced "
            "local lock/distribution bytes."
        )
    )
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=ROOT,
        help="Root for release and dependency-lock paths embedded in the SBOM.",
    )
    args = parser.parse_args(argv)
    try:
        load_and_validate_sbom(args.sbom, artifact_root=args.artifact_root)
    except (OSError, ValueError) as exc:
        print(f"SBOM validation failed: {bounded_error(exc)}", file=sys.stderr)
        return 2
    print(f"SBOM validation passed: {display_path(args.sbom)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
