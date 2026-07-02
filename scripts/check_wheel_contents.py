from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SCHEMA_ROOT = ROOT / "schemas"
FROZEN_SCHEMA_VERSIONS = ("v0.1.0", "v0.2.0", "v0.3.0")

BASE_REQUIRED_ARCHIVE_PATHS = (
    "agent_assure/__init__.py",
    "agent_assure/cli/main.py",
    "agent_assure/examples/",
    "agent_assure/examples/prior_auth_synthetic/",
    "agent_assure/examples/prior_auth_synthetic/suite.yaml",
    "agent_assure/examples/prior_auth_synthetic/variants/baseline.yaml",
    (
        "agent_assure/examples/prior_auth_synthetic/variants/"
        "candidate_evidence_normalization.yaml"
    ),
    (
        "agent_assure/examples/prior_auth_synthetic/fixtures/shared/requests/"
        "shared-source-multi-claim.json"
    ),
    (
        "agent_assure/examples/prior_auth_synthetic/fixtures/shared/model_outputs/"
        "shared-source-multi-claim.json"
    ),
    (
        "agent_assure/examples/prior_auth_synthetic/fixtures/shared/tool_outputs/"
        "shared-source-multi-claim.json"
    ),
    "agent_assure/examples/expense_approval_minimal/",
    "agent_assure/examples/expense_approval_minimal/suite.yaml",
    "agent_assure/examples/expense_approval_minimal/variants/baseline.yaml",
    "agent_assure/examples/expense_approval_minimal/variants/candidate_provider_policy.yaml",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/requests/exp-001.json",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/model_outputs/exp-001.json",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/tool_outputs/exp-001.json",
    "agent_assure/schema_resources/__init__.py",
    "agent_assure/schema_resources/v0.1.0/",
    "agent_assure/schema_resources/v0.2.0/",
    "agent_assure/schema_resources/v0.3.0/",
)

FORBIDDEN_ARCHIVE_PREFIXES = (
    "schemas/",
    "agent_assure/schema_resources/unreleased/",
    ".tmp/",
    "dist/",
    "build/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
)

FORBIDDEN_ARCHIVE_SEGMENTS = (
    "__pycache__",
)

FORBIDDEN_ARCHIVE_SUFFIXES = (
    ".pyc",
)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        wheel = find_single_wheel(args.dist)
        missing, forbidden = inspect_wheel(wheel)
    except ValueError as exc:
        print(f"wheel-contents: {exc}", file=sys.stderr)
        return 1

    failures = []
    if missing:
        failures.append("missing required paths:\n" + "\n".join(f"  - {path}" for path in missing))
    if forbidden:
        failures.append(
            "forbidden paths present:\n" + "\n".join(f"  - {path}" for path in forbidden)
        )
    if failures:
        print(f"wheel-contents: {wheel}", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"wheel-contents: ok ({wheel.name})")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify built wheel archive contents.")
    parser.add_argument(
        "--dist",
        type=Path,
        default=DIST,
        help="Directory containing exactly one built wheel. Defaults to dist/.",
    )
    return parser.parse_args(argv)


def find_single_wheel(dist_dir: Path) -> Path:
    wheels = sorted(dist_dir.glob("*.whl"))
    if len(wheels) != 1:
        wheel_list = ", ".join(wheel.name for wheel in wheels) or "none"
        raise ValueError(f"expected exactly one wheel in {dist_dir}, found {wheel_list}")
    return wheels[0]


def inspect_wheel(wheel: Path) -> tuple[list[str], list[str]]:
    with zipfile.ZipFile(wheel) as archive:
        names = tuple(sorted(archive.namelist()))
    required_paths = required_archive_paths()
    missing = [
        required
        for required in required_paths
        if not _archive_contains(names, required)
    ]
    forbidden = [name for name in names if _is_forbidden_archive_path(name)]
    return missing, forbidden


def required_archive_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] = FROZEN_SCHEMA_VERSIONS,
) -> tuple[str, ...]:
    schema_paths: list[str] = []
    for version in schema_versions:
        version_dir = schema_root / version
        if not version_dir.is_dir():
            schema_paths.append(f"agent_assure/schema_resources/{version}/")
            continue
        schema_paths.extend(
            f"agent_assure/schema_resources/{version}/{path.name}"
            for path in sorted(version_dir.glob("*.schema.json"))
        )
    return (*BASE_REQUIRED_ARCHIVE_PATHS, *tuple(schema_paths))


def _archive_contains(names: tuple[str, ...], required: str) -> bool:
    if required.endswith("/"):
        return any(name.startswith(required) for name in names)
    return required in names


def _is_forbidden_archive_path(name: str) -> bool:
    if any(name.startswith(prefix) for prefix in FORBIDDEN_ARCHIVE_PREFIXES):
        return True
    if any(segment in name.split("/") for segment in FORBIDDEN_ARCHIVE_SEGMENTS):
        return True
    return any(name.endswith(suffix) for suffix in FORBIDDEN_ARCHIVE_SUFFIXES)


if __name__ == "__main__":
    raise SystemExit(main())
