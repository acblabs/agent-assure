from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.schema_versions import (  # noqa: E402
    SCHEMA_ROOT,
    frozen_schema_versions,
    schema_resource_archive_paths,
)

DIST = ROOT / "dist"

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
    (
        "agent_assure/examples/prior_auth_synthetic/fixtures/rag/"
        "counterfactual_query_families.json"
    ),
    "agent_assure/examples/expense_approval_minimal/",
    "agent_assure/examples/expense_approval_minimal/suite.yaml",
    "agent_assure/examples/expense_approval_minimal/variants/baseline.yaml",
    "agent_assure/examples/expense_approval_minimal/variants/candidate_provider_policy.yaml",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/requests/exp-001.json",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/model_outputs/exp-001.json",
    "agent_assure/examples/expense_approval_minimal/fixtures/shared/tool_outputs/exp-001.json",
    "agent_assure/examples/langgraph_expense_assurance/",
    "agent_assure/examples/langgraph_expense_assurance/__init__.py",
    "agent_assure/examples/langgraph_expense_assurance/README.md",
    "agent_assure/examples/langgraph_expense_assurance/runner.py",
    "agent_assure/examples/langgraph_expense_assurance/suite.yaml",
    "agent_assure/examples/process_measurement_cases/",
    "agent_assure/examples/process_measurement_cases/README.md",
    "agent_assure/examples/process_measurement_cases/runner.py",
    "agent_assure/examples/process_measurement_cases/suite.yaml",
    "agent_assure/examples/process_measurement_cases/variants/baseline.yaml",
    (
        "agent_assure/examples/process_measurement_cases/variants/"
        "candidate_process_regressions.yaml"
    ),
    (
        "agent_assure/examples/process_measurement_cases/fixtures/shared/requests/"
        "same-output-human-review-bypassed.json"
    ),
    (
        "agent_assure/examples/process_measurement_cases/fixtures/shared/model_outputs/"
        "same-output-provider-boundary.json"
    ),
    (
        "agent_assure/examples/process_measurement_cases/fixtures/shared/tool_outputs/"
        "same-output-missing-evidence.json"
    ),
    "agent_assure/schema_resources/__init__.py",
    "agent_assure/mappings/nist_ai_rmf.yaml",
    "agent_assure/mappings/owasp_llm_top_10_2025.yaml",
    "agent_assure/mappings/iso_iec_42001.yaml",
    "agent_assure/mappings/mitre_atlas_2026_06.yaml",
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

FORBIDDEN_SDIST_PREFIXES = (
    "schemas/unreleased/",
    ".tmp/",
    "dist/",
    "build/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
)

FORBIDDEN_SDIST_EXACT_PATHS = (
    "schemas/unreleased",
)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        wheel = find_single_wheel(args.dist)
        sdist = find_single_sdist(args.dist)
        missing, forbidden = inspect_wheel(wheel)
        sdist_forbidden = inspect_sdist(sdist)
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
    if sdist_forbidden:
        failures.append(
            "forbidden sdist paths present:\n"
            + "\n".join(f"  - {path}" for path in sdist_forbidden)
        )
    if failures:
        print(f"wheel-contents: {wheel}", file=sys.stderr)
        print(f"sdist-contents: {sdist}", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"wheel-contents: ok ({wheel.name}, {sdist.name})")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify built wheel archive contents.")
    parser.add_argument(
        "--dist",
        type=Path,
        default=DIST,
        help="Directory containing exactly one built wheel and sdist. Defaults to dist/.",
    )
    return parser.parse_args(argv)


def find_single_wheel(dist_dir: Path) -> Path:
    wheels = sorted(dist_dir.glob("*.whl"))
    if len(wheels) != 1:
        wheel_list = ", ".join(wheel.name for wheel in wheels) or "none"
        raise ValueError(f"expected exactly one wheel in {dist_dir}, found {wheel_list}")
    return wheels[0]


def find_single_sdist(dist_dir: Path) -> Path:
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(sdists) != 1:
        sdist_list = ", ".join(sdist.name for sdist in sdists) or "none"
        raise ValueError(
            f"expected exactly one source distribution in {dist_dir}, found {sdist_list}"
        )
    return sdists[0]


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


def inspect_sdist(sdist: Path) -> list[str]:
    with tarfile.open(sdist, "r:gz") as archive:
        names = tuple(sorted(member.name for member in archive.getmembers()))
    return [name for name in names if _is_forbidden_sdist_path(name)]


def required_archive_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    versions = schema_versions or frozen_schema_versions(schema_root)
    schema_dirs = tuple(
        f"agent_assure/schema_resources/{version}/" for version in versions
    )
    schema_paths = schema_resource_archive_paths(
        schema_root=schema_root,
        schema_versions=versions,
    )
    return (*BASE_REQUIRED_ARCHIVE_PATHS, *schema_dirs, *schema_paths)


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


def _is_forbidden_sdist_path(name: str) -> bool:
    normalized = _strip_sdist_root(name)
    if normalized in FORBIDDEN_SDIST_EXACT_PATHS:
        return True
    if any(normalized.startswith(prefix) for prefix in FORBIDDEN_SDIST_PREFIXES):
        return True
    if any(segment in normalized.split("/") for segment in FORBIDDEN_ARCHIVE_SEGMENTS):
        return True
    return any(normalized.endswith(suffix) for suffix in FORBIDDEN_ARCHIVE_SUFFIXES)


def _strip_sdist_root(name: str) -> str:
    parts = name.split("/", 1)
    if len(parts) == 1:
        return name
    return parts[1]


if __name__ == "__main__":
    raise SystemExit(main())
