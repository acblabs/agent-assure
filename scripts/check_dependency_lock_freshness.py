from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = Path("pyproject.toml")
LOCK_PATHS = (
    Path("requirements.lock"),
    Path("requirements-langgraph.lock"),
    Path("requirements-adk.lock"),
    Path("requirements-otel.lock"),
)
SOURCE_DIGEST_MARKER = "source-dependency-input-sha256"
_SOURCE_DIGEST_RE = re.compile(rf"(?m)^# {SOURCE_DIGEST_MARKER}: (?P<digest>[0-9a-f]{{64}})$")


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def dependency_input_projection(pyproject_path: Path) -> dict[str, object]:
    """Project only the declarations that can change dependency resolution."""
    with pyproject_path.open("rb") as handle:
        payload = tomllib.load(handle)
    build_system = payload.get("build-system", {})
    project = payload.get("project", {})
    if not isinstance(build_system, dict) or not isinstance(project, dict):
        raise ValueError("pyproject dependency tables must be TOML mappings")
    build_requirements = build_system.get("requires", [])
    dependencies = project.get("dependencies", [])
    optional_dependencies = project.get("optional-dependencies", {})
    requires_python = project.get("requires-python")
    if not isinstance(build_requirements, list) or not all(
        isinstance(item, str) for item in build_requirements
    ):
        raise ValueError("build-system.requires must be a list of strings")
    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) for item in dependencies
    ):
        raise ValueError("project.dependencies must be a list of strings")
    if not isinstance(optional_dependencies, dict) or any(
        not isinstance(group, str)
        or not isinstance(requirements, list)
        or not all(isinstance(item, str) for item in requirements)
        for group, requirements in optional_dependencies.items()
    ):
        raise ValueError("project.optional-dependencies must map names to string lists")
    if not isinstance(requires_python, str):
        raise ValueError("project.requires-python must be a string")
    return {
        "build-system": {"requires": sorted(build_requirements)},
        "project": {
            "requires-python": requires_python,
            "dependencies": sorted(dependencies),
            "optional-dependencies": {
                group: sorted(requirements)
                for group, requirements in sorted(optional_dependencies.items())
            },
        },
    }


def dependency_input_sha256(pyproject_path: Path) -> str:
    projection = dependency_input_projection(pyproject_path)
    encoded = json.dumps(
        projection,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def dependency_lock_freshness_errors(project_root: Path = PROJECT_ROOT) -> tuple[str, ...]:
    """Return source-marker failures for every checked-in Python dependency lock."""
    source_path = project_root / PYPROJECT_PATH
    if not source_path.is_file():
        return (f"missing dependency source: {PYPROJECT_PATH.as_posix()}",)
    source_digest = dependency_input_sha256(source_path)
    failures: list[str] = []
    for relative_lock in LOCK_PATHS:
        lock_path = project_root / relative_lock
        if not lock_path.is_file():
            failures.append(f"missing dependency lock: {relative_lock.as_posix()}")
            continue
        match = _SOURCE_DIGEST_RE.search(lock_path.read_text(encoding="utf-8"))
        if match is None:
            failures.append(
                f"{relative_lock.as_posix()}: missing '# {SOURCE_DIGEST_MARKER}: <sha256>' marker"
            )
            continue
        marker_digest = match.group("digest")
        if marker_digest != source_digest:
            failures.append(
                f"{relative_lock.as_posix()}: source marker {marker_digest} does not "
                "match the canonical pyproject dependency-input projection "
                f"{source_digest}"
            )
    return tuple(failures)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fail when a checked-in Python dependency lock does not bind the "
            "current canonical pyproject dependency-input projection."
        )
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository root containing pyproject.toml and the checked-in lockfiles.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    failures = dependency_lock_freshness_errors(args.project_root.resolve())
    if failures:
        for failure in failures:
            print(f"dependency lock freshness: FAIL: {failure}")
        return 1
    print(
        "dependency lock freshness: PASS: all checked-in Python locks bind the "
        "current pyproject dependency-input projection"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
