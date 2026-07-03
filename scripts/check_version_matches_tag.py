from __future__ import annotations

import argparse
import ast
import os
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_INIT = ROOT / "src" / "agent_assure" / "__init__.py"
SCHEMA_BASE = ROOT / "src" / "agent_assure" / "schema" / "base.py"
SCHEMA_ROOT = ROOT / "schemas"
VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:rc[1-9]\d*)?$")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        tag = normalize_tag(args.tag or tag_from_environment())
        pyproject_version = read_pyproject_version(args.pyproject)
        package_version = read_package_version(args.package_init)
        package_schema_version = read_schema_version(args.package_init)
        base_schema_version = read_schema_version(args.schema_base)
    except ValueError as exc:
        print(f"version-tag: {exc}", file=sys.stderr)
        return 1

    expected_tag = f"v{pyproject_version}"
    expected_schema_version = release_schema_version(pyproject_version)
    expected_schema_dir = args.schema_root / f"v{expected_schema_version}"
    failures: list[str] = []
    if tag != expected_tag:
        failures.append(f"tag {tag!r} does not match pyproject version {pyproject_version!r}")
    if package_version != pyproject_version:
        failures.append(
            f"package __version__ {package_version!r} does not match "
            f"pyproject version {pyproject_version!r}"
        )
    if package_schema_version != expected_schema_version:
        failures.append(
            f"package SCHEMA_VERSION {package_schema_version!r} does not match "
            f"release schema version {expected_schema_version!r}"
        )
    if base_schema_version != expected_schema_version:
        failures.append(
            f"schema.base SCHEMA_VERSION {base_schema_version!r} does not match "
            f"release schema version {expected_schema_version!r}"
        )
    if not expected_schema_dir.is_dir():
        failures.append(
            "frozen schema directory missing for release version: "
            f"{expected_schema_dir}"
        )
    if failures:
        for failure in failures:
            print(f"version-tag: {failure}", file=sys.stderr)
        return 1

    print(f"version-tag: ok ({tag})")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a release tag matches package version metadata."
    )
    parser.add_argument(
        "tag",
        nargs="?",
        help="Release tag to check, for example v0.3.0. Defaults to GitHub ref env vars.",
    )
    parser.add_argument(
        "--pyproject",
        type=Path,
        default=PYPROJECT,
        help="Path to pyproject.toml.",
    )
    parser.add_argument(
        "--package-init",
        type=Path,
        default=PACKAGE_INIT,
        help="Path to src/agent_assure/__init__.py.",
    )
    parser.add_argument(
        "--schema-base",
        type=Path,
        default=SCHEMA_BASE,
        help="Path to src/agent_assure/schema/base.py.",
    )
    parser.add_argument(
        "--schema-root",
        type=Path,
        default=SCHEMA_ROOT,
        help="Directory containing frozen schema version snapshots.",
    )
    return parser.parse_args(argv)


def tag_from_environment() -> str:
    github_ref_name = os.environ.get("GITHUB_REF_NAME")
    if github_ref_name:
        return github_ref_name
    github_ref = os.environ.get("GITHUB_REF")
    if github_ref:
        return github_ref
    raise ValueError("release tag was not provided and no GitHub tag ref is set")


def normalize_tag(tag: str) -> str:
    normalized = tag.strip()
    prefix = "refs/tags/"
    if normalized.startswith(prefix):
        normalized = normalized[len(prefix) :]
    if not normalized:
        raise ValueError("release tag must not be empty")
    if not normalized.startswith("v"):
        raise ValueError(f"release tag must start with 'v': {tag!r}")
    validate_version(normalized[1:], source="release tag")
    return normalized


def read_pyproject_version(path: Path = PYPROJECT) -> str:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    project = payload.get("project")
    if not isinstance(project, dict):
        raise ValueError(f"{path} is missing [project]")
    version = project.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"{path} is missing project.version")
    validate_version(version, source=f"{path} project.version")
    return version


def read_package_version(path: Path = PACKAGE_INIT) -> str:
    version = read_string_assignment(path, "__version__")
    validate_version(version, source=f"{path} __version__")
    return version


def read_schema_version(path: Path) -> str:
    version = read_string_assignment(path, "SCHEMA_VERSION")
    validate_version(version, source=f"{path} SCHEMA_VERSION")
    return version


def release_schema_version(package_version: str) -> str:
    # v0.3.1 intentionally couples package and schema release versions. If a
    # future package-only release keeps the schema behind the package version,
    # replace this derivation with an explicit release-to-schema mapping.
    return package_version.split("rc", 1)[0]


def read_string_assignment(path: Path, name: str) -> str:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    value = ast.literal_eval(node.value)
                    if isinstance(value, str) and value:
                        return value
    raise ValueError(f"{path} is missing {name}")


def validate_version(version: str, *, source: str) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(
            f"{source} must match X.Y.Z or X.Y.ZrcN with no shell metacharacters: {version!r}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
