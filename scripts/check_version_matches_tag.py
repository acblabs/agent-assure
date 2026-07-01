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
VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:rc[1-9]\d*)?$")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        tag = normalize_tag(args.tag or tag_from_environment())
        pyproject_version = read_pyproject_version(args.pyproject)
        package_version = read_package_version(args.package_init)
    except ValueError as exc:
        print(f"version-tag: {exc}", file=sys.stderr)
        return 1

    expected_tag = f"v{pyproject_version}"
    failures: list[str] = []
    if tag != expected_tag:
        failures.append(f"tag {tag!r} does not match pyproject version {pyproject_version!r}")
    if package_version != pyproject_version:
        failures.append(
            f"package __version__ {package_version!r} does not match "
            f"pyproject version {pyproject_version!r}"
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
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    value = ast.literal_eval(node.value)
                    if isinstance(value, str) and value:
                        validate_version(value, source=f"{path} __version__")
                        return value
    raise ValueError(f"{path} is missing __version__")


def validate_version(version: str, *, source: str) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(
            f"{source} must match X.Y.Z or X.Y.ZrcN with no shell metacharacters: {version!r}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
