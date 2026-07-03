from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
PYPROJECT = ROOT / "pyproject.toml"
SCHEMA_BASE = ROOT / "src" / "agent_assure" / "schema" / "base.py"

_FROZEN_VERSION_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:rc(\d+))?$")


def frozen_schema_versions(schema_root: Path = SCHEMA_ROOT) -> tuple[str, ...]:
    if not schema_root.is_dir():
        return ()
    versions = [
        path.name
        for path in schema_root.iterdir()
        if path.is_dir()
        and _FROZEN_VERSION_PATTERN.fullmatch(path.name)
        and any(path.glob("*.schema.json"))
    ]
    return tuple(sorted(versions, key=_version_key))


def latest_frozen_schema_version(schema_root: Path = SCHEMA_ROOT) -> str:
    versions = frozen_schema_versions(schema_root)
    if not versions:
        raise ValueError(f"no frozen schema versions found under {schema_root}")
    return versions[-1]


def active_schema_version(schema_base: Path = SCHEMA_BASE) -> str:
    module = ast.parse(schema_base.read_text(encoding="utf-8"), filename=str(schema_base))
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SCHEMA_VERSION":
                    value = ast.literal_eval(node.value)
                    if isinstance(value, str) and value:
                        return value
    raise ValueError(f"{schema_base} is missing SCHEMA_VERSION")


def active_schema_dir(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_base: Path = SCHEMA_BASE,
) -> Path:
    return schema_root / f"v{active_schema_version(schema_base)}"


def schema_resource_archive_paths(
    *,
    schema_root: Path = SCHEMA_ROOT,
    schema_versions: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    versions = schema_versions or frozen_schema_versions(schema_root)
    paths: list[str] = []
    for version in versions:
        version_dir = schema_root / version
        paths.extend(
            f"agent_assure/schema_resources/{version}/{path.name}"
            for path in sorted(version_dir.glob("*.schema.json"))
        )
    return tuple(paths)


def expected_schema_force_includes(
    schema_root: Path = SCHEMA_ROOT,
) -> dict[str, str]:
    return {
        f"schemas/{version}": f"agent_assure/schema_resources/{version}"
        for version in frozen_schema_versions(schema_root)
    }


def pyproject_schema_force_includes(pyproject: Path = PYPROJECT) -> dict[str, str]:
    payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    force_include = (
        payload.get("tool", {})
        .get("hatch", {})
        .get("build", {})
        .get("targets", {})
        .get("wheel", {})
        .get("force-include", {})
    )
    if not isinstance(force_include, dict):
        return {}
    return {
        str(source): str(target)
        for source, target in force_include.items()
        if str(source).startswith("schemas/v")
        or str(target).startswith("agent_assure/schema_resources/v")
    }


def schema_packaging_failures(
    *,
    schema_root: Path = SCHEMA_ROOT,
    pyproject: Path = PYPROJECT,
) -> list[str]:
    expected = expected_schema_force_includes(schema_root)
    actual = pyproject_schema_force_includes(pyproject)
    failures: list[str] = []
    for source, target in sorted(expected.items()):
        if actual.get(source) != target:
            failures.append(
                "missing schema force-include: "
                f"{source!r} = {target!r} in {_display_path(pyproject)}"
            )
    for source, target in sorted(actual.items()):
        if source not in expected:
            failures.append(
                "stale schema force-include: "
                f"{source!r} = {target!r} in {_display_path(pyproject)}"
            )
    return failures


def _version_key(version: str) -> tuple[int, int, int, int]:
    match = _FROZEN_VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise ValueError(f"invalid frozen schema version: {version}")
    major, minor, patch, rc = match.groups()
    return (int(major), int(minor), int(patch), int(rc) if rc else 1_000_000)


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)
