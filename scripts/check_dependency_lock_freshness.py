from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT_PATH = Path("pyproject.toml")
LOCK_PATHS = (
    Path("requirements.lock"),
    Path("requirements-min.lock"),
    Path("requirements-langgraph.lock"),
    Path("requirements-adk.lock"),
    Path("requirements-otel.lock"),
)
MINIMUM_RUNTIME_CONSTRAINTS_PATH = Path("requirements-min.constraints.txt")
MINIMUM_RUNTIME_LOCK_PATH = Path("requirements-min.lock")
SOURCE_DIGEST_MARKER = "source-dependency-input-sha256"
_SOURCE_DIGEST_RE = re.compile(rf"(?m)^# {SOURCE_DIGEST_MARKER}: (?P<digest>[0-9a-f]{{64}})$")
MINIMUM_CONSTRAINTS_DIGEST_MARKER = "minimum-runtime-constraints-sha256"
_MINIMUM_CONSTRAINTS_DIGEST_RE = re.compile(
    rf"(?m)^# {MINIMUM_CONSTRAINTS_DIGEST_MARKER}: (?P<digest>[0-9a-f]{{64}})$"
)


@dataclass(frozen=True)
class _MinimumRequirement:
    declared_name: str
    normalized_name: str
    version: Version


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


def _validate_plain_requirement(requirement: Requirement, value: str, *, owner: str) -> None:
    if requirement.extras:
        raise ValueError(f"{owner}: dependency extras are not supported: {value!r}")
    if requirement.marker is not None:
        raise ValueError(f"{owner}: dependency markers are not supported: {value!r}")
    if requirement.url is not None:
        raise ValueError(f"{owner}: direct URL requirements are not supported: {value!r}")


def _parse_requirement(
    value: str,
    *,
    owner: str,
    require_plain: bool = True,
) -> Requirement:
    try:
        requirement = Requirement(value)
    except InvalidRequirement as exc:
        raise ValueError(f"{owner}: invalid requirement {value!r}: {exc}") from exc
    if require_plain:
        _validate_plain_requirement(requirement, value, owner=owner)
    return requirement


def _version(value: str, *, owner: str) -> Version:
    try:
        parsed = Version(value)
    except InvalidVersion as exc:
        raise ValueError(f"{owner}: invalid PEP 440 version {value!r}") from exc
    if parsed.local is not None:
        raise ValueError(f"{owner}: local versions are not valid minimum-profile pins: {value!r}")
    return parsed


def _runtime_lower_floor(requirement: Requirement, *, owner: str) -> Version:
    specifiers = tuple(requirement.specifier)
    unsupported = sorted(
        str(specifier)
        for specifier in specifiers
        if specifier.operator not in {">=", "==", "<", "<=", "!="}
    )
    if unsupported:
        raise ValueError(
            f"{owner}: unsupported or non-inclusive runtime specifier(s): {', '.join(unsupported)}"
        )
    floor_specifiers = tuple(
        specifier for specifier in specifiers if specifier.operator in {">=", "=="}
    )
    if len(floor_specifiers) != 1:
        raise ValueError(
            f"{owner}: runtime requirement must declare exactly one inclusive lower "
            "floor using >=VERSION or ==VERSION"
        )
    floor_specifier = floor_specifiers[0]
    if floor_specifier.operator == "==" and floor_specifier.version.endswith(".*"):
        raise ValueError(f"{owner}: wildcard equality is not an exact runtime floor")
    floor = _version(floor_specifier.version, owner=owner)
    if not requirement.specifier.contains(floor, prereleases=True):
        raise ValueError(
            f"{owner}: declared lower floor {floor} is excluded by {requirement.specifier}"
        )
    return floor


def _exact_pin(requirement: Requirement, *, owner: str) -> Version:
    specifiers = tuple(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator != "==":
        raise ValueError(f"{owner}: minimum-profile entry must be one exact ==VERSION pin")
    raw_version = specifiers[0].version
    if raw_version.endswith(".*"):
        raise ValueError(f"{owner}: wildcard equality is not an exact minimum-profile pin")
    return _version(raw_version, owner=owner)


def _record_minimum_requirement(
    parsed: dict[str, _MinimumRequirement],
    requirement: Requirement,
    version: Version,
    *,
    owner: str,
) -> None:
    normalized_name = str(canonicalize_name(requirement.name))
    existing = parsed.get(normalized_name)
    if existing is not None:
        raise ValueError(
            f"{owner}: duplicate normalized dependency name {normalized_name!r} "
            f"({existing.declared_name!r} and {requirement.name!r})"
        )
    parsed[normalized_name] = _MinimumRequirement(
        declared_name=requirement.name,
        normalized_name=normalized_name,
        version=version,
    )


def _project_runtime_floors(pyproject_path: Path) -> dict[str, _MinimumRequirement]:
    with pyproject_path.open("rb") as handle:
        payload = tomllib.load(handle)
    project = payload.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml: project must be a TOML mapping")
    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) for item in dependencies
    ):
        raise ValueError("pyproject.toml: project.dependencies must be a list of strings")
    parsed: dict[str, _MinimumRequirement] = {}
    for index, value in enumerate(dependencies, start=1):
        owner = f"pyproject.toml: project.dependencies[{index}]"
        requirement = _parse_requirement(value, owner=owner)
        _record_minimum_requirement(
            parsed,
            requirement,
            _runtime_lower_floor(requirement, owner=owner),
            owner="pyproject.toml: project.dependencies",
        )
    return parsed


def _requirement_lines(path: Path) -> tuple[tuple[int, str], ...]:
    parsed: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if line:
            parsed.append((line_number, line))
    return tuple(parsed)


def _minimum_constraint_pins(path: Path) -> dict[str, _MinimumRequirement]:
    parsed: dict[str, _MinimumRequirement] = {}
    for line_number, value in _requirement_lines(path):
        owner = f"{path.name}:{line_number}"
        requirement = _parse_requirement(value, owner=owner)
        _record_minimum_requirement(
            parsed,
            requirement,
            _exact_pin(requirement, owner=owner),
            owner=path.name,
        )
    return parsed


def _minimum_lock_pins(
    path: Path,
    *,
    direct_names: frozenset[str],
) -> dict[str, _MinimumRequirement]:
    parsed: dict[str, _MinimumRequirement] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line or raw_line[0].isspace() or raw_line.lstrip().startswith("#"):
            continue
        value = raw_line.strip()
        if value.endswith("\\"):
            value = value[:-1].rstrip()
        owner = f"{path.name}:{line_number}"
        requirement = _parse_requirement(value, owner=owner, require_plain=False)
        normalized_name = str(canonicalize_name(requirement.name))
        if normalized_name not in direct_names:
            continue
        _validate_plain_requirement(requirement, value, owner=owner)
        _record_minimum_requirement(
            parsed,
            requirement,
            _exact_pin(requirement, owner=owner),
            owner=f"{path.name}: direct runtime pins",
        )
    return parsed


def minimum_runtime_profile_errors(project_root: Path = PROJECT_ROOT) -> tuple[str, ...]:
    """Return semantic failures in the declared minimum runtime profile."""
    source_path = project_root / PYPROJECT_PATH
    constraints_path = project_root / MINIMUM_RUNTIME_CONSTRAINTS_PATH
    lock_path = project_root / MINIMUM_RUNTIME_LOCK_PATH
    missing: list[str] = []
    if not source_path.is_file():
        missing.append(f"missing dependency source: {PYPROJECT_PATH.as_posix()}")
    if not constraints_path.is_file():
        missing.append(
            f"missing minimum-runtime constraints: {MINIMUM_RUNTIME_CONSTRAINTS_PATH.as_posix()}"
        )
    if not lock_path.is_file():
        missing.append(f"missing dependency lock: {MINIMUM_RUNTIME_LOCK_PATH.as_posix()}")
    if missing:
        return tuple(missing)

    try:
        runtime_floors = _project_runtime_floors(source_path)
        constraint_pins = _minimum_constraint_pins(constraints_path)
    except (OSError, ValueError) as exc:
        return (str(exc),)

    failures: list[str] = []
    runtime_names = frozenset(runtime_floors)
    constraint_names = frozenset(constraint_pins)
    missing_constraints = sorted(runtime_names - constraint_names)
    if missing_constraints:
        failures.append(
            f"{MINIMUM_RUNTIME_CONSTRAINTS_PATH.as_posix()}: missing exact constraint(s) "
            f"for runtime dependencies: {', '.join(missing_constraints)}"
        )
    extra_constraints = sorted(constraint_names - runtime_names)
    if extra_constraints:
        failures.append(
            f"{MINIMUM_RUNTIME_CONSTRAINTS_PATH.as_posix()}: unexpected non-runtime "
            f"constraint(s): {', '.join(extra_constraints)}"
        )
    for name in sorted(runtime_names & constraint_names):
        floor = runtime_floors[name].version
        pin = constraint_pins[name].version
        if pin != floor:
            failures.append(
                f"{MINIMUM_RUNTIME_CONSTRAINTS_PATH.as_posix()}: {name} pin {pin} does "
                f"not match declared runtime lower floor {floor}"
            )

    try:
        lock_pins = _minimum_lock_pins(lock_path, direct_names=constraint_names)
    except (OSError, ValueError) as exc:
        failures.append(str(exc))
        return tuple(failures)
    lock_names = frozenset(lock_pins)
    missing_lock_pins = sorted(constraint_names - lock_names)
    if missing_lock_pins:
        failures.append(
            f"{MINIMUM_RUNTIME_LOCK_PATH.as_posix()}: missing direct minimum pin(s): "
            f"{', '.join(missing_lock_pins)}"
        )
    for name in sorted(constraint_names & lock_names):
        constraint = constraint_pins[name].version
        locked = lock_pins[name].version
        if locked != constraint:
            failures.append(
                f"{MINIMUM_RUNTIME_LOCK_PATH.as_posix()}: {name} direct pin {locked} "
                f"does not match minimum constraint {constraint}"
            )
    return tuple(failures)


def installed_minimum_version_errors(project_root: Path = PROJECT_ROOT) -> tuple[str, ...]:
    """Return failures when installed direct runtime versions are not exact floors."""
    constraints_path = project_root / MINIMUM_RUNTIME_CONSTRAINTS_PATH
    if not constraints_path.is_file():
        return (
            f"missing minimum-runtime constraints: {MINIMUM_RUNTIME_CONSTRAINTS_PATH.as_posix()}",
        )
    try:
        constraint_pins = _minimum_constraint_pins(constraints_path)
    except (OSError, ValueError) as exc:
        return (str(exc),)
    failures: list[str] = []
    for name, pin in sorted(constraint_pins.items()):
        try:
            installed_text = distribution_version(pin.declared_name)
        except PackageNotFoundError:
            failures.append(f"installed minimum profile: missing direct dependency {name}")
            continue
        try:
            installed = Version(installed_text)
        except InvalidVersion:
            failures.append(
                f"installed minimum profile: {name} has invalid version {installed_text!r}"
            )
            continue
        if installed != pin.version:
            failures.append(
                f"installed minimum profile: {name} version {installed} does not match "
                f"exact minimum {pin.version}"
            )
    return tuple(failures)


def dependency_lock_freshness_errors(project_root: Path = PROJECT_ROOT) -> tuple[str, ...]:
    """Return source-marker and minimum-profile failures for dependency locks."""
    source_path = project_root / PYPROJECT_PATH
    if not source_path.is_file():
        return (f"missing dependency source: {PYPROJECT_PATH.as_posix()}",)
    source_digest = dependency_input_sha256(source_path)
    failures: list[str] = []
    minimum_constraints_path = project_root / MINIMUM_RUNTIME_CONSTRAINTS_PATH
    minimum_constraints_digest = (
        file_sha256(minimum_constraints_path) if minimum_constraints_path.is_file() else None
    )
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
        if relative_lock != MINIMUM_RUNTIME_LOCK_PATH:
            continue
        if minimum_constraints_digest is None:
            failures.append(
                "missing minimum-runtime constraints: "
                f"{MINIMUM_RUNTIME_CONSTRAINTS_PATH.as_posix()}"
            )
            continue
        constraints_match = _MINIMUM_CONSTRAINTS_DIGEST_RE.search(
            lock_path.read_text(encoding="utf-8")
        )
        if constraints_match is None:
            failures.append(
                f"{relative_lock.as_posix()}: missing "
                f"'# {MINIMUM_CONSTRAINTS_DIGEST_MARKER}: <sha256>' marker"
            )
            continue
        constraints_marker = constraints_match.group("digest")
        if constraints_marker != minimum_constraints_digest:
            failures.append(
                f"{relative_lock.as_posix()}: minimum-runtime constraints marker "
                f"{constraints_marker} does not match "
                f"{MINIMUM_RUNTIME_CONSTRAINTS_PATH.as_posix()} {minimum_constraints_digest}"
            )
    failures.extend(minimum_runtime_profile_errors(project_root))
    return tuple(dict.fromkeys(failures))


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
    parser.add_argument(
        "--verify-installed-minimums",
        action="store_true",
        help=(
            "Also require every installed direct runtime dependency to equal its "
            "declared exact minimum-profile version."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project_root = args.project_root.resolve()
    failures = list(dependency_lock_freshness_errors(project_root))
    if args.verify_installed_minimums:
        failures.extend(installed_minimum_version_errors(project_root))
    failures = list(dict.fromkeys(failures))
    if failures:
        for failure in failures:
            print(f"dependency lock freshness: FAIL: {failure}")
        return 1
    qualification = ""
    if args.verify_installed_minimums:
        qualification = " and installed direct dependencies equal their exact floors"
    print(
        "dependency lock freshness: PASS: all checked-in Python locks bind the "
        f"current pyproject dependency-input projection{qualification}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
