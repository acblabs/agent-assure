from __future__ import annotations

import argparse
import ast
import os
import re
import sys
import tomllib
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_metadata import (  # noqa: E402
    check_citation_release,
    check_readme_action_source,
    check_readme_release,
    parse_changelog,
    readme_release_action_pin,
    require_latest_release,
)

PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_INIT = ROOT / "src" / "agent_assure" / "__init__.py"
SCHEMA_BASE = ROOT / "src" / "agent_assure" / "schema" / "base.py"
SCHEMA_ROOT = ROOT / "schemas"
SECURITY_POLICY = ROOT / "SECURITY.md"
CHANGELOG = ROOT / "CHANGELOG.md"
CITATION = ROOT / "CITATION.cff"
README = ROOT / "README.md"
VERSION_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:rc[1-9]\d*)?$")
SECURITY_VERSION_ROW_PATTERN = re.compile(
    r"^\|\s*(?P<version>(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))"
    r"\s*\|\s*(?P<status>[^|\r\n]+?)\s*\|\s*$"
)
SECURITY_SUPPORTED_VERSIONS_HEADING = "## Supported Versions"
SECURITY_RELEASE_TRANSITION_STATUS = "Supported upon publication; unsupported before publication"
MAX_DIAGNOSTIC_CHARS = 512
MAX_DIAGNOSTIC_SCAN_CHARS = 4096
DIAGNOSTIC_REDACTION = "[REDACTED]"
_DIAGNOSTIC_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(?:api[_-]?key|authorization|credential|password|passwd|secret|token)"
        r"\b\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(r"(?i)\bbearer\s+[^\s,;]+"),
    re.compile(r"(?i)\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"(?i)https?://[^\s/:@]+:[^\s/@]+@"),
    re.compile(
        r"(?i)([?&](?:api[_-]?key|access[_-]?token|auth|password|secret|token)=)"
        r"[^&#\s]+"
    ),
    re.compile(r"(?i)-----BEGIN [^-\r\n]*PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{32,}(?![A-Za-z0-9])"),
)
PACKAGE_SCHEMA_VERSION_OVERRIDES = {
    "0.4.0": "0.3.1",
    "0.4.1": "0.3.1",
    "0.4.2": "0.3.1",
    "0.4.4": "0.4.3",
    "0.7.0": "0.6.6",
}


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        tag = normalize_tag(args.tag or tag_from_environment())
        pyproject_version = read_pyproject_version(args.pyproject)
        package_version = read_package_version(args.package_init)
        package_schema_version = read_schema_version(args.package_init)
        base_schema_version = read_schema_version(args.schema_base)
    except ValueError as exc:
        print(f"version-tag: {bounded_error(exc)}", file=sys.stderr)
        return 1

    expected_tag = f"v{pyproject_version}"
    expected_schema_version = release_schema_version(pyproject_version)
    expected_schema_dir = args.schema_root / f"v{expected_schema_version}"
    failures: list[str] = []
    if args.require_stable and "rc" in pyproject_version:
        failures.append(
            f"production release requires a stable X.Y.Z version, got {pyproject_version!r}"
        )
    elif args.require_stable:
        failures.extend(
            check_security_support_transition(
                args.security,
                release_version=pyproject_version,
            )
        )
        failures.extend(
            check_release_collateral(
                changelog_path=args.changelog,
                citation_path=args.citation,
                readme_path=args.readme,
                repository_root=args.repository_root,
                release_version=pyproject_version,
            )
        )
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
            f"frozen schema directory missing for release version: {expected_schema_dir}"
        )
    if failures:
        for failure in failures:
            print(f"version-tag: {bounded_text(failure)}", file=sys.stderr)
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
    parser.add_argument(
        "--security",
        type=Path,
        default=SECURITY_POLICY,
        help=(
            "Path to SECURITY.md. Read only with --require-stable to verify "
            "truth-preserving support-table transition rows."
        ),
    )
    parser.add_argument(
        "--changelog",
        type=Path,
        default=CHANGELOG,
        help=(
            "Path to CHANGELOG.md. Read only with --require-stable to bind the "
            "stable package/tag version to the canonical latest dated release."
        ),
    )
    parser.add_argument(
        "--citation",
        type=Path,
        default=CITATION,
        help=(
            "Path to CITATION.cff. Read only with --require-stable to bind its "
            "release version and date to CHANGELOG.md."
        ),
    )
    parser.add_argument(
        "--readme",
        type=Path,
        default=README,
        help=(
            "Path to README.md. Read only with --require-stable to bind its package "
            "and immutable action pins to CHANGELOG.md."
        ),
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=ROOT,
        help=(
            "Git repository used with --require-stable to prove the README action "
            "pin is an ancestor with the exact release-target action tree."
        ),
    )
    parser.add_argument(
        "--require-stable",
        action="store_true",
        help="Reject release-candidate versions on production publication paths.",
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
    base_version = package_version.split("rc", 1)[0]
    return PACKAGE_SCHEMA_VERSION_OVERRIDES.get(base_version, base_version)


def check_release_collateral(
    *,
    changelog_path: Path,
    citation_path: Path,
    readme_path: Path,
    repository_root: Path,
    release_version: str,
) -> list[str]:
    """Validate stable release identity across canonical public collateral."""

    try:
        changelog_text = changelog_path.read_text(encoding="utf-8")
        changelog = parse_changelog(changelog_text, source=str(changelog_path))
        latest = require_latest_release(
            changelog,
            expected_version=release_version,
            source=str(changelog_path),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return [f"stable release collateral is invalid: {bounded_error(exc)}"]

    failures: list[str] = []
    try:
        citation_text = citation_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        failures.append(f"could not read release citation {citation_path}: {bounded_error(exc)}")
    else:
        failures.extend(
            check_citation_release(
                citation_text,
                expected=latest,
                source=str(citation_path),
            )
        )
    try:
        readme_text = readme_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        failures.append(f"could not read release README {readme_path}: {bounded_error(exc)}")
    else:
        readme_failures = check_readme_release(
            readme_text,
            expected=latest,
            source=str(readme_path),
        )
        failures.extend(readme_failures)
        if not readme_failures:
            pin = readme_release_action_pin(readme_text, source=str(readme_path))
            failures.extend(
                check_readme_action_source(
                    repository_root,
                    release_version=latest.version,
                    pinned_commit=pin.commit_sha,
                    source=str(readme_path),
                )
            )
    return failures


def check_security_support_transition(
    path: Path,
    *,
    release_version: str,
) -> list[str]:
    """Validate publication-conditional support rows for a stable release."""

    validate_version(release_version, source="security support release version")
    if "rc" in release_version:
        raise ValueError("security support transition requires a stable X.Y.Z version")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"could not read security support policy {path}: {bounded_error(exc)}"]

    heading_matches = list(
        re.finditer(
            rf"(?m)^{re.escape(SECURITY_SUPPORTED_VERSIONS_HEADING)}\s*$",
            text,
        )
    )
    if len(heading_matches) != 1:
        return [f"{path} must contain exactly one {SECURITY_SUPPORTED_VERSIONS_HEADING!r} section"]

    section_start = heading_matches[0].end()
    next_heading = re.search(r"(?m)^##\s+", text[section_start:])
    section_end = section_start + next_heading.start() if next_heading is not None else len(text)
    section = text[section_start:section_end]

    rows: dict[str, list[str]] = {}
    for line in section.splitlines():
        match = SECURITY_VERSION_ROW_PATTERN.fullmatch(line.strip())
        if match is None:
            continue
        version = match.group("version")
        status = " ".join(match.group("status").split())
        rows.setdefault(version, []).append(status)

    failures: list[str] = []
    for version, statuses in sorted(rows.items(), key=lambda item: _stable_version_key(item[0])):
        if len(statuses) != 1:
            failures.append(f"{path} contains duplicate support rows for {version}")

    release_statuses = rows.get(release_version)
    if release_statuses is None:
        failures.append(f"{path} is missing a support row for release {release_version}")
    elif release_statuses[0] != SECURITY_RELEASE_TRANSITION_STATUS:
        failures.append(
            f"{path} support row for {release_version} must be "
            f"{SECURITY_RELEASE_TRANSITION_STATUS!r}"
        )

    release_key = _stable_version_key(release_version)
    higher_versions = [version for version in rows if _stable_version_key(version) > release_key]
    if higher_versions:
        failures.append(
            f"{path} release {release_version} must be the highest explicit support-table "
            f"version; found {', '.join(sorted(higher_versions, key=_stable_version_key))}"
        )

    prior_versions = [version for version in rows if _stable_version_key(version) < release_key]
    if not prior_versions:
        failures.append(
            f"{path} is missing the previously supported version below {release_version}"
        )
    else:
        predecessor = max(prior_versions, key=_stable_version_key)
        predecessor_status = rows[predecessor][0]
        expected_predecessor_status = (
            f"Supported only until {release_version} is published; unsupported thereafter"
        )
        if predecessor_status != expected_predecessor_status:
            failures.append(
                f"{path} support row for predecessor {predecessor} must be "
                f"{expected_predecessor_status!r}"
            )

    return failures


def _stable_version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


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


def bounded_error(
    exc: BaseException,
    *,
    fallback: str = "bounded validation error",
) -> str:
    """Return one stdlib-only, redacted, terminal-safe exception summary."""

    return bounded_text(exc, fallback=fallback)


def bounded_text(
    value: object,
    *,
    fallback: str = "bounded diagnostic",
) -> str:
    """Return bounded terminal-safe text without importing package code."""

    candidate = str(value)[:MAX_DIAGNOSTIC_SCAN_CHARS]
    without_controls = "".join(
        (
            " "
            if character.isspace()
            else ""
            if unicodedata.category(character).startswith("C")
            else character
        )
        for character in candidate
    )
    normalized = " ".join(without_controls.split())
    for pattern in _DIAGNOSTIC_SECRET_PATTERNS:
        normalized = pattern.sub(DIAGNOSTIC_REDACTION, normalized)
    return (normalized or fallback)[:MAX_DIAGNOSTIC_CHARS]


def validate_version(version: str, *, source: str) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(
            f"{source} must match X.Y.Z or X.Y.ZrcN with no shell metacharacters: {version!r}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
