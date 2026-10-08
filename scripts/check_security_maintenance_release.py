"""Non-authorizing diagnostic for reviewing historical maintenance-shaped diffs.

This module is deliberately disconnected from every Make and GitHub publication
path. A successful result cannot authorize a tag, signing, or publication and
cannot replace the active version-bound claim profile, deterministic efficacy,
or release gates.
"""

from __future__ import annotations

import argparse
import re
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.onboarding.diagnostics import bounded_error  # noqa: E402

_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_BASE_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_PROTECTED_PREFIXES = {
    "empirical-evidence": ("evidence/", "study/registration/"),
    "published-study": ("paper/", "docs/measurement/"),
    "claim-media": ("docs/assets/", "docs/social/"),
    "registered-benchmark": ("examples/process_equivalence_benchmark",),
    "study-template": (
        "docs/templates/real_model_study",
        "docs/templates/external_pilot",
    ),
}
_PROTECTED_EXACT = {
    "docs/claim_boundary.md": "claim-contract",
    "docs/claims_traceability_matrix.md": "claim-contract",
    "docs/claims_traceability_matrix.yaml": "claim-contract",
    "docs/control_efficacy.md": "empirical-claim",
    "docs/evidence_carrying_releases.md": "empirical-claim",
    "docs/evidence_sensitivity.md": "empirical-claim",
    "docs/external_pilot.md": "empirical-claim",
    "docs/external_pilot_review.md": "empirical-claim",
    "docs/live_calibration.md": "empirical-claim",
    "docs/real_model_study.md": "empirical-claim",
    "docs/what_this_measures.md": "claim-contract",
}
_RELEASE_NOTE_MARKER = "Release profile: `security-maintenance`"


class SecurityMaintenanceReleaseError(ValueError):
    """Raised when a maintenance-shaped diff fails the non-authorizing diagnostic."""


@dataclass(frozen=True)
class StableVersion:
    major: int
    minor: int
    patch: int


def _stable_version(value: str, *, label: str) -> StableVersion:
    match = _VERSION.fullmatch(value)
    if match is None:
        raise SecurityMaintenanceReleaseError(f"{label} must be a stable X.Y.Z version")
    return StableVersion(*(int(part) for part in match.groups()))


def _git(root: Path, *arguments: str, check: bool = True) -> bytes:
    result = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if check and result.returncode != 0:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release could not verify repository history"
        )
    return result.stdout


def _version_from_pyproject(value: bytes, *, label: str) -> StableVersion:
    try:
        version = tomllib.loads(value.decode("utf-8"))["project"]["version"]
    except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise SecurityMaintenanceReleaseError(
            f"{label} pyproject does not declare a valid project version"
        ) from error
    if not isinstance(version, str):
        raise SecurityMaintenanceReleaseError(f"{label} pyproject project.version must be a string")
    return _stable_version(version, label=label)


def _protected_category(path: str) -> str | None:
    exact = _PROTECTED_EXACT.get(path)
    if exact is not None:
        return exact
    for category, prefixes in _PROTECTED_PREFIXES.items():
        if path.startswith(prefixes):
            return category
    return None


def check_security_maintenance_release(
    *,
    root: Path = ROOT,
    expected_release: str,
    base_tag: str,
) -> tuple[str, ...]:
    """Diagnose a clean, claim-preserving patch-shaped diff against a base tag.

    This historical review helper has no publication authority and does not run
    or replace any standard release gate.
    """

    expected = _stable_version(expected_release, label="expected release")
    tag_match = _BASE_TAG.fullmatch(base_tag)
    if tag_match is None:
        raise SecurityMaintenanceReleaseError("base tag must be an exact stable vX.Y.Z tag")
    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise SecurityMaintenanceReleaseError(
            "security maintenance release requires a clean committed worktree"
        )
    tag_type = (
        _git(root, "cat-file", "-t", f"refs/tags/{base_tag}").decode("ascii", "strict").strip()
    )
    if tag_type != "tag":
        raise SecurityMaintenanceReleaseError("base tag must be an annotated release tag")
    base_commit = _git(root, "rev-parse", "--verify", f"{base_tag}^{{commit}}").strip()
    head_commit = _git(root, "rev-parse", "--verify", "HEAD").strip()
    if base_commit == head_commit:
        raise SecurityMaintenanceReleaseError("maintenance release must change the base release")
    if (
        subprocess.run(
            ("git", "-C", str(root), "merge-base", "--is-ancestor", base_tag, "HEAD"),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        != 0
    ):
        raise SecurityMaintenanceReleaseError(
            "base release must be an ancestor of the maintenance release"
        )
    current = _version_from_pyproject(
        (root / "pyproject.toml").read_bytes(),
        label="current",
    )
    if current != expected:
        raise SecurityMaintenanceReleaseError(
            "expected release does not match the current project version"
        )
    base = _version_from_pyproject(
        _git(root, "show", f"{base_tag}:pyproject.toml"),
        label="base",
    )
    tag_version = StableVersion(*(int(part) for part in tag_match.groups()))
    if base != tag_version:
        raise SecurityMaintenanceReleaseError(
            "base tag does not match its committed project version"
        )
    if (
        expected.major,
        expected.minor,
        expected.patch,
    ) != (base.major, base.minor, base.patch + 1):
        raise SecurityMaintenanceReleaseError(
            "security maintenance releases must be the next patch version"
        )

    raw_paths = _git(
        root,
        "diff",
        "--name-only",
        "--no-renames",
        "-z",
        f"{base_tag}..HEAD",
        "--",
    )
    try:
        changed = tuple(path.decode("utf-8") for path in raw_paths.split(b"\0") if path)
    except UnicodeDecodeError as error:
        raise SecurityMaintenanceReleaseError(
            "changed paths must be valid UTF-8 repository paths"
        ) from error
    protected = sorted(
        {category for path in changed if (category := _protected_category(path)) is not None}
    )
    if protected:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release changes protected claim surfaces: " + ", ".join(protected)
        )

    note_path = f"docs/release_notes/v{expected_release}.md"
    if note_path not in changed:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release must add its versioned release note"
        )
    note = root / note_path
    try:
        note_status = note.lstat()
    except OSError as error:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release note is missing or inaccessible"
        ) from error
    if not stat.S_ISREG(note_status.st_mode) or note_status.st_size > 256_000:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release note must be a bounded regular file"
        )
    try:
        note_lines = note.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release note must be valid UTF-8"
        ) from error
    if _RELEASE_NOTE_MARKER not in note_lines:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release note must declare the maintenance profile "
            "on an exact line"
        )
    metadata = {"CHANGELOG.md", "pyproject.toml", note_path}
    if not set(changed) - metadata:
        raise SecurityMaintenanceReleaseError(
            "security maintenance release must contain a substantive corrective change"
        )
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Diagnose a maintenance-shaped diff without granting publication authority.")
    )
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--base-tag", required=True)
    args = parser.parse_args(argv)
    try:
        changed = check_security_maintenance_release(
            expected_release=args.expected_release,
            base_tag=args.base_tag,
        )
    except (OSError, SecurityMaintenanceReleaseError) as error:
        print(
            f"security maintenance diagnostic failed: {bounded_error(error)}",
            file=sys.stderr,
        )
        return 1
    print(
        "security maintenance diagnostic passed: "
        f"{len(changed)} committed paths reviewed; no publication authority granted"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
