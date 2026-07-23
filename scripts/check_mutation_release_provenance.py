from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.artifact_io import git_output  # noqa: E402
from agent_assure.mutation.catalog import (  # noqa: E402
    CatalogIntegrityError,
    implementation_component_sha256,
    introduction_components_from_source,
    lf_normalized_sha256,
    registered_operators,
    target_control_component_path,
)
from agent_assure.schema.mutation import OperatorProvenance  # noqa: E402

CreationSourceLoader = Callable[[str, str], bytes]
RevisionAncestryChecker = Callable[[str, str], bool]

_INTRODUCTION_BINDING_PATHS = (
    "agent_assure/mutation/catalog.py",
    "agent_assure/mutation/operators.py",
)
_INTRODUCTION_SNAPSHOT_PATH = "agent_assure/mutation/introduction_snapshots.json"
_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:rc([1-9]\d*))?$"
)
_GIT_COMMIT_PATTERN = re.compile(r"^(?:git:)?[a-f0-9]{40}$")


def release_provenance_failures(
    provenances: Iterable[OperatorProvenance],
    *,
    expected_release: str,
    release_commit: str | None = None,
    creation_source_loader: CreationSourceLoader | None = None,
    ancestry_checker: RevisionAncestryChecker | None = None,
) -> tuple[str, ...]:
    """Return deterministic failures that make an operator unsafe to release."""
    try:
        expected_release_precedence = _semver_precedence(expected_release)
    except ValueError:
        raise ValueError(
            f"invalid expected release version: {expected_release!r}"
        ) from None
    failures: list[str] = []
    source_cache: dict[tuple[str, str], bytes] = {}

    def load_source(commit: str, relative_path: str) -> bytes:
        key = (commit, relative_path)
        if key not in source_cache:
            if creation_source_loader is None:
                raise RuntimeError("no revision source loader")
            source_cache[key] = creation_source_loader(commit, relative_path)
        return source_cache[key]

    for provenance in sorted(provenances, key=lambda item: item.operator_id):
        prefix = f"operator {provenance.operator_id!r}"
        introduction_commit = provenance.introduced_at_commit
        immutable_commit = (
            introduction_commit
            if introduction_commit is not None and introduction_commit != "git:uncommitted"
            else None
        )
        if immutable_commit is None:
            failures.append(f"{prefix} has no immutable introduction commit")
        if provenance.introduced_in_release is None:
            failures.append(f"{prefix} has no introduction release")
        else:
            try:
                introduction_precedence = _semver_precedence(
                    provenance.introduced_in_release
                )
            except ValueError:
                failures.append(f"{prefix} has an invalid introduction release")
            else:
                if introduction_precedence > expected_release_precedence:
                    failures.append(
                        f"{prefix} introduction release "
                        f"{provenance.introduced_in_release!r} is newer than expected "
                        f"release {expected_release!r}"
                    )
        if not provenance.implementation_components:
            failures.append(f"{prefix} has no implementation-component manifest")
        if not provenance.introduction_components:
            failures.append(f"{prefix} has no introduction-component snapshot")
        if not provenance.target_controls:
            failures.append(f"{prefix} has no target-control provenance")
        if immutable_commit is not None:
            ancestry_failure = _revision_ancestry_failure(
                prefix,
                ancestor=immutable_commit,
                descendant=release_commit,
                relationship="introduction commit is not an ancestor of the release commit",
                checker=ancestry_checker,
            )
            if ancestry_failure is not None:
                failures.append(ancestry_failure)
        if immutable_commit is not None and provenance.introduction_components:
            implementation_failure = _introduction_snapshot_failure(
                provenance,
                immutable_commit=immutable_commit,
                source_loader=(load_source if creation_source_loader is not None else None),
            )
            if implementation_failure is not None:
                failures.append(implementation_failure)
        for target in provenance.target_controls:
            target_prefix = f"{prefix} target control {target.control_id!r}"
            if immutable_commit is not None:
                ancestry_failure = _revision_ancestry_failure(
                    target_prefix,
                    ancestor=target.first_seen_commit,
                    descendant=immutable_commit,
                    relationship=(
                        "first-seen commit is not an ancestor of the operator "
                        "introduction commit"
                    ),
                    checker=ancestry_checker,
                )
                if ancestry_failure is not None:
                    failures.append(ancestry_failure)
            if target.digest_at_operator_creation == "0" * 64:
                failures.append(f"{target_prefix} has no authored creation digest")
                continue
            if immutable_commit is None:
                continue
            try:
                source_path = target_control_component_path(target.control_id)
            except CatalogIntegrityError:
                failures.append(f"{target_prefix} has no provenance source mapping")
                continue
            if creation_source_loader is None:
                failures.append(f"{target_prefix} creation digest was not verified")
                continue
            try:
                source = load_source(immutable_commit, source_path)
            except Exception:
                failures.append(f"{target_prefix} source is unavailable at the introduction commit")
                continue
            if lf_normalized_sha256(source) != target.digest_at_operator_creation:
                failures.append(
                    f"{target_prefix} creation digest does not match the introduction commit"
                )
    return tuple(failures)


def _semver_precedence(value: str) -> tuple[int, int, int, int, int]:
    match = _SEMVER_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(value)
    major, minor, patch, release_candidate = match.groups()
    return (
        int(major),
        int(minor),
        int(patch),
        1 if release_candidate is None else 0,
        int(release_candidate or 0),
    )


def _revision_ancestry_failure(
    prefix: str,
    *,
    ancestor: str,
    descendant: str | None,
    relationship: str,
    checker: RevisionAncestryChecker | None,
) -> str | None:
    if descendant is None or checker is None:
        return f"{prefix} revision ancestry was not verified"
    try:
        is_ancestor = checker(ancestor, descendant)
    except Exception:
        return f"{prefix} revision ancestry could not be verified"
    if not is_ancestor:
        return f"{prefix} {relationship}"
    return None


def _introduction_snapshot_failure(
    provenance: OperatorProvenance,
    *,
    immutable_commit: str,
    source_loader: CreationSourceLoader | None,
) -> str | None:
    """Verify the authored introduction snapshot at the claimed commit.

    The current implementation manifest identifies the implementation being
    released. It is intentionally not replayed against an older introduction
    commit: legitimate maintenance changes its bytes. This separate, frozen
    snapshot proves that the catalog and transformation bindings existed when
    the operator claims to have been introduced.
    """
    prefix = f"operator {provenance.operator_id!r}"
    components_by_path = {
        component.relative_path: component
        for component in provenance.introduction_components
    }
    for relative_path in _INTRODUCTION_BINDING_PATHS:
        if relative_path not in components_by_path:
            return f"{prefix} introduction snapshot does not bind {relative_path!r}"
    if source_loader is None:
        return f"{prefix} introduction snapshot was not verified"
    try:
        snapshot_source = source_loader(immutable_commit, _INTRODUCTION_SNAPSHOT_PATH)
    except Exception:
        return (
            f"{prefix} authored introduction snapshot is unavailable at the "
            "introduction commit"
        )
    try:
        authored_components = introduction_components_from_source(
            provenance.operator_id,
            snapshot_source,
        )
    except CatalogIntegrityError:
        return (
            f"{prefix} authored introduction snapshot is invalid at the introduction commit"
        )
    if authored_components != provenance.introduction_components:
        return (
            f"{prefix} introduction components do not match the snapshot authored "
            "at introduction"
        )

    binding_order = {path: index for index, path in enumerate(_INTRODUCTION_BINDING_PATHS)}
    components = sorted(
        provenance.introduction_components,
        key=lambda item: (
            binding_order.get(item.relative_path, len(binding_order)),
            item.component_id,
            item.relative_path,
        ),
    )
    for component in components:
        component_prefix = f"{prefix} introduction component {component.relative_path!r}"
        try:
            source = source_loader(immutable_commit, component.relative_path)
        except Exception:
            return f"{component_prefix} source is unavailable at the introduction commit"
        if (
            implementation_component_sha256(component.relative_path, source)
            != component.sha256
        ):
            return f"{component_prefix} digest does not match the introduction commit"
    return None


def registered_release_provenance_failures(
    *,
    expected_release: str,
    release_commit: str | None = None,
) -> tuple[str, ...]:
    try:
        provenances = tuple(item.descriptor.provenance for item in registered_operators())
    except CatalogIntegrityError:
        return ("built-in mutation catalog integrity could not be established",)
    if release_commit is None:
        current_commit = git_output(ROOT, "rev-parse", "HEAD")
        if current_commit is None:
            return ("release commit could not be resolved for provenance validation",)
        release_commit = f"git:{current_commit}"
    elif _GIT_COMMIT_PATTERN.fullmatch(release_commit) is None:
        return (f"release commit is not an immutable Git commit: {release_commit!r}",)
    return release_provenance_failures(
        provenances,
        expected_release=expected_release,
        release_commit=release_commit,
        creation_source_loader=_git_creation_source,
        ancestry_checker=_git_is_ancestor,
    )


def _git_creation_source(commit: str, relative_path: str) -> bytes:
    revision = commit.removeprefix("git:")
    if _GIT_COMMIT_PATTERN.fullmatch(revision) is None:
        raise ValueError(f"invalid provenance commit: {commit!r}")
    if "\\" in relative_path or ".." in relative_path.split("/"):
        raise ValueError(f"unsafe provenance component path: {relative_path!r}")
    if relative_path.startswith("agent_assure/"):
        repository_path = f"src/{relative_path}"
    elif relative_path.startswith("schemas/"):
        repository_path = relative_path
    else:
        raise ValueError(f"unsupported provenance component path: {relative_path!r}")
    result = subprocess.run(
        ["git", "show", f"{revision}:{repository_path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return result.stdout


def _git_is_ancestor(ancestor: str, descendant: str) -> bool:
    ancestor_revision = ancestor.removeprefix("git:")
    descendant_revision = descendant.removeprefix("git:")
    return (
        git_output(
            ROOT,
            "merge-base",
            "--is-ancestor",
            ancestor_revision,
            descendant_revision,
            allow_empty=True,
        )
        is not None
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate mutation provenance against a concrete release version."
    )
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--release-commit", default=None)
    args = parser.parse_args(argv)
    failures = registered_release_provenance_failures(
        expected_release=args.expected_release,
        release_commit=args.release_commit,
    )
    if failures:
        print("mutation release provenance is incomplete:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("mutation release provenance is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
