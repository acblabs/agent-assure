from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_version_matches_tag import release_schema_version  # noqa: E402
from scripts.schema_versions import active_schema_version, frozen_schema_versions  # noqa: E402

_FINAL_RELEASE_TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

# v0.1.0 predates the immutable-snapshot policy and was expanded once before
# stabilizing in v0.2.0. Use that release as its explicit immutable baseline.
_HISTORICAL_STABILIZATION_BASELINES = {"v0.1.0": "v0.2.0"}
_SUPERSEDED_BASELINE_TAGS = frozenset({"v0.1.0"})


@dataclass(frozen=True)
class TaggedSchemaCheck:
    failures: tuple[str, ...]
    protected_releases: tuple[str, ...]
    unprotected_versions: tuple[str, ...]
    repository_available: bool


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    repo_root = args.repo_root.resolve()
    schema_root = args.schema_root
    if not schema_root.is_absolute():
        schema_root = repo_root / schema_root

    result = check_tagged_schema_immutability(
        repo_root=repo_root,
        schema_root=schema_root.resolve(),
    )
    if result.failures:
        for failure in result.failures:
            print(f"schema-immutability: {failure}", file=sys.stderr)
        print(
            "schema-immutability: released schema snapshots are immutable; "
            "restore the tagged contents",
            file=sys.stderr,
        )
        return 1

    if not result.repository_available:
        if args.require_release_tags:
            print(
                "schema-immutability: a Git work tree with release tags is required",
                file=sys.stderr,
            )
            return 1
        print(
            "schema-immutability: skipped "
            "(no local Git work tree; no release-tag baseline is available)"
        )
        return 0
    if not result.protected_releases:
        if args.require_release_tags:
            print(
                "schema-immutability: no protected final release tags are available locally",
                file=sys.stderr,
            )
            return 1
        print(
            "schema-immutability: skipped "
            "(no protected final release tags are available locally)"
        )
        return 0

    if args.require_release_tags:
        try:
            active_version = f"v{active_schema_version(_schema_base(repo_root))}"
        except (OSError, ValueError) as exc:
            print(
                f"schema-immutability: could not determine the active schema version: {exc}",
                file=sys.stderr,
            )
            return 1
        current_versions = frozen_schema_versions(schema_root)
        if active_version not in current_versions:
            print(
                "schema-immutability: active schema snapshot is missing: "
                f"{active_version}",
                file=sys.stderr,
            )
            return 1
        missing_baselines = tuple(
            version
            for version in result.unprotected_versions
            if version != active_version
        )
        if missing_baselines:
            print(
                "schema-immutability: released schema snapshots have no local tag "
                f"baseline: {', '.join(missing_baselines)}",
                file=sys.stderr,
            )
            return 1

    unprotected = (
        ", ".join(result.unprotected_versions)
        if result.unprotected_versions
        else "none"
    )
    print(
        "schema-immutability: ok "
        f"({len(result.protected_releases)} release baselines; "
        f"unprotected schema candidates: {unprotected})"
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare released schema directories with their local Git tag baselines. "
            "The check is offline and skips when no local release tags are available."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Git work-tree root. Defaults to the repository containing this script.",
    )
    parser.add_argument(
        "--schema-root",
        type=Path,
        default=Path("schemas"),
        help="Schema snapshot directory, absolute or relative to --repo-root.",
    )
    parser.add_argument(
        "--require-release-tags",
        action="store_true",
        help=(
            "Fail instead of skipping when Git history or protected final release "
            "tags are unavailable. Intended for the full-history CI check."
        ),
    )
    return parser.parse_args(argv)


def check_tagged_schema_immutability(
    *,
    repo_root: Path,
    schema_root: Path,
) -> TaggedSchemaCheck:
    current_versions = frozen_schema_versions(schema_root)
    if not _is_git_work_tree(repo_root):
        return TaggedSchemaCheck(
            failures=(),
            protected_releases=(),
            unprotected_versions=current_versions,
            repository_available=False,
        )

    try:
        schema_prefix = schema_root.relative_to(repo_root).as_posix()
    except ValueError:
        return TaggedSchemaCheck(
            failures=(f"schema root is outside the Git work tree: {schema_root}",),
            protected_releases=(),
            unprotected_versions=current_versions,
            repository_available=True,
        )

    tags_result = _git(repo_root, "tag", "--list", "v*")
    if tags_result.returncode != 0:
        return TaggedSchemaCheck(
            failures=(f"could not list local Git tags: {_stderr(tags_result)}",),
            protected_releases=(),
            unprotected_versions=current_versions,
            repository_available=True,
        )

    tags = sorted(
        tag
        for tag in tags_result.stdout.decode("utf-8").splitlines()
        if _FINAL_RELEASE_TAG.fullmatch(tag)
    )
    available_tags = set(tags)
    baselines = [
        (tag, f"v{release_schema_version(tag[1:])}")
        for tag in tags
        if tag not in _SUPERSEDED_BASELINE_TAGS
    ]
    baselines.extend(
        (baseline_tag, schema_version)
        for schema_version, baseline_tag in _HISTORICAL_STABILIZATION_BASELINES.items()
        if baseline_tag in available_tags
    )
    failures: list[str] = []
    protected_releases: list[str] = []
    protected_versions: set[str] = set()
    for tag, schema_version in sorted(baselines):
        relative_dir = f"{schema_prefix}/{schema_version}"
        tagged_files, tree_failure = _tagged_blob_ids(repo_root, tag, relative_dir)
        if tree_failure is not None:
            failures.append(tree_failure)
            continue
        if not tagged_files:
            failures.append(
                f"{tag} does not contain its mapped schema snapshot {relative_dir}"
            )
            continue

        protected_releases.append(f"{tag} -> {schema_version}")
        protected_versions.add(schema_version)
        current_dir = schema_root / schema_version
        current_files = _working_tree_files(current_dir, prefix=relative_dir)
        failures.extend(
            _compare_tagged_schema(
                repo_root=repo_root,
                tag=tag,
                tagged_files=tagged_files,
                current_files=current_files,
            )
        )

    return TaggedSchemaCheck(
        failures=tuple(failures),
        protected_releases=tuple(protected_releases),
        unprotected_versions=tuple(
            version for version in current_versions if version not in protected_versions
        ),
        repository_available=True,
    )


def _compare_tagged_schema(
    *,
    repo_root: Path,
    tag: str,
    tagged_files: dict[str, str],
    current_files: dict[str, Path],
) -> list[str]:
    failures: list[str] = []
    tagged_paths = set(tagged_files)
    current_paths = set(current_files)
    for path in sorted(tagged_paths - current_paths):
        failures.append(f"released schema removed since {tag}: {path}")
    for path in sorted(current_paths - tagged_paths):
        failures.append(f"released schema file added after {tag}: {path}")
    for path in sorted(tagged_paths & current_paths):
        hash_result = _git(
            repo_root,
            "hash-object",
            f"--path={path}",
            str(current_files[path]),
        )
        if hash_result.returncode != 0:
            failures.append(
                f"could not hash released schema {path}: {_stderr(hash_result)}"
            )
            continue
        working_blob = hash_result.stdout.decode("ascii").strip()
        if working_blob != tagged_files[path]:
            failures.append(f"released schema drift from {tag}: {path}")
    return failures


def _tagged_blob_ids(
    repo_root: Path,
    tag: str,
    relative_dir: str,
) -> tuple[dict[str, str], str | None]:
    result = _git(
        repo_root,
        "ls-tree",
        "-r",
        "-z",
        f"refs/tags/{tag}",
        "--",
        relative_dir,
    )
    if result.returncode != 0:
        return {}, f"could not read schema snapshot from {tag}: {_stderr(result)}"

    files: dict[str, str] = {}
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3 or fields[1] != b"blob":
            return {}, f"unexpected Git tree entry while reading {tag}"
        path = raw_path.decode("utf-8")
        files[path] = fields[2].decode("ascii")
    return files, None


def _working_tree_files(directory: Path, *, prefix: str) -> dict[str, Path]:
    if not directory.is_dir():
        return {}
    return {
        f"{prefix}/{path.relative_to(directory).as_posix()}": path
        for path in directory.rglob("*")
        if path.is_file()
    }


def _is_git_work_tree(repo_root: Path) -> bool:
    result = _git(repo_root, "rev-parse", "--show-toplevel")
    if result.returncode != 0:
        return False
    discovered_root = Path(result.stdout.decode("utf-8").strip()).resolve()
    return discovered_root == repo_root.resolve()


def _schema_base(repo_root: Path) -> Path:
    return repo_root / "src" / "agent_assure" / "schema" / "base.py"


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(
            args=["git", *args],
            returncode=127,
            stdout=b"",
            stderr=str(exc).encode("utf-8", errors="replace"),
        )


def _stderr(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stderr.decode("utf-8", errors="replace").strip() or "unknown Git error"


if __name__ == "__main__":
    raise SystemExit(main())
