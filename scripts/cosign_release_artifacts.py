from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for import_path in (ROOT, SRC):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from agent_assure.artifact_io import (  # noqa: E402
    ensure_unlinked_directory,
    git_file_bytes,
    git_output,
    write_bytes_atomic,
)
from agent_assure.io_limits import (  # noqa: E402
    BoundedFileContents,
    open_directory_at,
    read_file_bounded,
    read_file_bounded_at,
)
from agent_assure.release_evidence import (  # noqa: E402
    core_release_roles_for_schema_version,
    load_digest_replay,
    verify_digest_replay,
)
from agent_assure.reporting.packet import (  # noqa: E402
    load_evidence_packet,
    packet_summary_files_binding_error,
    render_evidence_packet_markdown,
)
from agent_assure.schema.packet import EvidencePacket  # noqa: E402
from agent_assure.schema.release import (  # noqa: E402
    ReleaseArtifactManifest,
    ReleaseDigestReplay,
)
from agent_assure.schema.validation import (  # noqa: E402
    load_validated_artifact_payload,
    project_validated_artifact_payload,
)

DEFAULT_RELEASE_DIR = ROOT / ".tmp" / "release"
DEFAULT_ISSUER = "https://token.actions.githubusercontent.com"
MAX_RELEASE_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_RELEASE_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_RELEASE_TREE_ENTRIES = 4_096
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_BACKSLASH = "\\"


@dataclass(frozen=True)
class _ReleaseBundleSnapshot:
    files: tuple[tuple[str, BoundedFileContents], ...]
    distribution_paths: tuple[str, str]
    artifact_root: Path


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    release_dir = _resolve_path(args.release_dir)
    try:
        if args.command == "sign":
            sign_artifacts(release_dir, cosign=args.cosign)
        elif args.command == "verify":
            verify_artifacts(
                release_dir,
                cosign=args.cosign,
                workflow_name=args.workflow_name,
                workflow_path=args.workflow_path,
                repository=args.repository,
                ref=args.ref,
                sha=args.sha,
                event_name=args.event_name,
                issuer=args.issuer,
                require_release_notes=args.require_release_notes,
            )
        elif args.command == "verify-and-promote":
            if args.promotion_dir is None:
                raise ValueError("--promotion-dir is required for verify-and-promote")
            verify_and_promote_artifacts(
                release_dir,
                promotion_dir=_resolve_path(args.promotion_dir),
                cosign=args.cosign,
                workflow_name=args.workflow_name,
                workflow_path=args.workflow_path,
                repository=args.repository,
                ref=args.ref,
                sha=args.sha,
                event_name=args.event_name,
                issuer=args.issuer,
                require_release_notes=args.require_release_notes,
            )
        elif args.command == "verify-uploaded":
            verify_uploaded_artifacts(
                release_dir,
                distributions_dir=(
                    _resolve_path(args.distributions_dir)
                    if args.distributions_dir is not None
                    else None
                ),
                cosign=args.cosign,
                workflow_name=args.workflow_name,
                workflow_path=args.workflow_path,
                repository=args.repository,
                ref=args.ref,
                sha=args.sha,
                event_name=args.event_name,
                issuer=args.issuer,
                require_release_notes=args.require_release_notes,
            )
        elif args.command == "verify-modified-fails":
            verify_modified_packet_fails(
                release_dir,
                cosign=args.cosign,
                workflow_name=args.workflow_name,
                workflow_path=args.workflow_path,
                repository=args.repository,
                ref=args.ref,
                sha=args.sha,
                event_name=args.event_name,
                issuer=args.issuer,
            )
        else:
            raise ValueError(f"unknown command: {args.command}")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"cosign-release-artifacts: {exc}", file=sys.stderr)
        for note in getattr(exc, "__notes__", ()):
            print(f"cosign-release-artifacts: note: {note}", file=sys.stderr)
        return 1
    return 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign or verify agent-assure release artifacts with cosign."
    )
    parser.add_argument(
        "command",
        choices=(
            "sign",
            "verify",
            "verify-and-promote",
            "verify-uploaded",
            "verify-modified-fails",
        ),
    )
    parser.add_argument("--release-dir", type=Path, default=DEFAULT_RELEASE_DIR)
    parser.add_argument(
        "--promotion-dir",
        type=Path,
        help=(
            "Fresh destination for an atomically promoted release/ tree and "
            "two-file distributions/ tree."
        ),
    )
    parser.add_argument(
        "--distributions-dir",
        type=Path,
        help=(
            "Optional independently uploaded flat distribution directory; when "
            "provided, require exactly the wheel and sdist from the verified full bundle."
        ),
    )
    parser.add_argument("--cosign", default="cosign")
    parser.add_argument("--workflow-name", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME", ""))
    parser.add_argument("--issuer", default=DEFAULT_ISSUER)
    parser.add_argument(
        "--require-release-notes",
        action="store_true",
        help=(
            "Require tag release notes and bind them to the immutable source blob; "
            "used by the release workflow, not evidence-only signing."
        ),
    )
    return parser.parse_args(argv)


def sign_artifacts(release_dir: Path, *, cosign: str) -> None:
    for artifact in release_artifacts(release_dir):
        _run(
            [
                cosign,
                "sign-blob",
                "--yes",
                "--bundle",
                str(bundle_path(artifact)),
                str(artifact),
            ]
        )


def verify_artifacts(
    release_dir: Path,
    *,
    cosign: str,
    workflow_name: str,
    workflow_path: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    issuer: str,
    require_release_notes: bool = False,
    artifact_root: Path | None = None,
) -> None:
    identity = workflow_identity(repository=repository, workflow_path=workflow_path, ref=ref)
    for artifact in release_artifacts(release_dir):
        verify_blob(
            artifact,
            cosign=cosign,
            identity=identity,
            issuer=issuer,
            workflow_name=workflow_name,
            repository=repository,
            ref=ref,
            sha=sha,
            event_name=event_name,
        )
    verify_release_bundle_bindings(
        release_dir,
        expected_ref=ref,
        expected_sha=sha,
        require_release_notes=require_release_notes,
        artifact_root=artifact_root,
    )


def verify_and_promote_artifacts(
    release_dir: Path,
    *,
    promotion_dir: Path,
    cosign: str,
    workflow_name: str,
    workflow_path: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    issuer: str,
    require_release_notes: bool = False,
) -> None:
    """Verify one descriptor-backed snapshot and atomically publish immutable views."""

    snapshot = _capture_release_bundle_snapshot(release_dir)
    destination = _fresh_promotion_destination(
        promotion_dir,
        release_dir=release_dir,
    )
    work_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
    )
    try:
        staged_release, _ = _verify_staged_release_snapshot(
            snapshot,
            release_dir=release_dir,
            work_dir=work_dir,
            cosign=cosign,
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            repository=repository,
            ref=ref,
            sha=sha,
            event_name=event_name,
            issuer=issuer,
            require_release_notes=require_release_notes,
        )

        promotion_stage = work_dir / "promotion"
        promoted_release = promotion_stage / "release"
        promoted_distributions = promotion_stage / "distributions"
        promotion_stage.mkdir()
        _stage_distribution_snapshot(snapshot, promoted_distributions)
        os.replace(staged_release, promoted_release)
        _require_snapshot_bytes(snapshot, promoted_release)
        _require_exact_release_tree(
            promoted_release,
            expected_files=tuple(path for path, _ in snapshot.files),
        )
        _require_distribution_snapshot(snapshot, promoted_distributions)

        if os.path.lexists(destination):
            raise RuntimeError(f"promotion destination already exists: {destination}")
        os.replace(promotion_stage, destination)
    except OSError as exc:
        raise RuntimeError(f"verified release snapshot promotion failed: {exc}") from exc
    finally:
        _remove_private_work_directory(work_dir, primary_error=sys.exception())


def verify_uploaded_artifacts(
    release_dir: Path,
    *,
    distributions_dir: Path | None,
    cosign: str,
    workflow_name: str,
    workflow_path: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    issuer: str,
    require_release_notes: bool = False,
) -> None:
    """Verify immutable uploaded views without creating another publish artifact."""

    if distributions_dir is not None:
        _require_disjoint_uploaded_views(release_dir, distributions_dir)
    snapshot = _capture_release_bundle_snapshot(release_dir)
    if distributions_dir is not None:
        _require_distribution_snapshot(snapshot, distributions_dir)

    ensure_unlinked_directory(release_dir.parent)
    work_dir = Path(
        tempfile.mkdtemp(
            prefix=".post-upload-verification.",
            dir=release_dir.parent.resolve(strict=True),
        )
    )
    try:
        _verify_staged_release_snapshot(
            snapshot,
            release_dir=release_dir,
            work_dir=work_dir,
            cosign=cosign,
            workflow_name=workflow_name,
            workflow_path=workflow_path,
            repository=repository,
            ref=ref,
            sha=sha,
            event_name=event_name,
            issuer=issuer,
            require_release_notes=require_release_notes,
        )
        _require_verified_snapshot_unchanged(
            snapshot,
            release_dir=release_dir,
            artifact_root=snapshot.artifact_root,
        )
        if distributions_dir is not None:
            _require_distribution_snapshot(snapshot, distributions_dir)
    except OSError as exc:
        raise RuntimeError(f"uploaded release verification failed: {exc}") from exc
    finally:
        _remove_private_work_directory(work_dir, primary_error=sys.exception())


def _verify_staged_release_snapshot(
    snapshot: _ReleaseBundleSnapshot,
    *,
    release_dir: Path,
    work_dir: Path,
    cosign: str,
    workflow_name: str,
    workflow_path: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    issuer: str,
    require_release_notes: bool,
) -> tuple[Path, Path]:
    staged_release, staged_artifact_root = _stage_verification_snapshot(
        snapshot,
        release_dir=release_dir,
        work_dir=work_dir,
    )
    verify_artifacts(
        staged_release,
        cosign=cosign,
        workflow_name=workflow_name,
        workflow_path=workflow_path,
        repository=repository,
        ref=ref,
        sha=sha,
        event_name=event_name,
        issuer=issuer,
        require_release_notes=require_release_notes,
        artifact_root=staged_artifact_root,
    )
    _require_verified_snapshot_unchanged(
        snapshot,
        release_dir=staged_release,
        artifact_root=staged_artifact_root,
    )
    return staged_release, staged_artifact_root


def _capture_release_bundle_snapshot(release_dir: Path) -> _ReleaseBundleSnapshot:
    _regular_tree_inventory(release_dir, label="release tree")
    paths, distribution_paths, artifact_root = _release_bundle_paths(release_dir)
    _require_exact_release_tree(release_dir, expected_files=paths)
    captured: list[tuple[str, BoundedFileContents]] = []
    total_bytes = 0
    for relative_path in paths:
        contents = read_file_bounded_at(
            release_dir,
            relative_path,
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label=f"release snapshot artifact {relative_path}",
        )
        total_bytes += contents.size
        if total_bytes > MAX_RELEASE_BUNDLE_BYTES:
            raise ValueError("release snapshot exceeds maximum supported total size")
        captured.append((relative_path, contents))
    _require_exact_release_tree(release_dir, expected_files=paths)
    return _ReleaseBundleSnapshot(
        files=tuple(captured),
        distribution_paths=distribution_paths,
        artifact_root=artifact_root,
    )


def _release_bundle_paths(
    release_dir: Path,
    *,
    artifact_root: Path | None = None,
) -> tuple[tuple[str, ...], tuple[str, str], Path]:
    release_root = release_dir.resolve(strict=True)
    packet = load_evidence_packet(release_dir / "reports" / "evidence-packet.json")
    manifest = project_validated_artifact_payload(
        load_validated_artifact_payload(
            release_dir / "reports" / "release-artifact-manifest.json",
            "release-artifact-manifest",
        ),
        ReleaseArtifactManifest,
        kind="release-artifact-manifest",
    )
    replay = load_digest_replay(release_dir / "release-digest-replay.json")
    verified_root = (
        _packet_artifact_root(packet, release_dir=release_dir)
        if artifact_root is None
        else _verified_artifact_root(
            packet,
            release_dir=release_dir,
            artifact_root=artifact_root,
        )
    )
    signable_artifacts = release_artifacts(release_dir)
    paths = {
        _release_relative_path(path, release_root=release_root, label="signed release artifact")
        for path in signable_artifacts
    }
    paths.update(
        _release_relative_path(
            bundle_path(path),
            release_root=release_root,
            label="release signature bundle",
        )
        for path in signable_artifacts
    )
    nested_manifest = packet.release_manifest
    if nested_manifest is None:
        raise ValueError("signed evidence packet has no release manifest")
    bound_artifact_identities = (
        *((artifact.role, artifact.path) for artifact in nested_manifest.artifacts),
        *((artifact.role, artifact.path) for artifact in manifest.artifacts),
        *((artifact.role, artifact.path) for artifact in replay.artifacts),
    )
    for role, artifact_path in bound_artifact_identities:
        resolved = _resolve_bound_artifact_path(
            verified_root,
            artifact_path,
            label=f"bound release artifact {role}",
        )
        paths.add(
            _release_relative_path(
                resolved,
                release_root=release_root,
                label=f"bound release artifact {role}",
            )
        )
    _require_portable_unique_paths(paths)
    wheel, sdist = _distribution_artifacts(release_dir / "dist")
    distributions = (
        _release_relative_path(wheel, release_root=release_root, label="release wheel"),
        _release_relative_path(sdist, release_root=release_root, label="release sdist"),
    )
    return tuple(sorted(paths)), distributions, verified_root


def _release_relative_path(
    path: Path,
    *,
    release_root: Path,
    label: str,
) -> str:
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(release_root)
    except ValueError as exc:
        raise ValueError(f"{label} is outside the release bundle") from exc
    normalized = relative.as_posix()
    if (
        not relative.parts
        or normalized in {"", "."}
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"{label} path is not normalized and confined")
    return normalized


def _require_portable_unique_paths(paths: set[str]) -> None:
    by_casefold: dict[str, str] = {}
    for relative_path in paths:
        folded = relative_path.casefold()
        prior = by_casefold.setdefault(folded, relative_path)
        if prior != relative_path:
            raise ValueError(
                f"release snapshot contains case-colliding paths: {prior} and {relative_path}"
            )


def _require_exact_release_tree(
    release_dir: Path,
    *,
    expected_files: Sequence[str],
) -> None:
    expected_file_set = set(expected_files)
    expected_directories: set[str] = set()
    for relative_path in expected_file_set:
        parent = Path(relative_path).parent
        while parent != Path("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent

    actual_files, actual_directories = _regular_tree_inventory(
        release_dir,
        label="release tree",
    )
    actual_file_set = set(actual_files)
    actual_directory_set = set(actual_directories)
    differences = (
        _inventory_difference("missing file(s)", expected_file_set - actual_file_set),
        _inventory_difference("extra file(s)", actual_file_set - expected_file_set),
        _inventory_difference(
            "missing directories",
            expected_directories - actual_directory_set,
        ),
        _inventory_difference(
            "extra directories",
            actual_directory_set - expected_directories,
        ),
    )
    details = tuple(detail for detail in differences if detail is not None)
    if details:
        raise RuntimeError("release tree inventory mismatch: " + "; ".join(details))


def _regular_tree_inventory(
    root: Path,
    *,
    label: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    files: set[str] = set()
    directories: set[str] = set()
    pending = ["."]
    entry_count = 0
    while pending:
        relative_directory = pending.pop()
        with open_directory_at(
            root,
            relative_directory,
            label=f"{label} directory",
        ) as opened:
            scan_target: int | Path = (
                opened.descriptor if opened.descriptor is not None else opened.path
            )
            with os.scandir(scan_target) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > MAX_RELEASE_TREE_ENTRIES:
                        raise ValueError(f"{label} exceeds maximum supported entry count")
                    name = entry.name
                    if not name or name in {".", ".."} or "/" in name or _BACKSLASH in name:
                        raise ValueError(f"{label} entry has an unsafe name: {name!r}")
                    relative_path = (
                        name if relative_directory == "." else f"{relative_directory}/{name}"
                    )
                    metadata = entry.stat(follow_symlinks=False)
                    if _metadata_is_link_or_reparse(metadata):
                        raise ValueError(
                            f"{label} entry must not be a link or reparse point: {relative_path}"
                        )
                    if stat.S_ISDIR(metadata.st_mode):
                        directories.add(relative_path)
                        pending.append(relative_path)
                    elif stat.S_ISREG(metadata.st_mode):
                        files.add(relative_path)
                    else:
                        raise ValueError(
                            f"{label} entry must be a regular file or directory: {relative_path}"
                        )
    _require_portable_unique_paths({*files, *directories})
    return tuple(sorted(files)), tuple(sorted(directories))


def _metadata_is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(
        stat.S_ISLNK(metadata.st_mode) or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    )


def _inventory_difference(label: str, paths: set[str]) -> str | None:
    if not paths:
        return None
    ordered = sorted(paths)
    preview = ", ".join(ordered[:8])
    if len(ordered) > 8:
        preview += f", ... ({len(ordered)} total)"
    return f"{label}: {preview}"


def _require_disjoint_uploaded_views(release_dir: Path, distributions_dir: Path) -> None:
    release_root = release_dir.resolve(strict=True)
    distributions_root = distributions_dir.resolve(strict=True)
    if (
        release_root == distributions_root
        or release_root in distributions_root.parents
        or distributions_root in release_root.parents
    ):
        raise ValueError("uploaded release and distribution views must be disjoint directories")


def _fresh_promotion_destination(promotion_dir: Path, *, release_dir: Path) -> Path:
    if promotion_dir.name in {"", ".", ".."}:
        raise ValueError("promotion destination must name a fresh directory")
    ensure_unlinked_directory(promotion_dir.parent)
    parent = promotion_dir.parent.resolve(strict=True)
    destination = parent / promotion_dir.name
    if os.path.lexists(destination):
        raise RuntimeError(f"promotion destination already exists: {destination}")
    release_root = release_dir.resolve(strict=True)
    if (
        destination == release_root
        or destination in release_root.parents
        or release_root in destination.parents
    ):
        raise ValueError("promotion destination must be disjoint from the release input")
    return destination


def _stage_verification_snapshot(
    snapshot: _ReleaseBundleSnapshot,
    *,
    release_dir: Path,
    work_dir: Path,
) -> tuple[Path, Path]:
    release_root = release_dir.resolve(strict=True)
    artifact_root = snapshot.artifact_root.resolve(strict=True)
    logical_root = work_dir / "logical"
    if release_root == artifact_root:
        staged_release = logical_root
        staged_artifact_root = logical_root
    elif release_root.is_relative_to(artifact_root):
        staged_artifact_root = logical_root
        staged_release = logical_root / release_root.relative_to(artifact_root)
    elif artifact_root.is_relative_to(release_root):
        staged_release = logical_root
        staged_artifact_root = logical_root / artifact_root.relative_to(release_root)
    else:
        raise ValueError("release directory and artifact root are not nested")
    _write_snapshot_tree(snapshot, staged_release)
    return staged_release, staged_artifact_root


def _write_snapshot_tree(snapshot: _ReleaseBundleSnapshot, destination: Path) -> None:
    ensure_unlinked_directory(destination)
    for relative_path, contents in snapshot.files:
        write_bytes_atomic(destination / Path(relative_path), contents.data)
    _require_exact_release_tree(
        destination,
        expected_files=tuple(path for path, _ in snapshot.files),
    )


def _require_verified_snapshot_unchanged(
    snapshot: _ReleaseBundleSnapshot,
    *,
    release_dir: Path,
    artifact_root: Path,
) -> None:
    expected_paths = tuple(relative_path for relative_path, _ in snapshot.files)
    _require_exact_release_tree(release_dir, expected_files=expected_paths)
    current_paths, current_distributions, current_root = _release_bundle_paths(
        release_dir,
        artifact_root=artifact_root,
    )
    if current_paths != expected_paths or current_distributions != snapshot.distribution_paths:
        raise RuntimeError("verified release snapshot path set changed before promotion")
    if current_root.resolve(strict=True) != artifact_root.resolve(strict=True):
        raise RuntimeError("verified release snapshot artifact root changed before promotion")
    _require_snapshot_bytes(snapshot, release_dir)
    _require_exact_release_tree(release_dir, expected_files=expected_paths)


def _require_snapshot_bytes(
    snapshot: _ReleaseBundleSnapshot,
    release_dir: Path,
) -> None:
    for relative_path, expected in snapshot.files:
        actual = read_file_bounded_at(
            release_dir,
            relative_path,
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label=f"verified release snapshot artifact {relative_path}",
        )
        if (
            actual.data != expected.data
            or actual.sha256 != expected.sha256
            or actual.size != expected.size
        ):
            raise RuntimeError(
                f"verified release snapshot changed before promotion: {relative_path}"
            )


def _stage_distribution_snapshot(
    snapshot: _ReleaseBundleSnapshot,
    destination: Path,
) -> None:
    ensure_unlinked_directory(destination)
    captured = dict(snapshot.files)
    names: set[str] = set()
    for relative_path in snapshot.distribution_paths:
        name = Path(relative_path).name
        if name in names:
            raise ValueError(f"release distributions have a duplicate filename: {name}")
        names.add(name)
        write_bytes_atomic(destination / name, captured[relative_path].data)


def _require_distribution_snapshot(
    snapshot: _ReleaseBundleSnapshot,
    destination: Path,
) -> None:
    captured = dict(snapshot.files)
    expected_names = {Path(path).name for path in snapshot.distribution_paths}
    actual_files, actual_directories = _regular_tree_inventory(
        destination,
        label="distribution tree",
    )
    if set(actual_files) != expected_names or actual_directories:
        raise RuntimeError("distribution snapshot is not the exact two-file set")
    for relative_path in snapshot.distribution_paths:
        name = Path(relative_path).name
        actual = read_file_bounded_at(
            destination,
            name,
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label=f"promoted distribution snapshot {name}",
        )
        expected = captured[relative_path]
        if actual.data != expected.data or actual.sha256 != expected.sha256:
            raise RuntimeError(f"distribution snapshot differs from full bundle: {name}")


def _remove_private_work_directory(
    work_dir: Path,
    *,
    primary_error: BaseException | None = None,
) -> None:
    try:
        if work_dir.is_symlink():
            work_dir.unlink(missing_ok=True)
        elif work_dir.exists():
            shutil.rmtree(work_dir)
    except OSError as exc:
        if primary_error is not None:
            primary_error.add_note(
                f"private workspace cleanup also failed: could not remove "
                f"private promotion workspace {work_dir}: {exc}"
            )
            return
        raise RuntimeError(f"could not remove private promotion workspace: {work_dir}") from exc


def verify_release_bundle_bindings(
    release_dir: Path,
    *,
    expected_ref: str | None = None,
    expected_sha: str | None = None,
    require_release_notes: bool = False,
    artifact_root: Path | None = None,
) -> None:
    """Verify every signed release artifact as one coherent, source-bound set."""

    packet_path = release_dir / "reports" / "evidence-packet.json"
    manifest_path = release_dir / "reports" / "release-artifact-manifest.json"
    try:
        packet = load_evidence_packet(packet_path)
        manifest = project_validated_artifact_payload(
            load_validated_artifact_payload(
                manifest_path,
                "release-artifact-manifest",
            ),
            ReleaseArtifactManifest,
            kind="release-artifact-manifest",
        )
        verified_artifact_root = (
            _packet_artifact_root(packet, release_dir=release_dir)
            if artifact_root is None
            else _verified_artifact_root(
                packet,
                release_dir=release_dir,
                artifact_root=artifact_root,
            )
        )
        binding_error = packet_summary_files_binding_error(
            packet,
            artifact_root=verified_artifact_root,
        )
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError(f"release evidence bundle could not be safely verified: {exc}") from exc
    if binding_error is not None:
        raise RuntimeError(f"release evidence bundle binding is invalid: {binding_error}")
    if packet.release_manifest != manifest:
        raise RuntimeError(
            "release evidence bundle binding is invalid: signed release artifact "
            "manifest does not match the manifest nested in the evidence packet"
        )
    try:
        _verify_manifest_artifact_bytes(manifest, artifact_root=verified_artifact_root)
        _verify_signed_manifest_paths(
            manifest,
            artifact_root=verified_artifact_root,
            release_dir=release_dir,
        )
        _verify_packet_markdown(packet, release_dir=release_dir)
        replay = _verify_digest_replay_binding(
            release_dir,
            artifact_root=verified_artifact_root,
            expected_ref=expected_ref,
            expected_sha=expected_sha,
        )
        _verify_replay_signed_paths(
            replay,
            artifact_root=verified_artifact_root,
            release_dir=release_dir,
        )
        _verify_release_notes_binding(
            release_dir,
            expected_ref=expected_ref,
            expected_sha=expected_sha,
            require_release_notes=require_release_notes,
        )
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError(
            f"release signed-set binding could not be safely verified: {exc}"
        ) from exc


def _verify_manifest_artifact_bytes(
    manifest: ReleaseArtifactManifest,
    *,
    artifact_root: Path,
) -> None:
    for artifact in manifest.artifacts:
        contents = read_file_bounded_at(
            artifact_root,
            artifact.path,
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label=f"release manifest artifact {artifact.role}",
        )
        if contents.sha256 != artifact.sha256:
            raise ValueError(
                f"release manifest artifact digest mismatch: {artifact.role} ({artifact.path})"
            )


def _verify_signed_manifest_paths(
    manifest: ReleaseArtifactManifest,
    *,
    artifact_root: Path,
    release_dir: Path,
) -> None:
    artifacts_by_role = {artifact.role: artifact for artifact in manifest.artifacts}
    wheel, sdist = _distribution_artifacts(release_dir / "dist")
    # This repository's official signing profile is comparative and requires both summaries.
    expected_paths = {
        "evaluation-summary": release_dir / "reports" / "evaluation-summary.json",
        "comparison-summary": release_dir / "reports" / "comparison-summary.json",
        "assurance-evidence-graph": (release_dir / "reports" / "assurance-evidence-graph.json"),
        "sbom": release_dir / "sbom.cdx.json",
        "python-wheel": wheel,
        "source-distribution": sdist,
    }
    for role, expected_path in expected_paths.items():
        artifact = artifacts_by_role.get(role)
        if artifact is None:
            raise ValueError(f"signed release artifact is missing from manifest: {role}")
        actual_path = _resolve_bound_artifact_path(
            artifact_root,
            artifact.path,
            label=f"release manifest artifact {role}",
        )
        if actual_path != expected_path.resolve(strict=True):
            raise ValueError(f"release manifest role {role} does not identify its signed artifact")


def _verify_packet_markdown(packet: EvidencePacket, *, release_dir: Path) -> None:
    markdown_path = release_dir / "reports" / "evidence-packet.md"
    contents = read_file_bounded(
        markdown_path,
        max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
        label="signed evidence packet Markdown",
    )
    expected = render_evidence_packet_markdown(packet).encode("utf-8")
    if contents.data != expected:
        raise ValueError("signed evidence packet Markdown does not match the signed packet JSON")


def _verify_digest_replay_binding(
    release_dir: Path,
    *,
    artifact_root: Path,
    expected_ref: str | None,
    expected_sha: str | None,
) -> ReleaseDigestReplay:
    replay = load_digest_replay(release_dir / "release-digest-replay.json")
    required_roles = core_release_roles_for_schema_version(replay.schema_version)
    actual_roles = tuple(artifact.role for artifact in replay.artifacts)
    if set(actual_roles) != set(required_roles) or len(actual_roles) != len(required_roles):
        raise ValueError(
            "release digest replay role set mismatch: expected "
            f"{', '.join(required_roles)}; got {', '.join(actual_roles)}"
        )
    for artifact in replay.artifacts:
        read_file_bounded_at(
            artifact_root,
            artifact.path,
            max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
            label=f"release replay artifact {artifact.role}",
        )
    verification = verify_digest_replay(
        replay,
        artifact_root=artifact_root,
        required_roles=required_roles,
        expect_commit=expected_sha,
        expect_ref=expected_ref,
    )
    if not verification.ok:
        messages = "; ".join(finding.message for finding in verification.findings)
        raise ValueError(f"release digest replay is incoherent: {messages}")
    if expected_sha is not None:
        current_sha = git_output(ROOT, "rev-parse", "HEAD")
        if current_sha != expected_sha:
            raise ValueError(
                "current checkout does not match the signed workflow SHA: "
                f"expected {expected_sha}, got {current_sha or '<unavailable>'}"
            )
    return replay


def _verify_replay_signed_paths(
    replay: ReleaseDigestReplay,
    *,
    artifact_root: Path,
    release_dir: Path,
) -> None:
    artifacts_by_role = {artifact.role: artifact for artifact in replay.artifacts}
    expected_paths = {
        "assurance-evidence-graph": (release_dir / "reports" / "assurance-evidence-graph.json"),
        "evidence-packet": release_dir / "reports" / "evidence-packet.json",
        "release-artifact-manifest": (release_dir / "reports" / "release-artifact-manifest.json"),
    }
    for role, expected_path in expected_paths.items():
        artifact = artifacts_by_role.get(role)
        if artifact is None:
            raise ValueError(f"signed release artifact is missing from digest replay: {role}")
        actual_path = _resolve_bound_artifact_path(
            artifact_root,
            artifact.path,
            label=f"release replay artifact {role}",
        )
        if actual_path != expected_path.resolve(strict=True):
            raise ValueError(f"release replay role {role} does not identify its signed artifact")


def _verify_release_notes_binding(
    release_dir: Path,
    *,
    expected_ref: str | None,
    expected_sha: str | None,
    require_release_notes: bool,
) -> None:
    if not require_release_notes:
        return
    if expected_ref is None or not expected_ref.startswith("refs/tags/v"):
        raise ValueError("release-note verification requires a version-tag ref")
    if expected_sha is None:
        raise ValueError("tag release-note verification requires the signed workflow SHA")
    tag = expected_ref.removeprefix("refs/tags/")
    if not tag or "/" in tag or _BACKSLASH in tag or tag in {".", ".."}:
        raise ValueError(f"tag release-note verification received an unsafe tag: {tag!r}")
    notes_path = release_dir / "release-notes.md"
    notes = read_file_bounded(
        notes_path,
        max_bytes=MAX_RELEASE_ARTIFACT_BYTES,
        label="signed release notes",
    )
    expected_notes = git_file_bytes(
        ROOT,
        expected_sha,
        f"docs/release_notes/{tag}.md",
    )
    if notes.data != expected_notes:
        raise ValueError("signed release notes do not match the immutable release-note Git blob")


def _resolve_bound_artifact_path(root: Path, relative_path: str, *, label: str) -> Path:
    path = Path(relative_path)
    if (
        path.is_absolute()
        or not path.parts
        or _BACKSLASH in relative_path
        or path.as_posix() != relative_path
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} path is not normalized and confined")
    resolved_root = root.resolve(strict=True)
    resolved = (resolved_root / path).resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"{label} path escapes its artifact root") from exc
    return resolved


def _packet_artifact_root(packet: EvidencePacket, *, release_dir: Path) -> Path:
    manifest = packet.release_manifest
    if manifest is None:
        raise ValueError("signed evidence packet has no release manifest")
    graph_artifact = next(
        (
            artifact
            for artifact in manifest.artifacts
            if artifact.role == "assurance-evidence-graph"
        ),
        None,
    )
    if graph_artifact is None:
        raise ValueError("signed evidence packet has no assurance evidence graph artifact")
    relative_graph_path = Path(graph_artifact.path)
    if (
        relative_graph_path.is_absolute()
        or not relative_graph_path.parts
        or any(part in {"", ".", ".."} for part in relative_graph_path.parts)
    ):
        raise ValueError("signed evidence packet graph path is not normalized and confined")
    signed_graph_path = (release_dir / "reports" / "assurance-evidence-graph.json").resolve(
        strict=True
    )
    candidate_root = signed_graph_path
    for expected_part in reversed(relative_graph_path.parts):
        if candidate_root.name != expected_part:
            raise ValueError(
                "signed evidence packet graph path does not identify the graph "
                "in the release bundle"
            )
        candidate_root = candidate_root.parent
    return candidate_root


def _verified_artifact_root(
    packet: EvidencePacket,
    *,
    release_dir: Path,
    artifact_root: Path,
) -> Path:
    manifest = packet.release_manifest
    if manifest is None:
        raise ValueError("signed evidence packet has no release manifest")
    graph_artifact = next(
        (
            artifact
            for artifact in manifest.artifacts
            if artifact.role == "assurance-evidence-graph"
        ),
        None,
    )
    if graph_artifact is None:
        raise ValueError("signed evidence packet has no assurance evidence graph artifact")
    root = artifact_root.resolve(strict=True)
    graph_path = _resolve_bound_artifact_path(
        root,
        graph_artifact.path,
        label="signed evidence packet assurance evidence graph",
    )
    expected_graph = (release_dir / "reports" / "assurance-evidence-graph.json").resolve(
        strict=True
    )
    if graph_path != expected_graph:
        raise ValueError("supplied artifact root does not identify the graph in the release bundle")
    return root


def verify_modified_packet_fails(
    release_dir: Path,
    *,
    cosign: str,
    workflow_name: str,
    workflow_path: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    issuer: str,
) -> None:
    packet = release_dir / "reports" / "evidence-packet.json"
    modified_packet = packet.with_name("evidence-packet.modified.json")
    shutil.copy2(packet, modified_packet)
    try:
        with modified_packet.open("ab") as handle:
            handle.write(b"\nmodified\n")
        identity = workflow_identity(
            repository=repository,
            workflow_path=workflow_path,
            ref=ref,
        )
        result = verify_blob(
            modified_packet,
            cosign=cosign,
            identity=identity,
            issuer=issuer,
            workflow_name=workflow_name,
            repository=repository,
            ref=ref,
            sha=sha,
            event_name=event_name,
            bundle=bundle_path(packet),
            check=False,
        )
        if result.returncode == 0:
            raise RuntimeError("modified evidence packet unexpectedly verified")
    finally:
        modified_packet.unlink(missing_ok=True)


def release_artifacts(release_dir: Path) -> tuple[Path, ...]:
    # This repository's official signing profile is comparative and requires both summaries.
    fixed = (
        release_dir / "reports" / "evidence-packet.json",
        release_dir / "reports" / "evidence-packet.md",
        release_dir / "reports" / "evaluation-summary.json",
        release_dir / "reports" / "comparison-summary.json",
        release_dir / "reports" / "assurance-evidence-graph.json",
        release_dir / "reports" / "release-artifact-manifest.json",
        release_dir / "release-digest-replay.json",
        release_dir / "sbom.cdx.json",
    )
    release_notes = release_dir / "release-notes.md"
    optional = (release_notes,) if release_notes.exists() else ()
    fixed_and_optional = (*fixed, *optional)
    missing = [path for path in fixed_and_optional if not path.is_file() or path.is_symlink()]
    if missing:
        raise RuntimeError(
            "missing release artifact(s): " + ", ".join(_display_path(path) for path in missing)
        )
    dist_dir = release_dir / "dist"
    dist_artifacts = _distribution_artifacts(dist_dir)
    return (*fixed_and_optional, *dist_artifacts)


def _distribution_artifacts(dist_dir: Path) -> tuple[Path, Path]:
    if not dist_dir.is_dir() or dist_dir.is_symlink():
        raise RuntimeError(f"missing release distribution directory: {_display_path(dist_dir)}")
    entries = tuple(sorted(dist_dir.iterdir(), key=lambda path: path.name))
    unsafe = [path for path in entries if path.is_symlink() or not path.is_file()]
    if unsafe:
        raise RuntimeError(
            "non-regular release distribution entry: "
            + ", ".join(_display_path(path) for path in unsafe)
        )
    distributions = tuple(
        path for path in entries if path.suffix == ".whl" or path.name.endswith(".tar.gz")
    )
    wheels = tuple(path for path in distributions if path.suffix == ".whl")
    sdists = tuple(path for path in distributions if path.name.endswith(".tar.gz"))
    allowed_bundle_names = {f"{path.name}.bundle" for path in distributions}
    unexpected = [
        path
        for path in entries
        if path not in distributions and path.name not in allowed_bundle_names
    ]
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        details = [
            f"{len(wheels)} wheel(s)",
            f"{len(sdists)} sdist(s)",
        ]
        if unexpected:
            details.append("unexpected " + ", ".join(_display_path(path) for path in unexpected))
        raise RuntimeError("invalid release distribution set: " + "; ".join(details))
    return wheels[0], sdists[0]


def verify_blob(
    artifact: Path,
    *,
    cosign: str,
    identity: str,
    issuer: str,
    workflow_name: str,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
    bundle: Path | None = None,
    check: bool = True,
    attempts: int = 5,
) -> subprocess.CompletedProcess[str]:
    _require_identity_context(
        repository=repository,
        ref=ref,
        sha=sha,
        event_name=event_name,
    )
    command = [
        cosign,
        "verify-blob",
        str(artifact),
        "--bundle",
        str(bundle or bundle_path(artifact)),
        "--certificate-identity",
        identity,
        "--certificate-oidc-issuer",
        issuer,
        "--certificate-github-workflow-name",
        workflow_name,
        "--certificate-github-workflow-repository",
        repository,
        "--certificate-github-workflow-ref",
        ref,
        "--certificate-github-workflow-sha",
        sha,
        "--certificate-github-workflow-trigger",
        event_name,
    ]
    last_result: subprocess.CompletedProcess[str] | None = None
    for attempt in range(1, attempts + 1):
        print(f"verifying {_display_path(artifact)} (attempt {attempt})")
        result = _run(command, check=False)
        if result.returncode == 0 or not check:
            return result
        last_result = result
        time.sleep(attempt * 2)
    if last_result is None:
        raise RuntimeError(f"cosign verification did not run: {_display_path(artifact)}")
    raise RuntimeError(_command_failure(command, last_result))


def workflow_identity(*, repository: str, workflow_path: str, ref: str) -> str:
    _require_nonempty("repository", repository)
    _require_nonempty("workflow_path", workflow_path)
    _require_nonempty("ref", ref)
    return f"https://github.com/{repository}/{workflow_path}@{ref}"


def bundle_path(artifact: Path) -> Path:
    return artifact.with_name(f"{artifact.name}.bundle")


def _run(args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args),
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(_command_failure(args, result))
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result


def _command_failure(
    args: Sequence[str],
    result: subprocess.CompletedProcess[str],
) -> str:
    details = [
        f"command failed with exit {result.returncode}: {' '.join(args)}",
        result.stdout.strip(),
        result.stderr.strip(),
    ]
    return "\n".join(detail for detail in details if detail)


def _require_identity_context(
    *,
    repository: str,
    ref: str,
    sha: str,
    event_name: str,
) -> None:
    _require_nonempty("repository", repository)
    _require_nonempty("ref", ref)
    _require_nonempty("sha", sha)
    _require_nonempty("event_name", event_name)


def _require_nonempty(name: str, value: str) -> None:
    if not value:
        raise ValueError(f"{name} is required")


def _resolve_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    return ROOT / path


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


if __name__ == "__main__":
    raise SystemExit(main())
