from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from agent_assure.artifact_io import (
    ensure_unlinked_directory,
    unlink_file_if_exists,
    write_bytes_atomic,
)
from agent_assure.artifact_transaction import OutputPublicationRollback
from agent_assure.io_limits import read_file_bounded_from_filesystem_root


def mirrored_staging_directory(
    staging_root: Path,
    *,
    out_dir: Path,
    artifact_root: Path,
    owner: str,
) -> Path:
    """Mirror an output directory below an isolated artifact root.

    Keeping the relative path identical lets release manifests be rendered and
    validated entirely in staging while still describing the final artifacts.
    """

    try:
        absolute_output = Path(os.path.abspath(out_dir)).resolve(strict=False)
        absolute_artifact_root = Path(os.path.abspath(artifact_root)).resolve(strict=False)
        relative_output = absolute_output.relative_to(absolute_artifact_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{owner} output escapes its release artifact root") from exc
    return staging_root / relative_output


def publish_staged_outputs(
    *,
    staging_dir: Path,
    out_dir: Path,
    output_names: tuple[str, ...],
    max_bytes: int,
    owner: str,
    owned_output_names: tuple[str, ...] | None = None,
    expected_contents_by_name: Mapping[str, bytes] | None = None,
) -> None:
    """Publish one fully rendered generation with byte-exact rollback."""

    owned_names = output_names if owned_output_names is None else owned_output_names
    normalized_names = _validated_output_names(owned_names, owner=owner)
    normalized_outputs = _validated_output_names(output_names, owner=owner)
    if not normalized_outputs.issubset(normalized_names):
        raise ValueError(f"{owner} publication output is not in its owned inventory")
    expected_contents = {} if expected_contents_by_name is None else dict(expected_contents_by_name)
    if not set(expected_contents).issubset(output_names):
        raise ValueError(f"{owner} expected content names must be published outputs")

    staged_contents = {
        name: read_file_bounded_from_filesystem_root(
            staging_dir / name,
            max_bytes=max_bytes,
            label=f"staged {owner} {name}",
        ).data
        for name in output_names
    }
    if any(staged_contents[name] != expected for name, expected in expected_contents.items()):
        raise ValueError(f"staged {owner} evidence changed after verification")
    owned_paths = tuple(out_dir / name for name in owned_names)
    rollback = OutputPublicationRollback.capture(
        owned_paths,
        max_bytes=max_bytes,
        label=f"{owner} output",
        path_resolution_error=f"{owner} artifact path cannot be safely resolved",
        concurrent_change_error=(
            f"{owner} output changed concurrently; refusing rollback overwrite"
        ),
    )
    out_dir_preexisted = out_dir.exists()
    try:
        ensure_unlinked_directory(out_dir)
        for name in output_names:
            destination = out_dir / name
            write_bytes_atomic(destination, staged_contents[name])
            rollback.mark_written(destination)
        for name in owned_names:
            if name in staged_contents:
                continue
            stale_path = out_dir / name
            unlink_file_if_exists(stale_path)
            rollback.mark_deleted(stale_path)
    except BaseException:
        try:
            rollback.restore()
        except BaseException as rollback_exc:
            raise ValueError(
                f"{owner} publication failed and prior outputs could not be restored"
            ) from rollback_exc
        if not out_dir_preexisted:
            try:
                out_dir.rmdir()
            except (FileNotFoundError, OSError):
                # Preserve a concurrently created unrelated entry.
                pass
        raise


def _validated_output_names(names: tuple[str, ...], *, owner: str) -> set[str]:
    normalized_names: set[str] = set()
    for name in names:
        candidate = Path(name)
        normalized = os.path.normcase(name)
        if (
            not name
            or candidate.is_absolute()
            or candidate.name != name
            or normalized in normalized_names
        ):
            raise ValueError(f"{owner} publication output names must be unique basenames")
        normalized_names.add(normalized)
    return normalized_names
