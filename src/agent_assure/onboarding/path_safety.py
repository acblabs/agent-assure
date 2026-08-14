from __future__ import annotations

import os
import stat
from pathlib import Path

from agent_assure.io_limits import BoundedFileContents, read_file_bounded_at

_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


class UnsafeDirectoryChainError(ValueError):
    """Raised when a lexical directory chain cannot satisfy local-file policy."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"path {detail}")


def confined_config_input_file(
    root: Path,
    relative_path: str,
    *,
    label: str,
) -> Path:
    """Resolve one configured input through the shared confined-file policy."""
    candidate = root.absolute() / Path(relative_path)
    if not is_safe_input_file(candidate, root=root):
        raise ValueError(f"{label} must be a confined, unlinked regular file")
    return candidate


def read_confined_config_input_file(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read a configured file while enforcing confinement before and after."""
    return read_confined_file(
        path,
        root=root,
        max_bytes=max_bytes,
        label=label,
    )


def confined_config_input_directory(
    root: Path,
    relative_path: str,
    *,
    label: str,
) -> Path:
    """Resolve one configured input directory without following linked components."""
    return require_confined_input_directory(
        root.absolute() / Path(relative_path),
        root=root,
        label=label,
    )


def require_confined_input_directory(
    path: Path,
    *,
    root: Path,
    label: str,
) -> Path:
    """Require an existing local directory confined beneath an explicit root.

    The ordering is deliberate: ``Path.absolute()`` preserves the lexical path
    components, every component is inspected with ``lstat``, and only then are
    the path and root resolved for canonical containment. Resolving first would
    erase the symlink or junction evidence that this policy is meant to reject.
    A safe ``..`` spelling is therefore accepted only when its complete lexical
    traversal chain exists and contains ordinary directories.
    """
    absolute_root = root.absolute()
    absolute_path = path.absolute()
    if is_explicit_network_path(absolute_root) or is_explicit_network_path(absolute_path):
        raise ValueError(f"{label} must be a local regular directory")
    try:
        require_regular_directory_chain(absolute_root)
        require_regular_directory_chain(absolute_path)
    except UnsafeDirectoryChainError as exc:
        raise ValueError(f"{label} {exc.detail}") from exc
    try:
        resolved_path = absolute_path.resolve(strict=True)
        resolved_root = absolute_root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} must be an existing confined regular directory") from exc
    if not resolved_path.is_relative_to(resolved_root):
        raise ValueError(f"{label} escapes its allowed root")
    return absolute_path


def is_safe_input_file(path: Path, *, root: Path) -> bool:
    """Return whether a file and its lexical parent chain satisfy input policy."""
    try:
        absolute_root = root.absolute()
        absolute_path = path.absolute()
        if is_explicit_network_path(absolute_root) or is_explicit_network_path(absolute_path):
            return False
        require_regular_directory_chain(absolute_root)
        require_regular_directory_chain(absolute_path.parent)
        if not is_regular_unlinked_file(absolute_path):
            return False
        return absolute_path.resolve(strict=True).is_relative_to(absolute_root.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False


def read_confined_file(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    label: str,
) -> bytes:
    return read_confined_file_snapshot(
        path,
        root=root,
        max_bytes=max_bytes,
        label=label,
    ).data


def read_confined_file_snapshot(
    path: Path,
    *,
    root: Path,
    max_bytes: int,
    label: str,
) -> BoundedFileContents:
    absolute_path = path.absolute()
    absolute_root = root.absolute()
    if not is_safe_input_file(absolute_path, root=absolute_root):
        raise ValueError(f"{label} must be a confined, unlinked regular file")
    try:
        resolved_root = absolute_root.resolve(strict=True)
        relative_path = absolute_path.resolve(strict=True).relative_to(resolved_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} must be a confined, unlinked regular file") from exc
    contents = read_file_bounded_at(
        resolved_root,
        relative_path,
        max_bytes=max_bytes,
        label=label,
    )
    if not is_safe_input_file(absolute_path, root=absolute_root):
        raise ValueError(f"{label} changed path identity while it was being read")
    return contents


def confined_snapshot_relative_path(
    path: Path,
    contents: BoundedFileContents,
    *,
    root: Path,
    path_root: Path,
    label: str,
) -> str:
    """Bind a descriptor snapshot to its still-confined lexical path identity."""
    absolute_path = path.absolute()
    absolute_root = root.absolute()
    absolute_path_root = path_root.absolute()
    if not is_safe_input_file(absolute_path, root=absolute_root):
        raise ValueError(f"{label} changed path identity after it was read")
    if is_explicit_network_path(absolute_path_root):
        raise ValueError(f"{label} path root must be local")
    try:
        require_regular_directory_chain(absolute_path_root)
        metadata = os.lstat(absolute_path)
    except (OSError, UnsafeDirectoryChainError) as exc:
        raise ValueError(f"{label} changed path identity after it was read") from exc
    observed_identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    expected_identity = (
        contents.device,
        contents.inode,
        contents.size,
        contents.modified_ns,
        contents.changed_ns,
    )
    if observed_identity != expected_identity:
        raise ValueError(f"{label} changed path identity after it was read")
    try:
        resolved_path = absolute_path.resolve(strict=True)
        resolved_path_root = absolute_path_root.resolve(strict=True)
        relative_path = resolved_path.relative_to(resolved_path_root).as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"{label} escapes its artifact root") from exc
    final_metadata = os.lstat(absolute_path)
    final_identity = (
        final_metadata.st_dev,
        final_metadata.st_ino,
        final_metadata.st_size,
        final_metadata.st_mtime_ns,
        final_metadata.st_ctime_ns,
    )
    if final_identity != expected_identity:
        raise ValueError(f"{label} changed path identity after it was read")
    return relative_path


def path_entry_exists(path: Path) -> bool:
    try:
        os.lstat(path)
    except OSError:
        return False
    return True


def is_explicit_network_path(path: Path) -> bool:
    return os.name == "nt" and path.absolute().drive.startswith(chr(92) * 2)


def metadata_is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    )


def metadata_is_regular_file(metadata: os.stat_result) -> bool:
    return stat.S_ISREG(metadata.st_mode) and not metadata_is_reparse(metadata)


def metadata_is_regular_directory(metadata: os.stat_result) -> bool:
    return stat.S_ISDIR(metadata.st_mode) and not metadata_is_reparse(metadata)


def is_regular_unlinked_file(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
        return metadata_is_regular_file(metadata) and metadata.st_nlink == 1
    except OSError:
        return False


def is_regular_directory(path: Path) -> bool:
    try:
        return metadata_is_regular_directory(os.lstat(path))
    except OSError:
        return False


def require_regular_directory_chain(path: Path) -> None:
    """Inspect every lexical component without resolving links first."""
    absolute = path.absolute()
    for component in (*reversed(absolute.parents), absolute):
        try:
            metadata = os.lstat(component)
        except OSError as exc:
            raise UnsafeDirectoryChainError(
                "has a missing or unreadable directory component"
            ) from exc
        if not metadata_is_regular_directory(metadata):
            raise UnsafeDirectoryChainError(
                "contains a symbolic link, junction, or non-directory component"
            )
