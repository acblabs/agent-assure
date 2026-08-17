from __future__ import annotations

import ctypes
import hashlib
import importlib
import os
import stat
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Self, cast

from agent_assure.io_limits import (
    BoundedFileContents,
    _require_regular_file,
    _require_same_file_identity,
)

_READ_CHUNK_BYTES = 1024 * 1024
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x0010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {
        "aux",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{suffix}" for suffix in "123456789\u00b9\u00b2\u00b3"),
        *(f"lpt{suffix}" for suffix in "123456789\u00b9\u00b2\u00b3"),
    }
)
_WINDOWS_FORBIDDEN_NAME_CHARACTERS = frozenset('<>:"|?*')


class _WindowsFileTime(ctypes.Structure):
    _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = (
        ("attributes", wintypes.DWORD),
        ("creation_time", _WindowsFileTime),
        ("last_access_time", _WindowsFileTime),
        ("last_write_time", _WindowsFileTime),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    )


@dataclass(frozen=True)
class _WindowsHandleIdentity:
    attributes: int
    volume_serial_number: int
    file_index: int
    size: int
    last_write_time: int


@dataclass(frozen=True)
class _PosixDirectoryComponent:
    parent_descriptor: int
    name: str
    metadata: os.stat_result
    path: Path


@dataclass(frozen=True)
class _WindowsPathComponent:
    path: Path
    identity: _WindowsHandleIdentity
    final_path: str


class BoundedFileDescriptor:
    """Validated file bytes plus descriptors that pin every rooted path component."""

    def __init__(
        self,
        *,
        descriptor: int,
        contents: BoundedFileContents,
        path: Path,
        root_device: int,
        root_inode: int,
        posix_directory_descriptors: tuple[int, ...] = (),
        windows_directory_handles: tuple[int, ...] = (),
    ) -> None:
        self.descriptor = descriptor
        self.contents = contents
        self.path = path
        self.root_device = root_device
        self.root_inode = root_inode
        self._posix_directory_descriptors = posix_directory_descriptors
        self._windows_directory_handles = windows_directory_handles
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def rewind(self) -> None:
        if self._closed:
            raise ValueError("rooted file descriptor is closed")
        os.lseek(self.descriptor, 0, os.SEEK_SET)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _close_descriptor(self.descriptor)
        finally:
            for descriptor in reversed(self._posix_directory_descriptors):
                _close_descriptor(descriptor)
            for handle in reversed(self._windows_directory_handles):
                _windows_close_handle(handle)


class RootedDirectoryDescriptor:
    """Directory lease that pins a trusted root and every traversed component."""

    def __init__(
        self,
        *,
        descriptor: int | None,
        path: Path,
        device: int,
        inode: int,
        root_device: int,
        root_inode: int,
        posix_directory_descriptors: tuple[int, ...] = (),
        windows_directory_handles: tuple[int, ...] = (),
    ) -> None:
        self.descriptor = descriptor
        self.path = path
        self.device = device
        self.inode = inode
        self.root_device = root_device
        self.root_inode = root_inode
        self._posix_directory_descriptors = posix_directory_descriptors
        self._windows_directory_handles = windows_directory_handles
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _close_descriptor(self.descriptor)
        finally:
            for descriptor in reversed(self._posix_directory_descriptors):
                _close_descriptor(descriptor)
            for handle in reversed(self._windows_directory_handles):
                _windows_close_handle(handle)


def open_rooted_bounded_file(
    root: Path,
    relative_path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileDescriptor:
    """Open one relative regular file while pinning and validating its full path."""
    _validate_max_bytes(max_bytes)
    parts = portable_relative_path_parts(relative_path)
    if os.name == "nt":
        return _open_windows_rooted_file(root, parts, max_bytes=max_bytes, label=label)
    return _open_posix_rooted_file(root, parts, max_bytes=max_bytes, label=label)


def open_rooted_directory(
    root: Path,
    relative_path: str | Path,
    *,
    label: str,
) -> RootedDirectoryDescriptor:
    """Lease one relative directory through a pinned trusted-root walk."""
    parts = _relative_directory_parts(relative_path)
    if os.name == "nt":
        return _open_windows_rooted_directory(root, parts, label=label)
    return _open_posix_rooted_directory(root, parts, label=label)


def _open_posix_rooted_directory(
    root: Path,
    parts: tuple[str, ...],
    *,
    label: str,
) -> RootedDirectoryDescriptor:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("race-resistant rooted directory leases are unavailable on this platform")
    root_path = Path(os.path.abspath(root))
    display_path = root_path.joinpath(*parts)
    root_before = os.lstat(root_path)
    _require_directory(root_before, path=root_path, label=f"{label} root")
    no_follow = cast(int, vars(os)["O_NOFOLLOW"])
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | no_follow
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NONBLOCK", 0)
    directories: list[int] = []
    components: list[_PosixDirectoryComponent] = []
    try:
        root_descriptor = os.open(root_path, directory_flags)
        directories.append(root_descriptor)
        pinned_root = os.fstat(root_descriptor)
        _require_directory(pinned_root, path=root_path, label=f"{label} root")
        _require_same_object(root_before, pinned_root, path=root_path, label=f"{label} root")
        parent_descriptor = root_descriptor
        current_path = root_path
        for name in parts:
            current_path = current_path / name
            before_open = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            _require_directory(before_open, path=current_path, label=f"{label} path")
            descriptor = os.open(name, directory_flags, dir_fd=parent_descriptor)
            directories.append(descriptor)
            opened = os.fstat(descriptor)
            _require_directory(opened, path=current_path, label=f"{label} path")
            _require_same_object(
                before_open,
                opened,
                path=current_path,
                label=f"{label} path",
            )
            components.append(
                _PosixDirectoryComponent(
                    parent_descriptor=parent_descriptor,
                    name=name,
                    metadata=opened,
                    path=current_path,
                )
            )
            parent_descriptor = descriptor
        _revalidate_posix_directories(
            root_path,
            pinned_root,
            tuple(components),
            label=label,
        )
        target_descriptor = directories[-1]
        target_metadata = os.fstat(target_descriptor)
        keepalive = tuple(directories[:-1])
        directories.clear()
        return RootedDirectoryDescriptor(
            descriptor=target_descriptor,
            path=display_path,
            device=target_metadata.st_dev,
            inode=target_metadata.st_ino,
            root_device=pinned_root.st_dev,
            root_inode=pinned_root.st_ino,
            posix_directory_descriptors=keepalive,
        )
    finally:
        for descriptor in reversed(directories):
            _close_descriptor(descriptor)


def _open_windows_rooted_directory(
    root: Path,
    parts: tuple[str, ...],
    *,
    label: str,
) -> RootedDirectoryDescriptor:
    root_path = Path(os.path.abspath(root))
    display_path = root_path.joinpath(*parts)
    directory_handles: list[int] = []
    try:
        root_handle = _windows_open_handle(root_path, directory=True)
        directory_handles.append(root_handle)
        root_identity = _windows_handle_identity(root_handle)
        _windows_require_directory(root_identity, path=root_path, label=f"{label} root")
        root_final_path = _windows_final_path(root_handle)
        components: list[_WindowsPathComponent] = []
        current_path = root_path
        for name in parts:
            current_path = current_path / name
            handle = _windows_open_handle(current_path, directory=True)
            directory_handles.append(handle)
            identity = _windows_handle_identity(handle)
            _windows_require_directory(identity, path=current_path, label=f"{label} path")
            final_path = _windows_final_path(handle)
            _windows_require_within_root(
                root_final_path,
                final_path,
                path=current_path,
                label=label,
            )
            components.append(_WindowsPathComponent(current_path, identity, final_path))
        _revalidate_windows_directories(
            root_path,
            root_identity,
            root_final_path,
            tuple(components),
            label=label,
        )
        root_metadata = os.stat(root_path, follow_symlinks=False)
        _require_directory(root_metadata, path=root_path, label=f"{label} root")
        if root_metadata.st_ino != root_identity.file_index:
            raise ValueError(f"{label} root changed while it was being opened: {root_path}")
        target_identity = components[-1].identity if components else root_identity
        target_metadata = os.stat(display_path, follow_symlinks=False)
        _require_directory(target_metadata, path=display_path, label=label)
        if target_metadata.st_ino != target_identity.file_index:
            raise ValueError(f"{label} path changed while it was being opened: {display_path}")
        result = RootedDirectoryDescriptor(
            descriptor=None,
            path=display_path,
            device=target_metadata.st_dev,
            inode=target_metadata.st_ino,
            root_device=root_metadata.st_dev,
            root_inode=root_metadata.st_ino,
            windows_directory_handles=tuple(directory_handles),
        )
        directory_handles.clear()
        return result
    finally:
        for handle in reversed(directory_handles):
            _windows_close_handle(handle)


def _open_posix_rooted_file(
    root: Path,
    parts: tuple[str, ...],
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileDescriptor:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("race-resistant rooted file reads are unavailable on this platform")
    root_path = Path(os.path.abspath(root))
    display_path = root_path.joinpath(*parts)
    root_before = os.lstat(root_path)
    _require_directory(root_before, path=root_path, label=f"{label} root")

    no_follow = cast(int, vars(os)["O_NOFOLLOW"])
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | no_follow
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NONBLOCK", 0)
    file_flags = os.O_RDONLY | no_follow
    file_flags |= getattr(os, "O_BINARY", 0)
    file_flags |= getattr(os, "O_CLOEXEC", 0)
    file_flags |= getattr(os, "O_NONBLOCK", 0)

    directories: list[int] = []
    components: list[_PosixDirectoryComponent] = []
    file_descriptor: int | None = None
    try:
        root_descriptor = os.open(root_path, directory_flags)
        directories.append(root_descriptor)
        pinned_root = os.fstat(root_descriptor)
        _require_directory(pinned_root, path=root_path, label=f"{label} root")
        _require_same_object(root_before, pinned_root, path=root_path, label=f"{label} root")

        parent_descriptor = root_descriptor
        current_path = root_path
        for name in parts[:-1]:
            current_path = current_path / name
            before_open = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            _require_directory(before_open, path=current_path, label=f"{label} path")
            descriptor = os.open(name, directory_flags, dir_fd=parent_descriptor)
            directories.append(descriptor)
            opened = os.fstat(descriptor)
            _require_directory(opened, path=current_path, label=f"{label} path")
            _require_same_object(
                before_open,
                opened,
                path=current_path,
                label=f"{label} path",
            )
            components.append(
                _PosixDirectoryComponent(
                    parent_descriptor=parent_descriptor,
                    name=name,
                    metadata=opened,
                    path=current_path,
                )
            )
            parent_descriptor = descriptor

        final_name = parts[-1]
        before_open = os.stat(final_name, dir_fd=parent_descriptor, follow_symlinks=False)
        _require_regular_file(before_open, path=display_path, label=label)
        if before_open.st_size > max_bytes:
            raise ValueError(f"{label} exceeds maximum supported size: {display_path}")
        file_descriptor = os.open(final_name, file_flags, dir_fd=parent_descriptor)
        opened = os.fstat(file_descriptor)
        _require_regular_file(opened, path=display_path, label=label)
        _require_same_file_identity(before_open, opened, path=display_path, label=label)

        def current_metadata() -> os.stat_result:
            return os.stat(final_name, dir_fd=parent_descriptor, follow_symlinks=False)

        contents = _read_descriptor_bounded(
            file_descriptor,
            opened,
            current_metadata=current_metadata,
            path=display_path,
            max_bytes=max_bytes,
            label=label,
        )
        _revalidate_posix_directories(
            root_path,
            pinned_root,
            tuple(components),
            label=label,
        )
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        result = BoundedFileDescriptor(
            descriptor=file_descriptor,
            contents=contents,
            path=display_path,
            root_device=pinned_root.st_dev,
            root_inode=pinned_root.st_ino,
            posix_directory_descriptors=tuple(directories),
        )
        file_descriptor = None
        directories.clear()
        return result
    finally:
        _close_descriptor(file_descriptor)
        for descriptor in reversed(directories):
            _close_descriptor(descriptor)


def _revalidate_posix_directories(
    root_path: Path,
    pinned_root: os.stat_result,
    components: tuple[_PosixDirectoryComponent, ...],
    *,
    label: str,
) -> None:
    current_root = os.lstat(root_path)
    _require_directory(current_root, path=root_path, label=f"{label} root")
    _require_same_object(
        pinned_root,
        current_root,
        path=root_path,
        label=f"{label} root",
    )
    for component in components:
        current = os.stat(
            component.name,
            dir_fd=component.parent_descriptor,
            follow_symlinks=False,
        )
        _require_directory(current, path=component.path, label=f"{label} path")
        _require_same_object(
            component.metadata,
            current,
            path=component.path,
            label=f"{label} path",
        )


def _open_windows_rooted_file(
    root: Path,
    parts: tuple[str, ...],
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileDescriptor:
    root_path = Path(os.path.abspath(root))
    display_path = root_path.joinpath(*parts)
    directory_handles: list[int] = []
    file_descriptor: int | None = None
    file_handle: int | None = None
    try:
        root_handle = _windows_open_handle(root_path, directory=True)
        directory_handles.append(root_handle)
        root_identity = _windows_handle_identity(root_handle)
        _windows_require_directory(root_identity, path=root_path, label=f"{label} root")
        root_final_path = _windows_final_path(root_handle)
        components: list[_WindowsPathComponent] = []

        current_path = root_path
        for name in parts[:-1]:
            current_path = current_path / name
            handle = _windows_open_handle(current_path, directory=True)
            directory_handles.append(handle)
            identity = _windows_handle_identity(handle)
            _windows_require_directory(identity, path=current_path, label=f"{label} path")
            final_path = _windows_final_path(handle)
            _windows_require_within_root(
                root_final_path,
                final_path,
                path=current_path,
                label=label,
            )
            components.append(
                _WindowsPathComponent(
                    path=current_path,
                    identity=identity,
                    final_path=final_path,
                )
            )

        file_handle = _windows_open_handle(display_path, directory=False)
        file_identity = _windows_handle_identity(file_handle)
        _windows_require_regular_file(file_identity, path=display_path, label=label)
        if file_identity.size > max_bytes:
            raise ValueError(f"{label} exceeds maximum supported size: {display_path}")
        file_final_path = _windows_final_path(file_handle)
        _windows_require_within_root(
            root_final_path,
            file_final_path,
            path=display_path,
            label=label,
        )
        file_descriptor = _windows_handle_to_descriptor(file_handle)
        file_handle = None
        opened = os.fstat(file_descriptor)
        _require_regular_file(opened, path=display_path, label=label)

        def current_metadata() -> os.stat_result:
            current_handle = _windows_open_handle(display_path, directory=False)
            try:
                current_identity = _windows_handle_identity(current_handle)
                _windows_require_regular_file(
                    current_identity,
                    path=display_path,
                    label=label,
                )
                _windows_require_same_identity(
                    file_identity,
                    current_identity,
                    path=display_path,
                    label=label,
                )
                _windows_require_within_root(
                    root_final_path,
                    _windows_final_path(current_handle),
                    path=display_path,
                    label=label,
                )
                return os.stat(display_path, follow_symlinks=False)
            finally:
                _windows_close_handle(current_handle)

        contents = _read_descriptor_bounded(
            file_descriptor,
            opened,
            current_metadata=current_metadata,
            path=display_path,
            max_bytes=max_bytes,
            label=label,
        )
        _revalidate_windows_directories(
            root_path,
            root_identity,
            root_final_path,
            tuple(components),
            label=label,
        )
        root_metadata = os.stat(root_path, follow_symlinks=False)
        _require_directory(root_metadata, path=root_path, label=f"{label} root")
        if root_metadata.st_ino != root_identity.file_index:
            raise ValueError(f"{label} root changed while it was being read: {root_path}")
        os.lseek(file_descriptor, 0, os.SEEK_SET)
        result = BoundedFileDescriptor(
            descriptor=file_descriptor,
            contents=contents,
            path=display_path,
            root_device=root_metadata.st_dev,
            root_inode=root_metadata.st_ino,
            windows_directory_handles=tuple(directory_handles),
        )
        file_descriptor = None
        directory_handles.clear()
        return result
    finally:
        _close_descriptor(file_descriptor)
        _windows_close_handle(file_handle)
        for handle in reversed(directory_handles):
            _windows_close_handle(handle)


def _revalidate_windows_directories(
    root_path: Path,
    root_identity: _WindowsHandleIdentity,
    root_final_path: str,
    components: tuple[_WindowsPathComponent, ...],
    *,
    label: str,
) -> None:
    paths = (
        _WindowsPathComponent(root_path, root_identity, root_final_path),
        *components,
    )
    for component in paths:
        handle = _windows_open_handle(component.path, directory=True)
        try:
            current_identity = _windows_handle_identity(handle)
            _windows_require_directory(
                current_identity,
                path=component.path,
                label=f"{label} path",
            )
            _windows_require_same_identity(
                component.identity,
                current_identity,
                path=component.path,
                label=f"{label} path",
            )
            if _windows_normalize_final_path(_windows_final_path(handle)) != (
                _windows_normalize_final_path(component.final_path)
            ):
                raise ValueError(f"{label} path changed while it was being read: {component.path}")
        finally:
            _windows_close_handle(handle)


def _read_descriptor_bounded(
    descriptor: int,
    opened: os.stat_result,
    *,
    current_metadata: Callable[[], os.stat_result],
    path: Path,
    max_bytes: int,
    label: str,
) -> BoundedFileContents:
    _require_regular_file(opened, path=path, label=label)
    if opened.st_size > max_bytes:
        raise ValueError(f"{label} exceeds maximum supported size: {path}")
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    digest = hashlib.sha256()
    size = 0
    while True:
        remaining_with_sentinel = (max_bytes - size) + 1
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining_with_sentinel))
        if not chunk:
            break
        size += len(chunk)
        if size > max_bytes:
            raise ValueError(f"{label} exceeds maximum supported size: {path}")
        chunks.append(chunk)
        digest.update(chunk)
    if size != opened.st_size:
        raise ValueError(f"{label} changed while it was being read: {path}")
    after_read = os.fstat(descriptor)
    _require_regular_file(after_read, path=path, label=label)
    _require_same_file_identity(
        opened,
        after_read,
        path=path,
        label=label,
        compare_change_time=True,
    )
    current = current_metadata()
    _require_regular_file(current, path=path, label=label)
    _require_same_file_identity(opened, current, path=path, label=label)
    return BoundedFileContents(
        data=b"".join(chunks),
        sha256=digest.hexdigest(),
        device=current.st_dev,
        inode=current.st_ino,
        size=current.st_size,
        modified_ns=current.st_mtime_ns,
        changed_ns=current.st_ctime_ns,
    )


def portable_relative_path_parts(relative_path: str | Path) -> tuple[str, ...]:
    """Return validated path parts portable across POSIX and Windows filesystems."""
    raw = str(relative_path).replace("\\", "/")
    posix_path = PurePosixPath(raw)
    windows_path = PureWindowsPath(str(relative_path))
    if "\0" in raw:
        raise ValueError("rooted file path must not contain NUL bytes")
    if raw in {"", "."}:
        raise ValueError("rooted file path must not be empty")
    if posix_path.is_absolute() or windows_path.drive:
        raise ValueError("rooted file path must be relative to its trusted root")
    raw_parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("rooted file path must not contain unsafe path segments")
    for part in raw_parts:
        _require_portable_windows_segment(part)
    return tuple(raw_parts)


def _require_portable_windows_segment(segment: str) -> None:
    if segment.endswith((" ", ".")) or any(
        character in _WINDOWS_FORBIDDEN_NAME_CHARACTERS or ord(character) < 32
        for character in segment
    ):
        raise ValueError("rooted file path contains a Windows-unsafe segment")
    basename = segment.split(".", 1)[0].casefold()
    if basename in _WINDOWS_RESERVED_BASENAMES:
        raise ValueError("rooted file path contains a reserved Windows device name")


def _relative_directory_parts(relative_path: str | Path) -> tuple[str, ...]:
    raw = str(relative_path).replace("\\", "/")
    if raw == ".":
        return ()
    if raw == "":
        raise ValueError("rooted directory path must not be empty")
    return portable_relative_path_parts(relative_path)


def _validate_max_bytes(max_bytes: int) -> None:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("maximum file size must be a non-negative integer")


def _require_directory(metadata: os.stat_result, *, path: Path, label: str) -> None:
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"{label} must be a directory without links: {path}")


def _require_same_object(
    expected: os.stat_result,
    observed: os.stat_result,
    *,
    path: Path,
    label: str,
) -> None:
    if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino):
        raise ValueError(f"{label} changed while it was being read: {path}")


def _windows_kernel32() -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("Win32 handle APIs are unavailable")
    return win_dll("kernel32", use_last_error=True)


def _windows_last_error() -> OSError:
    ctypes_api = vars(ctypes)
    get_last_error = cast(Callable[[], int], ctypes_api["get_last_error"])
    win_error = cast(Callable[[int], OSError], ctypes_api["WinError"])
    return win_error(get_last_error())


def _windows_open_handle(path: Path, *, directory: bool) -> int:
    kernel32 = _windows_kernel32()
    create_file = cast(Any, kernel32.CreateFileW)
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    desired_access = _WINDOWS_GENERIC_READ
    share_mode = _WINDOWS_FILE_SHARE_READ
    flags = _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT
    flags |= (
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS if directory else _WINDOWS_FILE_FLAG_SEQUENTIAL_SCAN
    )
    raw_handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        _WINDOWS_OPEN_EXISTING,
        flags,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if raw_handle is None or raw_handle == invalid_handle:
        raise _windows_last_error()
    return int(raw_handle)


def _windows_handle_identity(handle: int) -> _WindowsHandleIdentity:
    kernel32 = _windows_kernel32()
    get_information = cast(Any, kernel32.GetFileInformationByHandle)
    get_information.argtypes = (wintypes.HANDLE, ctypes.POINTER(_WindowsByHandleFileInformation))
    get_information.restype = wintypes.BOOL
    information = _WindowsByHandleFileInformation()
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise _windows_last_error()
    return _WindowsHandleIdentity(
        attributes=int(information.attributes),
        volume_serial_number=int(information.volume_serial_number),
        file_index=(int(information.file_index_high) << 32) | int(information.file_index_low),
        size=(int(information.file_size_high) << 32) | int(information.file_size_low),
        last_write_time=(int(information.last_write_time.high) << 32)
        | int(information.last_write_time.low),
    )


def _windows_final_path(handle: int) -> str:
    kernel32 = _windows_kernel32()
    get_final_path = cast(Any, kernel32.GetFinalPathNameByHandleW)
    get_final_path.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    get_final_path.restype = wintypes.DWORD
    capacity = 32768
    buffer = ctypes.create_unicode_buffer(capacity)
    length = int(get_final_path(wintypes.HANDLE(handle), buffer, capacity, 0))
    if length == 0:
        raise _windows_last_error()
    if length >= capacity:
        raise OSError("opened Windows path exceeded supported length")
    return buffer.value


def _windows_handle_to_descriptor(handle: int) -> int:
    msvcrt = importlib.import_module("msvcrt")
    open_osfhandle = cast(Callable[[int, int], int], msvcrt.open_osfhandle)
    return open_osfhandle(handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))


def _windows_close_handle(handle: int | None) -> None:
    if handle is None:
        return
    try:
        kernel32 = _windows_kernel32()
        close_handle = cast(Any, kernel32.CloseHandle)
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        close_handle(wintypes.HANDLE(handle))
    except (AttributeError, OSError):
        pass


def _windows_require_directory(
    identity: _WindowsHandleIdentity,
    *,
    path: Path,
    label: str,
) -> None:
    if not identity.attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY or (
        identity.attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"{label} must be a directory without reparse points: {path}")


def _windows_require_regular_file(
    identity: _WindowsHandleIdentity,
    *,
    path: Path,
    label: str,
) -> None:
    if identity.attributes & (
        _WINDOWS_FILE_ATTRIBUTE_DIRECTORY | _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"{label} must be a regular file: {path}")


def _windows_require_same_identity(
    expected: _WindowsHandleIdentity,
    observed: _WindowsHandleIdentity,
    *,
    path: Path,
    label: str,
) -> None:
    if expected != observed:
        raise ValueError(f"{label} changed while it was being read: {path}")


def _windows_require_within_root(
    root_final_path: str,
    candidate_final_path: str,
    *,
    path: Path,
    label: str,
) -> None:
    root = _windows_normalize_final_path(root_final_path)
    candidate = _windows_normalize_final_path(candidate_final_path)
    if candidate == root or not candidate.startswith(root + "\\"):
        raise ValueError(f"{label} path escaped its trusted root: {path}")


def _windows_normalize_final_path(path: str) -> str:
    return os.path.normcase(path.rstrip("\\/"))


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass
