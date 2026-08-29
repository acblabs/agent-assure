from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib
import math
import os
import platform
import stat
import sys
import time
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from functools import partial
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Self, TypeVar, cast

from agent_assure.io_limits import (
    BoundedFileContents,
    _require_regular_file,
    _require_same_file_identity,
)

_READ_CHUNK_BYTES = 1024 * 1024
PUBLICATION_LOCK_TIMEOUT_SECONDS = 60.0
_PUBLICATION_LOCK_RETRY_INTERVAL_SECONDS = 0.05
_IS_WINDOWS = os.name == "nt"
_IS_LINUX = sys.platform.startswith("linux")
_IS_DARWIN = sys.platform == "darwin"
_IS_FREEBSD = sys.platform.startswith("freebsd")
_POSIX_LOCK_CONTENTION_ERRNOS = frozenset(
    {
        errno.EACCES,
        errno.EAGAIN,
        getattr(errno, "EWOULDBLOCK", errno.EAGAIN),
    }
)
_WINDOWS_LOCK_CONTENTION_ERRNOS = frozenset(
    {
        errno.EACCES,
        errno.EAGAIN,
        getattr(errno, "EDEADLK", errno.EACCES),
    }
)
_WINDOWS_LOCK_CONTENTION_WINERRORS = frozenset(
    {
        32,  # ERROR_SHARING_VIOLATION
        33,  # ERROR_LOCK_VIOLATION
    }
)
_WINDOWS_SHARING_RETRY_INITIAL_INTERVAL_SECONDS = 0.001
_WINDOWS_SHARING_RETRY_MAX_INTERVAL_SECONDS = 0.016
_RetryResult = TypeVar("_RetryResult")
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x0010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_WINDOWS_DELETE = 0x00010000
_WINDOWS_READ_CONTROL = 0x00020000
_WINDOWS_SYNCHRONIZE = 0x00100000
_WINDOWS_FILE_READ_DATA = 0x00000001
_WINDOWS_FILE_LIST_DIRECTORY = 0x00000001
_WINDOWS_FILE_WRITE_DATA = 0x00000002
_WINDOWS_FILE_ADD_FILE = 0x00000002
_WINDOWS_FILE_ADD_SUBDIRECTORY = 0x00000004
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_WRITE_ATTRIBUTES = 0x00000100
_WINDOWS_FILE_ATTRIBUTE_NORMAL = 0x00000080
_WINDOWS_FILE_CREATE = 2
_WINDOWS_FILE_OPEN = 1
_WINDOWS_FILE_OPENED = 1
_WINDOWS_FILE_CREATED = 2
_WINDOWS_FILE_DIRECTORY_FILE = 0x00000001
_WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
_WINDOWS_FILE_RENAME_INFORMATION = 10
_WINDOWS_DACL_SECURITY_INFORMATION = 0x00000004
_WINDOWS_SDDL_REVISION_1 = 1
_WINDOWS_FILE_NON_DIRECTORY_FILE = 0x00000040
_WINDOWS_FILE_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_OBJ_CASE_INSENSITIVE = 0x00000040
_WINDOWS_FILE_DISPOSITION_INFORMATION = 4
_WINDOWS_STATUS_OBJECT_NAME_COLLISION = 0xC0000035
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
_RENAME_NOREPLACE = 1
_RENAME_EXCL = 0x00000004
_LINUX_RENAMEAT2_SYSCALL_BY_ABI: dict[tuple[str, int], int] = {
    ("aarch64", 64): 276,
    ("amd64", 64): 316,
    ("arm", 32): 382,
    ("arm64", 64): 276,
    ("armv6l", 32): 382,
    ("armv7l", 32): 382,
    ("armv8l", 32): 382,
    ("i386", 32): 353,
    ("i486", 32): 353,
    ("i586", 32): 353,
    ("i686", 32): 353,
    ("loongarch64", 64): 276,
    ("ppc64", 64): 357,
    ("ppc64le", 64): 357,
    ("riscv64", 64): 276,
    ("s390x", 64): 347,
    ("x86", 32): 353,
    ("x86_64", 64): 316,
}

_PosixRenameFunction = Callable[[int, bytes, int, bytes, int], int]
_PosixRenameSyscallFunction = Callable[..., int]


def _load_posix_libc() -> ctypes.CDLL | None:
    if _IS_WINDOWS:
        return None
    try:
        return ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None


def _configure_c_function(
    library: ctypes.CDLL | None,
    name: str,
    *,
    argtypes: tuple[Any, ...],
    restype: Any,
) -> Callable[..., int] | None:
    if library is None:
        return None
    function = getattr(library, name, None)
    if function is None:
        return None
    function.argtypes = argtypes
    function.restype = restype
    return cast(Callable[..., int], function)


def _linux_renameat2_syscall_number(machine: str, pointer_bits: int) -> int | None:
    return _LINUX_RENAMEAT2_SYSCALL_BY_ABI.get((machine.strip().lower(), pointer_bits))


_POSIX_LIBC = _load_posix_libc()
_raw_posix_renameat2 = _configure_c_function(
    _POSIX_LIBC if (_IS_LINUX or _IS_FREEBSD) else None,
    "renameat2",
    argtypes=(
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ),
    restype=ctypes.c_int,
)
_POSIX_RENAMEAT2: _PosixRenameFunction | None = (
    cast(_PosixRenameFunction, _raw_posix_renameat2) if _raw_posix_renameat2 is not None else None
)
_raw_posix_renameatx_np = _configure_c_function(
    _POSIX_LIBC if _IS_DARWIN else None,
    "renameatx_np",
    argtypes=(
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ),
    restype=ctypes.c_int,
)
_POSIX_RENAMEATX_NP: _PosixRenameFunction | None = (
    cast(_PosixRenameFunction, _raw_posix_renameatx_np)
    if _raw_posix_renameatx_np is not None
    else None
)
_raw_posix_syscall = _configure_c_function(
    _POSIX_LIBC if _IS_LINUX else None,
    "syscall",
    # syscall(2) is variadic. Only its fixed syscall-number parameter may be
    # declared; every renameat2 argument is explicitly typed at the call site.
    argtypes=(ctypes.c_long,),
    restype=ctypes.c_long,
)
_POSIX_RENAMEAT2_SYSCALL: _PosixRenameSyscallFunction | None = _raw_posix_syscall
_LINUX_RENAMEAT2_SYSCALL_NUMBER = (
    _linux_renameat2_syscall_number(
        platform.machine(),
        ctypes.sizeof(ctypes.c_void_p) * 8,
    )
    if _IS_LINUX
    else None
)


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


class _WindowsUnicodeString(ctypes.Structure):
    _fields_ = (
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", wintypes.LPWSTR),
    )


class _WindowsObjectAttributes(ctypes.Structure):
    _fields_ = (
        ("length", wintypes.ULONG),
        ("root_directory", wintypes.HANDLE),
        ("object_name", ctypes.POINTER(_WindowsUnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security_descriptor", wintypes.LPVOID),
        ("security_quality_of_service", wintypes.LPVOID),
    )


class _WindowsIoStatusValue(ctypes.Union):
    _fields_ = (("status", wintypes.LONG), ("pointer", wintypes.LPVOID))


class _WindowsIoStatusBlock(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = (("value", _WindowsIoStatusValue), ("information", ctypes.c_size_t))


class _WindowsFileDispositionInformation(ctypes.Structure):
    _fields_ = (("delete_file", wintypes.BOOLEAN),)


class _WindowsFileRenameInformation(ctypes.Structure):
    _fields_ = (
        ("replace_if_exists", wintypes.BOOLEAN),
        ("root_directory", wintypes.HANDLE),
        ("file_name_length", wintypes.DWORD),
        ("file_name", wintypes.WCHAR * 1),
    )


@dataclass(frozen=True)
class _WindowsHandleIdentity:
    attributes: int
    volume_serial_number: int
    file_index: int
    number_of_links: int
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


class PinnedDirectoryFile:
    """A bounded child read whose descriptor remains pinned to its lease entry."""

    def __init__(
        self,
        *,
        descriptor: int,
        contents: BoundedFileContents,
        path: Path,
        revalidate: Callable[[], None],
    ) -> None:
        self.descriptor = descriptor
        self.contents = contents
        self.path = path
        self._revalidate = revalidate
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def revalidate(self) -> None:
        if self._closed:
            raise ValueError("pinned directory file is closed")
        self._revalidate()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        _close_descriptor(self.descriptor)


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

    def entry_names(self, *, max_entries: int, label: str) -> tuple[str, ...]:
        """List one pinned directory with a strict entry-count bound."""
        if isinstance(max_entries, bool) or not isinstance(max_entries, int):
            raise ValueError("maximum directory entries must be an integer")
        if max_entries < 0:
            raise ValueError("maximum directory entries must be non-negative")
        self._require_open(label=label)
        return _lease_entry_names(self, max_entries=max_entries, label=label)

    def read_file_bounded(
        self,
        name: str | Path,
        *,
        max_bytes: int,
        label: str,
        require_single_link: bool = False,
    ) -> BoundedFileContents:
        """Read one regular child through this already-pinned directory lease."""
        with self.open_file_bounded(
            name,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        ) as opened:
            return opened.contents

    def open_file_bounded(
        self,
        name: str | Path,
        *,
        max_bytes: int,
        label: str,
        require_single_link: bool = False,
        permit_rename: bool = False,
    ) -> PinnedDirectoryFile:
        """Read and retain a no-follow child descriptor for later revalidation."""
        component = _portable_single_component(name, label=f"{label} filename")
        _validate_max_bytes(max_bytes)
        if not isinstance(require_single_link, bool):
            raise ValueError("require_single_link must be a boolean")
        if not isinstance(permit_rename, bool):
            raise ValueError("permit_rename must be a boolean")
        self._require_open(label=label)
        opener = _open_windows_lease_file if os.name == "nt" else _open_posix_lease_file
        return opener(
            self,
            component,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
            permit_rename=permit_rename,
        )

    def open_regular_file_exclusive(
        self,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> int:
        """Create one regular child without replacing an existing entry."""
        descriptor, _ = self.open_regular_file_exclusive_with_metadata(
            name,
            mode=mode,
        )
        return descriptor

    def open_regular_file_exclusive_with_metadata(
        self,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> tuple[int, os.stat_result]:
        """Create one regular child and return its pinned descriptor identity."""
        component = _portable_single_component(name, label="rooted output filename")
        _validate_creation_mode(mode)
        self._require_open(label="rooted output")
        return _open_lease_regular_file_exclusive(self, component, mode=mode)

    def open_regular_lock_file(
        self,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> tuple[int, os.stat_result]:
        """Open or create one persistent single-link lock file through this lease."""
        component = _portable_single_component(name, label="rooted lock filename")
        _validate_creation_mode(mode)
        self._require_open(label="rooted lock")
        return _open_lease_regular_lock_file(self, component, mode=mode)

    def stat_entry_no_follow(self, name: str | Path) -> os.stat_result:
        """Stat one direct child relative to this lease without following links."""
        component = _portable_single_component(name, label="rooted output filename")
        self._require_open(label="rooted output")
        return _stat_lease_entry_no_follow(self, component)

    def replace_regular_file(
        self,
        source_name: str | Path,
        target_name: str | Path,
        *,
        source_descriptor: int,
        expected_device: int,
        expected_inode: int,
    ) -> None:
        """Atomically replace one child with a pinned, single-link source file."""
        source = _portable_single_component(source_name, label="rooted source filename")
        target = _portable_single_component(target_name, label="rooted target filename")
        _validate_expected_identity(expected_device, expected_inode)
        if isinstance(source_descriptor, bool) or not isinstance(source_descriptor, int):
            raise ValueError("rooted source descriptor must be an integer")
        if source_descriptor < 0:
            raise ValueError("rooted source descriptor must be non-negative")
        self._require_open(label="rooted output")
        _replace_lease_regular_file(
            self,
            source,
            target,
            source_descriptor=source_descriptor,
            expected_device=expected_device,
            expected_inode=expected_inode,
        )

    def move_regular_file_no_replace(
        self,
        source_name: str | Path,
        target_name: str | Path,
        *,
        source_descriptor: int,
        expected_device: int,
        expected_inode: int,
    ) -> None:
        """Atomically move one pinned child without replacing the target name."""
        source = _portable_single_component(source_name, label="rooted source filename")
        target = _portable_single_component(target_name, label="rooted target filename")
        _validate_expected_identity(expected_device, expected_inode)
        if isinstance(source_descriptor, bool) or not isinstance(source_descriptor, int):
            raise ValueError("rooted source descriptor must be an integer")
        if source_descriptor < 0:
            raise ValueError("rooted source descriptor must be non-negative")
        self._require_open(label="rooted output")
        _move_lease_regular_file_no_replace(
            self,
            source,
            target,
            source_descriptor=source_descriptor,
            expected_device=expected_device,
            expected_inode=expected_inode,
        )

    def unlink_entry_no_follow(
        self,
        name: str | Path,
        *,
        expected_device: int | None = None,
        expected_inode: int | None = None,
    ) -> None:
        """Unlink a direct regular child only when its expected identity matches."""
        component = _portable_single_component(name, label="rooted output filename")
        _validate_expected_identity(expected_device, expected_inode)
        self._require_open(label="rooted output")
        _unlink_lease_entry_no_follow(
            self,
            component,
            expected_device=expected_device,
            expected_inode=expected_inode,
        )

    def unlink_file_or_link_no_follow(
        self,
        name: str | Path,
        *,
        expected_device: int | None = None,
        expected_inode: int | None = None,
    ) -> None:
        """Unlink a direct file or link entry through this pinned directory."""
        component = _portable_single_component(name, label="rooted output filename")
        _validate_expected_identity(expected_device, expected_inode)
        self._require_open(label="rooted output")
        _unlink_lease_file_or_link_no_follow(
            self,
            component,
            expected_device=expected_device,
            expected_inode=expected_inode,
        )

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

    def _require_open(self, *, label: str) -> None:
        if self._closed:
            raise ValueError(f"{label} directory lease is closed")

    def _require_posix_descriptor(self, *, label: str) -> int:
        if self.descriptor is None:
            raise OSError(f"{label} POSIX directory descriptor is unavailable")
        return self.descriptor

    def _require_windows_handle(self, *, label: str) -> int:
        if not self._windows_directory_handles:
            raise OSError(f"{label} Windows directory handle is unavailable")
        return self._windows_directory_handles[-1]


class RootedDirectoryClaim:
    """Exclusively created child directory pinned independently of its parent lease.

    The claim owns duplicate parent and child pins. It never closes the parent
    RootedDirectoryDescriptor, and file descriptors returned by
    open_regular_file_exclusive belong to the caller.
    """

    def __init__(
        self,
        *,
        path: Path,
        name: str,
        device: int,
        inode: int,
        descriptor: int | None = None,
        parent_descriptor: int | None = None,
        windows_handle: int | None = None,
        windows_parent_handle: int | None = None,
    ) -> None:
        self.path = path
        self.name = name
        self.device = device
        self.inode = inode
        self._descriptor = descriptor
        self._parent_descriptor = parent_descriptor
        self._windows_handle = windows_handle
        self._windows_parent_handle = windows_parent_handle
        self._closed = False
        self._removed = False

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def removed(self) -> bool:
        return self._removed

    def open_regular_file_exclusive(
        self,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> int:
        """Create one regular file relative to the pinned claim and return O_RDWR fd."""
        descriptor, _ = self.open_regular_file_exclusive_with_metadata(
            name,
            mode=mode,
        )
        return descriptor

    def open_regular_file_exclusive_with_metadata(
        self,
        name: str | Path,
        *,
        mode: int = 0o600,
    ) -> tuple[int, os.stat_result]:
        """Create one regular file and return its pinned descriptor identity."""
        component = _portable_single_component(name, label="rooted output filename")
        _validate_creation_mode(mode)
        self._require_open()
        if os.name == "nt":
            return self._open_windows_regular_file_exclusive(component)
        return self._open_posix_regular_file_exclusive(component, mode=mode)

    def open_file_bounded(
        self,
        name: str | Path,
        *,
        max_bytes: int,
        label: str,
        require_single_link: bool = False,
    ) -> PinnedDirectoryFile:
        """Read and pin an existing child through this private directory claim."""
        component = _portable_single_component(name, label=f"{label} filename")
        _validate_max_bytes(max_bytes)
        if not isinstance(require_single_link, bool):
            raise ValueError("require_single_link must be a boolean")
        self._require_open()
        opener = _open_windows_lease_file if os.name == "nt" else _open_posix_lease_file
        return opener(
            self,
            component,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        )

    def entry_names(self, *, max_entries: int, label: str) -> tuple[str, ...]:
        """List this pinned claim with a strict entry-count bound."""
        if isinstance(max_entries, bool) or not isinstance(max_entries, int):
            raise ValueError("maximum directory entries must be an integer")
        if max_entries < 0:
            raise ValueError("maximum directory entries must be non-negative")
        self._require_open()
        return _claim_entry_names(self, max_entries=max_entries, label=label)

    def stat_entry_no_follow(self, name: str | Path) -> os.stat_result:
        """Stat one entry relative to the pinned claim without following links."""
        component = _portable_single_component(name, label="rooted output filename")
        self._require_open()
        if os.name == "nt":
            handle = _windows_open_relative_handle(
                self._require_windows_handle(),
                component,
                desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
                share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
                create_disposition=_WINDOWS_FILE_OPEN,
                create_options=(
                    _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT | _WINDOWS_FILE_OPEN_REPARSE_POINT
                ),
                file_attributes=0,
            )
            try:
                identity = _windows_handle_identity(handle)
                _windows_require_not_reparse(identity, path=self.path / component)
                return _windows_fstat_handle(handle)
            finally:
                _windows_close_handle(handle)
        descriptor = self._require_posix_descriptor()
        metadata = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
        _require_not_link(metadata, path=self.path / component)
        return metadata

    def unlink_entry_no_follow(
        self,
        name: str | Path,
        *,
        expected_device: int | None = None,
        expected_inode: int | None = None,
    ) -> None:
        """Unlink one regular entry, optionally requiring its pinned identity."""
        component = _portable_single_component(name, label="rooted output filename")
        _validate_expected_identity(expected_device, expected_inode)
        self._require_open()
        path = self.path / component
        if os.name == "nt":
            handle = _windows_open_relative_handle(
                self._require_windows_handle(),
                component,
                desired_access=(
                    _WINDOWS_DELETE | _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE
                ),
                share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
                create_disposition=_WINDOWS_FILE_OPEN,
                create_options=(
                    _WINDOWS_FILE_NON_DIRECTORY_FILE
                    | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                    | _WINDOWS_FILE_OPEN_REPARSE_POINT
                ),
                file_attributes=0,
            )
            try:
                identity = _windows_handle_identity(handle)
                _windows_require_regular_file(identity, path=path, label="rooted output")
                metadata = _windows_fstat_handle(handle)
                _require_unlinked_regular_file(metadata, path=path)
                _require_expected_entry_identity(
                    metadata,
                    expected_device=expected_device,
                    expected_inode=expected_inode,
                    path=path,
                )
                _windows_set_delete_disposition(handle, expected_identity=identity)
            finally:
                _windows_close_handle(handle)
            return

        descriptor = self._require_posix_descriptor()
        metadata = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
        _require_unlinked_regular_file(metadata, path=path)
        _require_expected_entry_identity(
            metadata,
            expected_device=expected_device,
            expected_inode=expected_inode,
            path=path,
        )
        os.unlink(component, dir_fd=descriptor)

    def remove_empty(self) -> None:
        """Remove the claimed directory and release the claim on success.

        Failure is non-terminal: pins stay open so callers can inspect or retry
        without silently losing the identity guarantee.
        """
        self._require_open()
        if os.name == "nt":
            handle = self._require_windows_handle()
            identity = _windows_handle_identity(handle)
            _windows_require_directory(identity, path=self.path, label="claimed directory")
            if identity.file_index != self.inode:
                raise OSError("claimed directory identity changed")
            _windows_set_delete_disposition(handle, expected_identity=identity)
        else:
            descriptor = self._require_posix_descriptor()
            parent_descriptor = self._require_posix_parent_descriptor()
            opened = os.fstat(descriptor)
            _require_directory(opened, path=self.path, label="claimed directory")
            _require_claim_identity(
                opened,
                device=self.device,
                inode=self.inode,
                path=self.path,
            )
            current = os.stat(
                self.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _require_directory(current, path=self.path, label="claimed directory")
            _require_claim_identity(
                current,
                device=self.device,
                inode=self.inode,
                path=self.path,
            )
            os.rmdir(self.name, dir_fd=parent_descriptor)
        self._removed = True
        self.close()

    def install_no_replace(self, name: str | Path) -> None:
        """Atomically rename this claim within its pinned parent without replacement.

        Once the operating-system rename succeeds, ``path`` and ``name`` are
        updated before post-commit identity validation. Consequently, callers
        can distinguish a retained private claim from a committed generation
        even when the post-commit validation raises.
        """
        component = _portable_single_component(name, label="rooted install name")
        self._require_open()
        if os.name == "nt":
            _windows_install_claim_no_replace(self, component)
        else:
            _posix_install_claim_no_replace(self, component)
        self.path = self.path.parent / component
        self.name = component
        _require_installed_claim_identity(self)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _close_descriptor(self._descriptor)
            self._descriptor = None
        finally:
            try:
                _close_descriptor(self._parent_descriptor)
                self._parent_descriptor = None
            finally:
                try:
                    _windows_close_handle(self._windows_handle)
                    self._windows_handle = None
                finally:
                    _windows_close_handle(self._windows_parent_handle)
                    self._windows_parent_handle = None

    def _open_posix_regular_file_exclusive(
        self,
        name: str,
        *,
        mode: int,
    ) -> tuple[int, os.stat_result]:
        descriptor = self._require_posix_descriptor()
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= cast(int, vars(os)["O_NOFOLLOW"])
        created_descriptor: int | None = None
        try:
            created_descriptor = os.open(name, flags, mode, dir_fd=descriptor)
            metadata = os.fstat(created_descriptor)
            _require_unlinked_regular_file(metadata, path=self.path / name)
            result = (created_descriptor, metadata)
            created_descriptor = None
            return result
        finally:
            _close_descriptor(created_descriptor)

    def _open_windows_regular_file_exclusive(
        self,
        name: str,
    ) -> tuple[int, os.stat_result]:
        handle: int | None = None
        descriptor: int | None = None
        try:
            handle = _windows_open_relative_handle(
                self._require_windows_handle(),
                name,
                desired_access=(
                    _WINDOWS_FILE_READ_DATA
                    | _WINDOWS_FILE_WRITE_DATA
                    | _WINDOWS_FILE_READ_ATTRIBUTES
                    | _WINDOWS_FILE_WRITE_ATTRIBUTES
                    | _WINDOWS_DELETE
                    | _WINDOWS_SYNCHRONIZE
                ),
                share_access=_WINDOWS_FILE_SHARE_READ,
                create_disposition=_WINDOWS_FILE_CREATE,
                create_options=(
                    _WINDOWS_FILE_NON_DIRECTORY_FILE
                    | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                    | _WINDOWS_FILE_OPEN_REPARSE_POINT
                ),
                file_attributes=_WINDOWS_FILE_ATTRIBUTE_NORMAL,
                require_created=True,
            )
            identity = _windows_handle_identity(handle)
            _windows_require_regular_file(
                identity,
                path=self.path / name,
                label="rooted output",
            )
            descriptor = _windows_handle_to_descriptor(
                handle,
                flags=os.O_RDWR | getattr(os, "O_BINARY", 0),
            )
            handle = None
            metadata = os.fstat(descriptor)
            _require_unlinked_regular_file(metadata, path=self.path / name)
            result = (descriptor, metadata)
            descriptor = None
            return result
        except BaseException:
            if descriptor is not None:
                try:
                    _windows_set_descriptor_delete_disposition(descriptor)
                except OSError:
                    pass
            elif handle is not None:
                try:
                    _windows_set_delete_disposition(handle)
                except OSError:
                    pass
            raise
        finally:
            _close_descriptor(descriptor)
            _windows_close_handle(handle)

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("rooted directory claim is closed")

    def _require_posix_descriptor(self, *, label: str = "rooted output") -> int:
        if self._descriptor is None:
            raise OSError(f"{label} POSIX rooted directory claim descriptor is unavailable")
        return self._descriptor

    def _require_posix_parent_descriptor(self) -> int:
        if self._parent_descriptor is None:
            raise OSError("POSIX rooted directory parent descriptor is unavailable")
        return self._parent_descriptor

    def _require_windows_handle(self, *, label: str = "rooted output") -> int:
        if self._windows_handle is None:
            raise OSError(f"{label} Windows rooted directory claim handle is unavailable")
        return self._windows_handle

    def _require_windows_parent_handle(self) -> int:
        if self._windows_parent_handle is None:
            raise OSError("Windows rooted directory parent handle is unavailable")
        return self._windows_parent_handle


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


def _lease_entry_names(
    lease: RootedDirectoryDescriptor,
    *,
    max_entries: int,
    label: str,
) -> tuple[str, ...]:
    names: list[str] = []
    if os.name == "nt":
        handle = lease._require_windows_handle(label=label)
        windows_before = _windows_handle_identity(handle)
        _windows_require_directory(windows_before, path=lease.path, label=label)
        if windows_before.file_index != lease.inode:
            raise OSError(f"{label} directory identity changed")
        with os.scandir(lease.path) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) > max_entries:
                    raise ValueError(f"{label} contains too many entries")
        windows_after = _windows_handle_identity(handle)
        _windows_require_same_identity(
            windows_before,
            windows_after,
            path=lease.path,
            label=label,
        )
        current = os.stat(lease.path, follow_symlinks=False)
        _require_directory(current, path=lease.path, label=label)
        if current.st_ino != windows_before.file_index:
            raise ValueError(f"{label} directory changed while being enumerated")
        return tuple(names)

    descriptor = lease._require_posix_descriptor(label=label)
    posix_before = os.fstat(descriptor)
    _require_directory(posix_before, path=lease.path, label=label)
    _require_claim_identity(
        posix_before,
        device=lease.device,
        inode=lease.inode,
        path=lease.path,
    )
    flags = os.O_RDONLY | cast(int, vars(os)["O_DIRECTORY"])
    flags |= cast(int, vars(os)["O_NOFOLLOW"])
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    scan_descriptor = os.open(".", flags, dir_fd=descriptor)
    try:
        opened = os.fstat(scan_descriptor)
        _require_directory(opened, path=lease.path, label=label)
        _require_same_object(posix_before, opened, path=lease.path, label=label)
        with os.scandir(scan_descriptor) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) > max_entries:
                    raise ValueError(f"{label} contains too many entries")
        _require_same_object(
            opened,
            os.fstat(scan_descriptor),
            path=lease.path,
            label=label,
        )
        _require_same_object(
            posix_before,
            os.fstat(descriptor),
            path=lease.path,
            label=label,
        )
        return tuple(names)
    finally:
        _close_descriptor(scan_descriptor)


def _claim_entry_names(
    claim: RootedDirectoryClaim,
    *,
    max_entries: int,
    label: str,
) -> tuple[str, ...]:
    names: list[str] = []
    if os.name == "nt":
        handle = claim._require_windows_handle()
        windows_before = _windows_handle_identity(handle)
        _windows_require_directory(windows_before, path=claim.path, label=label)
        if windows_before.file_index != claim.inode:
            raise OSError(f"{label} directory identity changed")
        with os.scandir(claim.path) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) > max_entries:
                    raise ValueError(f"{label} contains too many entries")
        windows_after = _windows_handle_identity(handle)
        _windows_require_same_identity(
            windows_before,
            windows_after,
            path=claim.path,
            label=label,
        )
        current = os.stat(claim.path, follow_symlinks=False)
        _require_directory(current, path=claim.path, label=label)
        if current.st_ino != windows_before.file_index:
            raise ValueError(f"{label} directory changed while being enumerated")
        return tuple(names)

    descriptor = claim._require_posix_descriptor()
    posix_before = os.fstat(descriptor)
    _require_directory(posix_before, path=claim.path, label=label)
    _require_claim_identity(
        posix_before,
        device=claim.device,
        inode=claim.inode,
        path=claim.path,
    )
    flags = os.O_RDONLY | cast(int, vars(os)["O_DIRECTORY"])
    flags |= cast(int, vars(os)["O_NOFOLLOW"])
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    scan_descriptor = os.open(".", flags, dir_fd=descriptor)
    try:
        opened = os.fstat(scan_descriptor)
        _require_directory(opened, path=claim.path, label=label)
        _require_same_object(posix_before, opened, path=claim.path, label=label)
        with os.scandir(scan_descriptor) as iterator:
            for entry in iterator:
                names.append(entry.name)
                if len(names) > max_entries:
                    raise ValueError(f"{label} contains too many entries")
        _require_same_object(
            opened,
            os.fstat(scan_descriptor),
            path=claim.path,
            label=label,
        )
        _require_same_object(
            posix_before,
            os.fstat(descriptor),
            path=claim.path,
            label=label,
        )
        return tuple(names)
    finally:
        _close_descriptor(scan_descriptor)


def _open_posix_lease_file(
    lease: RootedDirectoryDescriptor | RootedDirectoryClaim,
    name: str,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool,
    permit_rename: bool = False,
) -> PinnedDirectoryFile:
    del permit_rename
    directory = lease._require_posix_descriptor(label=label)
    pinned_directory = os.fstat(directory)
    _require_directory(pinned_directory, path=lease.path, label=f"{label} directory")
    _require_claim_identity(
        pinned_directory,
        device=lease.device,
        inode=lease.inode,
        path=lease.path,
    )
    path = lease.path / name
    before_open = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _require_regular_file(before_open, path=path, label=label)
    if require_single_link:
        _require_unlinked_regular_file(before_open, path=path)
    if before_open.st_size > max_bytes:
        raise ValueError(f"{label} exceeds maximum supported size: {path}")

    flags = os.O_RDONLY | cast(int, vars(os)["O_NOFOLLOW"])
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = os.open(name, flags, dir_fd=directory)
    try:
        assert descriptor is not None
        opened = os.fstat(descriptor)
        _require_regular_file(opened, path=path, label=label)
        _require_same_object(before_open, opened, path=path, label=label)
        if require_single_link:
            _require_unlinked_regular_file(opened, path=path)

        def current_metadata() -> os.stat_result:
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _require_regular_file(current, path=path, label=label)
            if require_single_link:
                _require_unlinked_regular_file(current, path=path)
            return current

        contents = _read_descriptor_bounded(
            descriptor,
            opened,
            current_metadata=current_metadata,
            path=path,
            max_bytes=max_bytes,
            label=label,
        )
        owned_descriptor = descriptor

        def revalidate() -> None:
            after = os.fstat(owned_descriptor)
            _require_regular_file(after, path=path, label=label)
            _require_same_file_identity(
                opened,
                after,
                path=path,
                label=label,
                compare_change_time=True,
            )
            current = current_metadata()
            _require_same_file_identity(opened, current, path=path, label=label)
            _require_same_object(
                pinned_directory,
                os.fstat(directory),
                path=lease.path,
                label=f"{label} directory",
            )

        result = PinnedDirectoryFile(
            descriptor=owned_descriptor,
            contents=contents,
            path=path,
            revalidate=revalidate,
        )
        descriptor = None
        result.revalidate()
        return result
    finally:
        _close_descriptor(descriptor)


def _open_windows_lease_file(
    lease: RootedDirectoryDescriptor | RootedDirectoryClaim,
    name: str,
    *,
    max_bytes: int,
    label: str,
    require_single_link: bool,
    permit_rename: bool = False,
) -> PinnedDirectoryFile:
    directory = lease._require_windows_handle(label=label)
    pinned_directory = _windows_handle_identity(directory)
    _windows_require_directory(
        pinned_directory,
        path=lease.path,
        label=f"{label} directory",
    )
    if pinned_directory.file_index != lease.inode:
        raise OSError(f"{label} directory identity changed")
    path = lease.path / name
    handle: int | None = None
    descriptor: int | None = None
    try:
        handle = _windows_open_relative_handle(
            directory,
            name,
            desired_access=(
                _WINDOWS_FILE_READ_DATA
                | _WINDOWS_FILE_READ_ATTRIBUTES
                | _WINDOWS_SYNCHRONIZE
                | (_WINDOWS_DELETE if permit_rename else 0)
            ),
            share_access=_WINDOWS_FILE_SHARE_READ,
            create_disposition=_WINDOWS_FILE_OPEN,
            create_options=(
                _WINDOWS_FILE_NON_DIRECTORY_FILE
                | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                | _WINDOWS_FILE_OPEN_REPARSE_POINT
            ),
            file_attributes=0,
        )
        opened_identity = _windows_handle_identity(handle)
        _windows_require_regular_file(opened_identity, path=path, label=label)
        if require_single_link and opened_identity.number_of_links != 1:
            raise ValueError(f"{label} must be a single-link regular file: {path}")
        if opened_identity.size > max_bytes:
            raise ValueError(f"{label} exceeds maximum supported size: {path}")
        descriptor = _windows_handle_to_descriptor(handle)
        handle = None
        opened = os.fstat(descriptor)
        _require_regular_file(opened, path=path, label=label)
        if opened.st_size != opened_identity.size:
            raise ValueError(f"{label} changed while it was being opened: {path}")

        def current_metadata() -> os.stat_result:
            current_handle = _windows_open_relative_handle(
                directory,
                name,
                desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
                share_access=_WINDOWS_FILE_SHARE_READ,
                create_disposition=_WINDOWS_FILE_OPEN,
                create_options=(
                    _WINDOWS_FILE_NON_DIRECTORY_FILE
                    | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                    | _WINDOWS_FILE_OPEN_REPARSE_POINT
                ),
                file_attributes=0,
            )
            try:
                current_identity = _windows_handle_identity(current_handle)
                _windows_require_regular_file(current_identity, path=path, label=label)
                _windows_require_same_identity(
                    opened_identity,
                    current_identity,
                    path=path,
                    label=label,
                )
                if require_single_link and current_identity.number_of_links != 1:
                    raise ValueError(f"{label} must be a single-link regular file: {path}")
                return _windows_fstat_handle(current_handle)
            finally:
                _windows_close_handle(current_handle)

        contents = _read_descriptor_bounded(
            descriptor,
            opened,
            current_metadata=current_metadata,
            path=path,
            max_bytes=max_bytes,
            label=label,
        )
        owned_descriptor = descriptor

        def revalidate() -> None:
            assert owned_descriptor is not None
            after = os.fstat(owned_descriptor)
            _require_regular_file(after, path=path, label=label)
            _require_same_file_identity(
                opened,
                after,
                path=path,
                label=label,
                compare_change_time=True,
            )
            current = current_metadata()
            _require_same_file_identity(opened, current, path=path, label=label)
            _windows_require_same_directory_object(
                pinned_directory,
                _windows_handle_identity(directory),
                path=lease.path,
                label=f"{label} directory",
            )

        assert owned_descriptor is not None
        result = PinnedDirectoryFile(
            descriptor=owned_descriptor,
            contents=contents,
            path=path,
            revalidate=revalidate,
        )
        descriptor = None
        result.revalidate()
        return result
    finally:
        _close_descriptor(descriptor)
        _windows_close_handle(handle)


def _open_lease_regular_file_exclusive(
    lease: RootedDirectoryDescriptor,
    name: str,
    *,
    mode: int,
) -> tuple[int, os.stat_result]:
    path = lease.path / name
    if os.name != "nt":
        directory = lease._require_posix_descriptor(label="rooted output")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= cast(int, vars(os)["O_NOFOLLOW"])
        descriptor: int | None = None
        try:
            descriptor = os.open(name, flags, mode, dir_fd=directory)
            metadata = os.fstat(descriptor)
            _require_unlinked_regular_file(metadata, path=path)
            result = (descriptor, metadata)
            descriptor = None
            return result
        finally:
            _close_descriptor(descriptor)

    directory = lease._require_windows_handle(label="rooted output")
    handle: int | None = None
    descriptor = None
    try:
        handle = _windows_open_relative_handle(
            directory,
            name,
            desired_access=(
                _WINDOWS_FILE_READ_DATA
                | _WINDOWS_FILE_WRITE_DATA
                | _WINDOWS_FILE_READ_ATTRIBUTES
                | _WINDOWS_FILE_WRITE_ATTRIBUTES
                | _WINDOWS_DELETE
                | _WINDOWS_SYNCHRONIZE
            ),
            share_access=_WINDOWS_FILE_SHARE_READ,
            create_disposition=_WINDOWS_FILE_CREATE,
            create_options=(
                _WINDOWS_FILE_NON_DIRECTORY_FILE
                | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                | _WINDOWS_FILE_OPEN_REPARSE_POINT
            ),
            file_attributes=_WINDOWS_FILE_ATTRIBUTE_NORMAL,
            require_created=True,
        )
        identity = _windows_handle_identity(handle)
        _windows_require_regular_file(identity, path=path, label="rooted output")
        if identity.number_of_links != 1:
            raise ValueError(f"rooted output must be a single-link regular file: {path}")
        descriptor = _windows_handle_to_descriptor(
            handle,
            flags=os.O_RDWR | getattr(os, "O_BINARY", 0),
        )
        handle = None
        metadata = os.fstat(descriptor)
        _require_unlinked_regular_file(metadata, path=path)
        result = (descriptor, metadata)
        descriptor = None
        return result
    except BaseException:
        if descriptor is not None:
            try:
                _windows_set_descriptor_delete_disposition(descriptor)
            except OSError:
                pass
        elif handle is not None:
            try:
                _windows_set_delete_disposition(handle)
            except OSError:
                pass
        raise
    finally:
        _close_descriptor(descriptor)
        _windows_close_handle(handle)


def _replace_lease_regular_file(
    lease: RootedDirectoryDescriptor,
    source_name: str,
    target_name: str,
    *,
    source_descriptor: int,
    expected_device: int,
    expected_inode: int,
) -> None:
    if source_name == target_name:
        raise ValueError("rooted source and target filenames must differ")
    source_path = lease.path / source_name
    target_path = lease.path / target_name
    opened = os.fstat(source_descriptor)
    _require_unlinked_regular_file(opened, path=source_path)
    _require_expected_entry_identity(
        opened,
        expected_device=expected_device,
        expected_inode=expected_inode,
        path=source_path,
    )

    if os.name != "nt":
        directory = lease._require_posix_descriptor(label="rooted output")
        posix_current = os.stat(source_name, dir_fd=directory, follow_symlinks=False)
        _require_unlinked_regular_file(posix_current, path=source_path)
        _require_same_object(opened, posix_current, path=source_path, label="rooted output")
        os.replace(
            source_name,
            target_name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        posix_installed = os.stat(target_name, dir_fd=directory, follow_symlinks=False)
        _require_unlinked_regular_file(posix_installed, path=target_path)
        _require_same_object(opened, posix_installed, path=target_path, label="rooted output")
        os.fsync(directory)
        return

    msvcrt = importlib.import_module("msvcrt")
    get_osfhandle = cast(Callable[[int], int], msvcrt.get_osfhandle)
    source_handle = get_osfhandle(source_descriptor)
    if source_handle == -1:
        raise OSError("Windows descriptor has no native handle")
    before = _windows_handle_identity(source_handle)
    _windows_require_regular_file(before, path=source_path, label="rooted output")
    if before.number_of_links != 1:
        raise ValueError(f"rooted output must be a single-link regular file: {source_path}")
    parent_handle = lease._require_windows_handle(label="rooted output")
    current_handle = _windows_open_relative_handle(
        parent_handle,
        source_name,
        desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        share_access=(
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE
        ),
        create_disposition=_WINDOWS_FILE_OPEN,
        create_options=(
            _WINDOWS_FILE_NON_DIRECTORY_FILE
            | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
            | _WINDOWS_FILE_OPEN_REPARSE_POINT
        ),
        file_attributes=0,
    )
    try:
        windows_current = _windows_handle_identity(current_handle)
        _windows_require_regular_file(
            windows_current,
            path=source_path,
            label="rooted output",
        )
        _windows_require_same_identity(
            before,
            windows_current,
            path=source_path,
            label="rooted output",
        )
    finally:
        _windows_close_handle(current_handle)
    _windows_rename_regular_file(
        source_handle,
        parent_handle,
        target_name,
        replace_if_exists=True,
    )
    installed_handle = _windows_open_relative_handle(
        parent_handle,
        target_name,
        desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        share_access=(
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE
        ),
        create_disposition=_WINDOWS_FILE_OPEN,
        create_options=(
            _WINDOWS_FILE_NON_DIRECTORY_FILE
            | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
            | _WINDOWS_FILE_OPEN_REPARSE_POINT
        ),
        file_attributes=0,
    )
    try:
        windows_installed = _windows_handle_identity(installed_handle)
        _windows_require_regular_file(
            windows_installed,
            path=target_path,
            label="rooted output",
        )
        _windows_require_same_identity(
            before,
            windows_installed,
            path=target_path,
            label="rooted output",
        )
    finally:
        _windows_close_handle(installed_handle)


def _move_lease_regular_file_no_replace(
    lease: RootedDirectoryDescriptor,
    source_name: str,
    target_name: str,
    *,
    source_descriptor: int,
    expected_device: int,
    expected_inode: int,
) -> None:
    if source_name == target_name:
        raise ValueError("rooted source and target filenames must differ")
    source_path = lease.path / source_name
    target_path = lease.path / target_name
    opened = os.fstat(source_descriptor)
    _require_unlinked_regular_file(opened, path=source_path)
    _require_expected_entry_identity(
        opened,
        expected_device=expected_device,
        expected_inode=expected_inode,
        path=source_path,
    )

    if os.name != "nt":
        directory = lease._require_posix_descriptor(label="rooted output")
        current = os.stat(source_name, dir_fd=directory, follow_symlinks=False)
        _require_unlinked_regular_file(current, path=source_path)
        _require_same_object(opened, current, path=source_path, label="rooted output")
        _posix_renameat_no_replace(directory, source_name, target_name)
        try:
            installed = os.stat(target_name, dir_fd=directory, follow_symlinks=False)
            _require_unlinked_regular_file(installed, path=target_path)
            _require_same_object(opened, installed, path=target_path, label="rooted output")
            os.fsync(directory)
        except BaseException:
            try:
                _posix_renameat_no_replace(directory, target_name, source_name)
                os.fsync(directory)
            except BaseException as cleanup_exc:
                raise OSError(
                    "rooted no-replace move failed and source restoration was incomplete"
                ) from cleanup_exc
            raise
        return

    msvcrt = importlib.import_module("msvcrt")
    get_osfhandle = cast(Callable[[int], int], msvcrt.get_osfhandle)
    source_handle = get_osfhandle(source_descriptor)
    if source_handle == -1:
        raise OSError("Windows descriptor has no native handle")
    before = _windows_handle_identity(source_handle)
    _windows_require_regular_file(before, path=source_path, label="rooted output")
    if before.number_of_links != 1:
        raise ValueError(f"rooted output must be a single-link regular file: {source_path}")
    parent_handle = lease._require_windows_handle(label="rooted output")
    current_handle = _windows_open_relative_handle(
        parent_handle,
        source_name,
        desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        share_access=(
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE
        ),
        create_disposition=_WINDOWS_FILE_OPEN,
        create_options=(
            _WINDOWS_FILE_NON_DIRECTORY_FILE
            | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
            | _WINDOWS_FILE_OPEN_REPARSE_POINT
        ),
        file_attributes=0,
    )
    try:
        current_identity = _windows_handle_identity(current_handle)
        _windows_require_regular_file(
            current_identity,
            path=source_path,
            label="rooted output",
        )
        _windows_require_same_identity(
            before,
            current_identity,
            path=source_path,
            label="rooted output",
        )
    finally:
        _windows_close_handle(current_handle)
    _windows_rename_regular_file(
        source_handle,
        parent_handle,
        target_name,
        replace_if_exists=False,
    )
    try:
        installed_handle = _windows_open_relative_handle(
            parent_handle,
            target_name,
            desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
            share_access=(
                _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE
            ),
            create_disposition=_WINDOWS_FILE_OPEN,
            create_options=(
                _WINDOWS_FILE_NON_DIRECTORY_FILE
                | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                | _WINDOWS_FILE_OPEN_REPARSE_POINT
            ),
            file_attributes=0,
        )
        try:
            installed_identity = _windows_handle_identity(installed_handle)
            _windows_require_regular_file(
                installed_identity,
                path=target_path,
                label="rooted output",
            )
            _windows_require_same_identity(
                before,
                installed_identity,
                path=target_path,
                label="rooted output",
            )
        finally:
            _windows_close_handle(installed_handle)
    except BaseException:
        try:
            _windows_rename_regular_file(
                source_handle,
                parent_handle,
                source_name,
                replace_if_exists=False,
            )
        except BaseException as cleanup_exc:
            raise OSError(
                "rooted no-replace move failed and source restoration was incomplete"
            ) from cleanup_exc
        raise


def _windows_rename_regular_file(
    source_handle: int,
    parent_handle: int,
    target_name: str,
    *,
    replace_if_exists: bool,
) -> None:
    encoded_name = target_name.encode("utf-16-le")
    file_name_offset = _WindowsFileRenameInformation.file_name.offset
    buffer = ctypes.create_string_buffer(
        ctypes.sizeof(_WindowsFileRenameInformation) + len(encoded_name)
    )
    information = ctypes.cast(
        buffer,
        ctypes.POINTER(_WindowsFileRenameInformation),
    ).contents
    information.replace_if_exists = replace_if_exists
    information.root_directory = wintypes.HANDLE(parent_handle)
    information.file_name_length = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + file_name_offset,
        encoded_name,
        len(encoded_name),
    )
    ntdll = _windows_ntdll()
    set_information = getattr(ntdll, "NtSetInformationFile", None)
    if set_information is None:
        raise OSError("Windows handle-relative file rename is unavailable")
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_WindowsIoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    )
    set_information.restype = wintypes.LONG
    io_status = _WindowsIoStatusBlock()
    status = int(
        set_information(
            wintypes.HANDLE(source_handle),
            ctypes.byref(io_status),
            buffer,
            len(buffer),
            _WINDOWS_FILE_RENAME_INFORMATION,
        )
    )
    if status != 0:
        raise _windows_ntstatus_error(status)


def _open_lease_regular_lock_file(
    lease: RootedDirectoryDescriptor,
    name: str,
    *,
    mode: int,
) -> tuple[int, os.stat_result]:
    path = lease.path / name
    if os.name != "nt":
        directory = lease._require_posix_descriptor(label="rooted lock")
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= cast(int, vars(os)["O_NOFOLLOW"])
        descriptor: int | None = None
        try:
            descriptor = os.open(name, flags, mode, dir_fd=directory)
            metadata = os.fstat(descriptor)
            _require_unlinked_regular_file(metadata, path=path)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            _require_unlinked_regular_file(current, path=path)
            _require_same_object(metadata, current, path=path, label="rooted lock")
            result = (descriptor, metadata)
            descriptor = None
            return result
        finally:
            _close_descriptor(descriptor)

    directory = lease._require_windows_handle(label="rooted lock")
    handle: int | None = None
    descriptor = None
    try:
        try:
            handle = _windows_open_relative_handle(
                directory,
                name,
                desired_access=(
                    _WINDOWS_FILE_READ_DATA
                    | _WINDOWS_FILE_WRITE_DATA
                    | _WINDOWS_FILE_READ_ATTRIBUTES
                    | _WINDOWS_FILE_WRITE_ATTRIBUTES
                    | _WINDOWS_SYNCHRONIZE
                ),
                share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
                create_disposition=_WINDOWS_FILE_CREATE,
                create_options=(
                    _WINDOWS_FILE_NON_DIRECTORY_FILE
                    | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                    | _WINDOWS_FILE_OPEN_REPARSE_POINT
                ),
                file_attributes=_WINDOWS_FILE_ATTRIBUTE_NORMAL,
                require_created=True,
            )
        except FileExistsError:
            handle = _windows_open_relative_handle(
                directory,
                name,
                desired_access=(
                    _WINDOWS_FILE_READ_DATA
                    | _WINDOWS_FILE_WRITE_DATA
                    | _WINDOWS_FILE_READ_ATTRIBUTES
                    | _WINDOWS_FILE_WRITE_ATTRIBUTES
                    | _WINDOWS_SYNCHRONIZE
                ),
                share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
                create_disposition=_WINDOWS_FILE_OPEN,
                create_options=(
                    _WINDOWS_FILE_NON_DIRECTORY_FILE
                    | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                    | _WINDOWS_FILE_OPEN_REPARSE_POINT
                ),
                file_attributes=0,
            )
        identity = _windows_handle_identity(handle)
        _windows_require_regular_file(identity, path=path, label="rooted lock")
        if identity.number_of_links != 1:
            raise ValueError(f"rooted lock must be a single-link regular file: {path}")
        descriptor = _windows_handle_to_descriptor(
            handle,
            flags=os.O_RDWR | getattr(os, "O_BINARY", 0),
        )
        handle = None
        metadata = os.fstat(descriptor)
        _require_unlinked_regular_file(metadata, path=path)
        result = (descriptor, metadata)
        descriptor = None
        return result
    finally:
        _close_descriptor(descriptor)
        _windows_close_handle(handle)


def _stat_lease_entry_no_follow(
    lease: RootedDirectoryDescriptor,
    name: str,
) -> os.stat_result:
    path = lease.path / name
    if os.name != "nt":
        directory = lease._require_posix_descriptor(label="rooted output")
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _require_not_link(metadata, path=path)
        return metadata
    handle = _windows_open_relative_handle(
        lease._require_windows_handle(label="rooted output"),
        name,
        desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        create_disposition=_WINDOWS_FILE_OPEN,
        create_options=(_WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT | _WINDOWS_FILE_OPEN_REPARSE_POINT),
        file_attributes=0,
    )
    try:
        identity = _windows_handle_identity(handle)
        _windows_require_not_reparse(identity, path=path)
        return _windows_fstat_handle(handle)
    finally:
        _windows_close_handle(handle)


def _unlink_lease_entry_no_follow(
    lease: RootedDirectoryDescriptor,
    name: str,
    *,
    expected_device: int | None,
    expected_inode: int | None,
) -> None:
    path = lease.path / name
    if os.name != "nt":
        directory = lease._require_posix_descriptor(label="rooted output")
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _require_unlinked_regular_file(metadata, path=path)
        _require_expected_entry_identity(
            metadata,
            expected_device=expected_device,
            expected_inode=expected_inode,
            path=path,
        )
        os.unlink(name, dir_fd=directory)
        return

    handle = _windows_open_relative_handle(
        lease._require_windows_handle(label="rooted output"),
        name,
        desired_access=_WINDOWS_DELETE | _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        create_disposition=_WINDOWS_FILE_OPEN,
        create_options=(
            _WINDOWS_FILE_NON_DIRECTORY_FILE
            | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
            | _WINDOWS_FILE_OPEN_REPARSE_POINT
        ),
        file_attributes=0,
    )
    try:
        identity = _windows_handle_identity(handle)
        _windows_require_regular_file(identity, path=path, label="rooted output")
        if identity.number_of_links != 1:
            raise ValueError(f"rooted output must be a single-link regular file: {path}")
        metadata = _windows_fstat_handle(handle)
        _require_expected_entry_identity(
            metadata,
            expected_device=expected_device,
            expected_inode=expected_inode,
            path=path,
        )
        _windows_set_delete_disposition(handle, expected_identity=identity)
    finally:
        _windows_close_handle(handle)


def _unlink_lease_file_or_link_no_follow(
    lease: RootedDirectoryDescriptor,
    name: str,
    *,
    expected_device: int | None,
    expected_inode: int | None,
) -> None:
    path = lease.path / name
    if os.name != "nt":
        directory = lease._require_posix_descriptor(label="rooted output")
        metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
        attributes = getattr(metadata, "st_file_attributes", 0)
        is_reparse = bool(attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
        if stat.S_ISDIR(metadata.st_mode) and not (stat.S_ISLNK(metadata.st_mode) or is_reparse):
            raise IsADirectoryError(path)
        _require_expected_entry_identity(
            metadata,
            expected_device=expected_device,
            expected_inode=expected_inode,
            path=path,
        )
        os.unlink(name, dir_fd=directory)
        return

    handle = _windows_open_relative_handle(
        lease._require_windows_handle(label="rooted output"),
        name,
        desired_access=_WINDOWS_DELETE | _WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        share_access=(
            _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE | _WINDOWS_FILE_SHARE_DELETE
        ),
        create_disposition=_WINDOWS_FILE_OPEN,
        create_options=(_WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT | _WINDOWS_FILE_OPEN_REPARSE_POINT),
        file_attributes=0,
    )
    try:
        identity = _windows_handle_identity(handle)
        is_reparse = bool(identity.attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
        if identity.attributes & _WINDOWS_FILE_ATTRIBUTE_DIRECTORY and not is_reparse:
            raise IsADirectoryError(path)
        metadata = _windows_fstat_handle(handle)
        _require_expected_entry_identity(
            metadata,
            expected_device=expected_device,
            expected_inode=expected_inode,
            path=path,
        )
        _windows_set_delete_disposition(handle, expected_identity=identity)
    finally:
        _windows_close_handle(handle)


def acquire_publication_lock(
    descriptor: int,
    *,
    label: str,
    timeout_seconds: float = PUBLICATION_LOCK_TIMEOUT_SECONDS,
) -> None:
    """Acquire a publication lock under one explicit cross-platform deadline."""

    if not label.strip():
        raise ValueError("publication lock label must not be empty")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("publication lock timeout must be finite and positive")
    acquire_once: Callable[[], None]
    is_contention: Callable[[OSError], bool]
    if _IS_WINDOWS:
        locking, nonblocking_mode, _unlock_mode = _windows_locking_api()
        acquire_once = partial(locking, descriptor, nonblocking_mode, 1)
        is_contention = _is_windows_lock_contention
    else:
        flock, nonblocking_mode, _unlock_mode = _posix_locking_api()
        acquire_once = partial(flock, descriptor, nonblocking_mode)
        is_contention = _is_posix_lock_contention

    deadline = _publication_lock_monotonic() + timeout_seconds
    while True:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            acquire_once()
        except OSError as exc:
            if not is_contention(exc):
                raise
            remaining = deadline - _publication_lock_monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    errno.ETIMEDOUT,
                    f"{label} lock acquisition timed out after {timeout_seconds:g} seconds",
                ) from exc
            _publication_lock_sleep(min(_PUBLICATION_LOCK_RETRY_INTERVAL_SECONDS, remaining))
            if _publication_lock_monotonic() >= deadline:
                raise TimeoutError(
                    errno.ETIMEDOUT,
                    f"{label} lock acquisition timed out after {timeout_seconds:g} seconds",
                ) from exc
        else:
            return


def release_publication_lock(descriptor: int) -> None:
    """Release a lock acquired by :func:`acquire_publication_lock`."""

    os.lseek(descriptor, 0, os.SEEK_SET)
    if _IS_WINDOWS:
        locking, _nonblocking_mode, unlock_mode = _windows_locking_api()
        locking(descriptor, unlock_mode, 1)
        return
    flock, _nonblocking_mode, unlock_mode = _posix_locking_api()
    flock(descriptor, unlock_mode)


def retry_windows_sharing_violation(
    operation: Callable[[], _RetryResult],
    *,
    timeout_seconds: float,
) -> _RetryResult:
    """Retry a complete verification only for typed Windows sharing contention.

    This is intended for a rooted publication verifier that races an honest
    winner's short-lived, rename-pinning DELETE handle. Every retry invokes the
    complete caller-supplied operation again. Numeric WinError 32/33 is required;
    broad ``EACCES`` failures and exception text never trigger a retry.
    """

    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("sharing-violation retry timeout must be finite and positive")
    deadline = _publication_lock_monotonic() + timeout_seconds
    retry_interval = _WINDOWS_SHARING_RETRY_INITIAL_INTERVAL_SECONDS
    while True:
        try:
            return operation()
        except Exception as exc:
            if not _contains_windows_sharing_violation(exc):
                raise
            remaining = deadline - _publication_lock_monotonic()
            if remaining <= 0:
                raise
            _publication_lock_sleep(min(retry_interval, remaining))
            if _publication_lock_monotonic() >= deadline:
                raise
            retry_interval = min(
                retry_interval * 2,
                _WINDOWS_SHARING_RETRY_MAX_INTERVAL_SECONDS,
            )


def _contains_windows_sharing_violation(exc: BaseException) -> bool:
    if not _IS_WINDOWS:
        return False
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if (
            isinstance(current, OSError)
            and getattr(current, "winerror", None) in _WINDOWS_LOCK_CONTENTION_WINERRORS
        ):
            return True
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return False


def _windows_locking_api() -> tuple[
    Callable[[int, int, int], None],
    int,
    int,
]:
    msvcrt = importlib.import_module("msvcrt")
    locking = cast(Callable[[int, int, int], None], msvcrt.locking)
    return locking, int(msvcrt.LK_NBLCK), int(msvcrt.LK_UNLCK)


def _posix_locking_api() -> tuple[
    Callable[[int, int], None],
    int,
    int,
]:
    fcntl = importlib.import_module("fcntl")
    flock = cast(Callable[[int, int], None], fcntl.flock)
    return flock, int(fcntl.LOCK_EX | fcntl.LOCK_NB), int(fcntl.LOCK_UN)


def _is_windows_lock_contention(exc: OSError) -> bool:
    return (
        exc.errno in _WINDOWS_LOCK_CONTENTION_ERRNOS
        or getattr(
            exc,
            "winerror",
            None,
        )
        in _WINDOWS_LOCK_CONTENTION_WINERRORS
    )


def _is_posix_lock_contention(exc: OSError) -> bool:
    return exc.errno in _POSIX_LOCK_CONTENTION_ERRNOS


def _publication_lock_monotonic() -> float:
    return time.monotonic()


def _publication_lock_sleep(seconds: float) -> None:
    time.sleep(seconds)


def claim_rooted_directory(
    parent: RootedDirectoryDescriptor,
    name: str | Path,
    *,
    label: str,
    mode: int = 0o700,
) -> RootedDirectoryClaim:
    """Atomically create and pin one child directory below a pinned parent."""
    component = _portable_single_component(name, label=f"{label} name")
    _validate_creation_mode(mode)
    if parent.closed:
        raise ValueError(f"{label} parent directory lease is closed")
    if os.name == "nt":
        return _claim_windows_rooted_directory(
            parent,
            component,
            label=label,
            mode=mode,
        )
    return _claim_posix_rooted_directory(parent, component, label=label, mode=mode)


def _posix_install_claim_no_replace(
    claim: RootedDirectoryClaim,
    target_name: str,
) -> None:
    descriptor = claim._require_posix_descriptor()
    parent_descriptor = claim._require_posix_parent_descriptor()
    opened = os.fstat(descriptor)
    _require_directory(opened, path=claim.path, label="claimed directory")
    _require_claim_identity(
        opened,
        device=claim.device,
        inode=claim.inode,
        path=claim.path,
    )
    source = os.stat(
        claim.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    _require_directory(source, path=claim.path, label="claimed directory")
    _require_same_object(opened, source, path=claim.path, label="claimed directory")
    _posix_renameat_no_replace(
        parent_descriptor,
        claim.name,
        target_name,
    )


def _posix_renameat_no_replace(
    parent_descriptor: int,
    source_name: str,
    target_name: str,
) -> None:
    source = os.fsencode(source_name)
    target = os.fsencode(target_name)
    ctypes.set_errno(0)
    result: int
    if (_IS_LINUX or _IS_FREEBSD) and _POSIX_RENAMEAT2 is not None:
        result = int(
            _POSIX_RENAMEAT2(
                parent_descriptor,
                source,
                parent_descriptor,
                target,
                _RENAME_NOREPLACE,
            )
        )
    elif (
        _IS_LINUX
        and _POSIX_RENAMEAT2_SYSCALL is not None
        and _LINUX_RENAMEAT2_SYSCALL_NUMBER is not None
    ):
        result = int(
            _POSIX_RENAMEAT2_SYSCALL(
                ctypes.c_long(_LINUX_RENAMEAT2_SYSCALL_NUMBER),
                ctypes.c_int(parent_descriptor),
                ctypes.c_char_p(source),
                ctypes.c_int(parent_descriptor),
                ctypes.c_char_p(target),
                ctypes.c_uint(_RENAME_NOREPLACE),
            )
        )
    elif _IS_DARWIN and _POSIX_RENAMEATX_NP is not None:
        result = int(
            _POSIX_RENAMEATX_NP(
                parent_descriptor,
                source,
                parent_descriptor,
                target,
                _RENAME_EXCL,
            )
        )
    else:
        raise OSError(
            errno.ENOSYS,
            (
                "atomic no-replace directory installation requires renameat2, "
                "a supported Linux renameat2 syscall ABI, or renameatx_np"
            ),
            target_name,
        )
    if result == 0:
        return
    error = ctypes.get_errno() or errno.EIO
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, os.strerror(error), target_name)
    if error == errno.ENOSYS:
        raise OSError(
            error,
            "atomic no-replace directory installation is unavailable on this kernel",
            target_name,
        )
    raise OSError(error, os.strerror(error), target_name)


def _windows_install_claim_no_replace(
    claim: RootedDirectoryClaim,
    target_name: str,
) -> None:
    handle = claim._require_windows_handle()
    parent_handle = claim._require_windows_parent_handle()
    before = _windows_handle_identity(handle)
    _windows_require_directory(before, path=claim.path, label="claimed directory")
    if before.file_index != claim.inode:
        raise OSError("claimed directory identity changed")
    encoded_name = target_name.encode("utf-16-le")
    file_name_offset = _WindowsFileRenameInformation.file_name.offset
    buffer = ctypes.create_string_buffer(
        ctypes.sizeof(_WindowsFileRenameInformation) + len(encoded_name)
    )
    information = ctypes.cast(
        buffer,
        ctypes.POINTER(_WindowsFileRenameInformation),
    ).contents
    information.replace_if_exists = False
    information.root_directory = wintypes.HANDLE(parent_handle)
    information.file_name_length = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + file_name_offset,
        encoded_name,
        len(encoded_name),
    )
    ntdll = _windows_ntdll()
    set_information = getattr(ntdll, "NtSetInformationFile", None)
    if set_information is None:
        raise OSError("Windows handle-relative no-replace rename is unavailable")
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_WindowsIoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    )
    set_information.restype = wintypes.LONG
    io_status = _WindowsIoStatusBlock()
    status = int(
        set_information(
            wintypes.HANDLE(handle),
            ctypes.byref(io_status),
            buffer,
            len(buffer),
            _WINDOWS_FILE_RENAME_INFORMATION,
        )
    )
    if status != 0:
        raise _windows_ntstatus_error(status)


def _require_installed_claim_identity(claim: RootedDirectoryClaim) -> None:
    """Verify the committed name still resolves to the claim's pinned object."""
    if os.name == "nt":
        _windows_require_installed_claim_identity(claim)
        return
    descriptor = claim._require_posix_descriptor()
    parent_descriptor = claim._require_posix_parent_descriptor()
    opened = os.fstat(descriptor)
    _require_directory(opened, path=claim.path, label="installed directory")
    _require_claim_identity(
        opened,
        device=claim.device,
        inode=claim.inode,
        path=claim.path,
    )
    installed = os.stat(
        claim.name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    _require_directory(installed, path=claim.path, label="installed directory")
    _require_same_object(
        opened,
        installed,
        path=claim.path,
        label="installed directory",
    )


def _windows_require_installed_claim_identity(claim: RootedDirectoryClaim) -> None:
    handle = claim._require_windows_handle()
    parent_handle = claim._require_windows_parent_handle()
    after = _windows_handle_identity(handle)
    _windows_require_directory(after, path=claim.path, label="installed directory")
    if after.file_index != claim.inode:
        raise OSError("installed directory identity changed")
    target_handle = _windows_open_relative_handle(
        parent_handle,
        claim.name,
        desired_access=_WINDOWS_FILE_READ_ATTRIBUTES | _WINDOWS_SYNCHRONIZE,
        share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        create_disposition=_WINDOWS_FILE_OPEN,
        create_options=(
            _WINDOWS_FILE_DIRECTORY_FILE
            | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
            | _WINDOWS_FILE_OPEN_REPARSE_POINT
        ),
        file_attributes=0,
    )
    try:
        _windows_require_same_directory_object(
            after,
            _windows_handle_identity(target_handle),
            path=claim.path,
            label="installed directory",
        )
    finally:
        _windows_close_handle(target_handle)


def _claim_posix_rooted_directory(
    parent: RootedDirectoryDescriptor,
    name: str,
    *,
    label: str,
    mode: int,
) -> RootedDirectoryClaim:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("race-resistant rooted directory claims are unavailable on this platform")
    if parent.descriptor is None:
        raise OSError(f"{label} parent POSIX descriptor is unavailable")
    parent_descriptor: int | None = None
    child_descriptor: int | None = None
    created_identity: os.stat_result | None = None
    created = False
    try:
        parent_descriptor = os.dup(parent.descriptor)
        parent_metadata = os.fstat(parent_descriptor)
        _require_directory(parent_metadata, path=parent.path, label=f"{label} parent")
        _require_claim_identity(
            parent_metadata,
            device=parent.device,
            inode=parent.inode,
            path=parent.path,
        )
        os.mkdir(name, mode=mode, dir_fd=parent_descriptor)
        created = True
        created_identity = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        _require_directory(created_identity, path=parent.path / name, label=label)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY
        directory_flags |= cast(int, vars(os)["O_NOFOLLOW"])
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NONBLOCK", 0)
        child_descriptor = os.open(name, directory_flags, dir_fd=parent_descriptor)
        opened = os.fstat(child_descriptor)
        _require_directory(opened, path=parent.path / name, label=label)
        _require_same_object(
            created_identity,
            opened,
            path=parent.path / name,
            label=label,
        )
        current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        _require_directory(current, path=parent.path / name, label=label)
        _require_same_object(created_identity, current, path=parent.path / name, label=label)
        result = RootedDirectoryClaim(
            path=parent.path / name,
            name=name,
            device=opened.st_dev,
            inode=opened.st_ino,
            descriptor=child_descriptor,
            parent_descriptor=parent_descriptor,
        )
        child_descriptor = None
        parent_descriptor = None
        return result
    except BaseException as exc:
        cleanup_error: OSError | None = None
        if created and parent_descriptor is not None and created_identity is not None:
            try:
                current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                _require_directory(current, path=parent.path / name, label=label)
                _require_same_object(
                    created_identity,
                    current,
                    path=parent.path / name,
                    label=label,
                )
                os.rmdir(name, dir_fd=parent_descriptor)
            except OSError as cleanup_exc:
                cleanup_error = cleanup_exc
            except ValueError as cleanup_exc:
                cleanup_error = OSError(str(cleanup_exc))
        if cleanup_error is not None:
            raise OSError(f"{label} claim failed and cleanup was incomplete") from exc
        raise
    finally:
        _close_descriptor(child_descriptor)
        _close_descriptor(parent_descriptor)


def _claim_windows_rooted_directory(
    parent: RootedDirectoryDescriptor,
    name: str,
    *,
    label: str,
    mode: int,
) -> RootedDirectoryClaim:
    if not parent._windows_directory_handles:
        raise OSError(f"{label} parent Windows handle is unavailable")
    source_handle = parent._windows_directory_handles[-1]
    parent_handle: int | None = None
    child_handle: int | None = None
    security_descriptor: int | None = None
    created = False
    try:
        source_identity = _windows_handle_identity(source_handle)
        _windows_require_directory(source_identity, path=parent.path, label=f"{label} parent")
        if source_identity.file_index != parent.inode:
            raise OSError(f"{label} parent identity changed")
        parent_handle = _windows_reopen_directory_for_mutation(source_handle)
        reopened_identity = _windows_handle_identity(parent_handle)
        _windows_require_directory(reopened_identity, path=parent.path, label=f"{label} parent")
        _windows_require_same_directory_object(
            source_identity,
            reopened_identity,
            path=parent.path,
            label=f"{label} parent",
        )
        if mode != 0o700:
            raise OSError("Windows rooted directory claims require owner-only mode 0o700")
        security_descriptor = _windows_owner_only_security_descriptor()
        child_handle = _windows_open_relative_handle(
            parent_handle,
            name,
            desired_access=(
                _WINDOWS_FILE_LIST_DIRECTORY
                | _WINDOWS_FILE_ADD_FILE
                | _WINDOWS_FILE_READ_ATTRIBUTES
                | _WINDOWS_FILE_WRITE_ATTRIBUTES
                | _WINDOWS_READ_CONTROL
                | _WINDOWS_DELETE
                | _WINDOWS_SYNCHRONIZE
            ),
            share_access=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
            create_disposition=_WINDOWS_FILE_CREATE,
            create_options=(
                _WINDOWS_FILE_DIRECTORY_FILE
                | _WINDOWS_FILE_SYNCHRONOUS_IO_NONALERT
                | _WINDOWS_FILE_OPEN_REPARSE_POINT
            ),
            file_attributes=_WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
            require_created=True,
            security_descriptor=security_descriptor,
        )
        created = True
        _windows_require_owner_only_dacl(child_handle)
        identity = _windows_handle_identity(child_handle)
        _windows_require_directory(identity, path=parent.path / name, label=label)
        metadata = _windows_fstat_handle(child_handle)
        _require_directory(metadata, path=parent.path / name, label=label)
        if metadata.st_ino != identity.file_index:
            raise OSError(f"{label} native and descriptor identities differ")
        result = RootedDirectoryClaim(
            path=parent.path / name,
            name=name,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            windows_handle=child_handle,
            windows_parent_handle=parent_handle,
        )
        child_handle = None
        parent_handle = None
        return result
    except BaseException as exc:
        cleanup_error: OSError | None = None
        if created and child_handle is not None:
            try:
                _windows_set_delete_disposition(child_handle)
            except OSError as cleanup_exc:
                cleanup_error = cleanup_exc
        if cleanup_error is not None:
            raise OSError(f"{label} claim failed and cleanup was incomplete") from exc
        raise
    finally:
        _windows_local_free(security_descriptor)
        _windows_close_handle(child_handle)
        _windows_close_handle(parent_handle)


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
            _windows_require_same_directory_object(
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


def _portable_single_component(name: str | Path, *, label: str) -> str:
    try:
        parts = portable_relative_path_parts(name)
    except ValueError as exc:
        raise ValueError(f"{label} must be one portable path component") from exc
    if len(parts) != 1:
        raise ValueError(f"{label} must be one portable path component")
    return parts[0]


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


def _validate_creation_mode(mode: int) -> None:
    if isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o777:
        raise ValueError("creation mode must contain only portable permission bits")


def _validate_expected_identity(
    expected_device: int | None,
    expected_inode: int | None,
) -> None:
    if (expected_device is None) != (expected_inode is None):
        raise ValueError("expected entry device and inode must be supplied together")
    for value in (expected_device, expected_inode):
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ValueError("expected entry identity must contain non-negative integers")


def _require_directory(metadata: os.stat_result, *, path: Path, label: str) -> None:
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"{label} must be a directory without links: {path}")


def _require_not_link(metadata: os.stat_result, *, path: Path) -> None:
    attributes = getattr(metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(metadata.st_mode) or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"rooted output entry must not be a link or reparse point: {path}")


def _require_unlinked_regular_file(metadata: os.stat_result, *, path: Path) -> None:
    _require_not_link(metadata, path=path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"rooted output entry must be a single-link regular file: {path}")


def _require_expected_entry_identity(
    metadata: os.stat_result,
    *,
    expected_device: int | None,
    expected_inode: int | None,
    path: Path,
) -> None:
    if expected_device is None or expected_inode is None:
        return
    if (metadata.st_dev, metadata.st_ino) != (expected_device, expected_inode):
        raise OSError(f"rooted output entry identity changed: {path}")


def _require_claim_identity(
    metadata: os.stat_result,
    *,
    device: int,
    inode: int,
    path: Path,
) -> None:
    if (metadata.st_dev, metadata.st_ino) != (device, inode):
        raise OSError(f"claimed directory identity changed: {path}")


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


def _windows_advapi32() -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("Win32 security APIs are unavailable")
    return win_dll("advapi32", use_last_error=True)


def _windows_owner_only_security_descriptor() -> int:
    advapi32 = _windows_advapi32()
    convert = getattr(
        advapi32,
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        None,
    )
    if convert is None:
        raise OSError("Windows owner-only security descriptor creation is unavailable")
    convert.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.ULONG),
    )
    convert.restype = wintypes.BOOL
    descriptor = wintypes.LPVOID()
    descriptor_size = wintypes.ULONG()
    if not convert(
        "D:P(A;;FA;;;OW)",
        _WINDOWS_SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        raise _windows_last_error()
    if descriptor.value is None:
        raise OSError("Windows owner-only security descriptor creation returned no value")
    return int(descriptor.value)


def _windows_local_free(pointer: int | None) -> None:
    if pointer is None:
        return
    kernel32 = _windows_kernel32()
    local_free = getattr(kernel32, "LocalFree", None)
    if local_free is None:
        raise OSError("Windows local security descriptor cleanup is unavailable")
    local_free.argtypes = (wintypes.LPVOID,)
    local_free.restype = wintypes.LPVOID
    result = local_free(wintypes.LPVOID(pointer))
    if result:
        raise _windows_last_error()


def _windows_require_owner_only_dacl(handle: int) -> None:
    advapi32 = _windows_advapi32()
    get_security = getattr(advapi32, "GetKernelObjectSecurity", None)
    convert = getattr(
        advapi32,
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        None,
    )
    if get_security is None or convert is None:
        raise OSError("Windows owner-only DACL verification is unavailable")
    get_security.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    get_security.restype = wintypes.BOOL
    required = wintypes.DWORD()
    get_security(
        wintypes.HANDLE(handle),
        _WINDOWS_DACL_SECURITY_INFORMATION,
        None,
        0,
        ctypes.byref(required),
    )
    if required.value == 0:
        raise _windows_last_error()
    descriptor = ctypes.create_string_buffer(required.value)
    if not get_security(
        wintypes.HANDLE(handle),
        _WINDOWS_DACL_SECURITY_INFORMATION,
        descriptor,
        required.value,
        ctypes.byref(required),
    ):
        raise _windows_last_error()
    convert.argtypes = (
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.ULONG),
    )
    convert.restype = wintypes.BOOL
    rendered = wintypes.LPWSTR()
    rendered_length = wintypes.ULONG()
    if not convert(
        descriptor,
        _WINDOWS_SDDL_REVISION_1,
        _WINDOWS_DACL_SECURITY_INFORMATION,
        ctypes.byref(rendered),
        ctypes.byref(rendered_length),
    ):
        raise _windows_last_error()
    rendered_pointer = ctypes.cast(rendered, ctypes.c_void_p).value
    try:
        if rendered.value != "D:P(A;;FA;;;OW)":
            raise OSError("Windows rooted directory does not have the owner-only DACL")
    finally:
        _windows_local_free(int(rendered_pointer) if rendered_pointer is not None else None)


def _windows_ntdll() -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("Windows native handle APIs are unavailable")
    return win_dll("ntdll")


def _windows_ntstatus_error(status: int) -> OSError:
    unsigned_status = status & 0xFFFFFFFF
    if unsigned_status == _WINDOWS_STATUS_OBJECT_NAME_COLLISION:
        return FileExistsError(errno.EEXIST, "rooted entry already exists")
    try:
        ntdll = _windows_ntdll()
        to_dos_error = getattr(ntdll, "RtlNtStatusToDosError", None)
        if to_dos_error is None:
            raise OSError("RtlNtStatusToDosError is unavailable")
        to_dos_error.argtypes = (wintypes.LONG,)
        to_dos_error.restype = wintypes.ULONG
        error_code = int(to_dos_error(wintypes.LONG(status)))
        if error_code in {0, 317}:  # ERROR_SUCCESS / ERROR_MR_MID_NOT_FOUND
            raise OSError("NTSTATUS could not be mapped to a Win32 error")
        win_error = cast(Callable[[int], OSError], vars(ctypes)["WinError"])
        return win_error(error_code)
    except (AttributeError, KeyError, OSError):
        return OSError(
            f"Windows native file operation failed with NTSTATUS 0x{unsigned_status:08x}"
        )


def _windows_reopen_directory_for_mutation(handle: int) -> int:
    """Open mutation access while the source handle prevents path replacement."""
    kernel32 = _windows_kernel32()
    create_file = getattr(kernel32, "CreateFileW", None)
    if create_file is None:
        raise OSError("race-resistant Windows directory claims are unavailable")
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
    source_identity = _windows_handle_identity(handle)
    source_final_path = _windows_final_path(handle)
    raw_handle = create_file(
        source_final_path,
        _WINDOWS_FILE_LIST_DIRECTORY
        | _WINDOWS_FILE_ADD_SUBDIRECTORY
        | _WINDOWS_FILE_READ_ATTRIBUTES
        | _WINDOWS_SYNCHRONIZE,
        _WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT | _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if raw_handle is None or raw_handle == invalid_handle:
        raise _windows_last_error()
    reopened_handle = int(raw_handle)
    try:
        reopened_identity = _windows_handle_identity(reopened_handle)
        _windows_require_same_directory_object(
            source_identity,
            reopened_identity,
            path=Path(source_final_path),
            label="rooted directory parent",
        )
        if _windows_normalize_final_path(_windows_final_path(reopened_handle)) != (
            _windows_normalize_final_path(source_final_path)
        ):
            raise OSError("rooted directory parent final path changed while reopening")
        return reopened_handle
    except BaseException:
        _windows_close_handle(reopened_handle)
        raise


def _windows_open_relative_handle(
    root_handle: int,
    name: str,
    *,
    desired_access: int,
    share_access: int,
    create_disposition: int,
    create_options: int,
    file_attributes: int,
    require_created: bool = False,
    security_descriptor: int | None = None,
) -> int:
    ntdll = _windows_ntdll()
    nt_create_file = getattr(ntdll, "NtCreateFile", None)
    if nt_create_file is None:
        raise OSError("race-resistant Windows relative file APIs are unavailable")
    nt_create_file.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_WindowsObjectAttributes),
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    )
    nt_create_file.restype = wintypes.LONG

    name_length = len(name.encode("utf-16-le"))
    if name_length > 0xFFFC:
        raise ValueError("rooted entry name exceeds the Windows native name limit")
    name_buffer = ctypes.create_unicode_buffer(name)
    unicode_name = _WindowsUnicodeString(
        length=name_length,
        maximum_length=name_length + 2,
        buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    object_attributes = _WindowsObjectAttributes(
        length=ctypes.sizeof(_WindowsObjectAttributes),
        root_directory=wintypes.HANDLE(root_handle),
        object_name=ctypes.pointer(unicode_name),
        attributes=_WINDOWS_OBJ_CASE_INSENSITIVE,
        security_descriptor=(
            wintypes.LPVOID(security_descriptor) if security_descriptor is not None else None
        ),
        security_quality_of_service=None,
    )
    io_status = _WindowsIoStatusBlock()
    result_handle = wintypes.HANDLE()
    status = int(
        nt_create_file(
            ctypes.byref(result_handle),
            desired_access,
            ctypes.byref(object_attributes),
            ctypes.byref(io_status),
            None,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            None,
            0,
        )
    )
    handle = int(result_handle.value) if result_handle.value is not None else None
    if status != 0:
        cleanup_error: OSError | None = None
        if (
            handle is not None
            and create_disposition == _WINDOWS_FILE_CREATE
            and int(io_status.information) == _WINDOWS_FILE_CREATED
        ):
            try:
                _windows_set_delete_disposition(handle)
            except OSError as exc:
                cleanup_error = exc
        _windows_close_handle(handle)
        if cleanup_error is not None:
            raise OSError(
                "Windows native file operation returned an anomalous status and cleanup "
                "was incomplete"
            ) from cleanup_error
        if status < 0:
            raise _windows_ntstatus_error(status)
        raise OSError(f"Windows native file operation returned unexpected NTSTATUS 0x{status:08x}")
    if handle is None:
        raise OSError("Windows native file operation returned no handle")

    information = int(io_status.information)
    expected_information = (
        _WINDOWS_FILE_CREATED
        if create_disposition == _WINDOWS_FILE_CREATE
        else _WINDOWS_FILE_OPENED
    )
    if information != expected_information or (
        require_created and information != _WINDOWS_FILE_CREATED
    ):
        cleanup_error = None
        if create_disposition == _WINDOWS_FILE_CREATE and information == _WINDOWS_FILE_CREATED:
            try:
                _windows_set_delete_disposition(handle)
            except OSError as exc:
                cleanup_error = exc
        _windows_close_handle(handle)
        if cleanup_error is not None:
            raise OSError(
                "Windows native file operation returned an unexpected disposition and "
                "cleanup was incomplete"
            ) from cleanup_error
        raise OSError("Windows native file operation returned an unexpected I/O disposition")
    return handle


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
    if directory:
        share_mode |= _WINDOWS_FILE_SHARE_WRITE
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
        number_of_links=int(information.number_of_links),
        size=(int(information.file_size_high) << 32) | int(information.file_size_low),
        last_write_time=(int(information.last_write_time.high) << 32)
        | int(information.last_write_time.low),
    )


def _windows_duplicate_handle(handle: int) -> int:
    kernel32 = _windows_kernel32()
    get_current_process = cast(Any, kernel32.GetCurrentProcess)
    get_current_process.argtypes = ()
    get_current_process.restype = wintypes.HANDLE
    duplicate_handle = cast(Any, kernel32.DuplicateHandle)
    duplicate_handle.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    duplicate_handle.restype = wintypes.BOOL
    process = get_current_process()
    duplicated = wintypes.HANDLE()
    if not duplicate_handle(
        process,
        wintypes.HANDLE(handle),
        process,
        ctypes.byref(duplicated),
        0,
        False,
        0x00000002,  # DUPLICATE_SAME_ACCESS
    ):
        raise _windows_last_error()
    if duplicated.value is None:
        raise OSError("Windows handle duplication returned no handle")
    return int(duplicated.value)


def _windows_fstat_handle(handle: int) -> os.stat_result:
    duplicated_handle: int | None = _windows_duplicate_handle(handle)
    descriptor: int | None = None
    try:
        assert duplicated_handle is not None
        descriptor = _windows_handle_to_descriptor(
            duplicated_handle,
            flags=os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        duplicated_handle = None
        return os.fstat(descriptor)
    finally:
        _close_descriptor(descriptor)
        _windows_close_handle(duplicated_handle)


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


def _windows_handle_to_descriptor(handle: int, *, flags: int | None = None) -> int:
    msvcrt = importlib.import_module("msvcrt")
    open_osfhandle = cast(Callable[[int, int], int], msvcrt.open_osfhandle)
    descriptor_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) if flags is None else flags
    return open_osfhandle(handle, descriptor_flags)


def _windows_set_delete_disposition(
    handle: int,
    *,
    expected_identity: _WindowsHandleIdentity | None = None,
) -> None:
    if expected_identity is not None:
        observed_identity = _windows_handle_identity(handle)
        _windows_require_same_identity(
            expected_identity,
            observed_identity,
            path=Path("<native-handle>"),
            label="rooted output",
        )
    kernel32 = _windows_kernel32()
    set_information = getattr(kernel32, "SetFileInformationByHandle", None)
    if set_information is None:
        raise OSError("Windows handle-anchored deletion is unavailable")
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL
    disposition = _WindowsFileDispositionInformation(delete_file=True)
    if not set_information(
        wintypes.HANDLE(handle),
        _WINDOWS_FILE_DISPOSITION_INFORMATION,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise _windows_last_error()


def _windows_set_descriptor_delete_disposition(descriptor: int) -> None:
    msvcrt = importlib.import_module("msvcrt")
    get_osfhandle = cast(Callable[[int], int], msvcrt.get_osfhandle)
    handle = get_osfhandle(descriptor)
    if handle == -1:
        raise OSError("Windows descriptor has no native handle")
    identity = _windows_handle_identity(handle)
    _windows_set_delete_disposition(handle, expected_identity=identity)


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


def _windows_require_not_reparse(
    identity: _WindowsHandleIdentity,
    *,
    path: Path,
) -> None:
    if identity.attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
        raise ValueError(f"rooted output entry must not be a reparse point: {path}")


def _windows_require_same_identity(
    expected: _WindowsHandleIdentity,
    observed: _WindowsHandleIdentity,
    *,
    path: Path,
    label: str,
) -> None:
    if expected != observed:
        raise ValueError(f"{label} changed while it was being read: {path}")


def _windows_require_same_directory_object(
    expected: _WindowsHandleIdentity,
    observed: _WindowsHandleIdentity,
    *,
    path: Path,
    label: str,
) -> None:
    """Compare stable directory object identity, not mutable inventory metadata."""
    if (expected.volume_serial_number, expected.file_index) != (
        observed.volume_serial_number,
        observed.file_index,
    ):
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
