from __future__ import annotations

import errno
import hashlib
import importlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_assure import rooted_io
from agent_assure.io_limits import (
    load_json_bounded_at,
    open_directory_at,
    open_file_bounded_at,
    read_bytes_bounded_at,
    read_file_bounded_at,
    read_text_bounded_at,
)


def test_windows_publication_lock_uses_explicit_nonblocking_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    attempts: list[tuple[int, int, int]] = []
    sleeps: list[float] = []
    clock = iter((0.0, 0.0, 0.05, 0.05, 0.10))

    def locking(fd: int, mode: int, size: int) -> None:
        attempts.append((fd, mode, size))
        if len(attempts) < 3:
            raise PermissionError(errno.EACCES, "synthetic lock contention")

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(
        rooted_io,
        "_windows_locking_api",
        lambda: (locking, 101, 202),
    )
    monkeypatch.setattr(rooted_io, "_publication_lock_monotonic", lambda: next(clock))
    monkeypatch.setattr(rooted_io, "_publication_lock_sleep", sleeps.append)
    try:
        rooted_io.acquire_publication_lock(
            descriptor,
            label="unit publication",
            timeout_seconds=0.2,
        )
        rooted_io.release_publication_lock(descriptor)
    finally:
        os.close(descriptor)

    assert attempts == [
        (descriptor, 101, 1),
        (descriptor, 101, 1),
        (descriptor, 101, 1),
        (descriptor, 202, 1),
    ]
    assert sleeps == [0.05, 0.05]


def test_windows_publication_lock_timeout_is_precise_and_monotonic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    attempts: list[int] = []
    sleeps: list[float] = []
    clock = iter((10.0, 10.0, 10.05, 10.10, 10.12))

    def always_contended(_fd: int, mode: int, _size: int) -> None:
        attempts.append(mode)
        raise BlockingIOError(errno.EAGAIN, "synthetic lock contention")

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(
        rooted_io,
        "_windows_locking_api",
        lambda: (always_contended, 303, 404),
    )
    monkeypatch.setattr(rooted_io, "_publication_lock_monotonic", lambda: next(clock))
    monkeypatch.setattr(rooted_io, "_publication_lock_sleep", sleeps.append)
    try:
        with pytest.raises(
            TimeoutError,
            match=r"unit publication lock acquisition timed out after 0\.12 seconds",
        ) as exc_info:
            rooted_io.acquire_publication_lock(
                descriptor,
                label="unit publication",
                timeout_seconds=0.12,
            )
    finally:
        os.close(descriptor)

    assert exc_info.value.errno == errno.ETIMEDOUT
    assert isinstance(exc_info.value.__cause__, BlockingIOError)
    assert attempts == [303, 303]
    assert sleeps == pytest.approx([0.05, 0.02])


def test_windows_sharing_retry_uses_numeric_cause_chain_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    sleeps: list[float] = []

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            sharing_error = PermissionError(
                errno.EACCES,
                "opaque transient access failure",
            )
            sharing_error.winerror = 32
            raise ValueError("typed wrapper") from sharing_error
        return "verified"

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(rooted_io, "_publication_lock_sleep", sleeps.append)

    assert rooted_io.retry_windows_sharing_violation(operation, timeout_seconds=1.0) == "verified"
    assert attempts == 3
    assert sleeps == [0.001, 0.002]


def test_windows_sharing_retry_does_not_treat_broad_access_denial_as_transient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    def operation() -> None:
        nonlocal attempts
        attempts += 1
        raise PermissionError(errno.EACCES, "sharing violation text is not authority")

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", True)

    with pytest.raises(PermissionError, match="text is not authority"):
        rooted_io.retry_windows_sharing_violation(operation, timeout_seconds=1.0)
    assert attempts == 1


def test_windows_publication_lock_propagates_noncontention_error_immediately(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    attempts: list[int] = []

    def invalid_descriptor(_fd: int, mode: int, _size: int) -> None:
        attempts.append(mode)
        raise OSError(errno.EBADF, "synthetic invalid descriptor")

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(
        rooted_io,
        "_windows_locking_api",
        lambda: (invalid_descriptor, 505, 606),
    )
    monkeypatch.setattr(rooted_io, "_publication_lock_monotonic", lambda: 0.0)
    monkeypatch.setattr(
        rooted_io,
        "_publication_lock_sleep",
        lambda _seconds: pytest.fail("non-contention errors must not be retried"),
    )
    try:
        with pytest.raises(OSError, match="synthetic invalid descriptor") as exc_info:
            rooted_io.acquire_publication_lock(
                descriptor,
                label="unit publication",
                timeout_seconds=0.2,
            )
    finally:
        os.close(descriptor)

    assert exc_info.value.errno == errno.EBADF
    assert attempts == [505]


def test_posix_publication_lock_uses_explicit_nonblocking_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    attempts: list[tuple[int, int]] = []
    sleeps: list[float] = []
    clock = iter((0.0, 0.0, 0.05, 0.05, 0.10))

    def flock(fd: int, mode: int) -> None:
        attempts.append((fd, mode))
        if len(attempts) < 3:
            raise PermissionError(errno.EACCES, "synthetic lock contention")

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", False)
    monkeypatch.setattr(rooted_io, "_posix_locking_api", lambda: (flock, 701, 702))
    monkeypatch.setattr(rooted_io, "_publication_lock_monotonic", lambda: next(clock))
    monkeypatch.setattr(rooted_io, "_publication_lock_sleep", sleeps.append)
    try:
        rooted_io.acquire_publication_lock(
            descriptor,
            label="unit publication",
            timeout_seconds=0.2,
        )
        rooted_io.release_publication_lock(descriptor)
    finally:
        os.close(descriptor)

    assert attempts == [
        (descriptor, 701),
        (descriptor, 701),
        (descriptor, 701),
        (descriptor, 702),
    ]
    assert sleeps == [0.05, 0.05]


def test_posix_publication_lock_timeout_is_precise_and_monotonic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    attempts: list[int] = []
    sleeps: list[float] = []
    clock = iter((10.0, 10.0, 10.05, 10.10, 10.12))

    def always_contended(_fd: int, mode: int) -> None:
        attempts.append(mode)
        raise BlockingIOError(errno.EAGAIN, "synthetic lock contention")

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", False)
    monkeypatch.setattr(
        rooted_io,
        "_posix_locking_api",
        lambda: (always_contended, 703, 704),
    )
    monkeypatch.setattr(rooted_io, "_publication_lock_monotonic", lambda: next(clock))
    monkeypatch.setattr(rooted_io, "_publication_lock_sleep", sleeps.append)
    try:
        with pytest.raises(
            TimeoutError,
            match=r"unit publication lock acquisition timed out after 0.12 seconds",
        ) as exc_info:
            rooted_io.acquire_publication_lock(
                descriptor,
                label="unit publication",
                timeout_seconds=0.12,
            )
    finally:
        os.close(descriptor)

    assert exc_info.value.errno == errno.ETIMEDOUT
    assert isinstance(exc_info.value.__cause__, BlockingIOError)
    assert attempts == [703, 703]
    assert sleeps == pytest.approx([0.05, 0.02])


def test_posix_publication_lock_propagates_noncontention_error_immediately(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)

    def unsupported(_fd: int, _mode: int) -> None:
        raise OSError(errno.ENOLCK, "synthetic lock service unavailable")

    monkeypatch.setattr(rooted_io, "_IS_WINDOWS", False)
    monkeypatch.setattr(rooted_io, "_posix_locking_api", lambda: (unsupported, 705, 706))
    monkeypatch.setattr(rooted_io, "_publication_lock_monotonic", lambda: 0.0)
    monkeypatch.setattr(
        rooted_io,
        "_publication_lock_sleep",
        lambda _seconds: pytest.fail("non-contention errors must not be retried"),
    )
    try:
        with pytest.raises(OSError, match="synthetic lock service unavailable") as exc_info:
            rooted_io.acquire_publication_lock(
                descriptor,
                label="unit publication",
                timeout_seconds=0.2,
            )
    finally:
        os.close(descriptor)

    assert exc_info.value.errno == errno.ENOLCK


@pytest.mark.skipif(os.name == "nt", reason="POSIX flock contention regression")
def test_posix_publication_lock_real_contention_has_outer_hang_guard(
    tmp_path: Path,
) -> None:
    import fcntl

    lock_path = tmp_path / "publication.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    contender = """
import errno
import os
import sys
from agent_assure.rooted_io import acquire_publication_lock

descriptor = os.open(sys.argv[1], os.O_RDWR)
try:
    acquire_publication_lock(descriptor, label="subprocess publication", timeout_seconds=0.1)
except TimeoutError as exc:
    raise SystemExit(0 if exc.errno == errno.ETIMEDOUT else 2)
finally:
    os.close(descriptor)
raise SystemExit(3)
"""
    try:
        completed = subprocess.run(
            [sys.executable, "-c", contender, str(lock_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("machine", "pointer_bits", "expected"),
    (
        ("x86_64", 64, 316),
        ("AMD64", 64, 316),
        ("i686", 32, 353),
        ("armv7l", 32, 382),
        ("aarch64", 64, 276),
        ("riscv64", 64, 276),
        ("ppc64le", 64, 357),
        ("s390x", 64, 347),
        ("x86_64", 32, None),
        ("aarch64", 32, None),
        ("unknown", 64, None),
    ),
)
def test_linux_renameat2_syscall_number_is_abi_specific(
    machine: str,
    pointer_bits: int,
    expected: int | None,
) -> None:
    assert rooted_io._linux_renameat2_syscall_number(machine, pointer_bits) == expected


def _select_posix_rename_platform(
    monkeypatch: pytest.MonkeyPatch,
    *,
    linux: bool = False,
    darwin: bool = False,
    freebsd: bool = False,
) -> None:
    monkeypatch.setattr(rooted_io, "_IS_LINUX", linux)
    monkeypatch.setattr(rooted_io, "_IS_DARWIN", darwin)
    monkeypatch.setattr(rooted_io, "_IS_FREEBSD", freebsd)


def test_posix_rename_prefers_module_scoped_linux_libc_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, bytes, int, bytes, int]] = []

    def renameat2(
        source_fd: int,
        source: bytes,
        target_fd: int,
        target: bytes,
        flags: int,
    ) -> int:
        calls.append((source_fd, source, target_fd, target, flags))
        return 0

    _select_posix_rename_platform(monkeypatch, linux=True)
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2", renameat2)
    monkeypatch.setattr(
        rooted_io,
        "_POSIX_RENAMEAT2_SYSCALL",
        lambda *_args: pytest.fail("libc renameat2 must be preferred"),
    )
    monkeypatch.setattr(
        rooted_io.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: pytest.fail("libc must not be reconstructed per rename"),
    )

    rooted_io._posix_renameat_no_replace(41, "private-stage", "generation")

    assert calls == [(41, b"private-stage", 41, b"generation", 1)]


def test_posix_rename_uses_typed_linux_syscall_when_wrapper_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Any, ...]] = []

    def syscall(*args: Any) -> int:
        calls.append(args)
        return 0

    _select_posix_rename_platform(monkeypatch, linux=True)
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2", None)
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2_SYSCALL", syscall)
    monkeypatch.setattr(rooted_io, "_LINUX_RENAMEAT2_SYSCALL_NUMBER", 316)

    rooted_io._posix_renameat_no_replace(43, "private-stage", "generation")

    assert len(calls) == 1
    number, source_fd, source, target_fd, target, flags = calls[0]
    assert isinstance(number, rooted_io.ctypes.c_long)
    assert isinstance(source_fd, rooted_io.ctypes.c_int)
    assert isinstance(source, rooted_io.ctypes.c_char_p)
    assert isinstance(target_fd, rooted_io.ctypes.c_int)
    assert isinstance(target, rooted_io.ctypes.c_char_p)
    assert isinstance(flags, rooted_io.ctypes.c_uint)
    assert number.value == 316
    assert source_fd.value == target_fd.value == 43
    assert source.value == b"private-stage"
    assert target.value == b"generation"
    assert flags.value == 1


@pytest.mark.parametrize(
    ("platform_name", "expected_flag"),
    (("freebsd", 1), ("darwin", 4)),
)
def test_posix_rename_dispatches_supported_non_linux_native_primitive(
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
    expected_flag: int,
) -> None:
    calls: list[tuple[int, bytes, int, bytes, int]] = []

    def native_rename(
        source_fd: int,
        source: bytes,
        target_fd: int,
        target: bytes,
        flags: int,
    ) -> int:
        calls.append((source_fd, source, target_fd, target, flags))
        return 0

    _select_posix_rename_platform(
        monkeypatch,
        darwin=platform_name == "darwin",
        freebsd=platform_name == "freebsd",
    )
    monkeypatch.setattr(
        rooted_io,
        "_POSIX_RENAMEAT2",
        native_rename if platform_name == "freebsd" else None,
    )
    monkeypatch.setattr(
        rooted_io,
        "_POSIX_RENAMEATX_NP",
        native_rename if platform_name == "darwin" else None,
    )

    rooted_io._posix_renameat_no_replace(47, "private-stage", "generation")

    assert calls == [(47, b"private-stage", 47, b"generation", expected_flag)]


@pytest.mark.parametrize(
    ("native_errno", "expected_exception"),
    ((errno.EEXIST, FileExistsError), (errno.ENOTEMPTY, FileExistsError)),
)
def test_posix_rename_collision_remains_file_exists(
    monkeypatch: pytest.MonkeyPatch,
    native_errno: int,
    expected_exception: type[OSError],
) -> None:
    def collides(*_args: Any) -> int:
        rooted_io.ctypes.set_errno(native_errno)
        return -1

    _select_posix_rename_platform(monkeypatch, linux=True)
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2", collides)

    with pytest.raises(expected_exception) as exc_info:
        rooted_io._posix_renameat_no_replace(53, "private-stage", "generation")

    assert exc_info.value.errno == native_errno


def test_posix_rename_syscall_enosys_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: Any) -> int:
        rooted_io.ctypes.set_errno(errno.ENOSYS)
        return -1

    _select_posix_rename_platform(monkeypatch, linux=True)
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2", None)
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2_SYSCALL", unavailable)
    monkeypatch.setattr(rooted_io, "_LINUX_RENAMEAT2_SYSCALL_NUMBER", 316)

    with pytest.raises(OSError, match="unavailable on this kernel") as exc_info:
        rooted_io._posix_renameat_no_replace(59, "private-stage", "generation")

    assert exc_info.value.errno == errno.ENOSYS


def test_posix_rename_unknown_linux_abi_fails_before_syscall(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _select_posix_rename_platform(monkeypatch, linux=True)
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2", None)
    monkeypatch.setattr(
        rooted_io,
        "_POSIX_RENAMEAT2_SYSCALL",
        lambda *_args: pytest.fail("unknown ABI must not invoke syscall"),
    )
    monkeypatch.setattr(rooted_io, "_LINUX_RENAMEAT2_SYSCALL_NUMBER", None)

    with pytest.raises(OSError, match="supported Linux renameat2 syscall ABI") as exc_info:
        rooted_io._posix_renameat_no_replace(61, "private-stage", "generation")

    assert exc_info.value.errno == errno.ENOSYS


@pytest.mark.skipif(
    not rooted_io._IS_LINUX
    or rooted_io._POSIX_RENAMEAT2_SYSCALL is None
    or rooted_io._LINUX_RENAMEAT2_SYSCALL_NUMBER is None,
    reason="supported native Linux renameat2 syscall ABI required",
)
def test_linux_syscall_fallback_installs_without_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "root"
    parent.mkdir()
    monkeypatch.setattr(rooted_io, "_POSIX_RENAMEAT2", None)

    with rooted_io.open_rooted_directory(parent, ".", label="publication parent") as lease:
        first = rooted_io.claim_rooted_directory(lease, "first-stage", label="first stage")
        try:
            descriptor = first.open_regular_file_exclusive("artifact.json")
            try:
                os.write(descriptor, b"first")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            first.install_no_replace("generation")
        finally:
            first.close()

        second = rooted_io.claim_rooted_directory(lease, "second-stage", label="second stage")
        try:
            with pytest.raises(FileExistsError):
                second.install_no_replace("generation")
            assert second.path == parent / "second-stage"
        finally:
            second.close()

    assert (parent / "generation" / "artifact.json").read_bytes() == b"first"


@pytest.mark.parametrize(
    ("module_name", "wrapper_name", "expected_label", "expected_timeout", "expected_result"),
    (
        (
            "agent_assure.reporting.stochastic_sensitivity",
            "_lock_descriptor",
            "repeated sensitivity publication",
            0.001,
            True,
        ),
        (
            "agent_assure.reporting.sensitivity",
            "_lock_sensitivity_descriptor",
            "evidence sensitivity publication",
            0.001,
            True,
        ),
        (
            "agent_assure.cli.rag_cmd",
            "_lock_finalize_descriptor",
            "sensitivity finalize publication",
            None,
            None,
        ),
    ),
)
def test_publication_writers_use_shared_bounded_lock_primitive(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    wrapper_name: str,
    expected_label: str,
    expected_timeout: float | None,
    expected_result: bool | None,
) -> None:
    module = importlib.import_module(module_name)
    observed: list[tuple[int, str, float | None]] = []

    def fake_acquire(
        descriptor: int,
        *,
        label: str,
        timeout_seconds: float | None = None,
    ) -> None:
        observed.append((descriptor, label, timeout_seconds))

    monkeypatch.setattr(module, "acquire_publication_lock", fake_acquire)

    result = getattr(module, wrapper_name)(123)

    assert observed == [(123, expected_label, expected_timeout)]
    assert result is expected_result


def test_rooted_read_pins_nested_file_and_preserves_bounded_metadata(tmp_path: Path) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    payload = b'{"value":"rooted"}'
    (nested / "artifact.json").write_bytes(payload)

    contents = read_file_bounded_at(
        root,
        "nested/artifact.json",
        max_bytes=len(payload),
        label="test artifact",
    )

    assert contents.data == payload
    assert contents.sha256 == hashlib.sha256(payload).hexdigest()
    assert contents.size == len(payload)
    assert (
        read_bytes_bounded_at(
            root,
            Path("nested/artifact.json"),
            max_bytes=len(payload),
            label="test artifact",
        )
        == payload
    )
    assert read_text_bounded_at(
        root,
        "nested/artifact.json",
        max_bytes=len(payload),
        label="test artifact",
    ) == payload.decode("utf-8")
    assert load_json_bounded_at(root, "nested/artifact.json") == {"value": "rooted"}


def test_rooted_descriptor_lease_rewinds_and_closes_file_descriptor(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "script.py").write_bytes(b"print('ok')\n")

    with open_file_bounded_at(
        root,
        "script.py",
        max_bytes=1024,
        label="external script",
    ) as opened:
        descriptor = opened.descriptor
        assert os.read(descriptor, 5) == b"print"
        opened.rewind()
        assert os.read(descriptor, 5) == b"print"

    assert opened.closed
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_windows_last_error_preserves_dynamic_ctypes_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_codes: list[int] = []

    def fake_win_error(error_code: int) -> OSError:
        observed_codes.append(error_code)
        return OSError(error_code, "synthetic Windows failure")

    monkeypatch.setattr(rooted_io.ctypes, "get_last_error", lambda: 1234, raising=False)
    monkeypatch.setattr(rooted_io.ctypes, "WinError", fake_win_error, raising=False)

    error = rooted_io._windows_last_error()

    assert observed_codes == [1234]
    assert error.errno == 1234


def test_windows_relative_create_never_deletes_unknown_opened_handle_on_anomaly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic_handle = 4242
    closed: list[int | None] = []
    deleted: list[int] = []

    class FakeNtCreateFile:
        argtypes: object = None
        restype: object = None

        def __call__(self, *args: Any) -> int:
            result_handle = rooted_io.ctypes.cast(
                args[0],
                rooted_io.ctypes.POINTER(rooted_io.wintypes.HANDLE),
            )
            io_status = rooted_io.ctypes.cast(
                args[3],
                rooted_io.ctypes.POINTER(rooted_io._WindowsIoStatusBlock),
            )
            result_handle.contents.value = synthetic_handle
            io_status.contents.status = 0
            io_status.contents.information = rooted_io._WINDOWS_FILE_OPENED
            return 0

    class FakeNtdll:
        NtCreateFile = FakeNtCreateFile()

    def record_close(handle: int | None) -> None:
        closed.append(handle)

    def reject_delete(handle: int, **_kwargs: object) -> None:
        deleted.append(handle)
        raise AssertionError("an unknown opened handle must never be disposition-deleted")

    monkeypatch.setattr(rooted_io, "_windows_ntdll", FakeNtdll)
    monkeypatch.setattr(rooted_io, "_windows_close_handle", record_close)
    monkeypatch.setattr(rooted_io, "_windows_set_delete_disposition", reject_delete)

    with pytest.raises(OSError, match="unexpected I/O disposition"):
        rooted_io._windows_open_relative_handle(
            17,
            "artifact.json",
            desired_access=rooted_io._WINDOWS_FILE_READ_ATTRIBUTES,
            share_access=rooted_io._WINDOWS_FILE_SHARE_READ,
            create_disposition=rooted_io._WINDOWS_FILE_CREATE,
            create_options=rooted_io._WINDOWS_FILE_NON_DIRECTORY_FILE,
            file_attributes=rooted_io._WINDOWS_FILE_ATTRIBUTE_NORMAL,
            require_created=True,
        )

    assert closed == [synthetic_handle]
    assert deleted == []


def test_rooted_directory_lease_pins_nested_directory_and_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)

    with open_directory_at(root, "nested", label="external script cwd") as opened:
        assert opened.path == nested.absolute()
        descriptor = opened.descriptor
        if descriptor is not None:
            assert os.path.samestat(os.fstat(descriptor), os.stat(nested))

    assert opened.closed
    if descriptor is not None:
        with pytest.raises(OSError):
            os.fstat(descriptor)

    with open_directory_at(root, ".", label="external script cwd") as root_lease:
        assert root_lease.path == root.absolute()


@pytest.mark.skipif(os.name == "nt", reason="POSIX root replacement regression")
def test_separate_leases_expose_root_replacement_between_acquisitions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    original_root = tmp_path / "original-root"
    replacement_root = tmp_path / "replacement-root"
    (root / "work").mkdir(parents=True)
    replacement_root.mkdir()
    (replacement_root / "script.py").write_bytes(b"print('replacement')\n")

    with open_directory_at(root, "work", label="external script cwd") as cwd:
        root.rename(original_root)
        replacement_root.rename(root)
        try:
            with open_file_bounded_at(
                root,
                "script.py",
                max_bytes=1024,
                label="external script",
            ) as script:
                assert (cwd.root_device, cwd.root_inode) != (
                    script.root_device,
                    script.root_inode,
                )
        finally:
            root.rename(replacement_root)
            original_root.rename(root)


def test_portable_relative_path_parts_public_internal_contract() -> None:
    assert rooted_io.portable_relative_path_parts("nested/artifact.json") == (
        "nested",
        "artifact.json",
    )


@pytest.mark.parametrize(
    "relative_path",
    (
        "",
        ".",
        "../escape.json",
        "nested/../escape.json",
        "/absolute.json",
        r"C:\absolute.json",
        "nested//artifact.json",
        "artifact.json:secret",
        "nested./artifact.json",
        "nested /artifact.json",
        "CON",
        "aux.json",
        "LPT1.txt",
        "COM\u00b9.txt",
        "a?b.json",
        "line\nfeed.json",
    ),
)
def test_rooted_read_rejects_unsafe_and_windows_ambiguous_paths(
    tmp_path: Path,
    relative_path: str,
) -> None:
    with pytest.raises(ValueError, match="rooted file path"):
        read_bytes_bounded_at(
            tmp_path,
            relative_path,
            max_bytes=1024,
            label="test artifact",
        )


def test_rooted_read_rejects_linked_parent_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "artifact.json").write_bytes(b"outside")
    link = root / "linked"
    _create_directory_link(link, outside)
    try:
        with pytest.raises((OSError, ValueError)):
            read_bytes_bounded_at(
                root,
                "linked/artifact.json",
                max_bytes=1024,
                label="test artifact",
            )
    finally:
        _remove_directory_link(link)


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative swap regression")
def test_rooted_read_fails_closed_when_parent_is_swapped_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    parent = root / "parent"
    saved_parent = root / "saved-parent"
    outside = tmp_path / "outside"
    parent.mkdir(parents=True)
    outside.mkdir()
    (parent / "artifact.json").write_bytes(b"inside")
    (outside / "artifact.json").write_bytes(b"outside")
    real_open = rooted_io.os.open
    swapped = False

    def swapping_open(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "parent" and dir_fd is not None and not swapped:
            swapped = True
            parent.rename(saved_parent)
            parent.symlink_to(outside, target_is_directory=True)
        return descriptor

    monkeypatch.setattr(rooted_io.os, "open", swapping_open)
    try:
        with pytest.raises(ValueError, match="path"):
            read_bytes_bounded_at(
                root,
                "parent/artifact.json",
                max_bytes=1024,
                label="test artifact",
            )
    finally:
        if parent.is_symlink():
            parent.unlink()
        if saved_parent.exists():
            saved_parent.rename(parent)
    assert swapped


@pytest.mark.skipif(os.name != "nt", reason="Windows non-delete-share handle regression")
def test_rooted_directory_lease_blocks_lexical_rename_until_close(tmp_path: Path) -> None:
    root = tmp_path / "root"
    parent = root / "parent"
    saved_parent = root / "saved-parent"
    parent.mkdir(parents=True)

    with open_directory_at(root, "parent", label="external script cwd"):
        with pytest.raises(OSError):
            parent.rename(saved_parent)

    parent.rename(saved_parent)
    saved_parent.rename(parent)


def test_rooted_directory_lease_reads_bounded_single_link_children(tmp_path: Path) -> None:
    root = tmp_path / "root"
    generation = root / "generation"
    generation.mkdir(parents=True)
    payload = b'{"result":"pinned"}'
    artifact = generation / "artifact.json"
    artifact.write_bytes(payload)

    with rooted_io.open_rooted_directory(
        root,
        "generation",
        label="existing publication",
    ) as lease:
        assert lease.entry_names(max_entries=1, label="existing publication") == ("artifact.json",)
        contents = lease.read_file_bounded(
            "artifact.json",
            max_bytes=len(payload),
            label="existing publication artifact",
            require_single_link=True,
        )
        assert contents.data == payload
        with pytest.raises(ValueError, match="maximum supported size"):
            lease.read_file_bounded(
                "artifact.json",
                max_bytes=len(payload) - 1,
                label="existing publication artifact",
                require_single_link=True,
            )

        alias = generation / "artifact-alias.json"
        try:
            os.link(artifact, alias)
        except OSError:
            pytest.skip("hard links are unavailable on this platform")
        with pytest.raises(ValueError, match="single-link regular file"):
            lease.read_file_bounded(
                "artifact.json",
                max_bytes=len(payload),
                label="existing publication artifact",
                require_single_link=True,
            )
        with pytest.raises(ValueError, match="too many entries"):
            lease.entry_names(max_entries=1, label="existing publication")

    with pytest.raises(ValueError, match="lease is closed"):
        lease.entry_names(max_entries=2, label="existing publication")


def test_rooted_directory_lease_exclusive_create_and_identity_checked_unlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with rooted_io.open_rooted_directory(root, ".", label="publication") as lease:
        descriptor, created = lease.open_regular_file_exclusive_with_metadata("artifact.json")
        try:
            assert os.write(descriptor, b"owned") == 5
            os.fsync(descriptor)
            assert os.path.samestat(created, os.fstat(descriptor))
            observed = lease.stat_entry_no_follow("artifact.json")
            assert os.path.samestat(created, observed)
            with pytest.raises(FileExistsError):
                lease.open_regular_file_exclusive("artifact.json")
        finally:
            os.close(descriptor)

        with pytest.raises(OSError, match="identity changed"):
            lease.unlink_entry_no_follow(
                "artifact.json",
                expected_device=created.st_dev,
                expected_inode=created.st_ino + 1,
            )
        assert (root / "artifact.json").read_bytes() == b"owned"
        lease.unlink_entry_no_follow(
            "artifact.json",
            expected_device=created.st_dev,
            expected_inode=created.st_ino,
        )
    assert not (root / "artifact.json").exists()


def test_rooted_directory_lease_lock_file_is_persistent_and_single_link(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    lock_path = root / ".publication.lock"
    with rooted_io.open_rooted_directory(root, ".", label="publication") as lease:
        first_descriptor, first = lease.open_regular_lock_file(lock_path.name)
        try:
            os.write(first_descriptor, b"\0")
            os.fsync(first_descriptor)
        finally:
            os.close(first_descriptor)
        second_descriptor, second = lease.open_regular_lock_file(lock_path.name)
        try:
            assert os.path.samestat(first, second)
            assert os.path.samestat(second, os.fstat(second_descriptor))
        finally:
            os.close(second_descriptor)

        alias = root / ".publication-alias.lock"
        try:
            os.link(lock_path, alias)
        except OSError:
            pytest.skip("hard links are unavailable on this platform")
        with pytest.raises(ValueError, match="single-link regular file"):
            lease.open_regular_lock_file(lock_path.name)


def test_rooted_directory_claim_reopens_bounded_single_link_child(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = b'{"result":"final-precommit-pin"}'
    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        claim = rooted_io.claim_rooted_directory(parent, "stage", label="publication stage")
        try:
            descriptor = claim.open_regular_file_exclusive("artifact.json")
            try:
                assert os.write(descriptor, payload) == len(payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

            with claim.open_file_bounded(
                "artifact.json",
                max_bytes=len(payload),
                label="final staged child",
                require_single_link=True,
            ) as opened:
                assert opened.contents.data == payload
                opened.revalidate()

            alias = claim.path / "artifact-alias.json"
            try:
                os.link(claim.path / "artifact.json", alias)
            except OSError:
                pytest.skip("hard links are unavailable on this platform")
            with pytest.raises(ValueError, match="single-link regular file"):
                claim.open_file_bounded(
                    "artifact.json",
                    max_bytes=len(payload),
                    label="final staged child",
                    require_single_link=True,
                )
        finally:
            claim.close()


def test_windows_directory_object_identity_ignores_mutable_inventory_metadata() -> None:
    expected = rooted_io._WindowsHandleIdentity(
        attributes=rooted_io._WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
        volume_serial_number=17,
        file_index=23,
        number_of_links=1,
        size=0,
        last_write_time=100,
    )
    inventory_changed = rooted_io._WindowsHandleIdentity(
        attributes=rooted_io._WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
        volume_serial_number=17,
        file_index=23,
        number_of_links=7,
        size=4096,
        last_write_time=200,
    )

    rooted_io._windows_require_same_directory_object(
        expected,
        inventory_changed,
        path=Path("directory"),
        label="rooted directory",
    )

    replaced = rooted_io._WindowsHandleIdentity(
        attributes=rooted_io._WINDOWS_FILE_ATTRIBUTE_DIRECTORY,
        volume_serial_number=17,
        file_index=24,
        number_of_links=7,
        size=4096,
        last_write_time=200,
    )
    with pytest.raises(ValueError, match="changed while it was being read"):
        rooted_io._windows_require_same_directory_object(
            expected,
            replaced,
            path=Path("directory"),
            label="rooted directory",
        )


def test_rooted_directory_lease_read_rejects_link_child(tmp_path: Path) -> None:
    root = tmp_path / "root"
    generation = root / "generation"
    generation.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside")
    link = generation / "artifact.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("file symlinks are unavailable on this platform")

    with rooted_io.open_rooted_directory(
        root,
        "generation",
        label="existing publication",
    ) as lease:
        with pytest.raises((OSError, ValueError)):
            lease.read_file_bounded(
                "artifact.json",
                max_bytes=16,
                label="existing publication artifact",
                require_single_link=True,
            )
    assert outside.read_bytes() == b"outside"


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative read regression")
def test_rooted_directory_lease_read_stays_anchored_after_lexical_swap(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    generation = root / "generation"
    saved = root / "saved-generation"
    outside = tmp_path / "outside"
    generation.mkdir(parents=True)
    outside.mkdir()
    (generation / "artifact.json").write_bytes(b"pinned")
    (outside / "artifact.json").write_bytes(b"outside")

    with rooted_io.open_rooted_directory(
        root,
        "generation",
        label="existing publication",
    ) as lease:
        generation.rename(saved)
        generation.symlink_to(outside, target_is_directory=True)
        assert lease.entry_names(max_entries=1, label="existing publication") == ("artifact.json",)
        assert (
            lease.read_file_bounded(
                "artifact.json",
                max_bytes=16,
                label="existing publication artifact",
                require_single_link=True,
            ).data
            == b"pinned"
        )


def test_rooted_directory_claim_owns_independent_pins_and_writer_operations(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    parent = rooted_io.open_rooted_directory(root, ".", label="publication parent")
    claim = rooted_io.claim_rooted_directory(
        parent,
        "generation",
        label="publication",
    )
    claim_descriptor = claim._descriptor
    claim_parent_descriptor = claim._parent_descriptor
    claim_windows_handle = claim._windows_handle
    claim_windows_parent_handle = claim._windows_parent_handle
    parent.close()

    descriptor, created = claim.open_regular_file_exclusive_with_metadata("artifact.json")
    try:
        payload = b'{"result":"pinned"}'
        assert os.write(descriptor, payload) == len(payload)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(payload)) == payload
        assert os.path.samestat(created, os.fstat(descriptor))
        observed = claim.stat_entry_no_follow("artifact.json")
        assert os.path.samestat(created, observed)
        assert claim.entry_names(max_entries=1, label="publication") == ("artifact.json",)
        with pytest.raises(FileExistsError):
            claim.open_regular_file_exclusive("artifact.json")
    finally:
        os.close(descriptor)

    with pytest.raises(OSError, match="identity changed"):
        claim.unlink_entry_no_follow(
            "artifact.json",
            expected_device=created.st_dev,
            expected_inode=created.st_ino + 1,
        )
    assert (root / "generation" / "artifact.json").read_bytes() == payload
    claim.unlink_entry_no_follow(
        "artifact.json",
        expected_device=created.st_dev,
        expected_inode=created.st_ino,
    )
    claim.remove_empty()

    assert claim.closed
    assert claim.removed
    assert not (root / "generation").exists()
    if os.name == "nt":
        assert claim_windows_handle is not None
        assert claim_windows_parent_handle is not None
        with pytest.raises(OSError):
            rooted_io._windows_handle_identity(claim_windows_handle)
        with pytest.raises(OSError):
            rooted_io._windows_handle_identity(claim_windows_parent_handle)
    else:
        assert claim_descriptor is not None
        assert claim_parent_descriptor is not None
        with pytest.raises(OSError):
            os.fstat(claim_descriptor)
        with pytest.raises(OSError):
            os.fstat(claim_parent_descriptor)
    with pytest.raises(ValueError, match="claim is closed"):
        claim.stat_entry_no_follow("artifact.json")
    with pytest.raises(ValueError, match="claim is closed"):
        claim.entry_names(max_entries=1, label="publication")


def test_rooted_directory_claim_collision_is_exclusive(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "generation").mkdir(parents=True)

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        with pytest.raises(FileExistsError):
            rooted_io.claim_rooted_directory(parent, "generation", label="publication")

    assert (root / "generation").is_dir()


def test_rooted_directory_claim_installs_atomically_without_replacement(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "root"
    parent.mkdir()
    with rooted_io.open_rooted_directory(parent, ".", label="publication parent") as lease:
        claim = rooted_io.claim_rooted_directory(
            lease,
            "private-stage",
            label="publication staging",
        )
        descriptor = claim.open_regular_file_exclusive("artifact.json")
        try:
            os.write(descriptor, b"owned")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        claim.install_no_replace("generation")
        assert claim.name == "generation"
        assert claim.path == parent / "generation"
        claim.close()

        assert (parent / "generation" / "artifact.json").read_bytes() == b"owned"
        competing = rooted_io.claim_rooted_directory(
            lease,
            "second-private-stage",
            label="competing publication staging",
        )
        try:
            with pytest.raises(FileExistsError):
                competing.install_no_replace("generation")
            assert competing.path == parent / "second-private-stage"
            assert (parent / "generation" / "artifact.json").read_bytes() == b"owned"
        finally:
            competing.close()


def test_rooted_directory_claim_records_commit_before_post_install_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "root"
    parent.mkdir()
    with rooted_io.open_rooted_directory(parent, ".", label="publication parent") as lease:
        claim = rooted_io.claim_rooted_directory(
            lease,
            "private-stage",
            label="publication staging",
        )

        def fail_post_install_validation(_claim: rooted_io.RootedDirectoryClaim) -> None:
            raise OSError("injected post-install validation failure")

        monkeypatch.setattr(
            rooted_io,
            "_require_installed_claim_identity",
            fail_post_install_validation,
        )
        try:
            with pytest.raises(OSError, match="post-install validation"):
                claim.install_no_replace("generation")
            assert claim.name == "generation"
            assert claim.path == parent / "generation"
            assert (parent / "generation").is_dir()
            assert not (parent / "private-stage").exists()
        finally:
            claim.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows owner-only ACL regression")
def test_windows_rooted_directory_claim_has_verified_owner_only_dacl(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "root"
    parent.mkdir()
    with rooted_io.open_rooted_directory(parent, ".", label="publication parent") as lease:
        claim = rooted_io.claim_rooted_directory(
            lease,
            "private-stage",
            label="private staging",
            mode=0o700,
        )
        try:
            rooted_io._windows_require_owner_only_dacl(claim._require_windows_handle())
        finally:
            claim.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative claim regression")
def test_rooted_directory_claim_stays_anchored_after_lexical_swap(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    saved = root / "saved-generation"
    root.mkdir()
    outside.mkdir()

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        claim = rooted_io.claim_rooted_directory(parent, "generation", label="publication")
        (root / "generation").rename(saved)
        (root / "generation").symlink_to(outside, target_is_directory=True)
        try:
            descriptor = claim.open_regular_file_exclusive("artifact.json")
            try:
                os.write(descriptor, b"anchored")
            finally:
                os.close(descriptor)
            assert (saved / "artifact.json").read_bytes() == b"anchored"
            assert not (outside / "artifact.json").exists()
            with pytest.raises(ValueError, match="directory without links"):
                claim.remove_empty()
            assert (root / "generation").is_symlink()
            assert outside.is_dir()
        finally:
            claim.close()
            (saved / "artifact.json").unlink()
            saved.rmdir()
            (root / "generation").unlink()


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor cleanup regression")
def test_rooted_directory_claim_closes_parent_pin_and_removes_claim_on_baseexception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    duplicated: list[int] = []
    opened_claim_descriptors: list[int] = []
    real_dup = os.dup
    real_fstat = os.fstat
    real_open = os.open

    def recording_dup(descriptor: int) -> int:
        result = real_dup(descriptor)
        duplicated.append(result)
        return result

    def recording_open(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        result = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "generation" and dir_fd is not None:
            opened_claim_descriptors.append(result)
        return result

    def interrupted_fstat(descriptor: int) -> os.stat_result:
        if descriptor in opened_claim_descriptors:
            raise KeyboardInterrupt
        return real_fstat(descriptor)

    monkeypatch.setattr(os, "dup", recording_dup)
    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "fstat", interrupted_fstat)
    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        with pytest.raises(KeyboardInterrupt):
            rooted_io.claim_rooted_directory(parent, "generation", label="publication")

    assert duplicated
    assert opened_claim_descriptors
    assert not (root / "generation").exists()
    for descriptor in (*duplicated, *opened_claim_descriptors):
        with pytest.raises(OSError):
            real_fstat(descriptor)


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor-relative link regression")
def test_rooted_directory_claim_rejects_link_entries(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside.json"
    root.mkdir()
    outside.write_bytes(b"outside")

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        claim = rooted_io.claim_rooted_directory(parent, "generation", label="publication")
        link = claim.path / "artifact.json"
        link.symlink_to(outside)
        try:
            with pytest.raises(ValueError, match="link"):
                claim.stat_entry_no_follow("artifact.json")
            with pytest.raises(ValueError, match="link"):
                claim.unlink_entry_no_follow("artifact.json")
            assert link.is_symlink()
            assert outside.read_bytes() == b"outside"
        finally:
            link.unlink()
            claim.remove_empty()


@pytest.mark.parametrize(
    "name",
    (
        "",
        ".",
        "..",
        "../generation",
        "nested/generation",
        r"C:\generation",
        "generation.",
        "CON",
        "name:stream",
    ),
)
def test_rooted_directory_claim_rejects_nonportable_component(
    tmp_path: Path,
    name: str,
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        with pytest.raises(ValueError, match="one portable path component"):
            rooted_io.claim_rooted_directory(parent, name, label="publication")


@pytest.mark.skipif(os.name != "nt", reason="Windows handle lifetime regression")
def test_windows_rooted_directory_claim_blocks_rename_until_close(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    generation = root / "generation"
    saved = root / "saved-generation"

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        claim = rooted_io.claim_rooted_directory(parent, "generation", label="publication")
        with pytest.raises(OSError):
            generation.rename(saved)
        claim.close()

    generation.rename(saved)
    saved.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows native capability regression")
def test_windows_rooted_directory_claim_fails_closed_without_native_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    def unavailable_ntdll() -> Any:
        raise OSError("synthetic native API outage")

    monkeypatch.setattr(rooted_io, "_windows_ntdll", unavailable_ntdll)
    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        with pytest.raises(OSError, match="synthetic native API outage"):
            rooted_io.claim_rooted_directory(parent, "generation", label="publication")
        assert not parent.closed

    assert not (root / "generation").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows native cleanup regression")
def test_windows_rooted_directory_claim_closes_handles_and_removes_on_baseexception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    child_handles: list[int] = []
    parent_handles: list[int] = []
    real_fstat_handle = rooted_io._windows_fstat_handle
    real_reopen = rooted_io._windows_reopen_directory_for_mutation

    def recording_reopen(handle: int) -> int:
        reopened = real_reopen(handle)
        parent_handles.append(reopened)
        return reopened

    def interrupted_fstat(handle: int) -> os.stat_result:
        child_handles.append(handle)
        raise KeyboardInterrupt

    monkeypatch.setattr(rooted_io, "_windows_reopen_directory_for_mutation", recording_reopen)
    monkeypatch.setattr(rooted_io, "_windows_fstat_handle", interrupted_fstat)
    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        with pytest.raises(KeyboardInterrupt):
            rooted_io.claim_rooted_directory(parent, "generation", label="publication")

    monkeypatch.setattr(rooted_io, "_windows_fstat_handle", real_fstat_handle)
    assert child_handles
    assert parent_handles
    assert not (root / "generation").exists()
    for handle in (*child_handles, *parent_handles):
        with pytest.raises(OSError):
            rooted_io._windows_handle_identity(handle)


@pytest.mark.skipif(os.name != "nt", reason="Windows native writer cleanup regression")
def test_windows_rooted_writer_removes_file_and_closes_descriptor_on_baseexception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    created_descriptors: list[int] = []
    real_fstat = os.fstat
    real_handle_to_descriptor = rooted_io._windows_handle_to_descriptor

    def recording_handle_to_descriptor(handle: int, *, flags: int | None = None) -> int:
        descriptor = real_handle_to_descriptor(handle, flags=flags)
        created_descriptors.append(descriptor)
        return descriptor

    def interrupted_fstat(descriptor: int) -> os.stat_result:
        if descriptor in created_descriptors:
            raise KeyboardInterrupt
        return real_fstat(descriptor)

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        claim = rooted_io.claim_rooted_directory(parent, "generation", label="publication")
        monkeypatch.setattr(
            rooted_io,
            "_windows_handle_to_descriptor",
            recording_handle_to_descriptor,
        )
        monkeypatch.setattr(os, "fstat", interrupted_fstat)
        with pytest.raises(KeyboardInterrupt):
            claim.open_regular_file_exclusive("artifact.json")

        assert created_descriptors
        assert not (claim.path / "artifact.json").exists()
        for descriptor in created_descriptors:
            with pytest.raises(OSError):
                real_fstat(descriptor)
        claim.remove_empty()


@pytest.mark.skipif(os.name != "nt", reason="Windows native reparse regression")
def test_windows_rooted_claim_rejects_reparse_entry_without_following_it(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        claim = rooted_io.claim_rooted_directory(parent, "generation", label="publication")
        link = claim.path / "artifact-link"
        _create_directory_link(link, outside)
        try:
            with pytest.raises(ValueError, match="reparse"):
                claim.stat_entry_no_follow("artifact-link")
            with pytest.raises((OSError, ValueError)):
                claim.unlink_entry_no_follow("artifact-link")
            assert outside.is_dir()
        finally:
            _remove_directory_link(link)
            claim.remove_empty()


def _create_directory_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError as exc:
        if os.name != "nt":
            pytest.skip(f"directory symlinks unavailable: {exc}")
    command_processor = os.environ.get("COMSPEC", "cmd.exe")
    completed = subprocess.run(
        [command_processor, "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(f"directory junctions unavailable: {completed.stderr or completed.stdout}")


def _remove_directory_link(link: Path) -> None:
    if not link.exists() and not link.is_symlink():
        return
    if link.is_symlink():
        link.unlink()
    else:
        link.rmdir()
