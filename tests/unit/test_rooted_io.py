from __future__ import annotations

import hashlib
import os
import subprocess
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

    descriptor = claim.open_regular_file_exclusive("artifact.json")
    try:
        payload = b'{"result":"pinned"}'
        assert os.write(descriptor, payload) == len(payload)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(payload)) == payload
        created = os.fstat(descriptor)
        observed = claim.stat_entry_no_follow("artifact.json")
        assert os.path.samestat(created, observed)
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


def test_rooted_directory_claim_collision_is_exclusive(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "generation").mkdir(parents=True)

    with rooted_io.open_rooted_directory(root, ".", label="publication parent") as parent:
        with pytest.raises(FileExistsError):
            rooted_io.claim_rooted_directory(parent, "generation", label="publication")

    assert (root / "generation").is_dir()


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
