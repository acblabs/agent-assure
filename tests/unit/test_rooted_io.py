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
