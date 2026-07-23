from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from agent_assure import artifact_io
from agent_assure.artifact_io import write_text_atomic


def test_atomic_writer_replaces_destination_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    target = tmp_path / "outside.txt"
    destination = tmp_path / "report.json"
    target.write_text("keep", encoding="utf-8")
    try:
        destination.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    write_text_atomic(destination, "replacement")

    assert target.read_text(encoding="utf-8") == "keep"
    assert destination.read_text(encoding="utf-8") == "replacement"
    assert not destination.is_symlink()


def test_atomic_writer_breaks_destination_hardlink_before_writing(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    destination = tmp_path / "report.json"
    target.write_text("keep", encoding="utf-8")
    try:
        os.link(target, destination)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    write_text_atomic(destination, "replacement")

    assert target.read_text(encoding="utf-8") == "keep"
    assert destination.read_text(encoding="utf-8") == "replacement"


def test_atomic_writer_refuses_linked_parent_directory(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    linked_parent = tmp_path / "linked"
    real_parent.mkdir()
    _create_directory_link(linked_parent, real_parent)

    with pytest.raises(OSError, match="linked directory component"):
        write_text_atomic(linked_parent / "report.json", "replacement")

    assert not (real_parent / "report.json").exists()


def test_atomic_writer_refuses_linked_parent_before_creating_nested_child(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real"
    linked_parent = tmp_path / "linked"
    real_parent.mkdir()
    _create_directory_link(linked_parent, real_parent)

    nested_child = real_parent / "new-child"
    with pytest.raises(OSError, match="linked directory component"):
        write_text_atomic(linked_parent / "new-child" / "report.json", "replacement")

    assert not nested_child.exists()


def _create_directory_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError as symlink_error:
        if os.name != "nt":
            pytest.skip(f"directory symlinks unavailable: {symlink_error}")
    command_processor = os.environ.get("COMSPEC", "cmd.exe")
    result = subprocess.run(
        [command_processor, "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(
            "directory symlinks and junctions unavailable: "
            + (result.stderr.strip() or result.stdout.strip())
        )


def test_windows_reparse_point_fallback_covers_python_311_junctions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ReparseMetadata:
        st_file_attributes = 0x0400

    monkeypatch.setattr(artifact_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(artifact_io.os, "lstat", lambda _path: ReparseMetadata())
    monkeypatch.setattr(Path, "is_symlink", lambda _path: False)
    monkeypatch.setattr(Path, "is_junction", lambda _path: False, raising=False)

    assert artifact_io._is_linked_directory_component(tmp_path)
