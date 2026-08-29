from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from agent_assure import artifact_io, rooted_io
from agent_assure.artifact_io import (
    git_file_bytes,
    unlink_file_if_exists,
    write_text_atomic,
)


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


def test_atomic_writer_rejects_parent_swapped_after_initial_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intended_parent = tmp_path / "intended"
    moved_parent = tmp_path / "moved"
    outside_parent = tmp_path / "outside"
    intended_parent.mkdir()
    outside_parent.mkdir()
    original_ensure = artifact_io.ensure_unlinked_directory

    def swap_after_validation(directory: Path) -> Path:
        result = original_ensure(directory)
        intended_parent.rename(moved_parent)
        _create_directory_link(intended_parent, outside_parent)
        return result

    monkeypatch.setattr(artifact_io, "ensure_unlinked_directory", swap_after_validation)

    with pytest.raises((OSError, ValueError)):
        write_text_atomic(intended_parent / "report.json", "replacement")

    assert not (outside_parent / "report.json").exists()
    assert not tuple(outside_parent.glob(".agent-assure-*.tmp"))
    assert not (moved_parent / "report.json").exists()


def test_unlink_file_removes_a_destination_symlink_without_touching_its_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "outside.txt"
    destination = tmp_path / "stale-report.json"
    target.write_text("keep", encoding="utf-8")
    try:
        destination.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    unlink_file_if_exists(destination)

    assert target.read_text(encoding="utf-8") == "keep"
    assert not destination.exists()


def test_unlink_file_refuses_a_linked_parent_directory(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    linked_parent = tmp_path / "linked"
    stale_report = real_parent / "stale-report.json"
    real_parent.mkdir()
    stale_report.write_text("keep", encoding="utf-8")
    _create_directory_link(linked_parent, real_parent)

    with pytest.raises(OSError, match="linked directory component"):
        unlink_file_if_exists(linked_parent / stale_report.name)

    assert stale_report.read_text(encoding="utf-8") == "keep"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle-relative regression")
def test_windows_unlink_stays_on_pinned_parent_when_swapped_after_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intended_parent = tmp_path / "intended"
    moved_parent = tmp_path / "moved"
    outside_parent = tmp_path / "outside"
    intended_parent.mkdir()
    outside_parent.mkdir()
    destination = intended_parent / "stale-report.json"
    outside_destination = outside_parent / destination.name
    destination.write_text("owned", encoding="utf-8")
    outside_destination.write_text("foreign", encoding="utf-8")

    monkeypatch.setattr(
        rooted_io,
        "_WINDOWS_FILE_SHARE_WRITE",
        rooted_io._WINDOWS_FILE_SHARE_WRITE | rooted_io._WINDOWS_FILE_SHARE_DELETE,
    )
    real_lstat = artifact_io.os.lstat
    swapped = False

    def swap_after_metadata(path: object) -> os.stat_result:
        nonlocal swapped
        metadata = real_lstat(path)
        if Path(path) == destination and not swapped:
            intended_parent.rename(moved_parent)
            _create_directory_link(intended_parent, outside_parent)
            swapped = True
        return metadata

    monkeypatch.setattr(artifact_io.os, "lstat", swap_after_metadata)

    with pytest.raises((OSError, ValueError)):
        unlink_file_if_exists(destination)

    assert swapped
    assert outside_destination.read_text(encoding="utf-8") == "foreign"
    assert not (moved_parent / destination.name).exists()


def test_git_file_bytes_uses_hardened_noninteractive_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(
        args: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout=b"blob\n", stderr=b"")

    monkeypatch.setattr(artifact_io, "_resolve_git_executable", lambda: "/usr/bin/git")
    monkeypatch.setattr(artifact_io.subprocess, "run", fake_run)
    monkeypatch.setenv("GIT_DIR", "/tmp/attacker-repository")

    blob = git_file_bytes(tmp_path, "a" * 40, "src/agent_assure/example.py")

    assert blob == b"blob\n"
    command = captured["args"]
    assert isinstance(command, list)
    assert command[-2:] == ["show", f"{'a' * 40}:src/agent_assure/example.py"]
    assert "core.fsmonitor=false" in command
    assert f"safe.directory={tmp_path.resolve()}" in command
    assert captured["timeout"] == 5
    git_environment = captured["env"]
    assert isinstance(git_environment, dict)
    assert "GIT_DIR" not in git_environment
    assert git_environment["GIT_NO_LAZY_FETCH"] == "1"


def test_windows_git_resolution_rejects_batch_shims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "git.cmd").write_text("@echo off\r\n", encoding="utf-8")
    (tmp_path / "git.bat").write_text("@echo off\r\n", encoding="utf-8")
    monkeypatch.setattr(artifact_io, "_IS_WINDOWS", True)
    monkeypatch.setenv("PATH", str(tmp_path))

    assert artifact_io._resolve_git_executable() is None


def test_windows_git_resolution_accepts_native_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    git_executable = tmp_path / "git.exe"
    git_executable.write_bytes(b"native executable placeholder")
    git_executable.chmod(0o755)
    monkeypatch.setattr(artifact_io, "_IS_WINDOWS", True)
    monkeypatch.setenv("PATH", str(tmp_path))

    assert artifact_io._resolve_git_executable() == str(git_executable)


def test_sanitized_git_environment_disables_lazy_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GIT_NO_LAZY_FETCH", raising=False)

    environment = artifact_io._git_environment()

    assert environment["GIT_NO_LAZY_FETCH"] == "1"


@pytest.mark.parametrize(
    ("revision", "repository_path"),
    (
        ("HEAD", "src/agent_assure/example.py"),
        ("a" * 40, "../outside.py"),
        ("a" * 40, "src\\agent_assure\\example.py"),
        ("a" * 40, "/absolute.py"),
    ),
)
def test_git_file_bytes_rejects_mutable_revisions_and_unsafe_paths(
    tmp_path: Path,
    revision: str,
    repository_path: str,
) -> None:
    with pytest.raises(ValueError):
        git_file_bytes(tmp_path, revision, repository_path)


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
