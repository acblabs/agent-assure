from __future__ import annotations

import io
import os
import subprocess
import zlib
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
    objects: dict[str, tuple[str, bytes]] = {}

    def add_object(object_type: str, payload: bytes) -> str:
        object_id = artifact_io._canonical_git_object_id(object_type, payload)
        objects[object_id] = (object_type, payload)
        return object_id

    blob = b"blob\n"
    blob_id = add_object("blob", blob)
    leaf_tree_id = add_object(
        "tree",
        b"100644 example.py\0" + bytes.fromhex(blob_id),
    )
    source_tree_id = add_object(
        "tree",
        b"40000 agent_assure\0" + bytes.fromhex(leaf_tree_id),
    )
    root_tree_id = add_object(
        "tree",
        b"40000 src\0" + bytes.fromhex(source_tree_id),
    )
    revision = add_object("commit", f"tree {root_tree_id}\n\ntest commit\n".encode())
    captured: list[tuple[list[str], dict[str, object]]] = []

    class FakeProcess:
        def __init__(self, output: bytes) -> None:
            self.stdout = io.BytesIO(output)

        def poll(self) -> int:
            return 0

        def wait(self, *, timeout: float) -> int:
            assert timeout > 0
            return 0

        def kill(self) -> None:
            pytest.fail("successful Git reads must not be killed")

    def fake_popen(
        args: list[str],
        **kwargs: object,
    ) -> FakeProcess:
        captured.append((args, kwargs))
        operation, object_id = args[-2:]
        object_type, payload = objects[object_id]
        if operation == "-t":
            output = f"{object_type}\n".encode()
        elif operation == "-s":
            output = f"{len(payload)}\n".encode()
        else:
            assert operation == object_type
            output = payload
        return FakeProcess(output)

    monkeypatch.setattr(artifact_io, "_resolve_git_executable", lambda: "/usr/bin/git")
    monkeypatch.setattr(artifact_io, "_IS_WINDOWS", True)
    monkeypatch.setattr(artifact_io.subprocess, "Popen", fake_popen)
    monkeypatch.setenv("GIT_DIR", "/tmp/attacker-repository")

    actual = git_file_bytes(tmp_path, revision, "src/agent_assure/example.py")

    assert actual == blob
    commands = [command for command, _kwargs in captured]
    object_reads = [revision, root_tree_id, source_tree_id, leaf_tree_id, blob_id]
    expected_tails = [
        ["cat-file", operation, object_id]
        for object_id in object_reads
        for operation in ("-t", "-s", objects[object_id][0])
    ]
    assert [command[-3:] for command in commands] == expected_tails
    assert all("core.longpaths=true" in command for command in commands)
    assert all("core.fsmonitor=false" in command for command in commands)
    assert all(f"safe.directory={tmp_path.resolve()}" in command for command in commands)
    git_environment = captured[0][1]["env"]
    assert isinstance(git_environment, dict)
    assert "GIT_DIR" not in git_environment
    assert git_environment["GIT_NO_LAZY_FETCH"] == "1"
    assert all(kwargs["stdin"] is subprocess.DEVNULL for _command, kwargs in captured)
    assert all(kwargs["stdout"] is subprocess.PIPE for _command, kwargs in captured)
    assert all(kwargs["stderr"] is subprocess.DEVNULL for _command, kwargs in captured)
    assert all(kwargs["close_fds"] is True for _command, kwargs in captured)


def test_git_file_bytes_rejects_oversized_blob_before_content_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "b" * 40
    requests: list[tuple[tuple[str, ...], int]] = []

    def fake_git_stdout_bounded(
        _git_executable: str,
        _project_root: Path,
        *args: str,
        max_bytes: int,
        label: str,
    ) -> bytes:
        del label
        requests.append((args, max_bytes))
        if args[1] == "-t":
            return b"blob\n"
        if args[1] == "-s":
            return b"6\n"
        pytest.fail("oversized blob content must not be requested")

    monkeypatch.setattr(artifact_io, "_git_stdout_bounded", fake_git_stdout_bounded)

    with pytest.raises(ValueError, match="maximum supported size of 5 bytes"):
        artifact_io._read_and_verify_git_object(
            "/usr/bin/git",
            tmp_path,
            object_id,
            expected_type="blob",
            max_bytes=5,
            label="Git blob",
        )

    assert requests[-1][0] == ("cat-file", "-s", object_id)
    assert not any(args[:2] == ("cat-file", "blob") for args, _limit in requests)


def test_git_object_reader_rejects_wrong_type_before_size_or_content_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "b" * 40
    requests: list[tuple[str, ...]] = []

    def fake_git_stdout_bounded(
        _git_executable: str,
        _project_root: Path,
        *args: str,
        max_bytes: int,
        label: str,
    ) -> bytes:
        del max_bytes, label
        requests.append(args)
        if args[1] == "-t":
            return b"tree\n"
        pytest.fail("non-blob size or content must not be requested")

    monkeypatch.setattr(artifact_io, "_git_stdout_bounded", fake_git_stdout_bounded)

    with pytest.raises(OSError, match="unexpected object type"):
        artifact_io._read_and_verify_git_object(
            "/usr/bin/git",
            tmp_path,
            object_id,
            expected_type="blob",
            max_bytes=5,
            label="Git blob",
        )

    assert requests == [("cat-file", "-t", object_id)]


@pytest.mark.parametrize("size_output", (b"-1\n", b"01\n", b"5 trailing\n", b"5"))
def test_git_object_reader_rejects_noncanonical_object_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    size_output: bytes,
) -> None:
    object_id = "b" * 40

    def fake_git_stdout_bounded(
        _git_executable: str,
        _project_root: Path,
        *args: str,
        max_bytes: int,
        label: str,
    ) -> bytes:
        del max_bytes, label
        if args[1] == "-t":
            return b"blob\n"
        if args[1] == "-s":
            return size_output
        pytest.fail("content must not be requested after an invalid size preflight")

    monkeypatch.setattr(artifact_io, "_git_stdout_bounded", fake_git_stdout_bounded)

    with pytest.raises(OSError, match="canonical non-negative integer"):
        artifact_io._read_and_verify_git_object(
            "/usr/bin/git",
            tmp_path,
            object_id,
            expected_type="blob",
            max_bytes=5,
            label="Git blob",
        )


@pytest.mark.parametrize("content", (b"four", b"sixsix"))
def test_git_object_reader_rejects_content_length_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
) -> None:
    object_id = "b" * 40

    def fake_git_stdout_bounded(
        _git_executable: str,
        _project_root: Path,
        *args: str,
        max_bytes: int,
        label: str,
    ) -> bytes:
        del max_bytes, label
        if args[1] == "-t":
            return b"blob\n"
        if args[1] == "-s":
            return b"5\n"
        return content

    monkeypatch.setattr(artifact_io, "_git_stdout_bounded", fake_git_stdout_bounded)

    with pytest.raises(OSError, match="length does not match"):
        artifact_io._read_and_verify_git_object(
            "/usr/bin/git",
            tmp_path,
            object_id,
            expected_type="blob",
            max_bytes=5,
            label="Git blob",
        )


def test_git_object_reader_rejects_content_with_wrong_object_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"good\n"
    substituted = b"evil\n"
    object_id = artifact_io._canonical_git_object_id("blob", expected)

    def fake_git_stdout_bounded(
        _git_executable: str,
        _project_root: Path,
        *args: str,
        max_bytes: int,
        label: str,
    ) -> bytes:
        del max_bytes, label
        if args[1] == "-t":
            return b"blob\n"
        if args[1] == "-s":
            return b"5\n"
        return substituted

    monkeypatch.setattr(artifact_io, "_git_stdout_bounded", fake_git_stdout_bounded)

    with pytest.raises(OSError, match="does not match its immutable object ID"):
        artifact_io._read_and_verify_git_object(
            "/usr/bin/git",
            tmp_path,
            object_id,
            expected_type="blob",
            max_bytes=5,
            label="Git blob",
        )


@pytest.mark.parametrize(
    "commit",
    (
        f"tree {'a' * 40}\n".encode(),
        f"parent {'b' * 40}\ntree {'a' * 40}\n\nmessage\n".encode(),
        f"tree {'a' * 40}\ntree {'b' * 40}\n\nmessage\n".encode(),
    ),
)
def test_commit_tree_parser_rejects_noncanonical_root_tree_headers(commit: bytes) -> None:
    with pytest.raises(OSError, match="root-tree header"):
        artifact_io._commit_tree_id(commit)


def test_git_stdout_bounded_stops_after_limit_plus_one_byte(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TrackingStream(io.BytesIO):
        requests: list[int]

        def __init__(self, payload: bytes) -> None:
            super().__init__(payload)
            self.requests = []
            self.bytes_read = 0

        def read(self, size: int = -1) -> bytes:
            self.requests.append(size)
            chunk = super().read(size)
            self.bytes_read += len(chunk)
            return chunk

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = TrackingStream(b"attacker-controlled-output")
            self.killed = False

        def poll(self) -> int | None:
            return -9 if self.killed else None

        def wait(self, *, timeout: float) -> int:
            assert timeout > 0
            return -9 if self.killed else 0

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()
    monkeypatch.setattr(artifact_io.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(OSError, match="exceeded its bounded output size"):
        artifact_io._git_stdout_bounded(
            "/usr/bin/git",
            tmp_path,
            "cat-file",
            "blob",
            "b" * 40,
            max_bytes=5,
            label="adversarial Git output",
        )

    assert process.killed
    assert process.stdout.requests == [6]
    assert process.stdout.bytes_read == 6


@pytest.mark.skipif(os.name != "nt", reason="Windows long-path Git regression")
def test_git_file_bytes_reads_blob_from_a_deep_windows_checkout(tmp_path: Path) -> None:
    git = artifact_io._resolve_git_executable()
    if git is None:
        pytest.skip("native Git executable is unavailable")

    repository = tmp_path / "repo"
    component_index = 0
    while len(str(repository.resolve())) < 210:
        repository /= f"deep-{component_index:03d}"
        component_index += 1
    repository.mkdir(parents=True)

    git_prefix = [
        git,
        "--no-optional-locks",
        "-c",
        "core.longpaths=true",
        "-c",
        f"core.hooksPath={os.devnull}",
    ]

    def run_git(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [*git_prefix, *arguments],
            cwd=repository,
            env=artifact_io._git_environment(),
            check=True,
            capture_output=True,
        )

    run_git("init")
    payload = b"immutable external-pilot input\n"
    (repository / "participant.yaml").write_bytes(payload)
    run_git("add", "--", "participant.yaml")
    run_git(
        "-c",
        "user.name=agent-assure test",
        "-c",
        "user.email=agent-assure@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    revision = run_git("rev-parse", "HEAD").stdout.decode("ascii").strip()

    assert len(str(repository.resolve() / f"{revision}:participant.yaml")) > 260
    assert git_file_bytes(repository, revision, "participant.yaml") == payload


@pytest.mark.parametrize("corrupted_type", ("commit", "tree", "blob"))
def test_git_file_bytes_rejects_corrupted_loose_object_chain(
    tmp_path: Path,
    corrupted_type: str,
) -> None:
    git = artifact_io._resolve_git_executable()
    if git is None:
        pytest.skip("native Git executable is unavailable")

    repository = tmp_path / "repo"
    repository.mkdir()
    git_prefix = [
        git,
        "--no-optional-locks",
        "-c",
        f"core.hooksPath={os.devnull}",
    ]

    def run_git(*arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [*git_prefix, *arguments],
            cwd=repository,
            env=artifact_io._git_environment(),
            check=True,
            capture_output=True,
        )

    run_git("init")
    (repository / "input.yaml").write_bytes(b"good\n")
    run_git("add", "--", "input.yaml")
    run_git(
        "-c",
        "user.name=agent-assure test",
        "-c",
        "user.email=agent-assure@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    revision = run_git("rev-parse", "HEAD").stdout.decode("ascii").strip()
    object_ids = {
        "commit": revision,
        "tree": run_git("rev-parse", "HEAD^{tree}").stdout.decode("ascii").strip(),
        "blob": run_git("rev-parse", "HEAD:input.yaml").stdout.decode("ascii").strip(),
    }
    object_id = object_ids[corrupted_type]
    original = run_git("cat-file", corrupted_type, object_id).stdout
    if corrupted_type == "commit":
        corrupted = original.replace(b"fixture", b"fIxture", 1)
    elif corrupted_type == "tree":
        corrupted = original.replace(b"input.yaml", b"jnput.yaml", 1)
    else:
        corrupted = b"evil\n"
    assert corrupted != original
    assert len(corrupted) == len(original)

    loose_object = repository / ".git" / "objects" / object_id[:2] / object_id[2:]
    assert loose_object.is_file()
    canonical = f"{corrupted_type} {len(corrupted)}\0".encode("ascii") + corrupted
    loose_object.chmod(0o600)
    loose_object.write_bytes(zlib.compress(canonical))
    assert run_git("cat-file", corrupted_type, object_id).stdout == corrupted

    with pytest.raises(
        OSError,
        match=rf"Git {corrupted_type} content does not match its immutable object ID",
    ):
        git_file_bytes(repository, revision, "input.yaml", max_bytes=5)


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
