import os
from pathlib import Path

import pytest

from agent_assure.artifact_io import write_bytes_atomic
from agent_assure.artifact_transaction import OutputPublicationRollback
from agent_assure.rooted_io import RootedDirectoryDescriptor


def test_publication_rollback_restores_prior_bytes(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"original\n")
    rollback = _capture((existing,))

    write_bytes_atomic(existing, b"replacement\n")
    rollback.mark_written(existing)

    rollback.restore()

    assert existing.read_bytes() == b"original\n"


def test_publication_rollback_deletes_newly_created_output(tmp_path: Path) -> None:
    created = tmp_path / "created.json"
    rollback = _capture((created,))

    write_bytes_atomic(created, b"created\n")
    rollback.mark_written(created)

    rollback.restore()

    assert not created.exists()


def test_publication_rollback_verifies_every_output_before_restoring_any(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(b"first-original\n")
    second.write_bytes(b"second-original\n")
    rollback = _capture((first, second))
    write_bytes_atomic(first, b"first-published\n")
    rollback.mark_written(first)
    write_bytes_atomic(second, b"second-published\n")
    rollback.mark_written(second)

    write_bytes_atomic(second, b"concurrent-writer\n")

    with pytest.raises(ValueError, match="test output changed concurrently"):
        rollback.restore()

    assert first.read_bytes() == b"first-published\n"
    assert second.read_bytes() == b"concurrent-writer\n"


def test_publication_rollback_does_not_restore_unmarked_output(
    tmp_path: Path,
) -> None:
    written = tmp_path / "written.json"
    untouched = tmp_path / "untouched.json"
    written.write_bytes(b"written-original\n")
    untouched.write_bytes(b"untouched-original\n")
    rollback = _capture((written, untouched))
    write_bytes_atomic(written, b"written-published\n")
    rollback.mark_written(written)
    write_bytes_atomic(untouched, b"independent-writer\n")

    rollback.restore()

    assert written.read_bytes() == b"written-original\n"
    assert untouched.read_bytes() == b"independent-writer\n"


def test_publication_rollback_rejects_byte_identical_replacement_inode(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.json"
    replaced = tmp_path / "replaced.json"
    first.write_bytes(b"first-original\n")
    replaced.write_bytes(b"replaced-original\n")
    rollback = _capture((first, replaced))
    write_bytes_atomic(first, b"first-published\n")
    rollback.mark_written(first)
    write_bytes_atomic(replaced, b"replaced-published\n")
    rollback.mark_written(replaced)
    published_inode = os.stat(replaced).st_ino

    write_bytes_atomic(replaced, b"replaced-published\n")
    replacement_inode = os.stat(replaced).st_ino
    assert replacement_inode != published_inode

    with pytest.raises(ValueError, match="test output changed concurrently"):
        rollback.restore()

    assert first.read_bytes() == b"first-published\n"
    assert replaced.read_bytes() == b"replaced-published\n"
    assert os.stat(replaced).st_ino == replacement_inode


def test_publication_rollback_preserves_replacement_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "output.json"
    path.write_bytes(b"original\n")
    rollback = _capture((path,))
    write_bytes_atomic(path, b"published\n")
    rollback.mark_written(path)
    published_inode = os.stat(path).st_ino
    replacement = tmp_path / "replacement.tmp"
    replacement.write_bytes(b"concurrent-writer\n")

    original_move = RootedDirectoryDescriptor.move_regular_file_no_replace
    replacement_inode: int | None = None
    swap_error: BaseException | None = None
    swapped = False

    def move_after_swap(
        parent: RootedDirectoryDescriptor,
        source_name: str | Path,
        target_name: str | Path,
        *,
        source_descriptor: int,
        expected_device: int,
        expected_inode: int,
    ) -> None:
        nonlocal replacement_inode, swap_error, swapped
        if not swapped and str(source_name) == path.name:
            swapped = True
            try:
                os.replace(replacement, path)
            except BaseException as exc:
                swap_error = exc
                raise
            replacement_inode = os.stat(path).st_ino
        original_move(
            parent,
            source_name,
            target_name,
            source_descriptor=source_descriptor,
            expected_device=expected_device,
            expected_inode=expected_inode,
        )

    monkeypatch.setattr(
        RootedDirectoryDescriptor,
        "move_regular_file_no_replace",
        move_after_swap,
    )

    with pytest.raises(ValueError, match="test output changed concurrently"):
        rollback.restore()

    assert swapped
    if os.name == "nt":
        # The pinned Windows handle denies rename/delete sharing, so the swap
        # cannot occur at all and both files retain their original identities.
        assert isinstance(swap_error, PermissionError)
        assert replacement_inode is None
        assert path.read_bytes() == b"published\n"
        assert os.stat(path).st_ino == published_inode
        assert replacement.read_bytes() == b"concurrent-writer\n"
        assert {entry.name for entry in tmp_path.iterdir()} == {
            "output.json",
            "replacement.tmp",
        }
    else:
        # POSIX permits a pathname swap while the old inode remains pinned.
        # The conditional move detects it and leaves the replacement untouched.
        assert swap_error is None
        assert replacement_inode is not None
        assert path.read_bytes() == b"concurrent-writer\n"
        assert os.stat(path).st_ino == replacement_inode
        assert {entry.name for entry in tmp_path.iterdir()} == {"output.json"}


def test_publication_rollback_refuses_resolved_identity_change_before_any_restore(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.json"
    replaced = tmp_path / "replaced.json"
    outside = tmp_path / "outside.json"
    first.write_bytes(b"first-original\n")
    replaced.write_bytes(b"replaced-original\n")
    outside.write_bytes(b"outside\n")
    rollback = _capture((first, replaced))
    write_bytes_atomic(first, b"first-published\n")
    rollback.mark_written(first)
    write_bytes_atomic(replaced, b"replaced-published\n")
    rollback.mark_written(replaced)
    replaced.unlink()
    try:
        replaced.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="test output changed concurrently"):
        rollback.restore()

    assert first.read_bytes() == b"first-published\n"
    assert replaced.is_symlink()
    assert outside.read_bytes() == b"outside\n"


def _capture(paths: tuple[Path, ...]) -> OutputPublicationRollback:
    return OutputPublicationRollback.capture(
        paths,
        max_bytes=1_024,
        label="test output",
        path_resolution_error="test output path cannot be safely resolved",
        concurrent_change_error=("test output changed concurrently; refusing rollback overwrite"),
    )
