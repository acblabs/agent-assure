from __future__ import annotations

import os
import secrets
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from agent_assure.io_limits import read_file_bounded_from_filesystem_root
from agent_assure.rooted_io import (
    PinnedDirectoryFile,
    RootedDirectoryDescriptor,
    open_rooted_directory,
)


@dataclass(frozen=True)
class _OutputSnapshot:
    path: Path
    contents: bytes | None
    owned_identity: str
    device: int | None
    inode: int | None


@dataclass(frozen=True)
class _PublishedOutput:
    sha256: str
    device: int
    inode: int


@dataclass(frozen=True)
class _PinnedPublishedOutput:
    snapshot: _OutputSnapshot
    published: _PublishedOutput
    parent: RootedDirectoryDescriptor
    opened: PinnedDirectoryFile


@dataclass
class OutputPublicationRollback:
    """Restore bounded output snapshots without clobbering concurrent writers."""

    snapshots: tuple[_OutputSnapshot, ...]
    max_bytes: int
    label: str
    path_resolution_error: str
    concurrent_change_error: str
    published_outputs: dict[str, _PublishedOutput | None] = field(default_factory=dict)

    @classmethod
    def capture(
        cls,
        paths: tuple[Path, ...],
        *,
        max_bytes: int,
        label: str,
        path_resolution_error: str,
        concurrent_change_error: str,
    ) -> OutputPublicationRollback:
        snapshots: list[_OutputSnapshot] = []
        for path in paths:
            try:
                existing = read_file_bounded_from_filesystem_root(
                    path,
                    max_bytes=max_bytes,
                    label=f"existing {label}",
                )
            except FileNotFoundError:
                existing = None
            snapshots.append(
                _OutputSnapshot(
                    path=path,
                    contents=(existing.data if existing is not None else None),
                    owned_identity=_owned_path_identity(path),
                    device=(existing.device if existing is not None else None),
                    inode=(existing.inode if existing is not None else None),
                )
            )
        return cls(
            snapshots=tuple(snapshots),
            max_bytes=max_bytes,
            label=label,
            path_resolution_error=path_resolution_error,
            concurrent_change_error=concurrent_change_error,
        )

    def mark_written(self, path: Path) -> None:
        owned_identity = _owned_path_identity(path)
        # Record publication intent before re-reading the path. If validation
        # fails, restore must fail closed instead of treating this output as
        # untouched and partially restoring the rest of the transaction.
        self.published_outputs[owned_identity] = None
        contents = read_file_bounded_from_filesystem_root(
            path,
            max_bytes=self.max_bytes,
            label=f"published {self.label}",
        )
        self.published_outputs[owned_identity] = _PublishedOutput(
            sha256=contents.sha256,
            device=contents.device,
            inode=contents.inode,
        )

    def restore(self) -> None:
        pinned: list[_PinnedPublishedOutput] = []
        with ExitStack() as stack:
            # Pin and verify every transaction-owned inode before mutating any
            # output. A byte-identical replacement is therefore still foreign.
            for snapshot in self.snapshots:
                if snapshot.owned_identity not in self.published_outputs:
                    continue
                published = self.published_outputs[snapshot.owned_identity]
                if published is None:
                    raise ValueError(self.concurrent_change_error)
                try:
                    parent = stack.enter_context(self._open_parent(snapshot.path))
                    opened = stack.enter_context(
                        parent.open_file_bounded(
                            snapshot.path.name,
                            max_bytes=self.max_bytes,
                            label=f"published {self.label}",
                            require_single_link=True,
                            permit_rename=True,
                        )
                    )
                except (OSError, ValueError) as exc:
                    raise ValueError(self.concurrent_change_error) from exc
                contents = opened.contents
                if contents.sha256 != published.sha256 or (contents.device, contents.inode) != (
                    published.device,
                    published.inode,
                ):
                    raise ValueError(self.concurrent_change_error)
                pinned.append(
                    _PinnedPublishedOutput(
                        snapshot=snapshot,
                        published=published,
                        parent=parent,
                        opened=opened,
                    )
                )
            for item in reversed(pinned):
                self._restore_pinned(item)

    def _restore_pinned(self, item: _PinnedPublishedOutput) -> None:
        snapshot = item.snapshot
        published = item.published
        parent = item.parent
        opened = item.opened
        quarantine_name = f".agent-assure-rollback-{secrets.token_hex(16)}.tmp"
        try:
            parent.move_regular_file_no_replace(
                snapshot.path.name,
                quarantine_name,
                source_descriptor=opened.descriptor,
                expected_device=published.device,
                expected_inode=published.inode,
            )
        except (OSError, ValueError) as exc:
            raise ValueError(self.concurrent_change_error) from exc

        if snapshot.contents is None:
            opened.close()
            parent.unlink_entry_no_follow(
                quarantine_name,
                expected_device=published.device,
                expected_inode=published.inode,
            )
            self._require_target_absent(parent, snapshot.path.name)
            return

        stage_name = f".agent-assure-restore-{secrets.token_hex(16)}.tmp"
        stage_descriptor: int | None = None
        stage_metadata: os.stat_result | None = None
        stage_installed = False
        try:
            stage_descriptor, stage_metadata = parent.open_regular_file_exclusive_with_metadata(
                stage_name,
                mode=0o600,
            )
            with os.fdopen(stage_descriptor, "wb", closefd=False) as handle:
                handle.write(snapshot.contents)
                handle.flush()
                os.fsync(handle.fileno())
            parent.move_regular_file_no_replace(
                stage_name,
                snapshot.path.name,
                source_descriptor=stage_descriptor,
                expected_device=stage_metadata.st_dev,
                expected_inode=stage_metadata.st_ino,
            )
            stage_installed = True
        except BaseException:
            if stage_descriptor is not None:
                try:
                    os.close(stage_descriptor)
                finally:
                    if not stage_installed and stage_metadata is not None:
                        try:
                            parent.unlink_entry_no_follow(
                                stage_name,
                                expected_device=stage_metadata.st_dev,
                                expected_inode=stage_metadata.st_ino,
                            )
                        except FileNotFoundError:
                            pass
            self._recover_quarantined_publication(item, quarantine_name)
            raise
        else:
            assert stage_descriptor is not None
            os.close(stage_descriptor)
        opened.close()
        parent.unlink_entry_no_follow(
            quarantine_name,
            expected_device=published.device,
            expected_inode=published.inode,
        )

    def _recover_quarantined_publication(
        self,
        item: _PinnedPublishedOutput,
        quarantine_name: str,
    ) -> None:
        try:
            item.parent.move_regular_file_no_replace(
                quarantine_name,
                item.snapshot.path.name,
                source_descriptor=item.opened.descriptor,
                expected_device=item.published.device,
                expected_inode=item.published.inode,
            )
        except FileExistsError as exc:
            item.opened.close()
            item.parent.unlink_entry_no_follow(
                quarantine_name,
                expected_device=item.published.device,
                expected_inode=item.published.inode,
            )
            raise ValueError(self.concurrent_change_error) from exc

    def _require_target_absent(
        self,
        parent: RootedDirectoryDescriptor,
        name: str,
    ) -> None:
        try:
            parent.stat_entry_no_follow(name)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            raise ValueError(self.concurrent_change_error) from exc
        raise ValueError(self.concurrent_change_error)

    def _open_parent(self, path: Path) -> RootedDirectoryDescriptor:
        absolute_parent = Path(os.path.abspath(path.parent))
        if not absolute_parent.anchor:
            raise ValueError(self.path_resolution_error)
        root = Path(absolute_parent.anchor)
        relative = absolute_parent.relative_to(root)
        return open_rooted_directory(
            root,
            relative if relative.parts else Path("."),
            label=f"{self.label} parent",
        )


def _owned_path_identity(path: Path) -> str:
    """Identify the owned directory entry without following the final path."""
    return os.path.normcase(os.path.abspath(path))
