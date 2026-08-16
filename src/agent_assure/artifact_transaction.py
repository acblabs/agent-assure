from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from agent_assure.artifact_io import unlink_file_if_exists, write_bytes_atomic
from agent_assure.io_limits import read_file_bounded


@dataclass(frozen=True)
class _OutputSnapshot:
    path: Path
    contents: bytes | None
    owned_identity: str


@dataclass(frozen=True)
class _PublishedOutput:
    resolved_identity: str
    sha256: str


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
            contents = (
                read_file_bounded(
                    path,
                    max_bytes=max_bytes,
                    label=f"existing {label}",
                ).data
                if path.exists()
                else None
            )
            snapshots.append(
                _OutputSnapshot(
                    path=path,
                    contents=contents,
                    owned_identity=_owned_path_identity(path),
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
        resolved_identity = self._path_identity(path, strict=True)
        contents = read_file_bounded(
            path,
            max_bytes=self.max_bytes,
            label=f"published {self.label}",
        )
        if self._path_identity(path, strict=True) != resolved_identity:
            raise ValueError(self.concurrent_change_error)
        self.published_outputs[owned_identity] = _PublishedOutput(
            resolved_identity=resolved_identity,
            sha256=contents.sha256,
        )

    def restore(self) -> None:
        # Verify every transaction-owned output before restoring any snapshot.
        # A concurrent replacement therefore leaves the whole output set alone.
        for snapshot in self.snapshots:
            if snapshot.owned_identity not in self.published_outputs:
                continue
            published = self.published_outputs[snapshot.owned_identity]
            if published is None:
                raise ValueError(self.concurrent_change_error)
            current_identity = self._path_identity(snapshot.path, strict=False)
            if current_identity != published.resolved_identity:
                raise ValueError(self.concurrent_change_error)
            current = read_file_bounded(
                snapshot.path,
                max_bytes=self.max_bytes,
                label=f"published {self.label}",
            )
            if (
                self._path_identity(snapshot.path, strict=False) != current_identity
                or current.sha256 != published.sha256
            ):
                raise ValueError(self.concurrent_change_error)
        for snapshot in reversed(self.snapshots):
            if snapshot.owned_identity not in self.published_outputs:
                continue
            if snapshot.contents is None:
                unlink_file_if_exists(snapshot.path)
            else:
                write_bytes_atomic(snapshot.path, snapshot.contents)

    def _path_identity(self, path: Path, *, strict: bool) -> str:
        try:
            resolved = path.resolve(strict=strict)
        except RuntimeError as exc:
            raise ValueError(self.path_resolution_error) from exc
        return os.path.normcase(os.path.abspath(resolved))


def _owned_path_identity(path: Path) -> str:
    """Identify the owned directory entry without following the final path."""
    return os.path.normcase(os.path.abspath(path))
