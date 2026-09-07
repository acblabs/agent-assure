from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_assure.rooted_io import BoundedFileDescriptor, RootedDirectoryDescriptor

MAX_ARTIFACT_JSON_BYTES = 16 * 1024 * 1024
# A v0.6.6 live RunSet may carry the complete bounded attempt journal needed
# to prove every issued provider request and retry. At the declared 4,096
# observation ceiling, that journal plus the records can exceed the generic
# artifact cap while remaining bounded by each arm's preregistered max_requests.
# Only explicitly identified RunSet publication/loading paths opt into this cap.
MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 80
MAX_CONFIG_TEXT_BYTES = 1 * 1024 * 1024
MAX_PROMPT_BYTES = 1 * 1024 * 1024
MAX_STATIC_JSONL_BYTES = 16 * 1024 * 1024
MAX_STATIC_JSONL_LINE_BYTES = 1 * 1024 * 1024
# A RunSet is a single bounded JSON artifact, not a streaming container. Keep
# planned record cardinality far below the ordinary 16 MiB byte ceiling so
# hostile plans cannot allocate six-figure schedules. A journal-bearing live
# RunSet may use the explicit 64 MiB exception above; writers still enforce its
# exact byte limit because record and retry-event payloads vary in size.
MAX_PERSISTED_OBSERVATIONS = 4_096
_READ_CHUNK_BYTES = 1024 * 1024
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


@dataclass(frozen=True)
class BoundedFileContents:
    """Bytes, digest, and identity from one validated regular-file descriptor."""

    data: bytes
    sha256: str
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def open_directory_at(
    root: Path,
    relative_path: str | Path,
    *,
    label: str,
) -> RootedDirectoryDescriptor:
    """Lease a directory through a pinned trusted-root descriptor walk."""
    from agent_assure.rooted_io import open_rooted_directory

    return open_rooted_directory(root, relative_path, label=label)


def open_file_bounded_at(
    root: Path,
    relative_path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileDescriptor:
    """Open and read one file through a pinned trusted-root descriptor walk."""
    from agent_assure.rooted_io import open_rooted_bounded_file

    return open_rooted_bounded_file(
        root,
        relative_path,
        max_bytes=max_bytes,
        label=label,
    )


def read_file_bounded_at(
    root: Path,
    relative_path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileContents:
    with open_file_bounded_at(
        root,
        relative_path,
        max_bytes=max_bytes,
        label=label,
    ) as opened:
        return opened.contents


def read_bytes_bounded_at(
    root: Path,
    relative_path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    return read_file_bounded_at(
        root,
        relative_path,
        max_bytes=max_bytes,
        label=label,
    ).data


def read_text_bounded_at(
    root: Path,
    relative_path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> str:
    return read_bytes_bounded_at(
        root,
        relative_path,
        max_bytes=max_bytes,
        label=label,
    ).decode("utf-8")


def open_file_bounded_from_filesystem_root(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileDescriptor:
    """Open a file while pinning every directory from its filesystem root."""
    root, relative_path = _filesystem_rooted_path(path)
    return open_file_bounded_at(
        root,
        relative_path,
        max_bytes=max_bytes,
        label=label,
    )


def read_file_bounded_from_filesystem_root(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileContents:
    """Read a file without following any intermediate or final path links."""
    with open_file_bounded_from_filesystem_root(
        path,
        max_bytes=max_bytes,
        label=label,
    ) as opened:
        return opened.contents


def read_bytes_bounded_from_filesystem_root(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    return read_file_bounded_from_filesystem_root(
        path,
        max_bytes=max_bytes,
        label=label,
    ).data


def read_text_bounded_from_filesystem_root(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> str:
    return read_bytes_bounded_from_filesystem_root(
        path,
        max_bytes=max_bytes,
        label=label,
    ).decode("utf-8")


def _filesystem_rooted_path(path: Path) -> tuple[Path, Path]:
    absolute = Path(os.path.abspath(path))
    if not absolute.anchor:
        raise ValueError("bounded file path must have a filesystem root")
    root = Path(absolute.anchor)
    relative_path = absolute.relative_to(root)
    if not relative_path.parts:
        raise ValueError("bounded file path must identify a file below its filesystem root")
    return root, relative_path


def read_text_bounded(path: Path, *, max_bytes: int, label: str) -> str:
    return read_bytes_bounded(path, max_bytes=max_bytes, label=label).decode("utf-8")


def read_bytes_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    return read_file_bounded(path, max_bytes=max_bytes, label=label).data


def read_file_bounded(
    path: Path,
    *,
    max_bytes: int,
    label: str,
) -> BoundedFileContents:
    """Read and hash one bounded regular file without following its final link."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("maximum file size must be a non-negative integer")

    # Reject FIFOs and devices before opening them. O_NONBLOCK and the descriptor
    # checks below close the race if the directory entry changes after this lstat.
    before_open = os.lstat(path)
    _require_regular_file(before_open, path=path, label=label)
    if before_open.st_size > max_bytes:
        raise ValueError(f"{label} exceeds maximum supported size: {path}")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _require_regular_file(opened, path=path, label=label)
        _require_same_file_identity(before_open, opened, path=path, label=label)
        if opened.st_size > max_bytes:
            raise ValueError(f"{label} exceeds maximum supported size: {path}")

        chunks: list[bytes] = []
        digest = hashlib.sha256()
        size = 0
        while True:
            remaining_with_sentinel = (max_bytes - size) + 1
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, remaining_with_sentinel),
            )
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
        current = os.lstat(path)
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
    finally:
        os.close(descriptor)


def _require_regular_file(
    metadata: os.stat_result,
    *,
    path: Path,
    label: str,
) -> None:
    attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError(f"{label} must be a regular file: {path}")


def _require_same_file_identity(
    expected: os.stat_result,
    observed: os.stat_result,
    *,
    path: Path,
    label: str,
    compare_change_time: bool = False,
) -> None:
    expected_identity = (
        expected.st_dev,
        expected.st_ino,
        expected.st_size,
        expected.st_mtime_ns,
    )
    observed_identity = (
        observed.st_dev,
        observed.st_ino,
        observed.st_size,
        observed.st_mtime_ns,
    )
    if expected_identity != observed_identity or (
        compare_change_time and expected.st_ctime_ns != observed.st_ctime_ns
    ):
        raise ValueError(f"{label} changed while it was being read: {path}")


def load_json_bounded(
    path: Path,
    *,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
    label: str = "artifact JSON",
) -> dict[str, Any]:
    text = read_text_bounded(path, max_bytes=max_bytes, label=label)
    value = loads_json_bounded(text, label=label)
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def load_json_bounded_from_filesystem_root(
    path: Path,
    *,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
    label: str = "artifact JSON",
) -> dict[str, Any]:
    text = read_text_bounded_from_filesystem_root(
        path,
        max_bytes=max_bytes,
        label=label,
    )
    value = loads_json_bounded(text, label=label)
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def load_json_bounded_at(
    root: Path,
    relative_path: str | Path,
    *,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
    label: str = "artifact JSON",
) -> dict[str, Any]:
    text = read_text_bounded_at(
        root,
        relative_path,
        max_bytes=max_bytes,
        label=label,
    )
    value = loads_json_bounded(text, label=label)
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def load_json_bytes_bounded(
    data: bytes,
    *,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
    label: str = "artifact JSON",
) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError(f"{label} bytes must be bytes")
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds maximum supported size")
    text = data.decode("utf-8")
    value = loads_json_bounded(text, label=label)
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return value


def loads_json_bounded(
    text: str,
    *,
    label: str,
    max_depth: int = MAX_JSON_DEPTH,
) -> Any:
    _validate_json_nesting(text, max_depth=max_depth, label=label)
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_pairs(label),
            parse_constant=_reject_non_finite_json_constant(label),
            parse_float=_parse_finite_json_float(label),
        )
    except RecursionError as exc:
        raise ValueError(f"{label} exceeds maximum supported nesting depth") from exc


def _reject_duplicate_object_pairs(
    label: str,
) -> Callable[[list[tuple[str, Any]]], dict[str, Any]]:
    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate object keys")
            result[key] = value
        return result

    return reject


def _reject_non_finite_json_constant(label: str) -> Callable[[str], None]:
    def reject(_constant: str) -> None:
        raise ValueError(f"{label} contains a non-finite numeric value")

    return reject


def _parse_finite_json_float(label: str) -> Callable[[str], float]:
    def parse(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError(f"{label} contains a non-finite numeric value")
        return parsed

    return parse


def _validate_json_nesting(text: str, *, max_depth: int, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False

    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue

        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > max_depth:
                raise ValueError(f"{label} exceeds maximum supported nesting depth")
        elif character in "]}":
            depth -= 1
