from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_assure import io_limits
from agent_assure.io_limits import (
    MAX_JSON_DEPTH,
    load_json_bounded,
    loads_json_bounded,
    read_file_bounded,
)


def test_load_json_bounded_accepts_maximum_nesting_depth(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    nested_array_count = MAX_JSON_DEPTH - 1
    path.write_text(
        '{"value":' + ("[" * nested_array_count) + "0" + ("]" * nested_array_count) + "}",
        encoding="utf-8",
    )

    payload = load_json_bounded(path)

    assert "value" in payload


def test_load_json_bounded_rejects_excessive_nesting(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    nested_array_count = MAX_JSON_DEPTH
    path.write_text(
        '{"value":' + ("[" * nested_array_count) + "0" + ("]" * nested_array_count) + "}",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_json_bounded(path)


def test_load_json_bounded_ignores_delimiters_and_escapes_in_strings(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    expected = {
        "text": ("[{" * (MAX_JSON_DEPTH + 1)) + ' "quoted" \\ tail',
        "nested": {"valid": True},
    }
    path.write_text(json.dumps(expected), encoding="utf-8")

    assert load_json_bounded(path) == expected


def test_load_json_bounded_converts_decoder_recursion_error(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    path.write_text("{}", encoding="utf-8")

    def raise_recursion_error(_text: str, **_kwargs: object) -> object:
        raise RecursionError("decoder recursion limit")

    monkeypatch.setattr("agent_assure.io_limits.json.loads", raise_recursion_error)

    with pytest.raises(ValueError, match="exceeds maximum supported nesting depth"):
        load_json_bounded(path)


def test_load_json_bounded_rejects_non_object_root(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "artifact.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="root must be an object"):
        load_json_bounded(path)


@pytest.mark.parametrize(
    "payload",
    (
        '{"decision":"allow","decision":"deny"}',
        '{"outer":{"decision":"allow","decision":"deny"}}',
    ),
)
def test_loads_json_bounded_rejects_duplicate_object_keys(payload: str) -> None:
    with pytest.raises(ValueError, match="contains duplicate object keys"):
        loads_json_bounded(payload, label="test JSON")


def test_loads_json_bounded_rejects_escaped_equivalent_duplicate_keys() -> None:
    with pytest.raises(ValueError, match="contains duplicate object keys"):
        loads_json_bounded('{"decision":1,"dec\\u0069sion":2}', label="test JSON")


def test_loads_json_bounded_allows_same_key_in_separate_objects() -> None:
    assert loads_json_bounded('[{"decision":1},{"decision":2}]', label="test JSON") == [
        {"decision": 1},
        {"decision": 2},
    ]


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_loads_json_bounded_rejects_non_finite_constants(constant: str) -> None:
    with pytest.raises(ValueError, match="contains a non-finite numeric value"):
        loads_json_bounded(f'{{"value":{constant}}}', label="test JSON")


def test_loads_json_bounded_rejects_float_overflow() -> None:
    with pytest.raises(ValueError, match="contains a non-finite numeric value"):
        loads_json_bounded('{"value":1e9999}', label="test JSON")


def test_read_file_bounded_returns_bytes_and_hash_from_one_regular_file(
    tmp_path: Path,
) -> None:
    path = tmp_path / "artifact.json"
    payload = b'{"value":"bounded"}'
    path.write_bytes(payload)

    contents = read_file_bounded(path, max_bytes=len(payload), label="test artifact")

    assert contents.data == payload
    assert contents.sha256 == hashlib.sha256(payload).hexdigest()


def test_read_file_bounded_rejects_oversize_and_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    link = tmp_path / "link.json"
    target.write_bytes(b"1234")

    with pytest.raises(ValueError, match="exceeds maximum supported size"):
        read_file_bounded(target, max_bytes=3, label="test artifact")

    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(ValueError, match="must be a regular file"):
        read_file_bounded(link, max_bytes=16, label="test artifact")


def test_read_file_bounded_rejects_directory_and_sparse_oversize_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "artifact-directory"
    sparse = tmp_path / "sparse-artifact.json"
    directory.mkdir()
    with sparse.open("wb") as handle:
        handle.seek((1024 * 1024) - 1)
        handle.write(b"\0")

    def unexpected_read(_descriptor: int, _size: int) -> bytes:
        raise AssertionError("unsafe artifact reached os.read")

    monkeypatch.setattr(io_limits.os, "read", unexpected_read)

    with pytest.raises(ValueError, match="must be a regular file"):
        read_file_bounded(directory, max_bytes=16, label="test artifact")
    with pytest.raises(ValueError, match="exceeds maximum supported size"):
        read_file_bounded(sparse, max_bytes=16, label="test artifact")


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO test")
def test_read_file_bounded_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "artifact.fifo"
    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="must be a regular file"):
        read_file_bounded(fifo, max_bytes=16, label="test artifact")


def test_read_file_bounded_rejects_in_place_metadata_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "artifact.json"
    path.write_bytes(b'{"stable":true}')
    real_fstat = io_limits.os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = real_fstat(descriptor)
        if calls != 2:
            return metadata
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns,
            st_ctime_ns=metadata.st_ctime_ns + 1,
            st_file_attributes=getattr(metadata, "st_file_attributes", 0),
        )

    monkeypatch.setattr(io_limits.os, "fstat", changing_fstat)

    with pytest.raises(ValueError, match="changed while it was being read"):
        read_file_bounded(path, max_bytes=1024, label="test artifact")
