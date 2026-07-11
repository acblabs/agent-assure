from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_ARTIFACT_JSON_BYTES = 16 * 1024 * 1024
MAX_CONFIG_TEXT_BYTES = 1 * 1024 * 1024
MAX_PROMPT_BYTES = 1 * 1024 * 1024
MAX_STATIC_JSONL_BYTES = 16 * 1024 * 1024
MAX_STATIC_JSONL_LINE_BYTES = 1 * 1024 * 1024


def read_text_bounded(path: Path, *, max_bytes: int, label: str) -> str:
    return read_bytes_bounded(path, max_bytes=max_bytes, label=label).decode("utf-8")


def read_bytes_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds maximum supported size: {path}")
    return data


def load_json_bounded(path: Path, *, max_bytes: int = MAX_ARTIFACT_JSON_BYTES) -> dict[str, Any]:
    value = json.loads(
        read_text_bounded(path, max_bytes=max_bytes, label="artifact JSON")
    )
    if not isinstance(value, dict):
        raise ValueError("artifact JSON root must be an object")
    return value
