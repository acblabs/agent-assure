from __future__ import annotations

import json
import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_ARTIFACT_JSON_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 80
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
