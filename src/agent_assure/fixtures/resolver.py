from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from agent_assure.canonical.manifest import posix_manifest_path
from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES, read_text_bounded


class FixturePathError(ValueError):
    """Raised when a fixture path is absolute or escapes the suite root."""


@dataclass(frozen=True)
class FixtureResolver:
    suite_root: Path

    def __post_init__(self) -> None:
        if not self.suite_root.exists():
            raise FixturePathError(f"suite root does not exist: {self.suite_root}")
        if not self.suite_root.is_dir():
            raise FixturePathError(f"suite root is not a directory: {self.suite_root}")

    @property
    def resolved_root(self) -> Path:
        return self.suite_root.resolve()

    def resolve(self, relative_path: str | Path) -> Path:
        normalized = _normalize_relative_path(relative_path)
        candidate = (self.resolved_root / Path(*PurePosixPath(normalized).parts)).resolve()
        try:
            candidate.relative_to(self.resolved_root)
        except ValueError as exc:
            raise FixturePathError(f"fixture path escapes suite root: {relative_path}") from exc
        return candidate

    def manifest_path(self, path: Path) -> str:
        try:
            return posix_manifest_path(path, self.resolved_root)
        except ValueError as exc:
            raise FixturePathError(f"fixture path escapes suite root: {path}") from exc

    def read_json(self, relative_path: str | Path) -> dict[str, Any]:
        resolved = self.resolve(relative_path)
        payload = json.loads(
            read_text_bounded(resolved, max_bytes=MAX_ARTIFACT_JSON_BYTES, label="fixture JSON")
        )
        if not isinstance(payload, dict):
            raise ValueError(f"fixture JSON root must be an object: {relative_path}")
        return payload


def _normalize_relative_path(relative_path: str | Path) -> str:
    raw = str(relative_path).replace("\\", "/")
    posix_path = PurePosixPath(raw)
    windows_path = PureWindowsPath(str(relative_path))
    if raw in {"", "."}:
        raise FixturePathError("fixture path must not be empty")
    if posix_path.is_absolute() or windows_path.drive:
        raise FixturePathError(f"fixture path must be relative: {relative_path}")
    if any(part in {"", ".", ".."} for part in posix_path.parts):
        raise FixturePathError(f"fixture path contains unsafe segment: {relative_path}")
    return posix_path.as_posix()
