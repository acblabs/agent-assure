from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath


def resolve_live_config_path(base_dir: Path, value: str, *, field_name: str) -> Path:
    """Resolve a live config path while keeping it inside the config directory."""
    raw = str(value).replace("\\", "/")
    posix_path = PurePosixPath(raw)
    windows_path = PureWindowsPath(str(value))
    if raw in {"", "."}:
        raise ValueError(f"{field_name} must not be empty")
    if posix_path.is_absolute() or windows_path.drive:
        raise ValueError(f"{field_name} must be relative to the live config directory")
    if any(part in {"", ".", ".."} for part in posix_path.parts):
        raise ValueError(f"{field_name} must not contain unsafe path segments")
    root = base_dir.resolve()
    resolved = (root / Path(*posix_path.parts)).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{field_name} resolves outside the live config directory") from exc
    return resolved
