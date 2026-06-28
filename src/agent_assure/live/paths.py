from __future__ import annotations

from pathlib import Path


def resolve_live_config_path(base_dir: Path, value: str, *, field_name: str) -> Path:
    """Resolve a live config path while keeping it inside the config directory."""
    path = Path(value)
    if path.is_absolute():
        raise ValueError(f"{field_name} must be relative to the live config directory")
    if any(part == ".." for part in path.parts):
        raise ValueError(f"{field_name} must not contain parent directory traversal")
    root = base_dir.resolve()
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{field_name} resolves outside the live config directory") from exc
    return resolved
