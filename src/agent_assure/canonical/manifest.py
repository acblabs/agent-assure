from __future__ import annotations

from pathlib import Path


def posix_manifest_path(path: Path, root: Path) -> str:
    resolved = path.resolve()
    resolved_root = root.resolve()
    relative = resolved.relative_to(resolved_root)
    return relative.as_posix()
