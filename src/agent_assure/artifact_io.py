from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_output(project_root: Path, *args: str) -> str | None:
    git_executable = _resolve_git_executable()
    if git_executable is None:
        return None
    try:
        result = subprocess.run(
            [git_executable, *args],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _resolve_git_executable() -> str | None:
    executable_names: tuple[str, ...] = ("git",)
    if os.name == "nt":
        executable_names = ("git.exe", "git.cmd", "git.bat", "git")
    for raw_directory in os.environ.get("PATH", "").split(os.pathsep):
        directory_text = raw_directory.strip().strip('"')
        if not directory_text:
            continue
        directory = Path(directory_text)
        if not directory.is_absolute():
            continue
        for executable_name in executable_names:
            candidate = directory / executable_name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None
