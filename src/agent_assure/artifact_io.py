from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from pathlib import Path

_ALLOWED_GIT_COMMANDS = frozenset(
    {
        ("rev-parse", "HEAD"),
        ("rev-parse", "--show-toplevel"),
        ("status", "--porcelain"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
    }
)
_UNTRUSTED_GIT_ENVIRONMENT = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_ASKPASS",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_TEMPLATE_DIR",
        "GIT_WORK_TREE",
        "SSH_ASKPASS",
    }
)
_FULL_GIT_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_IS_WINDOWS = os.name == "nt"
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_bytes_atomic(path: Path, payload: bytes) -> Path:
    """Atomically replace a file without following a destination link or hard link."""
    if not isinstance(payload, bytes):
        raise TypeError("atomic file payload must be bytes")
    # Check the existing prefix before mkdir so a linked ancestor cannot cause
    # creation of a previously absent child directory outside the intended tree.
    _assert_no_linked_directory_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Re-check the complete path after creation to catch linked components that
    # appeared between validation and mkdir.
    _assert_no_linked_directory_components(path.parent)
    parent = path.parent.resolve(strict=True)
    destination = parent / path.name
    if destination.exists() and destination.is_dir():
        raise IsADirectoryError(destination)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return path


def write_text_atomic(path: Path, text: str) -> Path:
    if not isinstance(text, str):
        raise TypeError("atomic text payload must be a string")
    return write_bytes_atomic(path, text.encode("utf-8"))


def _assert_no_linked_directory_components(directory: Path) -> None:
    absolute = directory.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if _is_linked_directory_component(current):
            raise OSError(f"refusing to write through linked directory component: {current}")


def _is_linked_directory_component(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    if not _IS_WINDOWS:
        return False
    try:
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    # Python 3.11 has no Path.is_junction(). NTFS junctions and mount points
    # are reparse points, so use lstat metadata as the fail-closed fallback.
    return bool(attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)


def git_output(
    project_root: Path,
    *args: str,
    allow_empty: bool = False,
) -> str | None:
    if tuple(args) not in _ALLOWED_GIT_COMMANDS and not _is_allowed_ancestry_query(args):
        raise ValueError(f"unsupported read-only git command: {' '.join(args)}")
    git_executable = _resolve_git_executable()
    if git_executable is None:
        return None
    try:
        result = subprocess.run(
            [
                git_executable,
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                *args,
            ],
            cwd=project_root,
            env=_git_environment(),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output if output or allow_empty else None


def _is_allowed_ancestry_query(args: tuple[str, ...]) -> bool:
    return (
        len(args) == 4
        and args[:2] == ("merge-base", "--is-ancestor")
        and _FULL_GIT_COMMIT.fullmatch(args[2]) is not None
        and _FULL_GIT_COMMIT.fullmatch(args[3]) is not None
    )


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in _UNTRUSTED_GIT_ENVIRONMENT
        and not key.upper().startswith("GIT_CONFIG_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


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
