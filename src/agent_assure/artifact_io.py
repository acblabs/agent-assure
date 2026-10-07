from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
import subprocess
import threading
import time
from pathlib import Path

_ALLOWED_GIT_COMMANDS = frozenset(
    {
        ("rev-parse", "HEAD"),
        ("rev-parse", "--show-toplevel"),
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
_GIT_COMMIT_TREE_HEADER = re.compile(rb"tree ([a-f0-9]{40})")
_GIT_OBJECT_SIZE_OUTPUT = re.compile(rb"(0|[1-9][0-9]*)\r?\n")
_GIT_REPOSITORY_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_GIT_TREE_MODES = frozenset({b"40000", b"100644", b"100755", b"120000", b"160000"})
_IS_WINDOWS = os.name == "nt"
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_GIT_METADATA_OUTPUT_BYTES = 128
_GIT_READ_CHUNK_BYTES = 64 * 1024
_GIT_TIMEOUT_SECONDS = 5.0
_MAX_GIT_COMMIT_BYTES = 1 * 1024 * 1024
_MAX_GIT_PATH_BYTES = 4 * 1024
_MAX_GIT_PATH_COMPONENTS = 64
_MAX_GIT_TREE_BYTES = 16 * 1024 * 1024
_MAX_GIT_TREE_TRAVERSAL_BYTES = 64 * 1024 * 1024
MAX_GIT_BLOB_BYTES = 128 * 1024 * 1024


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
    ensure_unlinked_directory(path.parent)
    parent_root, parent_relative = _rooted_absolute_path(path.parent)
    from agent_assure.rooted_io import open_rooted_directory

    with open_rooted_directory(
        parent_root,
        parent_relative,
        label="atomic output parent",
    ) as parent:
        _revalidate_atomic_parent(
            parent_root,
            parent_relative,
            expected_device=parent.device,
            expected_inode=parent.inode,
        )
        temporary_name = f".agent-assure-{secrets.token_hex(16)}.tmp"
        descriptor, metadata = parent.open_regular_file_exclusive_with_metadata(
            temporary_name,
            mode=0o600,
        )
        committed = False
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _revalidate_atomic_parent(
                parent_root,
                parent_relative,
                expected_device=parent.device,
                expected_inode=parent.inode,
            )
            parent.replace_regular_file(
                temporary_name,
                path.name,
                source_descriptor=descriptor,
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
            committed = True
            _revalidate_atomic_parent(
                parent_root,
                parent_relative,
                expected_device=parent.device,
                expected_inode=parent.inode,
            )
        finally:
            try:
                os.close(descriptor)
            finally:
                if not committed:
                    try:
                        parent.unlink_entry_no_follow(
                            temporary_name,
                            expected_device=metadata.st_dev,
                            expected_inode=metadata.st_ino,
                        )
                    except FileNotFoundError:
                        pass
    return path


def _rooted_absolute_path(path: Path) -> tuple[Path, Path]:
    absolute = Path(os.path.abspath(path))
    root = Path(absolute.anchor)
    if not absolute.anchor:
        raise ValueError("atomic output path must have a filesystem root")
    relative = absolute.relative_to(root)
    return root, relative if relative.parts else Path(".")


def _revalidate_atomic_parent(
    root: Path,
    relative: Path,
    *,
    expected_device: int,
    expected_inode: int,
) -> None:
    from agent_assure.rooted_io import open_rooted_directory

    with open_rooted_directory(root, relative, label="atomic output parent") as current:
        if (current.device, current.inode) != (expected_device, expected_inode):
            raise OSError("atomic output parent identity changed during publication")


def write_text_atomic(path: Path, text: str) -> Path:
    if not isinstance(text, str):
        raise TypeError("atomic text payload must be a string")
    return write_bytes_atomic(path, text.encode("utf-8"))


def unlink_file_if_exists(path: Path) -> None:
    """Remove one file through a pinned parent without following path links."""
    _assert_no_linked_directory_components(path.parent)
    parent_root, parent_relative = _rooted_absolute_path(path.parent)
    from agent_assure.rooted_io import open_rooted_directory

    with open_rooted_directory(
        parent_root,
        parent_relative,
        label="atomic output parent",
    ) as parent:
        _revalidate_atomic_parent(
            parent_root,
            parent_relative,
            expected_device=parent.device,
            expected_inode=parent.inode,
        )
        destination = parent.path / path.name
        try:
            if os.name == "nt":
                metadata = os.lstat(destination)
            else:
                if parent.descriptor is None:
                    raise OSError("atomic output parent descriptor is unavailable")
                metadata = os.stat(
                    path.name,
                    dir_fd=parent.descriptor,
                    follow_symlinks=False,
                )
        except FileNotFoundError:
            return
        attributes = getattr(metadata, "st_file_attributes", 0)
        is_reparse = bool(attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT)
        if stat.S_ISDIR(metadata.st_mode) and not (stat.S_ISLNK(metadata.st_mode) or is_reparse):
            raise IsADirectoryError(destination)
        parent.unlink_file_or_link_no_follow(
            path.name,
            expected_device=metadata.st_dev,
            expected_inode=metadata.st_ino,
        )
        _revalidate_atomic_parent(
            parent_root,
            parent_relative,
            expected_device=parent.device,
            expected_inode=parent.inode,
        )


def ensure_unlinked_directory(directory: Path) -> Path:
    """Create a directory only when its existing path components are not links."""
    # Check the existing prefix before mkdir so a linked ancestor cannot cause
    # creation of a previously absent child directory outside the intended tree.
    _assert_no_linked_directory_components(directory.parent)
    directory.mkdir(parents=True, exist_ok=True)
    # Re-check the complete path after creation to catch linked components that
    # appeared between validation and mkdir.
    _assert_no_linked_directory_components(directory)
    if not directory.is_dir():
        raise NotADirectoryError(directory)
    return directory


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
            _hardened_git_command(git_executable, project_root, *args),
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


def git_file_bytes(
    project_root: Path,
    revision: str,
    repository_path: str,
    *,
    max_bytes: int = MAX_GIT_BLOB_BYTES,
) -> bytes:
    """Read one size-bounded immutable Git blob with unsafe Git inputs disabled."""
    if _FULL_GIT_COMMIT.fullmatch(revision) is None:
        raise ValueError(f"invalid immutable Git revision: {revision!r}")
    path_parts = repository_path.split("/")
    if (
        _GIT_REPOSITORY_PATH.fullmatch(repository_path) is None
        or "\\" in repository_path
        or any(part in {"", ".", ".."} for part in path_parts)
    ):
        raise ValueError(f"unsafe Git repository path: {repository_path!r}")
    if len(repository_path.encode("ascii")) > _MAX_GIT_PATH_BYTES:
        raise ValueError("Git repository path exceeds the bounded traversal limit")
    if len(path_parts) > _MAX_GIT_PATH_COMPONENTS:
        raise ValueError("Git repository path has too many components")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("maximum Git blob size must be a non-negative integer")
    if max_bytes > MAX_GIT_BLOB_BYTES:
        raise ValueError(
            f"maximum Git blob size cannot exceed the {MAX_GIT_BLOB_BYTES}-byte hard limit"
        )
    git_executable = _resolve_git_executable()
    if git_executable is None:
        raise FileNotFoundError("git executable is unavailable")

    commit = _read_and_verify_git_object(
        git_executable,
        project_root,
        revision,
        expected_type="commit",
        max_bytes=_MAX_GIT_COMMIT_BYTES,
        label="Git commit",
    )
    tree_id = _commit_tree_id(commit)
    traversed_tree_bytes = 0
    blob_id: str | None = None
    for index, component in enumerate(path_parts):
        remaining_tree_bytes = _MAX_GIT_TREE_TRAVERSAL_BYTES - traversed_tree_bytes
        if remaining_tree_bytes <= 0:
            raise ValueError("Git tree traversal exceeds its cumulative byte limit")
        tree = _read_and_verify_git_object(
            git_executable,
            project_root,
            tree_id,
            expected_type="tree",
            max_bytes=min(_MAX_GIT_TREE_BYTES, remaining_tree_bytes),
            label="Git tree",
        )
        traversed_tree_bytes += len(tree)
        mode, entry_id = _git_tree_entry(tree, component.encode("ascii"))
        is_final = index == len(path_parts) - 1
        if not is_final:
            if mode != b"40000":
                raise OSError("Git repository path traverses a non-tree object")
            tree_id = entry_id
            continue
        if mode not in {b"100644", b"100755", b"120000"}:
            raise OSError("Git repository path does not resolve to a blob")
        blob_id = entry_id

    if blob_id is None:  # pragma: no cover - path validation guarantees at least one component
        raise OSError("Git repository path did not resolve to an object")
    return _read_and_verify_git_object(
        git_executable,
        project_root,
        blob_id,
        expected_type="blob",
        max_bytes=max_bytes,
        label="Git blob",
    )


def _read_and_verify_git_object(
    git_executable: str,
    project_root: Path,
    object_id: str,
    *,
    expected_type: str,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read and rehash one exact Git object under a caller-supplied byte ceiling."""
    if _FULL_GIT_COMMIT.fullmatch(object_id) is None:
        raise OSError(f"{label} identity is not one canonical full object ID")

    object_type = _git_stdout_bounded(
        git_executable,
        project_root,
        "cat-file",
        "-t",
        object_id,
        max_bytes=_GIT_METADATA_OUTPUT_BYTES,
        label="Git object type",
    )
    if object_type not in {
        f"{expected_type}\n".encode("ascii"),
        f"{expected_type}\r\n".encode("ascii"),
    }:
        raise OSError(f"{label} has an unexpected object type")

    size_output = _git_stdout_bounded(
        git_executable,
        project_root,
        "cat-file",
        "-s",
        object_id,
        max_bytes=_GIT_METADATA_OUTPUT_BYTES,
        label=f"{label} size",
    )
    size_match = _GIT_OBJECT_SIZE_OUTPUT.fullmatch(size_output)
    if size_match is None:
        raise OSError(f"{label} size is not one canonical non-negative integer")
    object_size = int(size_match.group(1))
    if object_size > max_bytes:
        raise ValueError(f"{label} exceeds maximum supported size of {max_bytes} bytes")

    payload = _git_stdout_bounded(
        git_executable,
        project_root,
        "cat-file",
        expected_type,
        object_id,
        max_bytes=object_size,
        label=f"{label} content",
    )
    if len(payload) != object_size:
        raise OSError(f"{label} content length does not match its immutable object size")
    actual_id = _canonical_git_object_id(expected_type, payload)
    if not secrets.compare_digest(actual_id, object_id):
        raise OSError(f"{label} content does not match its immutable object ID")
    return payload


def _canonical_git_object_id(object_type: str, payload: bytes) -> str:
    # The accepted revision grammar is Git's 40-hex SHA-1 object format. This
    # digest is an identity-format operation, not a new cryptographic choice.
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"{object_type} {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def _commit_tree_id(commit: bytes) -> str:
    header_block, separator, _message = commit.partition(b"\n\n")
    header_lines = header_block.split(b"\n")
    match = _GIT_COMMIT_TREE_HEADER.fullmatch(header_lines[0]) if header_lines else None
    if not separator or match is None:
        raise OSError("Git commit does not contain one canonical root-tree header")
    if any(line.startswith(b"tree ") for line in header_lines[1:]):
        raise OSError("Git commit contains duplicate root-tree headers")
    return match.group(1).decode("ascii")


def _git_tree_entry(tree: bytes, expected_name: bytes) -> tuple[bytes, str]:
    position = 0
    match: tuple[bytes, str] | None = None
    while position < len(tree):
        mode_end = tree.find(b" ", position)
        if mode_end <= position:
            raise OSError("Git tree contains a malformed entry mode")
        name_end = tree.find(b"\0", mode_end + 1)
        if name_end <= mode_end + 1:
            raise OSError("Git tree contains a malformed entry name")
        object_end = name_end + 21
        if object_end > len(tree):
            raise OSError("Git tree contains a truncated entry object ID")
        mode = tree[position:mode_end]
        name = tree[mode_end + 1 : name_end]
        if mode not in _GIT_TREE_MODES or b"/" in name:
            raise OSError("Git tree contains a noncanonical entry")
        if name == expected_name:
            if match is not None:
                raise OSError("Git tree contains duplicate path entries")
            match = (mode, tree[name_end + 1 : object_end].hex())
        position = object_end
    if match is None:
        raise OSError("Git repository path is absent from the immutable commit")
    return match


def _git_stdout_bounded(
    git_executable: str,
    project_root: Path,
    *args: str,
    max_bytes: int,
    label: str,
) -> bytes:
    """Run one hardened Git read without permitting unbounded pipe capture."""
    try:
        process = subprocess.Popen(
            _hardened_git_command(git_executable, project_root, *args),
            cwd=project_root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError as exc:
        raise OSError(f"{label} could not be read") from exc
    stdout = process.stdout
    if stdout is None:  # pragma: no cover - PIPE guarantees this branch is unreachable
        _terminate_git_process(process)
        raise OSError(f"{label} pipe is unavailable")

    output: list[bytes] = []
    read_errors: list[Exception] = []

    def read_stdout() -> None:
        payload = bytearray()
        try:
            while len(payload) <= max_bytes:
                remaining = max_bytes + 1 - len(payload)
                chunk = stdout.read(min(_GIT_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    break
                payload.extend(chunk)
            output.append(bytes(payload))
        except Exception as exc:  # pragma: no cover - platform pipe failures are nondeterministic
            read_errors.append(exc)

    deadline = time.monotonic() + _GIT_TIMEOUT_SECONDS
    reader = threading.Thread(target=read_stdout, name="agent-assure-git-reader", daemon=True)
    reader.start()
    reader.join(timeout=_GIT_TIMEOUT_SECONDS)
    if reader.is_alive():
        _terminate_git_process(process)
        reader.join(timeout=1.0)
        # Closing a buffered pipe while another thread owns its read lock can
        # itself block indefinitely. A killed Git process normally closes the
        # writer and releases the reader; if an unexpected descendant retained
        # the handle, leave the daemon reader isolated instead of defeating the
        # caller's deadline while trying to close it synchronously.
        if not reader.is_alive():
            stdout.close()
        raise OSError(f"{label} timed out")
    if read_errors:
        _terminate_git_process(process)
        stdout.close()
        raise OSError(f"{label} could not be read") from read_errors[0]
    if not output:
        _terminate_git_process(process)
        stdout.close()
        raise OSError(f"{label} produced no readable pipe result")
    payload = output[0]
    if len(payload) > max_bytes:
        _terminate_git_process(process)
        stdout.close()
        raise OSError(f"{label} exceeded its bounded output size")
    try:
        remaining_seconds = max(0.001, deadline - time.monotonic())
        returncode = process.wait(timeout=remaining_seconds)
    except subprocess.TimeoutExpired as exc:
        _terminate_git_process(process)
        raise OSError(f"{label} timed out") from exc
    finally:
        stdout.close()
    if returncode != 0:
        raise OSError(f"{label} could not be read")
    return payload


def _terminate_git_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1.0)
    except (OSError, subprocess.SubprocessError):
        pass


def _hardened_git_command(
    git_executable: str,
    project_root: Path,
    *args: str,
) -> list[str]:
    command = [git_executable, "--no-optional-locks"]
    if _IS_WINDOWS:
        # Keep long-path support process-local. Persisting it in repository or
        # user configuration would mutate caller state and widen this helper's
        # authority beyond its read-only provenance query.
        command.extend(("-c", "core.longpaths=true"))
    command.extend(
        (
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            f"safe.directory={project_root.resolve()}",
            *args,
        )
    )
    return command


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
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _resolve_git_executable() -> str | None:
    executable_names: tuple[str, ...] = ("git",)
    if _IS_WINDOWS:
        # Batch shims are interpreted by cmd.exe even when subprocess is invoked
        # without shell=True. Provenance reads include an absolute repository path
        # in Git's safe.directory argument, so accept only the native executable on
        # Windows and avoid command-shell metacharacter interpretation entirely.
        executable_names = ("git.exe",)
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
