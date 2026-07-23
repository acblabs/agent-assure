from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

from agent_assure.artifact_io import write_bytes_atomic, write_text_atomic
from agent_assure.io_limits import loads_json_bounded, read_text_bounded

DEMO_MARKER_FILENAME = ".agent-assure-demo-owned.json"
MAX_DEMO_MARKER_BYTES = 1024
DEMO_COMMAND_TIMEOUT_SECONDS = 30
PACKAGE_IMPORT_ROOT = Path(__file__).resolve().parents[2]
_NETWORK_GUARD_DIRNAME = ".runtime"
_DEMO_ENV_ALLOWLIST = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "WINDIR",
    }
)
_NETWORK_GUARD_SOURCE = """
from __future__ import annotations

import socket


class AgentAssureDemoNetworkDisabled(RuntimeError):
    pass


def _blocked(*args: object, **kwargs: object) -> None:
    raise AgentAssureDemoNetworkDisabled(
        "network access is disabled for agent-assure demo subprocesses"
    )


socket.create_connection = _blocked
socket.getaddrinfo = _blocked
_OriginalSocket = socket.socket


class _BlockedSocket(_OriginalSocket):
    def connect(self, address: object) -> None:
        _blocked(address)

    def connect_ex(self, address: object) -> int:
        _blocked(address)
        return 1


socket.socket = _BlockedSocket
""".lstrip()


class DemoError(RuntimeError):
    """Raised when a demo cannot prove its expected evidence facts."""


@dataclass(frozen=True)
class ExpectedCommandResult:
    name: str
    expected_exit_codes: set[int]
    actual_exit_code: int
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    command: tuple[str, ...] = ()

    @property
    def matched(self) -> bool:
        return self.actual_exit_code in self.expected_exit_codes

    def model_dump(self, *, root: Path) -> dict[str, object]:
        return {
            "name": self.name,
            "expected_exit_codes": sorted(self.expected_exit_codes),
            "actual_exit_code": self.actual_exit_code,
            "matched": self.matched,
            "stdout_path": _relative_path(self.stdout_path, root) if self.stdout_path else None,
            "stderr_path": _relative_path(self.stderr_path, root) if self.stderr_path else None,
            "command": list(_display_command(self.command, root=root)),
        }


def prepare_output_dir(out_dir: Path, *, clean: bool) -> Path:
    resolved = out_dir.resolve()
    if resolved.exists():
        if not resolved.is_dir():
            raise DemoError(f"demo output path exists and is not a directory: {resolved}")
        _assert_safe_output_dir(resolved)
        if clean:
            _clean_owned_output_dir(resolved)
        elif not _has_ownership_marker(resolved) and any(resolved.iterdir()):
            raise DemoError(
                f"demo output path already exists and is not empty or demo-owned: {resolved}"
            )
    resolved.mkdir(parents=True, exist_ok=True)
    _write_ownership_marker(resolved)
    return resolved


def copy_example_resource(example_name: str, destination: Path, *, owner_root: Path) -> Path:
    resource = files("agent_assure.examples").joinpath(example_name)
    if not resource.is_dir():
        raise DemoError(f"bundled example resource is missing: {example_name}")
    _assert_child_path(destination.resolve(), owner_root.resolve())
    if destination.exists():
        shutil.rmtree(destination)
    _copy_resource_tree(resource, destination)
    return destination


def run_cli_command(
    *,
    name: str,
    args: list[str],
    out_dir: Path,
    expected_exit_codes: set[int],
    cwd: Path,
    timeout_seconds: int = DEMO_COMMAND_TIMEOUT_SECONDS,
) -> ExpectedCommandResult:
    logs_dir = out_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = logs_dir / f"{name}.stdout.txt"
    stderr_path = logs_dir / f"{name}.stderr.txt"
    command = (sys.executable, "-m", "agent_assure.cli.main", *args)
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env = demo_subprocess_env(out_dir, env=env)
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        write_text_atomic(stdout_path, _timeout_output(exc.stdout))
        write_text_atomic(stderr_path, _timeout_output(exc.stderr))
        raise DemoError(
            f"{name} exceeded {timeout_seconds} second timeout. "
            f"See {stdout_path} and {stderr_path}."
        ) from exc
    write_text_atomic(stdout_path, result.stdout)
    write_text_atomic(stderr_path, result.stderr)
    command_result = ExpectedCommandResult(
        name=name,
        expected_exit_codes=expected_exit_codes,
        actual_exit_code=result.returncode,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        command=command,
    )
    if not command_result.matched:
        raise DemoError(
            f"{name} exited {result.returncode}; expected one of "
            f"{sorted(expected_exit_codes)}. See {stdout_path} and {stderr_path}."
        )
    return command_result


def demo_subprocess_env(out_dir: Path, *, env: dict[str, str] | None = None) -> dict[str, str]:
    source_env = os.environ if env is None else env
    resolved_env = {
        key: value for key, value in source_env.items() if key.upper() in _DEMO_ENV_ALLOWLIST
    }
    guard_dir = _ensure_network_guard(out_dir)
    pythonpath_parts = [str(guard_dir), str(PACKAGE_IMPORT_ROOT)]
    resolved_env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)
    resolved_env["PYTHONDONTWRITEBYTECODE"] = "1"
    resolved_env["PYTHONIOENCODING"] = "utf-8"
    resolved_env["PYTHONNOUSERSITE"] = "1"
    resolved_env["PYTHONSAFEPATH"] = "1"
    resolved_env["AGENT_ASSURE_DEMO_NETWORK_DISABLED"] = "1"
    return resolved_env


def write_json(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def artifact_path(path: Path, *, root: Path) -> str:
    return _relative_path(path, root)


def _copy_resource_tree(resource: Traversable, destination: Path) -> None:
    if resource.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        for child in resource.iterdir():
            if child.name == "__pycache__" or child.name.endswith(".pyc"):
                continue
            _copy_resource_tree(child, destination / child.name)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_bytes_atomic(destination, resource.read_bytes())


def _assert_safe_output_dir(path: Path) -> None:
    anchor = Path(path.anchor).resolve()
    forbidden = {anchor, Path.cwd().resolve(), Path.home().resolve()}
    if path in forbidden:
        raise DemoError(f"refusing to use unsafe demo output path: {path}")
    if _contains_path(path, Path.cwd().resolve()) or _contains_path(path, Path.home().resolve()):
        raise DemoError(f"refusing to use unsafe demo output path: {path}")
    if len(path.parts) <= len(anchor.parts):
        raise DemoError(f"refusing to use unsafe demo output path: {path}")


def _clean_owned_output_dir(path: Path) -> None:
    if any(path.iterdir()) and not _has_ownership_marker(path):
        raise DemoError(
            "refusing to clean existing directory without agent-assure demo ownership marker: "
            f"{path}"
        )
    for child in path.iterdir():
        _assert_child_path(child.resolve(), path.resolve())
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    _write_ownership_marker(path)


def _has_ownership_marker(path: Path) -> bool:
    marker = path / DEMO_MARKER_FILENAME
    try:
        if not marker.is_file():
            return False
        text = read_text_bounded(
            marker,
            max_bytes=MAX_DEMO_MARKER_BYTES,
            label="demo ownership marker",
        )
        payload = loads_json_bounded(text, label="demo ownership marker JSON")
    except (OSError, ValueError):
        return False
    return isinstance(payload, dict) and payload == {"owner": "agent-assure-demo"}


def _write_ownership_marker(path: Path) -> None:
    marker = path / DEMO_MARKER_FILENAME
    write_text_atomic(
        marker,
        json.dumps({"owner": "agent-assure-demo"}, sort_keys=True) + "\n",
    )


def _ensure_network_guard(out_dir: Path) -> Path:
    guard_dir = out_dir / _NETWORK_GUARD_DIRNAME
    guard_dir.mkdir(parents=True, exist_ok=True)
    write_text_atomic(guard_dir / "sitecustomize.py", _NETWORK_GUARD_SOURCE)
    return guard_dir


def _relative_path(path: Path | None, root: Path) -> str:
    if path is None:
        return ""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _display_command(command: tuple[str, ...], *, root: Path) -> tuple[str, ...]:
    if not command:
        return ()
    return ("<python>", *(_display_command_arg(arg, root=root) for arg in command[1:]))


def _display_command_arg(arg: str, *, root: Path) -> str:
    if not _looks_like_path(arg):
        return arg
    path = Path(arg)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"<absolute-path:{path.name}>"


def _looks_like_path(value: str) -> bool:
    path = Path(value)
    return path.is_absolute() or "\\" in value or "/" in value


def _assert_child_path(path: Path, parent: Path) -> None:
    try:
        path.relative_to(parent)
    except ValueError as exc:
        raise DemoError(f"refusing to write outside demo output path: {path}") from exc


def _contains_path(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return child != parent


def _timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
