from __future__ import annotations

import ctypes
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import FrameType
from typing import Any, cast

CONTAINMENT_UNAVAILABLE_EXIT_CODE = 125
CHILD_SPAWN_FAILED_EXIT_CODE = 126
INTERNAL_SUPERVISOR_EXIT_CODE = 127
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_CLEANUP_POLL_SECONDS = 0.005
_SIGKILL = cast(int, getattr(signal, "SIGKILL", 9))
_TERMINATION_SIGNALS = tuple(
    cast(int, getattr(signal, name))
    for name in ("SIGTERM", "SIGINT", "SIGHUP")
    if hasattr(signal, name)
)
_WAIT_NOHANG = cast(int, getattr(os, "WNOHANG", 1))
_TERMINATION_SIGNAL: int | None = None
_PYTHON_DESCRIPTOR_BOOTSTRAP = """
import os
import sys

_original_path = sys.argv[1]
_descriptor_path = sys.argv[2]
sys.argv = [_original_path, *sys.argv[3:]]
sys.path[0] = os.path.dirname(_original_path)
with open(_descriptor_path, "rb", buffering=0) as _script_file:
    _source = _script_file.read()
_code = compile(_source, _original_path, "exec", dont_inherit=True)
_globals = {
    "__name__": "__main__",
    "__file__": _original_path,
    "__cached__": None,
    "__loader__": None,
    "__package__": None,
    "__spec__": None,
    "__annotations__": {},
}
exec(_code, _globals, _globals)
""".strip()


def main(argv: tuple[str, ...] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 2:
        return INTERNAL_SUPERVISOR_EXIT_CODE
    try:
        status_fd = int(arguments[0])
    except ValueError:
        return INTERNAL_SUPERVISOR_EXIT_CODE
    if status_fd <= 2:
        return INTERNAL_SUPERVISOR_EXIT_CODE
    global _TERMINATION_SIGNAL
    _TERMINATION_SIGNAL = None
    _install_signal_handlers()
    return _supervise(arguments[1:], status_fd)


def _supervise(argv: tuple[str, ...], status_fd: int) -> int:
    child: subprocess.Popen[bytes] | None = None
    return_code: int | None = None
    status_open = True
    try:
        if not _establish_linux_containment():
            _write_status(status_fd, b"ERROR:containment\n")
            return CONTAINMENT_UNAVAILABLE_EXIT_CODE
        if _TERMINATION_SIGNAL is not None:
            return 128 + _TERMINATION_SIGNAL
        try:
            child = _spawn_child(argv)
        except OSError:
            _write_status(status_fd, b"ERROR:spawn\n")
            return CHILD_SPAWN_FAILED_EXIT_CODE
        if not _write_status(status_fd, b"READY\n"):
            return INTERNAL_SUPERVISOR_EXIT_CODE
        _close_fd(status_fd)
        status_open = False
        return_code = _wait_for_child_or_termination(child)
    finally:
        if status_open:
            _close_fd(status_fd)
        if child is not None:
            _cleanup_all_children()
            child.poll()
    termination_signal = _TERMINATION_SIGNAL
    if termination_signal is not None:
        return 128 + termination_signal
    if return_code is None:
        return INTERNAL_SUPERVISOR_EXIT_CODE
    return return_code if return_code >= 0 else 128 - return_code


def _establish_linux_containment() -> bool:
    if (
        sys.platform != "linux"
        or not _proc_children_interface_available()
        or not _pidfd_interface_available()
    ):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = cast(Any, libc.prctl)
        prctl.argtypes = (
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        )
        prctl.restype = ctypes.c_int
        if prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            return False
        state = ctypes.c_int(0)
        if prctl(_PR_GET_CHILD_SUBREAPER, ctypes.addressof(state), 0, 0, 0) != 0:
            return False
        return state.value == 1
    except (AttributeError, OSError):
        return False


def _proc_children_interface_available() -> bool:
    children = Path("/proc/self/task") / str(os.getpid()) / "children"
    try:
        children.read_text(encoding="ascii")
    except OSError:
        return False
    return True


def _pidfd_interface_available() -> bool:
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if not callable(pidfd_open) or not callable(pidfd_send_signal):
        return False
    try:
        pidfd = cast(int, pidfd_open(os.getpid(), 0))
    except OSError:
        return False
    try:
        pidfd_send_signal(pidfd, 0, None, 0)
    except OSError:
        return False
    finally:
        _close_fd(pidfd)
    return True


def _spawn_child(argv: tuple[str, ...]) -> subprocess.Popen[bytes]:
    cwd_descriptor, command = _supervisor_cwd_binding(argv)
    if cwd_descriptor is not None:
        metadata = os.fstat(cwd_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("external script cwd descriptor was not a directory")
        cast(Any, vars(os)["fchdir"])(cwd_descriptor)
    child_argv, inherited_descriptors, executable = _bound_child_command(command)
    return subprocess.Popen(
        list(child_argv),
        executable=executable,
        close_fds=True,
        pass_fds=inherited_descriptors,
        restore_signals=True,
    )


def _supervisor_cwd_binding(argv: tuple[str, ...]) -> tuple[int | None, tuple[str, ...]]:
    prefix = "--agent-assure-cwd-fd="
    if not argv or not argv[0].startswith(prefix):
        return None, argv
    raw_descriptor = argv[0][len(prefix) :]
    command = argv[1:]
    if not command:
        raise OSError("external script cwd descriptor binding protocol was invalid")
    if raw_descriptor == "none":
        return None, command
    try:
        descriptor = int(raw_descriptor)
    except ValueError as exc:
        raise OSError("external script cwd descriptor binding protocol was invalid") from exc
    if descriptor <= 2:
        raise OSError("external script cwd descriptor binding protocol was invalid")
    return descriptor, command


def _bound_child_command(
    argv: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[int, ...], str | None]:
    if len(argv) >= 2 and argv[:2] == ("--agent-assure-no-script-binding", "--"):
        command = argv[2:]
        if not command:
            raise OSError("external script command was empty")
        return command, (), None
    if len(argv) < 3 or not argv[0].startswith("--agent-assure-script-binding="):
        if not argv:
            raise OSError("external script command was empty")
        return argv, (), None
    if argv[1] != "--":
        raise OSError("external script descriptor binding protocol was invalid")
    binding = argv[0].split("=", 1)[1].split(":", 1)
    if len(binding) != 2:
        raise OSError("external script descriptor binding protocol was invalid")
    try:
        descriptor = int(binding[0])
        script_index = int(binding[1])
    except ValueError as exc:
        raise OSError("external script descriptor binding protocol was invalid") from exc
    command = argv[2:]
    if descriptor <= 2 or script_index < 0 or script_index >= len(command):
        raise OSError("external script descriptor binding protocol was invalid")
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or not os.path.isfile(f"/proc/self/fd/{descriptor}"):
        raise OSError("external script descriptor was not a regular file")
    descriptor_path = f"/proc/self/fd/{descriptor}"
    if script_index == 0:
        return command, (descriptor,), descriptor_path
    if (
        script_index == 1
        and Path(command[script_index]).suffix.lower() == ".py"
        and _same_executable(command[0], sys.executable)
    ):
        python_command = (
            command[0],
            "-c",
            _PYTHON_DESCRIPTOR_BOOTSTRAP,
            command[script_index],
            descriptor_path,
            *command[script_index + 1 :],
        )
        return python_command, (descriptor,), None
    bound_command = list(command)
    bound_command[script_index] = descriptor_path
    return tuple(bound_command), (descriptor,), None


def _same_executable(left: str, right: str) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return os.path.abspath(left) == os.path.abspath(right)


def _wait_for_child_or_termination(child: subprocess.Popen[bytes]) -> int | None:
    while _TERMINATION_SIGNAL is None:
        return_code = child.poll()
        if return_code is not None:
            return return_code
        time.sleep(_CLEANUP_POLL_SECONDS)
    return child.poll()


def _cleanup_all_children() -> None:
    supervisor_pid = os.getpid()
    while True:
        for pid in reversed(_descendant_pids(supervisor_pid)):
            _kill_descendant(pid, supervisor_pid)
        if _reap_available_children():
            return
        time.sleep(_CLEANUP_POLL_SECONDS)


def _descendant_pids(root_pid: int) -> tuple[int, ...]:
    pending = list(_direct_child_pids(root_pid))
    descendants: list[int] = []
    seen: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        descendants.append(pid)
        pending.extend(_direct_child_pids(pid))
    return tuple(descendants)


def _direct_child_pids(pid: int) -> tuple[int, ...]:
    task_dir = Path("/proc") / str(pid) / "task"
    try:
        tasks = tuple(task_dir.iterdir())
    except OSError:
        return ()
    children: set[int] = set()
    for task in tasks:
        try:
            values = (task / "children").read_text(encoding="ascii").split()
        except OSError:
            continue
        for value in values:
            try:
                children.add(int(value))
            except ValueError:
                continue
    return tuple(children)


def _kill_descendant(pid: int, supervisor_pid: int) -> None:
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if callable(pidfd_open) and callable(pidfd_send_signal):
        try:
            pidfd = cast(int, pidfd_open(pid, 0))
        except OSError:
            return
        try:
            if _is_descendant(pid, supervisor_pid):
                pidfd_send_signal(pidfd, _SIGKILL, None, 0)
        except OSError:
            pass
        finally:
            _close_fd(pidfd)
        return
    if not _is_descendant(pid, supervisor_pid):
        return
    try:
        os.kill(pid, _SIGKILL)
    except OSError:
        pass


def _is_descendant(pid: int, supervisor_pid: int) -> bool:
    current = pid
    seen: set[int] = set()
    while current > 1 and current not in seen:
        seen.add(current)
        parent = _parent_pid(current)
        if parent is None:
            return False
        if parent == supervisor_pid:
            return True
        current = parent
    return False


def _parent_pid(pid: int) -> int | None:
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
        suffix = stat[stat.rfind(")") + 2 :].split()
        return int(suffix[1])
    except (IndexError, OSError, ValueError):
        return None


def _reap_available_children() -> bool:
    while True:
        try:
            pid, _ = os.waitpid(-1, _WAIT_NOHANG)
        except ChildProcessError:
            return True
        except InterruptedError:
            continue
        except OSError:
            return False
        if pid == 0:
            return False


def _write_status(fd: int, value: bytes) -> bool:
    try:
        written = os.write(fd, value)
    except OSError:
        return False
    return written == len(value)


def _close_fd(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _install_signal_handlers() -> None:
    for signum in _TERMINATION_SIGNALS:
        signal.signal(signum, _request_termination)


def _request_termination(signum: int, frame: FrameType | None) -> None:
    del frame
    global _TERMINATION_SIGNAL
    if _TERMINATION_SIGNAL is None:
        _TERMINATION_SIGNAL = signum


if __name__ == "__main__":
    raise SystemExit(main())
