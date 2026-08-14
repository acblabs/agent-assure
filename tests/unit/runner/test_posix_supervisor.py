from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import cast

import pytest

from agent_assure.runner import _posix_supervisor


def test_containment_failure_never_spawns_untrusted_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_read_fd, status_write_fd = os.pipe()
    spawned: list[tuple[str, ...]] = []
    monkeypatch.setattr(_posix_supervisor, "_TERMINATION_SIGNAL", None)
    monkeypatch.setattr(
        _posix_supervisor,
        "_establish_linux_containment",
        lambda: False,
    )
    monkeypatch.setattr(
        _posix_supervisor,
        "_spawn_child",
        lambda argv: spawned.append(argv),
    )

    exit_code = _posix_supervisor._supervise(("untrusted-command",), status_write_fd)
    status = os.read(status_read_fd, 64)
    os.close(status_read_fd)

    assert exit_code == _posix_supervisor.CONTAINMENT_UNAVAILABLE_EXIT_CODE
    assert status == b"ERROR:containment\n"
    assert spawned == []


def test_supervisor_cleans_descendants_before_propagating_child_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeChild:
        def poll(self) -> int:
            return 7

    status_read_fd, status_write_fd = os.pipe()
    events: list[str] = []
    monkeypatch.setattr(_posix_supervisor, "_TERMINATION_SIGNAL", None)
    monkeypatch.setattr(
        _posix_supervisor,
        "_establish_linux_containment",
        lambda: True,
    )
    monkeypatch.setattr(
        _posix_supervisor,
        "_spawn_child",
        lambda argv: cast("object", FakeChild()),
    )
    monkeypatch.setattr(
        _posix_supervisor,
        "_cleanup_all_children",
        lambda: events.append("cleanup"),
    )

    exit_code = _posix_supervisor._supervise(("untrusted-command",), status_write_fd)
    status = os.read(status_read_fd, 64)
    os.close(status_read_fd)

    assert status == b"READY\n"
    assert events == ["cleanup"]
    assert exit_code == 7


def test_supervisor_repeats_kill_and_reap_until_no_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots = iter(((11, 12), (13,), ()))
    reap_states = iter((False, False, True))
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        _posix_supervisor,
        "_descendant_pids",
        lambda root_pid: next(snapshots),
    )
    monkeypatch.setattr(
        _posix_supervisor,
        "_kill_descendant",
        lambda pid, root_pid: killed.append((pid, root_pid)),
    )
    monkeypatch.setattr(
        _posix_supervisor,
        "_reap_available_children",
        lambda: next(reap_states),
    )
    monkeypatch.setattr(_posix_supervisor.time, "sleep", lambda seconds: None)

    _posix_supervisor._cleanup_all_children()

    assert [pid for pid, _ in killed] == [12, 11, 13]
    assert all(root_pid == os.getpid() for _, root_pid in killed)


def test_bound_direct_executable_uses_descriptor_without_changing_argv_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "adapter"
    executable.write_bytes(b"executable")
    with executable.open("rb") as handle:
        descriptor = handle.fileno()
        monkeypatch.setattr(_posix_supervisor.os.path, "isfile", lambda path: True)

        argv, inherited, executable_path = _posix_supervisor._bound_child_command(
            (
                f"--agent-assure-script-binding={descriptor}:0",
                "--",
                str(executable),
                "argument",
            )
        )

    assert argv == (str(executable), "argument")
    assert inherited == (descriptor,)
    assert executable_path == f"/proc/self/fd/{descriptor}"


def test_bound_current_python_script_preserves_main_script_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "adapter.py"
    script.write_text("print(__file__)", encoding="utf-8")
    with script.open("rb") as handle:
        descriptor = handle.fileno()
        monkeypatch.setattr(_posix_supervisor.os.path, "isfile", lambda path: True)
        monkeypatch.setattr(_posix_supervisor, "_same_executable", lambda left, right: True)

        argv, inherited, executable_path = _posix_supervisor._bound_child_command(
            (
                f"--agent-assure-script-binding={descriptor}:1",
                "--",
                sys.executable,
                str(script),
                "argument",
            )
        )

    assert argv[:2] == (sys.executable, "-c")
    assert argv[3] == str(script)
    assert argv[4] == f"/proc/self/fd/{descriptor}"
    assert argv[5:] == ("argument",)
    assert "__file__" in argv[2]
    assert inherited == (descriptor,)
    assert executable_path is None


def test_supervisor_cwd_binding_parses_pinned_directory_descriptor() -> None:
    descriptor, command = _posix_supervisor._supervisor_cwd_binding(
        (
            "--agent-assure-cwd-fd=17",
            "--agent-assure-no-script-binding",
            "--",
            "external-command",
        )
    )

    assert descriptor == 17
    assert command == (
        "--agent-assure-no-script-binding",
        "--",
        "external-command",
    )
