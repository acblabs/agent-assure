from __future__ import annotations

import ctypes
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from agent_assure.live.adapters import (
    ExternalScriptAdapter,
    LiveProviderRequest,
    TrustedLiveExecution,
)
from agent_assure.live.config import LiveAdapterConfig
from agent_assure.runner import subprocess_harness
from agent_assure.runner.subprocess_harness import (
    ExternalScriptError,
    ExternalScriptInvocation,
    run_external_script,
)
from agent_assure.telemetry.context import trace_context_for_seed


def test_external_script_adapter_invokes_script_with_trace_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHOULD_NOT_LEAK", "secret")
    script = tmp_path / "adapter.py"
    script.write_text(
        """
import json
import os
import sys

payload = json.loads(sys.stdin.read())
assert os.environ["TRACEPARENT"] == payload["trace_context"]["traceparent"]
assert os.environ["CUSTOM_FLAG"] == "enabled"
assert "SHOULD_NOT_LEAK" not in os.environ
print(json.dumps({
    "record": {
        "recommendation": "approve",
        "outcome": "approve",
        "output_summary": "subprocess approved",
        "tools": [],
        "evidence_refs": [],
        "evidence_items": [],
        "claims": [],
        "claim_evidence_links": [],
        "policy_results": []
    },
    "provider": "local-script",
    "model": "script-model",
    "resolved_model": "script-model@local",
    "prompt_tokens": 3,
    "completion_tokens": 4,
    "total_tokens": 7,
    "estimated_cost_usd": "0.000001"
}))
""".lstrip(),
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
            script_env=({"name": "CUSTOM_FLAG", "value": "enabled"},),
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )
    trace_context = trace_context_for_seed("obs-001")

    response = adapter.complete(
        LiveProviderRequest(
            run_id="run-001",
            observation_id="obs-001",
            case_id="case-001",
            repetition_index=0,
            prompt="summarize the request",
            provider="local-script",
            model="script-model",
            traceparent=trace_context.traceparent,
        )
    )

    content = json.loads(response.content)
    assert content["recommendation"] == "approve"
    assert response.total_tokens == 7
    assert response.resolved_model == "script-model@local"


def test_external_script_failure_creates_redacted_emergency_record(tmp_path: Path) -> None:
    script = tmp_path / "bad_adapter.py"
    script.write_text(
        """
import sys

print("ssn: 123-45-6789", file=sys.stderr)
raise SystemExit(7)
""".lstrip(),
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )
    trace_context = trace_context_for_seed("obs-002")

    with pytest.raises(ExternalScriptError) as raised:
        adapter.complete(
            LiveProviderRequest(
                run_id="run-002",
                observation_id="obs-002",
                case_id="case-002",
                repetition_index=0,
                prompt="summarize the request",
                provider="local-script",
                model="script-model",
                traceparent=trace_context.traceparent,
            )
        )

    emergency = raised.value.emergency_record
    dumped = json.dumps(emergency.model_dump(mode="json"))
    assert emergency.failure_kind == "nonzero_exit"
    assert emergency.exit_code == 7
    assert "123-45-6789" not in dumped
    assert "[REDACTED]" in dumped
    assert emergency.traceparent == trace_context.traceparent


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        pytest.param(
            f"{'x' * 483} Bearer {'T' * 40}",
            f"{'x' * 483} [REDACTED]",
            id="bearer-token",
        ),
        pytest.param(
            f"{'x' * 290} eyJ{'A' * 100}.{'B' * 100}.{'C' * 100}",
            f"{'x' * 290} [REDACTED]",
            id="json-web-token",
        ),
    ],
)
def test_emergency_summary_redacts_secret_crossing_truncation_boundary(
    stderr: str,
    expected: str,
) -> None:
    summary = subprocess_harness._summary(stderr)

    assert summary == expected
    assert len(summary) <= 500


def test_emergency_summary_remains_bounded_after_redaction() -> None:
    assert subprocess_harness._summary("x" * 600) == "x" * 500


@pytest.mark.parametrize(
    "stderr",
    (
        ("x" * 493) + " " + "a@b.co",
        ("x" * 499) + "Bearer " + ("T" * 40),
        ("x" * 499) + subprocess_harness.REDACTION_MASK_CHARACTER,
    ),
)
def test_emergency_summary_remains_bounded_when_mask_expands(stderr: str) -> None:
    summary = subprocess_harness._summary(stderr)

    assert summary is not None
    assert len(summary) <= 500


def test_emergency_summary_drops_short_truncated_source() -> None:
    clipped = "diagnostic" + (" " * 80) + "Bearer SHORT"

    assert subprocess_harness._summary(clipped, source_truncated=True) is None


def test_emergency_summary_redacts_sensitive_value_split_across_lines() -> None:
    summary = subprocess_harness._summary("card 4111\r\n1111\r\n1111\r\n1111")

    assert summary == "card [REDACTED]"


def test_external_script_path_cannot_escape_config_dir(tmp_path: Path) -> None:
    script = tmp_path / "adapter.py"
    script.write_text("print('{}')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="script_path"):
        ExternalScriptAdapter(
            LiveAdapterConfig(
                adapter_id="external-script",
                provider="local-script",
                model="script-model",
                script_path=str(script.resolve()),
                script_executable=sys.executable,
            ),
            base_dir=tmp_path,
            trust=TrustedLiveExecution(allow_external_script=True),
        )


def test_external_script_adapter_requires_explicit_trust(tmp_path: Path) -> None:
    script = tmp_path / "adapter.py"
    script.write_text("print('{}')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="allow_external_script"):
        ExternalScriptAdapter(
            LiveAdapterConfig(
                adapter_id="external-script",
                provider="local-script",
                model="script-model",
                script_path=script.name,
                script_executable=sys.executable,
            ),
            base_dir=tmp_path,
        )


def test_external_script_stdout_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess_harness, "MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES", 32)
    script = tmp_path / "noisy_adapter.py"
    script.write_text(
        """
print("x" * 128)
""".lstrip(),
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )

    with pytest.raises(ExternalScriptError, match="output exceeded byte limit") as raised:
        adapter.complete(
            LiveProviderRequest(
                run_id="run-oversized",
                observation_id="obs-oversized",
                case_id="case-oversized",
                repetition_index=0,
                prompt="summarize the request",
                provider="local-script",
                model="script-model",
            )
        )

    emergency = raised.value.emergency_record
    assert emergency.failure_kind == "invalid_output"
    assert emergency.stdout_bytes > 32


def test_external_script_stderr_summary_does_not_pull_clipped_secret_across_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limit = 128
    monkeypatch.setattr(subprocess_harness, "MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES", limit)
    script = tmp_path / "boundary_adapter.py"
    script.write_text(
        "import sys\n\n"
        f"sys.stderr.write('diagnostic' + (' ' * {limit - 24}) + "
        "'Bearer ' + ('T' * 40))\n",
        encoding="utf-8",
    )
    adapter = ExternalScriptAdapter(
        LiveAdapterConfig(
            adapter_id="external-script",
            provider="local-script",
            model="script-model",
            script_path=script.name,
            script_executable=sys.executable,
        ),
        base_dir=tmp_path,
        trust=TrustedLiveExecution(allow_external_script=True),
    )

    with pytest.raises(ExternalScriptError, match="output exceeded byte limit") as raised:
        adapter.complete(
            LiveProviderRequest(
                run_id="run-boundary",
                observation_id="obs-boundary",
                case_id="case-boundary",
                repetition_index=0,
                prompt="summarize the request",
                provider="local-script",
                model="script-model",
            )
        )

    emergency = raised.value.emergency_record
    assert emergency.stderr_bytes > limit
    assert emergency.stderr_summary is None


def test_external_script_timeout_terminates_descendant_process_tree(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived.txt"
    script = tmp_path / "spawn_descendant.py"
    child_code = (
        "import pathlib,time; "
        "time.sleep(2); "
        f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
    )
    script.write_text(
        "import subprocess,sys,time\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    invocation = ExternalScriptInvocation(
        argv=(sys.executable, str(script)),
        cwd=tmp_path,
        timeout_seconds=1,
        request_payload={},
        observation_id="obs-tree-timeout",
        run_id="run-tree-timeout",
        case_id="case-tree-timeout",
        adapter_id="external-script",
    )
    started = time.monotonic()

    with pytest.raises(ExternalScriptError, match="timed out") as raised:
        run_external_script(invocation)

    assert time.monotonic() - started < 4
    assert raised.value.emergency_record.stdout_bytes > 0
    time.sleep(2)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="native Windows job-object containment")
def test_windows_external_script_success_kills_descendant_when_job_closes(
    tmp_path: Path,
) -> None:
    ready = tmp_path / "normal-completion-descendant-ready.txt"
    marker = tmp_path / "normal-completion-descendant-survived.txt"
    script = tmp_path / "spawn_normal_completion_descendant.py"
    child_code = (
        "import pathlib,time; "
        f"pathlib.Path({str(ready)!r}).write_text('ready', encoding='utf-8'); "
        "time.sleep(1.5); "
        f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
    )
    script.write_text(
        "import pathlib,subprocess,sys,time\n"
        f"ready = pathlib.Path({str(ready)!r})\n"
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "deadline = time.monotonic() + 2\n"
        "while not ready.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.01)\n"
        "raise SystemExit(0 if ready.exists() else 2)\n",
        encoding="utf-8",
    )
    invocation = ExternalScriptInvocation(
        argv=(sys.executable, str(script)),
        cwd=tmp_path,
        timeout_seconds=5,
        request_payload={},
        observation_id="obs-windows-normal-completion",
        run_id="run-windows-normal-completion",
        case_id="case-windows-normal-completion",
        adapter_id="external-script",
    )

    run_external_script(invocation)

    assert ready.read_text(encoding="utf-8") == "ready"
    time.sleep(1.75)
    assert not marker.exists()


def test_external_script_fails_closed_when_tree_containment_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "wait.py"
    script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    invocation = ExternalScriptInvocation(
        argv=(sys.executable, str(script)),
        cwd=tmp_path,
        timeout_seconds=10,
        request_payload={},
        observation_id="obs-tree-setup",
        run_id="run-tree-setup",
        case_id="case-tree-setup",
        adapter_id="external-script",
    )
    terminated: list[int] = []
    terminate = subprocess_harness._terminate_process_tree

    monkeypatch.setattr(
        subprocess_harness,
        "_attach_windows_kill_on_close_job",
        lambda process: False,
    )

    def record_termination(process: object) -> None:
        terminated.append(process.pid)  # type: ignore[attr-defined]
        terminate(process)  # type: ignore[arg-type]

    monkeypatch.setattr(subprocess_harness, "_terminate_process_tree", record_termination)

    with pytest.raises(ExternalScriptError, match="could not be started") as raised:
        run_external_script(invocation)

    assert terminated
    assert raised.value.emergency_record.failure_kind == "spawn_failed"


def test_post_spawn_validation_failure_terminates_and_reaps_suspended_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 4242
        stdout = None
        stderr = None

    invocation = ExternalScriptInvocation(
        argv=("external-command",),
        cwd=tmp_path,
        timeout_seconds=10,
        request_payload={},
        observation_id="obs-validation-failure",
        run_id="run-validation-failure",
        case_id="case-validation-failure",
        adapter_id="external-script",
        cwd_device=1,
        cwd_inode=2,
    )
    validation_calls = 0
    terminated: list[object] = []
    waited: list[object] = []

    def fail_after_spawn(_invocation: ExternalScriptInvocation) -> None:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 2:
            raise OSError("cwd identity changed")

    monkeypatch.setattr(
        subprocess_harness.subprocess,
        "Popen",
        lambda *args, **kwargs: FakeProcess(),
    )
    monkeypatch.setattr(subprocess_harness, "_validate_bound_cwd", fail_after_spawn)
    monkeypatch.setattr(
        subprocess_harness,
        "_terminate_process_tree",
        lambda process: terminated.append(process),
    )
    monkeypatch.setattr(
        subprocess_harness,
        "_wait_for_terminated_process",
        lambda process: waited.append(process),
    )
    monkeypatch.setattr(subprocess_harness, "_release_process_tree", lambda process: None)
    monkeypatch.setattr(
        subprocess_harness,
        "_attach_windows_kill_on_close_job",
        lambda process: pytest.fail("validation failure reached job attachment"),
    )

    with pytest.raises(ExternalScriptError, match="could not be started"):
        run_external_script(invocation)

    assert validation_calls == 2
    assert len(terminated) == 1
    assert waited == terminated


def test_output_limit_uses_process_tree_termination(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        stdout = None
        stderr = None

    terminated: list[object] = []
    fake_process = FakeProcess()
    monkeypatch.setattr(subprocess_harness, "MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES", 4)
    monkeypatch.setattr(
        subprocess_harness,
        "_terminate_process_tree",
        lambda process: terminated.append(process),
    )
    capture = subprocess_harness._ProcessOutputCapture(fake_process)  # type: ignore[arg-type]

    capture.add("stdout", b"12345")

    assert terminated == [fake_process]


def test_output_capture_finalize_never_joins_reader_without_a_deadline() -> None:
    class FakeProcess:
        stdout = None
        stderr = None

    release_reader = threading.Event()
    reader = threading.Thread(target=release_reader.wait, daemon=True)
    capture = subprocess_harness._ProcessOutputCapture(FakeProcess())  # type: ignore[arg-type]
    capture._threads.append(reader)
    reader.start()
    started = time.monotonic()

    capture.finalize()

    assert time.monotonic() - started < 1
    assert reader.is_alive()
    release_reader.set()
    reader.join(timeout=1)


def test_windows_process_group_options_start_suspended(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess_harness.os, "name", "nt")
    monkeypatch.setattr(
        subprocess_harness.subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        0x00000200,
        raising=False,
    )
    monkeypatch.setattr(
        subprocess_harness.subprocess,
        "CREATE_SUSPENDED",
        0x00000004,
        raising=False,
    )

    options = subprocess_harness._process_group_options()

    assert options == {"creationflags": 0x00000204}


@pytest.mark.parametrize(
    ("prior_suspend_count", "expected"),
    ((1, True), (0, False), (2, False)),
)
def test_windows_suspended_process_requires_exact_primary_suspend_count(
    monkeypatch: pytest.MonkeyPatch,
    prior_suspend_count: int,
    expected: bool,
) -> None:
    events: list[str] = []

    class FakeKernel32:
        def CreateToolhelp32Snapshot(self, flags: int, process_id: int) -> int:
            assert flags == 0x00000004
            assert process_id == 0
            events.append("snapshot")
            return 41

        def Thread32First(self, snapshot: int, entry_pointer: object) -> int:
            assert snapshot == 41
            entry = ctypes.cast(
                entry_pointer,
                ctypes.POINTER(subprocess_harness._WindowsThreadEntry32),
            ).contents
            entry.th32ThreadID = 902
            entry.th32OwnerProcessID = 901
            events.append("first")
            return 1

        def Thread32Next(self, snapshot: int, entry_pointer: object) -> int:
            assert snapshot == 41
            assert entry_pointer is not None
            events.append("next")
            return 0

        def OpenThread(self, access: int, inherit: bool, thread_id: int) -> int:
            assert (access, inherit, thread_id) == (0x0002, False, 902)
            events.append("open")
            return 42

        def ResumeThread(self, thread: int) -> int:
            assert thread == 42
            events.append("resume")
            return prior_suspend_count

        def CloseHandle(self, handle: int) -> None:
            events.append(f"close-{handle}")

    class FakeProcess:
        pid = 901

    monkeypatch.setattr(subprocess_harness.os, "name", "nt")
    monkeypatch.setattr(subprocess_harness, "_windows_kernel32", lambda: FakeKernel32())

    resumed = subprocess_harness._resume_windows_suspended_process(FakeProcess())  # type: ignore[arg-type]

    assert resumed is expected
    assert events == [
        "snapshot",
        "first",
        "next",
        "close-41",
        "open",
        "resume",
        "close-42",
    ]


def test_external_script_fails_closed_when_suspended_process_cannot_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "never_resume.py"
    script.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    invocation = ExternalScriptInvocation(
        argv=(sys.executable, str(script)),
        cwd=tmp_path,
        timeout_seconds=10,
        request_payload={},
        observation_id="obs-resume-setup",
        run_id="run-resume-setup",
        case_id="case-resume-setup",
        adapter_id="external-script",
    )
    terminated: list[int] = []
    terminate = subprocess_harness._terminate_process_tree

    monkeypatch.setattr(
        subprocess_harness,
        "_attach_windows_kill_on_close_job",
        lambda process: True,
    )
    monkeypatch.setattr(
        subprocess_harness,
        "_resume_windows_suspended_process",
        lambda process: False,
    )

    def record_termination(process: object) -> None:
        terminated.append(process.pid)  # type: ignore[attr-defined]
        terminate(process)  # type: ignore[arg-type]

    monkeypatch.setattr(subprocess_harness, "_terminate_process_tree", record_termination)

    with pytest.raises(ExternalScriptError, match="could not be started") as raised:
        run_external_script(invocation)

    assert terminated
    assert raised.value.emergency_record.failure_kind == "spawn_failed"


def test_posix_tracker_retains_observed_descendant_after_reparenting() -> None:
    tracker = subprocess_harness._PosixDescendantTracker(100)
    tracker.observe(
        {
            100: (1, "root-start"),
            101: (100, "middle-start"),
            102: (101, "grandchild-start"),
        }
    )

    tracker.observe({102: (1, "grandchild-start")})

    assert tracker.descendants() == (
        subprocess_harness._PosixProcessIdentity(101, "middle-start"),
        subprocess_harness._PosixProcessIdentity(102, "grandchild-start"),
    )


def test_posix_tracker_does_not_kill_reused_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = subprocess_harness._PosixDescendantTracker(100)
    tracker.observe(
        {
            100: (1, "root-start"),
            101: (100, "old-child-start"),
            102: (101, "grandchild-start"),
        }
    )
    monkeypatch.setattr(
        subprocess_harness,
        "_posix_process_snapshot",
        lambda seed_pids: {
            100: (1, "root-start"),
            101: (1, "replacement-start"),
            102: (1, "grandchild-start"),
        },
    )
    killed: list[int] = []
    monkeypatch.setattr(subprocess_harness, "_kill_posix_pid", killed.append)
    monkeypatch.setattr(subprocess_harness, "_reap_posix_child", lambda pid: None)

    subprocess_harness._kill_tracked_posix_descendants(tracker)

    assert killed == [102]


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-tree behavior")
def test_external_script_success_terminates_observed_reparented_setsid_descendant(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "setsid-grandchild-survived.txt"
    grandchild_code = (
        "import pathlib,time; "
        "time.sleep(1); "
        f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
    )
    middle_code = (
        "import os,subprocess,sys,time; "
        "os.setsid(); "
        f"subprocess.Popen([sys.executable, '-c', {grandchild_code!r}]); "
        "time.sleep(0.25)"
    )
    script = tmp_path / "spawn_reparented_setsid_descendant.py"
    script.write_text(
        "import subprocess,sys,time\n"
        f"subprocess.Popen([sys.executable, '-c', {middle_code!r}])\n"
        "time.sleep(0.5)\n",
        encoding="utf-8",
    )
    invocation = ExternalScriptInvocation(
        argv=(sys.executable, str(script)),
        cwd=tmp_path,
        timeout_seconds=3,
        request_payload={},
        observation_id="obs-tree-success",
        run_id="run-tree-success",
        case_id="case-tree-success",
        adapter_id="external-script",
    )

    run_external_script(invocation)

    time.sleep(1.1)
    assert not marker.exists()


def test_non_linux_posix_external_scripts_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess_harness.sys, "platform", "darwin")

    with pytest.raises(OSError, match="Windows job objects or Linux subreaper"):
        subprocess_harness._linux_supervisor_argv(("external-command",), status_fd=10)


def test_linux_supervisor_command_uses_isolated_trusted_interpreter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess_harness.sys, "platform", "linux")

    command = subprocess_harness._linux_supervisor_argv(
        ("external-command", "argument"),
        status_fd=10,
    )

    assert command[1:3] == ("-I", "-S")
    assert Path(command[3]).name == "_posix_supervisor.py"
    assert command[4:] == (
        "10",
        "--agent-assure-cwd-fd=none",
        "--agent-assure-no-script-binding",
        "--",
        "external-command",
        "argument",
    )


def test_linux_supervisor_command_carries_internal_script_descriptor_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess_harness.sys, "platform", "linux")

    command = subprocess_harness._linux_supervisor_argv(
        (sys.executable, "/trusted/script.py", "argument"),
        status_fd=10,
        script_descriptor=12,
        script_argv_index=1,
        cwd_descriptor=13,
    )

    assert command[4:] == (
        "10",
        "--agent-assure-cwd-fd=13",
        "--agent-assure-script-binding=12:1",
        "--",
        sys.executable,
        "/trusted/script.py",
        "argument",
    )


@pytest.mark.skipif(sys.platform != "linux", reason="Linux subreaper containment")
def test_external_script_success_contains_immediate_double_fork(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "immediate-daemon-survived.txt"
    script = tmp_path / "immediate_double_fork.py"
    script.write_text(
        "import os,pathlib,time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    if os.fork() != 0:\n"
        "        os._exit(0)\n"
        "    time.sleep(0.75)\n"
        f"    pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')\n"
        "    os._exit(0)\n"
        "os._exit(0)\n",
        encoding="utf-8",
    )
    invocation = ExternalScriptInvocation(
        argv=(sys.executable, str(script)),
        cwd=tmp_path,
        timeout_seconds=3,
        request_payload={},
        observation_id="obs-immediate-success",
        run_id="run-immediate-success",
        case_id="case-immediate-success",
        adapter_id="external-script",
    )

    completed = run_external_script(invocation)

    assert completed.duration_ms < 2000
    time.sleep(1)
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux subreaper containment")
def test_external_script_timeout_contains_immediate_double_fork(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "immediate-timeout-daemon-survived.txt"
    script = tmp_path / "immediate_timeout_double_fork.py"
    script.write_text(
        "import os,pathlib,time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    if os.fork() != 0:\n"
        "        os._exit(0)\n"
        "    time.sleep(1.5)\n"
        f"    pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')\n"
        "    os._exit(0)\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    invocation = ExternalScriptInvocation(
        argv=(sys.executable, str(script)),
        cwd=tmp_path,
        timeout_seconds=1,
        request_payload={},
        observation_id="obs-immediate-timeout",
        run_id="run-immediate-timeout",
        case_id="case-immediate-timeout",
        adapter_id="external-script",
    )
    started = time.monotonic()

    with pytest.raises(ExternalScriptError, match="timed out"):
        run_external_script(invocation)

    assert time.monotonic() - started < 3
    time.sleep(1.75)
    assert not marker.exists()
