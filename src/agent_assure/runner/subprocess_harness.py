from __future__ import annotations

import ctypes
import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Literal
from uuid import uuid5

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.privacy.redaction import (
    REDACTION,
    REDACTION_MASK_CHARACTER,
    mask_sensitive_text_preserving_length,
)
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.runner.ids import AGENT_ASSURE_NAMESPACE
from agent_assure.schema.runtime import EmergencyProcessRecord

FailureKind = Literal["spawn_failed", "timeout", "nonzero_exit", "invalid_output"]
MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES = 1_048_576
MAX_EMERGENCY_SUMMARY_SOURCE_CHARS = 500
OUTPUT_CAPTURE_JOIN_TIMEOUT_SECONDS = 0.5
PROCESS_TERMINATION_GRACE_SECONDS = 1.0
_REDACTION_MASK_RUN = re.compile(f"{re.escape(REDACTION_MASK_CHARACTER)}+")
_WINDOWS_JOBS: dict[int, int] = {}
_WINDOWS_JOBS_LOCK = threading.Lock()


class ExternalScriptError(RuntimeError):
    def __init__(self, message: str, emergency_record: EmergencyProcessRecord) -> None:
        super().__init__(message)
        self.emergency_record = emergency_record


@dataclass(frozen=True)
class ExternalScriptInvocation:
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: int
    request_payload: dict[str, object]
    observation_id: str
    run_id: str
    case_id: str
    adapter_id: str
    environment: tuple[tuple[str, str], ...] = ()
    environment_allowlist: tuple[str, ...] = ()
    traceparent: str | None = None
    tracestate: str | None = None


@dataclass(frozen=True)
class ExternalScriptCompleted:
    stdout: str
    stderr: str
    duration_ms: int
    started_at_utc: str
    completed_at_utc: str
    stdout_bytes: int = 0
    stderr_bytes: int = 0


class _ProcessOutputCapture:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.stdout_sample = bytearray()
        self.stderr_sample = bytearray()
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self.limit_exceeded = False
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._finalized = False

    def start(self) -> None:
        for stream_name, pipe in (
            ("stdout", self.process.stdout),
            ("stderr", self.process.stderr),
        ):
            if pipe is None:
                continue
            thread = threading.Thread(
                target=_read_process_stream,
                args=(pipe, stream_name, self),
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def add(self, stream_name: str, chunk: bytes) -> None:
        with self._lock:
            if stream_name == "stdout":
                self.stdout_bytes += len(chunk)
                _append_sample(self.stdout_sample, chunk)
            else:
                self.stderr_bytes += len(chunk)
                _append_sample(self.stderr_sample, chunk)
            if (
                self.stdout_bytes + self.stderr_bytes > MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES
                and not self.limit_exceeded
            ):
                self.limit_exceeded = True
                _terminate_process_tree(self.process)

    def join(self, *, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        for thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in self._threads)

    def finalize(self) -> None:
        if self._finalized:
            return
        # Never wait indefinitely for EOF: an escaped descendant may retain an
        # inherited pipe handle. The daemon readers can finish later without
        # holding the caller past this deadline.
        self.join(timeout_seconds=OUTPUT_CAPTURE_JOIN_TIMEOUT_SECONDS)
        self._finalized = True

    def snapshot(self) -> tuple[bytes, int, bytes, int]:
        with self._lock:
            return (
                bytes(self.stdout_sample),
                self.stdout_bytes,
                bytes(self.stderr_sample),
                self.stderr_bytes,
            )


def _capture_process_output(process: subprocess.Popen[bytes]) -> _ProcessOutputCapture:
    capture = _ProcessOutputCapture(process)
    capture.start()
    return capture


def _read_process_stream(
    pipe: BinaryIO,
    stream_name: str,
    capture: _ProcessOutputCapture,
) -> None:
    try:
        while True:
            chunk = pipe.read(8192)
            if not chunk:
                return
            capture.add(stream_name, chunk)
    except (OSError, ValueError):
        return
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            pass


def _append_sample(sample: bytearray, chunk: bytes) -> None:
    remaining = MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES - len(sample)
    if remaining > 0:
        sample.extend(chunk[:remaining])


def _collected_output(
    capture: _ProcessOutputCapture | None,
) -> tuple[str, int, str, int]:
    if capture is None:
        return "", 0, "", 0
    stdout_sample, stdout_bytes, stderr_sample, stderr_bytes = capture.snapshot()
    return (
        _decode_sample(stdout_sample),
        stdout_bytes,
        _decode_sample(stderr_sample),
        stderr_bytes,
    )


def run_external_script(invocation: ExternalScriptInvocation) -> ExternalScriptCompleted:
    if not invocation.argv:
        emergency = _emergency_record(
            invocation,
            failure_kind="spawn_failed",
            message="external script argv was empty",
        )
        raise ExternalScriptError("external script argv was empty", emergency)
    started_at_utc = _utc_now()
    started = time.perf_counter()
    env = _process_env(invocation)
    request_body = json.dumps(invocation.request_payload, sort_keys=True).encode("utf-8")
    with tempfile.TemporaryFile() as stdin_file:
        stdin_file.write(request_body)
        stdin_file.seek(0)
        process: subprocess.Popen[bytes] | None = None
        capture: _ProcessOutputCapture | None = None
        returncode = -1
        try:
            process = subprocess.Popen(
                list(invocation.argv),
                cwd=invocation.cwd,
                stdin=stdin_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                **_process_group_options(),
            )
            if not _attach_windows_kill_on_close_job(process):
                _terminate_process_tree(process)
                _wait_for_terminated_process(process)
                raise OSError(
                    "external script could not be placed in a kill-on-close process job"
                )
            capture = _capture_process_output(process)
            returncode = process.wait(timeout=invocation.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            if process is not None:
                _terminate_process_tree(process)
                _wait_for_terminated_process(process)
            if capture is not None:
                capture.finalize()
            duration_ms = _duration_ms(started)
            completed_at_utc = _utc_now()
            stdout, stdout_bytes, stderr, stderr_bytes = _collected_output(capture)
            emergency = _emergency_record(
                invocation,
                failure_kind="timeout",
                message=f"external script timed out after {invocation.timeout_seconds} seconds",
                started_at_utc=started_at_utc,
                completed_at_utc=completed_at_utc,
                duration_ms=duration_ms,
                stdout=stdout,
                stderr=stderr,
                stdout_bytes=stdout_bytes,
                stderr_bytes=stderr_bytes,
            )
            raise ExternalScriptError("external script timed out", emergency) from exc
        except OSError as exc:
            duration_ms = _duration_ms(started)
            completed_at_utc = _utc_now()
            emergency = _emergency_record(
                invocation,
                failure_kind="spawn_failed",
                message=str(exc),
                started_at_utc=started_at_utc,
                completed_at_utc=completed_at_utc,
                duration_ms=duration_ms,
                exc=exc,
            )
            raise ExternalScriptError("external script could not be started", emergency) from exc
        finally:
            if process is not None:
                _release_process_tree(process)
            if capture is not None:
                capture.finalize()
        stdout, stdout_bytes, stderr, stderr_bytes = _collected_output(capture)
    duration_ms = _duration_ms(started)
    completed_at_utc = _utc_now()
    completed = ExternalScriptCompleted(
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        started_at_utc=started_at_utc,
        completed_at_utc=completed_at_utc,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
    )
    if stdout_bytes + stderr_bytes > MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES:
        emergency = invalid_output_emergency(
            invocation,
            completed,
            "external script output exceeded configured byte limit",
        )
        raise ExternalScriptError("external script output exceeded byte limit", emergency)
    if returncode != 0:
        emergency = _emergency_record(
            invocation,
            failure_kind="nonzero_exit",
            message=f"external script exited with code {returncode}",
            started_at_utc=started_at_utc,
            completed_at_utc=completed_at_utc,
            duration_ms=duration_ms,
            exit_code=returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )
        raise ExternalScriptError("external script exited nonzero", emergency)
    return completed


def emergency_from_exception(exc: BaseException) -> EmergencyProcessRecord | None:
    if isinstance(exc, ExternalScriptError):
        return exc.emergency_record
    return None


def invalid_output_emergency(
    invocation: ExternalScriptInvocation,
    completed: ExternalScriptCompleted,
    message: str,
    exc: BaseException | None = None,
) -> EmergencyProcessRecord:
    return _emergency_record(
        invocation,
        failure_kind="invalid_output",
        message=message,
        started_at_utc=completed.started_at_utc,
        completed_at_utc=completed.completed_at_utc,
        duration_ms=completed.duration_ms,
        exit_code=0,
        stdout=completed.stdout,
        stderr=completed.stderr,
        stdout_bytes=completed.stdout_bytes,
        stderr_bytes=completed.stderr_bytes,
        exc=exc,
    )


def command_digest(argv: tuple[str, ...], cwd: Path) -> str:
    return sha256_hexdigest(
        {
            "argv": argv,
            "cwd": str(cwd.resolve()),
        }
    )


def _process_env(invocation: ExternalScriptInvocation) -> dict[str, str]:
    # Child environments are allowlist-only; callers that resolve helper
    # executables by bare name must explicitly allowlist PATH.
    env = {
        name: os.environ[name] for name in invocation.environment_allowlist if name in os.environ
    }
    env.update(dict(invocation.environment))
    if invocation.traceparent is not None:
        env["TRACEPARENT"] = invocation.traceparent
        env["AGENT_ASSURE_TRACEPARENT"] = invocation.traceparent
    if invocation.tracestate:
        env["TRACESTATE"] = invocation.tracestate
        env["AGENT_ASSURE_TRACESTATE"] = invocation.tracestate
    env["AGENT_ASSURE_OBSERVATION_ID"] = invocation.observation_id
    env["AGENT_ASSURE_RUN_ID"] = invocation.run_id
    env["AGENT_ASSURE_CASE_ID"] = invocation.case_id
    return env


def _emergency_record(
    invocation: ExternalScriptInvocation,
    *,
    failure_kind: FailureKind,
    message: str,
    started_at_utc: str | None = None,
    completed_at_utc: str | None = None,
    duration_ms: int | None = None,
    exit_code: int | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
    stdout_bytes: int | None = None,
    stderr_bytes: int | None = None,
    exc: BaseException | None = None,
) -> EmergencyProcessRecord:
    safe = safe_error(f"external_script_{failure_kind}", message, exc)
    return EmergencyProcessRecord(
        artifact_kind="emergency-process-record",
        emergency_id=_emergency_id(invocation, failure_kind),
        failure_kind=failure_kind,
        command_digest=command_digest(invocation.argv, invocation.cwd),
        executable_name=Path(invocation.argv[0]).name if invocation.argv else "unknown",
        script_name=Path(invocation.argv[1]).name if len(invocation.argv) > 1 else None,
        working_directory_digest=sha256_hexdigest({"cwd": str(invocation.cwd.resolve())}),
        observation_id=invocation.observation_id,
        run_id=invocation.run_id,
        case_id=invocation.case_id,
        adapter_id=invocation.adapter_id,
        started_at_utc=started_at_utc,
        completed_at_utc=completed_at_utc,
        duration_ms=duration_ms,
        timeout_seconds=invocation.timeout_seconds,
        exit_code=exit_code,
        stdout_bytes=stdout_bytes if stdout_bytes is not None else _byte_count(stdout),
        stderr_bytes=stderr_bytes if stderr_bytes is not None else _byte_count(stderr),
        stderr_summary=_summary(
            stderr,
            source_truncated=(
                stderr_bytes is not None and stderr_bytes > MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES
            ),
        ),
        safe_error_code=safe.code,
        safe_error_message=safe.message,
        local_debug_reference=safe.local_debug_reference,
        traceparent=invocation.traceparent,
        tracestate=invocation.tracestate,
    )


def _summary(value: str | None, *, source_truncated: bool = False) -> str | None:
    if value is None:
        return None
    if source_truncated:
        return None
    compact = " ".join(value.split())
    if not compact:
        return None
    masked = mask_sensitive_text_preserving_length(compact)
    source_prefix = masked[:MAX_EMERGENCY_SUMMARY_SOURCE_CHARS]
    return _REDACTION_MASK_RUN.sub(REDACTION, source_prefix)[:MAX_EMERGENCY_SUMMARY_SOURCE_CHARS]


def _decode_sample(sample: bytes | bytearray) -> str:
    return bytes(sample[:MAX_EXTERNAL_SCRIPT_OUTPUT_BYTES]).decode(
        "utf-8",
        errors="replace",
    )


def _byte_count(value: str | None) -> int:
    if value is None:
        return 0
    return len(value.encode("utf-8"))


def _duration_ms(started: float) -> int:
    return max(0, int(round((time.perf_counter() - started) * 1000)))


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _emergency_id(invocation: ExternalScriptInvocation, failure_kind: FailureKind) -> str:
    digest = command_digest(invocation.argv, invocation.cwd)
    key = f"{failure_kind}:{invocation.observation_id}:{digest}"
    return f"emergency-{uuid5(AGENT_ASSURE_NAMESPACE, key)}"


def _process_group_options() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        if not _terminate_windows_job(process.pid):
            _terminate_windows_process_tree(process.pid)
    else:
        _kill_posix_process_group(process.pid)
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _release_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        _close_windows_job(process.pid)
        return
    # External adapters are synchronous. Do not allow a successfully exited
    # adapter parent to leave descendants running or holding capture pipes.
    _kill_posix_process_group(process.pid)


def _kill_posix_process_group(pid: int) -> None:
    killpg_name = "killpg"
    sigkill_name = "SIGKILL"
    killpg = getattr(os, killpg_name, None)
    sigkill = getattr(signal, sigkill_name, None)
    if killpg is None or sigkill is None:
        return
    try:
        killpg(pid, sigkill)
    except OSError:
        pass


def _attach_windows_kill_on_close_job(process: subprocess.Popen[bytes]) -> bool:
    if os.name != "nt":
        return True
    process_handle = getattr(process, "_handle", None)
    if process_handle is None:
        return False
    kernel32 = _windows_kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return False
    info = _WindowsJobObjectExtendedLimitInformation()
    info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    configured = kernel32.SetInformationJobObject(
        job,
        9,  # JobObjectExtendedLimitInformation
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    assigned = configured and kernel32.AssignProcessToJobObject(
        job,
        ctypes.c_void_p(int(process_handle)),
    )
    if not assigned:
        kernel32.CloseHandle(job)
        return False
    with _WINDOWS_JOBS_LOCK:
        _WINDOWS_JOBS[process.pid] = int(job)
    return True


def _terminate_windows_job(pid: int) -> bool:
    handle = _pop_windows_job(pid)
    if handle is None:
        return False
    kernel32 = _windows_kernel32()
    try:
        kernel32.TerminateJobObject(ctypes.c_void_p(handle), 1)
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    return True


def _close_windows_job(pid: int) -> None:
    handle = _pop_windows_job(pid)
    if handle is not None:
        _windows_kernel32().CloseHandle(ctypes.c_void_p(handle))


def _pop_windows_job(pid: int) -> int | None:
    with _WINDOWS_JOBS_LOCK:
        return _WINDOWS_JOBS.pop(pid, None)


def _windows_kernel32() -> Any:
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.SetInformationJobObject.argtypes = (
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    )
    kernel32.SetInformationJobObject.restype = ctypes.c_int
    kernel32.AssignProcessToJobObject.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    kernel32.AssignProcessToJobObject.restype = ctypes.c_int
    kernel32.TerminateJobObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel32.TerminateJobObject.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    return kernel32


class _WindowsJobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    )


class _WindowsIoCounters(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    )


class _WindowsJobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _WindowsJobObjectBasicLimitInformation),
        ("IoInfo", _WindowsIoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


def _terminate_windows_process_tree(pid: int) -> None:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    taskkill = system_root / "System32" / "taskkill.exe"
    if not taskkill.is_file():
        return
    try:
        subprocess.run(
            [str(taskkill), "/PID", str(pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=PROCESS_TERMINATION_GRACE_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _wait_for_terminated_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=PROCESS_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass
