from __future__ import annotations

import ctypes
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Literal, cast
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
POSIX_SUPERVISOR_START_TIMEOUT_SECONDS = 2.0
POSIX_SUPERVISOR_SHUTDOWN_TIMEOUT_SECONDS = 2.0
_REDACTION_MASK_RUN = re.compile(f"{re.escape(REDACTION_MASK_CHARACTER)}+")
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_WINDOWS_JOBS: dict[int, int] = {}
_WINDOWS_JOBS_LOCK = threading.Lock()
_POSIX_TRACKERS: dict[int, _PosixDescendantTracker] = {}
_POSIX_TRACKERS_LOCK = threading.Lock()
_POSIX_TRACKER_POLL_SECONDS = 0.01
_POSIX_SUPERVISORS: set[int] = set()
_POSIX_SUPERVISORS_LOCK = threading.Lock()


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
    script_descriptor: int | None = None
    script_argv_index: int | None = None
    cwd_descriptor: int | None = None
    cwd_device: int | None = None
    cwd_inode: int | None = None


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
        supervisor_status_read_fd: int | None = None
        supervisor_status_write_fd: int | None = None
        try:
            bound_script = _validate_bound_script(invocation)
            _validate_bound_cwd(invocation)
            process_options = _process_group_options()
            launch_argv = invocation.argv
            if os.name != "nt":
                supervisor_status_read_fd, supervisor_status_write_fd = os.pipe()
                launch_argv = _linux_supervisor_argv(
                    invocation.argv,
                    status_fd=supervisor_status_write_fd,
                    script_descriptor=invocation.script_descriptor,
                    script_argv_index=invocation.script_argv_index,
                    cwd_descriptor=invocation.cwd_descriptor,
                )
                inherited_descriptors = [supervisor_status_write_fd]
                if invocation.script_descriptor is not None:
                    inherited_descriptors.append(invocation.script_descriptor)
                if (
                    invocation.cwd_descriptor is not None
                    and invocation.cwd_descriptor not in inherited_descriptors
                ):
                    inherited_descriptors.append(invocation.cwd_descriptor)
                process_options["pass_fds"] = tuple(inherited_descriptors)
            process = subprocess.Popen(
                list(launch_argv),
                cwd=(
                    None
                    if os.name != "nt" and invocation.cwd_descriptor is not None
                    else invocation.cwd
                ),
                stdin=stdin_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                **process_options,
            )
            if os.name == "nt":
                if bound_script is not None:
                    _require_bound_script_path_unchanged(invocation, bound_script)
                _validate_bound_cwd(invocation)
            if supervisor_status_write_fd is not None:
                _close_file_descriptor(supervisor_status_write_fd)
                supervisor_status_write_fd = None
                _register_posix_supervisor(process.pid)
                try:
                    _await_posix_supervisor_ready(
                        supervisor_status_read_fd,
                        timeout_seconds=min(
                            float(invocation.timeout_seconds),
                            POSIX_SUPERVISOR_START_TIMEOUT_SECONDS,
                        ),
                    )
                finally:
                    _close_file_descriptor(supervisor_status_read_fd)
                    supervisor_status_read_fd = None
            if not _attach_windows_kill_on_close_job(process):
                _terminate_process_tree(process)
                _wait_for_terminated_process(process)
                raise OSError("external script could not be placed in a kill-on-close process job")
            if os.name == "nt":
                if bound_script is not None:
                    _require_bound_script_path_unchanged(invocation, bound_script)
                _validate_bound_cwd(invocation)
            if not _resume_windows_suspended_process(process):
                _terminate_process_tree(process)
                _wait_for_terminated_process(process)
                raise OSError("external script suspended process could not be resumed safely")
            _start_posix_descendant_tracking(process)
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
            if process is not None:
                _terminate_process_tree(process)
                _wait_for_terminated_process(process)
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
            _close_file_descriptor(supervisor_status_read_fd)
            _close_file_descriptor(supervisor_status_write_fd)
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
        # Popen closes the primary thread handle returned by CreateProcess. Start
        # suspended so no uncontained child can run before we assign the process
        # to its kill-on-close job, then resume it through a freshly opened
        # thread handle after assignment succeeds.
        return {
            "creationflags": (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
            )
        }
    return {"start_new_session": True}


def _linux_supervisor_argv(
    argv: tuple[str, ...],
    *,
    status_fd: int,
    script_descriptor: int | None = None,
    script_argv_index: int | None = None,
    cwd_descriptor: int | None = None,
) -> tuple[str, ...]:
    if sys.platform != "linux":
        raise OSError("external scripts require Windows job objects or Linux subreaper containment")
    interpreter = Path(sys.executable)
    supervisor = Path(__file__).with_name("_posix_supervisor.py")
    if status_fd <= 2 or not interpreter.is_file() or not supervisor.is_file():
        raise OSError("Linux subprocess containment supervisor was unavailable")
    if cwd_descriptor is not None and cwd_descriptor <= 2:
        raise OSError("external script cwd descriptor binding was invalid")
    cwd_argument = (
        "--agent-assure-cwd-fd=none"
        if cwd_descriptor is None
        else f"--agent-assure-cwd-fd={cwd_descriptor}"
    )
    binding_arguments = ("--agent-assure-no-script-binding", "--")
    if script_descriptor is not None or script_argv_index is not None:
        if (
            script_descriptor is None
            or script_descriptor <= 2
            or script_argv_index is None
            or script_argv_index < 0
            or script_argv_index >= len(argv)
        ):
            raise OSError("external script descriptor binding was invalid")
        binding_arguments = (
            f"--agent-assure-script-binding={script_descriptor}:{script_argv_index}",
            "--",
        )
    return (
        str(interpreter.resolve()),
        "-I",
        "-S",
        str(supervisor.resolve()),
        str(status_fd),
        cwd_argument,
        *binding_arguments,
        *argv,
    )


def _validate_bound_script(
    invocation: ExternalScriptInvocation,
) -> os.stat_result | None:
    descriptor = invocation.script_descriptor
    index = invocation.script_argv_index
    if descriptor is None and index is None:
        return None
    if (
        descriptor is None
        or descriptor <= 2
        or index is None
        or index < 0
        or index >= len(invocation.argv)
    ):
        raise OSError("external script descriptor binding was invalid")
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise OSError("external script descriptor was unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("external script descriptor was not a regular file")
    if os.name == "nt":
        _require_bound_script_path_unchanged(invocation, metadata)
    elif sys.platform == "linux":
        descriptor_path = Path(f"/proc/self/fd/{descriptor}")
        try:
            current = descriptor_path.stat()
        except OSError as exc:
            raise OSError("external script descriptor path was unavailable") from exc
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise OSError("external script descriptor path identity was inconsistent")
    return metadata


def _validate_bound_cwd(invocation: ExternalScriptInvocation) -> None:
    descriptor = invocation.cwd_descriptor
    if descriptor is not None:
        if descriptor <= 2:
            raise OSError("external script cwd descriptor binding was invalid")
        try:
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise OSError("external script cwd descriptor was unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("external script cwd descriptor was not a directory")
    if invocation.cwd_device is None and invocation.cwd_inode is None:
        return
    if invocation.cwd_device is None or invocation.cwd_inode is None:
        raise OSError("external script cwd identity binding was invalid")
    if os.name == "nt":
        _require_bound_cwd_path_unchanged(invocation)


def _require_bound_cwd_path_unchanged(invocation: ExternalScriptInvocation) -> None:
    try:
        current = os.stat(invocation.cwd, follow_symlinks=False)
    except OSError as exc:
        raise OSError("external script cwd changed before execution") from exc
    attributes = getattr(current, "st_file_attributes", 0)
    if (
        not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(current.st_mode)
        or attributes & _WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
        or (current.st_dev, current.st_ino) != (invocation.cwd_device, invocation.cwd_inode)
    ):
        raise OSError("external script cwd changed before execution")


def _require_bound_script_path_unchanged(
    invocation: ExternalScriptInvocation,
    expected: os.stat_result,
) -> None:
    index = invocation.script_argv_index
    if index is None or index < 0 or index >= len(invocation.argv):
        raise OSError("external script descriptor binding was invalid")
    path = Path(invocation.argv[index])
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise OSError("external script path changed before execution") from exc
    expected_identity = (expected.st_dev, expected.st_ino, expected.st_size)
    current_identity = (current.st_dev, current.st_ino, current.st_size)
    if expected_identity != current_identity or not stat.S_ISREG(current.st_mode):
        raise OSError("external script path changed before execution")


def _await_posix_supervisor_ready(
    status_fd: int | None,
    *,
    timeout_seconds: float,
) -> None:
    if status_fd is None:
        raise OSError("Linux subprocess containment status pipe was unavailable")
    deadline = time.monotonic() + max(0.001, timeout_seconds)
    status = bytearray()
    while b"\n" not in status and len(status) < 64:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError("Linux subprocess containment supervisor did not become ready")
        try:
            readable, _, _ = select.select((status_fd,), (), (), remaining)
        except (OSError, ValueError) as exc:
            raise OSError("Linux subprocess containment handshake failed") from exc
        if not readable:
            raise OSError("Linux subprocess containment supervisor did not become ready")
        try:
            chunk = os.read(status_fd, 64 - len(status))
        except OSError as exc:
            raise OSError("Linux subprocess containment handshake failed") from exc
        if not chunk:
            break
        status.extend(chunk)
    line = bytes(status).split(b"\n", 1)[0]
    if line == b"READY":
        return
    if line == b"ERROR:spawn":
        raise OSError("external script child could not be started")
    if line == b"ERROR:containment":
        raise OSError("Linux subprocess containment could not be established")
    raise OSError("Linux subprocess containment supervisor returned an invalid handshake")


def _close_file_descriptor(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _register_posix_supervisor(pid: int) -> None:
    with _POSIX_SUPERVISORS_LOCK:
        _POSIX_SUPERVISORS.add(pid)


def _is_posix_supervisor(pid: int) -> bool:
    with _POSIX_SUPERVISORS_LOCK:
        return pid in _POSIX_SUPERVISORS


def _unregister_posix_supervisor(pid: int) -> None:
    with _POSIX_SUPERVISORS_LOCK:
        _POSIX_SUPERVISORS.discard(pid)


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        if not _terminate_windows_job(process.pid):
            _terminate_windows_process_tree(process.pid)
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        return
    if _is_posix_supervisor(process.pid) and _request_posix_supervisor_shutdown(process):
        return
    _force_terminate_posix_process_tree(process)


def _force_terminate_posix_process_tree(process: subprocess.Popen[bytes]) -> None:
    _kill_posix_process_group(process.pid)
    _terminate_tracked_posix_descendants(process.pid)
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass


def _request_posix_supervisor_shutdown(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is not None:
        return True
    try:
        process.terminate()
    except OSError:
        return process.poll() is not None
    try:
        process.wait(timeout=POSIX_SUPERVISOR_SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return False
    return True


def _release_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        _close_windows_job(process.pid)
        return
    supervised = _is_posix_supervisor(process.pid)
    try:
        if supervised:
            if process.poll() is None:
                _terminate_process_tree(process)
            elif process.returncode is not None and process.returncode < 0:
                # A signal killed the trusted supervisor before its normal
                # cleanup proof completed. Retain the tracked/group fallback.
                _force_terminate_posix_process_tree(process)
        else:
            _kill_posix_process_group(process.pid)
        _release_posix_descendant_tracking(process.pid)
    finally:
        if supervised:
            _unregister_posix_supervisor(process.pid)


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


@dataclass(frozen=True)
class _PosixProcessIdentity:
    pid: int
    start_token: str


class _PosixDescendantTracker:
    """Tracks observed descendants across reparenting and process-group changes."""

    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid
        self._tracked: dict[int, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._monitor,
            name=f"agent-assure-process-tree-{root_pid}",
            daemon=True,
        )

    def start(self) -> None:
        self.sample()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=OUTPUT_CAPTURE_JOIN_TIMEOUT_SECONDS)

    def sample(self) -> dict[int, tuple[int, str]]:
        with self._lock:
            seed_pids = (self.root_pid, *self._tracked)
        snapshot = _posix_process_snapshot(seed_pids)
        self.observe(snapshot)
        return snapshot

    def observe(self, snapshot: dict[int, tuple[int, str]]) -> None:
        with self._lock:
            root = snapshot.get(self.root_pid)
            if root is not None:
                self._tracked.setdefault(self.root_pid, root[1])
            live_known = {
                pid
                for pid, start_token in self._tracked.items()
                if snapshot.get(pid, (0, ""))[1] == start_token
            }
            changed = True
            while changed:
                changed = False
                for pid, (parent_pid, start_token) in snapshot.items():
                    if pid in live_known or parent_pid not in live_known:
                        continue
                    self._tracked[pid] = start_token
                    live_known.add(pid)
                    changed = True

    def descendants(self) -> tuple[_PosixProcessIdentity, ...]:
        with self._lock:
            return tuple(
                _PosixProcessIdentity(pid=pid, start_token=start_token)
                for pid, start_token in self._tracked.items()
                if pid != self.root_pid
            )

    def _monitor(self) -> None:
        while not self._stop.wait(_POSIX_TRACKER_POLL_SECONDS):
            self.sample()


def _start_posix_descendant_tracking(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        return
    tracker = _PosixDescendantTracker(process.pid)
    try:
        tracker.start()
    except RuntimeError as exc:
        raise OSError("POSIX descendant tracking could not be started") from exc
    with _POSIX_TRACKERS_LOCK:
        _POSIX_TRACKERS[process.pid] = tracker


def _terminate_tracked_posix_descendants(pid: int) -> None:
    with _POSIX_TRACKERS_LOCK:
        tracker = _POSIX_TRACKERS.get(pid)
    if tracker is not None:
        _kill_tracked_posix_descendants(tracker)


def _release_posix_descendant_tracking(pid: int) -> None:
    with _POSIX_TRACKERS_LOCK:
        tracker = _POSIX_TRACKERS.pop(pid, None)
    if tracker is None:
        return
    _kill_tracked_posix_descendants(tracker)
    tracker.stop()
    # Close the sampling/termination race once more after the monitor exits.
    _kill_tracked_posix_descendants(tracker)


def _kill_tracked_posix_descendants(tracker: _PosixDescendantTracker) -> None:
    snapshot = tracker.sample()
    for identity in reversed(tracker.descendants()):
        current = snapshot.get(identity.pid)
        if current is None or current[1] != identity.start_token:
            continue
        _kill_posix_pid(identity.pid)
        _reap_posix_child(identity.pid)


def _kill_posix_pid(pid: int) -> None:
    sigkill = getattr(signal, "SIGKILL", None)
    if sigkill is None:
        return
    try:
        os.kill(pid, sigkill)
    except OSError:
        pass


def _reap_posix_child(pid: int) -> None:
    waitpid = getattr(os, "waitpid", None)
    wait_nohang = getattr(os, "WNOHANG", None)
    if waitpid is None or wait_nohang is None:
        return
    try:
        waitpid(pid, wait_nohang)
    except (ChildProcessError, OSError):
        pass


def _posix_process_snapshot(seed_pids: tuple[int, ...]) -> dict[int, tuple[int, str]]:
    proc = Path("/proc")
    if proc.is_dir():
        return _linux_proc_process_snapshot(proc, seed_pids)
    return _ps_process_snapshot()


def _linux_proc_process_snapshot(
    proc: Path,
    seed_pids: tuple[int, ...],
) -> dict[int, tuple[int, str]]:
    snapshot: dict[int, tuple[int, str]] = {}
    pending: list[tuple[int, int | None]] = [(pid, None) for pid in dict.fromkeys(seed_pids)]
    visited: set[int] = set()
    while pending:
        pid, observed_parent = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        stat = _linux_proc_stat(proc, pid)
        if stat is None:
            continue
        parent_pid, start_token = stat
        snapshot[pid] = (
            observed_parent if observed_parent is not None else parent_pid,
            start_token,
        )
        task_dir = proc / str(pid) / "task"
        try:
            tasks = tuple(task_dir.iterdir())
        except OSError:
            continue
        for task in tasks:
            try:
                child_pids = (task / "children").read_text(encoding="ascii").split()
            except OSError:
                continue
            for child_pid in child_pids:
                try:
                    pending.append((int(child_pid), pid))
                except ValueError:
                    continue
    return snapshot


def _linux_proc_stat(proc: Path, pid: int) -> tuple[int, str] | None:
    try:
        stat = (proc / str(pid) / "stat").read_text(encoding="ascii")
        suffix = stat[stat.rfind(")") + 2 :].split()
        # Fields after comm begin at stat field 3. ppid is field 4 and
        # starttime is field 22; starttime protects against PID reuse.
        return int(suffix[1]), suffix[19]
    except (IndexError, OSError, ValueError):
        return None


def _ps_process_snapshot() -> dict[int, tuple[int, str]]:
    try:
        completed = subprocess.run(
            ["/bin/ps", "-axo", "pid=,ppid=,lstart="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=OUTPUT_CAPTURE_JOIN_TIMEOUT_SECONDS,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    snapshot: dict[int, tuple[int, str]] = {}
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) < 7:
            continue
        try:
            pid = int(fields[0])
            parent_pid = int(fields[1])
        except ValueError:
            continue
        snapshot[pid] = (parent_pid, " ".join(fields[2:7]))
    return snapshot


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


def _resume_windows_suspended_process(process: subprocess.Popen[bytes]) -> bool:
    if os.name != "nt":
        return True
    kernel32 = _windows_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot in (None, invalid_handle):
        return False
    matching_thread_ids: list[int] = []
    entry = _WindowsThreadEntry32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        has_entry = kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while has_entry:
            if entry.th32OwnerProcessID == process.pid:
                matching_thread_ids.append(entry.th32ThreadID)
            has_entry = kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    # CREATE_SUSPENDED guarantees one primary thread. Anything else means we
    # cannot prove the process remained suspended, so leave it in the job and
    # let the caller fail closed by terminating that job.
    if len(matching_thread_ids) != 1:
        return False
    thread = kernel32.OpenThread(0x0002, False, matching_thread_ids[0])
    if not thread:
        return False
    try:
        return cast(int, kernel32.ResumeThread(thread)) == 1
    finally:
        kernel32.CloseHandle(thread)


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
    windll = cast(Any, vars(ctypes)["windll"])
    kernel32 = windll.kernel32
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
    kernel32.CreateToolhelp32Snapshot.argtypes = (ctypes.c_uint32, ctypes.c_uint32)
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.Thread32First.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsThreadEntry32),
    )
    kernel32.Thread32First.restype = ctypes.c_int
    kernel32.Thread32Next.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(_WindowsThreadEntry32),
    )
    kernel32.Thread32Next.restype = ctypes.c_int
    kernel32.OpenThread.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    kernel32.OpenThread.restype = ctypes.c_void_p
    kernel32.ResumeThread.argtypes = (ctypes.c_void_p,)
    kernel32.ResumeThread.restype = ctypes.c_uint32
    kernel32.TerminateJobObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    kernel32.TerminateJobObject.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    return kernel32


class _WindowsThreadEntry32(ctypes.Structure):
    _fields_ = (
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ThreadID", ctypes.c_uint32),
        ("th32OwnerProcessID", ctypes.c_uint32),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32),
    )


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
