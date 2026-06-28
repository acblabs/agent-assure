from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid5

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.privacy.redaction import redact_text
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.runner.ids import AGENT_ASSURE_NAMESPACE
from agent_assure.schema.runtime import EmergencyProcessRecord

FailureKind = Literal["spawn_failed", "timeout", "nonzero_exit", "invalid_output"]


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
    try:
        result = subprocess.run(
            list(invocation.argv),
            cwd=invocation.cwd,
            input=json.dumps(invocation.request_payload, sort_keys=True),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=invocation.timeout_seconds,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = _duration_ms(started)
        completed_at_utc = _utc_now()
        emergency = _emergency_record(
            invocation,
            failure_kind="timeout",
            message=f"external script timed out after {invocation.timeout_seconds} seconds",
            started_at_utc=started_at_utc,
            completed_at_utc=completed_at_utc,
            duration_ms=duration_ms,
            stdout=exc.stdout if isinstance(exc.stdout, str) else None,
            stderr=exc.stderr if isinstance(exc.stderr, str) else None,
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
    duration_ms = _duration_ms(started)
    completed_at_utc = _utc_now()
    if result.returncode != 0:
        emergency = _emergency_record(
            invocation,
            failure_kind="nonzero_exit",
            message=f"external script exited with code {result.returncode}",
            started_at_utc=started_at_utc,
            completed_at_utc=completed_at_utc,
            duration_ms=duration_ms,
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        raise ExternalScriptError("external script exited nonzero", emergency)
    return ExternalScriptCompleted(
        stdout=result.stdout,
        stderr=result.stderr,
        duration_ms=duration_ms,
        started_at_utc=started_at_utc,
        completed_at_utc=completed_at_utc,
    )


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
    env = {
        name: os.environ[name]
        for name in invocation.environment_allowlist
        if name in os.environ
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
        stdout_bytes=_byte_count(stdout),
        stderr_bytes=_byte_count(stderr),
        stderr_summary=_summary(stderr),
        safe_error_code=safe.code,
        safe_error_message=safe.message,
        local_debug_reference=safe.local_debug_reference,
        traceparent=invocation.traceparent,
        tracestate=invocation.tracestate,
    )


def _summary(value: str | None) -> str | None:
    if value is None:
        return None
    compact = " ".join(value.split())
    if not compact:
        return None
    return redact_text(compact[:500])


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
