from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.privacy.redaction import redact_text
from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex
from agent_assure.telemetry.context import TRACEPARENT_FIELD_PATTERN


class EmergencyProcessRecord(PersistedArtifact):
    artifact_kind: Literal["emergency-process-record"] = "emergency-process-record"
    emergency_id: str = Field(min_length=1)
    failure_kind: Literal["spawn_failed", "timeout", "nonzero_exit", "invalid_output"]
    process_kind: Literal["external_script"] = "external_script"
    command_digest: DigestHex
    executable_name: str = Field(min_length=1)
    script_name: str | None = None
    working_directory_digest: DigestHex | None = None
    observation_id: str | None = None
    run_id: str | None = None
    case_id: str | None = None
    adapter_id: str | None = None
    started_at_utc: str | None = None
    completed_at_utc: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    timeout_seconds: int | None = Field(default=None, ge=1)
    exit_code: int | None = None
    stdout_bytes: int = Field(default=0, ge=0)
    stderr_bytes: int = Field(default=0, ge=0)
    stderr_summary: str | None = None
    safe_error_code: str = Field(min_length=1)
    safe_error_message: str = Field(min_length=1)
    local_debug_reference: str = Field(min_length=1)
    traceparent: str | None = Field(default=None, pattern=TRACEPARENT_FIELD_PATTERN)
    tracestate: str | None = None

    @field_validator("stderr_summary", "safe_error_message", mode="before")
    @classmethod
    def _redact_text_fields(cls, value: object) -> object:
        if isinstance(value, str):
            return redact_text(value)
        return value
