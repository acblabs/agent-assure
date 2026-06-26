from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_assure.privacy.detectors import SENSITIVE_PATTERNS

REDACTION = "[REDACTED]"
RUN_RECORD_SUMMARY_FIELDS = ("input_summary", "output_summary")


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub(REDACTION, redacted)
    return redacted


def redact_run_record_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    for field_name in RUN_RECORD_SUMMARY_FIELDS:
        value = redacted.get(field_name)
        if isinstance(value, str):
            redacted[field_name] = redact_text(value)
    return redacted


def redact_runset_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted = dict(payload)
    runs = redacted.get("runs")
    if isinstance(runs, list | tuple):
        redacted["runs"] = [
            redact_run_record_payload(run) if isinstance(run, Mapping) else run
            for run in runs
        ]
    return redacted


PRESERVE_PACKET_KEYS = frozenset(
    {
        "artifact_kind",
        "schema_version",
        "packet_id",
        "manifest_id",
        "role",
        "sha256",
        "lockfile_digest",
        "dependency_inventory_digest",
        "git_commit",
        "path",
    }
)


def redact_artifact_payload(value: Any, *, preserve_keys: frozenset[str] = frozenset()) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {
            key: item
            if isinstance(key, str) and (key in preserve_keys or key.endswith("_digest"))
            else redact_artifact_payload(item, preserve_keys=preserve_keys)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact_artifact_payload(item, preserve_keys=preserve_keys) for item in value)
    if isinstance(value, list):
        return [redact_artifact_payload(item, preserve_keys=preserve_keys) for item in value]
    return value


def redact_packet_payload(value: Any) -> Any:
    return redact_artifact_payload(value, preserve_keys=PRESERVE_PACKET_KEYS)
