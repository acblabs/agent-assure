from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from agent_assure.privacy.detectors import SENSITIVE_PATTERNS

REDACTION = "[REDACTED]"
_DIGEST_HEX_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub(REDACTION, redacted)
    return redacted


def redact_run_record_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted = redact_artifact_payload(payload, preserve_keys=PRESERVE_RUNSET_KEYS)
    return dict(redacted) if isinstance(redacted, Mapping) else dict(payload)


def redact_runset_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted = redact_artifact_payload(payload, preserve_keys=PRESERVE_RUNSET_KEYS)
    return dict(redacted) if isinstance(redacted, Mapping) else dict(payload)


PRESERVE_RUNSET_KEYS = frozenset(
    {
        "artifact_kind",
        "schema_version",
        "runset_id",
        "suite_id",
        "suite_version",
        "execution_mode",
        "protocol_id",
        "completion_status",
        "stop_reasons",
        "run_id",
        "case_id",
        "pipeline_id",
        "recommendation",
        "outcome",
        "observation_status",
        "observation_id",
        "randomization_block_id",
        "cluster_id",
        "source_group_id",
        "adapter_id",
        "provider",
        "model",
        "resolved_model",
        "provider_api_version",
        "provider_sdk",
        "provider_region",
        "provider_response_id",
        "traceparent",
        "started_at_utc",
        "completed_at_utc",
        "estimated_cost_usd",
        "estimated_cost_source",
        "ref_id",
        "source_id",
        "claim_ids",
        "content_digest",
        "claim_id",
        "evidence_ref_id",
        "policy_id",
        "state",
        "reason_codes",
        "severity",
        "gate_profile",
        "emergency_id",
        "failure_kind",
        "process_kind",
        "command_digest",
        "executable_name",
        "script_name",
        "working_directory_digest",
        "safe_error_code",
        "local_debug_reference",
    }
)


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
            key: _redact_mapping_item(key, item, preserve_keys=preserve_keys)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact_artifact_payload(item, preserve_keys=preserve_keys) for item in value)
    if isinstance(value, list):
        return [redact_artifact_payload(item, preserve_keys=preserve_keys) for item in value]
    return value


def redact_packet_payload(value: Any) -> Any:
    return redact_artifact_payload(value, preserve_keys=PRESERVE_PACKET_KEYS)


def _preserves_scalar_value(
    key: object,
    item: object,
    *,
    preserve_keys: frozenset[str],
) -> bool:
    return (
        isinstance(key, str)
        and isinstance(item, str)
        and (
            key in preserve_keys
            or (key.endswith("_digest") and _DIGEST_HEX_PATTERN.fullmatch(item) is not None)
        )
    )


def _redact_mapping_item(
    key: object,
    item: Any,
    *,
    preserve_keys: frozenset[str],
) -> Any:
    if _is_invalid_digest_scalar(key, item):
        return REDACTION
    if _preserves_scalar_value(key, item, preserve_keys=preserve_keys):
        return item
    return redact_artifact_payload(item, preserve_keys=preserve_keys)


def _is_invalid_digest_scalar(key: object, item: object) -> bool:
    return (
        isinstance(key, str)
        and key.endswith("_digest")
        and isinstance(item, str)
        and _DIGEST_HEX_PATTERN.fullmatch(item) is None
    )
