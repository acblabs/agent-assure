from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from typing import Any

from agent_assure.privacy.detectors import SENSITIVE_PATTERNS

REDACTION = "[REDACTED]"
_DIGEST_HEX_PATTERN = re.compile(r"^[a-f0-9]{64}$")
FAIL_CLOSED_RUNSET_KEYS = frozenset(
    {
        "runset_id",
        "suite_id",
        "suite_version",
        "protocol_id",
        "stop_reasons",
        "run_id",
        "case_id",
        "pipeline_id",
        "recommendation",
        "outcome",
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
        "currency",
        "cost_basis",
        "cost_basis_ids",
        "pricing_snapshot_id",
        "pricing_snapshot_ids",
        "ref_id",
        "source_id",
        "claim_ids",
        "claim_id",
        "evidence_ref_id",
        "policy_id",
        "gate_profile",
        "emergency_id",
        "executable_name",
        "script_name",
        "local_debug_reference",
    }
)
FAIL_CLOSED_STREAM_KEYS = FAIL_CLOSED_RUNSET_KEYS | frozenset(
    {
        "stream_id",
        "event_id",
        "producer_id",
        "node_id",
        "event_type",
        "span_id",
        "parent_span_id",
        "traceparent",
        "producer_field",
        "scope",
        "run_ids",
        "case_ids",
        "composite_key",
        "kept_event_id",
        "duplicate_event_ids",
        "diagnostics",
    }
)


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


def assert_runset_payload_safe_for_persistence(payload: Mapping[str, Any]) -> None:
    for path, key, value in _iter_string_fields(payload):
        if key in FAIL_CLOSED_RUNSET_KEYS and _contains_sensitive_value(value):
            raise ValueError(
                f"runset preserved field contains sensitive-looking content: {path}"
            )


def assert_stream_payload_safe_for_persistence(payload: Mapping[str, Any]) -> None:
    for path, key, value in _iter_string_fields(payload):
        if key in FAIL_CLOSED_STREAM_KEYS and _contains_sensitive_value(value):
            raise ValueError(
                f"stream preserved field contains sensitive-looking content: {path}"
            )


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
        "estimated_cost_microusd",
        "estimated_cost_source",
        "currency",
        "cost_basis",
        "cost_basis_ids",
        "pricing_snapshot_id",
        "pricing_snapshot_ids",
        "pricing_snapshot_digest",
        "pricing_snapshot_digests",
        "cost_observation_count",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cached_tokens",
        "reasoning_tokens",
        "tool_call_count",
        "retry_count",
        "latency_ms",
        "total_tool_calls",
        "total_retries",
        "total_latency_ms",
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
        "estimated_cost_microusd",
        "currency",
        "cost_basis",
        "pricing_snapshot_id",
        "pricing_snapshot_digest",
        "pricing_snapshot_digests",
        "cost_observation_count",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cached_tokens",
        "reasoning_tokens",
        "tool_call_count",
        "retry_count",
        "latency_ms",
        "total_tool_calls",
        "total_retries",
        "total_latency_ms",
        "total_tokens_delta",
        "total_tokens_delta_bps",
        "total_tool_calls_delta",
        "total_tool_calls_delta_bps",
        "total_retries_delta",
        "total_retries_delta_bps",
        "total_latency_ms_delta",
        "total_latency_ms_delta_bps",
        "estimated_cost_microusd_delta",
        "estimated_cost_microusd_delta_bps",
    }
)


def redact_artifact_payload(
    value: Any,
    *,
    preserve_keys: frozenset[str] = frozenset(),
    parent_key: str | None = None,
) -> Any:
    if isinstance(value, str):
        if _is_invalid_digest_scalar(parent_key, value):
            return REDACTION
        if _preserves_scalar_value(parent_key, value, preserve_keys=preserve_keys):
            return value
        return redact_text(value)
    if isinstance(value, Mapping):
        return {
            key: _redact_mapping_item(key, item, preserve_keys=preserve_keys)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(
            redact_artifact_payload(
                item,
                preserve_keys=preserve_keys,
                parent_key=parent_key,
            )
            for item in value
        )
    if isinstance(value, list):
        return [
            redact_artifact_payload(
                item,
                preserve_keys=preserve_keys,
                parent_key=parent_key,
            )
            for item in value
        ]
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
    return redact_artifact_payload(
        item,
        preserve_keys=preserve_keys,
        parent_key=key if isinstance(key, str) else None,
    )


def _is_invalid_digest_scalar(key: object, item: object) -> bool:
    return (
        isinstance(key, str)
        and (key.endswith("_digest") or key.endswith("_digests"))
        and isinstance(item, str)
        and _DIGEST_HEX_PATTERN.fullmatch(item) is None
    )


def _contains_sensitive_value(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in SENSITIVE_PATTERNS)


def _iter_string_fields(value: Any, path: str = "$") -> Iterator[tuple[str, str, str]]:
    if isinstance(value, str):
        key = path.rsplit(".", maxsplit=1)[-1].split("[", maxsplit=1)[0]
        yield path, key, value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            yield from _iter_string_fields(item, child_path)
        return
    if isinstance(value, tuple | list):
        for index, item in enumerate(value):
            yield from _iter_string_fields(item, f"{path}[{index}]")
