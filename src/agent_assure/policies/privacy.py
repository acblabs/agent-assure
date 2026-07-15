from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from agent_assure.policies.base import ControlResult
from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord

SENSITIVE_SCAN_SKIP_KEYS = frozenset(
    {
        "artifact_kind",
        "schema_version",
        "run_id",
        "case_id",
        "observation_id",
        "pipeline_id",
        "variant_id",
        "suite_id",
        "suite_version",
        "traceparent",
        "tracestate",
        "started_at_utc",
        "completed_at_utc",
    }
)
_DIGEST_OR_HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def evaluate_redaction(run: AgentRunRecord) -> tuple[ControlResult, ...]:
    return tuple(
        ControlResult(
            control_id="redaction_required",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.RAW_SENSITIVE_CONTENT,
            severity=Severity.blocker,
            target=field_name,
            message=f"{field_name} contains sensitive-looking content",
        )
        for field_name, value in _iter_sensitive_strings(run.model_dump(mode="json"))
        if contains_sensitive_value(value)
    )


def _iter_sensitive_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path or "$", value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if _skip_key(key_text, item):
                continue
            child_path = f"{path}.{key_text}" if path else key_text
            yield from _iter_sensitive_strings(item, child_path)
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for index, item in enumerate(value):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            yield from _iter_sensitive_strings(item, child_path)


def _skip_key(key: str, value: Any) -> bool:
    return key in SENSITIVE_SCAN_SKIP_KEYS or (
        key.endswith(("_digest", "_hash")) and _is_digest_like(value)
    )


def _is_digest_like(value: Any) -> bool:
    if isinstance(value, str):
        return _DIGEST_OR_HASH_PATTERN.fullmatch(value) is not None
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return all(_is_digest_like(item) for item in value)
    return False
