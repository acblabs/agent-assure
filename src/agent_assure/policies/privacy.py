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
        "traceparent",
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
        or (field_name.endswith(".<mapping-key>") and _contains_control_character(value))
    )


def _iter_sensitive_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path or "$", value
        return
    if isinstance(value, Mapping):
        for index, (key, item) in enumerate(value.items()):
            key_text = str(key)
            unsafe_key = contains_sensitive_value(key_text) or _contains_control_character(key_text)
            if unsafe_key:
                key_path = f"{path or '$'}[{index}].<mapping-key>"
                yield key_path, key_text
            if _skip_key(key_text, item):
                continue
            safe_path_key = f"<key:{index}>" if unsafe_key else key_text
            child_path = f"{path}.{safe_path_key}" if path else safe_path_key
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


def _contains_control_character(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
