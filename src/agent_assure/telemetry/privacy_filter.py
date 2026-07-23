from __future__ import annotations

import re
from typing import TYPE_CHECKING

from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.privacy.redaction import redact_text
from agent_assure.schema.telemetry import (
    MAX_OTEL_ATTRIBUTE_KEY_CHARS,
    MAX_OTEL_ATTRIBUTE_VALUE_CHARS,
    MAX_OTEL_NAME_CHARS,
)
from agent_assure.telemetry.context import validate_tracestate

if TYPE_CHECKING:
    from agent_assure.schema.telemetry import SpanPlan

_INVALID_OTEL_NAME_CHARACTER = re.compile(r"[^A-Za-z0-9_.-]+")
_TRUNCATION_MARKER = "...[TRUNCATED]"


def safe_attribute(value: str, *, max_chars: int = MAX_OTEL_ATTRIBUTE_VALUE_CHARS) -> str:
    redacted = redact_text(value)
    sanitized = "".join(
        " " if character in "\r\n\t" else "\ufffd" if _is_control(character) else character
        for character in redacted
    )
    if len(sanitized) <= max_chars:
        return sanitized
    retained = max(0, max_chars - len(_TRUNCATION_MARKER))
    return sanitized[:retained] + _TRUNCATION_MARKER[: max_chars - retained]


def safe_otel_name(value: str, *, prefix: str = "") -> str:
    sanitized = _INVALID_OTEL_NAME_CHARACTER.sub("_", safe_attribute(value)).strip("_.-")
    if not sanitized:
        sanitized = "redacted"
    if not sanitized[0].isalpha() or not sanitized[0].isascii():
        sanitized = f"value_{sanitized}"
    complete = f"{prefix}{sanitized}"
    return complete[:MAX_OTEL_NAME_CHARS]


def safe_attribute_key_segment(value: str) -> str:
    if contains_sensitive_value(value):
        raise ValueError("OpenTelemetry attribute-key segment contains sensitive-looking content")
    sanitized = _INVALID_OTEL_NAME_CHARACTER.sub("_", value).strip("_.-")
    if not sanitized:
        raise ValueError("OpenTelemetry attribute-key segment must not be empty")
    return sanitized[:MAX_OTEL_ATTRIBUTE_KEY_CHARS]


def safe_tracestate(value: str | None) -> str | None:
    if value is None:
        return None
    validate_tracestate(value)
    if contains_sensitive_value(value):
        raise ValueError("tracestate contains sensitive-looking content")
    return value


def assert_span_plan_safe_for_export(plan: SpanPlan) -> None:
    """Fail closed on sensitive strings at the final telemetry egress boundary."""
    _assert_export_string_safe(plan.span_name, path="span_name")
    if plan.tracestate is not None:
        _assert_export_string_safe(plan.tracestate, path="tracestate")
    for index, attribute in enumerate(plan.attributes):
        _assert_export_attribute_safe(
            attribute.key,
            attribute.value,
            path=f"attributes[{index}]",
        )
    for event_index, event in enumerate(plan.events):
        _assert_export_string_safe(event.name, path=f"events[{event_index}].name")
        for attribute_index, attribute in enumerate(event.attributes):
            path = f"events[{event_index}].attributes[{attribute_index}]"
            _assert_export_attribute_safe(attribute.key, attribute.value, path=path)


def _assert_export_attribute_safe(
    key: str,
    value: str | int | bool,
    *,
    path: str,
) -> None:
    _assert_export_string_safe(key, path=f"{path}.key")
    if isinstance(value, bool):
        value_text = "true" if value else "false"
    else:
        value_text = str(value)
    _assert_export_string_safe(value_text, path=f"{path}.value")
    # Some detectors intentionally depend on a label such as ``ssn=`` or
    # ``patient=``. Scan the canonical attribute representation as well as its
    # parts so a structured key/value split cannot erase that context.
    _assert_export_string_safe(f"{key}={value_text}", path=f"{path}.key_value")


def _assert_export_string_safe(value: str, *, path: str) -> None:
    if contains_sensitive_value(value):
        raise ValueError(f"OpenTelemetry export field contains sensitive-looking content: {path}")
    if any(_is_control(character) for character in value):
        raise ValueError(f"OpenTelemetry export field contains control characters: {path}")


def _is_control(character: str) -> bool:
    return ord(character) < 0x20 or ord(character) == 0x7F
