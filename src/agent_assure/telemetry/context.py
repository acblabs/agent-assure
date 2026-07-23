from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

TRACEPARENT_FIELD_PATTERN = r"^00-[a-f0-9]{32}-[a-f0-9]{16}-[a-f0-9]{2}$"
TRACEPARENT_PATTERN = re.compile(TRACEPARENT_FIELD_PATTERN)
TRACESTATE_MAX_CHARS = 512
TRACESTATE_MAX_MEMBERS = 32
_TRACESTATE_SIMPLE_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_\-*/]{0,255}$")
_TRACESTATE_MULTI_TENANT_KEY_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9_\-*/]{0,240}@[a-z][a-z0-9_\-*/]{0,13}$"
)


@dataclass(frozen=True)
class RuntimeTraceContext:
    traceparent: str
    tracestate: str | None = None

    @property
    def trace_id(self) -> str:
        return self.traceparent.split("-")[1]

    @property
    def span_id(self) -> str:
        return self.traceparent.split("-")[2]


def trace_context_for_seed(seed: str) -> RuntimeTraceContext:
    digest = hashlib.sha256(f"agent-assure-runtime-trace:{seed}".encode()).hexdigest()
    trace_id = digest[:32]
    span_id = digest[32:48]
    if trace_id == "0" * 32:
        trace_id = "1" + trace_id[1:]
    if span_id == "0" * 16:
        span_id = "1" + span_id[1:]
    return RuntimeTraceContext(traceparent=f"00-{trace_id}-{span_id}-01")


def validate_traceparent(value: str) -> str:
    if not TRACEPARENT_PATTERN.fullmatch(value):
        raise ValueError("traceparent must use W3C version 00 format")
    if value[3:35] == "0" * 32:
        raise ValueError("traceparent trace-id must not be all zero")
    if value[36:52] == "0" * 16:
        raise ValueError("traceparent parent-id must not be all zero")
    return value


def validate_tracestate(value: str) -> str:
    """Validate the W3C tracestate wire format without interpreting vendor values."""
    if not value or len(value) > TRACESTATE_MAX_CHARS:
        raise ValueError("tracestate must contain between 1 and 512 characters")
    members = value.split(",")
    if len(members) > TRACESTATE_MAX_MEMBERS:
        raise ValueError("tracestate must contain no more than 32 list-members")

    seen: set[str] = set()
    for raw_member in members:
        member = raw_member.strip(" \t")
        key, separator, member_value = member.partition("=")
        if not separator or not key or not member_value:
            raise ValueError("tracestate list-members must use key=value syntax")
        if not (
            _TRACESTATE_SIMPLE_KEY_PATTERN.fullmatch(key)
            or _TRACESTATE_MULTI_TENANT_KEY_PATTERN.fullmatch(key)
        ):
            raise ValueError("tracestate contains an invalid list-member key")
        if key in seen:
            raise ValueError("tracestate list-member keys must be unique")
        seen.add(key)
        if len(member_value) > 256 or member_value[0] == " " or member_value[-1] == " ":
            raise ValueError("tracestate contains an invalid list-member value")
        if any(
            character in {",", "="} or not 0x20 <= ord(character) <= 0x7E
            for character in member_value
        ):
            raise ValueError("tracestate contains an invalid list-member value")
    return value


def trace_context_carrier(
    traceparent: str | None,
    tracestate: str | None = None,
) -> dict[str, str]:
    carrier: dict[str, str] = {}
    if traceparent is not None:
        carrier["traceparent"] = validate_traceparent(traceparent)
    if tracestate:
        carrier["tracestate"] = validate_tracestate(tracestate)
    return carrier
