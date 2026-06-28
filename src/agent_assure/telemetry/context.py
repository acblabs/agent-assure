from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

TRACEPARENT_FIELD_PATTERN = r"^00-[a-f0-9]{32}-[a-f0-9]{16}-[a-f0-9]{2}$"
TRACEPARENT_PATTERN = re.compile(TRACEPARENT_FIELD_PATTERN)


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


def trace_context_carrier(
    traceparent: str | None,
    tracestate: str | None = None,
) -> dict[str, str]:
    carrier: dict[str, str] = {}
    if traceparent is not None:
        carrier["traceparent"] = validate_traceparent(traceparent)
    if tracestate:
        carrier["tracestate"] = tracestate
    return carrier
