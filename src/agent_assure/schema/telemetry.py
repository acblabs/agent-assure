from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import coerce_tuple
from agent_assure.telemetry.context import (
    TRACEPARENT_FIELD_PATTERN,
    validate_traceparent,
    validate_tracestate,
)

MAX_OTEL_ATTRIBUTE_KEY_CHARS = 255
MAX_OTEL_ATTRIBUTE_VALUE_CHARS = 8_192
MAX_OTEL_ATTRIBUTES = 128
MAX_OTEL_EVENT_ATTRIBUTES = 64
MAX_OTEL_EVENTS = 128
MAX_OTEL_NAME_CHARS = 255
MAX_OTEL_SPANS_PER_EXPORT = 1_024
OTelAttributeKey = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MAX_OTEL_ATTRIBUTE_KEY_CHARS,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    ),
]
OTelAttributeString = Annotated[str, Field(max_length=MAX_OTEL_ATTRIBUTE_VALUE_CHARS)]


class SpanAttribute(PersistedArtifact):
    artifact_kind: Literal["span-attribute"] = "span-attribute"
    key: OTelAttributeKey
    value: OTelAttributeString | int | bool

    @field_validator("value")
    @classmethod
    def _validate_integer_range(cls, value: str | int | bool) -> str | int | bool:
        if isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value < 2**63:
            raise ValueError("OpenTelemetry integer attributes must fit signed 64-bit range")
        return value


class SpanEvent(PersistedArtifact):
    artifact_kind: Literal["span-event"] = "span-event"
    name: str = Field(
        min_length=1,
        max_length=MAX_OTEL_NAME_CHARS,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )
    attributes: tuple[SpanAttribute, ...] = Field(
        default=(),
        max_length=MAX_OTEL_EVENT_ATTRIBUTES,
    )

    @field_validator("attributes", mode="before")
    @classmethod
    def _coerce_attributes(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_unique_attribute_keys(self) -> Self:
        _validate_unique_attribute_keys(self.attributes, owner="span event")
        return self


class SpanPlan(PersistedArtifact):
    artifact_kind: Literal["span-plan"] = "span-plan"
    span_name: str = Field(
        min_length=1,
        max_length=MAX_OTEL_NAME_CHARS,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )
    traceparent: str | None = Field(default=None, pattern=TRACEPARENT_FIELD_PATTERN)
    tracestate: str | None = None
    attributes: tuple[SpanAttribute, ...] = Field(max_length=MAX_OTEL_ATTRIBUTES)
    events: tuple[SpanEvent, ...] = Field(default=(), max_length=MAX_OTEL_EVENTS)
    semconv_commit: str = Field(min_length=1, max_length=128)
    semconv_checksum: str = Field(min_length=1, max_length=128)

    @field_validator("attributes", "events", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("traceparent")
    @classmethod
    def _validate_traceparent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_traceparent(value)

    @field_validator("tracestate")
    @classmethod
    def _validate_tracestate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_tracestate(value)

    @model_validator(mode="after")
    def _validate_unique_attribute_keys(self) -> Self:
        _validate_unique_attribute_keys(self.attributes, owner="span")
        return self


def _validate_unique_attribute_keys(
    attributes: tuple[SpanAttribute, ...],
    *,
    owner: str,
) -> None:
    keys = [attribute.key for attribute in attributes]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{owner} attribute keys must be unique")
