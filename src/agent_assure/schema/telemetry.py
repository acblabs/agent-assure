from __future__ import annotations

from typing import Literal

from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import coerce_tuple


class SpanAttribute(PersistedArtifact):
    artifact_kind: Literal["span-attribute"] = "span-attribute"
    key: str
    value: str | int | bool


class SpanEvent(PersistedArtifact):
    artifact_kind: Literal["span-event"] = "span-event"
    name: str
    attributes: tuple[SpanAttribute, ...] = ()

    @field_validator("attributes", mode="before")
    @classmethod
    def _coerce_attributes(cls, value: object) -> object:
        return coerce_tuple(value)


class SpanPlan(PersistedArtifact):
    artifact_kind: Literal["span-plan"] = "span-plan"
    span_name: str
    attributes: tuple[SpanAttribute, ...]
    events: tuple[SpanEvent, ...] = ()
    semconv_commit: str
    semconv_checksum: str

    @field_validator("attributes", "events", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)
