from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.adapters.base import (
    FrameworkObservation,
    validate_privacy_filtered_mapping,
    validate_privacy_filtered_usage_segment,
)
from agent_assure.schema.base import PersistedArtifact, StrictModel
from agent_assure.schema.common import DigestHex, coerce_tuple
from agent_assure.schema.usage import (
    UsageLedger,
    UsageSegment,
    UsageSummary,
    validate_usage_summary_consistency,
)
from agent_assure.telemetry.context import TRACEPARENT_FIELD_PATTERN, validate_traceparent

StreamSequenceScope = Literal["global", "producer_local"]
StreamProducerField = Literal["producer_id", "node_id", "span_id"]


class StreamSequenceContract(StrictModel):
    scope: StreamSequenceScope
    producer_field: StreamProducerField | None = None

    @model_validator(mode="after")
    def _validate_contract(self) -> StreamSequenceContract:
        if self.scope == "global" and self.producer_field is not None:
            raise ValueError("global stream sequencing must not declare producer_field")
        if self.scope == "producer_local" and self.producer_field is None:
            raise ValueError("producer-local stream sequencing requires producer_field")
        return self


class StreamEventRecord(PersistedArtifact):
    artifact_kind: Literal["stream-event-record"] = "stream-event-record"
    event_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    case_id: str | None = None
    producer_id: str | None = None
    node_id: str | None = None
    sequence_number: int = Field(ge=0)
    timestamp: str | None = None
    event_type: str = Field(min_length=1)

    observation: FrameworkObservation | None = None
    usage_segment: UsageSegment | None = None

    span_id: str | None = None
    parent_span_id: str | None = None
    traceparent: str | None = Field(default=None, pattern=TRACEPARENT_FIELD_PATTERN)
    privacy_filtered_attributes: dict[str, str] = Field(default_factory=dict)
    digest: DigestHex

    @field_validator("traceparent")
    @classmethod
    def _validate_traceparent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_traceparent(value)

    @model_validator(mode="after")
    def _validate_event(self) -> StreamEventRecord:
        validate_privacy_filtered_mapping(
            self.privacy_filtered_attributes,
            owner="stream privacy_filtered_attributes",
        )
        if self.usage_segment is not None:
            validate_privacy_filtered_usage_segment(self.usage_segment)
        if self.observation is None:
            return self
        if self.observation.run_id != self.run_id:
            raise ValueError("stream event observation.run_id must match run_id")
        if self.observation.sequence_number != self.sequence_number:
            raise ValueError(
                "stream event observation.sequence_number must match sequence_number"
            )
        if (
            self.case_id is not None
            and self.observation.case_id is not None
            and self.observation.case_id != self.case_id
        ):
            raise ValueError("stream event observation.case_id must match case_id")
        if self.observation.event_type != self.event_type:
            raise ValueError("stream event observation.event_type must match event_type")
        return self


class StreamDuplicateSummary(PersistedArtifact):
    artifact_kind: Literal["stream-duplicate-summary"] = "stream-duplicate-summary"
    composite_key: tuple[str, ...]
    kept_event_id: str = Field(min_length=1)
    duplicate_event_ids: tuple[str, ...] = ()
    duplicate_count: int = Field(ge=1)
    digest: DigestHex

    @field_validator("composite_key", "duplicate_event_ids", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class StreamIngestionDiagnostics(PersistedArtifact):
    artifact_kind: Literal["stream-ingestion-diagnostics"] = (
        "stream-ingestion-diagnostics"
    )
    stream_id: str = Field(min_length=1)
    sequence_contract: StreamSequenceContract
    source_event_count: int = Field(ge=0)
    accepted_event_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    run_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    duplicates: tuple[StreamDuplicateSummary, ...] = ()

    @field_validator("run_ids", "diagnostics", "duplicates", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class StreamRunRecord(PersistedArtifact):
    artifact_kind: Literal["stream-run"] = "stream-run"
    stream_id: str = Field(min_length=1)
    sequence_contract: StreamSequenceContract
    source_event_count: int = Field(ge=0)
    accepted_event_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    run_ids: tuple[str, ...] = Field(min_length=1)
    case_ids: tuple[str, ...] = ()
    events: tuple[StreamEventRecord, ...] = Field(min_length=1)
    usage_ledger: UsageLedger | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    usage_summary: UsageSummary | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    @field_validator("run_ids", "case_ids", "events", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_stream_run(self) -> StreamRunRecord:
        event_run_ids = tuple(sorted({event.run_id for event in self.events}))
        if self.run_ids != event_run_ids:
            raise ValueError("stream run run_ids must match event run_ids")
        event_case_ids = tuple(
            sorted({event.case_id for event in self.events if event.case_id is not None})
        )
        if self.case_ids != event_case_ids:
            raise ValueError("stream run case_ids must match event case_ids")
        if self.accepted_event_count != len(self.events):
            raise ValueError("stream run accepted_event_count must match events")
        case_ids_by_run: dict[str, set[str]] = {}
        for event in self.events:
            if event.case_id is not None:
                case_ids_by_run.setdefault(event.run_id, set()).add(event.case_id)
        conflicting = sorted(
            run_id for run_id, case_ids in case_ids_by_run.items() if len(case_ids) > 1
        )
        if conflicting:
            raise ValueError(
                "stream run events must not mix case_id values within a run_id: "
                + ", ".join(conflicting)
            )
        validate_usage_summary_consistency(
            self.usage_ledger,
            self.usage_summary,
            owner="stream run",
        )
        return self
