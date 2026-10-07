from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.adapters.base import (
    FrameworkObservation,
    validate_privacy_filtered_mapping,
    validate_privacy_filtered_usage_segment,
)
from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact, StrictModel
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_PATTERN,
    MAX_LABEL_CHARS,
    MAX_SUMMARY_CHARS,
    PROVIDER_MODEL_IDENTIFIER_PATTERN,
    STRICT_RFC3339_TIMESTAMP_PATTERN,
    DigestHex,
    coerce_tuple,
    validate_machine_identifier,
    validate_provider_model_identifier,
)
from agent_assure.schema.usage import (
    UsageLedger,
    UsageSegment,
    UsageSummary,
    validate_usage_summary_consistency,
)
from agent_assure.telemetry.context import TRACEPARENT_FIELD_PATTERN, validate_traceparent

StreamSequenceScope = Literal["global", "producer_local"]
StreamProducerField = Literal["producer_id", "node_id", "span_id"]
StreamLabel = Annotated[str, Field(max_length=MAX_LABEL_CHARS)]
StreamRequiredLabel = Annotated[str, Field(min_length=1, max_length=MAX_LABEL_CHARS)]
StreamSummary = Annotated[str, Field(max_length=MAX_SUMMARY_CHARS)]
StreamTimestamp = Annotated[
    str,
    Field(max_length=MAX_LABEL_CHARS, pattern=STRICT_RFC3339_TIMESTAMP_PATTERN),
]
_CURRENT_STREAM_SCHEMA_VERSION = SCHEMA_VERSION
_USAGE_MACHINE_IDENTIFIER_JSON_SCHEMA: dict[str, object] = {
    "minLength": 1,
    "maxLength": MACHINE_IDENTIFIER_MAX_CHARS,
    "pattern": MACHINE_IDENTIFIER_PATTERN.removesuffix("$") + r"(?![\s\S])",
}


_USAGE_PROVIDER_MODEL_IDENTIFIER_JSON_SCHEMA: dict[str, object] = {
    "minLength": 1,
    "maxLength": MACHINE_IDENTIFIER_MAX_CHARS,
    "pattern": PROVIDER_MODEL_IDENTIFIER_PATTERN.removesuffix("$") + r"(?![\s\S])",
}


def _usage_machine_identifier_properties() -> dict[str, dict[str, object]]:
    return {
        "provider": dict(_USAGE_MACHINE_IDENTIFIER_JSON_SCHEMA),
        "model": dict(_USAGE_PROVIDER_MODEL_IDENTIFIER_JSON_SCHEMA),
    }


_STREAM_EVENT_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "$comment": (
        "A current stream-event parent revalidates provider and model identifiers "
        "on its usage segment even when that segment declares a legacy schema version."
    ),
    "allOf": [
        {
            "if": {
                "properties": {
                    "schema_version": {"const": _CURRENT_STREAM_SCHEMA_VERSION},
                },
            },
            "then": {
                "properties": {
                    "usage_segment": {
                        "properties": _usage_machine_identifier_properties(),
                    }
                }
            },
        }
    ],
}
_STREAM_RUN_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "$comment": (
        "A current stream-run parent revalidates provider and model identifiers "
        "across legacy event usage segments and legacy usage ledgers."
    ),
    "allOf": [
        {
            "if": {
                "properties": {
                    "schema_version": {"const": _CURRENT_STREAM_SCHEMA_VERSION},
                },
            },
            "then": {
                "properties": {
                    "events": {
                        "items": {
                            "properties": {
                                "usage_segment": {
                                    "properties": _usage_machine_identifier_properties(),
                                }
                            }
                        }
                    },
                    "usage_ledger": {
                        "properties": {
                            "segments": {
                                "items": {
                                    "properties": _usage_machine_identifier_properties(),
                                }
                            }
                        }
                    },
                }
            },
        }
    ],
}


def _validate_usage_machine_identifiers(
    segment: UsageSegment,
    *,
    field_prefix: str,
) -> None:
    if segment.provider is not None:
        validate_machine_identifier(
            segment.provider,
            field_name=f"{field_prefix}.provider",
        )
    if segment.model is not None:
        validate_provider_model_identifier(
            segment.model,
            field_name=f"{field_prefix}.model",
        )


def parse_stream_timestamp_utc(value: str, *, owner: str) -> datetime:
    text = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{owner} timestamp must use strict RFC 3339 date-time syntax") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{owner} timestamp must include timezone")
    if re.fullmatch(STRICT_RFC3339_TIMESTAMP_PATTERN, value) is None:
        raise ValueError(f"{owner} timestamp must use strict RFC 3339 date-time syntax")
    return parsed.astimezone(UTC)


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
    model_config = ConfigDict(json_schema_extra=_STREAM_EVENT_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["stream-event-record"] = "stream-event-record"
    event_id: StreamRequiredLabel
    run_id: StreamRequiredLabel
    case_id: StreamLabel | None = None
    producer_id: StreamLabel | None = None
    node_id: StreamLabel | None = None
    sequence_number: int = Field(ge=0)
    timestamp: StreamTimestamp | None = None
    event_type: StreamRequiredLabel

    observation: FrameworkObservation | None = None
    usage_segment: UsageSegment | None = None

    span_id: StreamLabel | None = None
    parent_span_id: StreamLabel | None = None
    traceparent: str | None = Field(
        default=None,
        max_length=MAX_LABEL_CHARS,
        pattern=TRACEPARENT_FIELD_PATTERN,
    )
    privacy_filtered_attributes: dict[StreamLabel, StreamSummary] = Field(default_factory=dict)
    digest: DigestHex

    @field_validator("traceparent")
    @classmethod
    def _validate_traceparent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_traceparent(value)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, value: object) -> object:
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        parse_stream_timestamp_utc(value, owner="stream event")
        return value

    @model_validator(mode="after")
    def _validate_event(self) -> StreamEventRecord:
        validate_privacy_filtered_mapping(
            self.privacy_filtered_attributes,
            owner="stream privacy_filtered_attributes",
        )
        if self.usage_segment is not None:
            if self.schema_version == _CURRENT_STREAM_SCHEMA_VERSION:
                _validate_usage_machine_identifiers(
                    self.usage_segment,
                    field_prefix="usage_segment",
                )
            validate_privacy_filtered_usage_segment(self.usage_segment)
        if self.observation is None:
            return self
        if self.observation.run_id != self.run_id:
            raise ValueError("stream event observation.run_id must match run_id")
        if self.observation.sequence_number != self.sequence_number:
            raise ValueError("stream event observation.sequence_number must match sequence_number")
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
    composite_key: tuple[StreamLabel, ...]
    kept_event_id: StreamRequiredLabel
    duplicate_event_ids: tuple[StreamLabel, ...] = ()
    duplicate_count: int = Field(ge=1)
    digest: DigestHex

    @field_validator("composite_key", "duplicate_event_ids", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class StreamIngestionDiagnostics(PersistedArtifact):
    artifact_kind: Literal["stream-ingestion-diagnostics"] = "stream-ingestion-diagnostics"
    stream_id: StreamRequiredLabel
    sequence_contract: StreamSequenceContract
    source_event_count: int = Field(ge=0)
    accepted_event_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    run_ids: tuple[StreamLabel, ...] = ()
    diagnostics: tuple[StreamSummary, ...] = ()
    duplicates: tuple[StreamDuplicateSummary, ...] = ()

    @field_validator("run_ids", "diagnostics", "duplicates", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class StreamRunRecord(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_STREAM_RUN_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["stream-run"] = "stream-run"
    stream_id: StreamRequiredLabel
    sequence_contract: StreamSequenceContract
    source_event_count: int = Field(ge=0)
    accepted_event_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    run_ids: tuple[StreamLabel, ...] = Field(min_length=1)
    case_ids: tuple[StreamLabel, ...] = ()
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
        if self.schema_version == _CURRENT_STREAM_SCHEMA_VERSION:
            for event_index, event in enumerate(self.events):
                if event.usage_segment is not None:
                    _validate_usage_machine_identifiers(
                        event.usage_segment,
                        field_prefix=f"events[{event_index}].usage_segment",
                    )
            if self.usage_ledger is not None:
                for segment_index, segment in enumerate(self.usage_ledger.segments):
                    _validate_usage_machine_identifiers(
                        segment,
                        field_prefix=f"usage_ledger.segments[{segment_index}]",
                    )
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
