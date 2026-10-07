from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from agent_assure.schema.common import MAX_LABEL_CHARS, MAX_SUMMARY_CHARS
from agent_assure.schema.export import SCHEMA_MODELS
from agent_assure.schema.stream import StreamEventRecord, StreamRunRecord
from agent_assure.schema.usage import USAGE_SEGMENT_SUM_FIELDS
from agent_assure.schema.validation import validate_artifact
from agent_assure.streaming.ingestion import ingest_jsonl_events


def test_stream_artifacts_match_pydantic_and_jsonschema(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(
        json.dumps(
            {
                "event_id": "evt-stream-001",
                "run_id": "run-stream-001",
                "case_id": "stream-case",
                "sequence_number": 1,
                "timestamp": "2026-07-14T00:00:01Z",
                "event_type": "run_completed",
                "privacy_filtered_attributes": {
                    "recommendation": "approve",
                    "outcome": "approved",
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    result = ingest_jsonl_events(events_path, sequence_scope="global")

    for artifact_kind, artifact in (
        ("stream-run", result.stream_run),
        ("stream-ingestion-diagnostics", result.diagnostics),
        ("stream-event-record", result.stream_run.events[0]),
    ):
        payload = artifact.model_dump(mode="json")
        model = SCHEMA_MODELS[artifact_kind]
        model.model_validate(payload)
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
        path = tmp_path / f"{artifact_kind}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert validate_artifact(path, artifact_kind) == "pydantic+jsonschema"


def test_stream_event_direct_usage_segment_uses_privacy_filter() -> None:
    with pytest.raises(ValidationError, match="compact filtered token"):
        StreamEventRecord.model_validate(
            {
                "artifact_kind": "stream-event-record",
                "event_id": "evt-stream-usage",
                "run_id": "run-stream-001",
                "case_id": "stream-case",
                "sequence_number": 1,
                "timestamp": "2026-07-14T00:00:01Z",
                "event_type": "token_chunk_observed",
                "usage_segment": {
                    "segment_id": "raw segment identifier",
                    "total_tokens": 12,
                },
                "privacy_filtered_attributes": {},
                "digest": "a" * 64,
            }
        )


def test_stream_event_and_jsonschema_reject_naive_timestamp() -> None:
    payload = {
        "artifact_kind": "stream-event-record",
        "event_id": "evt-stream-naive-time",
        "run_id": "run-stream-001",
        "case_id": "stream-case",
        "sequence_number": 1,
        "timestamp": "2026-07-14T00:00:01",
        "event_type": "run_started",
        "privacy_filtered_attributes": {},
        "digest": "a" * 64,
    }

    with pytest.raises(ValidationError, match="timestamp must include timezone"):
        StreamEventRecord.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(StreamEventRecord.model_json_schema(mode="validation")).validate(
            payload
        )


def test_stream_event_rejects_oversized_strings() -> None:
    with pytest.raises(ValidationError, match="at most"):
        StreamEventRecord.model_validate(
            {
                "artifact_kind": "stream-event-record",
                "event_id": "x" * (MAX_LABEL_CHARS + 1),
                "run_id": "run-stream-001",
                "sequence_number": 1,
                "event_type": "run_completed",
                "privacy_filtered_attributes": {},
                "digest": "a" * 64,
            }
        )

    with pytest.raises(ValidationError, match="at most"):
        StreamEventRecord.model_validate(
            {
                "artifact_kind": "stream-event-record",
                "event_id": "evt-stream-001",
                "run_id": "run-stream-001",
                "sequence_number": 1,
                "event_type": "run_completed",
                "privacy_filtered_attributes": {
                    "summary": "x" * (MAX_SUMMARY_CHARS + 1),
                },
                "digest": "a" * 64,
            }
        )


def test_stream_run_rejects_case_id_conflict_within_run(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    events_path.write_text(
        "\n".join(
            json.dumps(event, sort_keys=True)
            for event in (
                {
                    "event_id": "evt-stream-001",
                    "run_id": "run-stream-001",
                    "case_id": "stream-case-a",
                    "sequence_number": 1,
                    "timestamp": "2026-07-14T00:00:01Z",
                    "event_type": "run_started",
                    "privacy_filtered_attributes": {},
                },
                {
                    "event_id": "evt-stream-002",
                    "run_id": "run-stream-001",
                    "case_id": "stream-case-b",
                    "sequence_number": 2,
                    "timestamp": "2026-07-14T00:00:02Z",
                    "event_type": "run_completed",
                    "privacy_filtered_attributes": {
                        "recommendation": "approve",
                        "outcome": "approved",
                    },
                },
            )
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="mix case_id values"):
        ingest_jsonl_events(events_path, sequence_scope="global")


def _stream_event_with_legacy_usage_segment_payload(
    *,
    parent_schema_version: str | None,
    provider: str = "provider-1",
    model: str = "model-1",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "stream-event-record",
        "event_id": "evt-stream-usage",
        "run_id": "run-stream-001",
        "sequence_number": 1,
        "event_type": "token_chunk_observed",
        "usage_segment": {
            "artifact_kind": "usage-segment",
            "schema_version": "0.4.3",
            "segment_id": "segment-1",
            "provider": provider,
            "model": model,
        },
        "privacy_filtered_attributes": {},
        "digest": "a" * 64,
    }
    if parent_schema_version is not None:
        payload["schema_version"] = parent_schema_version
    return payload


@pytest.mark.parametrize("field_name", ("provider", "model"))
def test_current_stream_event_revalidates_legacy_usage_machine_identifiers(
    field_name: str,
) -> None:
    identifiers = {"provider": "provider-1", "model": "model-1"}
    identifiers[field_name] = "legacy\u200bidentifier"
    valid_payload = _stream_event_with_legacy_usage_segment_payload(
        parent_schema_version="0.6.6",
    )
    default_parent_payload = _stream_event_with_legacy_usage_segment_payload(
        parent_schema_version=None,
        **identifiers,
    )
    current_parent_payload = _stream_event_with_legacy_usage_segment_payload(
        parent_schema_version="0.6.6",
        **identifiers,
    )

    StreamEventRecord.model_validate(valid_payload)
    for payload in (default_parent_payload, current_parent_payload):
        with pytest.raises(
            ValidationError,
            match=rf"usage_segment\.{field_name} must use the ASCII machine-identifier grammar",
        ):
            StreamEventRecord.model_validate(payload)

    schema = StreamEventRecord.model_json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(valid_payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(current_parent_payload)
    default_schema = schema | {
        "required": [field for field in schema["required"] if field != "schema_version"]
    }
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(default_schema).validate(default_parent_payload)


@pytest.mark.parametrize("field_name", ("provider", "model"))
def test_current_stream_event_schema_uses_absolute_identifier_end(
    field_name: str,
) -> None:
    identifiers = {"provider": "provider-1", "model": "model-1"}
    identifiers[field_name] = "identifier\n"
    payload = _stream_event_with_legacy_usage_segment_payload(
        parent_schema_version="0.6.6",
        **identifiers,
    )

    with pytest.raises(
        ValidationError,
        match=rf"usage_segment\.{field_name} must use the ASCII machine-identifier grammar",
    ):
        StreamEventRecord.model_validate(payload)
    schema = StreamEventRecord.model_json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(payload)


@pytest.mark.parametrize(
    ("field_name", "identifier", "accepted"),
    (
        ("provider", "vertex-ai", True),
        ("provider", "vertex-ai@regional", False),
        ("model", "gemini-2.5-pro@001", True),
        ("model", "gemini-2.5-pro", True),
        ("model", "gemini-2.5-pro@", False),
        ("model", "gemini-2.5-pro@@001", False),
        ("model", "@001", False),
        ("model", "gemini-2.5-pro@001@canary", False),
    ),
)
def test_current_stream_event_identifier_grammar_has_runtime_schema_parity(
    field_name: str,
    identifier: str,
    accepted: bool,
) -> None:
    identifiers = {"provider": "vertex-ai", "model": "gemini-2.5-pro"}
    identifiers[field_name] = identifier
    payload = _stream_event_with_legacy_usage_segment_payload(
        parent_schema_version="0.6.6",
        **identifiers,
    )
    schema = StreamEventRecord.model_json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)

    if accepted:
        StreamEventRecord.model_validate(payload)
        Draft202012Validator(schema).validate(payload)
    else:
        with pytest.raises(ValidationError):
            StreamEventRecord.model_validate(payload)
        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(payload)


def test_legacy_stream_event_keeps_legacy_usage_identifiers_readable() -> None:
    payload = _stream_event_with_legacy_usage_segment_payload(
        parent_schema_version="0.6.5",
        provider="legacy\u200bprovider",
        model="legacy\u200bmodel",
    )

    event = StreamEventRecord.model_validate(payload)

    assert event.usage_segment is not None
    assert event.usage_segment.provider == "legacy\u200bprovider"
    Draft202012Validator(StreamEventRecord.model_json_schema(mode="validation")).validate(payload)


def _stream_run_with_legacy_usage_payload(
    *,
    parent_schema_version: str | None,
    event_model: str = "event-model",
    event_provider: str = "event-provider",
    ledger_model: str = "ledger-model",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "stream-run",
        "stream_id": "stream-001",
        "sequence_contract": {"scope": "global"},
        "source_event_count": 1,
        "accepted_event_count": 1,
        "duplicate_event_count": 0,
        "run_ids": ["run-stream-001"],
        "case_ids": [],
        "events": [
            _stream_event_with_legacy_usage_segment_payload(
                parent_schema_version="0.6.5",
                provider=event_provider,
                model=event_model,
            )
        ],
        "usage_ledger": {
            "artifact_kind": "usage-ledger",
            "schema_version": "0.4.3",
            "segments": [
                {
                    "artifact_kind": "usage-segment",
                    "schema_version": "0.4.3",
                    "segment_id": "ledger-segment-1",
                    "provider": "ledger-provider",
                    "model": ledger_model,
                }
            ],
            "aggregation_method": "sum_known_fields_v1",
            "missingness": {field_name: 1 for field_name in USAGE_SEGMENT_SUM_FIELDS},
        },
    }
    if parent_schema_version is not None:
        payload["schema_version"] = parent_schema_version
    return payload


@pytest.mark.parametrize(
    ("payload_overrides", "error_path"),
    (
        (
            {"event_provider": "legacy\u200bevent-provider"},
            r"events\[0\]\.usage_segment\.provider",
        ),
        (
            {"ledger_model": "legacy\u200bledger-model"},
            r"usage_ledger\.segments\[0\]\.model",
        ),
    ),
)
def test_current_stream_run_revalidates_legacy_event_and_ledger_identifiers(
    payload_overrides: dict[str, str],
    error_path: str,
) -> None:
    valid_payload = _stream_run_with_legacy_usage_payload(parent_schema_version="0.6.6")
    default_parent_payload = _stream_run_with_legacy_usage_payload(
        parent_schema_version=None,
        **payload_overrides,
    )
    current_parent_payload = _stream_run_with_legacy_usage_payload(
        parent_schema_version="0.6.6",
        **payload_overrides,
    )

    StreamRunRecord.model_validate(valid_payload)
    for payload in (default_parent_payload, current_parent_payload):
        with pytest.raises(
            ValidationError,
            match=error_path + " must use the ASCII machine-identifier grammar",
        ):
            StreamRunRecord.model_validate(payload)

    schema = StreamRunRecord.model_json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(valid_payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(current_parent_payload)
    default_schema = schema | {
        "required": [field for field in schema["required"] if field != "schema_version"]
    }
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(default_schema).validate(default_parent_payload)


def test_current_stream_run_accepts_provider_model_versions_in_nested_usage() -> None:
    payload = _stream_run_with_legacy_usage_payload(
        parent_schema_version="0.6.6",
        event_model="gemini-2.5-pro@001",
        ledger_model="claude-sonnet-4@20250514",
    )

    stream_run = StreamRunRecord.model_validate(payload)
    schema = StreamRunRecord.model_json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(payload)

    assert stream_run.events[0].usage_segment is not None
    assert stream_run.events[0].usage_segment.model == "gemini-2.5-pro@001"
    assert stream_run.usage_ledger is not None
    assert stream_run.usage_ledger.segments[0].model == "claude-sonnet-4@20250514"


def test_legacy_stream_run_keeps_legacy_event_and_ledger_identifiers_readable() -> None:
    payload = _stream_run_with_legacy_usage_payload(
        parent_schema_version="0.6.5",
        event_provider="legacy\u200bevent-provider",
        ledger_model="legacy\u200bledger-model",
    )

    stream_run = StreamRunRecord.model_validate(payload)

    assert stream_run.events[0].usage_segment is not None
    assert stream_run.events[0].usage_segment.provider == "legacy\u200bevent-provider"
    assert stream_run.usage_ledger is not None
    assert stream_run.usage_ledger.segments[0].model == "legacy\u200bledger-model"
    Draft202012Validator(StreamRunRecord.model_json_schema(mode="validation")).validate(payload)
