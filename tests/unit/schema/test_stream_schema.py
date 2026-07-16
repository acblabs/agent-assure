from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from agent_assure.schema.common import MAX_LABEL_CHARS, MAX_SUMMARY_CHARS
from agent_assure.schema.export import SCHEMA_MODELS
from agent_assure.schema.stream import StreamEventRecord
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
