from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_assure.privacy.redaction import redact_run_record_payload
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.run import AgentRunRecord, RunSet


def _record(**overrides: object) -> AgentRunRecord:
    payload: dict[str, object] = {
        "artifact_kind": "agent-run-record",
        "run_id": "run-001",
        "case_id": "case-001",
        "execution_mode": "fixture",
        "pipeline_id": "pipeline",
        "recommendation": "approve",
        "outcome": "approve",
        "input_summary": "summary",
        "output_summary": "summary",
    }
    payload.update(overrides)
    return AgentRunRecord.model_validate(payload)


def test_persisted_artifact_is_immutable() -> None:
    record = _record()
    with pytest.raises(ValidationError):
        record.run_id = "changed"


def test_extra_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        _record(otel_attributes={})


def test_agent_run_record_has_no_persisted_otel_attributes() -> None:
    assert "otel_attributes" not in AgentRunRecord.model_fields


def test_run_record_accepts_sensitive_summaries_for_verdict_evaluation() -> None:
    record = _record(input_summary="member: Jane")
    assert record.input_summary == "member: Jane"


def test_run_record_payload_redaction_is_explicit_before_persistence() -> None:
    payload: dict[str, object] = {
        "artifact_kind": "agent-run-record",
        "run_id": "run-001",
        "case_id": "case-001",
        "execution_mode": "fixture",
        "pipeline_id": "pipeline",
        "recommendation": "approve",
        "outcome": "approve",
        "input_summary": "patient=Jane ssn: 123-45-6789",
        "output_summary": "email jane@example.com",
    }
    record = AgentRunRecord.model_validate(redact_run_record_payload(payload))
    dumped = record.model_dump_json()
    assert "123-45-6789" not in dumped
    assert "jane@example.com" not in dumped
    assert "[REDACTED]" in dumped


def test_live_mode_is_schema_recognized() -> None:
    record = _record(execution_mode="live")
    assert record.execution_mode is ExecutionMode.live


def test_runset_is_first_class_schema() -> None:
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-001",
        suite_id="suite-001",
        suite_version="0.1.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        runs=(_record(),),
    )
    assert runset.artifact_kind == "run-set"
