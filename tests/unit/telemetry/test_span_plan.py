from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.telemetry import MAX_OTEL_EVENTS
from agent_assure.telemetry.otel_mapping import run_record_to_span_plan


def _record() -> AgentRunRecord:
    return AgentRunRecord.model_validate_json(
        Path("tests/fixtures/run_record.json").read_text(encoding="utf-8")
    )


def test_span_plan_omits_unsupported_attributes() -> None:
    plan = run_record_to_span_plan(_record())
    dumped = json.dumps(plan.model_dump(mode="json"))
    assert "gen_ai.response.tokens" not in dumped
    assert "rpc.method" not in dumped
    assert "gen_ai.operation.name" not in dumped
    assert any(attribute.key == "agent_assure.operation.name" for attribute in plan.attributes)
    assert plan.traceparent is not None
    assert plan.traceparent.startswith("00-")


def test_span_plan_redacts_summaries() -> None:
    record = _record().model_copy(
        update={
            "input_summary": "patient=Jane ssn: 123-45-6789",
            "output_summary": "email jane@example.com",
        }
    )
    plan = run_record_to_span_plan(record)
    dumped = json.dumps(plan.model_dump(mode="json"))
    assert "123-45-6789" not in dumped
    assert "jane@example.com" not in dumped
    assert "[REDACTED]" in dumped


def test_span_plan_redacts_identifier_attributes() -> None:
    record = _record().model_copy(
        update={
            "run_id": "jane@example.com",
            "case_id": "patient: Jane Example",
            "pipeline_id": "api_key=abcdefghijklmnop",
        }
    )

    dumped = json.dumps(run_record_to_span_plan(record).model_dump(mode="json"))

    assert "jane@example.com" not in dumped
    assert "Jane Example" not in dumped
    assert "abcdefghijklmnop" not in dumped
    assert "[REDACTED]" in dumped


def test_span_plan_rejects_run_with_too_many_tool_events() -> None:
    record = _record().model_copy(
        update={"tools": tuple(f"tool-{index}" for index in range(MAX_OTEL_EVENTS + 1))}
    )

    with pytest.raises(ValueError, match="event limit"):
        run_record_to_span_plan(record)
