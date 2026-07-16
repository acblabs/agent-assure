from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import redact_run_record_payload
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.run import AgentRunRecord, RunSet

ROOT = Path(__file__).resolve().parents[3]


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
    record = _record(
        execution_mode="live",
        observation_id="obs-001",
        repetition_index=0,
        schedule_index=0,
        cluster_id="case-001",
        adapter_id="static-jsonl",
    )
    assert record.execution_mode is ExecutionMode.live


def test_runset_is_first_class_schema() -> None:
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-001",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="suite-001",
        suite_version="0.1.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        runs=(_record(),),
    )
    assert runset.artifact_kind == "run-set"


def test_current_runset_requires_explicit_privacy_profile_binding() -> None:
    with pytest.raises(ValidationError, match="privacy_profile_id"):
        RunSet(
            runset_id="runset-001",
            suite_id="suite-001",
            suite_version="0.1.0",
            suite_digest="0" * 64,
            fixture_manifest_digest="1" * 64,
            runs=(_record(),),
        )


def test_legacy_runset_dump_remains_valid_against_frozen_schema() -> None:
    runset = RunSet.model_validate(
        {
            "schema_version": "0.4.3",
            "runset_id": "runset-legacy",
            "suite_id": "suite-001",
            "suite_version": "0.1.0",
            "suite_digest": "0" * 64,
            "fixture_manifest_digest": "1" * 64,
            "runs": [],
        }
    )

    dumped = runset.model_dump(mode="json")
    assert "privacy_profile_id" not in dumped
    assert "privacy_profile_digest" not in dumped
    schema = json.loads(
        (ROOT / "schemas" / "v0.4.3" / "run-set.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(schema).validate(dumped)


def test_legacy_runset_rejects_new_privacy_profile_fields() -> None:
    with pytest.raises(ValidationError, match="does not support"):
        RunSet.model_validate(
            {
                "schema_version": "0.4.3",
                "runset_id": "runset-legacy",
                "privacy_profile_id": PRIVACY_PROFILE_ID,
                "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
                "suite_id": "suite-001",
                "suite_version": "0.1.0",
                "suite_digest": "0" * 64,
                "fixture_manifest_digest": "1" * 64,
                "runs": [],
            }
        )
