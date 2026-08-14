from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import redact_run_record_payload
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_SCHEMA_VERSION,
    ExecutionMode,
)
from agent_assure.schema.export import writer_json_schema
from agent_assure.schema.live import (
    DriftComparabilityResult,
    DriftWindowSummary,
    LiveObservationResult,
)
from agent_assure.schema.run import AgentRunRecord, EvidenceItem, EvidenceRef, RunSet
from agent_assure.schema.validation import validate_artifact_payload

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
        cost_budget_committed_usd="0.000000",
        generated_token_budget_committed=0,
        total_token_budget_committed=0,
    )
    assert record.execution_mode is ExecutionMode.live


@pytest.mark.parametrize("model", (EvidenceRef, EvidenceItem))
@pytest.mark.parametrize("field_name", ("ref_id", "source_id"))
@pytest.mark.parametrize(
    "invalid_value",
    (
        pytest.param("", id="empty"),
        pytest.param("   ", id="blank"),
        pytest.param(" padded ", id="padded"),
        pytest.param("unsafe\x00identifier", id="control"),
        pytest.param("unsafe\u202eidentifier", id="bidi-control"),
        pytest.param("unsafe\ue000identifier", id="private-use"),
        pytest.param("unsafe\u0378identifier", id="unassigned"),
        pytest.param("unsafe\U0001bca0identifier", id="shorthand-format-control"),
        pytest.param("unsafe\U000110bdidentifier", id="kaithi-number-sign"),
        pytest.param("x" * (MACHINE_IDENTIFIER_MAX_CHARS + 1), id="oversized"),
    ),
)
def test_current_evidence_identifiers_are_bounded_nonblank_and_control_safe(
    model: type[EvidenceRef] | type[EvidenceItem],
    field_name: str,
    invalid_value: str,
) -> None:
    payload: dict[str, object] = {
        "artifact_kind": model.model_fields["artifact_kind"].default,
        "schema_version": MACHINE_IDENTIFIER_SCHEMA_VERSION,
        "ref_id": "ref-safe",
        "source_id": "source-safe",
    }
    if model is EvidenceItem:
        payload["content_digest"] = "0" * 64
    payload[field_name] = invalid_value

    with pytest.raises(ValidationError):
        model.model_validate(payload)
    for schema in (
        model.model_json_schema(mode="validation"),
        writer_json_schema(model),
    ):
        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(schema).validate(payload)


@pytest.mark.parametrize("model", (EvidenceRef, EvidenceItem))
@pytest.mark.parametrize(
    "valid_value",
    (
        "a",
        "source:namespace/path.segment_value-1",
        "x" * MACHINE_IDENTIFIER_MAX_CHARS,
    ),
)
def test_current_evidence_identifier_grammar_has_model_and_schema_parity(
    model: type[EvidenceRef] | type[EvidenceItem],
    valid_value: str,
) -> None:
    payload: dict[str, object] = {
        "artifact_kind": model.model_fields["artifact_kind"].default,
        "schema_version": MACHINE_IDENTIFIER_SCHEMA_VERSION,
        "ref_id": valid_value,
        "source_id": valid_value,
    }
    if model is EvidenceItem:
        payload["content_digest"] = "0" * 64

    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    Draft202012Validator(writer_json_schema(model)).validate(payload)


@pytest.mark.parametrize("model", (EvidenceRef, EvidenceItem))
def test_evidence_identifier_compatibility_schema_retains_v060_values(
    model: type[EvidenceRef] | type[EvidenceItem],
) -> None:
    payload: dict[str, object] = {
        "artifact_kind": model.model_fields["artifact_kind"].default,
        "schema_version": "0.6.0",
        "ref_id": " padded ",
        "source_id": "legacy\ue000source",
    }
    if model is EvidenceItem:
        payload["content_digest"] = "0" * 64

    model.model_validate(payload)
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(model)).validate(payload)


def test_frozen_v060_runset_retains_legacy_unbounded_evidence_identifiers() -> None:
    legacy_ref = EvidenceRef(
        schema_version="0.6.0",
        ref_id=" padded ",
        source_id="legacy\u202esource",
    )
    legacy_item = EvidenceItem(
        schema_version="0.6.0",
        ref_id=" padded ",
        source_id="legacy\u202esource",
        content_digest="0" * 64,
    )
    legacy_record = _record(
        schema_version="0.6.0",
        evidence_refs=(legacy_ref,),
        evidence_items=(legacy_item,),
    )
    legacy_runset = RunSet(
        schema_version="0.6.0",
        runset_id="runset-legacy-identifiers",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="suite-001",
        suite_version="0.6.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        runs=(legacy_record,),
    )
    payload = legacy_runset.model_dump(mode="json")
    pending: list[object] = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "schema_version" in value:
                value["schema_version"] = "0.6.0"
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)

    assert validate_artifact_payload(payload, "run-set") == "frozen-jsonschema"


@pytest.mark.parametrize("schema_version", ("0.6.0", "0.6.1", "0.6.2"))
def test_v06_live_mode_requires_committed_budget_fields(schema_version: str) -> None:
    with pytest.raises(ValidationError, match="cost_budget_committed_usd"):
        _record(
            schema_version=schema_version,
            execution_mode="live",
            observation_id="obs-001",
            repetition_index=0,
            schedule_index=0,
            cluster_id="case-001",
            adapter_id="static-jsonl",
        )


@pytest.mark.parametrize("schema_version", ("0.6.0", "0.6.1", "0.6.2"))
def test_v06_live_observations_require_pairing_identity(schema_version: str) -> None:
    with pytest.raises(ValidationError, match="prompt, schedule, and randomization identity"):
        LiveObservationResult(
            schema_version=schema_version,
            observation_id="obs-001",
            run_id="run-001",
            case_id="case-001",
            repetition_index=0,
            pipeline_id="pipeline",
            cluster_id="case-001",
            tool_schema_digest="0" * 64,
            policy_bundle_digest="1" * 64,
            state="pass",
        )


@pytest.mark.parametrize("schema_version", ("0.6.0", "0.6.1", "0.6.2"))
def test_v06_drift_windows_require_configuration_digest(schema_version: str) -> None:
    with pytest.raises(ValidationError, match="configuration_digest"):
        DriftWindowSummary(
            schema_version=schema_version,
            window_id="window-001",
            window_index=0,
            runset_id="runset-001",
            suite_id="suite-001",
            suite_version="0.6.0",
            analysis_method="cluster_t_interval",
            observations=0,
            included_observations=0,
            excluded_observations=0,
        )


@pytest.mark.parametrize("schema_version", ("0.6.0", "0.6.1", "0.6.2"))
def test_v06_drift_comparability_requires_configuration_match(
    schema_version: str,
) -> None:
    with pytest.raises(ValidationError, match="configuration_digest_matches"):
        DriftComparabilityResult(
            schema_version=schema_version,
            status="invalid",
            compared_windows=0,
            suite_matches=False,
            baseline_mode_matches=False,
            analysis_method_matches=False,
            protocol_digest_matches=False,
            material_fields_match=False,
            tool_schema_digest_matches=False,
            policy_bundle_digest_matches=False,
        )


def test_run_timestamps_are_calendar_valid_rfc3339() -> None:
    record = _record(
        started_at_utc="2026-07-21T12:34:56.123456Z",
        completed_at_utc="2026-07-21T08:34:57-04:00",
    )
    assert record.started_at_utc == "2026-07-21T12:34:56.123456Z"

    with pytest.raises(ValidationError, match="valid RFC 3339 date-time"):
        _record(started_at_utc="2026-02-31T12:00:00Z")


@pytest.mark.parametrize(
    "timestamp",
    ("2026-07-21T12:00:00", "patient: Alice", "2026-7-21T12:00:00Z"),
)
def test_run_timestamp_shape_has_model_and_jsonschema_parity(timestamp: str) -> None:
    payload = _record().model_dump(mode="json")
    payload["started_at_utc"] = timestamp

    with pytest.raises(ValidationError):
        AgentRunRecord.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(AgentRunRecord.model_json_schema(mode="validation")).validate(payload)


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


@pytest.mark.parametrize("value", (1 << 53, -(1 << 53)))
def test_persisted_artifacts_reject_integers_outside_rfc8785_domain(value: int) -> None:
    with pytest.raises(ValidationError, match="RFC 8785 safe integer domain"):
        _record(latency_ms=value)


def test_persisted_artifacts_accept_rfc8785_integer_boundaries() -> None:
    assert _record(latency_ms=(1 << 53) - 1).latency_ms == (1 << 53) - 1


def test_run_record_rejects_inconsistent_zero_token_components() -> None:
    with pytest.raises(
        ValidationError,
        match="total_tokens must equal prompt_tokens \\+ completion_tokens",
    ):
        _record(prompt_tokens=0, completion_tokens=0, total_tokens=7)


def test_run_record_accepts_partial_token_components_bounded_by_total() -> None:
    record = _record(prompt_tokens=3, completion_tokens=None, total_tokens=7)

    assert record.prompt_tokens == 3
    assert record.completion_tokens is None
    assert record.total_tokens == 7


def test_run_record_rejects_partial_token_components_above_total() -> None:
    with pytest.raises(
        ValidationError,
        match="observed token components cannot exceed total_tokens",
    ):
        _record(prompt_tokens=8, completion_tokens=None, total_tokens=7)


def test_fixture_runset_rejects_live_run_records() -> None:
    live_record = _record(
        execution_mode="live",
        observation_id="obs-001",
        repetition_index=0,
        schedule_index=0,
        cluster_id="case-001",
        adapter_id="static-jsonl",
        cost_budget_committed_usd="0.000000",
        generated_token_budget_committed=0,
        total_token_budget_committed=0,
    )

    with pytest.raises(
        ValidationError,
        match="fixture run sets may contain only fixture run records",
    ):
        RunSet(
            artifact_kind="run-set",
            runset_id="runset-mixed",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            suite_id="suite-001",
            suite_version="0.1.0",
            suite_digest="0" * 64,
            fixture_manifest_digest="1" * 64,
            runs=(live_record,),
        )


def test_live_runset_rejects_fixture_run_records() -> None:
    with pytest.raises(
        ValidationError,
        match="live run sets may contain only live run records",
    ):
        RunSet(
            artifact_kind="run-set",
            runset_id="runset-mixed",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            suite_id="suite-001",
            suite_version="0.1.0",
            suite_digest="0" * 64,
            fixture_manifest_digest="1" * 64,
            execution_mode="live",
            protocol_id="protocol-001",
            protocol_digest="2" * 64,
            runs=(_record(),),
        )


@pytest.mark.parametrize("identity_field", ("artifact_kind", "schema_version"))
def test_raw_runset_requires_explicit_persisted_identity(identity_field: str) -> None:
    payload = RunSet.model_construct(
        runset_id="runset-001",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="suite-001",
        suite_version="0.1.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        runs=(),
    ).model_dump(mode="json")
    del payload[identity_field]

    with pytest.raises(ValueError, match="explicit identity fields before parsing"):
        validate_artifact_payload(payload, "run-set")
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(RunSet.model_json_schema(mode="validation")).validate(payload)


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
        (ROOT / "schemas" / "v0.4.3" / "run-set.schema.json").read_text(encoding="utf-8")
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
