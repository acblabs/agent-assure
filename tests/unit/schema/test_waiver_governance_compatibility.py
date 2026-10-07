from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from agent_assure.ci import gate_evaluation_summary
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.validation import ArchivalOnlyArtifactError, validate_artifact_payload


def _waiver_governance() -> dict[str, str]:
    return {
        "owner": "risk-owner",
        "reviewer": "independent-reviewer",
        "rationale": "Approved for deterministic regression coverage.",
    }


def _evaluation_summary_payload(
    schema_version: str | None,
    *,
    include_governance: bool,
) -> dict[str, Any]:
    nested_version = schema_version or "0.6.6"
    waiver: dict[str, Any] = {
        "waiver_id": "waiver-1",
        "reason_code": "POLICY_FAILED",
        "finding_id": "finding-1",
        "artifact_digest": "b" * 64,
        "expires_on": "2026-01-02",
    }
    if include_governance:
        waiver.update(_waiver_governance())
    payload: dict[str, Any] = {
        "artifact_kind": "evaluation-summary",
        "runset_id": "runset-1",
        "runset_digest": "b" * 64,
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "state": "warn",
        "findings": [
            {
                "artifact_kind": "finding",
                "schema_version": nested_version,
                "finding_id": "finding-1",
                "case_id": "case-1",
                "state": "warn",
                "reason_code": "POLICY_FAILED",
                "message": "waived",
            }
        ],
        "replay_context": {
            "suite_digest": "a" * 64,
            "gate_profile": {
                "profile_id": "default",
                "fail_severities": ["error"],
                "fail_reason_codes": [],
                "fail_on_warn": False,
                "fail_on_not_evaluated": False,
            },
            "waivers": [waiver],
            "evaluation_date": "2026-01-01",
            "report_mode": "full",
        },
    }
    if schema_version is not None:
        payload["schema_version"] = schema_version
    return payload


def _evaluation_report_payload(
    schema_version: str | None,
    *,
    include_summary_governance: bool,
    include_disposition_governance: bool,
) -> dict[str, Any]:
    disposition: dict[str, Any] = {
        "waiver_id": "waiver-1",
        "status": "matched",
        "reason_code": "POLICY_FAILED",
        "finding_id": "finding-1",
        "expires_on": "2026-01-02",
    }
    if include_disposition_governance:
        disposition.update(_waiver_governance())
    summary_version = schema_version or "0.6.6"
    payload: dict[str, Any] = {
        "artifact_kind": "evaluation-report",
        "candidate_vs_expectations": _evaluation_summary_payload(
            summary_version,
            include_governance=include_summary_governance,
        ),
        "runset_id": "runset-1",
        "runset_digest": "b" * 64,
        "suite_id": "suite-1",
        "suite_version": "1",
        "gate_profile": "default",
        "metrics": {
            "total_cases": 1,
            "evaluated_cases": 1,
            "unevaluated_cases": 0,
            "passed_cases": 0,
            "warning_cases": 1,
            "failed_cases": 0,
            "warning_findings": 1,
            "blocking_findings": 0,
            "global_blocking_findings": 0,
            "findings_by_reason": {"POLICY_FAILED": 1},
            "findings_by_control": {"": 1},
        },
        "warning_controls": [
            {
                "artifact_kind": "finding",
                "schema_version": summary_version,
                "finding_id": "finding-1",
                "case_id": "case-1",
                "state": "warn",
                "reason_code": "POLICY_FAILED",
                "message": "waived",
            }
        ],
        "waiver_dispositions": [disposition],
    }
    if summary_version != "0.6.6":
        # warning_cases was added to the current arithmetic contract and must
        # not be projected into the frozen v0.6.5 schema.
        payload["metrics"].pop("warning_cases")
    else:
        payload["source_projection"] = {
            "suite_id": "suite-1",
            "suite_version": "1",
            "suite_digest": "a" * 64,
            "runset_id": "runset-1",
            "runset_digest": "b" * 64,
            "cases": [
                {
                    "case_id": "case-1",
                    "run_record_count": 1,
                    "record_status": "included",
                }
            ],
            "unknown_run_case_ids": [],
            "tool_policy_configured": True,
        }
        payload["case_outcomes"] = [{"case_id": "case-1", "state": "warn"}]
        payload["capability_coverage"] = [
            {
                "capability_id": "raw_payload_persistence_forbidden",
                "state": "not_evaluated",
                "reason": (
                    "runset writers redact summary fields and evaluation checks raw summaries, "
                    "but no evaluator policy inspects external raw payload storage"
                ),
            },
            {
                "capability_id": "live_stochastic_model_quality_regression",
                "state": "not_evaluated",
                "reason": "fixture mode does not run live stochastic model comparisons",
            },
            {
                "capability_id": "production_runtime_isolation",
                "state": "not_evaluated",
                "reason": "offline run records do not observe production sandbox isolation",
            },
            {
                "capability_id": "regulatory_compliance_certification",
                "state": "not_evaluated",
                "reason": "deterministic checks do not certify legal or regulatory compliance",
            },
            {
                "capability_id": "tool_allowlist",
                "state": "pass",
                "reason": (
                    "suite or case expectations configure a tool policy; per-case evaluation "
                    "is reported separately"
                ),
            },
        ]
        payload["not_evaluated_capabilities"] = payload["capability_coverage"][:4]
    if schema_version is not None:
        payload["schema_version"] = schema_version
    return payload


def _allow_omitted_default_version(schema: dict[str, Any]) -> None:
    schema["required"] = [
        field_name for field_name in schema["required"] if field_name != "schema_version"
    ]


def test_v065_waiver_governance_projection_remains_compatible() -> None:
    payload = _evaluation_report_payload(
        "0.6.5",
        include_summary_governance=False,
        include_disposition_governance=False,
    )
    legacy_expiry = "2027-01-02"
    payload["candidate_vs_expectations"]["replay_context"]["waivers"][0]["expires_on"] = (
        legacy_expiry
    )
    payload["waiver_dispositions"][0]["expires_on"] = legacy_expiry
    schema_root = Path(__file__).resolve().parents[3] / "schemas" / "v0.6.5"
    frozen_report_schema = json.loads(
        (schema_root / "evaluation-report.schema.json").read_text(encoding="utf-8")
    )
    frozen_summary_schema = json.loads(
        (schema_root / "evaluation-summary.schema.json").read_text(encoding="utf-8")
    )

    Draft202012Validator(frozen_report_schema).validate(payload)
    Draft202012Validator(frozen_summary_schema).validate(payload["candidate_vs_expectations"])
    with pytest.raises(ArchivalOnlyArtifactError, match="archival-only"):
        validate_artifact_payload(payload, "evaluation-report")
    report = EvaluationReport.model_validate(payload)
    Draft202012Validator(EvaluationReport.model_json_schema(mode="validation")).validate(payload)

    assert report.waiver_dispositions[0].owner == ""
    assert report.candidate_vs_expectations.replay_context is not None
    assert report.candidate_vs_expectations.replay_context.waivers[0].owner == ""
    round_trip = report.model_dump(mode="json")
    assert "owner" not in round_trip["waiver_dispositions"][0]
    replay_context = round_trip["candidate_vs_expectations"]["replay_context"]
    assert "owner" not in replay_context["waivers"][0]


def test_v065_waiver_remains_parseable_but_cannot_authorize_strict_ci() -> None:
    payload = _evaluation_summary_payload("0.6.5", include_governance=False)
    payload["replay_context"]["waivers"][0]["expires_on"] = "9999-12-31"

    summary = EvaluationSummary.model_validate(payload)
    assert summary.replay_context is not None
    assert summary.replay_context.waivers[0].owner == ""

    decision = gate_evaluation_summary(summary, fail_on_warn=True)

    assert decision.exit_code == 1
    assert decision.outcome.value == "fail"
    assert decision.waiver_authorization.value == "not_applicable"
    assert "archival-only and cannot authorize strict CI" in decision.message
    assert "authorized-exact-waiver" not in decision.message

    non_strict_decision = gate_evaluation_summary(summary)
    assert non_strict_decision.exit_code == 2
    assert non_strict_decision.outcome.value == "invalid"


@pytest.mark.parametrize("schema_version", ("0.6.6", None))
def test_current_summary_owns_waiver_expiry_horizon(
    schema_version: str | None,
) -> None:
    payload = _evaluation_summary_payload(schema_version, include_governance=True)
    payload["replay_context"]["waivers"][0]["expires_on"] = "2026-04-02"
    schema = EvaluationSummary.model_json_schema(mode="validation")
    if schema_version is None:
        _allow_omitted_default_version(schema)

    with pytest.raises(PydanticValidationError, match="no more than 90 days"):
        EvaluationSummary.model_validate(payload)

    # Draft 2020-12 cannot compare the two dates, so the parent schema explicitly
    # delegates this relational constraint to runtime model validation.
    Draft202012Validator(schema).validate(payload)
    assert "cannot compare date-valued sibling fields" in json.dumps(schema, sort_keys=True)

    payload["replay_context"]["waivers"][0]["expires_on"] = "2026-04-01"
    EvaluationSummary.model_validate(payload)
    Draft202012Validator(schema).validate(payload)


@pytest.mark.parametrize("schema_version", ("0.6.6", None))
def test_current_summary_requires_waiver_governance_in_model_and_schema(
    schema_version: str | None,
) -> None:
    payload = _evaluation_summary_payload(schema_version, include_governance=False)
    schema = EvaluationSummary.model_json_schema(mode="validation")
    if schema_version is None:
        _allow_omitted_default_version(schema)

    with pytest.raises(PydanticValidationError, match="requires waiver governance fields"):
        EvaluationSummary.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(payload)

    payload["replay_context"]["waivers"][0].update(_waiver_governance())
    EvaluationSummary.model_validate(payload)
    Draft202012Validator(schema).validate(payload)


@pytest.mark.parametrize("schema_version", ("0.6.6", None))
def test_current_report_requires_disposition_governance_in_model_and_schema(
    schema_version: str | None,
) -> None:
    payload = _evaluation_report_payload(
        schema_version,
        include_summary_governance=True,
        include_disposition_governance=False,
    )
    schema = EvaluationReport.model_json_schema(mode="validation")
    if schema_version is None:
        _allow_omitted_default_version(schema)

    with pytest.raises(PydanticValidationError, match="requires waiver governance fields"):
        EvaluationReport.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(payload)

    payload["waiver_dispositions"][0].update(_waiver_governance())
    EvaluationReport.model_validate(payload)
    Draft202012Validator(schema).validate(payload)


def test_current_parent_preserves_runtime_reviewer_independence_check() -> None:
    payload = _evaluation_summary_payload("0.6.6", include_governance=True)
    waiver = payload["replay_context"]["waivers"][0]
    waiver["owner"] = "RiskOwner"
    waiver["reviewer"] = "riskowner"

    with pytest.raises(PydanticValidationError, match="different identities"):
        EvaluationSummary.model_validate(payload)

    schema = EvaluationSummary.model_json_schema(mode="validation")
    Draft202012Validator(schema).validate(payload)
    assert "runtime model constraints" in json.dumps(schema, sort_keys=True)


def test_current_report_parent_preserves_runtime_reviewer_independence_check() -> None:
    payload = _evaluation_report_payload(
        "0.6.6",
        include_summary_governance=True,
        include_disposition_governance=True,
    )
    disposition = payload["waiver_dispositions"][0]
    disposition["owner"] = "RiskOwner"
    disposition["reviewer"] = "riskowner"

    with pytest.raises(PydanticValidationError, match="different identities"):
        EvaluationReport.model_validate(payload)

    schema = EvaluationReport.model_json_schema(mode="validation")
    Draft202012Validator(schema).validate(payload)
    assert "runtime model constraints" in json.dumps(schema, sort_keys=True)
