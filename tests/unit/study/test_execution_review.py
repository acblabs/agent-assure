from __future__ import annotations

import pytest

from agent_assure.study_artifact_serialization import published_model_json_bytes
from agent_assure.study_execution_review import (
    build_study_execution_review_receipt,
    validate_study_execution_review,
)
from tests.unit.study.test_real_model_study import _analyze, _fixture


def _receipt(fixture):  # type: ignore[no-untyped-def]
    return build_study_execution_review_receipt(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        report=_analyze(fixture),
        evidence=fixture.evidence_by_condition,
        receipt_id="public-api-execution-review",
        reviewed_at_utc="2025-04-01T00:00:00Z",
        reviewer_pseudonym="independent-api-reviewer",
        reviewer_independent_of_execution=True,
        reviewer_independence_rationale=(
            "The test reviewer did not operate or select the provider executions."
        ),
        provider_log_review_scope=(
            "The reviewer inspected all request and response events recorded by the "
            "synthetic provider log during the registered execution window."
        ),
        provider_log_evidence_digest="1234567890abcdef" * 4,
        provider_account_review_scope=(
            "The reviewer reconciled the complete synthetic account usage ledger "
            "against every attempt and terminal provider response."
        ),
        provider_account_evidence_digest="abcdef0123456789" * 4,
        provider_log_and_account_review_confirmed=True,
        provider_log_time_window_coverage_confirmed=True,
        provider_account_usage_reconciled=True,
        exhaustive_attempt_failure_retry_accounting_confirmed=True,
        provider_response_id_matches_confirmed=True,
        exact_runset_artifact_digest_matches_confirmed=True,
        provider_serving_fingerprint_availability_reviewed=True,
    )


def test_execution_review_public_api_replays_and_binds_exact_model_bytes() -> None:
    fixture = _fixture(real_provider_execution=True)
    report = _analyze(fixture)
    receipt = _receipt(fixture)

    validated = validate_study_execution_review(
        manifest=fixture.manifest,
        benchmark=fixture.benchmark,
        protocols=fixture.protocols,
        report=report,
        evidence=fixture.evidence_by_condition,
        review_receipt=receipt,
        manifest_bytes=published_model_json_bytes(fixture.manifest),
        report_bytes=published_model_json_bytes(report),
        baseline_runset_bytes={
            condition_id: published_model_json_bytes(item.baseline_runset)
            for condition_id, item in fixture.evidence_by_condition.items()
        },
        counterfactual_runset_bytes={
            condition_id: published_model_json_bytes(item.counterfactual_runset)
            for condition_id, item in fixture.evidence_by_condition.items()
        },
    )

    assert validated.receipt == receipt
    assert receipt.provider_serving_fingerprint_absence_acknowledged is True
    assert all(
        condition.provider_serving_fingerprint_status == "not_exposed_by_provider"
        for condition in receipt.conditions
    )


def test_execution_review_rejects_placeholder_provider_evidence_digest() -> None:
    fixture = _fixture(real_provider_execution=True)

    with pytest.raises(ValueError, match="commit to actual evidence bytes"):
        build_study_execution_review_receipt(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            report=_analyze(fixture),
            evidence=fixture.evidence_by_condition,
            receipt_id="placeholder-evidence-review",
            reviewed_at_utc="2025-04-01T00:00:00Z",
            reviewer_pseudonym="independent-api-reviewer",
            reviewer_independent_of_execution=True,
            reviewer_independence_rationale=(
                "The independent reviewer did not operate or select provider executions."
            ),
            provider_log_review_scope=(
                "The reviewer inspected every provider log event in the registered window."
            ),
            provider_log_evidence_digest="0" * 64,
            provider_account_review_scope=(
                "The reviewer reconciled all provider account usage against attempts."
            ),
            provider_account_evidence_digest="abcdef0123456789" * 4,
            provider_log_and_account_review_confirmed=True,
            provider_log_time_window_coverage_confirmed=True,
            provider_account_usage_reconciled=True,
            exhaustive_attempt_failure_retry_accounting_confirmed=True,
            provider_response_id_matches_confirmed=True,
            exact_runset_artifact_digest_matches_confirmed=True,
            provider_serving_fingerprint_availability_reviewed=True,
        )


@pytest.mark.parametrize("byte_input", ("manifest_bytes", "report_bytes"))
def test_execution_review_public_api_rejects_unrelated_top_level_bytes(
    byte_input: str,
) -> None:
    fixture = _fixture(real_provider_execution=True)
    values = {byte_input: b"{}\n"}

    with pytest.raises(ValueError, match="bytes do not exactly encode the supplied model"):
        validate_study_execution_review(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            report=_analyze(fixture),
            evidence=fixture.evidence_by_condition,
            review_receipt=_receipt(fixture),
            **values,  # type: ignore[arg-type]
        )


def test_execution_review_public_api_rejects_evidence_that_does_not_replay_report() -> None:
    fixture = _fixture(real_provider_execution=True)
    different = _fixture(
        responses=(False, False, False, False),
        real_provider_execution=True,
    )

    with pytest.raises(ValueError, match="does not exactly replay"):
        validate_study_execution_review(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            report=_analyze(fixture),
            evidence=different.evidence_by_condition,
            review_receipt=_receipt(fixture),
        )


def test_execution_review_public_api_rejects_unrelated_runset_bytes() -> None:
    fixture = _fixture(real_provider_execution=True)
    baseline_bytes = {
        condition_id: published_model_json_bytes(item.baseline_runset)
        for condition_id, item in fixture.evidence_by_condition.items()
    }
    baseline_bytes[next(iter(baseline_bytes))] = b"{}\n"

    with pytest.raises(ValueError, match="bytes do not exactly encode the supplied model"):
        validate_study_execution_review(
            manifest=fixture.manifest,
            benchmark=fixture.benchmark,
            protocols=fixture.protocols,
            report=_analyze(fixture),
            evidence=fixture.evidence_by_condition,
            review_receipt=_receipt(fixture),
            baseline_runset_bytes=baseline_bytes,
        )
