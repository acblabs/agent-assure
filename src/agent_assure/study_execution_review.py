"""Fail-closed validation for post-execution provider-evidence review."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING, Literal

from agent_assure.privacy.persistence import assert_persisted_payload_safe
from agent_assure.rag.repeated_sensitivity import validate_paired_attempt_journal
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import RepeatedEvidenceSensitivityProtocol
from agent_assure.schema.study import (
    RealModelStudyManifest,
    RealModelStudyReport,
    StudyExecutionOrigin,
    StudyExecutionReviewCondition,
    StudyExecutionReviewReceipt,
    StudyObservedExecutionProvenance,
)
from agent_assure.study_artifact_serialization import (
    published_model_json_bytes,
    require_published_model_json_bytes,
)

if TYPE_CHECKING:
    from agent_assure.study.analysis import StudyConditionEvidence


@dataclass(frozen=True, slots=True)
class ValidatedStudyExecutionReview:
    """Receipt proven to bind one exact, replayed study generation."""

    receipt: StudyExecutionReviewReceipt


def build_study_execution_review_receipt(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    report: RealModelStudyReport,
    evidence: Mapping[str, StudyConditionEvidence | None],
    receipt_id: str,
    reviewed_at_utc: str,
    reviewer_pseudonym: str,
    reviewer_independent_of_execution: Literal[True],
    reviewer_independence_rationale: str,
    provider_log_and_account_review_confirmed: Literal[True],
    exhaustive_attempt_failure_retry_accounting_confirmed: Literal[True],
    provider_response_id_matches_confirmed: Literal[True],
    exact_runset_artifact_digest_matches_confirmed: Literal[True],
) -> StudyExecutionReviewReceipt:
    """Build a self-digested receipt from exact canonical study artifacts."""

    receipt = StudyExecutionReviewReceipt.build(
        receipt_id=receipt_id,
        study_id=manifest.study_id,
        study_manifest_digest=manifest.manifest_digest,
        study_manifest_sha256=sha256(published_model_json_bytes(manifest)).hexdigest(),
        study_report_digest=report.report_digest,
        study_report_sha256=sha256(published_model_json_bytes(report)).hexdigest(),
        execution_window_end_utc=manifest.execution_window.end,
        reviewed_at_utc=reviewed_at_utc,
        reviewer_pseudonym=reviewer_pseudonym,
        reviewer_independent_of_execution=reviewer_independent_of_execution,
        reviewer_independence_rationale=reviewer_independence_rationale,
        conditions=_expected_conditions(
            manifest=manifest,
            protocols=protocols,
            report=report,
            evidence=evidence,
        ),
        provider_log_and_account_review_confirmed=(provider_log_and_account_review_confirmed),
        exhaustive_attempt_failure_retry_accounting_confirmed=(
            exhaustive_attempt_failure_retry_accounting_confirmed
        ),
        provider_response_id_matches_confirmed=provider_response_id_matches_confirmed,
        exact_runset_artifact_digest_matches_confirmed=(
            exact_runset_artifact_digest_matches_confirmed
        ),
    )
    validate_study_execution_review(
        manifest=manifest,
        benchmark=benchmark,
        protocols=protocols,
        report=report,
        evidence=evidence,
        review_receipt=receipt,
    )
    return receipt


def validate_study_execution_review(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    report: RealModelStudyReport,
    evidence: Mapping[str, StudyConditionEvidence | None],
    review_receipt: StudyExecutionReviewReceipt,
    manifest_bytes: bytes | None = None,
    report_bytes: bytes | None = None,
    baseline_runset_bytes: Mapping[str, bytes] | None = None,
    counterfactual_runset_bytes: Mapping[str, bytes] | None = None,
) -> ValidatedStudyExecutionReview:
    """Verify a human receipt against exact local and provider-linked evidence.

    The booleans remain human attestations. This function proves that those
    attestations name the exact canonical artifacts replayed by Agent Assure;
    it does not authenticate the reviewer or provider account.
    """

    from agent_assure.study.analysis import (
        StudyConditionEvidence,
        analyze_real_model_study,
    )

    manifest = RealModelStudyManifest.model_validate(
        manifest.model_dump(mode="json", warnings="error")
    )
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(
        benchmark.model_dump(mode="json", warnings="error")
    )
    report = RealModelStudyReport.model_validate(report.model_dump(mode="json", warnings="error"))
    protocols = {
        condition_id: RepeatedEvidenceSensitivityProtocol.model_validate(
            protocol.model_dump(mode="json", warnings="error")
        )
        for condition_id, protocol in protocols.items()
    }
    evidence = {
        condition_id: (
            None
            if item is None
            else StudyConditionEvidence(
                protocol=RepeatedEvidenceSensitivityProtocol.model_validate(
                    item.protocol.model_dump(mode="json", warnings="error")
                ),
                baseline_runset=RunSet.model_validate(
                    item.baseline_runset.model_dump(mode="json", warnings="error")
                ),
                counterfactual_runset=RunSet.model_validate(
                    item.counterfactual_runset.model_dump(mode="json", warnings="error")
                ),
                observed_execution_provenance=(
                    None
                    if item.observed_execution_provenance is None
                    else StudyObservedExecutionProvenance.model_validate(
                        item.observed_execution_provenance.model_dump(
                            mode="json",
                            warnings="error",
                        )
                    )
                ),
            )
        )
        for condition_id, item in evidence.items()
    }
    if report.manifest != manifest:
        raise ValueError("study execution review report does not embed the supplied manifest")
    replayed = analyze_real_model_study(
        manifest=manifest,
        benchmark=benchmark,
        protocols=protocols,
        evidence=evidence,
    )
    if replayed != report:
        raise ValueError("study execution review report does not exactly replay from evidence")

    receipt = StudyExecutionReviewReceipt.model_validate(
        review_receipt.model_dump(mode="json", warnings="error")
    )
    assert_persisted_payload_safe(
        receipt.model_dump(mode="json", warnings="error"),
        owner="study execution review receipt",
    )
    expected_conditions = _expected_conditions(
        manifest=manifest,
        protocols=protocols,
        report=report,
        evidence=evidence,
        baseline_runset_bytes=baseline_runset_bytes,
        counterfactual_runset_bytes=counterfactual_runset_bytes,
    )
    expected_manifest_sha256 = sha256(
        require_published_model_json_bytes(
            manifest_bytes,
            manifest,
            label="study manifest",
        )
    ).hexdigest()
    expected_report_sha256 = sha256(
        require_published_model_json_bytes(
            report_bytes,
            report,
            label="study report",
        )
    ).hexdigest()
    if (
        receipt.study_id,
        receipt.study_manifest_digest,
        receipt.study_manifest_sha256,
        receipt.study_report_digest,
        receipt.study_report_sha256,
        receipt.execution_window_end_utc,
        receipt.conditions,
    ) != (
        manifest.study_id,
        manifest.manifest_digest,
        expected_manifest_sha256,
        report.report_digest,
        expected_report_sha256,
        manifest.execution_window.end,
        expected_conditions,
    ):
        raise ValueError(
            "study execution review receipt does not exactly bind the manifest, "
            "report, and source evidence"
        )
    return ValidatedStudyExecutionReview(receipt=receipt)


def _expected_conditions(
    *,
    manifest: RealModelStudyManifest,
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
    report: RealModelStudyReport,
    evidence: Mapping[str, StudyConditionEvidence | None],
    baseline_runset_bytes: Mapping[str, bytes] | None = None,
    counterfactual_runset_bytes: Mapping[str, bytes] | None = None,
) -> tuple[StudyExecutionReviewCondition, ...]:
    condition_ids = tuple(item.condition_id for item in manifest.conditions)
    if tuple(sorted(evidence)) != condition_ids:
        raise ValueError("study execution review requires the exact manifest condition set")
    results = {item.condition_id: item for item in report.conditions}
    if tuple(sorted(results)) != condition_ids:
        raise ValueError("study execution review requires the exact report condition set")
    if baseline_runset_bytes is not None and tuple(sorted(baseline_runset_bytes)) != condition_ids:
        raise ValueError("baseline RunSet byte inventory does not match the study conditions")
    if (
        counterfactual_runset_bytes is not None
        and tuple(sorted(counterfactual_runset_bytes)) != condition_ids
    ):
        raise ValueError("counterfactual RunSet byte inventory does not match study conditions")

    expected: list[StudyExecutionReviewCondition] = []
    for index, binding in enumerate(manifest.conditions):
        condition_id = binding.condition_id
        condition_evidence = evidence[condition_id]
        result = results[condition_id]
        if condition_evidence is None:
            raise ValueError("execution review requires source evidence for every condition")
        provenance = condition_evidence.observed_execution_provenance
        if provenance is None or result.observed_execution_provenance != provenance:
            raise ValueError(
                "execution review requires report-matched observed provenance for every condition"
            )
        if (
            binding.execution_origin is not StudyExecutionOrigin.real_provider
            or binding.execution_attempt_id is None
            or provenance.observed_origin is not StudyExecutionOrigin.real_provider
            or provenance.provider_response_id_set_digest is None
        ):
            raise ValueError("execution review requires complete real-provider response provenance")
        baseline = condition_evidence.baseline_runset
        counterfactual = condition_evidence.counterfactual_runset
        protocol = protocols[condition_id]
        if condition_evidence.protocol != protocol:
            raise ValueError("execution review source protocol does not match the registered one")
        validate_paired_attempt_journal(protocol, baseline, counterfactual)
        from agent_assure.study.analysis import derive_study_observed_execution_provenance

        derived_provenance = derive_study_observed_execution_provenance(
            manifest=manifest,
            binding=binding,
            protocol=protocol,
            baseline_runset=baseline,
            counterfactual_runset=counterfactual,
        )
        if provenance != derived_provenance:
            raise ValueError(
                "execution review provenance does not exactly derive from source evidence"
            )
        execution_attempt_journal_digest = baseline.execution_attempt_journal_digest
        if (
            baseline.execution_attempt_id != binding.execution_attempt_id
            or counterfactual.execution_attempt_id != binding.execution_attempt_id
            or execution_attempt_journal_digest is None
            or counterfactual.execution_attempt_journal_digest != execution_attempt_journal_digest
        ):
            raise ValueError(
                "execution review requires one manifest-bound attempt journal per condition"
            )
        baseline_bytes = require_published_model_json_bytes(
            (baseline_runset_bytes[condition_id] if baseline_runset_bytes is not None else None),
            baseline,
            label=f"baseline RunSet {condition_id}",
        )
        counterfactual_bytes = require_published_model_json_bytes(
            (
                counterfactual_runset_bytes[condition_id]
                if counterfactual_runset_bytes is not None
                else None
            ),
            counterfactual,
            label=f"counterfactual RunSet {condition_id}",
        )
        expected.append(
            StudyExecutionReviewCondition(
                condition_id=condition_id,
                execution_attempt_id=binding.execution_attempt_id,
                execution_attempt_journal_digest=execution_attempt_journal_digest,
                baseline_runset_artifact=(f"condition-{index:03d}.baseline.source.runset.json"),
                baseline_runset_id=baseline.runset_id,
                baseline_runset_sha256=sha256(baseline_bytes).hexdigest(),
                counterfactual_runset_artifact=(
                    f"condition-{index:03d}.counterfactual.source.runset.json"
                ),
                counterfactual_runset_id=counterfactual.runset_id,
                counterfactual_runset_sha256=sha256(counterfactual_bytes).hexdigest(),
                observed_provenance_digest=provenance.provenance_digest,
                provider_response_id_set_digest=(provenance.provider_response_id_set_digest),
            )
        )
    return tuple(expected)


__all__ = [
    "ValidatedStudyExecutionReview",
    "build_study_execution_review_receipt",
    "validate_study_execution_review",
]
