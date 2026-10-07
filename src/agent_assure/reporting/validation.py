from __future__ import annotations

from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.schema.validation import validate_loaded_artifact_payload


def validated_evaluation_report_for_reporting(
    report: EvaluationReport,
) -> EvaluationReport:
    """Re-enter the public validation boundary before emitting evaluation evidence."""

    payload = report.model_dump(mode="json", warnings="error")
    validate_loaded_artifact_payload(payload, "evaluation-report")
    return EvaluationReport.model_validate(payload)


def validated_comparison_report_for_reporting(
    report: ComparisonReport,
) -> ComparisonReport:
    """Re-enter the public validation boundary before emitting comparison evidence."""

    payload = report.model_dump(mode="json", warnings="error")
    validate_loaded_artifact_payload(payload, "comparison-report")
    return ComparisonReport.model_validate(payload)
