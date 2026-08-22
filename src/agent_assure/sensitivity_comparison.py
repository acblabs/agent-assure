from __future__ import annotations

from agent_assure.compare.runsets import compare_runsets
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.sensitivity import RAGSensitivityReport
from agent_assure.sensitivity_contract import SENSITIVITY_EVALUATION_DATE


def derive_sensitivity_comparison(
    report: RAGSensitivityReport,
) -> ComparisonSummary:
    """Recompute the sole comparison authorized by an exact sensitivity report.

    The report embeds the compiled suite and both authenticated RunSets.  Using
    those objects, rather than their human-readable IDs, makes the comparison a
    deterministic projection of the same evidence carried by the report.
    """
    return compare_runsets(
        report.compiled_suite,
        report.baseline_runset,
        report.counterfactual_runset,
        today=SENSITIVITY_EVALUATION_DATE,
    ).comparison_summary


def sensitivity_comparison_binding_error(
    comparison: ComparisonSummary,
    report: RAGSensitivityReport,
) -> str | None:
    """Return an error unless ``comparison`` is the report's exact semantic projection.

    Producer-local environment metadata remains integrity-carried by the comparison
    artifact's own file and release digests, but it is not a semantic property of the
    controlled sensitivity comparison. Every other persisted comparison field remains
    in the exact canonical comparison below.
    """
    validated_comparison = ComparisonSummary.model_validate(comparison.model_dump(mode="json"))
    validated_report = RAGSensitivityReport.model_validate(report.model_dump(mode="json"))
    expected = derive_sensitivity_comparison(validated_report)
    if validated_comparison.baseline_runset_digest != validated_report.baseline_arm.runset_digest:
        return (
            "comparison baseline_runset_digest must exactly match the authenticated "
            "baseline RunSet carried by the evidence sensitivity report"
        )
    if (
        validated_comparison.candidate_runset_digest
        != validated_report.counterfactual_arm.runset_digest
    ):
        return (
            "comparison candidate_runset_digest must exactly match the authenticated "
            "counterfactual RunSet carried by the evidence sensitivity report"
        )
    if _semantic_binding_projection(validated_comparison) != _semantic_binding_projection(expected):
        return (
            "comparison must exactly equal the canonical comparison rederived "
            "from the evidence sensitivity report's compiled suite and RunSets; "
            "only producer-local environment metadata is excluded"
        )
    return None


def _semantic_binding_projection(comparison: ComparisonSummary) -> dict[str, object]:
    return comparison.model_dump(mode="json", exclude={"environment"})


__all__ = [
    "derive_sensitivity_comparison",
    "sensitivity_comparison_binding_error",
]
