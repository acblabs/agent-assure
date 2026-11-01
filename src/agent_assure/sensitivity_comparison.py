from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel, ValidationError

from agent_assure.compare.runsets import compare_runsets
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.sensitivity import RAGSensitivityReport
from agent_assure.schema.validation import validate_loaded_artifact_model
from agent_assure.sensitivity_contract import SENSITIVITY_EVALUATION_DATE

ComparisonInputT = TypeVar("ComparisonInputT", bound=BaseModel)


def _admit_owned_comparison_input(
    value: ComparisonInputT,
    model: type[ComparisonInputT],
    *,
    kind: str,
) -> ComparisonInputT:
    payload = value.model_dump(mode="json", warnings="error")
    try:
        return validate_loaded_artifact_model(payload, model, kind=kind)
    except ValueError:
        # Preserve the public typed-error contract without a second semantic
        # projection on successful admission. A typed-valid payload still must
        # fail if the authoritative schema/archival boundary rejected it.
        try:
            model.model_validate(payload)
        except ValidationError as exc:
            raise exc from None
        raise


def derive_sensitivity_comparison(
    report: RAGSensitivityReport,
) -> ComparisonSummary:
    """Recompute the sole comparison authorized by an exact sensitivity report.

    The report embeds the compiled suite and both authenticated RunSets.  Using
    those objects, rather than their human-readable IDs, makes the comparison a
    deterministic projection of the same evidence carried by the report.
    """
    report = _admit_owned_comparison_input(
        report,
        RAGSensitivityReport,
        kind="evidence-sensitivity-report",
    )
    return _derive_validated_sensitivity_comparison(report)


def _derive_validated_sensitivity_comparison(
    report: RAGSensitivityReport,
) -> ComparisonSummary:
    """Derive only from this call's owned, fully admitted report projection."""
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
    validated_comparison = _admit_owned_comparison_input(
        comparison,
        ComparisonSummary,
        kind="comparison-summary",
    )
    validated_report = _admit_owned_comparison_input(
        report,
        RAGSensitivityReport,
        kind="evidence-sensitivity-report",
    )
    expected = _derive_validated_sensitivity_comparison(validated_report)
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
