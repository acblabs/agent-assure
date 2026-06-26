from __future__ import annotations

from agent_assure.compare.invariant_diff import BehaviorChange, ControlChange
from agent_assure.compare.provenance_diff import ProvenanceChange
from agent_assure.schema.common import ComparisonClassification, GateState


def choose_comparison_classification(
    *,
    control_changes: tuple[ControlChange, ...],
    behavioral_changes: tuple[BehaviorChange, ...],
    provenance_changes: tuple[ProvenanceChange, ...],
    baseline_state: GateState,
    candidate_state: GateState,
) -> ComparisonClassification:
    """Classify a comparison after fixture equivalence has already passed."""
    if (
        baseline_state is GateState.not_evaluated
        or candidate_state is GateState.not_evaluated
    ):
        return ComparisonClassification.not_evaluated
    if any(
        change.classification is ComparisonClassification.new_failure
        for change in control_changes
    ):
        return ComparisonClassification.new_failure
    if any(
        change.classification is ComparisonClassification.persistent_failure
        for change in control_changes
    ):
        return ComparisonClassification.persistent_failure
    if any(
        change.classification is ComparisonClassification.resolved_failure
        for change in control_changes
    ):
        return ComparisonClassification.resolved_failure
    if provenance_changes and not behavioral_changes:
        return ComparisonClassification.provenance_only_change
    return ComparisonClassification.allowed_behavioral_change
