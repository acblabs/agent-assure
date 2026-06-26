from __future__ import annotations

import json
from typing import Any

from pydantic.functional_validators import field_validator

from agent_assure.compare.case_map import unique_case_map
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import (
    ComparisonClassification,
    GateState,
    ReasonCode,
    coerce_enum,
)
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.run import RunSet

# Structural record fields used for v0.1 behavioral context. This is a deliberate
# projection, not a semantic diff of every nested evidence or policy shape.
BEHAVIOR_FIELDS = (
    "recommendation",
    "outcome",
    "output_summary",
    "provider",
    "model",
    "tools",
    "evidence_refs",
    "policy_results",
    "human_review_required",
    "human_review_performed",
)


class ControlChange(StrictModel):
    classification: ComparisonClassification
    finding_id: str
    case_id: str
    control_id: str
    target: str
    reason_code: ReasonCode
    baseline_state: GateState | None = None
    candidate_state: GateState | None = None
    message: str

    @field_validator("classification", mode="before")
    @classmethod
    def _coerce_classification(cls, value: object) -> ComparisonClassification:
        return coerce_enum(ComparisonClassification, value)

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)

    @field_validator("baseline_state", "candidate_state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState | None:
        if value is None:
            return None
        return coerce_enum(GateState, value)


class BehaviorChange(StrictModel):
    case_id: str
    field: str
    baseline_value: str
    candidate_value: str


def diff_control_findings(
    baseline: EvaluationReport,
    candidate: EvaluationReport,
) -> tuple[ControlChange, ...]:
    baseline_findings = {_finding_key(finding): finding for finding in baseline.failed_controls}
    candidate_findings = {_finding_key(finding): finding for finding in candidate.failed_controls}
    changes: list[ControlChange] = []
    for key in sorted(set(candidate_findings) - set(baseline_findings)):
        finding = candidate_findings[key]
        changes.append(
            _control_change(
                ComparisonClassification.new_failure,
                finding,
                baseline_state=None,
                candidate_state=finding.state,
                message=(
                    "candidate introduced blocking finding "
                    f"{finding.reason_code.value}"
                ),
            )
        )
    for key in sorted(set(baseline_findings) - set(candidate_findings)):
        finding = baseline_findings[key]
        changes.append(
            _control_change(
                ComparisonClassification.resolved_failure,
                finding,
                baseline_state=finding.state,
                candidate_state=None,
                message=(
                    "candidate resolved baseline finding "
                    f"{finding.reason_code.value}"
                ),
            )
        )
    for key in sorted(set(baseline_findings) & set(candidate_findings)):
        baseline_finding = baseline_findings[key]
        candidate_finding = candidate_findings[key]
        changes.append(
            _control_change(
                ComparisonClassification.persistent_failure,
                candidate_finding,
                baseline_state=baseline_finding.state,
                candidate_state=candidate_finding.state,
                message=(
                    "candidate retains blocking finding "
                    f"{candidate_finding.reason_code.value}"
                ),
            )
        )
    return tuple(changes)


def diff_behavior(baseline: RunSet, candidate: RunSet) -> tuple[BehaviorChange, ...]:
    baseline_runs = unique_case_map(baseline)
    candidate_runs = unique_case_map(candidate)
    changes: list[BehaviorChange] = []
    for case_id in sorted(set(baseline_runs) & set(candidate_runs)):
        baseline_payload = baseline_runs[case_id].model_dump(mode="json")
        candidate_payload = candidate_runs[case_id].model_dump(mode="json")
        for field in BEHAVIOR_FIELDS:
            baseline_value = _stable_value(baseline_payload[field])
            candidate_value = _stable_value(candidate_payload[field])
            if baseline_value != candidate_value:
                changes.append(
                    BehaviorChange(
                        case_id=case_id,
                        field=field,
                        baseline_value=baseline_value,
                        candidate_value=candidate_value,
                    )
                )
    return tuple(changes)


def summarize_control_change(change: ControlChange) -> str:
    return (
        f"{change.classification.value}: {change.case_id} {change.control_id} "
        f"{change.reason_code.value} {change.target}"
    )


def _finding_key(finding: Finding) -> tuple[str, str, str, str, str]:
    return (
        finding.finding_id,
        finding.case_id,
        finding.control_id,
        finding.target,
        finding.reason_code.value,
    )


def _control_change(
    classification: ComparisonClassification,
    finding: Finding,
    *,
    baseline_state: GateState | None,
    candidate_state: GateState | None,
    message: str,
) -> ControlChange:
    return ControlChange(
        classification=classification,
        finding_id=finding.finding_id,
        case_id=finding.case_id,
        control_id=finding.control_id,
        target=finding.target,
        reason_code=finding.reason_code,
        baseline_state=baseline_state,
        candidate_state=candidate_state,
        message=message,
    )


def _stable_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
