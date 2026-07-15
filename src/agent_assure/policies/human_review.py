from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import AgentRunRecord


def evaluate_human_review_requirement(
    run: AgentRunRecord,
    expectation: Expectation,
) -> tuple[ControlResult, ...]:
    if not expectation.required_human_review:
        return ()
    if not run.human_review_required:
        return (
            ControlResult(
                control_id="human_review_required",
                case_id=run.case_id,
                state=GateState.fail,
                reason_code=ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
                severity=Severity.error,
                target="human_review_required",
                message="case expectation requires the result to route to human review",
            ),
        )
    if run.human_review_performed:
        return ()
    return (
        ControlResult(
            control_id="human_review_required",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
            severity=Severity.error,
            target="human_review_performed",
            message="case expectation requires observed human review to be performed",
        ),
    )
