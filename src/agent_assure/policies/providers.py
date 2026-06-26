from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.policies.review_boundary import review_boundary_failed
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.suite import SuiteCase


def evaluate_provider_boundary(
    run: AgentRunRecord,
    case: SuiteCase,
    expectation: Expectation,
) -> tuple[ControlResult, ...]:
    if "provider-policy" not in case.tags:
        return ()
    if not run.provider or not review_boundary_failed(run, expectation):
        return ()
    return (
        ControlResult(
            control_id="provider_review_boundary",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.REVIEW_BOUNDARY_FAILED,
            severity=Severity.error,
            target=f"provider:{run.provider}",
            message=(
                f"provider-boundary case used provider {run.provider!r} without "
                "the required review boundary"
            ),
        ),
    )
