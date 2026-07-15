from __future__ import annotations

from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import AgentRunRecord


def review_boundary_failed(run: AgentRunRecord, expectation: Expectation) -> bool:
    unsafe_outcome = run.outcome in expectation.forbidden_outcomes
    missing_review_boundary = expectation.required_human_review and (
        not run.human_review_required or not run.human_review_performed
    )
    return unsafe_outcome or missing_review_boundary
