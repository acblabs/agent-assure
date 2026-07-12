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
    has_provider_policy = (
        "provider-policy" in case.tags
        or bool(expectation.allowed_providers)
        or bool(expectation.forbidden_providers)
    )
    if not has_provider_policy:
        return ()
    if not run.provider:
        return (
            ControlResult(
                control_id="provider_review_boundary",
                case_id=run.case_id,
                state=GateState.fail,
                reason_code=ReasonCode.VALID_RECORD_MISSING,
                severity=Severity.blocker,
                target="provider",
                message="provider-boundary policy requires provider metadata",
            ),
        )
    provider_allowed = (
        not expectation.allowed_providers or run.provider in set(expectation.allowed_providers)
    )
    provider_forbidden = run.provider in set(expectation.forbidden_providers)
    unsafe_without_review = review_boundary_failed(run, expectation)
    if (provider_forbidden or not provider_allowed) and unsafe_without_review:
        return (
            ControlResult(
                control_id="provider_review_boundary",
                case_id=run.case_id,
                state=GateState.fail,
                reason_code=ReasonCode.FORBIDDEN_PROVIDER,
                severity=Severity.error,
                target=f"provider:{run.provider}",
                message=(
                    f"provider {run.provider!r} is not allowed for this case "
                    "without the required review boundary"
                ),
            ),
        )
    if not unsafe_without_review:
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
