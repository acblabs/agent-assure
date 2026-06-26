from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord


def evaluate_runtime_success(run: AgentRunRecord) -> tuple[ControlResult, ...]:
    runtime_failed = run.outcome == "runtime_error"
    if not runtime_failed:
        return ()
    return (
        ControlResult(
            control_id="runtime_success_required",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.RUNTIME_FAILED,
            severity=Severity.blocker,
            target=run.run_id,
            message="run produced a fixture-mode runtime error record",
        ),
    )
