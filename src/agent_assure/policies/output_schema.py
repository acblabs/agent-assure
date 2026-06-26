from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord


def evaluate_structured_output(run: AgentRunRecord) -> tuple[ControlResult, ...]:
    results: list[ControlResult] = []
    for field_name, value in {
        "recommendation": run.recommendation,
        "outcome": run.outcome,
        "output_summary": run.output_summary,
    }.items():
        if not value.strip():
            results.append(
                ControlResult(
                    control_id="structured_output_required",
                    case_id=run.case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.STRUCTURED_OUTPUT_INVALID,
                    severity=Severity.error,
                    target=field_name,
                    message=f"structured output field {field_name!r} is empty",
                )
            )
    return tuple(results)
