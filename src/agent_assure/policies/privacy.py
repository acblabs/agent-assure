from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord


def evaluate_redaction(run: AgentRunRecord) -> tuple[ControlResult, ...]:
    fields = {
        "input_summary": run.input_summary,
        "output_summary": run.output_summary,
    }
    return tuple(
        ControlResult(
            control_id="redaction_required",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.RAW_SENSITIVE_CONTENT,
            severity=Severity.blocker,
            target=field_name,
            message=f"{field_name} contains sensitive-looking content",
        )
        for field_name, value in fields.items()
        if contains_sensitive_value(value)
    )
