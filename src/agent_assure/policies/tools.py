from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord


def evaluate_tool_allowlist(
    run: AgentRunRecord,
    *,
    allowed_tools: tuple[str, ...] = (),
    forbidden_tools: tuple[str, ...] = (),
) -> tuple[ControlResult, ...]:
    results: list[ControlResult] = []
    forbidden = set(forbidden_tools)
    results.extend(
        ControlResult(
            control_id="tool_allowlist",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.FORBIDDEN_TOOL,
            severity=Severity.error,
            target=f"tool:{tool}",
            message=f"tool {tool!r} is explicitly forbidden",
        )
        for tool in run.tools
        if tool in forbidden
    )
    if not allowed_tools:
        return tuple(results)
    allowed = set(allowed_tools)
    results.extend(
        ControlResult(
            control_id="tool_allowlist",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.FORBIDDEN_TOOL,
            severity=Severity.error,
            target=f"tool:{tool}",
            message=f"tool {tool!r} is not in the configured allowlist",
        )
        for tool in run.tools
        if tool not in allowed
    )
    return tuple(results)
