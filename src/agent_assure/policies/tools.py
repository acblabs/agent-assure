from __future__ import annotations

from agent_assure.policies.base import ControlResult
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord


def evaluate_tool_allowlist(
    run: AgentRunRecord,
    *,
    allowed_tools: tuple[str, ...] | None = None,
    forbidden_tools: tuple[str, ...] = (),
) -> tuple[ControlResult, ...]:
    forbidden = set(forbidden_tools)
    allowed = None if allowed_tools is None else set(allowed_tools)
    results: list[ControlResult] = []
    for tool in sorted(set(run.tools)):
        if tool in forbidden:
            message = f"tool {tool!r} is explicitly forbidden"
        elif allowed is not None and tool not in allowed:
            message = f"tool {tool!r} is not in the configured allowlist"
        else:
            continue
        results.append(
            ControlResult(
                control_id="tool_allowlist",
                case_id=run.case_id,
                state=GateState.fail,
                reason_code=ReasonCode.FORBIDDEN_TOOL,
                severity=Severity.error,
                target=f"tool:{tool}",
                message=message,
            )
        )
    return tuple(results)
