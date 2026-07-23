from __future__ import annotations

from agent_assure.policies.tools import evaluate_tool_allowlist
from agent_assure.schema.common import ReasonCode
from agent_assure.schema.run import AgentRunRecord


def test_tool_allowlist_none_disables_allowlist_check() -> None:
    run = _run(tools=("unexpected_tool",))

    assert evaluate_tool_allowlist(run, allowed_tools=None) == ()


def test_tool_allowlist_empty_tuple_forbids_all_tools() -> None:
    run = _run(tools=("unexpected_tool",))

    results = evaluate_tool_allowlist(run, allowed_tools=())

    assert len(results) == 1
    assert results[0].reason_code is ReasonCode.FORBIDDEN_TOOL
    assert results[0].target == "tool:unexpected_tool"


def test_forbidden_and_non_allowlisted_tool_emits_one_canonical_finding() -> None:
    run = _run(tools=("z-tool", "blocked-tool", "blocked-tool", "a-tool"))

    first = evaluate_tool_allowlist(
        run,
        allowed_tools=("safe-tool",),
        forbidden_tools=("blocked-tool",),
    )
    second = evaluate_tool_allowlist(
        _run(tools=tuple(reversed(run.tools))),
        allowed_tools=("safe-tool",),
        forbidden_tools=("blocked-tool",),
    )

    assert first == second
    assert tuple(result.target for result in first) == (
        "tool:a-tool",
        "tool:blocked-tool",
        "tool:z-tool",
    )
    assert len({result.finding_id for result in first}) == len(first)
    blocked = next(result for result in first if result.target == "tool:blocked-tool")
    assert blocked.message == "tool 'blocked-tool' is explicitly forbidden"


def _run(*, tools: tuple[str, ...]) -> AgentRunRecord:
    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id="run-tools",
        case_id="case-tools",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approved",
        input_summary="redacted input",
        output_summary="redacted output",
        tools=tools,
    )
