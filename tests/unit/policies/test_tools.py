from __future__ import annotations

from agent_assure.policies.tools import evaluate_tool_allowlist
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.run import (
    AgentRunRecord,
    StructuredFieldOrigin,
    StructuredFieldOrigins,
)


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


def test_self_reported_forbidden_tool_remains_verdict_bearing() -> None:
    payload = _run(tools=("blocked-tool",)).model_dump(mode="python")
    payload.update(
        {
            "execution_mode": "live",
            "observation_id": "obs-tools",
            "repetition_index": 0,
            "schedule_index": 0,
            "cluster_id": "case-tools",
            "adapter_id": "openai-chat-completions",
            "cost_budget_committed_usd": "0.000000",
            "generated_token_budget_committed": 0,
            "total_token_budget_committed": 0,
            "structured_field_origins": StructuredFieldOrigins.uniform(
                StructuredFieldOrigin.model_self_report
            ),
        }
    )
    run = AgentRunRecord.model_validate(payload)

    results = evaluate_tool_allowlist(run, forbidden_tools=("blocked-tool",))

    assert {result.reason_code for result in results} == {
        ReasonCode.FORBIDDEN_TOOL,
        ReasonCode.NOT_EVALUATED,
    }
    assert any(result.target == "tool:blocked-tool" for result in results)
    assert any(result.target == "tools" for result in results)


def test_non_control_eligible_observed_empty_tools_are_not_evaluated() -> None:
    payload = _run(tools=()).model_dump(mode="python")
    payload.update(
        {
            "execution_mode": "live",
            "observation_id": "obs-tools",
            "repetition_index": 0,
            "schedule_index": 0,
            "cluster_id": "case-tools",
            "adapter_id": "openai-chat-completions",
            "cost_budget_committed_usd": "0.000000",
            "generated_token_budget_committed": 0,
            "total_token_budget_committed": 0,
            "structured_field_origins": StructuredFieldOrigins.uniform(
                StructuredFieldOrigin.model_self_report
            ),
        }
    )

    results = evaluate_tool_allowlist(
        AgentRunRecord.model_validate(payload),
        allowed_tools=(),
    )

    assert len(results) == 1
    assert results[0].state is GateState.not_evaluated
    assert results[0].reason_code is ReasonCode.NOT_EVALUATED


def test_control_eligible_observed_empty_tools_are_not_evaluated() -> None:
    payload = _run(tools=()).model_dump(mode="python")
    payload.update(
        {
            "execution_mode": "live",
            "observation_id": "obs-tools",
            "repetition_index": 0,
            "schedule_index": 0,
            "cluster_id": "case-tools",
            "adapter_id": "external-script",
            "cost_budget_committed_usd": "0.000000",
            "generated_token_budget_committed": 0,
            "total_token_budget_committed": 0,
            "structured_field_origins": StructuredFieldOrigins.uniform(
                StructuredFieldOrigin.instrumented_adapter
            ),
        }
    )

    results = evaluate_tool_allowlist(
        AgentRunRecord.model_validate(payload),
        allowed_tools=(),
    )

    assert len(results) == 1
    assert results[0].state is GateState.not_evaluated
    assert results[0].reason_code is ReasonCode.NOT_EVALUATED
    assert "absence is not evidence" in results[0].message


def test_empty_tools_do_not_satisfy_a_forbidden_only_policy() -> None:
    run = _run(tools=())

    results = evaluate_tool_allowlist(run, forbidden_tools=("blocked-tool",))

    assert len(results) == 1
    assert results[0].state is GateState.not_evaluated
    assert results[0].reason_code is ReasonCode.NOT_EVALUATED


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
