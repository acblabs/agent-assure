from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypedDict

from agent_assure.adapters import (
    FrameworkObservation,
    FrameworkRunProjection,
    LangGraphAdapter,
    build_run_record_from_observations,
)
from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.run import RunSet
from agent_assure.schema.usage import UsagePricingModel, UsagePricingSnapshot, UsageSegment
from agent_assure.usage.pricing import estimate_segment_cost

ExampleVariant = Literal["baseline", "candidate_missing_evidence", "candidate_higher_usage"]
ExecutionPath = Literal["langgraph", "fallback-no-langgraph"]

EXAMPLE_ROOT = Path(__file__).resolve().parent
SUITE_PATH = EXAMPLE_ROOT / "suite.yaml"
CASE_ID = "lg-exp-001"
PROVIDER = "approved-expense-model"
MODEL = "expense-risk-v1"
TOOL_NAME = "expense_policy_lookup"
EVIDENCE_REF = "ref-expense-policy-v3"
CLAIM_ID = "claim-policy-evidence"
SOURCE_ID = "expense-policy-v3"
REVIEW_ROUTE = "manager_review"
PRICING_SNAPSHOT = UsagePricingSnapshot(
    pricing_snapshot_id="langgraph-expense-demo-pricing-v1",
    currency="USD",
    models=(
        UsagePricingModel(
            provider=PROVIDER,
            model=MODEL,
            input_token_microusd=1,
            output_token_microusd=3,
        ),
    ),
    limitations=("Demo fixture pricing only; not live provider pricing.",),
)
RAW_REQUEST = (
    "Employee E-7788 asks to approve a dinner expense for vendor Cafe Meridian "
    "using receipt R-44119."
)


class ExpenseGraphState(TypedDict, total=False):
    request: str
    variant: str
    case_id: str
    agent_assure: dict[str, object]


@dataclass(frozen=True)
class VariantRun:
    runset: RunSet
    execution_path: ExecutionPath


def run_variant(variant: ExampleVariant) -> RunSet:
    return _run_variant(variant).runset


def _run_variant(variant: ExampleVariant) -> VariantRun:
    compiled = compile_suite(SUITE_PATH)
    fixture_manifest_digest = _fixture_manifest_digest()
    adapter = LangGraphAdapter()
    run_id = _stable_id("run", variant, CASE_ID)
    observations, execution_path = _graph_observations(
        adapter,
        variant,
        run_id=run_id,
        case_id=CASE_ID,
    )
    record = build_run_record_from_observations(
        observations,
        projection=_projection(),
        run_id=run_id,
        case_id=CASE_ID,
        fixture_manifest_digest=fixture_manifest_digest,
        configuration_digest=_configuration_digest(variant),
    )
    return VariantRun(
        runset=RunSet(
            artifact_kind="run-set",
            runset_id=_stable_id("runset", variant, CASE_ID),
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest=fixture_manifest_digest,
            execution_mode=ExecutionMode.fixture,
            runs=(record,),
        ),
        execution_path=execution_path,
    )


def evaluate_variant(variant: ExampleVariant) -> EvaluationReport:
    compiled = compile_suite(SUITE_PATH)
    return evaluate_runset(compiled, run_variant(variant))


def run_offline_example() -> dict[str, object]:
    compiled = compile_suite(SUITE_PATH)
    baseline_result = _run_variant("baseline")
    candidate_result = _run_variant("candidate_missing_evidence")
    baseline = baseline_result.runset
    candidate = candidate_result.runset
    baseline_report = evaluate_runset(compiled, baseline)
    candidate_report = evaluate_runset(compiled, candidate)
    baseline_run = baseline.runs[0]
    candidate_run = candidate.runs[0]
    return {
        "example": "langgraph-expense-assurance",
        "status": "success",
        "langgraph_execution": _summary_execution_path(
            (baseline_result.execution_path, candidate_result.execution_path)
        ),
        "baseline_state": baseline_report.candidate_vs_expectations.state.value,
        "candidate_state": candidate_report.candidate_vs_expectations.state.value,
        "same_final_decision": (
            baseline_run.recommendation == candidate_run.recommendation
            and baseline_run.outcome == candidate_run.outcome
        ),
        "candidate_reason_codes": [
            finding.reason_code.value
            for finding in candidate_report.candidate_vs_expectations.findings
        ],
        "candidate_evidence_refs": [ref.ref_id for ref in candidate_run.evidence_refs],
        "candidate_usage_total_tokens": (
            candidate_run.usage_summary.total_tokens
            if candidate_run.usage_summary is not None
            else None
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    out_dir = Path(args[0]) if args else None
    summary = run_offline_example()
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        _write_json(
            out_dir / "baseline.runset.json",
            run_variant("baseline").model_dump(mode="json"),
        )
        _write_json(
            out_dir / "candidate.runset.json",
            run_variant("candidate_missing_evidence").model_dump(mode="json"),
        )
    print(json.dumps(summary, sort_keys=True))
    return 0


def _graph_observations(
    adapter: LangGraphAdapter,
    variant: ExampleVariant,
    *,
    run_id: str,
    case_id: str,
) -> tuple[tuple[FrameworkObservation, ...], ExecutionPath]:
    try:
        graph = _compiled_langgraph()
    except ModuleNotFoundError as exc:
        # Keep fallback narrow: a broken installed LangGraph path should fail loudly.
        if exc.name != "langgraph":
            raise
        events = _fallback_stream_events(variant, case_id=case_id)
        return (
            adapter.observations_from_events(events, run_id=run_id, case_id=case_id),
            "fallback-no-langgraph",
        )
    observations = adapter.observations_from_graph_stream(
        graph,
        {"request": RAW_REQUEST, "variant": variant, "case_id": case_id},
        run_id=run_id,
        case_id=case_id,
    )
    return observations, "langgraph"


def _compiled_langgraph() -> object:
    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(ExpenseGraphState)
    graph.add_node("intake", _intake_node)
    graph.add_node("policy_lookup", _policy_lookup_node)
    graph.add_node("review_route", _review_route_node)
    graph.add_node("decision", _decision_node)
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "policy_lookup")
    graph.add_edge("policy_lookup", "review_route")
    graph.add_edge("review_route", "decision")
    graph.add_edge("decision", END)
    return graph.compile()


def _fallback_stream_events(
    variant: ExampleVariant,
    *,
    case_id: str,
) -> tuple[Mapping[str, object], ...]:
    state: ExpenseGraphState = {"request": RAW_REQUEST, "variant": variant, "case_id": case_id}
    return (
        {"intake": _intake_node(state)},
        {"policy_lookup": _policy_lookup_node(state)},
        {"review_route": _review_route_node(state)},
        {"decision": _decision_node(state)},
    )


def _intake_node(state: ExpenseGraphState) -> ExpenseGraphState:
    return {
        "agent_assure": _metadata(
            state,
            sequence_number=1,
            event_type="case_intake",
            node_name="intake",
            privacy_filtered_attributes={
                "case_bucket": "domestic_meal",
                "request_digest": sha256_hexdigest({"request": RAW_REQUEST}),
            },
        )
    }


def _policy_lookup_node(state: ExpenseGraphState) -> ExpenseGraphState:
    evidence_refs = (
        ()
        if state["variant"] == "candidate_missing_evidence"
        else (EVIDENCE_REF,)
    )
    return {
        "agent_assure": _metadata(
            state,
            sequence_number=2,
            event_type="tool_call",
            node_name="policy_lookup",
            tool_name=TOOL_NAME,
            evidence_refs=evidence_refs,
            privacy_filtered_attributes={
                "policy_version": "expense-policy-v3",
                "tool_call_digest": sha256_hexdigest(
                    {
                        "case_id": state["case_id"],
                        "tool": TOOL_NAME,
                        "variant": state["variant"],
                    }
                ),
            },
        )
    }


def _review_route_node(state: ExpenseGraphState) -> ExpenseGraphState:
    return {
        "agent_assure": _metadata(
            state,
            sequence_number=3,
            event_type="review_route",
            node_name="review_route",
            review_route=REVIEW_ROUTE,
            privacy_filtered_attributes={
                "human_review_required": "true",
                "human_review_performed": "true",
            },
        )
    }


def _decision_node(state: ExpenseGraphState) -> ExpenseGraphState:
    return {
        "agent_assure": _metadata(
            state,
            sequence_number=4,
            event_type="decision",
            node_name="decision",
            provider=PROVIDER,
            model=MODEL,
            review_route=REVIEW_ROUTE,
            privacy_filtered_attributes={
                "recommendation": "approve",
                "outcome": "approved_with_review",
            },
            usage_segment=_decision_usage_segment(state),
        )
    }


def _metadata(
    state: ExpenseGraphState,
    *,
    sequence_number: int,
    event_type: str,
    node_name: str,
    provider: str | None = None,
    model: str | None = None,
    tool_name: str | None = None,
    review_route: str | None = None,
    evidence_refs: tuple[str, ...] = (),
    privacy_filtered_attributes: Mapping[str, str] | None = None,
    usage_segment: Mapping[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "case_id": state["case_id"],
        "event_type": event_type,
        "node_name": node_name,
        "sequence_number": sequence_number,
        "redaction_state": "redacted",
        "privacy_filtered_attributes": dict(privacy_filtered_attributes or {}),
    }
    if provider is not None:
        payload["provider"] = provider
    if model is not None:
        payload["model"] = model
    if tool_name is not None:
        payload["tool_name"] = tool_name
    if review_route is not None:
        payload["review_route"] = review_route
    if evidence_refs:
        payload["evidence_refs"] = evidence_refs
    if usage_segment is not None:
        payload["usage_segment"] = usage_segment
    return payload


def _decision_usage_segment(state: ExpenseGraphState) -> dict[str, object]:
    if state["variant"] == "baseline":
        prompt_tokens = 12
        completion_tokens = 8
        total_tokens = 20
        latency_ms = 25
    elif state["variant"] == "candidate_missing_evidence":
        prompt_tokens = 7
        completion_tokens = 5
        total_tokens = 12
        latency_ms = 18
    else:
        prompt_tokens = 18
        completion_tokens = 12
        total_tokens = 30
        latency_ms = 32
    segment = UsageSegment(
        segment_id=f"usage-{state['variant']}-{state['case_id']}",
        provider=PROVIDER,
        model=MODEL,
        operation="decision",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        tool_call_count=1,
        retry_count=0,
        latency_ms=latency_ms,
    )
    return estimate_segment_cost(segment, PRICING_SNAPSHOT).model_dump(mode="json")


def _projection() -> FrameworkRunProjection:
    return FrameworkRunProjection(
        pipeline_id="langgraph-expense-assurance",
        recommendation="approve",
        outcome="approved_with_review",
        provider=PROVIDER,
        model=MODEL,
        evidence_claim_map={EVIDENCE_REF: (CLAIM_ID,)},
        evidence_source_map={EVIDENCE_REF: SOURCE_ID},
        human_review_required=True,
        human_review_performed=True,
        adapter_id=LangGraphAdapter.adapter_id,
    )


def _fixture_manifest_digest() -> str:
    return sha256_hexdigest(
        {
            "case_id": CASE_ID,
            "example": "langgraph-expense-assurance",
            "request_digest": sha256_hexdigest({"request": RAW_REQUEST}),
        }
    )


def _configuration_digest(variant: ExampleVariant) -> str:
    return sha256_hexdigest(
        {
            "adapter": LangGraphAdapter.adapter_id,
            "example": "langgraph-expense-assurance",
            "variant": variant,
        }
    )


def _stable_id(prefix: str, variant: ExampleVariant, case_id: str) -> str:
    digest = sha256_hexdigest(
        {
            "case_id": case_id,
            "example": "langgraph-expense-assurance",
            "prefix": prefix,
            "variant": variant,
        }
    )
    return f"{prefix}-{digest[:16]}"


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _summary_execution_path(paths: tuple[ExecutionPath, ...]) -> str:
    if all(path == "langgraph" for path in paths):
        return "langgraph"
    if all(path == "fallback-no-langgraph" for path in paths):
        return "fallback-no-langgraph"
    return "mixed"


if __name__ == "__main__":
    raise SystemExit(main())
