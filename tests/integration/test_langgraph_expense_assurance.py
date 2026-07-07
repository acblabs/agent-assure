from __future__ import annotations

import json

import pytest

import agent_assure.examples.langgraph_expense_assurance.runner as runner
from agent_assure.examples.langgraph_expense_assurance.runner import (
    RAW_REQUEST,
    evaluate_variant,
    run_offline_example,
    run_variant,
)
from agent_assure.schema.common import GateState, ReasonCode


def test_langgraph_expense_example_runs_offline() -> None:
    summary = run_offline_example()

    assert summary["status"] == "success"
    assert summary["baseline_state"] == GateState.pass_.value
    assert summary["candidate_state"] == GateState.fail.value
    assert summary["same_final_decision"] is True
    assert summary["langgraph_execution"] in {"fallback-no-langgraph", "langgraph"}


def test_langgraph_baseline_passes_and_candidate_fails_process_invariant() -> None:
    baseline_report = evaluate_variant("baseline")
    candidate_report = evaluate_variant("candidate_missing_evidence")

    assert baseline_report.candidate_vs_expectations.state is GateState.pass_
    assert candidate_report.candidate_vs_expectations.state is GateState.fail
    reason_codes = {
        finding.reason_code for finding in candidate_report.candidate_vs_expectations.findings
    }
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE in reason_codes
    assert ReasonCode.REQUIRED_SOURCE_MISSING in reason_codes


def test_langgraph_candidate_preserves_final_answer_and_omits_raw_payloads() -> None:
    baseline = run_variant("baseline")
    candidate = run_variant("candidate_missing_evidence")
    baseline_run = baseline.runs[0]
    candidate_run = candidate.runs[0]

    assert candidate_run.recommendation == baseline_run.recommendation
    assert candidate_run.outcome == baseline_run.outcome
    assert candidate_run.human_review_required == baseline_run.human_review_required
    assert candidate_run.provider == baseline_run.provider
    assert candidate_run.tools == baseline_run.tools
    assert candidate_run.evidence_refs == ()
    assert candidate_run.usage_summary is not None
    assert candidate_run.usage_summary.total_tokens == 20
    assert RAW_REQUEST not in json.dumps(candidate.model_dump(mode="json"), sort_keys=True)


def test_langgraph_real_graph_stream_smoke() -> None:
    pytest.importorskip("langgraph.graph")

    summary = run_offline_example()

    assert summary["status"] == "success"
    assert summary["langgraph_execution"] == "langgraph"
    assert summary["same_final_decision"] is True
    assert summary["candidate_state"] == GateState.fail.value


@pytest.mark.parametrize("variant", ("baseline", "candidate_missing_evidence"))
def test_langgraph_real_and_fallback_paths_emit_identical_runsets(
    monkeypatch: pytest.MonkeyPatch,
    variant: runner.ExampleVariant,
) -> None:
    pytest.importorskip("langgraph.graph")
    real = run_variant(variant)

    def missing_langgraph_import() -> object:
        raise ModuleNotFoundError(
            "No module named 'langgraph'",
            name="langgraph",
        )

    monkeypatch.setattr(runner, "_compiled_langgraph", missing_langgraph_import)
    fallback = run_variant(variant)

    assert fallback.model_dump(mode="json") == real.model_dump(mode="json")


def test_langgraph_fallback_only_handles_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_transitive = ModuleNotFoundError(
        "No module named 'langgraph_core'",
        name="langgraph_core",
    )

    def broken_langgraph_import() -> object:
        raise missing_transitive

    monkeypatch.setattr(runner, "_compiled_langgraph", broken_langgraph_import)

    with pytest.raises(ModuleNotFoundError, match="langgraph_core"):
        run_offline_example()
