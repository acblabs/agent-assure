from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent_assure.examples.langgraph_expense_assurance.runner as runner
from agent_assure.authoring.compiler import compile_suite
from agent_assure.compare.runsets import compare_runsets
from agent_assure.examples.langgraph_expense_assurance.runner import (
    RAW_REQUEST,
    evaluate_variant,
    run_offline_example,
    run_variant,
)
from agent_assure.reporting.markdown import render_comparison_markdown
from agent_assure.reporting.packet import build_evidence_packet, render_evidence_packet_markdown
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.usage.pricing import load_pricing_snapshot, pricing_snapshot_digest

ROOT = Path(__file__).resolve().parents[2]


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
    assert candidate_run.usage_summary.total_tokens == 12
    assert candidate_run.usage_summary.estimated_cost_microusd == 22
    assert candidate_run.usage_summary.pricing_snapshot_ids == (
        "langgraph-expense-demo-pricing-v1",
    )
    assert len(candidate_run.usage_summary.pricing_snapshot_digests) == 1
    assert RAW_REQUEST not in json.dumps(candidate.model_dump(mode="json"), sort_keys=True)


def test_langgraph_inline_pricing_snapshot_matches_persisted_fixture() -> None:
    fixture_snapshot = load_pricing_snapshot(
        ROOT / "examples" / "usage" / "langgraph-expense-demo-pricing-v1.json"
    )

    assert fixture_snapshot == runner.PRICING_SNAPSHOT
    assert pricing_snapshot_digest(fixture_snapshot) == pricing_snapshot_digest(
        runner.PRICING_SNAPSHOT
    )


def test_langgraph_cheaper_candidate_still_reports_governance_regression() -> None:
    compiled = compile_suite(runner.SUITE_PATH)
    baseline = run_variant("baseline")
    candidate = run_variant("candidate_missing_evidence")

    report = compare_runsets(compiled, baseline, candidate)

    assert report.comparison_summary.classification is ComparisonClassification.new_failure
    assert report.comparison_summary.candidate_state is GateState.fail
    assert report.usage_delta is not None
    assert report.usage_delta.total_tokens_delta == -8
    assert report.usage_delta.total_tokens_delta_bps == -4000
    assert report.usage_delta.estimated_cost_microusd_delta == -14
    assert report.usage_delta.estimated_cost_microusd_delta_bps == -3888
    assert report.comparison_summary.baseline_usage_summary is not None
    assert report.comparison_summary.candidate_usage_summary is not None
    assert report.comparison_summary.usage_delta == report.usage_delta

    markdown = render_comparison_markdown(report)
    assert "declared estimated cost per cost observation" in markdown
    assert "declared estimated cost delta -14 micro-USD (-3888 bps)" in markdown
    assert "ROI" not in markdown

    packet = build_evidence_packet(
        report.candidate_vs_expectations,
        comparison=report.comparison_summary,
    )
    packet_markdown = render_evidence_packet_markdown(packet)
    assert "Baseline total tokens: `20`" in packet_markdown
    assert "Candidate total tokens: `12`" in packet_markdown
    assert "Baseline declared estimated cost per cost observation" in packet_markdown
    assert "declared estimated cost delta -14 micro-USD (-3888 bps)" in packet_markdown


def test_langgraph_higher_usage_candidate_does_not_create_governance_failure() -> None:
    compiled = compile_suite(runner.SUITE_PATH)
    baseline = run_variant("baseline")
    candidate = run_variant("candidate_higher_usage")

    candidate_report = evaluate_variant("candidate_higher_usage")
    report = compare_runsets(compiled, baseline, candidate)

    assert candidate_report.candidate_vs_expectations.state is GateState.pass_
    assert report.comparison_summary.candidate_state is GateState.pass_
    assert report.comparison_summary.classification is not ComparisonClassification.new_failure
    assert report.usage_delta is not None
    assert report.usage_delta.total_tokens_delta == 10
    assert report.usage_delta.total_tokens_delta_bps == 5000
    assert report.usage_delta.estimated_cost_microusd_delta == 18
    assert report.usage_delta.estimated_cost_microusd_delta_bps == 5000


def test_langgraph_example_records_observed_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_decision_node = runner._decision_node

    def missing_langgraph_import() -> object:
        raise ModuleNotFoundError(
            "No module named 'langgraph'",
            name="langgraph",
        )

    def changed_decision_node(
        state: runner.ExpenseGraphState,
    ) -> runner.ExpenseGraphState:
        node_output = original_decision_node(state)
        agent_metadata = dict(node_output["agent_assure"])
        attributes = dict(agent_metadata["privacy_filtered_attributes"])
        attributes["recommendation"] = "manual_review"
        attributes["outcome"] = "manual_review"
        agent_metadata["privacy_filtered_attributes"] = attributes
        return {"agent_assure": agent_metadata}

    monkeypatch.setattr(runner, "_compiled_langgraph", missing_langgraph_import)
    monkeypatch.setattr(runner, "_decision_node", changed_decision_node)

    runset = run_variant("candidate_missing_evidence")

    assert runset.runs[0].recommendation == "manual_review"
    assert runset.runs[0].outcome == "manual_review"


def test_langgraph_real_graph_stream_smoke() -> None:
    pytest.importorskip("langgraph.graph")

    summary = run_offline_example()

    assert summary["status"] == "success"
    assert summary["langgraph_execution"] == "langgraph"
    assert summary["same_final_decision"] is True
    assert summary["candidate_state"] == GateState.fail.value


@pytest.mark.parametrize(
    "variant",
    ("baseline", "candidate_missing_evidence", "candidate_higher_usage"),
)
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
