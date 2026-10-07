from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from agent_assure.authoring.compiler import compile_suite
from agent_assure.compare.runsets import ComparisonReport, compare_runsets
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.reporting.console import (
    render_comparison_console,
    render_evaluation_console,
)
from agent_assure.reporting.json_report import (
    write_comparison_json,
    write_evaluation_json,
)
from agent_assure.reporting.markdown import (
    render_comparison_markdown,
    render_evaluation_markdown,
    write_comparison_markdown,
    write_evaluation_markdown,
)
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from tests.unit.evaluation.test_evaluator import BASELINE, EVIDENCE_CANDIDATE, SUITE


@pytest.fixture(scope="module")
def primary_reports() -> tuple[EvaluationReport, ComparisonReport]:
    compiled = compile_suite(SUITE)
    baseline = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    candidate = run_suite(compiled, load_variant_config(EVIDENCE_CANDIDATE), SUITE.parent)
    return evaluate_runset(compiled, candidate), compare_runsets(compiled, baseline, candidate)


def _unsafe_evaluation_variants(report: EvaluationReport) -> tuple[EvaluationReport, ...]:
    forged_metrics = report.metrics.model_copy(
        update={"total_cases": report.metrics.total_cases + 1}
    )
    return (
        report.model_copy(update={"metrics": forged_metrics}),
        EvaluationReport.model_construct(**{**report.__dict__, "metrics": forged_metrics}),
    )


def _unsafe_comparison_variants(report: ComparisonReport) -> tuple[ComparisonReport, ...]:
    candidate_state = report.candidate_vs_expectations.state
    forged_state = next(state for state in type(candidate_state) if state is not candidate_state)
    forged_summary = report.comparison_summary.model_copy(update={"candidate_state": forged_state})
    return (
        report.model_copy(update={"comparison_summary": forged_summary}),
        ComparisonReport.model_construct(
            **{**report.__dict__, "comparison_summary": forged_summary}
        ),
    )


def test_evaluation_reporters_reject_unsafe_models_before_output(
    primary_reports: tuple[EvaluationReport, ComparisonReport],
    tmp_path: Path,
) -> None:
    evaluation, _ = primary_reports
    for index, forged in enumerate(_unsafe_evaluation_variants(evaluation)):
        with pytest.raises(ValueError):
            render_evaluation_markdown(forged)

        json_dir = tmp_path / f"evaluation-json-{index}"
        with pytest.raises(ValueError):
            write_evaluation_json(forged, json_dir)
        assert not json_dir.exists()

        markdown_dir = tmp_path / f"evaluation-markdown-{index}"
        with pytest.raises(ValueError):
            write_evaluation_markdown(forged, markdown_dir)
        assert not markdown_dir.exists()

        sink = StringIO()
        console = Console(file=sink, force_terminal=False, color_system=None)
        with pytest.raises(ValueError):
            render_evaluation_console(forged, console)
        assert sink.getvalue() == ""


def test_comparison_reporters_reject_unsafe_models_before_output(
    primary_reports: tuple[EvaluationReport, ComparisonReport],
    tmp_path: Path,
) -> None:
    _, comparison = primary_reports
    for index, forged in enumerate(_unsafe_comparison_variants(comparison)):
        with pytest.raises(ValueError):
            render_comparison_markdown(forged)

        json_dir = tmp_path / f"comparison-json-{index}"
        with pytest.raises(ValueError):
            write_comparison_json(forged, json_dir)
        assert not json_dir.exists()

        markdown_dir = tmp_path / f"comparison-markdown-{index}"
        with pytest.raises(ValueError):
            write_comparison_markdown(forged, markdown_dir)
        assert not markdown_dir.exists()

        sink = StringIO()
        console = Console(file=sink, force_terminal=False, color_system=None)
        with pytest.raises(ValueError):
            render_comparison_console(forged, console)
        assert sink.getvalue() == ""
