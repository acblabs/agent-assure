from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.cli.waivers import load_waivers
from agent_assure.compare.runsets import (
    ComparisonReport,
    InvalidComparisonError,
    compare_runsets,
)
from agent_assure.evaluation.evaluator import load_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.policies.base import DEFAULT_GATE_PROFILE
from agent_assure.reporting.console import render_comparison_console
from agent_assure.reporting.json_report import write_comparison_json
from agent_assure.reporting.markdown import write_comparison_markdown
from agent_assure.schema.common import ComparisonClassification, GateState

console = Console()


def compare(
    baseline_runset: Annotated[Path, typer.Argument(exists=True, readable=True)],
    candidate_runset: Annotated[Path, typer.Argument(exists=True, readable=True)],
    suite: Annotated[Path, typer.Option("--suite", exists=True, readable=True)],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Report output directory.")],
    fail_on_warn: Annotated[
        bool,
        typer.Option("--fail-on-warn", help="Treat warning controls as blocking."),
    ] = False,
    waiver: Annotated[
        list[Path] | None,
        typer.Option("--waiver", exists=True, readable=True, help="Waiver JSON or YAML file."),
    ] = None,
) -> None:
    gate_profile = (
        DEFAULT_GATE_PROFILE.model_copy(update={"fail_on_warn": True})
        if fail_on_warn
        else DEFAULT_GATE_PROFILE
    )
    try:
        compiled = load_compiled_suite(suite)
        baseline = load_runset(baseline_runset)
        candidate = load_runset(candidate_runset)
        report = compare_runsets(
            compiled,
            baseline,
            candidate,
            gate_profile=gate_profile,
            waivers=load_waivers(tuple(waiver or ())),
            today=date.today(),
        )
    except InvalidComparisonError as exc:
        if exc.report is None:
            raise typer.BadParameter(str(exc)) from exc
        _write_reports(exc.report, out_dir)
        render_comparison_console(exc.report, console)
        raise typer.Exit(2) from exc
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    _write_reports(report, out_dir)
    render_comparison_console(report, console)
    classification = report.comparison_summary.classification
    if classification is ComparisonClassification.invalid_comparison:
        raise typer.Exit(2)
    if report.candidate_vs_expectations.state is GateState.fail:
        raise typer.Exit(1)


def _write_reports(report: ComparisonReport, out_dir: Path) -> None:
    write_comparison_json(report, out_dir)
    write_comparison_markdown(report, out_dir)
