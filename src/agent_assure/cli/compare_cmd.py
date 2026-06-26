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
from agent_assure.reporting.environment import (
    attach_comparison_environment,
    build_release_manifest,
    environment_with_dependency_inventory,
    release_artifact,
    write_release_manifest,
)
from agent_assure.reporting.json_report import write_comparison_json
from agent_assure.reporting.markdown import write_comparison_markdown
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.environment import EnvironmentInfo

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
    fail_on_not_evaluated: Annotated[
        bool,
        typer.Option(
            "--fail-on-not-evaluated",
            help="Treat not-evaluated capabilities as blocking.",
        ),
    ] = False,
    waiver: Annotated[
        list[Path] | None,
        typer.Option("--waiver", exists=True, readable=True, help="Waiver JSON or YAML file."),
    ] = None,
) -> None:
    gate_profile = (
        DEFAULT_GATE_PROFILE
        if not fail_on_warn and not fail_on_not_evaluated
        else DEFAULT_GATE_PROFILE.model_copy(
            update={
                "fail_on_warn": fail_on_warn,
                "fail_on_not_evaluated": fail_on_not_evaluated,
            }
        )
    )
    environment = environment_with_dependency_inventory(Path.cwd().resolve(), out_dir)
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
        report = attach_comparison_environment(report, environment)
    except InvalidComparisonError as exc:
        if exc.report is None:
            raise typer.BadParameter(str(exc)) from exc
        report = attach_comparison_environment(exc.report, environment)
        _write_reports(
            report,
            out_dir,
            suite_path=suite,
            baseline_runset=baseline_runset,
            candidate_runset=candidate_runset,
            environment=environment,
        )
        render_comparison_console(report, console)
        raise typer.Exit(2) from exc
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    _write_reports(
        report,
        out_dir,
        suite_path=suite,
        baseline_runset=baseline_runset,
        candidate_runset=candidate_runset,
        environment=environment,
    )
    render_comparison_console(report, console)
    classification = report.comparison_summary.classification
    if classification is ComparisonClassification.invalid_comparison:
        raise typer.Exit(2)
    if report.candidate_vs_expectations.state is GateState.fail:
        raise typer.Exit(1)


def _write_reports(
    report: ComparisonReport,
    out_dir: Path,
    *,
    suite_path: Path,
    baseline_runset: Path,
    candidate_runset: Path,
    environment: EnvironmentInfo,
) -> None:
    report_json, summary_json = write_comparison_json(report, out_dir)
    write_comparison_markdown(report, out_dir)
    _write_release_manifest(
        suite_path=suite_path,
        baseline_runset=baseline_runset,
        candidate_runset=candidate_runset,
        report_path=report_json,
        summary_path=summary_json,
        out_dir=out_dir,
        environment=environment,
    )


def _write_release_manifest(
    *,
    suite_path: Path,
    baseline_runset: Path,
    candidate_runset: Path,
    report_path: Path,
    summary_path: Path,
    out_dir: Path,
    environment: EnvironmentInfo,
) -> None:
    project_root = Path.cwd().resolve()
    manifest = build_release_manifest(
        (
            release_artifact("compiled-suite", suite_path, project_root=project_root),
            release_artifact("baseline-runset", baseline_runset, project_root=project_root),
            release_artifact("candidate-runset", candidate_runset, project_root=project_root),
            release_artifact("comparison-report", report_path, project_root=project_root),
            release_artifact("comparison-summary", summary_path, project_root=project_root),
            release_artifact(
                "dependency-inventory",
                out_dir / "dependency-inventory.json",
                project_root=project_root,
            ),
        ),
        environment=environment,
    )
    write_release_manifest(manifest, out_dir / "release-artifact-manifest.json")
