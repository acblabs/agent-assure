from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.cli.dates import parse_cli_date
from agent_assure.cli.waivers import load_waivers
from agent_assure.evaluation.evaluator import evaluate_runset, load_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile
from agent_assure.reporting.console import render_evaluation_console
from agent_assure.reporting.environment import (
    artifact_project_root,
    attach_evaluation_environment,
    build_release_manifest,
    environment_with_dependency_inventory,
    release_artifact,
    source_project_root,
    write_release_manifest,
)
from agent_assure.reporting.json_report import write_evaluation_json
from agent_assure.reporting.markdown import write_evaluation_markdown
from agent_assure.schema.common import GateState
from agent_assure.schema.environment import EnvironmentInfo

app = typer.Typer(help="Evaluate run sets.")
console = Console()


def evaluate(
    runset_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    suite: Annotated[Path, typer.Option("--suite", exists=True, readable=True)],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Report output directory.")],
    waiver: Annotated[
        list[Path] | None,
        typer.Option("--waiver", exists=True, readable=True, help="Waiver JSON or YAML file."),
    ] = None,
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
    today: Annotated[
        str | None,
        typer.Option("--today", help="Evaluation date for waiver expiry checks."),
    ] = None,
) -> None:
    try:
        compiled = load_compiled_suite(suite)
        runset = load_runset(runset_path)
        report = evaluate_runset(
            compiled,
            runset,
            gate_profile=_gate_profile(fail_on_warn, fail_on_not_evaluated),
            waivers=load_waivers(tuple(waiver or ())),
            today=parse_cli_date(today) or date.today(),
        )
        source_root = source_project_root(
            (suite, runset_path),
            default_root=Path.cwd(),
        )
        artifact_root = artifact_project_root(
            (suite, runset_path, out_dir),
            default_root=source_root,
        )
        environment = environment_with_dependency_inventory(
            source_root,
            out_dir,
            artifact_root=artifact_root,
        )
        report = attach_evaluation_environment(report, environment)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    report_json, summary_json = write_evaluation_json(report, out_dir)
    write_evaluation_markdown(report, out_dir)
    _write_release_manifest(
        suite_path=suite,
        runset_path=runset_path,
        report_path=report_json,
        summary_path=summary_json,
        out_dir=out_dir,
        environment=environment,
        project_root=artifact_root,
    )
    render_evaluation_console(report, console)
    if report.candidate_vs_expectations.state is GateState.fail:
        raise typer.Exit(1)


@app.command("run")
def run(
    runset_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    suite: Annotated[Path, typer.Option("--suite", exists=True, readable=True)],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Report output directory.")],
    waiver: Annotated[
        list[Path] | None,
        typer.Option("--waiver", exists=True, readable=True, help="Waiver JSON or YAML file."),
    ] = None,
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
    today: Annotated[
        str | None,
        typer.Option("--today", help="Evaluation date for waiver expiry checks."),
    ] = None,
) -> None:
    evaluate(
        runset_path=runset_path,
        suite=suite,
        out_dir=out_dir,
        waiver=waiver,
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
        today=today,
    )


def _gate_profile(fail_on_warn: bool, fail_on_not_evaluated: bool) -> GateProfile:
    if not fail_on_warn and not fail_on_not_evaluated:
        return DEFAULT_GATE_PROFILE
    return DEFAULT_GATE_PROFILE.model_copy(
        update={
            "fail_on_warn": fail_on_warn,
            "fail_on_not_evaluated": fail_on_not_evaluated,
        }
    )


def _write_release_manifest(
    *,
    suite_path: Path,
    runset_path: Path,
    report_path: Path,
    summary_path: Path,
    out_dir: Path,
    environment: EnvironmentInfo,
    project_root: Path,
) -> None:
    manifest = build_release_manifest(
        (
            release_artifact("compiled-suite", suite_path, project_root=project_root),
            release_artifact("candidate-runset", runset_path, project_root=project_root),
            release_artifact("evaluation-report", report_path, project_root=project_root),
            release_artifact("evaluation-summary", summary_path, project_root=project_root),
            release_artifact(
                "dependency-inventory",
                out_dir / "dependency-inventory.json",
                project_root=project_root,
            ),
        ),
        environment=environment,
    )
    write_release_manifest(manifest, out_dir / "release-artifact-manifest.json")
