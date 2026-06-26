from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.cli.waivers import load_waivers
from agent_assure.evaluation.evaluator import evaluate_runset, load_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile
from agent_assure.reporting.console import render_evaluation_console
from agent_assure.reporting.json_report import write_evaluation_json
from agent_assure.reporting.markdown import write_evaluation_markdown
from agent_assure.schema.common import GateState

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
) -> None:
    try:
        compiled = load_compiled_suite(suite)
        runset = load_runset(runset_path)
        report = evaluate_runset(
            compiled,
            runset,
            gate_profile=_gate_profile(fail_on_warn, fail_on_not_evaluated),
            waivers=load_waivers(tuple(waiver or ())),
            today=date.today(),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    write_evaluation_json(report, out_dir)
    write_evaluation_markdown(report, out_dir)
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
) -> None:
    evaluate(
        runset_path=runset_path,
        suite=suite,
        out_dir=out_dir,
        waiver=waiver,
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
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
