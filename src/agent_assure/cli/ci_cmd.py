from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.ci import ReportMode, gate_artifact, load_gate_artifact, run_ci
from agent_assure.cli.dates import parse_cli_date
from agent_assure.cli.waivers import load_waivers
from agent_assure.policies.base import DEFAULT_GATE_PROFILE

console = Console()


def ci(
    args: Annotated[
        list[str] | None,
        typer.Argument(help="CANDIDATE_RUNSET, or: gate SUMMARY_OR_PACKET_JSON"),
    ] = None,
    suite: Annotated[
        Path | None,
        typer.Option("--suite", exists=True, readable=True, help="Compiled suite JSON."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", exists=True, readable=True, help="Baseline RunSet JSON."),
    ] = None,
    out_dir: Annotated[
        Path | None,
        typer.Option("--out-dir", help="CI artifact output directory."),
    ] = None,
    report_mode: Annotated[
        ReportMode,
        typer.Option("--report-mode", help="Report all findings or stop after the first blocker."),
    ] = "full",
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
        typer.Option("--fail-on-not-evaluated", help="Treat not-evaluated summaries as blocking."),
    ] = False,
    today: Annotated[
        str | None,
        typer.Option("--today", help="Evaluation date for waiver expiry checks."),
    ] = None,
) -> None:
    argv = tuple(args or ())
    if argv and argv[0] == "gate":
        _gate_existing_artifact(
            argv,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
        return
    if len(argv) != 1 or suite is None or out_dir is None:
        raise typer.BadParameter("ci requires CANDIDATE_RUNSET, --suite, and --out-dir")
    candidate_runset = Path(argv[0])
    if not candidate_runset.exists():
        raise typer.BadParameter(f"candidate runset does not exist: {candidate_runset}")
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
    try:
        result = run_ci(
            candidate_runset,
            suite_path=suite,
            baseline_runset_path=baseline,
            out_dir=out_dir,
            report_mode=report_mode,
            gate_profile=gate_profile,
            waivers=load_waivers(tuple(waiver or ())),
            today=parse_cli_date(today),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if result.decision.exit_code:
        typer.echo(json.dumps(result.decision.model_dump(), sort_keys=True))
        raise typer.Exit(result.decision.exit_code)
    console.print(result.decision.message)


def _gate_existing_artifact(
    argv: tuple[str, ...],
    *,
    fail_on_warn: bool,
    fail_on_not_evaluated: bool,
) -> None:
    if len(argv) != 2:
        raise typer.BadParameter("ci gate requires SUMMARY_OR_PACKET_JSON")
    artifact = Path(argv[1])
    if not artifact.exists():
        raise typer.BadParameter(f"artifact does not exist: {artifact}")
    try:
        decision = gate_artifact(
            load_gate_artifact(artifact),
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(decision.message)
    if decision.exit_code:
        raise typer.Exit(decision.exit_code)
