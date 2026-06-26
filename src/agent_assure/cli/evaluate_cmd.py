from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated

import typer
import yaml
from rich.console import Console

from agent_assure.evaluation.evaluator import evaluate_runset, load_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile, Waiver
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
) -> None:
    try:
        compiled = load_compiled_suite(suite)
        runset = load_runset(runset_path)
        report = evaluate_runset(
            compiled,
            runset,
            gate_profile=_gate_profile(fail_on_warn),
            waivers=_load_waivers(tuple(waiver or ())),
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
) -> None:
    evaluate(
        runset_path=runset_path,
        suite=suite,
        out_dir=out_dir,
        waiver=waiver,
        fail_on_warn=fail_on_warn,
    )


def _gate_profile(fail_on_warn: bool) -> GateProfile:
    if not fail_on_warn:
        return DEFAULT_GATE_PROFILE
    return DEFAULT_GATE_PROFILE.model_copy(update={"fail_on_warn": True})


def _load_waivers(paths: tuple[Path, ...]) -> tuple[Waiver, ...]:
    waivers: list[Waiver] = []
    for path in paths:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "waivers" in payload:
            raw_waivers = payload["waivers"]
        else:
            raw_waivers = payload
        if isinstance(raw_waivers, dict):
            raw_waivers = [raw_waivers]
        if not isinstance(raw_waivers, list):
            raise typer.BadParameter(f"waiver file must contain an object or list: {path}")
        waivers.extend(Waiver.model_validate(item) for item in raw_waivers)
    return tuple(waivers)
