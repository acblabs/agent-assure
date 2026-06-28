from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.evaluation.evaluator import load_runset
from agent_assure.fixtures.loader import compiled_suite_digest, load_compiled_suite
from agent_assure.live.adapters import adapter_ids
from agent_assure.live.comparison import compare_live_reports, load_live_evaluation_report
from agent_assure.live.config import load_live_run_config
from agent_assure.live.drift import build_live_drift_report
from agent_assure.live.runner import run_live_suite
from agent_assure.live.statistics import evaluate_live_runset
from agent_assure.reporting.live import (
    write_live_comparison_json,
    write_live_comparison_markdown,
    write_live_drift_json,
    write_live_drift_markdown,
    write_live_evaluation_json,
    write_live_evaluation_markdown,
)
from agent_assure.runner.fixture_runner import write_runset
from agent_assure.schema.common import GateState
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.suite import CompiledSuite

app = typer.Typer(help="Live provider execution and stochastic reports.")
console = Console()


@app.command("adapters")
def list_adapters() -> None:
    for adapter_id in adapter_ids():
        console.print(adapter_id)


@app.command("run")
def run(
    compiled_suite: Annotated[Path, typer.Argument(exists=True, readable=True)],
    config: Annotated[Path, typer.Option("--config", exists=True, readable=True)],
    protocol: Annotated[Path, typer.Option("--protocol", exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out", help="Live RunSet JSON output path.")],
) -> None:
    try:
        compiled = load_compiled_suite(compiled_suite)
        live_config = load_live_run_config(config)
        protocol_record = _load_protocol(protocol)
        runset = run_live_suite(
            compiled,
            live_config,
            protocol=protocol_record,
            config_dir=config.parent,
        )
        write_runset(runset, out)
    except (KeyError, ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"live run set: {out}")


@app.command("evaluate")
def evaluate(
    runset_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    suite: Annotated[Path, typer.Option("--suite", exists=True, readable=True)],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Report output directory.")],
    protocol_path: Annotated[
        Path,
        typer.Option("--protocol", exists=True, readable=True, help="Live protocol JSON."),
    ],
    confidence_level: Annotated[
        str,
        typer.Option("--confidence-level", help="Rate confidence level."),
    ] = "0.950000",
) -> None:
    try:
        compiled = load_compiled_suite(suite)
        runset = load_runset(runset_path)
        protocol_record = _load_protocol(protocol_path)
        _validate_protocol(protocol_record, compiled, confidence_level)
        report = evaluate_live_runset(
            compiled,
            runset,
            protocol=protocol_record,
        )
    except (ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    write_live_evaluation_json(report, out_dir)
    write_live_evaluation_markdown(report, out_dir)
    console.print(
        "live evaluation: "
        f"state={report.state.value} observations={report.overall.observations} "
        f"pass_rate={report.overall.expectation_pass_rate.rate}"
    )
    if report.state is GateState.fail:
        raise typer.Exit(1)


@app.command("drift")
def drift(
    report_paths: Annotated[
        list[Path],
        typer.Argument(exists=True, readable=True, help="Ordered live evaluation reports."),
    ],
    protocol_path: Annotated[
        Path,
        typer.Option("--protocol", exists=True, readable=True, help="Live protocol JSON."),
    ],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Report output directory.")],
) -> None:
    try:
        reports = tuple(load_live_evaluation_report(path) for path in report_paths)
        protocol_record = _load_protocol(protocol_path)
        report = build_live_drift_report(reports, protocol=protocol_record)
    except (KeyError, ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    write_live_drift_json(report, out_dir)
    write_live_drift_markdown(report, out_dir)
    console.print(
        "live drift: "
        f"status={report.monitoring_status} windows={len(report.windows)} "
        f"comparability={report.comparability.status}"
    )
    if report.monitoring_status == "invalid":
        raise typer.Exit(1)


@app.command("compare")
def compare(
    baseline_report: Annotated[Path, typer.Argument(exists=True, readable=True)],
    candidate_report: Annotated[Path, typer.Argument(exists=True, readable=True)],
    protocol_path: Annotated[
        Path,
        typer.Option("--protocol", exists=True, readable=True, help="Live protocol JSON."),
    ],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Report output directory.")],
) -> None:
    try:
        baseline = load_live_evaluation_report(baseline_report)
        candidate = load_live_evaluation_report(candidate_report)
        protocol_record = _load_protocol(protocol_path)
        report = compare_live_reports(
            baseline,
            candidate,
            protocol=protocol_record,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    write_live_comparison_json(report, out_dir)
    write_live_comparison_markdown(report, out_dir)
    console.print(
        "live comparison: "
        f"state={report.state.value} diff={report.pass_rate_difference} "
        f"ci={report.difference_ci_lower}..{report.difference_ci_upper}"
    )
    if report.state is GateState.fail:
        raise typer.Exit(1)


def _load_protocol(path: Path) -> LiveProtocolRecord:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return LiveProtocolRecord.model_validate(payload)


def _validate_protocol(
    protocol: LiveProtocolRecord,
    compiled: CompiledSuite,
    confidence_level: str,
) -> None:
    if protocol.suite_id != compiled.suite_id:
        raise ValueError("live protocol suite_id does not match compiled suite")
    if protocol.suite_version != compiled.suite_version:
        raise ValueError("live protocol suite_version does not match compiled suite")
    if protocol.suite_digest != compiled_suite_digest(compiled):
        raise ValueError("live protocol suite_digest does not match compiled suite")
    if protocol.confidence_level != confidence_level:
        raise ValueError("live protocol confidence_level does not match command option")
