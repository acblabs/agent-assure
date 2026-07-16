from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.evaluation.evaluator import load_runset
from agent_assure.fixtures.loader import compiled_suite_digest, load_compiled_suite
from agent_assure.io_limits import load_json_bounded
from agent_assure.live.adapters import TrustedLiveExecution, adapter_ids
from agent_assure.live.comparison import compare_live_reports, load_live_evaluation_report
from agent_assure.live.config import load_live_run_config
from agent_assure.live.drift import build_live_drift_report
from agent_assure.live.runner import run_live_suite
from agent_assure.live.statistics import evaluate_live_runset
from agent_assure.live.trajectory import build_live_trajectory_report
from agent_assure.reporting.live import (
    write_live_comparison_json,
    write_live_comparison_markdown,
    write_live_drift_json,
    write_live_drift_markdown,
    write_live_evaluation_json,
    write_live_evaluation_markdown,
    write_live_trajectory_json,
    write_live_trajectory_markdown,
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
    trust_config: Annotated[
        bool,
        typer.Option(
            "--trust-config",
            help="Acknowledge trusted live config execution or network egress.",
        ),
    ] = False,
    ci: Annotated[
        bool,
        typer.Option(
            "--ci",
            help="Non-interactive trusted-config acknowledgment for controlled CI jobs.",
        ),
    ] = False,
    allow_network: Annotated[
        bool,
        typer.Option(
            "--allow-network",
            help="Allow a trusted live config to send prompts or metadata to a network endpoint.",
        ),
    ] = False,
    allow_external_script: Annotated[
        bool,
        typer.Option(
            "--allow-external-script",
            help="Allow a trusted live config to execute an external script on this host.",
        ),
    ] = False,
    allow_script_env: Annotated[
        bool,
        typer.Option(
            "--allow-script-env",
            help="Allow a trusted live config to pass selected host environment variables.",
        ),
    ] = False,
    strict_endpoint_resolution: Annotated[
        bool,
        typer.Option(
            "--strict-endpoint-resolution",
            help=(
                "Compatibility flag; current network adapters already fail closed "
                "if endpoint hosts cannot be DNS-screened."
            ),
        ),
    ] = False,
) -> None:
    try:
        compiled = load_compiled_suite(compiled_suite)
        live_config = load_live_run_config(config)
        trust = _confirm_trusted_live_config(
            live_config,
            trust_config=trust_config,
            ci=ci,
            allow_network=allow_network,
            allow_external_script=allow_external_script,
            allow_script_env=allow_script_env,
        )
        protocol_record = _load_protocol(protocol)
        runset = run_live_suite(
            compiled,
            live_config,
            protocol=protocol_record,
            config_dir=config.parent,
            require_resolvable_endpoint_hosts=_require_resolvable_endpoint_hosts(
                live_config,
                strict_endpoint_resolution=strict_endpoint_resolution,
            ),
            trust=trust,
        )
        write_runset(runset, out)
    except (KeyError, ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"live run set: {out}")


def _confirm_trusted_live_config(
    config: object,
    *,
    trust_config: bool,
    ci: bool,
    allow_network: bool,
    allow_external_script: bool,
    allow_script_env: bool,
) -> TrustedLiveExecution:
    risks = _trusted_live_config_risks(config)
    if not risks:
        return TrustedLiveExecution()
    reasons = tuple(reason for _, reason, _ in risks)
    missing_flags = tuple(
        flag
        for risk_id, _, flag in risks
        if (risk_id == "network" and not allow_network)
        or (risk_id == "external-script" and not allow_external_script)
        or (risk_id == "script-env" and not allow_script_env)
    )
    message = "live config requires trust: " + "; ".join(reasons)
    if ci and not trust_config:
        raise ValueError(
            f"{message}; --ci is non-interactive only and requires --trust-config"
        )
    if (ci or trust_config) and missing_flags:
        flags = ", ".join(missing_flags)
        raise ValueError(f"{message}; explicit allow flag(s) required: {flags}")
    if trust_config:
        console.print(f"warning: {message}")
        return _trusted_live_execution_for_risks(risks)
    if not typer.confirm(f"{message}. Continue?", default=False):
        raise typer.Abort()
    return _trusted_live_execution_for_risks(risks)


def _trusted_live_config_reasons(config: object) -> tuple[str, ...]:
    return tuple(reason for _, reason, _ in _trusted_live_config_risks(config))


def _trusted_live_execution_for_risks(
    risks: tuple[tuple[str, str, str], ...],
) -> TrustedLiveExecution:
    risk_ids = {risk_id for risk_id, _, _ in risks}
    return TrustedLiveExecution(
        allow_network="network" in risk_ids,
        allow_external_script="external-script" in risk_ids,
        allow_script_env="script-env" in risk_ids,
    )


def _require_resolvable_endpoint_hosts(
    config: object,
    *,
    strict_endpoint_resolution: bool,
) -> bool:
    adapter = getattr(config, "adapter", None)
    return strict_endpoint_resolution or bool(getattr(adapter, "allow_network", False))


def _trusted_live_config_risks(config: object) -> tuple[tuple[str, str, str], ...]:
    adapter = getattr(config, "adapter", None)
    if adapter is None:
        return ()
    risks: list[tuple[str, str, str]] = []
    if getattr(adapter, "adapter_id", None) == "external-script":
        risks.append(
            (
                "external-script",
                "external-script executes host code with caller privileges",
                "--allow-external-script",
            )
        )
    if getattr(adapter, "allow_network", False):
        risks.append(
            (
                "network",
                "allow_network can send prompts and metadata to a configured endpoint",
                "--allow-network",
            )
        )
    if getattr(adapter, "script_env_allowlist", ()):
        risks.append(
            (
                "script-env",
                "script_env_allowlist passes selected host environment variables",
                "--allow-script-env",
            )
        )
    return tuple(risks)


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


@app.command("trajectory")
def trajectory(
    runset_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    report_path: Annotated[
        Path,
        typer.Option(
            "--report",
            exists=True,
            readable=True,
            help="Live evaluation report JSON.",
        ),
    ],
    protocol_path: Annotated[
        Path,
        typer.Option("--protocol", exists=True, readable=True, help="Live protocol JSON."),
    ],
    out_dir: Annotated[Path, typer.Option("--out-dir", help="Report output directory.")],
) -> None:
    try:
        runset = load_runset(runset_path)
        evaluation_report = load_live_evaluation_report(report_path)
        protocol_record = _load_protocol(protocol_path)
        report = build_live_trajectory_report(
            runset,
            evaluation_report,
            protocol=protocol_record,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    write_live_trajectory_json(report, out_dir)
    write_live_trajectory_markdown(report, out_dir)
    console.print(
        "live trajectory: "
        f"status={report.trajectory_status} observations={report.observations} "
        f"transitions={len(report.transitions)}"
    )
    if report.trajectory_status == "invalid":
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
    payload = load_json_bounded(path)
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
