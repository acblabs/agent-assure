from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Annotated

import typer

from agent_assure.ci import (
    EfficacyEvidenceState,
    EfficacyVerificationMode,
    GateDecision,
    GateOutcome,
    ReportMode,
    gate_artifact,
    load_control_efficacy_verifier_policy,
    load_gate_artifact,
    run_ci,
)
from agent_assure.cli.dates import parse_cli_date
from agent_assure.cli.waivers import load_waivers
from agent_assure.policies.base import DEFAULT_GATE_PROFILE
from agent_assure.reporting.environment import source_project_root
from agent_assure.schema.packet import EvidencePacket


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
    artifact_root: Annotated[
        Path | None,
        typer.Option(
            "--artifact-root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help=(
                "Trusted root for evidence-packet release-manifest paths; "
                "defaults to a root inferred from the packet location."
            ),
        ),
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
    efficacy_policy: Annotated[
        Path | None,
        typer.Option(
            "--efficacy-policy",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help=(
                "Verifier-owned controls-mutation YAML used for strict efficacy, "
                "or a gate-profile JSON for advisory policy override."
            ),
        ),
    ] = None,
    strict_efficacy: Annotated[
        bool,
        typer.Option(
            "--strict-efficacy/--allow-advisory-efficacy",
            help=(
                "When efficacy evidence is present, require verifier-owned policy "
                "and complete, all-caught evidence; advisory mode accepts the embedded profile."
            ),
        ),
    ] = True,
    require_efficacy: Annotated[
        bool,
        typer.Option(
            "--require-efficacy",
            help=(
                "Require an evidence packet to carry control-efficacy evidence. "
                "Supplying --efficacy-policy implies this requirement."
            ),
        ),
    ] = False,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            help="Decision output format: text or json.",
        ),
    ] = "text",
    today: Annotated[
        str | None,
        typer.Option("--today", help="Evaluation date for waiver expiry checks."),
    ] = None,
) -> None:
    if output_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be text or json")
    argv = tuple(args or ())
    if argv and argv[0] == "gate":
        _gate_existing_artifact(
            argv,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
            efficacy_policy=efficacy_policy,
            strict_efficacy=strict_efficacy,
            require_efficacy=require_efficacy,
            output_format=output_format,
            artifact_root=artifact_root,
        )
        return
    if artifact_root is not None:
        raise typer.BadParameter("--artifact-root is only valid with ci gate")
    if efficacy_policy is not None:
        raise typer.BadParameter("--efficacy-policy is only valid with ci gate")
    if require_efficacy:
        raise typer.BadParameter("--require-efficacy is only valid with ci gate")
    if len(argv) != 1 or suite is None or out_dir is None:
        raise typer.BadParameter("ci requires CANDIDATE_RUNSET, --suite, and --out-dir")
    candidate_runset = Path(argv[0])
    if not candidate_runset.exists():
        if output_format == "json":
            _exit_with_invalid_json(
                message=f"ci invalid: candidate runset does not exist: {candidate_runset}",
                artifact_path=candidate_runset,
            )
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
    waiver_paths = tuple(waiver or ())
    try:
        result = run_ci(
            candidate_runset,
            suite_path=suite,
            baseline_runset_path=baseline,
            out_dir=out_dir,
            report_mode=report_mode,
            gate_profile=gate_profile,
            waivers=load_waivers(waiver_paths),
            today=parse_cli_date(today),
            source_input_paths=waiver_paths,
        )
    except (OSError, ValueError) as exc:
        if output_format == "json":
            _exit_with_invalid_json(
                message=f"ci invalid: {exc}",
                artifact_path=candidate_runset,
            )
        raise typer.BadParameter(str(exc)) from exc
    decision = replace(
        result.decision,
        artifact_kind=result.decision.artifact_kind or "evidence-packet",
        artifact_path=result.decision.artifact_path or str(result.packet_path),
    )
    _emit_decision(
        decision,
        output_format=output_format,
        legacy_json_on_failure=True,
    )
    if decision.exit_code:
        raise typer.Exit(decision.exit_code)


def _emit_decision(
    decision: GateDecision,
    *,
    output_format: str,
    legacy_json_on_failure: bool = False,
) -> None:
    if output_format == "json" or (legacy_json_on_failure and decision.exit_code):
        typer.echo(json.dumps(decision.model_dump(), sort_keys=True))
        return
    typer.echo(decision.message)


def _exit_with_invalid_json(
    *,
    message: str,
    artifact_path: Path,
    strict_efficacy: bool | None = None,
    require_efficacy: bool = False,
) -> None:
    decision = GateDecision(
        exit_code=2,
        outcome=GateOutcome.invalid,
        message=message,
        artifact_path=str(artifact_path),
        efficacy_evidence=EfficacyEvidenceState.not_applicable,
        efficacy_verification=(
            EfficacyVerificationMode.not_requested
            if strict_efficacy is None
            else (
                EfficacyVerificationMode.strict
                if strict_efficacy
                else EfficacyVerificationMode.advisory
            )
        ),
        efficacy_required=require_efficacy,
    )
    _emit_decision(decision, output_format="json")
    raise typer.Exit(decision.exit_code)


def _gate_existing_artifact(
    argv: tuple[str, ...],
    *,
    fail_on_warn: bool,
    fail_on_not_evaluated: bool,
    efficacy_policy: Path | None,
    strict_efficacy: bool,
    require_efficacy: bool,
    output_format: str,
    artifact_root: Path | None,
) -> None:
    if len(argv) != 2:
        raise typer.BadParameter("ci gate requires SUMMARY_OR_PACKET_JSON")
    artifact = Path(argv[1])
    if not artifact.exists():
        if output_format == "json":
            _exit_with_invalid_json(
                message=f"ci gate invalid: artifact does not exist: {artifact}",
                artifact_path=artifact,
                strict_efficacy=strict_efficacy,
                require_efficacy=require_efficacy or efficacy_policy is not None,
            )
        raise typer.BadParameter(f"artifact does not exist: {artifact}")
    try:
        verifier_policy = (
            load_control_efficacy_verifier_policy(efficacy_policy)
            if efficacy_policy is not None
            else None
        )
        loaded_artifact = load_gate_artifact(artifact)
        trusted_artifact_root = None
        if isinstance(loaded_artifact, EvidencePacket):
            if loaded_artifact.release_manifest is not None:
                trusted_artifact_root = (
                    artifact_root or source_project_root((artifact,), default_root=Path.cwd())
                ).resolve()
            elif artifact_root is not None:
                trusted_artifact_root = artifact_root.resolve()
        elif artifact_root is not None:
            raise ValueError("--artifact-root is only valid when gating an evidence packet")
        decision = gate_artifact(
            loaded_artifact,
            artifact_root=trusted_artifact_root,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
            verifier_efficacy_policy=verifier_policy,
            strict_efficacy=strict_efficacy,
            require_efficacy=require_efficacy,
        )
    except (OSError, ValueError) as exc:
        if output_format == "json":
            _exit_with_invalid_json(
                message=f"ci gate invalid: {exc}",
                artifact_path=artifact,
                strict_efficacy=strict_efficacy,
                require_efficacy=require_efficacy or efficacy_policy is not None,
            )
        raise typer.BadParameter(str(exc)) from exc
    decision = replace(
        decision,
        artifact_kind=decision.artifact_kind or loaded_artifact.artifact_kind,
        artifact_path=decision.artifact_path or str(artifact),
    )
    _emit_decision(decision, output_format=output_format)
    if decision.exit_code:
        raise typer.Exit(decision.exit_code)
