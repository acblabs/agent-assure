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
from agent_assure.reporting.packet import packet_summary_files_binding_error
from agent_assure.reporting.text_safety import sanitize_display_text
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
    release_profile: Annotated[
        bool,
        typer.Option(
            "--release-profile",
            help=(
                "Apply the release-facing CI efficacy policy only (not publication "
                "authorization): evidence packet only, verifier-owned policy required, "
                "strict efficacy, and warnings/not-evaluated findings block."
            ),
        ),
    ] = False,
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
                "Explicitly restate the default evidence-packet efficacy requirement. "
                "Supplying --efficacy-policy also requires the evidence."
            ),
        ),
    ] = False,
    allow_missing_efficacy_for_migration: Annotated[
        bool,
        typer.Option(
            "--allow-missing-efficacy-for-migration",
            help=(
                "Allow an evidence packet without efficacy only for a temporary, "
                "non-assurance migration; the decision records the weaker profile."
            ),
        ),
    ] = False,
    require_evidence_sensitivity: Annotated[
        bool,
        typer.Option(
            "--require-evidence-sensitivity",
            help=(
                "Require an evidence packet to carry an evidence-sensitivity "
                "report; this is a verifier-owned presence policy."
            ),
        ),
    ] = False,
    require_stochastic_evidence_sensitivity: Annotated[
        bool,
        typer.Option(
            "--require-stochastic-evidence-sensitivity",
            help=(
                "Require an evidence packet to carry a verdict-bearing passing "
                "stochastic evidence-sensitivity report."
            ),
        ),
    ] = False,
    allow_sensitivity_non_verdict: Annotated[
        bool,
        typer.Option(
            "--allow-sensitivity-non-verdict",
            help=(
                "Explicitly allow a deterministic or stochastic sensitivity-bearing "
                "packet with a non-verdict result."
            ),
        ),
    ] = False,
    allow_legacy_unbound_comparison: Annotated[
        bool,
        typer.Option(
            "--allow-legacy-unbound-comparison",
            help=(
                "Explicit compatibility opt-in for a legacy comparison-bearing "
                "packet that lacks authenticated baseline and candidate RunSet digests."
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
    is_gate = bool(argv and argv[0] == "gate")
    if allow_missing_efficacy_for_migration:
        if release_profile or require_efficacy or efficacy_policy is not None:
            raise typer.BadParameter(
                "--allow-missing-efficacy-for-migration cannot be combined with "
                "--release-profile, --require-efficacy, or --efficacy-policy"
            )
    if release_profile:
        if not is_gate:
            raise typer.BadParameter("--release-profile is only valid with ci gate")
        if efficacy_policy is None:
            raise typer.BadParameter("--release-profile requires --efficacy-policy")
        if not strict_efficacy:
            raise typer.BadParameter(
                "--release-profile cannot be combined with --allow-advisory-efficacy"
            )
        if allow_sensitivity_non_verdict:
            raise typer.BadParameter(
                "--release-profile cannot be combined with --allow-sensitivity-non-verdict"
            )
        if allow_legacy_unbound_comparison:
            raise typer.BadParameter(
                "--release-profile cannot be combined with --allow-legacy-unbound-comparison"
            )
        fail_on_warn = True
        fail_on_not_evaluated = True
        require_efficacy = True
    if is_gate:
        _gate_existing_artifact(
            argv,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
            efficacy_policy=efficacy_policy,
            strict_efficacy=strict_efficacy,
            require_efficacy=require_efficacy,
            allow_missing_efficacy_for_migration=(allow_missing_efficacy_for_migration),
            require_evidence_sensitivity=require_evidence_sensitivity,
            require_stochastic_evidence_sensitivity=(require_stochastic_evidence_sensitivity),
            allow_sensitivity_non_verdict=allow_sensitivity_non_verdict,
            allow_legacy_unbound_comparison=allow_legacy_unbound_comparison,
            output_format=output_format,
            artifact_root=artifact_root,
            release_profile=release_profile,
        )
        return
    if artifact_root is not None:
        raise typer.BadParameter("--artifact-root is only valid with ci gate")
    if efficacy_policy is not None:
        raise typer.BadParameter("--efficacy-policy is only valid with ci gate")
    if require_efficacy:
        raise typer.BadParameter("--require-efficacy is only valid with ci gate")
    if require_evidence_sensitivity:
        raise typer.BadParameter("--require-evidence-sensitivity is only valid with ci gate")
    if require_stochastic_evidence_sensitivity:
        raise typer.BadParameter(
            "--require-stochastic-evidence-sensitivity is only valid with ci gate"
        )
    if allow_sensitivity_non_verdict:
        raise typer.BadParameter("--allow-sensitivity-non-verdict is only valid with ci gate")
    if allow_legacy_unbound_comparison:
        raise typer.BadParameter("--allow-legacy-unbound-comparison is only valid with ci gate")
    if len(argv) != 1 or suite is None or out_dir is None:
        raise typer.BadParameter("ci requires CANDIDATE_RUNSET, --suite, and --out-dir")
    candidate_runset = Path(argv[0])
    if not candidate_runset.exists():
        if output_format == "json":
            _exit_with_invalid_json(
                message=f"ci invalid: candidate runset does not exist: {candidate_runset}",
                artifact_path=candidate_runset,
            )
        raise typer.BadParameter(
            sanitize_display_text(f"candidate runset does not exist: {candidate_runset}")
        )
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
            allow_missing_efficacy_for_migration=(allow_missing_efficacy_for_migration),
        )
    except (OSError, ValueError) as exc:
        if output_format == "json":
            _exit_with_invalid_json(
                message=f"ci invalid: {exc}",
                artifact_path=candidate_runset,
            )
        raise typer.BadParameter(sanitize_display_text(exc)) from exc
    decision = replace(
        result.decision,
        artifact_kind=result.decision.artifact_kind or "evidence-packet",
        artifact_path=result.decision.artifact_path or str(result.packet_path),
        message=(
            result.decision.message
            + (
                " policy_profile=non-assurance-migration"
                if allow_missing_efficacy_for_migration
                else ""
            )
        ),
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
    typer.echo(sanitize_display_text(decision.message))


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
    allow_missing_efficacy_for_migration: bool,
    require_evidence_sensitivity: bool,
    require_stochastic_evidence_sensitivity: bool,
    allow_sensitivity_non_verdict: bool,
    allow_legacy_unbound_comparison: bool,
    output_format: str,
    artifact_root: Path | None,
    release_profile: bool,
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
        raise typer.BadParameter(sanitize_display_text(f"artifact does not exist: {artifact}"))
    try:
        if artifact_root is not None:
            if not artifact_root.exists():
                raise ValueError(f"--artifact-root does not exist: {artifact_root}")
            if not artifact_root.is_dir():
                raise ValueError(f"--artifact-root must be a directory: {artifact_root}")
        verifier_policy = (
            load_control_efficacy_verifier_policy(efficacy_policy)
            if efficacy_policy is not None
            else None
        )
        loaded_artifact = load_gate_artifact(artifact)
        if release_profile and not isinstance(loaded_artifact, EvidencePacket):
            raise ValueError("--release-profile requires an evidence packet")
        if allow_missing_efficacy_for_migration:
            if not isinstance(loaded_artifact, EvidencePacket):
                raise ValueError(
                    "--allow-missing-efficacy-for-migration requires an evidence packet"
                )
            if loaded_artifact.control_efficacy is not None:
                raise ValueError(
                    "--allow-missing-efficacy-for-migration is unused because the "
                    "evidence packet already carries control-efficacy evidence"
                )
        trusted_artifact_root = None
        if isinstance(loaded_artifact, EvidencePacket):
            if loaded_artifact.release_manifest is not None:
                trusted_artifact_root = (
                    artifact_root.resolve()
                    if artifact_root is not None
                    else _infer_packet_artifact_root(loaded_artifact, artifact)
                )
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
            require_efficacy=True if require_efficacy else None,
            allow_missing_efficacy_for_migration=(allow_missing_efficacy_for_migration),
            require_evidence_sensitivity=require_evidence_sensitivity,
            require_stochastic_evidence_sensitivity=(require_stochastic_evidence_sensitivity),
            allow_sensitivity_non_verdict=allow_sensitivity_non_verdict,
            allow_legacy_unbound_comparison=allow_legacy_unbound_comparison,
        )
    except (OSError, ValueError) as exc:
        if output_format == "json":
            _exit_with_invalid_json(
                message=f"ci gate invalid: {exc}",
                artifact_path=artifact,
                strict_efficacy=strict_efficacy,
                require_efficacy=require_efficacy or efficacy_policy is not None,
            )
        raise typer.BadParameter(sanitize_display_text(exc)) from exc
    policy_profile_suffix = (
        " policy_profile=release"
        if release_profile
        else (
            " policy_profile=non-assurance-migration"
            if allow_missing_efficacy_for_migration
            else ""
        )
    )
    decision = replace(
        decision,
        artifact_kind=decision.artifact_kind or loaded_artifact.artifact_kind,
        artifact_path=decision.artifact_path or str(artifact),
        message=f"{decision.message}{policy_profile_suffix}",
    )
    _emit_decision(decision, output_format=output_format)
    if decision.exit_code:
        raise typer.Exit(decision.exit_code)


def _infer_packet_artifact_root(packet: EvidencePacket, packet_path: Path) -> Path:
    """Select one fully verified root across current and legacy packet layouts."""
    packet_root = packet_path.resolve().parent
    legacy_root = source_project_root((packet_path,), default_root=Path.cwd()).resolve()
    candidates: list[tuple[str, Path]] = []
    for label, candidate in (
        ("packet directory", packet_root),
        ("legacy source/Git root", legacy_root),
    ):
        if all(candidate != existing for _, existing in candidates):
            candidates.append((label, candidate))

    results = tuple(
        (
            label,
            candidate,
            packet_summary_files_binding_error(packet, artifact_root=candidate),
        )
        for label, candidate in candidates
    )
    valid = tuple((label, candidate) for label, candidate, error in results if error is None)
    if len(valid) == 1:
        return valid[0][1]
    if len(valid) > 1:
        labels = " and ".join(label for label, _ in valid)
        raise ValueError(
            "evidence packet artifact root is ambiguous: "
            f"{labels} both satisfy every release-manifest binding; "
            "pass --artifact-root to select the trusted root explicitly"
        )
    failures = "; ".join(f"{label}: {error}" for label, _, error in results)
    raise ValueError(
        "evidence packet release-manifest binding failed for every inferred "
        f"artifact root: {failures}"
    )
