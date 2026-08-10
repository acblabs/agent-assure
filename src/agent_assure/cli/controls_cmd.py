from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from agent_assure import __version__
from agent_assure.artifact_io import file_sha256
from agent_assure.authoring.compiler import compile_suite
from agent_assure.authoring.yaml_nodes import MAX_YAML_BYTES
from agent_assure.cli.dates import parse_cli_date
from agent_assure.cli.waivers import load_waivers
from agent_assure.controls.coverage import build_control_coverage_report
from agent_assure.controls.efficacy import (
    build_control_efficacy_report,
    evaluate_control_efficacy_gate,
    load_threat_applicability_manifest,
)
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.io_limits import load_json_bounded
from agent_assure.mutation.campaign import (
    execute_mutation_campaign,
    mutation_campaign_exit_code,
)
from agent_assure.mutation.execution import execute_mutation
from agent_assure.onboarding.controls_mutation import (
    CONFIG_FILENAME,
    DEFAULT_SCAFFOLD_DIRECTORY,
    confined_config_input_directory,
    confined_config_input_file,
    load_controls_mutation_config,
    load_controls_mutation_input_binding,
    read_confined_config_input_file,
    require_confined_input_directory,
)
from agent_assure.onboarding.diagnostics import bounded_error as _bounded_error
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile, Waiver
from agent_assure.reporting.campaign import (
    ensure_inputs_do_not_alias_mutation_campaign_output,
    open_validated_mutation_campaign_artifact_generation,
    write_mutation_campaign_artifacts,
)
from agent_assure.reporting.controls import write_control_coverage_report
from agent_assure.reporting.efficacy import (
    CONTROL_EFFICACY_MARKDOWN_FILENAME,
    CONTROL_EFFICACY_REPORT_FILENAME,
    write_control_efficacy_report,
)
from agent_assure.reporting.mutation import (
    ensure_inputs_do_not_alias_mutation_output,
    write_mutation_artifacts,
)
from agent_assure.reporting.packet import load_evidence_packet
from agent_assure.schema.campaign import (
    CORE_MUTATION_CATALOG_ID,
    AssuranceMutationCampaign,
    AssuranceMutationCatalog,
    MutationApplicability,
    MutationCampaignMode,
)
from agent_assure.schema.common import GateState
from agent_assure.schema.controls import ControlFramework
from agent_assure.schema.mutation import RFC8785_SAFE_INTEGER_MAX, MutationResultState
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
)

app = typer.Typer(help="Control mapping and deterministic challenge utilities.")

_MUTATION_EXIT_CODES = {
    MutationResultState.caught: 0,
    MutationResultState.survived: 1,
    MutationResultState.invalid_operator: 2,
    MutationResultState.invalid_subject: 2,
    MutationResultState.inapplicable: 3,
    MutationResultState.execution_error: 4,
}


@app.callback()
def callback() -> None:
    """Map evidence and apply deterministic control challenges."""


@app.command("map")
def map_packet(
    packet: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, help="Evidence packet JSON."),
    ],
    framework: Annotated[
        ControlFramework,
        typer.Option("--framework", help="Framework mapping to apply."),
    ],
    out_dir: Annotated[
        Path,
        typer.Option("--out-dir", help="Report output directory."),
    ],
) -> None:
    try:
        evidence_packet = load_evidence_packet(packet)
        report = build_control_coverage_report(
            evidence_packet,
            framework=framework,
            evidence_packet_digest=file_sha256(packet),
        )
    except FileNotFoundError as exc:
        raise typer.BadParameter(str(exc), param_hint="built-in mapping") from exc
    except (ValueError, ValidationError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    report_json, report_markdown = write_control_coverage_report(report, out_dir)
    typer.echo(f"control coverage report: {report_json}")
    typer.echo(f"control coverage markdown: {report_markdown}")


@app.command("efficacy")
def efficacy(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            exists=True,
            readable=True,
            help="Controls-mutation configuration YAML.",
        ),
    ] = DEFAULT_SCAFFOLD_DIRECTORY / CONFIG_FILENAME,
    campaign: Annotated[
        Path | None,
        typer.Option(
            "--campaign",
            file_okay=False,
            help=(
                "Validated mutation campaign directory; defaults from config and "
                "must otherwise remain under the configuration directory."
            ),
        ),
    ] = None,
    allow_external_campaign: Annotated[
        bool,
        typer.Option(
            "--allow-external-campaign",
            help=(
                "Allow --campaign outside the configuration directory. "
                "Use only for verifier-controlled campaign inputs."
            ),
        ),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            file_okay=False,
            help="Report directory; defaults beside the configuration.",
        ),
    ] = None,
) -> None:
    """Build and gate exact catalog-relative control efficacy evidence."""
    try:
        onboarding = load_controls_mutation_config(config)
        # Keep lexical components visible for lstat checks; resolve only for containment.
        config_root = config.parent.absolute()
        if campaign is None and allow_external_campaign:
            raise ValueError("--allow-external-campaign requires --campaign")
        if campaign is None:
            configured_campaign = config_root / Path(onboarding.output_dir)
            try:
                os.lstat(configured_campaign)
            except FileNotFoundError as exc:
                raise ValueError(
                    "configured mutation campaign is missing; run "
                    "'agent-assure controls mutate' with the configured suite, "
                    "RunSet, catalog, operators, and output before efficacy"
                ) from exc
            campaign_dir = confined_config_input_directory(
                config_root,
                onboarding.output_dir,
                label="configured mutation campaign",
            )
        else:
            campaign_dir = require_confined_input_directory(
                campaign,
                root=campaign.parent if allow_external_campaign else config_root,
                label="mutation campaign",
            )
        manifest_path = confined_config_input_file(
            config_root,
            onboarding.threat_applicability_manifest,
            label="configured threat applicability manifest",
        )
        input_binding = load_controls_mutation_input_binding(
            onboarding,
            root=config_root,
        )
        report_dir = out or (config_root / "control-efficacy")
        if onboarding.package_version != __version__:
            raise ValueError(
                "controls-mutation package_version does not match the installed package"
            )
        threat_manifest = load_threat_applicability_manifest(
            manifest_path,
            reader=lambda path: read_confined_config_input_file(
                path,
                root=config_root,
                max_bytes=MAX_YAML_BYTES,
                label="configured threat applicability manifest",
            ),
        )
        with open_validated_mutation_campaign_artifact_generation(campaign_dir) as paths:
            campaign_inputs = [
                config,
                manifest_path,
                input_binding.suite_path,
                input_binding.runset_path,
                paths.catalog,
                paths.campaign,
                paths.generation_manifest,
            ]
            for operator_paths in paths.operator_artifacts:
                campaign_inputs.extend((operator_paths.result, operator_paths.evidence_descriptor))
                if operator_paths.mutated_runset is not None:
                    campaign_inputs.append(operator_paths.mutated_runset)
            _ensure_control_efficacy_inputs_do_not_alias_outputs(
                campaign_inputs,
                report_dir,
            )
            catalog = project_validated_artifact_payload(
                load_validated_artifact_payload(
                    paths.catalog,
                    "assurance-mutation-catalog",
                ),
                AssuranceMutationCatalog,
                kind="assurance-mutation-catalog",
            )
            campaign_artifact = project_validated_artifact_payload(
                load_validated_artifact_payload(
                    paths.campaign,
                    "assurance-mutation-campaign",
                ),
                AssuranceMutationCampaign,
                kind="assurance-mutation-campaign",
            )
        if campaign_artifact.catalog_id != onboarding.catalog_id:
            raise ValueError("campaign catalog identity does not match configuration")
        if campaign_artifact.selected_operator_order != onboarding.operator_ids:
            raise ValueError("campaign operator selection does not match configuration")
        if campaign_artifact.suite_digest != input_binding.suite_digest:
            raise ValueError("campaign suite digest does not match the configured suite snapshot")
        if campaign_artifact.source_digest != input_binding.source_digest:
            raise ValueError("campaign source digest does not match the configured RunSet snapshot")
        gate_config = onboarding.control_efficacy
        report = build_control_efficacy_report(
            campaign_artifact,
            catalog,
            threat_manifest,
            required_operator_ids=gate_config.required_operators,
        )
        decision = evaluate_control_efficacy_gate(report, gate_config)
        written = write_control_efficacy_report(
            report,
            report_dir,
            gate_decision=decision,
            gate_profile=gate_config,
        )
    except (OSError, TypeError, ValueError, ValidationError) as exc:
        typer.echo(f"invalid control-efficacy input: {_bounded_error(exc)}")
        raise typer.Exit(2) from exc

    typer.echo(f"control efficacy semantic state: {report.semantic_state.value}")
    typer.echo(f"control efficacy gate state: {decision.state.value}")
    typer.echo(
        "catalog detector kill ratio: "
        f"{report.catalog_kill_rate.numerator}/"
        f"{report.catalog_kill_rate.denominator} "
        f"({report.catalog_kill_rate.state.value})"
    )
    typer.echo(f"control efficacy report: {written.report}")
    typer.echo(f"control efficacy markdown: {written.markdown}")
    if decision.state is GateState.fail:
        raise typer.Exit(1)


@app.command("mutate")
def mutate(
    suite: Annotated[
        Path,
        typer.Option(
            "--suite",
            exists=True,
            readable=True,
            help="Authored suite YAML or compiled-suite JSON.",
        ),
    ],
    runset: Annotated[
        Path,
        typer.Option("--runset", exists=True, readable=True, help="Source RunSet JSON."),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", help="Mutation artifact output directory."),
    ],
    operator: Annotated[
        list[str] | None,
        typer.Option(
            "--operator",
            help=(
                "Built-in mutation operator ID. Repeatable with --catalog; "
                "exactly one is required without it."
            ),
        ),
    ] = None,
    catalog: Annotated[
        str | None,
        typer.Option(
            "--catalog",
            help=f"Run a mutation campaign from a closed catalog ({CORE_MUTATION_CATALOG_ID}).",
        ),
    ] = None,
    invariant_family: Annotated[
        list[str] | None,
        typer.Option(
            "--invariant-family",
            help="Select a catalog invariant family. Repeatable.",
        ),
    ] = None,
    threat_id: Annotated[
        list[str] | None,
        typer.Option(
            "--threat-id",
            help="Select catalog operators by threat-source ID. Repeatable.",
        ),
    ] = None,
    full_report: Annotated[
        bool,
        typer.Option(
            "--full-report",
            help="Execute every selected catalog operator (campaign default).",
        ),
    ] = False,
    fail_fast: Annotated[
        bool,
        typer.Option(
            "--fail-fast",
            help=(
                "Stop after the first survived, invalid_operator, invalid_subject, "
                "or execution_error result; caught and inapplicable continue."
            ),
        ),
    ] = False,
    seed: Annotated[
        int,
        typer.Option(
            "--seed",
            min=0,
            max=RFC8785_SAFE_INTEGER_MAX,
            help="RFC 8785-safe non-negative deterministic selection seed.",
        ),
    ] = 0,
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
    if out.exists() and not out.is_dir():
        typer.echo("invalid mutation input: --out must identify a directory")
        raise typer.Exit(2)

    operator_ids = tuple(operator or ())
    invariant_families = tuple(invariant_family or ())
    threat_ids = tuple(threat_id or ())
    if catalog is None:
        if len(operator_ids) != 1:
            typer.echo(
                "invalid mutation input: exactly one --operator is required without --catalog"
            )
            raise typer.Exit(2)
        if invariant_families or threat_ids or full_report or fail_fast:
            typer.echo(
                "invalid mutation input: campaign selection and mode flags require --catalog"
            )
            raise typer.Exit(2)
    else:
        if catalog != CORE_MUTATION_CATALOG_ID:
            typer.echo(
                "invalid mutation input: unsupported mutation catalog; "
                f"expected {CORE_MUTATION_CATALOG_ID}"
            )
            raise typer.Exit(2)
        if full_report and fail_fast:
            typer.echo(
                "invalid mutation input: --full-report and --fail-fast are mutually exclusive"
            )
            raise typer.Exit(2)

    source_inputs = (suite, runset, *(waiver or ()))
    try:
        if catalog is None:
            # Preserve the original single-mutation preflight. Waiver aliases
            # remain guarded transactionally by write_mutation_artifacts.
            ensure_inputs_do_not_alias_mutation_output((suite, runset), out)
        else:
            ensure_inputs_do_not_alias_mutation_campaign_output(
                source_inputs,
                out,
            )
        compiled = _load_mutation_suite(suite)
        source_payload = load_json_bounded(runset, label="RunSet JSON")
        waivers = load_waivers(tuple(waiver or ()))
        evaluation_date = parse_cli_date(today) or date.today()
    except (OSError, TypeError, ValueError) as exc:
        typer.echo(f"invalid mutation input: {_bounded_error(exc)}")
        raise typer.Exit(2) from exc

    if catalog is not None:
        _run_mutation_campaign(
            compiled=compiled,
            source_payload=source_payload,
            out=out,
            source_inputs=source_inputs,
            seed=seed,
            mode=(
                MutationCampaignMode.fail_fast if fail_fast else MutationCampaignMode.full_report
            ),
            operator_ids=operator_ids,
            invariant_families=invariant_families,
            threat_ids=threat_ids,
            gate_profile=_gate_profile(fail_on_warn, fail_on_not_evaluated),
            waivers=waivers,
            evaluation_date=evaluation_date,
        )
        return

    try:
        execution = execute_mutation(
            compiled,
            source_payload,
            operator_id=operator_ids[0],
            seed=seed,
            generated_at=_utc_now(),
            gate_profile=_gate_profile(fail_on_warn, fail_on_not_evaluated),
            waivers=waivers,
            evaluation_date=evaluation_date,
        )
        paths = write_mutation_artifacts(
            execution,
            out,
            source_inputs=source_inputs,
        )
    except (OSError, TypeError, ValueError) as exc:
        typer.echo(f"mutation execution error: {_bounded_error(exc)}")
        raise typer.Exit(4) from exc
    except Exception as exc:
        typer.echo("mutation execution error: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"mutation state: {execution.result.state.value}")
    typer.echo(f"mutation result: {paths.result}")
    typer.echo(f"evidence descriptor: {paths.evidence_descriptor}")
    if paths.mutated_runset is not None:
        typer.echo(f"mutated run set: {paths.mutated_runset}")
    if execution.result.state is MutationResultState.caught:
        typer.echo(
            "scope: the expected detector caught this exact fixture transformation; "
            f"independence_class={execution.result.independence_class.value}; "
            "this is not a broader model, planner, or red-team robustness result"
        )
    exit_code = _MUTATION_EXIT_CODES[execution.result.state]
    if exit_code:
        raise typer.Exit(exit_code)


def _run_mutation_campaign(
    *,
    compiled: CompiledSuite,
    source_payload: dict[str, object],
    out: Path,
    source_inputs: tuple[Path, ...],
    seed: int,
    mode: MutationCampaignMode,
    operator_ids: tuple[str, ...],
    invariant_families: tuple[str, ...],
    threat_ids: tuple[str, ...],
    gate_profile: GateProfile,
    waivers: tuple[Waiver, ...],
    evaluation_date: date,
) -> None:
    try:
        execution = execute_mutation_campaign(
            compiled,
            source_payload,
            seed=seed,
            generated_at=_utc_now(),
            mode=mode,
            operator_ids=operator_ids,
            invariant_families=invariant_families,
            threat_ids=threat_ids,
            gate_profile=gate_profile,
            waivers=waivers,
            evaluation_date=evaluation_date,
        )
    except (TypeError, ValueError) as exc:
        typer.echo(f"invalid mutation input: {_bounded_error(exc)}")
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("mutation campaign execution error: bounded internal error")
        raise typer.Exit(4) from exc

    try:
        paths = write_mutation_campaign_artifacts(
            execution,
            out,
            source_inputs=source_inputs,
        )
    except (OSError, TypeError, ValueError) as exc:
        typer.echo(f"mutation campaign execution error: {_bounded_error(exc)}")
        raise typer.Exit(4) from exc
    except Exception as exc:
        typer.echo("mutation campaign execution error: bounded internal error")
        raise typer.Exit(4) from exc

    typer.echo(f"mutation campaign completion: {execution.campaign.completion.value}")
    typer.echo(f"mutation catalog: {paths.catalog}")
    typer.echo(f"mutation campaign: {paths.campaign}")
    typer.echo(f"mutation operator results: {len(execution.campaign.operator_results)}")
    state_counts: Counter[MutationResultState] = Counter()
    applicability_counts: Counter[MutationApplicability] = Counter()
    for entry in execution.campaign.operator_results:
        state_counts[entry.result.state] += 1
        applicability_counts[entry.applicability] += 1
        typer.echo(
            "mutation operator result: "
            f"operator_id={entry.operator_id} "
            f"state={entry.result.state.value} "
            f"applicability={entry.applicability.value}"
        )
    typer.echo(
        "mutation campaign state counts: "
        + ", ".join(f"{state.value}={state_counts[state]}" for state in MutationResultState)
    )
    typer.echo(
        "mutation campaign applicability counts: "
        + ", ".join(
            f"{applicability.value}={applicability_counts[applicability]}"
            for applicability in MutationApplicability
        )
    )
    typer.echo(f"campaign generation manifest: {paths.generation_manifest}")
    independence_classes = ",".join(
        sorted(
            {entry.result.independence_class.value for entry in execution.campaign.operator_results}
        )
    )
    typer.echo(
        "scope: caught entries support only their exact fixture transformations "
        "and expected-detector contracts; caught does not assert exclusive detector "
        "isolation, and non-prohibited secondary findings remain visible; "
        "inapplicable entries were not exercised; "
        f"independence_classes={independence_classes}; "
        "this campaign is not a safety score or mutation kill rate; "
        "this is not a broader model, planner, or red-team robustness result"
    )
    exit_code = mutation_campaign_exit_code(execution.campaign)
    if exit_code:
        raise typer.Exit(exit_code)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ensure_control_efficacy_inputs_do_not_alias_outputs(
    source_inputs: Iterable[Path],
    out_dir: Path,
) -> None:
    try:
        resolved_out_dir = out_dir.resolve(strict=False)
    except RuntimeError as exc:
        raise ValueError("control-efficacy output directory cannot be safely resolved") from exc
    if resolved_out_dir == Path(resolved_out_dir.anchor):
        raise ValueError("control-efficacy output directory must not be a filesystem root")
    destinations = (
        resolved_out_dir / CONTROL_EFFICACY_REPORT_FILENAME,
        resolved_out_dir / CONTROL_EFFICACY_MARKDOWN_FILENAME,
    )
    destination_identities = {
        os.path.normcase(os.path.abspath(destination)) for destination in destinations
    }
    for source_input in source_inputs:
        try:
            resolved_source = source_input.resolve(strict=True)
        except RuntimeError as exc:
            raise ValueError("control-efficacy input path cannot be safely resolved") from exc
        source_identity = os.path.normcase(os.path.abspath(resolved_source))
        if source_identity in destination_identities or any(
            _paths_refer_to_same_file(source_input, destination) for destination in destinations
        ):
            raise ValueError("control-efficacy input aliases an owned output path")


def _paths_refer_to_same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return False


def _load_mutation_suite(path: Path) -> CompiledSuite:
    if path.suffix.lower() in {".yaml", ".yml"}:
        return compile_suite(path)
    return load_compiled_suite(path)


def _gate_profile(fail_on_warn: bool, fail_on_not_evaluated: bool) -> GateProfile:
    if not fail_on_warn and not fail_on_not_evaluated:
        return DEFAULT_GATE_PROFILE
    return DEFAULT_GATE_PROFILE.model_copy(
        update={
            "fail_on_warn": fail_on_warn,
            "fail_on_not_evaluated": fail_on_not_evaluated,
        }
    )
