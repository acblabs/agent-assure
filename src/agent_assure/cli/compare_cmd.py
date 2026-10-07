from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.cli.dates import parse_cli_date
from agent_assure.cli.path_safety import ensure_inputs_do_not_alias_outputs
from agent_assure.cli.report_transaction import (
    mirrored_staging_directory,
    publish_staged_outputs,
)
from agent_assure.cli.waivers import load_waivers, waiver_evaluation_date
from agent_assure.compare.runsets import (
    ComparisonReport,
    InvalidComparisonError,
    compare_runsets,
)
from agent_assure.evaluation.evaluator import load_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.io_limits import MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
from agent_assure.onboarding.diagnostics import bounded_error
from agent_assure.policies.base import DEFAULT_GATE_PROFILE
from agent_assure.reporting.console import render_comparison_console
from agent_assure.reporting.environment import (
    artifact_project_root,
    attach_comparison_environment,
    build_release_manifest,
    environment_with_dependency_inventory,
    release_artifact,
    source_project_root,
    write_release_manifest,
)
from agent_assure.reporting.json_report import write_comparison_json
from agent_assure.reporting.markdown import write_comparison_markdown
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.environment import EnvironmentInfo

console = Console(markup=False)
_COMPARE_OUTPUT_NAMES = (
    "dependency-inventory.json",
    "comparison-report.json",
    "comparison-summary.json",
    "comparison-report.md",
    "release-artifact-manifest.json",
)


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
    today: Annotated[
        str | None,
        typer.Option("--today", help="Evaluation date for waiver expiry checks."),
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
    invalid_comparison_error: InvalidComparisonError | None = None
    try:
        ensure_inputs_do_not_alias_outputs(
            (suite, baseline_runset, candidate_runset, *(waiver or ())),
            (out_dir, *(out_dir / name for name in _COMPARE_OUTPUT_NAMES)),
            owner="compare",
        )
        source_root = source_project_root(
            (suite, baseline_runset, candidate_runset),
            default_root=Path.cwd(),
        )
        artifact_root = artifact_project_root(
            (suite, baseline_runset, candidate_runset, out_dir),
            default_root=source_root,
        )
        compiled = load_compiled_suite(suite)
        baseline = load_runset(baseline_runset)
        candidate = load_runset(candidate_runset)
        loaded_waivers = load_waivers(tuple(waiver or ()))
        evaluation_date = waiver_evaluation_date(
            parse_cli_date(today),
            waivers=loaded_waivers,
        )
        try:
            report = compare_runsets(
                compiled,
                baseline,
                candidate,
                gate_profile=gate_profile,
                waivers=loaded_waivers,
                today=evaluation_date,
            )
        except InvalidComparisonError as exc:
            if exc.report is None:
                raise
            invalid_comparison_error = exc
            report = exc.report

        with TemporaryDirectory(prefix="agent-assure-compare-") as staging_parent:
            staging_root = Path(staging_parent)
            staged_out_dir = mirrored_staging_directory(
                staging_root,
                out_dir=out_dir,
                artifact_root=artifact_root,
                owner="compare",
            )
            environment = environment_with_dependency_inventory(
                source_root,
                staged_out_dir,
                artifact_root=staging_root,
            )
            report = attach_comparison_environment(report, environment)
            _write_reports(
                report,
                staged_out_dir,
                suite_path=suite,
                baseline_runset=baseline_runset,
                candidate_runset=candidate_runset,
                environment=environment,
                source_project_root=artifact_root,
                output_project_root=staging_root,
            )
            publish_staged_outputs(
                staging_dir=staged_out_dir,
                out_dir=out_dir,
                output_names=_COMPARE_OUTPUT_NAMES,
                max_bytes=MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
                owner="compare",
            )
    except InvalidComparisonError as exc:
        raise typer.BadParameter(bounded_error(exc)) from exc
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(bounded_error(exc)) from exc

    render_comparison_console(report, console)
    if invalid_comparison_error is not None:
        raise typer.Exit(2) from invalid_comparison_error
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
    source_project_root: Path,
    output_project_root: Path,
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
        source_project_root=source_project_root,
        output_project_root=output_project_root,
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
    source_project_root: Path,
    output_project_root: Path,
) -> None:
    manifest = build_release_manifest(
        (
            release_artifact(
                "compiled-suite",
                suite_path,
                project_root=source_project_root,
            ),
            release_artifact(
                "baseline-runset",
                baseline_runset,
                project_root=source_project_root,
            ),
            release_artifact(
                "candidate-runset",
                candidate_runset,
                project_root=source_project_root,
            ),
            release_artifact(
                "comparison-report",
                report_path,
                project_root=output_project_root,
            ),
            release_artifact(
                "comparison-summary",
                summary_path,
                project_root=output_project_root,
            ),
            release_artifact(
                "dependency-inventory",
                out_dir / "dependency-inventory.json",
                project_root=output_project_root,
            ),
        ),
        environment=environment,
    )
    write_release_manifest(manifest, out_dir / "release-artifact-manifest.json")
