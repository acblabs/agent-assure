from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.artifact_io import write_text_atomic
from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli.dates import parse_cli_date
from agent_assure.cli.path_safety import ensure_inputs_do_not_alias_outputs
from agent_assure.cli.report_transaction import (
    mirrored_staging_directory,
    publish_staged_outputs,
)
from agent_assure.cli.waivers import load_waivers, waiver_evaluation_date
from agent_assure.evaluation.evaluator import evaluate_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.io_limits import MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
from agent_assure.onboarding.diagnostics import bounded_error, display_path
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile
from agent_assure.privacy.redaction import assert_stream_payload_safe_for_persistence
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
from agent_assure.runner.fixture_runner import write_runset
from agent_assure.schema.common import GateState
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.stream import StreamProducerField, StreamRunRecord
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)
from agent_assure.streaming.ingestion import ingest_jsonl_events
from agent_assure.streaming.projection import stream_run_to_runset
from agent_assure.streaming.telemetry import stream_run_to_span_plans

app = typer.Typer(help="Streaming event ingestion and assurance.")
console = Console(markup=False)
_STREAM_OUTPUT_NAMES = (
    "dependency-inventory.json",
    "stream-runset.json",
    "stream-span-plans.json",
    "evaluation-report.json",
    "evaluation-summary.json",
    "evaluation-report.md",
    "release-artifact-manifest.json",
)


class SequenceScopeOption(StrEnum):
    global_scope = "global"
    producer_local = "producer_local"


@app.command("ingest")
def ingest(
    events_jsonl: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out", help="Stream run JSON output path.")],
    sequence_scope: Annotated[
        SequenceScopeOption | None,
        typer.Option(
            "--sequence-scope",
            help="Declared sequencing contract: global or producer_local.",
        ),
    ] = None,
    producer_field: Annotated[
        StreamProducerField | None,
        typer.Option(
            "--producer-field",
            help="Producer dimension for producer_local sequencing.",
        ),
    ] = None,
    diagnostics_out: Annotated[
        Path | None,
        typer.Option("--diagnostics-out", help="Optional diagnostics JSON path."),
    ] = None,
) -> None:
    if sequence_scope is None:
        raise typer.BadParameter("--sequence-scope is required")
    try:
        result = ingest_jsonl_events(
            events_jsonl,
            sequence_scope=sequence_scope.value,
            producer_field=producer_field,
        )
    except ValueError as exc:
        raise typer.BadParameter(bounded_error(exc)) from exc
    diagnostics_path = diagnostics_out or out.parent / "stream-ingestion-diagnostics.json"
    stream_payload = result.stream_run.model_dump(mode="json")
    diagnostics_payload = result.diagnostics.model_dump(mode="json")
    try:
        assert_stream_payload_safe_for_persistence(stream_payload)
        assert_stream_payload_safe_for_persistence(diagnostics_payload)
    except ValueError as exc:
        raise typer.BadParameter(bounded_error(exc)) from exc
    _write_json(out, stream_payload)
    _write_json(diagnostics_path, diagnostics_payload)
    console.print(
        "stream ingest: "
        f"events={result.stream_run.accepted_event_count} "
        f"duplicates={result.stream_run.duplicate_event_count} "
        f"out={display_path(out)}"
    )


@app.command("evaluate")
def evaluate(
    stream_run_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
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
        ensure_inputs_do_not_alias_outputs(
            (suite, stream_run_path, *(waiver or ())),
            (out_dir, *(out_dir / name for name in _STREAM_OUTPUT_NAMES)),
            owner="stream evaluate",
        )
        compiled = _load_suite(suite)
        stream_run = project_validated_artifact_payload(
            load_validated_artifact_payload(stream_run_path, "stream-run"),
            StreamRunRecord,
            kind="stream-run",
        )
        runset = stream_run_to_runset(stream_run, compiled, source_path=stream_run_path)
        source_root = source_project_root((suite, stream_run_path), default_root=Path.cwd())
        artifact_root = artifact_project_root(
            (suite, stream_run_path, out_dir),
            default_root=source_root,
        )
        loaded_waivers = load_waivers(tuple(waiver or ()))
        report = evaluate_runset(
            compiled,
            runset,
            gate_profile=_gate_profile(fail_on_warn, fail_on_not_evaluated),
            waivers=loaded_waivers,
            today=waiver_evaluation_date(parse_cli_date(today), waivers=loaded_waivers),
        )
        span_plan_payloads = []
        for plan in stream_run_to_span_plans(stream_run):
            payload = plan.model_dump(mode="json", warnings="error")
            validate_loaded_artifact_payload(payload, "span-plan")
            span_plan_payloads.append(payload)

        with TemporaryDirectory(prefix="agent-assure-stream-evaluate-") as staging_parent:
            staging_root = Path(staging_parent)
            staged_out_dir = mirrored_staging_directory(
                staging_root,
                out_dir=out_dir,
                artifact_root=artifact_root,
                owner="stream evaluate",
            )
            environment = environment_with_dependency_inventory(
                source_root,
                staged_out_dir,
                artifact_root=staging_root,
            )
            report = attach_evaluation_environment(report, environment)
            runset_path = staged_out_dir / "stream-runset.json"
            span_plans_path = staged_out_dir / "stream-span-plans.json"
            write_runset(runset, runset_path)
            _write_json(span_plans_path, span_plan_payloads)
            report_json, summary_json = write_evaluation_json(report, staged_out_dir)
            write_evaluation_markdown(report, staged_out_dir)
            _write_release_manifest(
                suite_path=suite,
                stream_run_path=stream_run_path,
                runset_path=runset_path,
                span_plans_path=span_plans_path,
                report_path=report_json,
                summary_path=summary_json,
                out_dir=staged_out_dir,
                environment=environment,
                source_project_root=artifact_root,
                output_project_root=staging_root,
            )
            publish_staged_outputs(
                staging_dir=staged_out_dir,
                out_dir=out_dir,
                output_names=_STREAM_OUTPUT_NAMES,
                max_bytes=MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES,
                owner="stream evaluate",
            )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(bounded_error(exc)) from exc

    render_evaluation_console(report, console)
    if report.candidate_vs_expectations.state is GateState.fail:
        raise typer.Exit(1)


def _load_suite(path: Path) -> CompiledSuite:
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


def _write_release_manifest(
    *,
    suite_path: Path,
    stream_run_path: Path,
    runset_path: Path,
    span_plans_path: Path,
    report_path: Path,
    summary_path: Path,
    out_dir: Path,
    environment: EnvironmentInfo,
    source_project_root: Path,
    output_project_root: Path,
) -> None:
    manifest = build_release_manifest(
        (
            release_artifact("suite", suite_path, project_root=source_project_root),
            release_artifact("stream-run", stream_run_path, project_root=source_project_root),
            release_artifact(
                "stream-projected-runset",
                runset_path,
                project_root=output_project_root,
            ),
            release_artifact(
                "stream-span-plans",
                span_plans_path,
                project_root=output_project_root,
            ),
            release_artifact(
                "evaluation-report",
                report_path,
                project_root=output_project_root,
            ),
            release_artifact(
                "evaluation-summary",
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


def _write_json(path: Path, payload: object) -> None:
    write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
