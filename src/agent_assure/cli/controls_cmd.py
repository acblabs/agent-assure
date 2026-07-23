from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from agent_assure.artifact_io import file_sha256
from agent_assure.authoring.compiler import compile_suite
from agent_assure.controls.coverage import build_control_coverage_report
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.io_limits import load_json_bounded
from agent_assure.mutation.execution import execute_mutation
from agent_assure.privacy.redaction import redact_text
from agent_assure.reporting.controls import write_control_coverage_report
from agent_assure.reporting.mutation import (
    ensure_inputs_do_not_alias_mutation_output,
    write_mutation_artifacts,
)
from agent_assure.reporting.packet import load_evidence_packet
from agent_assure.schema.controls import ControlFramework
from agent_assure.schema.mutation import RFC8785_SAFE_INTEGER_MAX, MutationResultState
from agent_assure.schema.suite import CompiledSuite

app = typer.Typer(help="Control mapping and deterministic challenge utilities.")
console = Console()

_MUTATION_EXIT_CODES = {
    MutationResultState.caught: 0,
    MutationResultState.survived: 1,
    MutationResultState.invalid_operator: 2,
    MutationResultState.invalid_subject: 2,
    MutationResultState.inapplicable: 3,
    MutationResultState.execution_error: 4,
}
_ERROR_SUMMARY_CHARS = 1024


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
    console.print(f"control coverage report: {report_json}")
    console.print(f"control coverage markdown: {report_markdown}")


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
    operator: Annotated[
        str,
        typer.Option("--operator", help="Built-in mutation operator ID."),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", help="Mutation artifact output directory."),
    ],
    seed: Annotated[
        int,
        typer.Option(
            "--seed",
            min=0,
            max=RFC8785_SAFE_INTEGER_MAX,
            help="RFC 8785-safe non-negative deterministic selection seed.",
        ),
    ] = 0,
) -> None:
    if out.exists() and not out.is_dir():
        console.print("invalid mutation input: --out must identify a directory")
        raise typer.Exit(2)

    try:
        ensure_inputs_do_not_alias_mutation_output((suite, runset), out)
        compiled = _load_mutation_suite(suite)
        source_payload = load_json_bounded(runset, label="RunSet JSON")
    except (OSError, TypeError, ValueError) as exc:
        console.print(f"invalid mutation input: {_bounded_error(exc)}")
        raise typer.Exit(2) from exc

    try:
        execution = execute_mutation(
            compiled,
            source_payload,
            operator_id=operator,
            seed=seed,
            generated_at=_utc_now(),
        )
        paths = write_mutation_artifacts(
            execution,
            out,
            source_inputs=(suite, runset),
        )
    except (OSError, TypeError, ValueError) as exc:
        console.print(f"mutation execution error: {_bounded_error(exc)}")
        raise typer.Exit(4) from exc
    except Exception as exc:
        console.print("mutation execution error: bounded internal error")
        raise typer.Exit(4) from exc

    console.print(f"mutation state: {execution.result.state.value}")
    console.print(f"mutation result: {paths.result}")
    console.print(f"evidence descriptor: {paths.evidence_descriptor}")
    if paths.mutated_runset is not None:
        console.print(f"mutated run set: {paths.mutated_runset}")
    if execution.result.state is MutationResultState.caught:
        console.print(
            "scope: the expected detector caught this exact fixture transformation; "
            "this is not a broader model, planner, or red-team robustness result"
        )
    exit_code = _MUTATION_EXIT_CODES[execution.result.state]
    if exit_code:
        raise typer.Exit(exit_code)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_mutation_suite(path: Path) -> CompiledSuite:
    if path.suffix.lower() in {".yaml", ".yml"}:
        return compile_suite(path)
    return load_compiled_suite(path)


def _bounded_error(exc: BaseException) -> str:
    summary = " ".join(redact_text(str(exc)).split())
    if not summary:
        return "bounded internal error"
    return summary[:_ERROR_SUMMARY_CHARS]
