from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from agent_assure.demo.assure_the_assurance import (
    render_assure_the_assurance_text,
    run_assure_the_assurance_demo,
)
from agent_assure.demo.common import DemoError
from agent_assure.demo.evidence_sensitivity import (
    render_evidence_sensitivity_text,
    run_evidence_sensitivity_demo,
)
from agent_assure.demo.flagship import render_flagship_text, run_flagship_demo
from agent_assure.demo.measurement_cases import (
    render_measurement_cases_text,
    run_measurement_cases_demo,
)
from agent_assure.demo.rag import render_rag_text, run_rag_demo
from agent_assure.onboarding.diagnostics import bounded_error

app = typer.Typer(help="One-command deterministic demos.")
console = Console()


@app.callback()
def callback() -> None:
    """Run bundled local demos."""


@app.command("assure-the-assurance")
def assure_the_assurance(
    out: Annotated[
        Path,
        typer.Option("--out", help="Demo output directory."),
    ] = Path(".tmp/demo/assure-the-assurance"),
    clean: Annotated[
        bool,
        typer.Option("--clean/--no-clean", help="Clean the output directory before running."),
    ] = True,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Return the underlying blocking status instead of demo status.",
        ),
    ] = False,
) -> None:
    """Show that a weak assurance control can survive and block release."""
    if output_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be text or json")
    try:
        summary = run_assure_the_assurance_demo(out, clean=clean)
    except (DemoError, OSError, ValueError, ValidationError) as exc:
        failure = _failure_payload("assure-the-assurance", out, exc)
        if output_format == "json":
            typer.echo(json.dumps(failure, indent=2, sort_keys=True))
        else:
            console.print(f"agent-assure assurance demo failed: {exc}")
        raise typer.Exit(1) from exc

    if output_format == "json":
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    else:
        console.print(render_assure_the_assurance_text(summary))
    if strict:
        raise typer.Exit(_strict_exit_code(summary))


@app.command("flagship")
def flagship(
    out: Annotated[
        Path,
        typer.Option("--out", help="Demo output directory."),
    ] = Path(".tmp/demo/flagship"),
    clean: Annotated[
        bool,
        typer.Option("--clean/--no-clean", help="Clean the output directory before running."),
    ] = True,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Return the underlying blocking status instead of demo status.",
        ),
    ] = False,
) -> None:
    if output_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be text or json")
    try:
        summary = run_flagship_demo(out, clean=clean)
    except (DemoError, OSError, ValueError, ValidationError) as exc:
        failure = _failure_payload("flagship", out, exc)
        if output_format == "json":
            typer.echo(json.dumps(failure, indent=2, sort_keys=True))
        else:
            console.print(f"agent-assure flagship demo failed: {exc}")
        raise typer.Exit(1) from exc

    if output_format == "json":
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    else:
        console.print(render_flagship_text(summary))
    if strict:
        raise typer.Exit(_strict_exit_code(summary))


@app.command("evidence-sensitivity")
def evidence_sensitivity(
    out: Annotated[
        Path,
        typer.Option("--out", help="Demo output directory."),
    ] = Path(".tmp/demo/evidence-sensitivity"),
    clean: Annotated[
        bool,
        typer.Option("--clean/--no-clean", help="Clean the output directory before running."),
    ] = True,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Return the underlying blocking status instead of demo status.",
        ),
    ] = False,
) -> None:
    """Show that citations can pass while evidence-use sensitivity blocks."""
    if output_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be text or json")
    try:
        summary = run_evidence_sensitivity_demo(out, clean=clean)
    except (DemoError, OSError, ValueError, ValidationError) as exc:
        failure = _failure_payload("evidence-sensitivity", out, exc)
        if output_format == "json":
            typer.echo(json.dumps(failure, indent=2, sort_keys=True))
        else:
            console.print(f"agent-assure evidence-sensitivity demo failed: {exc}")
        raise typer.Exit(1) from exc

    if output_format == "json":
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    else:
        console.print(render_evidence_sensitivity_text(summary))
    if strict:
        raise typer.Exit(_strict_exit_code(summary))


@app.command("rag")
def rag(
    out: Annotated[
        Path,
        typer.Option("--out", help="Demo output directory."),
    ] = Path(".tmp/demo/rag"),
    clean: Annotated[
        bool,
        typer.Option("--clean/--no-clean", help="Clean the output directory before running."),
    ] = True,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Return the underlying blocking status instead of demo status.",
        ),
    ] = False,
) -> None:
    if output_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be text or json")
    try:
        summary = run_rag_demo(out, clean=clean)
    except (DemoError, OSError, ValueError, ValidationError) as exc:
        failure = _failure_payload("rag", out, exc)
        if output_format == "json":
            typer.echo(json.dumps(failure, indent=2, sort_keys=True))
        else:
            console.print(f"agent-assure RAG demo failed: {exc}")
        raise typer.Exit(1) from exc

    if output_format == "json":
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    else:
        console.print(render_rag_text(summary))
    if strict:
        raise typer.Exit(_strict_exit_code(summary))


@app.command("measurement-cases")
def measurement_cases(
    out: Annotated[
        Path,
        typer.Option("--out", help="Demo output directory."),
    ] = Path(".tmp/measurement-cases"),
    clean: Annotated[
        bool,
        typer.Option("--clean/--no-clean", help="Clean the output directory before running."),
    ] = True,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: text or json."),
    ] = "text",
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Return the underlying blocking status instead of demo status.",
        ),
    ] = False,
) -> None:
    if output_format not in {"text", "json"}:
        raise typer.BadParameter("--format must be text or json")
    try:
        summary = run_measurement_cases_demo(out, clean=clean)
    except (DemoError, OSError, ValueError, ValidationError) as exc:
        failure = _failure_payload("measurement-cases", out, exc)
        if output_format == "json":
            typer.echo(json.dumps(failure, indent=2, sort_keys=True))
        else:
            console.print(f"agent-assure measurement cases demo failed: {exc}")
        raise typer.Exit(1) from exc

    if output_format == "json":
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    else:
        console.print(render_measurement_cases_text(summary))
    if strict:
        raise typer.Exit(_strict_exit_code(summary))


def _strict_exit_code(summary: dict[str, object]) -> int:
    value = summary.get("underlying_exit_code", 1)
    if isinstance(value, int):
        return value
    return 1


def _failure_payload(
    demo: str,
    out: Path,
    exc: DemoError | OSError | ValueError | ValidationError,
) -> dict[str, object]:
    if isinstance(exc, OSError):
        error = "demo filesystem operation failed"
    elif isinstance(exc, ValidationError):
        error = "demo artifact validation failed"
    else:
        message = str(exc)
        output_spellings = {
            str(out),
            str(out.absolute()),
        }
        for spelling in sorted(output_spellings, key=len, reverse=True):
            if spelling:
                message = message.replace(spelling, "<output-directory>")
        error = bounded_error(
            ValueError(message),
            fallback="demo operation failed",
        )
    return {
        "demo": demo,
        "status": "failure",
        "error": error,
        "out": "<output-directory>",
    }
