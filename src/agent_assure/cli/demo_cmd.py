from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.demo.common import DemoError
from agent_assure.demo.flagship import render_flagship_text, run_flagship_demo
from agent_assure.demo.measurement_cases import (
    render_measurement_cases_text,
    run_measurement_cases_demo,
)
from agent_assure.demo.rag import render_rag_text, run_rag_demo

app = typer.Typer(help="One-command deterministic demos.")
console = Console()


@app.callback()
def callback() -> None:
    """Run bundled local demos."""


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
    except DemoError as exc:
        failure = {
            "demo": "flagship",
            "status": "failure",
            "error": str(exc),
            "out": str(out),
        }
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
    except DemoError as exc:
        failure = {
            "demo": "rag",
            "status": "failure",
            "error": str(exc),
            "out": str(out),
        }
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
    except DemoError as exc:
        failure = {
            "demo": "measurement-cases",
            "status": "failure",
            "error": str(exc),
            "out": str(out),
        }
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
