from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.authoring.compiler import compile_suite
from agent_assure.authoring.yaml_lint import lint_yaml
from agent_assure.schema.common import ExecutionMode

app = typer.Typer(help="Suite authoring and compilation.")
console = Console()


@app.command("lint")
def lint(path: Annotated[Path, typer.Argument(exists=True, readable=True)]) -> None:
    warnings = lint_yaml(path)
    for warning in warnings:
        console.print(f"{warning.path}:{warning.line}:{warning.column}: warning: {warning.message}")
    try:
        compile_suite(path)
    except Exception as exc:
        raise typer.BadParameter(f"suite lint failed: {exc}") from exc
    console.print(f"lint ok: {path} ({len(warnings)} warning(s))")


@app.command("compile")
def compile_cmd(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out", help="Compiled JSON output path.")],
) -> None:
    compiled = compile_suite(path)
    if compiled.defaults.execution_mode is ExecutionMode.live:
        raise typer.BadParameter(
            "live execution mode is schema-recognized but command-rejected in v0.1"
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(compiled.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    console.print(f"compiled suite: {out}")
