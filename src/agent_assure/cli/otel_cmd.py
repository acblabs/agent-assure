from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.run import AgentRunRecord
from agent_assure.telemetry.otel_mapping import run_record_to_span_plan

app = typer.Typer(help="OpenTelemetry-aligned preview utilities.")
console = Console()


@app.command("preview")
def preview(
    path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Optional span-plan JSON output path."),
    ] = None,
) -> None:
    record = AgentRunRecord.model_validate_json(path.read_text(encoding="utf-8"))
    if record.execution_mode is ExecutionMode.live:
        raise typer.BadParameter(
            "live execution mode is schema-recognized but command-rejected in v0.1"
        )
    span_plan = run_record_to_span_plan(record)
    payload = json.dumps(span_plan.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if out is None:
        console.print(payload)
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(payload, encoding="utf-8", newline="\n")
    console.print(f"span plan: {out}")
