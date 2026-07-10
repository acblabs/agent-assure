from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from agent_assure.artifact_io import file_sha256
from agent_assure.controls.coverage import build_control_coverage_report
from agent_assure.reporting.controls import write_control_coverage_report
from agent_assure.reporting.packet import load_evidence_packet
from agent_assure.schema.controls import ControlFramework

app = typer.Typer(help="Framework evidence mapping utilities.")
console = Console()


@app.callback()
def callback() -> None:
    """Map observed evidence to framework concepts for human review."""


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
