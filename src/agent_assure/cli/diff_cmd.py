from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.reporting.evidence_diff import write_evidence_diff_html
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import RunSet

app = typer.Typer(help="Static evidence-diff rendering.")
console = Console()


@app.command("render")
def render(
    baseline_runset: Annotated[
        Path,
        typer.Option("--baseline-runset", exists=True, readable=True, help="Baseline RunSet JSON."),
    ],
    candidate_runset: Annotated[
        Path,
        typer.Option(
            "--candidate-runset",
            exists=True,
            readable=True,
            help="Candidate RunSet JSON.",
        ),
    ],
    baseline_summary: Annotated[
        Path,
        typer.Option(
            "--baseline-summary",
            exists=True,
            readable=True,
            help="Baseline evaluation summary JSON.",
        ),
    ],
    candidate_summary: Annotated[
        Path,
        typer.Option(
            "--candidate-summary",
            exists=True,
            readable=True,
            help="Candidate evaluation summary JSON.",
        ),
    ],
    comparison_summary: Annotated[
        Path,
        typer.Option(
            "--comparison-summary",
            exists=True,
            readable=True,
            help="Comparison summary JSON.",
        ),
    ],
    out: Annotated[Path, typer.Option("--out", help="Evidence-diff HTML output path.")],
    packet: Annotated[
        Path | None,
        typer.Option("--packet", exists=True, readable=True, help="Optional evidence packet JSON."),
    ] = None,
    title: Annotated[str, typer.Option("--title", help="HTML report title.")] = (
        "agent-assure evidence diff"
    ),
) -> None:
    try:
        packet_model = (
            EvidencePacket.model_validate_json(packet.read_text(encoding="utf-8"))
            if packet is not None
            else None
        )
        write_evidence_diff_html(
            baseline=RunSet.model_validate_json(baseline_runset.read_text(encoding="utf-8")),
            candidate=RunSet.model_validate_json(candidate_runset.read_text(encoding="utf-8")),
            baseline_summary=EvaluationSummary.model_validate_json(
                baseline_summary.read_text(encoding="utf-8")
            ),
            candidate_summary=EvaluationSummary.model_validate_json(
                candidate_summary.read_text(encoding="utf-8")
            ),
            comparison_summary=ComparisonSummary.model_validate_json(
                comparison_summary.read_text(encoding="utf-8")
            ),
            packet=packet_model,
            out=out,
            title=title,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"evidence diff: {out}")
