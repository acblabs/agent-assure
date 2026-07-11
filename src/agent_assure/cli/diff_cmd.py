from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES, read_text_bounded
from agent_assure.reporting.evidence_diff_html import THESIS_TITLE, write_evidence_diff_html
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import RunSet

app = typer.Typer(help="Static evidence-diff rendering.")
console = Console()


@app.command("render")
def render(
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            "--baseline-runset",
            exists=True,
            readable=True,
            help="Baseline RunSet JSON.",
        ),
    ] = None,
    candidate: Annotated[
        Path | None,
        typer.Option(
            "--candidate",
            "--candidate-runset",
            exists=True,
            readable=True,
            help="Candidate RunSet JSON.",
        ),
    ] = None,
    comparison: Annotated[
        Path | None,
        typer.Option(
            "--comparison",
            "--comparison-summary",
            exists=True,
            readable=True,
            help="Comparison summary JSON.",
        ),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Evidence-diff HTML output path."),
    ] = None,
    packet: Annotated[
        Path | None,
        typer.Option("--packet", exists=True, readable=True, help="Optional evidence packet JSON."),
    ] = None,
    baseline_summary: Annotated[
        Path | None,
        typer.Option(
            "--baseline-summary",
            exists=True,
            readable=True,
            help="Optional baseline evaluation summary JSON.",
        ),
    ] = None,
    candidate_summary: Annotated[
        Path | None,
        typer.Option(
            "--candidate-summary",
            exists=True,
            readable=True,
            help="Optional candidate evaluation summary JSON.",
        ),
    ] = None,
    title: Annotated[
        str,
        typer.Option("--title", help="HTML document title or subtitle."),
    ] = THESIS_TITLE,
) -> None:
    try:
        baseline_path = _required_path(baseline, "--baseline")
        candidate_path = _required_path(candidate, "--candidate")
        comparison_path = _required_path(comparison, "--comparison")
        out_path = _required_path(out, "--out")
        packet_model = _load_packet(packet) if packet is not None else None
        baseline_summary_model = (
            _load_evaluation_summary(baseline_summary)
            if baseline_summary is not None
            else None
        )
        candidate_summary_model = (
            _load_evaluation_summary(candidate_summary)
            if candidate_summary is not None
            else None
        )
        write_evidence_diff_html(
            baseline=_load_runset(baseline_path),
            candidate=_load_runset(candidate_path),
            comparison_summary=_load_comparison_summary(comparison_path),
            baseline_summary=baseline_summary_model,
            candidate_summary=candidate_summary_model,
            packet=packet_model,
            out=out_path,
            title=title,
            artifact_paths=_artifact_paths(
                baseline=baseline_path,
                candidate=candidate_path,
                comparison=comparison_path,
                packet=packet,
                baseline_summary=baseline_summary,
                candidate_summary=candidate_summary,
                root=out_path.parent,
            ),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"evidence diff: {out_path}")


def _required_path(path: Path | None, option_name: str) -> Path:
    if path is None:
        raise typer.BadParameter(f"{option_name} is required")
    return path


def _load_runset(path: Path) -> RunSet:
    return RunSet.model_validate_json(_artifact_json_text(path))


def _load_evaluation_summary(path: Path) -> EvaluationSummary:
    return EvaluationSummary.model_validate_json(_artifact_json_text(path))


def _load_comparison_summary(path: Path) -> ComparisonSummary:
    return ComparisonSummary.model_validate_json(_artifact_json_text(path))


def _load_packet(path: Path) -> EvidencePacket:
    return EvidencePacket.model_validate_json(_artifact_json_text(path))


def _artifact_json_text(path: Path) -> str:
    return read_text_bounded(path, max_bytes=MAX_ARTIFACT_JSON_BYTES, label="artifact JSON")


def _artifact_paths(
    *,
    baseline: Path,
    candidate: Path,
    comparison: Path,
    packet: Path | None,
    baseline_summary: Path | None,
    candidate_summary: Path | None,
    root: Path,
) -> dict[str, str]:
    paths = {
        "baseline run set": _safe_display_path(baseline, root=root),
        "candidate run set": _safe_display_path(candidate, root=root),
        "comparison summary": _safe_display_path(comparison, root=root),
    }
    if packet is not None:
        paths["evidence packet"] = _safe_display_path(packet, root=root)
    if baseline_summary is not None:
        paths["baseline evaluation summary"] = _safe_display_path(baseline_summary, root=root)
    if candidate_summary is not None:
        paths["candidate evaluation summary"] = _safe_display_path(candidate_summary, root=root)
    return paths


def _safe_display_path(path: Path, *, root: Path) -> str:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    try:
        return resolved_path.relative_to(resolved_root).as_posix()
    except ValueError:
        if path.is_absolute():
            return f"<absolute-path:{path.name or 'artifact'}>"
        return path.as_posix()
