from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent_assure.reporting.environment import (
    artifact_project_root,
    build_release_manifest,
    environment_with_dependency_inventory,
    release_artifact,
    source_project_root,
    write_release_manifest,
)
from agent_assure.reporting.packet import (
    build_evidence_packet,
    load_comparison_summary,
    load_evaluation_summary,
    packet_artifact_digest,
    write_evidence_packet,
    write_evidence_packet_markdown,
)

app = typer.Typer(help="Evidence packet utilities.")
console = Console()


@app.callback()
def callback() -> None:
    """Build deterministic evidence packets from report summaries."""


@app.command("build")
def build(
    evaluation: Annotated[
        Path,
        typer.Argument(exists=True, readable=True, help="Evaluation summary JSON."),
    ],
    out: Annotated[Path, typer.Option("--out", help="Evidence packet JSON output path.")],
    comparison: Annotated[
        Path | None,
        typer.Option("--comparison", exists=True, readable=True, help="Comparison summary JSON."),
    ] = None,
    packet_id: Annotated[
        str | None,
        typer.Option("--packet-id", help="Optional stable packet identifier."),
    ] = None,
    markdown_out: Annotated[
        Path | None,
        typer.Option("--markdown-out", help="Evidence packet Markdown output path."),
    ] = None,
    manifest_out: Annotated[
        Path | None,
        typer.Option("--manifest-out", help="Release artifact manifest JSON output path."),
    ] = None,
    project_root: Annotated[
        Path,
        typer.Option("--project-root", exists=True, file_okay=False, dir_okay=True),
    ] = Path("."),
) -> None:
    try:
        source_candidates = (evaluation, *(() if comparison is None else (comparison,)))
        source_root = (
            project_root.resolve()
            if project_root != Path(".")
            else source_project_root(source_candidates, default_root=Path.cwd())
        )
        artifact_root = artifact_project_root(
            (evaluation, out, *(() if comparison is None else (comparison,))),
            default_root=source_root,
        )
        evaluation_summary = load_evaluation_summary(evaluation)
        comparison_summary = load_comparison_summary(comparison) if comparison else None
        environment = environment_with_dependency_inventory(
            source_root,
            out.parent,
            artifact_root=artifact_root,
        )
        digests = [packet_artifact_digest("evaluation-summary", evaluation)]
        artifacts = [
            release_artifact(
                "evaluation-summary",
                evaluation,
                project_root=artifact_root,
            ),
            release_artifact(
                "dependency-inventory",
                out.parent / "dependency-inventory.json",
                project_root=artifact_root,
            ),
        ]
        if comparison is not None:
            digests.append(packet_artifact_digest("comparison-summary", comparison))
            artifacts.append(
                release_artifact(
                    "comparison-summary",
                    comparison,
                    project_root=artifact_root,
                )
            )
        manifest = build_release_manifest(
            tuple(artifacts),
            environment=environment,
        )
        manifest_path = manifest_out or out.parent / "release-artifact-manifest.json"
        write_release_manifest(manifest, manifest_path)
        packet = build_evidence_packet(
            evaluation_summary,
            comparison=comparison_summary,
            environment=environment,
            release_manifest=manifest,
            artifact_digests=tuple(digests),
            packet_id=packet_id,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    write_evidence_packet(packet, out)
    write_evidence_packet_markdown(packet, markdown_out or out.with_suffix(".md"))
    console.print(f"evidence packet: {out}")
