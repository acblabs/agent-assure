from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from agent_assure import __version__
from agent_assure.artifact_transaction import OutputPublicationRollback
from agent_assure.authoring.yaml_nodes import MAX_YAML_BYTES
from agent_assure.controls.efficacy import (
    evaluate_control_efficacy_gate,
    load_threat_applicability_manifest,
)
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bytes_bounded,
    read_file_bounded,
)
from agent_assure.onboarding.controls_mutation import (
    ControlsMutationOnboardingConfig,
    load_controls_mutation_config_snapshot,
)
from agent_assure.onboarding.path_safety import (
    confined_config_input_file,
    read_confined_file_snapshot,
)
from agent_assure.reporting.environment import (
    artifact_project_root,
    build_release_manifest,
    environment_with_dependency_inventory,
    release_artifact,
    source_project_root,
    write_release_manifest,
)
from agent_assure.reporting.graph import write_evidence_graph
from agent_assure.reporting.packet import (
    DEFAULT_PACKET_LIMITATIONS,
    build_evidence_packet,
    build_privacy_filtered_evidence_graph,
    load_comparison_summary_snapshot,
    load_evaluation_summary_snapshot,
    load_evidence_graph_snapshot,
    load_evidence_packet,
    packet_artifact_digest_from_snapshot,
    packet_summary_files_binding_error,
    release_artifact_from_summary_snapshot,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.schema.efficacy import (
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
)
from agent_assure.schema.mutation import AssuranceMutationResult
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact
from agent_assure.schema.validation import (
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)

app = typer.Typer(help="Evidence packet utilities.")
_MAX_PACKET_ROLLBACK_BYTES = 4 * MAX_ARTIFACT_JSON_BYTES
_MAX_PACKET_MUTATION_RESULTS = 4_096
_MAX_PACKET_MUTATION_RESULT_BYTES = MAX_ARTIFACT_JSON_BYTES


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
    control_efficacy: Annotated[
        Path | None,
        typer.Option(
            "--control-efficacy",
            exists=True,
            readable=True,
            help="Control-efficacy report JSON.",
        ),
    ] = None,
    efficacy_config: Annotated[
        Path | None,
        typer.Option(
            "--efficacy-config",
            exists=True,
            readable=True,
            help="Controls-mutation configuration used for gate mapping.",
        ),
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
    graph_out: Annotated[
        Path | None,
        typer.Option("--graph-out", help="Assurance evidence graph JSON output path."),
    ] = None,
    project_root: Annotated[
        Path,
        typer.Option("--project-root", exists=True, file_okay=False, dir_okay=True),
    ] = Path("."),
) -> None:
    rollback: OutputPublicationRollback | None = None
    try:
        if (control_efficacy is None) is not (efficacy_config is None):
            raise ValueError("--control-efficacy and --efficacy-config must be provided together")
        optional_sources = (
            *(() if comparison is None else (comparison,)),
            *(() if control_efficacy is None else (control_efficacy, efficacy_config)),
        )
        source_candidates = (evaluation, *optional_sources)
        markdown_path = markdown_out or out.with_suffix(".md")
        manifest_path = manifest_out or out.parent / "release-artifact-manifest.json"
        graph_path = graph_out or out.parent / "assurance-evidence-graph.json"
        _ensure_packet_paths_do_not_alias(
            source_candidates,
            (
                out,
                markdown_path,
                manifest_path,
                graph_path,
                out.parent / "dependency-inventory.json",
            ),
        )
        source_root = (
            project_root.resolve()
            if project_root != Path(".")
            else source_project_root(source_candidates, default_root=Path.cwd())
        )
        artifact_root = artifact_project_root(
            (evaluation, out, *optional_sources),
            default_root=source_root,
        )
        owned_outputs = (
            out,
            markdown_path,
            manifest_path,
            graph_path,
            out.parent / "dependency-inventory.json",
        )
        _require_packet_outputs_within_artifact_root(
            owned_outputs,
            artifact_root=artifact_root,
        )
        evaluation_snapshot = load_evaluation_summary_snapshot(
            evaluation,
            root=source_root,
            artifact_root=artifact_root,
        )
        comparison_snapshot = (
            load_comparison_summary_snapshot(
                comparison,
                root=source_root,
                artifact_root=artifact_root,
            )
            if comparison is not None
            else None
        )
        evaluation_summary = evaluation_snapshot.summary
        comparison_summary = (
            comparison_snapshot.summary if comparison_snapshot is not None else None
        )
        efficacy_report = None
        efficacy_report_snapshot = None
        efficacy_config_snapshot = None
        efficacy_decision = None
        efficacy_profile: ControlEfficacyGateProfile | None = None
        if control_efficacy is not None and efficacy_config is not None:
            efficacy_report_snapshot = read_confined_file_snapshot(
                control_efficacy,
                root=source_root,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="control-efficacy report",
            )
            efficacy_report = ControlEfficacyReport.model_validate(
                load_json_bytes_bounded(
                    efficacy_report_snapshot.data,
                    label="control-efficacy report",
                )
            )
            authored, efficacy_config_snapshot = load_controls_mutation_config_snapshot(
                efficacy_config
            )
            threat_manifest_digest = _configured_threat_manifest_digest(
                authored,
                config_path=efficacy_config,
                output_paths=(
                    out,
                    markdown_path,
                    manifest_path,
                    graph_path,
                    out.parent / "dependency-inventory.json",
                ),
            )
            _validate_efficacy_config_binding(
                authored,
                efficacy_report,
                threat_manifest_digest=threat_manifest_digest,
            )
            efficacy_profile = authored.control_efficacy
            efficacy_decision = evaluate_control_efficacy_gate(
                efficacy_report,
                efficacy_profile,
            )
        packet_limitations = DEFAULT_PACKET_LIMITATIONS
        evidence_graph = build_privacy_filtered_evidence_graph(
            evaluation_summary,
            comparison=comparison_summary,
            control_efficacy=efficacy_report,
            control_efficacy_gate_profile=efficacy_profile,
            control_efficacy_gate=efficacy_decision,
            limitations=packet_limitations,
        )
        rollback = OutputPublicationRollback.capture(
            owned_outputs,
            max_bytes=_MAX_PACKET_ROLLBACK_BYTES,
            label="packet output",
            path_resolution_error="packet artifact path cannot be safely resolved",
            concurrent_change_error=(
                "packet output changed concurrently; refusing to overwrite it during rollback"
            ),
        )
        write_evidence_graph(evidence_graph, graph_path)
        rollback.mark_written(graph_path)
        graph_snapshot = load_evidence_graph_snapshot(
            graph_path,
            root=artifact_root,
            artifact_root=artifact_root,
        )
        environment = environment_with_dependency_inventory(
            source_root,
            out.parent,
            artifact_root=artifact_root,
        )
        rollback.mark_written(out.parent / "dependency-inventory.json")
        digests = [
            packet_artifact_digest_from_snapshot(
                "evaluation-summary",
                evaluation_snapshot,
            ),
            packet_artifact_digest_from_snapshot(
                "assurance-evidence-graph",
                graph_snapshot,
            ),
        ]
        artifacts = [
            release_artifact_from_summary_snapshot(
                "evaluation-summary",
                evaluation_snapshot,
            ),
            release_artifact_from_summary_snapshot(
                "assurance-evidence-graph",
                graph_snapshot,
            ),
            release_artifact(
                "dependency-inventory",
                out.parent / "dependency-inventory.json",
                project_root=artifact_root,
            ),
        ]
        if comparison_snapshot is not None:
            digests.append(
                packet_artifact_digest_from_snapshot(
                    "comparison-summary",
                    comparison_snapshot,
                )
            )
            artifacts.append(
                release_artifact_from_summary_snapshot(
                    "comparison-summary",
                    comparison_snapshot,
                )
            )
        if control_efficacy is not None:
            if efficacy_report_snapshot is None:
                raise ValueError("control-efficacy report snapshot is unavailable")
            digests.append(
                PacketArtifactDigest(
                    artifact_kind="packet-artifact-digest",
                    role="control-efficacy-report",
                    sha256=efficacy_report_snapshot.sha256,
                )
            )
            artifacts.append(
                _release_artifact_from_snapshot(
                    "control-efficacy-report",
                    control_efficacy,
                    project_root=artifact_root,
                    sha256=efficacy_report_snapshot.sha256,
                )
            )
            if efficacy_config is None or efficacy_config_snapshot is None:
                raise ValueError("control-efficacy config snapshot is unavailable")
            digests.append(
                PacketArtifactDigest(
                    artifact_kind="packet-artifact-digest",
                    role="control-efficacy-onboarding-config",
                    sha256=efficacy_config_snapshot.sha256,
                )
            )
            artifacts.append(
                _release_artifact_from_snapshot(
                    "control-efficacy-onboarding-config",
                    efficacy_config,
                    project_root=artifact_root,
                    sha256=efficacy_config_snapshot.sha256,
                )
            )
        manifest = build_release_manifest(
            tuple(artifacts),
            environment=environment,
        )
        packet = build_evidence_packet(
            evaluation_summary,
            comparison=comparison_summary,
            control_efficacy=efficacy_report,
            control_efficacy_gate_profile=efficacy_profile,
            control_efficacy_gate=efficacy_decision,
            environment=environment,
            release_manifest=manifest,
            evidence_graph_digest=evidence_graph.graph_digest,
            artifact_digests=tuple(digests),
            packet_id=packet_id,
            limitations=packet_limitations,
        )
        summary_file_error = packet_summary_files_binding_error(
            packet,
            artifact_root=artifact_root,
        )
        if summary_file_error is not None:
            raise ValueError(summary_file_error)
        write_release_manifest(manifest, manifest_path)
        rollback.mark_written(manifest_path)
        write_evidence_packet(packet, out)
        rollback.mark_written(out)
        write_evidence_packet_markdown(packet, markdown_path)
        rollback.mark_written(markdown_path)
    except BaseException as exc:
        if rollback is not None:
            try:
                rollback.restore()
            except BaseException as rollback_exc:
                raise typer.BadParameter(
                    "packet publication failed and prior outputs could not be restored"
                ) from rollback_exc
        if isinstance(exc, (OSError, ValueError)):
            raise typer.BadParameter(str(exc)) from exc
        raise
    typer.echo(f"assurance evidence graph: {graph_path}")
    typer.echo(f"evidence packet: {out}")


@app.command("graph")
def graph(
    packet: Annotated[
        Path,
        typer.Option(
            "--packet",
            exists=True,
            readable=True,
            help="Evidence packet JSON to project.",
        ),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", help="Assurance evidence graph JSON output path."),
    ],
    mutation_results: Annotated[
        list[Path] | None,
        typer.Option(
            "--mutation-result",
            "--mutation-report",
            exists=True,
            readable=True,
            help="Optional repeatable AssuranceMutationResult JSON input.",
        ),
    ] = None,
) -> None:
    """Project a packet and optional mutation results into a canonical graph."""
    mutation_paths = tuple(mutation_results or ())
    try:
        _ensure_packet_paths_do_not_alias((packet, *mutation_paths), (out,))
        loaded_packet = load_evidence_packet(packet)
        if mutation_paths:
            _require_graph_output_not_packet_bound(
                packet,
                out,
                loaded_packet=loaded_packet,
            )
        loaded_results = _load_mutation_results(mutation_paths)
        base_graph = build_privacy_filtered_evidence_graph(
            loaded_packet.evaluation,
            comparison=loaded_packet.comparison,
            control_efficacy=loaded_packet.control_efficacy,
            control_efficacy_gate_profile=loaded_packet.control_efficacy_gate_profile,
            control_efficacy_gate=loaded_packet.control_efficacy_gate,
            limitations=loaded_packet.limitations,
        )
        if (
            loaded_packet.evidence_graph_digest is not None
            and loaded_packet.evidence_graph_digest != base_graph.graph_digest
        ):
            raise ValueError(
                "projected graph digest does not match the packet evidence_graph_digest"
            )
        evidence_graph = (
            build_privacy_filtered_evidence_graph(
                loaded_packet.evaluation,
                comparison=loaded_packet.comparison,
                mutation_results=loaded_results,
                control_efficacy=loaded_packet.control_efficacy,
                control_efficacy_gate_profile=loaded_packet.control_efficacy_gate_profile,
                control_efficacy_gate=loaded_packet.control_efficacy_gate,
                limitations=loaded_packet.limitations,
            )
            if loaded_results
            else base_graph
        )
        write_evidence_graph(evidence_graph, out)
    except (OSError, UnicodeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"assurance evidence graph: {out}")
    if loaded_results and loaded_packet.evidence_graph_digest is not None:
        typer.echo(f"packet-bound base graph digest: {base_graph.graph_digest}")
    typer.echo(f"graph digest: {evidence_graph.graph_digest}")


def _load_mutation_results(
    paths: tuple[Path, ...],
) -> tuple[AssuranceMutationResult, ...]:
    if len(paths) > _MAX_PACKET_MUTATION_RESULTS:
        raise ValueError(
            "mutation result input count exceeds the supported aggregate limit"
        )
    results: list[AssuranceMutationResult] = []
    total_bytes = 0
    for path in paths:
        contents = read_file_bounded(
            path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="assurance mutation result",
        )
        total_bytes += contents.size
        if total_bytes > _MAX_PACKET_MUTATION_RESULT_BYTES:
            raise ValueError(
                "mutation result inputs exceed the supported aggregate byte limit"
            )
        payload = load_json_bytes_bounded(
            contents.data,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="assurance mutation result",
        )
        validate_loaded_artifact_payload(payload, "assurance-mutation-result")
        results.append(
            project_validated_artifact_payload(
                payload,
                AssuranceMutationResult,
                kind="assurance-mutation-result",
            )
        )
    return tuple(results)


def _require_graph_output_not_packet_bound(
    packet_path: Path,
    output_path: Path,
    *,
    loaded_packet: EvidencePacket,
) -> None:
    protected_sha256 = {item.sha256 for item in loaded_packet.artifact_digests}
    manifest = loaded_packet.release_manifest
    if manifest is not None:
        protected_sha256.update(item.sha256 for item in manifest.artifacts)
        output_identity = _path_identity(output_path, strict=False)
        packet_parent = packet_path.resolve().parent
        for artifact in manifest.artifacts:
            relative_path = Path(artifact.path)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                continue
            for candidate_root in (packet_parent, *packet_parent.parents):
                candidate = candidate_root / relative_path
                if output_identity == _path_identity(candidate, strict=False) or _same_file(
                    output_path,
                    candidate,
                ):
                    raise ValueError(
                        "mutation-enriched graph output aliases a packet-bound artifact"
                    )
    if output_path.exists():
        output = read_file_bounded(
            output_path,
            max_bytes=_MAX_PACKET_ROLLBACK_BYTES,
            label="existing graph output",
        )
        if output.sha256 in protected_sha256:
            raise ValueError(
                "mutation-enriched graph output aliases a packet-bound artifact"
            )


def _configured_threat_manifest_digest(
    authored: ControlsMutationOnboardingConfig,
    *,
    config_path: Path,
    output_paths: tuple[Path, ...],
) -> str:
    config_root = config_path.parent.absolute()
    manifest_path = confined_config_input_file(
        config_root,
        authored.threat_applicability_manifest,
        label="configured threat applicability manifest",
    )
    _ensure_packet_paths_do_not_alias((manifest_path,), output_paths)
    manifest_snapshot = read_confined_file_snapshot(
        manifest_path,
        root=config_root,
        max_bytes=MAX_YAML_BYTES,
        label="configured threat applicability manifest",
    )
    manifest = load_threat_applicability_manifest(
        manifest_path,
        reader=lambda _path: manifest_snapshot.data,
    )
    return manifest.manifest_digest


def _validate_efficacy_config_binding(
    authored: ControlsMutationOnboardingConfig,
    report: ControlEfficacyReport,
    *,
    threat_manifest_digest: str,
) -> None:
    if authored.package_version != __version__:
        raise ValueError(
            "efficacy configuration package version does not match the installed package"
        )
    if report.catalog_id != authored.catalog_id:
        raise ValueError("efficacy configuration catalog does not match the report")
    if report.required_operator_ids != authored.control_efficacy.required_operators:
        raise ValueError("efficacy configuration required operators do not match the report scope")
    if report.selected_operator_ids != authored.operator_ids:
        raise ValueError("efficacy configuration operator selection does not match the report")
    if report.threat_manifest_digest != threat_manifest_digest:
        raise ValueError("efficacy configuration threat manifest does not match the report scope")


def _ensure_packet_paths_do_not_alias(
    source_paths: tuple[Path, ...],
    output_paths: tuple[Path, ...],
) -> None:
    output_identities: list[str] = []
    for output in output_paths:
        if output.is_symlink():
            raise ValueError("packet output paths must not be symbolic links")
        if output.exists() and not output.is_file():
            raise ValueError("packet output paths must identify files")
        identity = _path_identity(output, strict=False)
        if identity in output_identities or any(
            _same_file(output, previous) for previous in output_paths[: len(output_identities)]
        ):
            raise ValueError("packet output paths must be distinct")
        if any(
            _path_is_strict_ancestor(output, previous)
            or _path_is_strict_ancestor(previous, output)
            for previous in output_paths[: len(output_identities)]
        ):
            raise ValueError("packet output paths must not contain one another")
        output_identities.append(identity)

    for source in source_paths:
        source_identity = _path_identity(source, strict=True)
        if any(
            source_identity == output_identity or _same_file(source, output)
            for output_identity, output in zip(
                output_identities,
                output_paths,
                strict=True,
            )
        ):
            raise ValueError("packet input aliases an owned output path")


def _require_packet_outputs_within_artifact_root(
    paths: tuple[Path, ...],
    *,
    artifact_root: Path,
) -> None:
    resolved_root = artifact_root.resolve()
    for path in paths:
        try:
            path.resolve(strict=False).relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError(
                "packet output paths must stay within the artifact root"
            ) from exc


def _path_identity(path: Path, *, strict: bool) -> str:
    try:
        resolved = path.resolve(strict=strict)
    except RuntimeError as exc:
        raise ValueError("packet artifact path cannot be safely resolved") from exc
    return os.path.normcase(os.path.abspath(resolved))


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return False


def _path_is_strict_ancestor(left: Path, right: Path) -> bool:
    left_identity = _path_identity(left, strict=False)
    right_identity = _path_identity(right, strict=False)
    if left_identity == right_identity:
        return False
    try:
        return os.path.commonpath((left_identity, right_identity)) == left_identity
    except ValueError:
        return False


def _release_artifact_from_snapshot(
    role: str,
    path: Path,
    *,
    project_root: Path,
    sha256: str,
) -> ReleaseArtifact:
    resolved_root = project_root.resolve()
    resolved_path = path.resolve()
    try:
        relative_path = resolved_path.relative_to(resolved_root).as_posix()
    except ValueError as exc:
        raise ValueError(
            "release artifact paths must stay under project_root: "
            f"{resolved_path} is outside {resolved_root}"
        ) from exc
    return ReleaseArtifact(
        artifact_kind="release-artifact",
        role=role,
        path=relative_path,
        sha256=sha256,
    )
