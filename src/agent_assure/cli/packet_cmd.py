from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
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
    BoundedFileContents,
    load_json_bytes_bounded,
    read_file_bounded,
)
from agent_assure.onboarding.controls_mutation import (
    ControlsMutationOnboardingConfig,
    parse_controls_mutation_config,
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
from agent_assure.reporting.graph import evidence_graph_json_text, write_evidence_graph
from agent_assure.reporting.packet import (
    DEFAULT_PACKET_LIMITATIONS,
    PacketSourceFileSnapshot,
    PacketSummaryFileSnapshot,
    build_evidence_packet,
    build_privacy_filtered_evidence_graph,
    load_comparison_summary_snapshot,
    load_evaluation_summary_snapshot,
    load_evidence_graph_snapshot,
    load_evidence_packet,
    load_evidence_sensitivity_report_snapshot,
    load_identity_bound_packet_source_file_snapshot,
    load_packet_source_file_snapshot,
    load_statistical_sufficiency_report_snapshot,
    load_stochastic_evidence_sensitivity_report_snapshot,
    packet_artifact_digest_from_snapshot,
    packet_artifact_max_bytes,
    packet_summary_files_binding_error_for_trusted_publication,
    release_artifact_from_source_snapshot,
    release_artifact_from_summary_snapshot,
    render_evidence_packet_markdown,
    stochastic_source_runsets_binding_error,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.efficacy import (
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
)
from agent_assure.schema.mutation import AssuranceMutationResult
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest, PacketArtifactRole
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import (
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
)
from agent_assure.schema.validation import (
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)

app = typer.Typer(help="Evidence packet utilities.")
_MAX_PACKET_ROLLBACK_BYTES = 4 * MAX_ARTIFACT_JSON_BYTES
_MAX_PACKET_MUTATION_RESULTS = 4_096
_MAX_PACKET_MUTATION_RESULTS_TOTAL_BYTES = MAX_ARTIFACT_JSON_BYTES
_BACKSLASH = "\\"
_STOCHASTIC_PACKET_LIMITATIONS = (
    "evidence packets summarize protocol-bound evaluation artifacts, including repeated "
    "live evidence when supplied; they are not signatures, attestations, safety "
    "certifications, compliance certifications, or independent model-quality attestations",
)


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
    evidence_sensitivity: Annotated[
        Path | None,
        typer.Option(
            "--evidence-sensitivity",
            exists=True,
            readable=True,
            help="Deterministic evidence-sensitivity report JSON.",
        ),
    ] = None,
    statistical_sufficiency: Annotated[
        Path | None,
        typer.Option(
            "--statistical-sufficiency",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Statistical-sufficiency report JSON for a repeated sensitivity study.",
        ),
    ] = None,
    stochastic_evidence_sensitivity: Annotated[
        Path | None,
        typer.Option(
            "--stochastic-evidence-sensitivity",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Stochastic evidence-sensitivity report JSON.",
        ),
    ] = None,
    stochastic_baseline_source_runset: Annotated[
        Path | None,
        typer.Option(
            "--stochastic-baseline-source-runset",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Exact privacy-safe baseline source RunSet used by statistical sufficiency.",
        ),
    ] = None,
    stochastic_counterfactual_source_runset: Annotated[
        Path | None,
        typer.Option(
            "--stochastic-counterfactual-source-runset",
            "--stochastic-candidate-source-runset",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help=(
                "Exact privacy-safe counterfactual/candidate source RunSet used by "
                "statistical sufficiency."
            ),
        ),
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
        stochastic_inputs = tuple(
            path
            for path in (
                statistical_sufficiency,
                stochastic_evidence_sensitivity,
                stochastic_baseline_source_runset,
                stochastic_counterfactual_source_runset,
            )
            if path is not None
        )
        if stochastic_inputs and len(stochastic_inputs) != 4:
            raise ValueError(
                "--statistical-sufficiency, --stochastic-evidence-sensitivity, "
                "--stochastic-baseline-source-runset, and "
                "--stochastic-counterfactual-source-runset must be provided together"
            )
        optional_sources = (
            *(() if comparison is None else (comparison,)),
            *(() if evidence_sensitivity is None else (evidence_sensitivity,)),
            *stochastic_inputs,
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
        sensitivity_snapshot = (
            load_evidence_sensitivity_report_snapshot(
                evidence_sensitivity,
                root=source_root,
                artifact_root=artifact_root,
            )
            if evidence_sensitivity is not None
            else None
        )
        evaluation_summary = evaluation_snapshot.summary
        comparison_summary = (
            comparison_snapshot.summary if comparison_snapshot is not None else None
        )
        sensitivity_report = (
            sensitivity_snapshot.summary if sensitivity_snapshot is not None else None
        )
        sufficiency_snapshot: PacketSummaryFileSnapshot[StatisticalSufficiencyReport] | None = None
        stochastic_snapshot: (
            PacketSummaryFileSnapshot[StochasticEvidenceSensitivityReport] | None
        ) = None
        stochastic_baseline_snapshot: PacketSourceFileSnapshot | None = None
        stochastic_counterfactual_snapshot: PacketSourceFileSnapshot | None = None
        sufficiency_report: StatisticalSufficiencyReport | None = None
        stochastic_report: StochasticEvidenceSensitivityReport | None = None
        stochastic_source_runsets: tuple[RunSet, RunSet] | None = None
        if stochastic_inputs:
            (
                sufficiency_path,
                stochastic_path,
                stochastic_baseline_path,
                stochastic_counterfactual_path,
            ) = stochastic_inputs
            sufficiency_snapshot = load_statistical_sufficiency_report_snapshot(
                sufficiency_path,
                root=source_root,
                artifact_root=artifact_root,
            )
            stochastic_snapshot = load_stochastic_evidence_sensitivity_report_snapshot(
                stochastic_path,
                root=source_root,
                artifact_root=artifact_root,
            )
            stochastic_baseline_snapshot = load_identity_bound_packet_source_file_snapshot(
                stochastic_baseline_path,
                root=source_root,
                artifact_root=artifact_root,
                max_bytes=packet_artifact_max_bytes("stochastic-baseline-source-runset"),
                label="stochastic baseline source RunSet",
            )
            stochastic_counterfactual_snapshot = load_identity_bound_packet_source_file_snapshot(
                stochastic_counterfactual_path,
                root=source_root,
                artifact_root=artifact_root,
                max_bytes=packet_artifact_max_bytes("stochastic-counterfactual-source-runset"),
                label="stochastic counterfactual source RunSet",
            )
            sufficiency_report = sufficiency_snapshot.summary
            stochastic_report = stochastic_snapshot.summary
            stochastic_source_runsets = (
                _project_stochastic_source_runset(
                    stochastic_baseline_snapshot,
                    role="stochastic-baseline-source-runset",
                ),
                _project_stochastic_source_runset(
                    stochastic_counterfactual_snapshot,
                    role="stochastic-counterfactual-source-runset",
                ),
            )
            preflight_digests = [
                packet_artifact_digest_from_snapshot(
                    "evaluation-summary",
                    evaluation_snapshot,
                )
            ]
            if comparison_snapshot is not None:
                preflight_digests.append(
                    packet_artifact_digest_from_snapshot(
                        "comparison-summary",
                        comparison_snapshot,
                    )
                )
            preflight_digests.extend(
                (
                    packet_artifact_digest_from_snapshot(
                        "statistical-sufficiency-report",
                        sufficiency_snapshot,
                    ),
                    packet_artifact_digest_from_snapshot(
                        "stochastic-evidence-sensitivity-report",
                        stochastic_snapshot,
                    ),
                    packet_artifact_digest_from_snapshot(
                        "stochastic-baseline-source-runset",
                        stochastic_baseline_snapshot,
                    ),
                    packet_artifact_digest_from_snapshot(
                        "stochastic-counterfactual-source-runset",
                        stochastic_counterfactual_snapshot,
                    ),
                )
            )
            preflight_packet = build_evidence_packet(
                evaluation_summary,
                comparison=comparison_summary,
                statistical_sufficiency=sufficiency_report,
                stochastic_evidence_sensitivity=stochastic_report,
                artifact_digests=tuple(preflight_digests),
                limitations=_STOCHASTIC_PACKET_LIMITATIONS,
            )
            source_binding_error = stochastic_source_runsets_binding_error(
                preflight_packet,
                source_runsets=stochastic_source_runsets,
            )
            if source_binding_error is not None:
                raise ValueError(source_binding_error)
        efficacy_report = None
        efficacy_report_snapshot = None
        efficacy_config_snapshot = None
        efficacy_decision = None
        efficacy_profile: ControlEfficacyGateProfile | None = None
        if control_efficacy is not None and efficacy_config is not None:
            efficacy_report_snapshot = load_packet_source_file_snapshot(
                control_efficacy,
                root=source_root,
                artifact_root=artifact_root,
                max_bytes=MAX_ARTIFACT_JSON_BYTES,
                label="control-efficacy report",
            )
            efficacy_report = ControlEfficacyReport.model_validate(
                load_json_bytes_bounded(
                    efficacy_report_snapshot.contents.data,
                    label="control-efficacy report",
                )
            )
            efficacy_config_snapshot = load_packet_source_file_snapshot(
                efficacy_config,
                root=source_root,
                artifact_root=artifact_root,
                max_bytes=MAX_YAML_BYTES,
                label="controls-mutation config",
            )
            authored = parse_controls_mutation_config(efficacy_config_snapshot.contents.data)
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
        packet_limitations = (
            _STOCHASTIC_PACKET_LIMITATIONS
            if stochastic_report is not None
            else DEFAULT_PACKET_LIMITATIONS
        )
        evidence_graph = build_privacy_filtered_evidence_graph(
            evaluation_summary,
            comparison=comparison_summary,
            evidence_sensitivity=sensitivity_report,
            statistical_sufficiency=sufficiency_report,
            stochastic_evidence_sensitivity=stochastic_report,
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
            on_inventory_written=rollback.mark_written,
        )
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
        captured_source_snapshots: dict[str, BoundedFileContents] = {}
        if comparison_snapshot is not None:
            digests.append(
                packet_artifact_digest_from_snapshot(
                    "comparison-summary",
                    comparison_snapshot,
                )
            )
            comparison_artifact = release_artifact_from_summary_snapshot(
                "comparison-summary",
                comparison_snapshot,
            )
            artifacts.append(comparison_artifact)
        if sensitivity_snapshot is not None:
            digests.append(
                packet_artifact_digest_from_snapshot(
                    "evidence-sensitivity-report",
                    sensitivity_snapshot,
                )
            )
            sensitivity_artifact = release_artifact_from_summary_snapshot(
                "evidence-sensitivity-report",
                sensitivity_snapshot,
            )
            artifacts.append(sensitivity_artifact)
        if (
            sufficiency_snapshot is not None
            and stochastic_snapshot is not None
            and stochastic_baseline_snapshot is not None
            and stochastic_counterfactual_snapshot is not None
        ):
            digests.extend(
                (
                    packet_artifact_digest_from_snapshot(
                        "statistical-sufficiency-report",
                        sufficiency_snapshot,
                    ),
                    packet_artifact_digest_from_snapshot(
                        "stochastic-evidence-sensitivity-report",
                        stochastic_snapshot,
                    ),
                    packet_artifact_digest_from_snapshot(
                        "stochastic-baseline-source-runset",
                        stochastic_baseline_snapshot,
                    ),
                    packet_artifact_digest_from_snapshot(
                        "stochastic-counterfactual-source-runset",
                        stochastic_counterfactual_snapshot,
                    ),
                )
            )
            artifacts.extend(
                (
                    release_artifact_from_summary_snapshot(
                        "statistical-sufficiency-report",
                        sufficiency_snapshot,
                    ),
                    release_artifact_from_summary_snapshot(
                        "stochastic-evidence-sensitivity-report",
                        stochastic_snapshot,
                    ),
                    release_artifact_from_source_snapshot(
                        "stochastic-baseline-source-runset",
                        stochastic_baseline_snapshot,
                    ),
                    release_artifact_from_source_snapshot(
                        "stochastic-counterfactual-source-runset",
                        stochastic_counterfactual_snapshot,
                    ),
                )
            )
            captured_source_snapshots.update(
                {
                    stochastic_baseline_snapshot.relative_path: (
                        stochastic_baseline_snapshot.contents
                    ),
                    stochastic_counterfactual_snapshot.relative_path: (
                        stochastic_counterfactual_snapshot.contents
                    ),
                }
            )
        if control_efficacy is not None:
            if efficacy_report_snapshot is None:
                raise ValueError("control-efficacy report snapshot is unavailable")
            digests.append(
                PacketArtifactDigest(
                    artifact_kind="packet-artifact-digest",
                    role="control-efficacy-report",
                    sha256=efficacy_report_snapshot.contents.sha256,
                )
            )
            efficacy_report_artifact = release_artifact_from_source_snapshot(
                "control-efficacy-report",
                efficacy_report_snapshot,
            )
            artifacts.append(efficacy_report_artifact)
            captured_source_snapshots[efficacy_report_artifact.path] = (
                efficacy_report_snapshot.contents
            )
            if efficacy_config is None or efficacy_config_snapshot is None:
                raise ValueError("control-efficacy config snapshot is unavailable")
            digests.append(
                PacketArtifactDigest(
                    artifact_kind="packet-artifact-digest",
                    role="control-efficacy-onboarding-config",
                    sha256=efficacy_config_snapshot.contents.sha256,
                )
            )
            efficacy_config_artifact = release_artifact_from_source_snapshot(
                "control-efficacy-onboarding-config",
                efficacy_config_snapshot,
            )
            artifacts.append(efficacy_config_artifact)
            captured_source_snapshots[efficacy_config_artifact.path] = (
                efficacy_config_snapshot.contents
            )
        manifest = build_release_manifest(
            tuple(artifacts),
            environment=environment,
        )
        packet = build_evidence_packet(
            evaluation_summary,
            comparison=comparison_summary,
            evidence_sensitivity=sensitivity_report,
            statistical_sufficiency=sufficiency_report,
            stochastic_evidence_sensitivity=stochastic_report,
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
        summary_file_error = packet_summary_files_binding_error_for_trusted_publication(
            packet,
            artifact_root=artifact_root,
            expected_graph=evidence_graph,
            captured_snapshots_by_path=captured_source_snapshots,
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
        loaded_results = _load_mutation_results(mutation_paths)
        base_graph = build_privacy_filtered_evidence_graph(
            loaded_packet.evaluation,
            comparison=loaded_packet.comparison,
            evidence_sensitivity=loaded_packet.evidence_sensitivity,
            statistical_sufficiency=loaded_packet.statistical_sufficiency,
            stochastic_evidence_sensitivity=loaded_packet.stochastic_evidence_sensitivity,
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
                evidence_sensitivity=loaded_packet.evidence_sensitivity,
                statistical_sufficiency=loaded_packet.statistical_sufficiency,
                stochastic_evidence_sensitivity=loaded_packet.stochastic_evidence_sensitivity,
                mutation_results=loaded_results,
                control_efficacy=loaded_packet.control_efficacy,
                control_efficacy_gate_profile=loaded_packet.control_efficacy_gate_profile,
                control_efficacy_gate=loaded_packet.control_efficacy_gate,
                limitations=loaded_packet.limitations,
            )
            if loaded_results
            else base_graph
        )
        projected_graph_file_sha256 = hashlib.sha256(
            evidence_graph_json_text(evidence_graph).encode("utf-8")
        ).hexdigest()
        _require_graph_output_not_packet_bound(
            packet,
            out,
            loaded_packet=loaded_packet,
            projected_graph_digest=evidence_graph.graph_digest,
            projected_graph_file_sha256=projected_graph_file_sha256,
            mutation_enriched=bool(loaded_results),
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
        raise ValueError("mutation result input count exceeds the supported aggregate limit")
    results: list[AssuranceMutationResult] = []
    total_bytes = 0
    for path in paths:
        contents = read_file_bounded(
            path,
            max_bytes=MAX_ARTIFACT_JSON_BYTES,
            label="assurance mutation result",
        )
        total_bytes += contents.size
        if total_bytes > _MAX_PACKET_MUTATION_RESULTS_TOTAL_BYTES:
            raise ValueError("mutation result inputs exceed the supported aggregate byte limit")
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


def _project_stochastic_source_runset(
    snapshot: PacketSourceFileSnapshot,
    *,
    role: PacketArtifactRole,
) -> RunSet:
    payload = load_json_bytes_bounded(
        snapshot.contents.data,
        max_bytes=packet_artifact_max_bytes(role),
        label=role.replace("-", " "),
    )
    validate_loaded_artifact_payload(payload, "run-set")
    return project_validated_artifact_payload(payload, RunSet, kind="run-set")


def _require_graph_output_not_packet_bound(
    packet_path: Path,
    output_path: Path,
    *,
    loaded_packet: EvidencePacket,
    projected_graph_digest: str,
    projected_graph_file_sha256: str,
    mutation_enriched: bool,
) -> None:
    alias_error = (
        "mutation-enriched graph output aliases a packet-bound artifact"
        if mutation_enriched
        else "graph output aliases a packet-bound artifact"
    )
    markdown_output_error = (
        "mutation-enriched graph output must not target packet Markdown"
        if mutation_enriched
        else "graph output must not target packet Markdown"
    )
    output_identity = _path_identity(output_path, strict=False)
    resolved_output_path = Path(output_identity)
    if _path_uses_packet_markdown_suffix(output_path) or _path_uses_packet_markdown_suffix(
        resolved_output_path
    ):
        raise ValueError(markdown_output_error)
    packet_markdown_paths = (
        packet_path.with_suffix(".md"),
        packet_path.resolve(strict=True).with_suffix(".md"),
    )
    if any(
        output_identity == _path_identity(markdown_path, strict=False)
        or _same_file(output_path, markdown_path)
        for markdown_path in packet_markdown_paths
    ):
        raise ValueError(markdown_output_error)
    protected_roles_by_sha256: dict[str, set[str]] = {}
    for item in loaded_packet.artifact_digests:
        protected_roles_by_sha256.setdefault(item.sha256, set()).add(item.role)
    manifest = loaded_packet.release_manifest
    manifest_artifact_paths = (
        tuple(
            (artifact, _normalized_manifest_artifact_path(artifact.path))
            for artifact in manifest.artifacts
        )
        if manifest is not None
        else ()
    )
    if manifest_artifact_paths:
        for artifact, _relative_path in manifest_artifact_paths:
            protected_roles_by_sha256.setdefault(artifact.sha256, set()).add(artifact.role)
    packet_graph_file_sha256s = tuple(
        item.sha256
        for item in loaded_packet.artifact_digests
        if item.role == "assurance-evidence-graph"
    )
    bound_graph_file_sha256 = (
        packet_graph_file_sha256s[0] if len(packet_graph_file_sha256s) == 1 else None
    )
    manifest_graph_file_sha256s: tuple[str, ...] = ()
    if manifest_artifact_paths:
        manifest_graph_file_sha256s = tuple(
            artifact.sha256
            for artifact, _relative_path in manifest_artifact_paths
            if artifact.role == "assurance-evidence-graph"
        )
    existing_output = (
        read_file_bounded(
            output_path,
            max_bytes=_MAX_PACKET_ROLLBACK_BYTES,
            label="existing graph output",
        )
        if output_path.exists()
        else None
    )
    if existing_output is not None and existing_output.data == render_evidence_packet_markdown(
        loaded_packet
    ).encode("utf-8"):
        raise ValueError(markdown_output_error)
    projected_graph_matches_binding = (
        not mutation_enriched
        and loaded_packet.evidence_graph_digest is not None
        and projected_graph_digest == loaded_packet.evidence_graph_digest
        and bound_graph_file_sha256 == projected_graph_file_sha256
        and (manifest is None or manifest_graph_file_sha256s == (bound_graph_file_sha256,))
    )
    bound_graph_reemission = projected_graph_matches_binding and (
        existing_output is None or existing_output.sha256 == bound_graph_file_sha256
    )
    matching_manifest_artifacts = tuple(
        (artifact, relative_path)
        for artifact, relative_path in manifest_artifact_paths
        if _path_identity_ends_with(output_identity, relative_path)
    )
    if matching_manifest_artifacts:
        most_specific_length = max(
            len(relative_path.parts) for _artifact, relative_path in matching_manifest_artifacts
        )
        most_specific_matches = tuple(
            (artifact, relative_path)
            for artifact, relative_path in matching_manifest_artifacts
            if len(relative_path.parts) == most_specific_length
        )
        if len(most_specific_matches) != 1:
            raise ValueError("graph output ambiguously matches packet-bound artifacts")
        matched_artifact, _matched_relative_path = most_specific_matches[0]
        if matched_artifact.role == "assurance-evidence-graph" and not bound_graph_reemission:
            if mutation_enriched:
                raise ValueError(alias_error)
            elif projected_graph_matches_binding:
                raise ValueError("existing graph bytes do not match packet binding")
            else:
                raise ValueError("projected graph bytes do not match packet binding")
        elif matched_artifact.role != "assurance-evidence-graph":
            raise ValueError(alias_error)
    if existing_output is not None:
        protected_roles = protected_roles_by_sha256.get(existing_output.sha256, set())
        if protected_roles and not (
            bound_graph_reemission and protected_roles == {"assurance-evidence-graph"}
        ):
            raise ValueError(alias_error)
        if manifest is not None:
            try:
                output_payload = load_json_bytes_bounded(
                    existing_output.data,
                    max_bytes=_MAX_PACKET_ROLLBACK_BYTES,
                    label="existing graph output",
                )
            except (UnicodeError, ValueError):
                pass
            else:
                if output_payload == manifest.model_dump(mode="json"):
                    raise ValueError(alias_error)


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
            _path_is_strict_ancestor(output, previous) or _path_is_strict_ancestor(previous, output)
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
            raise ValueError("packet output paths must stay within the artifact root") from exc


def _path_identity(path: Path, *, strict: bool) -> str:
    try:
        resolved = path.resolve(strict=strict)
    except RuntimeError as exc:
        raise ValueError("packet artifact path cannot be safely resolved") from exc
    return os.path.normcase(os.path.abspath(resolved))


def _path_uses_packet_markdown_suffix(path: Path) -> bool:
    name = path.name.rstrip(" .") if os.name == "nt" else path.name
    return name.casefold().endswith(".md")


def _normalized_manifest_artifact_path(value: str) -> Path:
    posix_path = PurePosixPath(value)
    if _BACKSLASH in value or posix_path.as_posix() != value:
        raise ValueError("manifest path is not canonical portable POSIX-relative")
    try:
        parts = portable_relative_path_parts(value)
    except ValueError as exc:
        raise ValueError("manifest path is not canonical portable POSIX-relative") from exc
    return Path(*parts)


def _path_identity_ends_with(path_identity: str, relative_path: Path) -> bool:
    path_parts = Path(path_identity).parts
    relative_parts = relative_path.parts
    if not relative_parts or len(path_parts) < len(relative_parts):
        return False

    def component_identity(component: str) -> str:
        normalized = component.rstrip(" .") if os.name == "nt" else component
        return os.path.normcase(normalized)

    return tuple(component_identity(part) for part in path_parts[-len(relative_parts) :]) == tuple(
        component_identity(part) for part in relative_parts
    )


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
