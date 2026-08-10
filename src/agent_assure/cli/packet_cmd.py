from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

from agent_assure import __version__
from agent_assure.authoring.yaml_nodes import MAX_YAML_BYTES
from agent_assure.controls.efficacy import (
    evaluate_control_efficacy_gate,
    load_threat_applicability_manifest,
)
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bytes_bounded,
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
from agent_assure.reporting.packet import (
    build_evidence_packet,
    load_comparison_summary,
    load_evaluation_summary,
    packet_artifact_digest,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.schema.efficacy import (
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
)
from agent_assure.schema.packet import PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact

app = typer.Typer(help="Evidence packet utilities.")


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
    project_root: Annotated[
        Path,
        typer.Option("--project-root", exists=True, file_okay=False, dir_okay=True),
    ] = Path("."),
) -> None:
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
        _ensure_packet_paths_do_not_alias(
            source_candidates,
            (
                out,
                markdown_path,
                manifest_path,
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
        evaluation_summary = load_evaluation_summary(evaluation)
        comparison_summary = load_comparison_summary(comparison) if comparison else None
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
            artifact_digests=tuple(digests),
            packet_id=packet_id,
        )
        write_release_manifest(manifest, manifest_path)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    write_evidence_packet(packet, out)
    write_evidence_packet_markdown(packet, markdown_path)
    typer.echo(f"evidence packet: {out}")


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
