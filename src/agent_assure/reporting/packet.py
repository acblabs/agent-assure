from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, TypeVar

from agent_assure.artifact_io import file_sha256, write_text_atomic
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    BoundedFileContents,
    load_json_bytes_bounded,
)
from agent_assure.onboarding.path_safety import (
    confined_snapshot_relative_path,
    read_confined_file_snapshot,
)
from agent_assure.privacy.redaction import redact_packet_payload
from agent_assure.reporting.markdown_safety import (
    markdown_code_span,
    markdown_text,
)
from agent_assure.reporting.usage import prefixed_usage_summary_lines, usage_summary_lines
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    ExactRate,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import (
    EvidencePacket,
    PacketArtifactDigest,
    PacketArtifactRole,
    packet_summary_digest_binding_error,
)
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.usage import UsageSummary
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)
from agent_assure.usage.aggregation import format_usage_delta

DEFAULT_PACKET_LIMITATIONS = (
    "evidence packets summarize deterministic fixture-mode results; they are not "
    "signatures, attestations, safety certifications, compliance certifications, "
    "or live model-quality evidence",
)
DEFAULT_INTERPRETATION = (
    "Start with candidate_vs_expectations: pass means no blocking deterministic "
    "finding under the selected gate profile; fail means at least one expectation, "
    "policy, invariant, or configured gate failed.",
    "If a comparison summary is present, fixture_equivalence_state must be pass "
    "before interpreting candidate-to-baseline changes.",
    "Artifact digests and release-manifest digests are reproducibility anchors "
    "over local files; they are not signatures or external attestations.",
    "Not-evaluated capabilities are explicit scope boundaries, not evidence that "
    "the capability passed.",
    "If a usage summary is present, treat it as measured usage and declared "
    "estimated cost evidence for human review, not business impact evidence.",
    "If control efficacy is present, interpret it as catalog-relative challenge "
    "scope; it remains separate from candidate evidence closure.",
)
_MAX_RENDERED_IDENTIFIER_ITEMS = 20
SummaryT = TypeVar("SummaryT", EvaluationSummary, ComparisonSummary)


@dataclass(frozen=True)
class PacketSummaryFileSnapshot(Generic[SummaryT]):
    summary: SummaryT
    contents: BoundedFileContents
    relative_path: str


def load_evaluation_summary(path: Path) -> EvaluationSummary:
    return project_validated_artifact_payload(
        load_validated_artifact_payload(path, "evaluation-summary"),
        EvaluationSummary,
        kind="evaluation-summary",
    )


def load_comparison_summary(path: Path) -> ComparisonSummary:
    return project_validated_artifact_payload(
        load_validated_artifact_payload(path, "comparison-summary"),
        ComparisonSummary,
        kind="comparison-summary",
    )


def load_evaluation_summary_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
) -> PacketSummaryFileSnapshot[EvaluationSummary]:
    return _load_packet_summary_snapshot(
        path,
        root=root,
        artifact_root=artifact_root,
        kind="evaluation-summary",
        model=EvaluationSummary,
    )


def load_comparison_summary_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
) -> PacketSummaryFileSnapshot[ComparisonSummary]:
    return _load_packet_summary_snapshot(
        path,
        root=root,
        artifact_root=artifact_root,
        kind="comparison-summary",
        model=ComparisonSummary,
    )


def _load_packet_summary_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
    kind: PacketArtifactRole,
    model: type[SummaryT],
) -> PacketSummaryFileSnapshot[SummaryT]:
    label = kind.replace("-", " ")
    contents = read_confined_file_snapshot(
        path,
        root=root,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=label,
    )
    relative_path = confined_snapshot_relative_path(
        path,
        contents,
        root=root,
        path_root=artifact_root,
        label=label,
    )
    payload = load_json_bytes_bounded(
        contents.data,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=label,
    )
    validate_loaded_artifact_payload(payload, kind)
    summary = project_validated_artifact_payload(payload, model, kind=kind)
    return PacketSummaryFileSnapshot(
        summary=summary,
        contents=contents,
        relative_path=relative_path,
    )


def packet_artifact_digest_from_snapshot(
    role: PacketArtifactRole,
    snapshot: PacketSummaryFileSnapshot[EvaluationSummary]
    | PacketSummaryFileSnapshot[ComparisonSummary],
) -> PacketArtifactDigest:
    return PacketArtifactDigest(role=role, sha256=snapshot.contents.sha256)


def release_artifact_from_summary_snapshot(
    role: PacketArtifactRole,
    snapshot: PacketSummaryFileSnapshot[EvaluationSummary]
    | PacketSummaryFileSnapshot[ComparisonSummary],
) -> ReleaseArtifact:
    return ReleaseArtifact(
        role=role,
        path=snapshot.relative_path,
        sha256=snapshot.contents.sha256,
    )


def packet_summary_files_binding_error(
    packet: EvidencePacket,
    *,
    artifact_root: Path,
) -> str | None:
    """Verify summary models and exact bytes against trusted manifest paths."""
    binding_error = packet_summary_digest_binding_error(packet)
    if binding_error is not None:
        return binding_error
    if packet.release_manifest is None:
        return "trusted summary-file verification requires a release manifest"
    summaries: tuple[
        tuple[PacketArtifactRole, EvaluationSummary | ComparisonSummary],
        ...,
    ] = (("evaluation-summary", packet.evaluation),)
    if packet.comparison is not None:
        summaries = (
            *summaries,
            ("comparison-summary", packet.comparison),
        )
    manifest_by_role = {item.role: item for item in packet.release_manifest.artifacts}
    for role, nested_summary in summaries:
        manifest_artifact = manifest_by_role[role]
        source_path = artifact_root.absolute() / Path(manifest_artifact.path)
        try:
            snapshot = (
                load_evaluation_summary_snapshot(
                    source_path,
                    root=artifact_root,
                    artifact_root=artifact_root,
                )
                if role == "evaluation-summary"
                else load_comparison_summary_snapshot(
                    source_path,
                    root=artifact_root,
                    artifact_root=artifact_root,
                )
            )
        except (OSError, UnicodeError, ValueError):
            return f"evidence packet {role} source file could not be safely verified"
        if snapshot.relative_path != manifest_artifact.path:
            return f"evidence packet {role} manifest path is not normalized and confined"
        if snapshot.contents.sha256 != manifest_artifact.sha256:
            return f"evidence packet {role} source file digest does not match release manifest"
        if snapshot.summary != nested_summary:
            return f"evidence packet {role} source file does not match nested summary"
    return None


def build_evidence_packet(
    evaluation: EvaluationSummary,
    *,
    comparison: ComparisonSummary | None = None,
    control_efficacy: ControlEfficacyReport | None = None,
    control_efficacy_gate_profile: ControlEfficacyGateProfile | None = None,
    control_efficacy_gate: ControlEfficacyGateDecision | None = None,
    environment: EnvironmentInfo | None = None,
    release_manifest: ReleaseArtifactManifest | None = None,
    usage_summary: UsageSummary | None = None,
    artifact_digests: tuple[PacketArtifactDigest, ...] = (),
    packet_id: str | None = None,
    interpretation: tuple[str, ...] = DEFAULT_INTERPRETATION,
    limitations: tuple[str, ...] = DEFAULT_PACKET_LIMITATIONS,
) -> EvidencePacket:
    resolved_packet_id = packet_id or _packet_id(
        evaluation,
        comparison=comparison,
        control_efficacy=control_efficacy,
        control_efficacy_gate_profile=control_efficacy_gate_profile,
        control_efficacy_gate=control_efficacy_gate,
        interpretation=interpretation,
        limitations=limitations,
    )
    return EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id=resolved_packet_id,
        interpretation=interpretation,
        evaluation=evaluation,
        comparison=comparison,
        control_efficacy=control_efficacy,
        control_efficacy_gate_profile=control_efficacy_gate_profile,
        control_efficacy_gate=control_efficacy_gate,
        environment=environment,
        release_manifest=release_manifest,
        usage_summary=usage_summary or evaluation.usage_summary,
        artifact_digests=artifact_digests,
        limitations=limitations,
    )


def packet_artifact_digest(
    role: PacketArtifactRole,
    path: Path,
) -> PacketArtifactDigest:
    return PacketArtifactDigest(
        artifact_kind="packet-artifact-digest",
        role=role,
        sha256=file_sha256(path),
    )


def write_evidence_packet(packet: EvidencePacket, path: Path) -> None:
    payload = redact_packet_payload(
        packet.model_dump(
            mode="json",
        )
    )
    EvidencePacket.model_validate(payload)
    validate_loaded_artifact_payload(payload, "evidence-packet")
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(
        path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )


def load_evidence_packet(path: Path) -> EvidencePacket:
    return project_validated_artifact_payload(
        load_validated_artifact_payload(path, "evidence-packet"),
        EvidencePacket,
        kind="evidence-packet",
    )


def render_evidence_packet_markdown(packet: EvidencePacket) -> str:
    lines = [
        "# Evidence Packet",
        "",
        "## How to Interpret",
        "",
    ]
    lines.extend(f"- {markdown_text(item)}" for item in packet.interpretation)
    lines.extend(
        [
            "",
            "## Candidate Summary",
            "",
            f"- Run set: {markdown_code_span(packet.evaluation.runset_id)}",
            f"- State: {markdown_code_span(packet.evaluation.state.value)}",
            f"- Findings: `{len(packet.evaluation.findings)}`",
            f"- Usage summary: {markdown_code_span(_usage_presence(packet.usage_summary))}",
        ]
    )
    if packet.comparison is not None:
        lines.extend(
            [
                "",
                "## Comparison Summary",
                "",
                f"- Baseline run set: {markdown_code_span(packet.comparison.baseline_runset_id)}",
                f"- Candidate run set: {markdown_code_span(packet.comparison.candidate_runset_id)}",
                f"- Classification: {markdown_code_span(packet.comparison.classification.value)}",
                "- Fixture equivalence: "
                f"{markdown_code_span(packet.comparison.fixture_equivalence_state.value)}",
            ]
        )
    if packet.control_efficacy is not None:
        efficacy = packet.control_efficacy
        profile = packet.control_efficacy_gate_profile
        gate = packet.control_efficacy_gate
        if profile is None or gate is None:
            raise ValueError(
                "control-efficacy packet rendering requires a gate profile and decision"
            )
        independent_threat_count = markdown_code_span(
            str(efficacy.independently_challenged_threat_category_count)
        )
        lines.extend(
            [
                "",
                "## Assurance Control Challenge",
                "",
                "- Boundary: catalog-relative scope adequacy; this is separate "
                "from candidate evidence closure.",
                f"- Catalog: {markdown_code_span(efficacy.catalog_id)}",
                f"- Semantic state: {markdown_code_span(efficacy.semantic_state.value)}",
                f"- Gate profile: {markdown_code_span(profile.profile_id)}",
                f"- Gate mapping: {markdown_code_span(gate.state.value)}",
                "- Catalog detector kill ratio: "
                f"{markdown_code_span(_rate_text(efficacy.catalog_kill_rate))}",
                "- Required survivors: "
                f"{markdown_code_span(str(efficacy.required_survivor_count))} / "
                f"{markdown_code_span(str(len(efficacy.required_operator_ids)))} required",
                "- Critical survivors: "
                f"{markdown_code_span(str(efficacy.critical_survivor_count))}; "
                "operator IDs: "
                f"{_identifier_list(efficacy.critical_survivor_operator_ids)}",
                "- Threat categories challenged: "
                f"{markdown_code_span(str(efficacy.challenged_threat_category_count))} / "
                f"{markdown_code_span(str(efficacy.applicable_threat_category_count))} "
                "applicable",
                "- Independently challenged threat categories: "
                f"{independent_threat_count} / "
                f"{markdown_code_span(str(efficacy.applicable_threat_category_count))} "
                "applicable",
                "- Critical uncovered threats: "
                f"{markdown_code_span(str(efficacy.critical_uncovered_threat_count))} / "
                f"{markdown_code_span(str(efficacy.applicable_threat_category_count))} "
                "applicable",
                "- Unknown applicability: "
                f"{markdown_code_span(str(efficacy.unknown_applicability_count))} / "
                f"{markdown_code_span(str(len(efficacy.threat_coverage)))} declared",
                "- Unscoped catalog threats: "
                f"{markdown_code_span(str(efficacy.unscoped_catalog_threat_count))}; "
                "threat IDs: "
                f"{_identifier_list(efficacy.unscoped_catalog_threat_ids)}",
                "",
                "### Gate Findings",
                "",
            ]
        )
        if gate.findings:
            lines.extend(
                "- Reason: "
                f"{markdown_code_span(finding.reason_code.value)}; "
                f"effect: {markdown_code_span(finding.effect.value)}; "
                f"operator IDs: {_identifier_list(finding.operator_ids)}; "
                f"threat IDs: {_identifier_list(finding.threat_ids)}"
                for finding in gate.findings
            )
        else:
            lines.append("- None.")
        lines.extend(
            [
                "",
                "### Independence Strata",
                "",
            ]
        )
        lines.extend(
            "- "
            f"{markdown_code_span(stratum.stratum)}: "
            f"{markdown_code_span(_rate_text(stratum.kill_rate))}; "
            f"caught={stratum.state_counts.caught}, "
            f"survived={stratum.state_counts.survived}, "
            f"invalid_subject={stratum.state_counts.invalid_subject}, "
            f"total={stratum.state_counts.total}"
            for stratum in efficacy.kill_rate_by_independence_class
        )
    if packet.environment is not None:
        lines.extend(
            [
                "",
                "## Environment",
                "",
                f"- Platform: {markdown_code_span(packet.environment.platform)}",
                "- Python: "
                f"{markdown_code_span(packet.environment.python_version.splitlines()[0])}",
                f"- Git commit: {markdown_code_span(packet.environment.git_commit or '<unknown>')}",
                f"- Git dirty: {markdown_code_span(packet.environment.git_dirty)}",
                f"- Lockfile: {markdown_code_span(packet.environment.lockfile_path or '<none>')}",
                "- Lockfile digest: "
                f"{markdown_code_span(packet.environment.lockfile_digest or '<none>')}",
                "- Dependency inventory: "
                f"{markdown_code_span(packet.environment.dependency_inventory_path or '<none>')}",
                "- Dependency inventory digest: "
                f"{markdown_code_span(packet.environment.dependency_inventory_digest or '<none>')}",
                f"- Installed packages: `{len(packet.environment.installed_packages)}`",
            ]
        )
    if packet.release_manifest is not None:
        lines.extend(["", "## Release Artifact Manifest", ""])
        lines.extend(
            f"- {markdown_code_span(artifact.role)} "
            f"{markdown_code_span(artifact.path)} {markdown_code_span(artifact.sha256)}"
            for artifact in packet.release_manifest.artifacts
        )
    lines.extend(["", "## Measured Usage", ""])
    lines.extend(_packet_usage_lines(packet))
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {markdown_text(limitation)}" for limitation in packet.limitations)
    return "\n".join(lines) + "\n"


def write_evidence_packet_markdown(packet: EvidencePacket, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic(path, render_evidence_packet_markdown(packet))


def _packet_id(
    evaluation: EvaluationSummary,
    *,
    comparison: ComparisonSummary | None,
    control_efficacy: ControlEfficacyReport | None,
    control_efficacy_gate_profile: ControlEfficacyGateProfile | None,
    control_efficacy_gate: ControlEfficacyGateDecision | None,
    interpretation: tuple[str, ...],
    limitations: tuple[str, ...],
) -> str:
    payload = {
        "interpretation": interpretation,
        "evaluation": _summary_for_packet_id(evaluation),
        "comparison": _summary_for_packet_id(comparison) if comparison is not None else None,
        "control_efficacy": (
            _summary_for_packet_id(control_efficacy) if control_efficacy is not None else None
        ),
        "control_efficacy_gate_profile": (
            control_efficacy_gate_profile.model_dump(mode="json")
            if control_efficacy_gate_profile is not None
            else None
        ),
        "control_efficacy_gate": (
            control_efficacy_gate.model_dump(mode="json")
            if control_efficacy_gate is not None
            else None
        ),
        "limitations": limitations,
    }
    return f"packet-{sha256_hexdigest(redact_packet_payload(payload))[:16]}"


def _summary_for_packet_id(
    summary: EvaluationSummary | ComparisonSummary | ControlEfficacyReport,
) -> dict[str, object]:
    return summary.model_dump(mode="json", exclude={"environment"})


def _packet_usage_lines(packet: EvidencePacket) -> list[str]:
    comparison = packet.comparison
    if comparison is None or (
        comparison.baseline_usage_summary is None
        and comparison.candidate_usage_summary is None
        and comparison.usage_delta is None
    ):
        return usage_summary_lines(packet.usage_summary)
    lines: list[str] = []
    lines.extend(prefixed_usage_summary_lines("Baseline", comparison.baseline_usage_summary))
    lines.extend(prefixed_usage_summary_lines("Candidate", comparison.candidate_usage_summary))
    if comparison.usage_delta is None:
        lines.append("- Usage delta: `not_observed`")
    else:
        lines.append(f"- {markdown_text(format_usage_delta(comparison.usage_delta))}")
    return lines


def _usage_presence(summary: UsageSummary | None) -> str:
    if summary is None:
        return "not_observed"
    return "observed"


def _rate_text(rate: ExactRate) -> str:
    return f"{rate.numerator}/{rate.denominator} ({rate.state.value})"


def _identifier_list(values: tuple[str, ...]) -> str:
    if not values:
        return markdown_code_span("<none>")
    rendered = ", ".join(
        markdown_code_span(value) for value in values[:_MAX_RENDERED_IDENTIFIER_ITEMS]
    )
    omitted = len(values) - _MAX_RENDERED_IDENTIFIER_ITEMS
    if omitted <= 0:
        return rendered
    return f"{rendered}; {markdown_code_span(str(omitted))} omitted"
