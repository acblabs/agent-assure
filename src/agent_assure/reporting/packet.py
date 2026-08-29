from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

from pydantic import BaseModel

from agent_assure.artifact_io import file_sha256, write_text_atomic
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.graph import build_evidence_graph
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    BoundedFileContents,
    load_json_bytes_bounded,
)
from agent_assure.onboarding.path_safety import (
    confined_snapshot_relative_path,
    read_confined_file_snapshot,
)
from agent_assure.privacy.redaction import (
    assert_runset_payload_safe_for_persistence,
    redact_packet_payload,
    redact_runset_payload,
)
from agent_assure.reporting.markdown_safety import (
    markdown_code_span,
    markdown_text,
)
from agent_assure.reporting.usage import prefixed_usage_summary_lines, usage_summary_lines
from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.common import DigestHex
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    ExactRate,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationReplayContext, EvaluationSummary
from agent_assure.schema.graph import (
    AssuranceEvidenceGraph,
    EvidenceGraphSubjectPayload,
)
from agent_assure.schema.mutation import AssuranceMutationResult
from agent_assure.schema.packet import (
    EvidencePacket,
    PacketArtifactDigest,
    PacketArtifactRole,
    packet_summary_digest_binding_error,
)
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.sensitivity import RAGSensitivityReport
from agent_assure.schema.stochastic_sensitivity import (
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
)
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.usage import UsageSummary
from agent_assure.schema.validation import (
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)
from agent_assure.sensitivity_contract import SENSITIVITY_HARNESS_NOTICE
from agent_assure.usage.aggregation import format_usage_delta

if TYPE_CHECKING:
    from agent_assure.evaluation.evaluator import EvaluationReport
    from agent_assure.policies.base import GateProfile, Waiver

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
_MAX_RELEASE_MANIFEST_ARTIFACTS = 256
_MAX_RELEASE_MANIFEST_TOTAL_BYTES = 256 * 1024 * 1024
_TRUSTED_CAPTURED_SOURCE_ROLES = frozenset(
    {
        "control-efficacy-report",
        "control-efficacy-onboarding-config",
        "stochastic-baseline-source-runset",
        "stochastic-counterfactual-source-runset",
    }
)
_REVALIDATED_CAPTURED_SOURCE_ROLES = frozenset(
    {
        "stochastic-baseline-source-runset",
        "stochastic-counterfactual-source-runset",
    }
)
SummaryT = TypeVar(
    "SummaryT",
    EvaluationSummary,
    ComparisonSummary,
    AssuranceEvidenceGraph,
    RAGSensitivityReport,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
)
GraphSourceT = TypeVar("GraphSourceT", bound=BaseModel)


@dataclass(frozen=True)
class PacketSummaryFileSnapshot(Generic[SummaryT]):
    summary: SummaryT
    contents: BoundedFileContents
    relative_path: str


@dataclass(frozen=True)
class PacketSourceFileSnapshot:
    """One bounded descriptor snapshot with its confined manifest path."""

    contents: BoundedFileContents
    relative_path: str


def stochastic_source_runsets_binding_error(
    packet: EvidencePacket,
    *,
    source_runsets: tuple[RunSet, RunSet],
) -> str | None:
    """Recompute stochastic dependencies from two exact, privacy-safe RunSets.

    The tuple order is baseline then counterfactual. Whole-RunSet and every
    member-record digest are recomputed by the paired dependency builder and
    must exactly equal the dependency objects embedded in statistical
    sufficiency. The sufficiency model has already checked that its observation
    manifest names exactly those dependency records.
    """

    if not isinstance(source_runsets, tuple) or len(source_runsets) != 2:
        return "stochastic evidence requires exact baseline and counterfactual RunSets"
    try:
        packet = EvidencePacket.model_validate(packet.model_dump(mode="json", warnings="error"))
        if packet.stochastic_evidence_sensitivity is None:
            return "stochastic source RunSets require nested stochastic evidence"
        sufficiency = packet.statistical_sufficiency
        if sufficiency is None:
            return "stochastic evidence requires nested statistical sufficiency"
        baseline = _unchanged_privacy_safe_runset(source_runsets[0])
        counterfactual = _unchanged_privacy_safe_runset(source_runsets[1])
        from agent_assure.rag.repeated_sensitivity import (
            assemble_paired_observations,
            build_paired_runset_dependencies,
        )

        expected_dependencies = build_paired_runset_dependencies(
            sufficiency.protocol,
            baseline,
            counterfactual,
        )
        expected_observations = assemble_paired_observations(
            sufficiency.protocol,
            baseline,
            counterfactual,
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return "stochastic source RunSets could not be safely revalidated"
    if expected_dependencies != sufficiency.source_runsets:
        return (
            "stochastic source RunSet and record digests do not exactly match "
            "statistical sufficiency dependencies"
        )
    if expected_observations != sufficiency.observations:
        return "stochastic observations do not exactly reassemble from the source RunSets"
    return None


def _unchanged_privacy_safe_runset(runset: RunSet) -> RunSet:
    runset = RunSet.model_validate(runset.model_dump(mode="json", warnings="error"))
    payload = runset.model_dump(mode="json", warnings="error")
    filtered = redact_runset_payload(payload)
    assert_runset_payload_safe_for_persistence(filtered)
    if filtered != payload:
        raise ValueError(
            "stochastic source RunSets must already be privacy-filtered because "
            "redaction would invalidate their cryptographic dependencies"
        )
    return runset


def build_privacy_filtered_evidence_graph(
    evaluation: EvaluationSummary,
    *,
    comparison: ComparisonSummary | None = None,
    evidence_sensitivity: RAGSensitivityReport | None = None,
    statistical_sufficiency: StatisticalSufficiencyReport | None = None,
    stochastic_evidence_sensitivity: StochasticEvidenceSensitivityReport | None = None,
    mutation_results: tuple[AssuranceMutationResult, ...] = (),
    control_efficacy: ControlEfficacyReport | None = None,
    control_efficacy_gate_profile: ControlEfficacyGateProfile | None = None,
    control_efficacy_gate: ControlEfficacyGateDecision | None = None,
    limitations: tuple[str, ...],
) -> AssuranceEvidenceGraph:
    """Project packet-shaped evidence after applying the mandatory privacy profile."""
    graph_evaluation = _privacy_filtered_graph_source(evaluation, EvaluationSummary)
    graph_comparison = _privacy_filtered_optional_graph_source(
        comparison,
        ComparisonSummary,
    )
    graph_sensitivity = _privacy_filtered_optional_graph_source(
        evidence_sensitivity,
        RAGSensitivityReport,
    )
    graph_statistical_sufficiency = _privacy_filtered_optional_graph_source(
        statistical_sufficiency,
        StatisticalSufficiencyReport,
    )
    graph_stochastic_sensitivity = _privacy_filtered_optional_graph_source(
        stochastic_evidence_sensitivity,
        StochasticEvidenceSensitivityReport,
    )
    graph_mutation_results = tuple(
        _privacy_filtered_graph_source(result, AssuranceMutationResult)
        for result in mutation_results
    )
    graph_efficacy = _privacy_filtered_optional_graph_source(
        control_efficacy,
        ControlEfficacyReport,
    )
    graph_profile = _privacy_filtered_optional_graph_source(
        control_efficacy_gate_profile,
        ControlEfficacyGateProfile,
    )
    graph_decision = _privacy_filtered_optional_graph_source(
        control_efficacy_gate,
        ControlEfficacyGateDecision,
    )
    return build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=graph_evaluation.runset_id,
            subject_digest=graph_evaluation.runset_digest,
        ),
        evaluation=graph_evaluation,
        comparison=graph_comparison,
        evidence_sensitivity=graph_sensitivity,
        statistical_sufficiency=graph_statistical_sufficiency,
        stochastic_evidence_sensitivity=graph_stochastic_sensitivity,
        mutation_results=graph_mutation_results,
        control_efficacy=graph_efficacy,
        gate_profile=graph_profile,
        gate_decision=graph_decision,
        limitations=_privacy_filtered_graph_limitations(limitations),
    )


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


def load_evidence_sensitivity_report(path: Path) -> RAGSensitivityReport:
    return project_validated_artifact_payload(
        load_validated_artifact_payload(path, "evidence-sensitivity-report"),
        RAGSensitivityReport,
        kind="evidence-sensitivity-report",
    )


def load_statistical_sufficiency_report(path: Path) -> StatisticalSufficiencyReport:
    return project_validated_artifact_payload(
        load_validated_artifact_payload(path, "statistical-sufficiency-report"),
        StatisticalSufficiencyReport,
        kind="statistical-sufficiency-report",
    )


def load_stochastic_evidence_sensitivity_report(
    path: Path,
) -> StochasticEvidenceSensitivityReport:
    return project_validated_artifact_payload(
        load_validated_artifact_payload(
            path,
            "stochastic-evidence-sensitivity-report",
        ),
        StochasticEvidenceSensitivityReport,
        kind="stochastic-evidence-sensitivity-report",
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


def load_evidence_sensitivity_report_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
) -> PacketSummaryFileSnapshot[RAGSensitivityReport]:
    return _load_packet_summary_snapshot(
        path,
        root=root,
        artifact_root=artifact_root,
        kind="evidence-sensitivity-report",
        model=RAGSensitivityReport,
    )


def load_statistical_sufficiency_report_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
) -> PacketSummaryFileSnapshot[StatisticalSufficiencyReport]:
    return _load_packet_summary_snapshot(
        path,
        root=root,
        artifact_root=artifact_root,
        kind="statistical-sufficiency-report",
        model=StatisticalSufficiencyReport,
    )


def load_stochastic_evidence_sensitivity_report_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
) -> PacketSummaryFileSnapshot[StochasticEvidenceSensitivityReport]:
    return _load_packet_summary_snapshot(
        path,
        root=root,
        artifact_root=artifact_root,
        kind="stochastic-evidence-sensitivity-report",
        model=StochasticEvidenceSensitivityReport,
    )


def load_evidence_graph_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
) -> PacketSummaryFileSnapshot[AssuranceEvidenceGraph]:
    return _load_packet_summary_snapshot(
        path,
        root=root,
        artifact_root=artifact_root,
        kind="assurance-evidence-graph",
        model=AssuranceEvidenceGraph,
    )


def load_packet_source_file_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
    max_bytes: int,
    label: str,
) -> PacketSourceFileSnapshot:
    """Capture source bytes under the established producer-snapshot contract.

    The manifest path is derived lexically before opening the source and never
    from a later live-path resolution. The bounded read independently enforces
    the normal rooted, no-link policy. Existing control-efficacy publication
    intentionally consumes the captured descriptor bytes under this contract.
    """
    relative_path = _lexical_artifact_relative_path(
        path,
        artifact_root=artifact_root,
        label=label,
    )
    contents = read_confined_file_snapshot(
        path,
        root=root,
        max_bytes=max_bytes,
        label=label,
    )
    return PacketSourceFileSnapshot(
        contents=contents,
        relative_path=relative_path,
    )


def load_identity_bound_packet_source_file_snapshot(
    path: Path,
    *,
    root: Path,
    artifact_root: Path,
    max_bytes: int,
    label: str,
) -> PacketSourceFileSnapshot:
    """Capture bytes only while the source retains its descriptor path identity."""
    contents = read_confined_file_snapshot(
        path,
        root=root,
        max_bytes=max_bytes,
        label=label,
    )
    relative_path = confined_snapshot_relative_path(
        path,
        contents,
        root=root,
        path_root=artifact_root,
        label=label,
    )
    return PacketSourceFileSnapshot(
        contents=contents,
        relative_path=relative_path,
    )


def _lexical_artifact_relative_path(
    path: Path,
    *,
    artifact_root: Path,
    label: str,
) -> str:
    """Return a portable relative path without resolving live filesystem links."""
    absolute_path = Path(os.path.abspath(path))
    absolute_artifact_root = Path(os.path.abspath(artifact_root))
    try:
        relative_path = absolute_path.relative_to(absolute_artifact_root)
        canonical_path = "/".join(portable_relative_path_parts(relative_path))
    except ValueError as exc:
        raise ValueError(f"{label} escapes its artifact root") from exc
    if canonical_path != relative_path.as_posix():
        raise ValueError(f"{label} path is not normalized and confined")
    return canonical_path


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
    | PacketSummaryFileSnapshot[ComparisonSummary]
    | PacketSummaryFileSnapshot[AssuranceEvidenceGraph]
    | PacketSummaryFileSnapshot[RAGSensitivityReport]
    | PacketSummaryFileSnapshot[StatisticalSufficiencyReport]
    | PacketSummaryFileSnapshot[StochasticEvidenceSensitivityReport]
    | PacketSourceFileSnapshot,
) -> PacketArtifactDigest:
    return PacketArtifactDigest(role=role, sha256=snapshot.contents.sha256)


def release_artifact_from_summary_snapshot(
    role: PacketArtifactRole,
    snapshot: PacketSummaryFileSnapshot[EvaluationSummary]
    | PacketSummaryFileSnapshot[ComparisonSummary]
    | PacketSummaryFileSnapshot[AssuranceEvidenceGraph]
    | PacketSummaryFileSnapshot[RAGSensitivityReport]
    | PacketSummaryFileSnapshot[StatisticalSufficiencyReport]
    | PacketSummaryFileSnapshot[StochasticEvidenceSensitivityReport],
) -> ReleaseArtifact:
    return ReleaseArtifact(
        role=role,
        path=snapshot.relative_path,
        sha256=snapshot.contents.sha256,
    )


def release_artifact_from_source_snapshot(
    role: str,
    snapshot: PacketSourceFileSnapshot,
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
    """Independently verify bound artifact models and bytes from packet evidence."""
    return _packet_summary_files_binding_error_from_paths(
        packet,
        artifact_root=artifact_root,
        trusted_expected_graph=None,
    )


def packet_summary_snapshots_binding_error(
    packet: EvidencePacket,
    *,
    snapshots_by_path: Mapping[str, BoundedFileContents],
) -> str | None:
    """Verify packet bindings from exact, already-captured artifact snapshots.

    Keys must be the canonical portable POSIX-relative paths recorded by the
    release manifest. The supplied mapping must contain exactly one snapshot
    for every manifest artifact and no unmanifested snapshots.
    """
    validated_packet, validation_error = _prepare_packet_binding_verification(packet)
    if validation_error is not None:
        return validation_error
    assert validated_packet is not None
    return _packet_summary_snapshots_binding_error(
        validated_packet,
        snapshots_by_path=snapshots_by_path,
        trusted_expected_graph=None,
    )


def packet_summary_files_binding_error_for_trusted_publication(
    packet: EvidencePacket,
    *,
    artifact_root: Path,
    expected_graph: AssuranceEvidenceGraph,
    captured_snapshots_by_path: Mapping[str, BoundedFileContents] | None = None,
) -> str | None:
    """Verify an in-process publication using its already-built graph projection.

    This producer-only performance path is intended solely for an in-process publication
    transaction.
    ``expected_graph`` must be the exact projection built from the same nested evidence
    passed to ``build_evidence_packet`` in that transaction. External or persisted
    packets must use ``packet_summary_files_binding_error`` so the projection is
    reconstructed independently. The captured snapshot mapping is a bounded
    producer-only subset for source artifacts whose typed parsing and digest were
    already derived from one descriptor snapshot. Stochastic source RunSets are
    independently reopened at this final publication boundary and must retain
    both their captured identity and exact bytes. Other manifest paths are
    independently reopened unless their established producer contract explicitly
    permits the captured descriptor snapshot.
    """
    if not isinstance(expected_graph, AssuranceEvidenceGraph):
        return "expected assurance-evidence-graph projection has an invalid type"
    return _packet_summary_files_binding_error_from_paths(
        packet,
        artifact_root=artifact_root,
        trusted_expected_graph=expected_graph,
        captured_snapshots_by_path=captured_snapshots_by_path,
    )


def _packet_summary_files_binding_error_from_paths(
    packet: EvidencePacket,
    *,
    artifact_root: Path,
    trusted_expected_graph: AssuranceEvidenceGraph | None,
    captured_snapshots_by_path: Mapping[str, BoundedFileContents] | None = None,
) -> str | None:
    validated_packet, validation_error = _prepare_packet_binding_verification(packet)
    if validation_error is not None:
        return validation_error
    assert validated_packet is not None
    assert validated_packet.release_manifest is not None
    captured_snapshots, snapshot_error = _materialize_manifest_snapshots(
        {} if captured_snapshots_by_path is None else captured_snapshots_by_path,
        manifest=validated_packet.release_manifest,
        require_complete=False,
    )
    if snapshot_error is not None:
        return snapshot_error
    assert captured_snapshots is not None
    manifest_by_path = {
        artifact.path: artifact for artifact in validated_packet.release_manifest.artifacts
    }
    for captured_path in captured_snapshots:
        captured_role = manifest_by_path[captured_path].role
        if captured_role not in _TRUSTED_CAPTURED_SOURCE_ROLES:
            return f"evidence packet {captured_role} cannot use a producer-captured source snapshot"
    manifest_snapshots: dict[str, BoundedFileContents] = {}
    aggregate_bytes = 0
    for release_artifact in validated_packet.release_manifest.artifacts:
        captured_contents = captured_snapshots.get(release_artifact.path)
        contents = captured_contents
        if contents is None or release_artifact.role in _REVALIDATED_CAPTURED_SOURCE_ROLES:
            source_path = artifact_root.absolute() / Path(release_artifact.path)
            try:
                live_contents = read_confined_file_snapshot(
                    source_path,
                    root=artifact_root,
                    max_bytes=MAX_ARTIFACT_JSON_BYTES,
                    label=f"release manifest {release_artifact.role} artifact",
                )
                relative_path = confined_snapshot_relative_path(
                    source_path,
                    live_contents,
                    root=artifact_root,
                    path_root=artifact_root,
                    label=f"release manifest {release_artifact.role} artifact",
                )
            except (OSError, UnicodeError, ValueError):
                return (
                    f"evidence packet {release_artifact.role} source file could not be "
                    "safely verified"
                )
            if relative_path != release_artifact.path:
                return (
                    f"evidence packet {release_artifact.role} manifest path is not "
                    "normalized and confined"
                )
            if captured_contents is not None:
                captured_change_error = _captured_source_change_error(
                    release_artifact.role,
                    captured=captured_contents,
                    live=live_contents,
                )
                if captured_change_error is not None:
                    return captured_change_error
            contents = live_contents
        assert contents is not None
        snapshot_error, aggregate_bytes = _manifest_snapshot_binding_error(
            release_artifact,
            contents,
            aggregate_bytes=aggregate_bytes,
        )
        if snapshot_error is not None:
            return snapshot_error
        manifest_snapshots[release_artifact.path] = contents
    return _packet_summary_snapshots_binding_error(
        validated_packet,
        snapshots_by_path=manifest_snapshots,
        trusted_expected_graph=trusted_expected_graph,
    )


def _captured_source_change_error(
    role: str,
    *,
    captured: BoundedFileContents,
    live: BoundedFileContents,
) -> str | None:
    if live.data != captured.data or live.sha256 != captured.sha256 or live.size != captured.size:
        return f"evidence packet {role} contents changed after its producer snapshot"
    captured_identity = (
        captured.device,
        captured.inode,
        captured.modified_ns,
        captured.changed_ns,
    )
    live_identity = (
        live.device,
        live.inode,
        live.modified_ns,
        live.changed_ns,
    )
    if live_identity != captured_identity:
        return f"evidence packet {role} path identity changed after its producer snapshot"
    return None


def _prepare_packet_binding_verification(
    packet: EvidencePacket,
) -> tuple[EvidencePacket | None, str | None]:
    try:
        packet_payload = packet.model_dump(mode="json", warnings="error")
    except (TypeError, ValueError):
        return None, "evidence packet failed trusted model revalidation"
    try:
        packet = EvidencePacket.model_validate(packet_payload)
    except (TypeError, ValueError):
        # A model_copy(update=...) object is untrusted and never proceeds past
        # this branch. When its JSON-shaped projection still has a structurally
        # readable manifest, retain the more actionable missing-role diagnostic
        # that the verifier historically exposed. This changes only the error
        # selected for a rejected packet; it does not bypass strict revalidation.
        missing_role_error = _untrusted_packet_missing_manifest_role_error(packet_payload)
        return (
            None,
            missing_role_error or "evidence packet failed trusted model revalidation",
        )
    binding_error = packet_summary_digest_binding_error(packet)
    if binding_error is not None:
        return None, binding_error
    if packet.release_manifest is None:
        return None, "summary-file verification requires a release manifest"
    if len(packet.release_manifest.artifacts) > _MAX_RELEASE_MANIFEST_ARTIFACTS:
        return (
            None,
            "evidence packet release manifest exceeds the artifact verification limit",
        )
    return packet, None


def _untrusted_packet_missing_manifest_role_error(
    packet_payload: object,
) -> str | None:
    """Select a bounded missing-role diagnostic from rejected JSON-shaped data."""
    if not isinstance(packet_payload, Mapping):
        return None
    manifest = packet_payload.get("release_manifest")
    if not isinstance(manifest, Mapping):
        return None
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) > _MAX_RELEASE_MANIFEST_ARTIFACTS:
        return None
    observed_roles: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            return None
        role = artifact.get("role")
        if not isinstance(role, str):
            return None
        observed_roles.add(role)
    required_roles = ["evaluation-summary"]
    if isinstance(packet_payload.get("comparison"), Mapping):
        required_roles.append("comparison-summary")
    if isinstance(packet_payload.get("evidence_sensitivity"), Mapping):
        required_roles.append("evidence-sensitivity-report")
    if isinstance(packet_payload.get("statistical_sufficiency"), Mapping):
        required_roles.append("statistical-sufficiency-report")
    if isinstance(packet_payload.get("stochastic_evidence_sensitivity"), Mapping):
        required_roles.append("stochastic-evidence-sensitivity-report")
        required_roles.extend(
            (
                "stochastic-baseline-source-runset",
                "stochastic-counterfactual-source-runset",
            )
        )
    if isinstance(packet_payload.get("evidence_graph_digest"), str):
        required_roles.append("assurance-evidence-graph")
    for role in required_roles:
        if role not in observed_roles:
            return f"evidence packet {role} is missing from release manifest"
    return None


def _packet_summary_snapshots_binding_error(
    packet: EvidencePacket,
    *,
    snapshots_by_path: Mapping[str, BoundedFileContents],
    trusted_expected_graph: AssuranceEvidenceGraph | None,
) -> str | None:
    assert packet.release_manifest is not None
    manifest_path_error = _manifest_paths_binding_error(packet.release_manifest)
    if manifest_path_error is not None:
        return manifest_path_error
    snapshot_map, snapshot_map_error = _materialize_manifest_snapshots(
        snapshots_by_path,
        manifest=packet.release_manifest,
    )
    if snapshot_map_error is not None:
        return snapshot_map_error
    assert snapshot_map is not None
    aggregate_bytes = 0
    for release_artifact in packet.release_manifest.artifacts:
        contents = snapshot_map[release_artifact.path]
        snapshot_error, aggregate_bytes = _manifest_snapshot_binding_error(
            release_artifact,
            contents,
            aggregate_bytes=aggregate_bytes,
        )
        if snapshot_error is not None:
            return snapshot_error
    summaries: tuple[
        tuple[
            PacketArtifactRole,
            EvaluationSummary
            | ComparisonSummary
            | RAGSensitivityReport
            | StatisticalSufficiencyReport
            | StochasticEvidenceSensitivityReport,
        ],
        ...,
    ] = (("evaluation-summary", packet.evaluation),)
    if packet.comparison is not None:
        summaries = (
            *summaries,
            ("comparison-summary", packet.comparison),
        )
    if packet.evidence_sensitivity is not None:
        summaries = (
            *summaries,
            ("evidence-sensitivity-report", packet.evidence_sensitivity),
        )
    if packet.statistical_sufficiency is not None:
        summaries = (
            *summaries,
            ("statistical-sufficiency-report", packet.statistical_sufficiency),
        )
    if packet.stochastic_evidence_sensitivity is not None:
        summaries = (
            *summaries,
            (
                "stochastic-evidence-sensitivity-report",
                packet.stochastic_evidence_sensitivity,
            ),
        )
    manifest_by_role = {item.role: item for item in packet.release_manifest.artifacts}
    for role, nested_summary in summaries:
        manifest_artifact = manifest_by_role.get(role)
        if manifest_artifact is None:
            return f"evidence packet {role} is missing from release manifest"
        try:
            summary: object
            if role == "evaluation-summary":
                summary = _project_manifest_json_snapshot(
                    snapshot_map[manifest_artifact.path],
                    artifact_kind=role,
                    model=EvaluationSummary,
                )
            elif role == "comparison-summary":
                summary = _project_manifest_json_snapshot(
                    snapshot_map[manifest_artifact.path],
                    artifact_kind=role,
                    model=ComparisonSummary,
                )
            elif role == "evidence-sensitivity-report":
                summary = _project_manifest_json_snapshot(
                    snapshot_map[manifest_artifact.path],
                    artifact_kind=role,
                    model=RAGSensitivityReport,
                )
            elif role == "statistical-sufficiency-report":
                summary = _project_manifest_json_snapshot(
                    snapshot_map[manifest_artifact.path],
                    artifact_kind=role,
                    model=StatisticalSufficiencyReport,
                )
            else:
                summary = _project_manifest_json_snapshot(
                    snapshot_map[manifest_artifact.path],
                    artifact_kind=role,
                    model=StochasticEvidenceSensitivityReport,
                )
        except (OSError, UnicodeError, ValueError):
            return f"evidence packet {role} source file could not be safely verified"
        if summary != nested_summary:
            return f"evidence packet {role} source file does not match nested summary"
    evaluation_source_error = _evaluation_source_binding_error(
        packet,
        manifest_by_role=manifest_by_role,
        snapshots_by_path=snapshot_map,
    )
    if evaluation_source_error is not None:
        return evaluation_source_error
    if packet.stochastic_evidence_sensitivity is not None:
        baseline_role: PacketArtifactRole = "stochastic-baseline-source-runset"
        counterfactual_role: PacketArtifactRole = "stochastic-counterfactual-source-runset"
        baseline_artifact = manifest_by_role.get(baseline_role)
        counterfactual_artifact = manifest_by_role.get(counterfactual_role)
        if baseline_artifact is None or counterfactual_artifact is None:
            return "evidence packet stochastic source RunSets are missing from the release manifest"
        try:
            baseline_source = _project_runset_snapshot(
                snapshot_map[baseline_artifact.path],
                role=baseline_role,
            )
            counterfactual_source = _project_runset_snapshot(
                snapshot_map[counterfactual_artifact.path],
                role=counterfactual_role,
            )
        except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
            return "evidence packet stochastic source RunSets could not be safely verified"
        source_binding_error = stochastic_source_runsets_binding_error(
            packet,
            source_runsets=(baseline_source, counterfactual_source),
        )
        if source_binding_error is not None:
            return source_binding_error
    if packet.evidence_graph_digest is not None:
        graph_role: PacketArtifactRole = "assurance-evidence-graph"
        manifest_artifact = manifest_by_role.get(graph_role)
        if manifest_artifact is None:
            return "evidence packet assurance-evidence-graph is missing from release manifest"
        try:
            persisted_graph = _project_manifest_json_snapshot(
                snapshot_map[manifest_artifact.path],
                artifact_kind=graph_role,
                model=AssuranceEvidenceGraph,
            )
        except (OSError, UnicodeError, ValueError):
            return (
                "evidence packet assurance-evidence-graph source file could not be safely verified"
            )
        if persisted_graph.graph_digest != packet.evidence_graph_digest:
            return (
                "evidence packet assurance-evidence-graph semantic digest does not match "
                "evidence_graph_digest"
            )
        if trusted_expected_graph is None:
            try:
                trusted_expected_graph = build_privacy_filtered_evidence_graph(
                    packet.evaluation,
                    comparison=packet.comparison,
                    evidence_sensitivity=packet.evidence_sensitivity,
                    statistical_sufficiency=packet.statistical_sufficiency,
                    stochastic_evidence_sensitivity=(packet.stochastic_evidence_sensitivity),
                    control_efficacy=packet.control_efficacy,
                    control_efficacy_gate_profile=packet.control_efficacy_gate_profile,
                    control_efficacy_gate=packet.control_efficacy_gate,
                    limitations=packet.limitations,
                )
            except (TypeError, ValueError):
                return (
                    "evidence packet assurance-evidence-graph projection could not be "
                    "safely reconstructed"
                )
        if trusted_expected_graph != persisted_graph:
            return (
                "evidence packet assurance-evidence-graph does not correspond to "
                "nested packet evidence"
            )
    return None


def _evaluation_source_binding_error(
    packet: EvidencePacket,
    *,
    manifest_by_role: Mapping[str, ReleaseArtifact],
    snapshots_by_path: Mapping[str, BoundedFileContents],
) -> str | None:
    """Bind packet decisions to exact sources without assuming missing policy inputs."""

    candidate_artifact = manifest_by_role.get("candidate-runset")
    suite_artifact = manifest_by_role.get("compiled-suite")
    baseline_artifact = manifest_by_role.get("baseline-runset")
    comparison = packet.comparison
    if baseline_artifact is not None and comparison is None:
        return "evidence packet baseline-runset requires a nested comparison summary"
    if (
        comparison is not None
        and (candidate_artifact is not None or suite_artifact is not None)
        and baseline_artifact is None
    ):
        return (
            "evidence packet comparison with candidate evaluation sources requires "
            "a baseline-runset"
        )
    if candidate_artifact is None and suite_artifact is None and baseline_artifact is None:
        return None
    if candidate_artifact is None:
        if suite_artifact is None:
            assert baseline_artifact is not None
            assert comparison is not None
            try:
                standalone_baseline = _project_runset_snapshot(
                    snapshots_by_path[baseline_artifact.path],
                    role="baseline-runset",
                )
            except (KeyError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
                return "evidence packet baseline-runset could not be safely verified"
            return _comparison_runset_identity_binding_error(
                comparison,
                baseline=standalone_baseline,
            )
        return (
            "evidence packet compiled-suite requires a candidate-runset for "
            "independent source verification"
        )
    if suite_artifact is None:
        return (
            "evidence packet candidate-runset requires a compiled-suite for "
            "independent source verification"
        )
    if packet.evaluation.runset_digest is None:
        return (
            "evidence packet evaluation is missing runset_digest required to bind "
            "the manifest candidate-runset"
        )
    replay_context = packet.evaluation.replay_context
    if replay_context is None:
        return (
            "evidence packet evaluation is missing authenticated replay_context "
            "required for manifest source verification"
        )
    try:
        candidate = _project_runset_snapshot(
            snapshots_by_path[candidate_artifact.path],
            role="candidate-runset",
        )
        suite = _project_compiled_suite_snapshot(
            snapshots_by_path[suite_artifact.path],
        )
        baseline = (
            _project_runset_snapshot(
                snapshots_by_path[baseline_artifact.path],
                role="baseline-runset",
            )
            if baseline_artifact is not None
            else None
        )
        from agent_assure.evaluation.evaluator import (
            evaluate_runset,
            validate_runset_compatibility,
        )
        from agent_assure.fixtures.loader import compiled_suite_digest
        from agent_assure.policies.base import GateProfile, Waiver

        if replay_context.suite_digest != compiled_suite_digest(suite):
            return (
                "evidence packet evaluation replay_context suite_digest does not match "
                "manifest compiled-suite"
            )
        gate_profile = GateProfile.model_validate(
            replay_context.gate_profile.model_dump(mode="python")
        )
        waivers = tuple(
            Waiver(
                waiver_id=waiver.waiver_id,
                owner="authenticated-replay-context",
                rationale="authenticated scoring-semantic replay projection",
                reason_code=waiver.reason_code,
                finding_id=waiver.finding_id,
                artifact_digest=waiver.artifact_digest,
                expires_on=waiver.expires_on,
                reviewer="authenticated-replay-context",
            )
            for waiver in replay_context.waivers
        )
        validate_runset_compatibility(suite, candidate)
        candidate_report = evaluate_runset(
            suite,
            candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=replay_context.evaluation_date,
        )
    except (KeyError, OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return (
            "evidence packet manifest RunSets could not be safely verified against "
            "compiled-suite"
        )
    reproduced_evaluation = _replayed_evaluation_summary(
        candidate_report,
        replay_context=replay_context,
    )
    if _summary_without_environment(packet.evaluation) != _summary_without_environment(
        reproduced_evaluation
    ):
        return (
            "evidence packet evaluation does not match independent evaluation of the "
            "manifest candidate-runset, compiled-suite, and authenticated replay_context"
        )
    if comparison is None:
        return None
    assert baseline is not None
    identity_error = _comparison_runset_identity_binding_error(
        comparison,
        baseline=baseline,
        candidate=candidate,
    )
    if identity_error is not None:
        return identity_error
    try:
        validate_runset_compatibility(suite, baseline)
        reproduced_comparison = _replayed_comparison_summary(
            suite,
            baseline=baseline,
            candidate=candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            evaluation_date=replay_context.evaluation_date,
        )
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        return "evidence packet comparison sources could not be safely replayed"
    if _summary_without_environment(comparison) != _summary_without_environment(
        reproduced_comparison
    ):
        return (
            "evidence packet comparison does not match independent comparison of the "
            "manifest baseline-runset, candidate-runset, compiled-suite, and "
            "authenticated replay_context"
        )
    return None


def _replayed_evaluation_summary(
    report: EvaluationReport,
    *,
    replay_context: EvaluationReplayContext,
) -> EvaluationSummary:
    summary = report.candidate_vs_expectations.model_copy(
        update={"replay_context": replay_context}
    )
    if replay_context.report_mode == "fail-fast":
        first = next((finding for finding in report.failed_controls), None)
        if first is not None:
            summary = summary.model_copy(update={"findings": (first,)})
    return summary


def _summary_without_environment(summary: BaseModel) -> dict[str, object]:
    return summary.model_dump(
        mode="json",
        warnings="error",
        exclude={"environment"},
    )


def _comparison_runset_identity_binding_error(
    comparison: ComparisonSummary,
    *,
    baseline: RunSet,
    candidate: RunSet | None = None,
) -> str | None:
    from agent_assure.evaluation.evaluator import runset_digest

    if (
        comparison.baseline_runset_id,
        comparison.baseline_runset_digest,
    ) != (baseline.runset_id, runset_digest(baseline)):
        return (
            "evidence packet comparison baseline identity does not match manifest "
            "baseline-runset"
        )
    if (
        comparison.privacy_profile_id,
        comparison.privacy_profile_digest,
    ) != (baseline.privacy_profile_id, baseline.privacy_profile_digest):
        return (
            "evidence packet comparison privacy profile does not match manifest "
            "baseline-runset"
        )
    if candidate is None:
        return None
    if (
        comparison.candidate_runset_id,
        comparison.candidate_runset_digest,
    ) != (candidate.runset_id, runset_digest(candidate)):
        return (
            "evidence packet comparison candidate identity does not match manifest "
            "candidate-runset"
        )
    if (
        comparison.privacy_profile_id,
        comparison.privacy_profile_digest,
    ) != (candidate.privacy_profile_id, candidate.privacy_profile_digest):
        return (
            "evidence packet comparison privacy profile does not match manifest "
            "candidate-runset"
        )
    return None


def _replayed_comparison_summary(
    suite: CompiledSuite,
    *,
    baseline: RunSet,
    candidate: RunSet,
    gate_profile: GateProfile,
    waivers: tuple[Waiver, ...],
    evaluation_date: date,
) -> ComparisonSummary:
    from agent_assure.compare.runsets import (
        InvalidComparisonError,
        compare_runsets,
    )

    try:
        report = compare_runsets(
            suite,
            baseline,
            candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=evaluation_date,
        )
    except InvalidComparisonError as exc:
        if exc.report is None:
            raise
        report = exc.report
    return report.comparison_summary


def _manifest_paths_binding_error(manifest: ReleaseArtifactManifest) -> str | None:
    portable_paths: dict[str, str] = {}
    for artifact in manifest.artifacts:
        try:
            canonical_path = "/".join(portable_relative_path_parts(artifact.path))
        except ValueError:
            return f"evidence packet {artifact.role} manifest path is not normalized and confined"
        if canonical_path != artifact.path:
            return f"evidence packet {artifact.role} manifest path is not normalized and confined"
        portable_identity = os.path.normcase(canonical_path)
        previous = portable_paths.get(portable_identity)
        if previous is not None and previous != canonical_path:
            return "evidence packet release manifest contains ambiguous artifact paths"
        portable_paths[portable_identity] = canonical_path
    return None


def _materialize_manifest_snapshots(
    snapshots_by_path: Mapping[str, BoundedFileContents],
    *,
    manifest: ReleaseArtifactManifest,
    require_complete: bool = True,
) -> tuple[dict[str, BoundedFileContents] | None, str | None]:
    if not isinstance(snapshots_by_path, Mapping):
        return None, "evidence packet artifact snapshots have an invalid mapping type"
    materialized: dict[str, BoundedFileContents] = {}
    portable_paths: dict[str, str] = {}
    try:
        for index, (path, contents) in enumerate(snapshots_by_path.items()):
            if index >= _MAX_RELEASE_MANIFEST_ARTIFACTS:
                return None, "evidence packet artifact snapshots contain unmanifested paths"
            if not isinstance(path, str):
                return None, "evidence packet artifact snapshot path is not normalized"
            try:
                canonical_path = "/".join(portable_relative_path_parts(path))
            except ValueError:
                return None, "evidence packet artifact snapshot path is not normalized"
            if canonical_path != path:
                return None, "evidence packet artifact snapshot path is not normalized"
            portable_identity = os.path.normcase(canonical_path)
            previous = portable_paths.get(portable_identity)
            if previous is not None:
                return None, "evidence packet artifact snapshots contain ambiguous paths"
            if not isinstance(contents, BoundedFileContents):
                return None, "evidence packet artifact snapshot has an invalid type"
            portable_paths[portable_identity] = canonical_path
            materialized[canonical_path] = contents
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None, "evidence packet artifact snapshots could not be safely enumerated"

    expected_by_path = {artifact.path: artifact for artifact in manifest.artifacts}
    if any(path not in expected_by_path for path in materialized):
        return None, "evidence packet artifact snapshots contain unmanifested paths"
    if require_complete:
        for path, artifact in expected_by_path.items():
            if path not in materialized:
                return None, f"evidence packet {artifact.role} source snapshot is missing"
    return materialized, None


def _manifest_snapshot_binding_error(
    artifact: ReleaseArtifact,
    contents: BoundedFileContents,
    *,
    aggregate_bytes: int,
) -> tuple[str | None, int]:
    if not isinstance(contents.data, bytes):
        return f"evidence packet {artifact.role} source snapshot has invalid bytes", aggregate_bytes
    actual_size = len(contents.data)
    if actual_size > MAX_ARTIFACT_JSON_BYTES:
        return (
            f"evidence packet {artifact.role} source file exceeds the verification limit",
            aggregate_bytes,
        )
    actual_sha256 = hashlib.sha256(contents.data).hexdigest()
    if (
        isinstance(contents.size, bool)
        or not isinstance(contents.size, int)
        or contents.size != actual_size
        or contents.sha256 != actual_sha256
    ):
        return (
            f"evidence packet {artifact.role} source snapshot metadata does not match exact bytes",
            aggregate_bytes,
        )
    if actual_sha256 != artifact.sha256:
        return (
            f"evidence packet {artifact.role} source file digest does not match release manifest",
            aggregate_bytes,
        )
    aggregate_bytes += actual_size
    if aggregate_bytes > _MAX_RELEASE_MANIFEST_TOTAL_BYTES:
        return (
            "evidence packet release manifest exceeds the aggregate verification limit",
            aggregate_bytes,
        )
    return None, aggregate_bytes


def _project_manifest_json_snapshot(
    contents: BoundedFileContents,
    *,
    artifact_kind: PacketArtifactRole,
    model: type[SummaryT],
) -> SummaryT:
    payload = load_json_bytes_bounded(
        contents.data,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=artifact_kind.replace("-", " "),
    )
    validate_loaded_artifact_payload(payload, artifact_kind)
    return project_validated_artifact_payload(payload, model, kind=artifact_kind)


def _project_runset_snapshot(
    contents: BoundedFileContents,
    *,
    role: str,
) -> RunSet:
    payload = load_json_bytes_bounded(
        contents.data,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label=role.replace("-", " "),
    )
    validate_loaded_artifact_payload(payload, "run-set")
    runset = project_validated_artifact_payload(payload, RunSet, kind="run-set")
    return _unchanged_privacy_safe_runset(runset)


def _project_compiled_suite_snapshot(contents: BoundedFileContents) -> CompiledSuite:
    payload = load_json_bytes_bounded(
        contents.data,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="compiled suite",
    )
    validate_loaded_artifact_payload(payload, "compiled-suite")
    return project_validated_artifact_payload(
        payload,
        CompiledSuite,
        kind="compiled-suite",
    )


def build_evidence_packet(
    evaluation: EvaluationSummary,
    *,
    comparison: ComparisonSummary | None = None,
    evidence_sensitivity: RAGSensitivityReport | None = None,
    statistical_sufficiency: StatisticalSufficiencyReport | None = None,
    stochastic_evidence_sensitivity: StochasticEvidenceSensitivityReport | None = None,
    control_efficacy: ControlEfficacyReport | None = None,
    control_efficacy_gate_profile: ControlEfficacyGateProfile | None = None,
    control_efficacy_gate: ControlEfficacyGateDecision | None = None,
    environment: EnvironmentInfo | None = None,
    release_manifest: ReleaseArtifactManifest | None = None,
    evidence_graph_digest: DigestHex | None = None,
    usage_summary: UsageSummary | None = None,
    artifact_digests: tuple[PacketArtifactDigest, ...] = (),
    packet_id: str | None = None,
    interpretation: tuple[str, ...] = DEFAULT_INTERPRETATION,
    limitations: tuple[str, ...] = DEFAULT_PACKET_LIMITATIONS,
) -> EvidencePacket:
    resolved_packet_id = packet_id or _packet_id(
        evaluation,
        comparison=comparison,
        evidence_sensitivity=evidence_sensitivity,
        statistical_sufficiency=statistical_sufficiency,
        stochastic_evidence_sensitivity=stochastic_evidence_sensitivity,
        control_efficacy=control_efficacy,
        control_efficacy_gate_profile=control_efficacy_gate_profile,
        control_efficacy_gate=control_efficacy_gate,
        evidence_graph_digest=evidence_graph_digest,
        interpretation=interpretation,
        limitations=limitations,
    )
    return EvidencePacket(
        artifact_kind="evidence-packet",
        packet_id=resolved_packet_id,
        interpretation=interpretation,
        evaluation=evaluation,
        comparison=comparison,
        evidence_sensitivity=evidence_sensitivity,
        statistical_sufficiency=statistical_sufficiency,
        stochastic_evidence_sensitivity=stochastic_evidence_sensitivity,
        control_efficacy=control_efficacy,
        control_efficacy_gate_profile=control_efficacy_gate_profile,
        control_efficacy_gate=control_efficacy_gate,
        environment=environment,
        release_manifest=release_manifest,
        evidence_graph_digest=evidence_graph_digest,
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
    packet = EvidencePacket.model_validate(packet.model_dump(mode="json", warnings="error"))
    payload = redact_packet_payload(packet.model_dump(mode="json", warnings="error"))
    packet = EvidencePacket.model_validate(payload)
    safe_payload = packet.model_dump(mode="json", warnings="error")
    if redact_packet_payload(safe_payload) != safe_payload:
        raise ValueError("evidence packet Markdown payload could not be made privacy-safe")
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
    if packet.evidence_sensitivity is not None:
        sensitivity = packet.evidence_sensitivity
        reason_codes = (
            ", ".join(markdown_code_span(item.value) for item in sensitivity.reason_codes) or "none"
        )
        endpoint_value = (
            "not_evaluated"
            if sensitivity.endpoint_value is None
            else str(sensitivity.endpoint_value).lower()
        )
        lines.extend(
            [
                "",
                "## Controlled Evidence Sensitivity",
                "",
                f"- Harness notice: {markdown_text(SENSITIVITY_HARNESS_NOTICE)}",
                "- Boundary: synthetic detector contract test; this is controlled "
                "evidence sensitivity, not a causal guarantee or real-model "
                "prevalence estimate.",
                f"- State: {markdown_code_span(sensitivity.state.value)}",
                f"- Gate effect: {markdown_code_span(sensitivity.gate_effect.value)}",
                "- Verdict-bearing: "
                f"{markdown_code_span(str(sensitivity.verdict_bearing).lower())}",
                f"- Endpoint: {markdown_code_span(sensitivity.endpoint)}",
                f"- Endpoint value: {markdown_code_span(endpoint_value)}",
                f"- Expected relation: {markdown_code_span(sensitivity.expected_relation.value)}",
                f"- Observed relation: {markdown_code_span(sensitivity.observed_relation.value)}",
                "- Outcome classification: "
                f"{markdown_code_span(sensitivity.outcome_classification.value)}",
                f"- Outcome: {markdown_text(sensitivity.outcome_message)}",
                "- Detector-test status: "
                f"{markdown_code_span(sensitivity.detector_test_status.value)}",
                f"- Deterministic: {markdown_code_span(str(sensitivity.deterministic).lower())}",
                "- Decision inertia detected: "
                f"{markdown_code_span(str(sensitivity.decision_inertia_finding.detected).lower())}",
                f"- Reason codes: {reason_codes}",
                "- Baseline run set: "
                f"{markdown_code_span(sensitivity.baseline_arm.runset_id)} "
                f"{markdown_code_span(sensitivity.baseline_arm.runset_digest)}",
                "- Counterfactual run set: "
                f"{markdown_code_span(sensitivity.counterfactual_arm.runset_id)} "
                f"{markdown_code_span(sensitivity.counterfactual_arm.runset_digest)}",
                f"- Report digest: {markdown_code_span(sensitivity.report_digest)}",
                "",
                "### Sensitivity Limitations",
                "",
            ]
        )
        lines.extend(f"- {markdown_text(limitation)}" for limitation in sensitivity.limitations)
    if packet.statistical_sufficiency is not None:
        sufficiency = packet.statistical_sufficiency
        stochastic = packet.stochastic_evidence_sensitivity
        if stochastic is None:
            raise ValueError(
                "statistical sufficiency packet rendering requires stochastic evidence"
            )
        dependency = stochastic.dependency
        estimated_rate = stochastic.estimated_response_rate or "not_estimated"
        lines.extend(
            [
                "",
                "## Stochastic Evidence Sensitivity",
                "",
                "- Boundary: observed pair counterexamples are sample facts; the "
                "estimated independent-cluster response rate is a separate inferential "
                "summary, not a causal or externally generalizable claim.",
                f"- Protocol: {markdown_code_span(stochastic.protocol_id)} "
                f"{markdown_code_span(stochastic.protocol_digest)}",
                f"- Sufficiency state: {markdown_code_span(sufficiency.state.value)}",
                "- Pair accounting: "
                f"planned={sufficiency.planned_pairs}, actual={sufficiency.actual_pairs}, "
                f"included={sufficiency.included_pairs}, missing={sufficiency.missing_pairs}, "
                f"excluded={sufficiency.excluded_pairs}",
                "- Independent clusters: "
                f"planned={sufficiency.planned_clusters}, "
                f"actual={sufficiency.actual_clusters}, "
                f"analyzable={sufficiency.analyzable_clusters}",
                "- Population claim permitted: "
                f"{markdown_code_span(str(sufficiency.population_claim_permitted).lower())}",
                f"- State: {markdown_code_span(stochastic.state.value)}",
                f"- Gate effect: {markdown_code_span(stochastic.gate_effect.value)}",
                f"- Verdict-bearing: {markdown_code_span(str(stochastic.verdict_bearing).lower())}",
                "- Observed endpoint counts: "
                f"pairs={stochastic.observed_pair_count}, "
                f"responses={stochastic.observed_response_count}, "
                f"counterexamples={stochastic.observed_counterexample_count}",
                "- Observed cluster counts: "
                f"complete={stochastic.observed_cluster_count}, "
                f"responses={stochastic.observed_cluster_response_count}",
                "- Estimated independent-cluster response rate: "
                f"{markdown_code_span(estimated_rate)}",
                f"- Population claim: {markdown_code_span(stochastic.population_claim)}",
                "- Coupling classification: "
                f"{markdown_code_span(sufficiency.protocol.coupling.classification.value)}",
                "- Variance-reduction claim permitted: "
                f"{markdown_code_span(str(sufficiency.protocol.coupling.variance_reduction_claim_permitted).lower())}",
                "- Sufficiency dependency: "
                + (
                    f"{markdown_code_span(dependency.target_artifact_id)} "
                    f"{markdown_code_span(dependency.target_digest)}"
                    if dependency is not None
                    else markdown_code_span("none")
                ),
                f"- Sufficiency report digest: {markdown_code_span(sufficiency.report_digest)}",
                f"- Stochastic report digest: {markdown_code_span(stochastic.report_digest)}",
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
    if packet.evidence_graph_digest is not None:
        graph_artifacts = tuple(
            item for item in packet.artifact_digests if item.role == "assurance-evidence-graph"
        )
        if len(graph_artifacts) != 1:
            raise ValueError(
                "evidence-graph packet rendering requires exactly one exact-file digest"
            )
        graph_artifact = graph_artifacts[0]
        lines.extend(
            [
                "",
                "## Evidence Graph",
                "",
                "- Contract: `AssuranceEvidenceGraph/v1`",
                f"- Semantic digest: {markdown_code_span(packet.evidence_graph_digest)}",
                f"- Exact-file digest: {markdown_code_span(graph_artifact.sha256)}",
            ]
        )
    lines.extend(["", "## Measured Usage", ""])
    lines.extend(_packet_usage_lines(packet))
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {markdown_text(limitation)}" for limitation in packet.limitations)
    return "\n".join(lines) + "\n"


def write_evidence_packet_markdown(packet: EvidencePacket, path: Path) -> None:
    write_text_atomic(path, render_evidence_packet_markdown(packet))


def _privacy_filtered_graph_source(
    value: GraphSourceT,
    model: type[GraphSourceT],
) -> GraphSourceT:
    payload = redact_packet_payload(value.model_dump(mode="json"))
    return model.model_validate(payload)


def _privacy_filtered_optional_graph_source(
    value: GraphSourceT | None,
    model: type[GraphSourceT],
) -> GraphSourceT | None:
    if value is None:
        return None
    return _privacy_filtered_graph_source(value, model)


def _privacy_filtered_graph_limitations(
    limitations: tuple[str, ...],
) -> tuple[str, ...]:
    payload = redact_packet_payload({"limitations": limitations})
    filtered = payload.get("limitations")
    if not isinstance(filtered, list | tuple) or not all(
        isinstance(item, str) for item in filtered
    ):
        raise ValueError("packet limitations are invalid after graph privacy filtering")
    return tuple(filtered)


def _packet_id(
    evaluation: EvaluationSummary,
    *,
    comparison: ComparisonSummary | None,
    evidence_sensitivity: RAGSensitivityReport | None,
    statistical_sufficiency: StatisticalSufficiencyReport | None,
    stochastic_evidence_sensitivity: StochasticEvidenceSensitivityReport | None,
    control_efficacy: ControlEfficacyReport | None,
    control_efficacy_gate_profile: ControlEfficacyGateProfile | None,
    control_efficacy_gate: ControlEfficacyGateDecision | None,
    evidence_graph_digest: DigestHex | None,
    interpretation: tuple[str, ...],
    limitations: tuple[str, ...],
) -> str:
    payload: dict[str, object] = {
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
    if evidence_graph_digest is not None:
        payload["evidence_graph_digest"] = evidence_graph_digest
    if evidence_sensitivity is not None:
        payload["evidence_sensitivity"] = _summary_for_packet_id(evidence_sensitivity)
    if statistical_sufficiency is not None:
        payload["statistical_sufficiency"] = _summary_for_packet_id(statistical_sufficiency)
    if stochastic_evidence_sensitivity is not None:
        payload["stochastic_evidence_sensitivity"] = _summary_for_packet_id(
            stochastic_evidence_sensitivity
        )
    return f"packet-{sha256_hexdigest(redact_packet_payload(payload))[:16]}"


def _summary_for_packet_id(
    summary: (
        EvaluationSummary
        | ComparisonSummary
        | ControlEfficacyReport
        | RAGSensitivityReport
        | StatisticalSufficiencyReport
        | StochasticEvidenceSensitivityReport
    ),
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
