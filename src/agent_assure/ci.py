from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Literal

from agent_assure import __version__
from agent_assure.artifact_io import (
    ensure_unlinked_directory,
    unlink_file_if_exists,
    write_text_atomic,
)
from agent_assure.artifact_transaction import OutputPublicationRollback
from agent_assure.authoring.yaml_nodes import MAX_YAML_BYTES, load_yaml_nodes_text
from agent_assure.compare.runsets import ComparisonReport, InvalidComparisonError, compare_runsets
from agent_assure.controls.efficacy import (
    evaluate_control_efficacy_gate,
    load_threat_applicability_manifest,
)
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bytes_bounded,
)
from agent_assure.mutation.campaign import build_core_catalog
from agent_assure.onboarding.controls_mutation import ControlsMutationOnboardingConfig
from agent_assure.onboarding.path_safety import read_confined_file_snapshot
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile, Waiver
from agent_assure.reporting.environment import (
    artifact_project_root,
    attach_comparison_environment,
    attach_evaluation_environment,
    build_release_manifest,
    environment_with_dependency_inventory,
    release_artifact,
    source_project_root,
    write_release_manifest,
)
from agent_assure.reporting.graph import write_evidence_graph
from agent_assure.reporting.json_report import write_comparison_json, write_evaluation_json
from agent_assure.reporting.markdown import write_comparison_markdown, write_evaluation_markdown
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
    packet_summary_files_binding_error_for_trusted_publication,
    release_artifact_from_summary_snapshot,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.schema.campaign import AssuranceMutationCatalog
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateFinding,
    ControlEfficacyGateProfile,
    ControlEfficacyGateReason,
    ControlEfficacyReport,
    ControlEfficacySemanticState,
    ThreatApplicability,
    ThreatApplicabilityManifest,
    ThreatScopeSemanticState,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import (
    EvaluationSummary,
    evaluation_summary_coherence_error,
)
from agent_assure.schema.mutation import GateEffect
from agent_assure.schema.packet import (
    EvidencePacket,
    packet_summary_digest_binding_error,
)
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import (
    load_json,
    load_validated_artifact_payload,
    project_validated_artifact_payload,
    validate_loaded_artifact_payload,
)

GateArtifact = EvaluationSummary | ComparisonSummary | ControlEfficacyReport | EvidencePacket
ReportMode = Literal["full", "fail-fast"]
_CI_OUTPUT_FILENAMES = (
    "evaluation-report.json",
    "evaluation-summary.json",
    "evaluation-report.md",
    "comparison-report.json",
    "comparison-summary.json",
    "comparison-report.md",
    "evidence-packet.json",
    "evidence-packet.md",
    "assurance-evidence-graph.json",
    "release-artifact-manifest.json",
    "dependency-inventory.json",
    "ci-diagnostics.json",
)
_MAX_CI_PACKET_ROLLBACK_BYTES = 4 * MAX_ARTIFACT_JSON_BYTES


class _CiPacketBindingError(ValueError):
    """Raised when trusted source bytes change during CI packet publication."""


class GateOutcome(StrEnum):
    invalid = "invalid"
    fail = "fail"
    review = "review"
    not_evaluated = "not_evaluated"
    pass_ = "pass"


class EfficacyEvidenceState(StrEnum):
    not_applicable = "not_applicable"
    absent = "absent"
    present = "present"


class EfficacyVerificationMode(StrEnum):
    not_requested = "not_requested"
    advisory = "advisory"
    strict = "strict"


_GATE_OUTCOME_EXIT_CODES = {
    GateOutcome.invalid: 2,
    GateOutcome.fail: 1,
    GateOutcome.review: 0,
    GateOutcome.not_evaluated: 0,
    GateOutcome.pass_: 0,
}
_PACKET_OUTCOME_PRECEDENCE = (
    GateOutcome.invalid,
    GateOutcome.fail,
    GateOutcome.review,
    GateOutcome.not_evaluated,
    GateOutcome.pass_,
)


@dataclass(frozen=True)
class GateDecision:
    exit_code: int
    outcome: GateOutcome
    message: str
    reason_code: ReasonCode | ControlEfficacyGateReason | None = None
    artifact_kind: str = ""
    artifact_path: str = ""
    validator: str = "agent_assure.ci"
    efficacy_evidence: EfficacyEvidenceState = EfficacyEvidenceState.not_applicable
    efficacy_verification: EfficacyVerificationMode = EfficacyVerificationMode.not_requested
    efficacy_required: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, GateOutcome):
            raise TypeError("CI gate outcome must be a GateOutcome")
        if not isinstance(self.efficacy_evidence, EfficacyEvidenceState):
            raise TypeError("CI gate efficacy evidence must be an EfficacyEvidenceState")
        if not isinstance(self.efficacy_verification, EfficacyVerificationMode):
            raise TypeError("CI gate efficacy verification must be an EfficacyVerificationMode")
        expected_exit_code = _GATE_OUTCOME_EXIT_CODES[self.outcome]
        if self.exit_code != expected_exit_code:
            raise ValueError(
                "CI gate outcome/exit_code mismatch: "
                f"{self.outcome.value} requires {expected_exit_code}, got {self.exit_code}"
            )

    def model_dump(self) -> dict[str, object]:
        return {
            "exit_code": self.exit_code,
            "outcome": self.outcome.value,
            "message": self.message,
            "reason_code": self.reason_code.value if self.reason_code is not None else None,
            "artifact_kind": self.artifact_kind,
            "artifact_path": self.artifact_path,
            "validator": self.validator,
            "efficacy_evidence": self.efficacy_evidence.value,
            "efficacy_verification": self.efficacy_verification.value,
            "efficacy_required": self.efficacy_required,
        }


def _efficacy_mode(strict_efficacy: bool) -> EfficacyVerificationMode:
    return EfficacyVerificationMode.strict if strict_efficacy else EfficacyVerificationMode.advisory


def _efficacy_context(
    *,
    evidence: EfficacyEvidenceState,
    verification: EfficacyVerificationMode,
    required: bool,
) -> str:
    return (
        f"efficacy_evidence={evidence.value} "
        f"efficacy_verification={verification.value} "
        f"efficacy_required={'true' if required else 'false'}"
    )


def _efficacy_gate_decision(
    *,
    exit_code: int,
    outcome: GateOutcome,
    message: str,
    evidence: EfficacyEvidenceState,
    verification: EfficacyVerificationMode,
    required: bool,
    reason_code: ReasonCode | ControlEfficacyGateReason | None = None,
    artifact_kind: str = "",
) -> GateDecision:
    return GateDecision(
        exit_code=exit_code,
        outcome=outcome,
        message=(
            f"{message}; "
            f"{_efficacy_context(evidence=evidence, verification=verification, required=required)}"
        ),
        reason_code=reason_code,
        artifact_kind=artifact_kind,
        efficacy_evidence=evidence,
        efficacy_verification=verification,
        efficacy_required=required,
    )


@dataclass(frozen=True)
class CiRunResult:
    decision: GateDecision
    report_paths: tuple[Path, ...]
    packet_path: Path
    diagnostics_path: Path | None = None


@dataclass(frozen=True)
class VerifierThreatScopeProjection:
    """Verifier-owned manifest fields that affect efficacy report semantics."""

    manifest_digest: str
    present_control_ids: tuple[str, ...]
    items: tuple[tuple[str, ThreatApplicability, bool], ...]

    def __post_init__(self) -> None:
        if len(self.manifest_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.manifest_digest
        ):
            raise ValueError("verifier threat scope digest must be lowercase SHA-256")
        if self.present_control_ids != tuple(sorted(set(self.present_control_ids))):
            raise ValueError("verifier threat scope present controls must be unique and sorted")
        threat_ids = tuple(item[0] for item in self.items)
        if not threat_ids or threat_ids != tuple(sorted(set(threat_ids))):
            raise ValueError("verifier threat scope items must be nonempty, unique, and sorted")

    @classmethod
    def from_manifest(
        cls,
        manifest: ThreatApplicabilityManifest,
    ) -> VerifierThreatScopeProjection:
        return cls(
            manifest_digest=manifest.manifest_digest,
            present_control_ids=manifest.present_control_ids,
            items=tuple(
                (item.threat_id, item.applicability, item.critical) for item in manifest.items
            ),
        )


@dataclass(frozen=True)
class VerifierEfficacyPolicy:
    """Verifier-owned acceptance policy kept outside transported evidence."""

    profile: ControlEfficacyGateProfile
    expected_selected_operator_ids: tuple[str, ...]
    expected_catalog_digest: str
    source_sha256: str
    expected_threat_manifest_digest: str | None = None
    scope_source_sha256: str | None = None
    expected_catalog: AssuranceMutationCatalog | None = None
    expected_threat_scope: VerifierThreatScopeProjection | None = None

    def __post_init__(self) -> None:
        selected = self.expected_selected_operator_ids
        if not selected or selected != tuple(sorted(set(selected))):
            raise ValueError(
                "verifier efficacy selected operators must be nonempty, unique, and sorted"
            )
        if not set(self.profile.required_operators).issubset(selected):
            raise ValueError("verifier efficacy required operators must be selected operators")
        for label, digest in (
            ("catalog digest", self.expected_catalog_digest),
            ("policy source digest", self.source_sha256),
        ):
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ValueError(f"verifier efficacy {label} must be lowercase SHA-256")
        if (self.expected_threat_manifest_digest is None) is not (self.scope_source_sha256 is None):
            raise ValueError(
                "verifier efficacy threat manifest digest and source digest "
                "must be present together"
            )
        if (self.expected_threat_manifest_digest is None) is not (
            self.expected_threat_scope is None
        ):
            raise ValueError(
                "verifier efficacy threat manifest digest and semantic projection "
                "must be present together"
            )
        for label, optional_digest in (
            ("threat manifest digest", self.expected_threat_manifest_digest),
            ("threat manifest source digest", self.scope_source_sha256),
        ):
            if optional_digest is not None and (
                len(optional_digest) != 64
                or any(character not in "0123456789abcdef" for character in optional_digest)
            ):
                raise ValueError(f"verifier efficacy {label} must be lowercase SHA-256")


def load_gate_artifact(path: Path) -> GateArtifact:
    payload = load_json(path)
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind == "evaluation-summary":
        validate_loaded_artifact_payload(payload, artifact_kind)
        return project_validated_artifact_payload(
            payload,
            EvaluationSummary,
            kind=artifact_kind,
        )
    if artifact_kind == "comparison-summary":
        validate_loaded_artifact_payload(payload, artifact_kind)
        return project_validated_artifact_payload(
            payload,
            ComparisonSummary,
            kind=artifact_kind,
        )
    if artifact_kind == "evidence-packet":
        validate_loaded_artifact_payload(payload, artifact_kind)
        return project_validated_artifact_payload(
            payload,
            EvidencePacket,
            kind=artifact_kind,
        )
    if artifact_kind == "control-efficacy-report":
        validate_loaded_artifact_payload(payload, artifact_kind)
        return project_validated_artifact_payload(
            payload,
            ControlEfficacyReport,
            kind=artifact_kind,
        )
    raise ValueError(
        "CI gate expects artifact_kind evaluation-summary, comparison-summary, "
        "control-efficacy-report, or evidence-packet"
    )


def load_control_efficacy_verifier_policy(path: Path) -> VerifierEfficacyPolicy:
    """Load a verifier policy without consuming packet-controlled policy bytes."""
    suffix = path.suffix.lower()
    if suffix not in {".json", ".yaml", ".yml"}:
        raise ValueError("efficacy policy must use .json, .yaml, or .yml")
    contents = read_confined_file_snapshot(
        path,
        root=path.parent,
        max_bytes=MAX_YAML_BYTES,
        label="control-efficacy verifier policy",
    )
    if suffix == ".json":
        payload = load_json_bytes_bounded(
            contents.data,
            label="control-efficacy verifier policy",
        )
        profile = ControlEfficacyGateProfile.model_validate(payload)
        selected = profile.required_operators
        threat_manifest_digest = None
        scope_source_sha256 = None
        threat_scope_projection = None
    else:
        loaded = load_yaml_nodes_text(
            contents.data.decode("utf-8"),
            label="control-efficacy verifier policy",
        ).data
        config = ControlsMutationOnboardingConfig.model_validate(loaded)
        if config.package_version != __version__:
            raise ValueError(
                "control-efficacy verifier policy package version does not match "
                "the installed package"
            )
        profile = config.control_efficacy
        selected = config.operator_ids
        threat_manifest_path = path.parent / Path(config.threat_applicability_manifest)
        threat_manifest_contents = read_confined_file_snapshot(
            threat_manifest_path,
            root=path.parent,
            max_bytes=MAX_YAML_BYTES,
            label="verifier-owned threat applicability manifest",
        )
        threat_manifest = load_threat_applicability_manifest(
            threat_manifest_path,
            reader=lambda _path: threat_manifest_contents.data,
        )
        threat_manifest_digest = threat_manifest.manifest_digest
        scope_source_sha256 = threat_manifest_contents.sha256
        threat_scope_projection = VerifierThreatScopeProjection.from_manifest(threat_manifest)
    installed_catalog = build_core_catalog()
    if profile.required_catalog != installed_catalog.catalog_id:
        raise ValueError("verifier efficacy policy requires an unsupported catalog")
    return VerifierEfficacyPolicy(
        profile=profile,
        expected_selected_operator_ids=selected,
        expected_catalog_digest=installed_catalog.catalog_digest,
        source_sha256=contents.sha256,
        expected_threat_manifest_digest=threat_manifest_digest,
        scope_source_sha256=scope_source_sha256,
        expected_catalog=installed_catalog,
        expected_threat_scope=threat_scope_projection,
    )


def gate_artifact(
    artifact: GateArtifact,
    *,
    artifact_root: Path | None = None,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
    verifier_efficacy_policy: VerifierEfficacyPolicy | None = None,
    strict_efficacy: bool = True,
    require_efficacy: bool = False,
) -> GateDecision:
    """Gate one artifact with strict efficacy verification as the library default.

    ``strict_efficacy`` controls verification strength when efficacy evidence is
    present. ``require_efficacy`` controls whether an evidence packet must carry
    that evidence; supplying a verifier policy also implies the requirement.
    """
    if isinstance(artifact, EvaluationSummary):
        if verifier_efficacy_policy is not None or require_efficacy:
            return _unexpected_efficacy_options_decision(
                artifact.artifact_kind,
                strict_efficacy=strict_efficacy,
            )
        return gate_evaluation_summary(
            artifact,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
    if isinstance(artifact, ComparisonSummary):
        if verifier_efficacy_policy is not None or require_efficacy:
            return _unexpected_efficacy_options_decision(
                artifact.artifact_kind,
                strict_efficacy=strict_efficacy,
            )
        return gate_comparison_summary(
            artifact,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
    if isinstance(artifact, ControlEfficacyReport):
        return gate_control_efficacy_report(
            artifact,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
            verifier_policy=verifier_efficacy_policy,
            strict_efficacy=strict_efficacy,
            require_efficacy=require_efficacy,
        )
    return gate_evidence_packet(
        artifact,
        artifact_root=artifact_root,
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
        verifier_policy=verifier_efficacy_policy,
        strict_efficacy=strict_efficacy,
        require_efficacy=require_efficacy,
    )


def _unexpected_efficacy_options_decision(
    artifact_kind: str,
    *,
    strict_efficacy: bool,
) -> GateDecision:
    return _efficacy_gate_decision(
        exit_code=2,
        outcome=GateOutcome.invalid,
        message=(
            "ci gate invalid: efficacy verification options require a control-efficacy "
            "report or an evidence packet carrying control-efficacy evidence"
        ),
        evidence=EfficacyEvidenceState.not_applicable,
        verification=_efficacy_mode(strict_efficacy),
        required=True,
        artifact_kind=artifact_kind,
    )


def gate_evaluation_summary(
    summary: EvaluationSummary,
    *,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
) -> GateDecision:
    coherence_error = evaluation_summary_coherence_error(
        state=summary.state,
        findings=summary.findings,
    )
    if coherence_error is not None:
        return GateDecision(
            exit_code=2,
            outcome=GateOutcome.invalid,
            message=f"ci gate invalid: {coherence_error}",
            reason_code=ReasonCode.POLICY_FAILED,
            artifact_kind=summary.artifact_kind,
        )

    decision = _decision_for_state(
        summary.state,
        subject=f"evaluation-summary {summary.runset_id}",
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
    )
    if decision.exit_code:
        finding = summary.findings[0] if summary.findings else None
        return GateDecision(
            exit_code=decision.exit_code,
            outcome=decision.outcome,
            message=decision.message,
            reason_code=finding.reason_code if finding is not None else ReasonCode.POLICY_FAILED,
            artifact_kind=summary.artifact_kind,
        )
    return decision


def gate_comparison_summary(
    summary: ComparisonSummary,
    *,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
) -> GateDecision:
    if (
        summary.classification is ComparisonClassification.invalid_comparison
        or summary.fixture_equivalence_state is GateState.fail
    ):
        return GateDecision(
            exit_code=2,
            outcome=GateOutcome.invalid,
            message=(
                "ci gate invalid: comparison-summary "
                f"{summary.baseline_runset_id}->{summary.candidate_runset_id} "
                "has invalid fixture equivalence"
            ),
            reason_code=ReasonCode.FIXTURE_EQUIVALENCE_FAILED,
            artifact_kind=summary.artifact_kind,
        )
    if (
        summary.classification
        in {
            ComparisonClassification.new_failure,
            ComparisonClassification.persistent_failure,
        }
        and summary.candidate_state is not GateState.warn
    ):
        return GateDecision(
            exit_code=1,
            outcome=GateOutcome.fail,
            message=(
                "ci gate fail: comparison-summary "
                f"{summary.baseline_runset_id}->{summary.candidate_runset_id} "
                f"classification={summary.classification.value}"
            ),
            reason_code=ReasonCode.POLICY_FAILED,
            artifact_kind=summary.artifact_kind,
        )
    return _decision_for_state(
        summary.candidate_state,
        subject=(f"comparison-summary {summary.baseline_runset_id}->{summary.candidate_runset_id}"),
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
    )


def gate_evidence_packet(
    packet: EvidencePacket,
    *,
    artifact_root: Path | None = None,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
    verifier_policy: VerifierEfficacyPolicy | None = None,
    strict_efficacy: bool = True,
    require_efficacy: bool = False,
) -> GateDecision:
    summary_digest_error = packet_summary_digest_binding_error(packet)
    if summary_digest_error is not None:
        return GateDecision(
            exit_code=2,
            outcome=GateOutcome.invalid,
            message=f"ci gate invalid: {summary_digest_error}",
            reason_code=ReasonCode.POLICY_FAILED,
            artifact_kind=packet.artifact_kind,
        )
    if artifact_root is not None:
        summary_file_error = packet_summary_files_binding_error(
            packet,
            artifact_root=artifact_root,
        )
        if summary_file_error is not None:
            return GateDecision(
                exit_code=2,
                outcome=GateOutcome.invalid,
                message=f"ci gate invalid: {summary_file_error}",
                reason_code=ReasonCode.POLICY_FAILED,
                artifact_kind=packet.artifact_kind,
            )
    efficacy_required = require_efficacy or verifier_policy is not None
    efficacy_decision: GateDecision | None = None
    decisions = [
        gate_evaluation_summary(
            packet.evaluation,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
    ]
    if packet.comparison is not None:
        decisions.append(
            gate_comparison_summary(
                packet.comparison,
                fail_on_warn=fail_on_warn,
                fail_on_not_evaluated=fail_on_not_evaluated,
            )
        )
    if packet.control_efficacy is not None:
        if packet.control_efficacy_gate is None or packet.control_efficacy_gate_profile is None:
            return _efficacy_gate_decision(
                exit_code=2,
                outcome=GateOutcome.invalid,
                message=(
                    "ci gate invalid: evidence-packet "
                    f"{packet.packet_id} is missing its control-efficacy gate profile or decision"
                ),
                evidence=EfficacyEvidenceState.present,
                verification=_efficacy_mode(strict_efficacy),
                required=efficacy_required,
                artifact_kind=packet.artifact_kind,
            )
        embedded_check = gate_control_efficacy_decision(
            packet.control_efficacy,
            packet.control_efficacy_gate,
            profile=packet.control_efficacy_gate_profile,
            strict_efficacy=False,
            verification_mode=_efficacy_mode(strict_efficacy),
            efficacy_required=efficacy_required,
        )
        if embedded_check.outcome is GateOutcome.invalid:
            return embedded_check
        if verifier_policy is None:
            if strict_efficacy:
                return _missing_verifier_policy_decision(
                    packet.artifact_kind,
                    required=efficacy_required,
                )
            efficacy_decision = gate_control_efficacy_decision(
                packet.control_efficacy,
                packet.control_efficacy_gate,
                profile=packet.control_efficacy_gate_profile,
                fail_on_warn=fail_on_warn,
                fail_on_not_evaluated=fail_on_not_evaluated,
                strict_efficacy=False,
                efficacy_required=efficacy_required,
            )
        else:
            if strict_efficacy and (
                verifier_policy.expected_catalog is None
                or verifier_policy.expected_threat_scope is None
            ):
                return _missing_verifier_threat_scope_decision(
                    packet.artifact_kind,
                    required=efficacy_required,
                )
            binding_error = _verifier_policy_binding_decision(
                packet.control_efficacy,
                verifier_policy,
                artifact_kind=packet.artifact_kind,
                strict_efficacy=strict_efficacy,
                required=efficacy_required,
            )
            if binding_error is not None:
                return binding_error
            verifier_gate = evaluate_control_efficacy_gate(
                packet.control_efficacy,
                verifier_policy.profile,
            )
            efficacy_decision = gate_control_efficacy_decision(
                packet.control_efficacy,
                verifier_gate,
                profile=verifier_policy.profile,
                fail_on_warn=fail_on_warn,
                fail_on_not_evaluated=fail_on_not_evaluated,
                strict_efficacy=strict_efficacy,
                efficacy_required=efficacy_required,
            )
        decisions.append(efficacy_decision)
    elif efficacy_required:
        return _missing_packet_efficacy_decision(
            packet,
            strict_efficacy=strict_efficacy,
        )
    controlling_decision = next(
        candidate
        for outcome in _PACKET_OUTCOME_PRECEDENCE
        for candidate in decisions
        if candidate.outcome is outcome
    )
    if controlling_decision.outcome is not GateOutcome.pass_:
        return GateDecision(
            exit_code=controlling_decision.exit_code,
            outcome=controlling_decision.outcome,
            message=_packet_gate_message(
                packet,
                controlling_decision,
                efficacy_decision,
                verifier_policy=verifier_policy,
                efficacy_required=efficacy_required,
            ),
            reason_code=controlling_decision.reason_code,
            artifact_kind=packet.artifact_kind,
            efficacy_evidence=(
                EfficacyEvidenceState.present
                if efficacy_decision is not None
                else EfficacyEvidenceState.absent
            ),
            efficacy_verification=(
                efficacy_decision.efficacy_verification
                if efficacy_decision is not None
                else EfficacyVerificationMode.not_requested
            ),
            efficacy_required=efficacy_required,
        )
    if efficacy_decision is not None:
        policy_suffix = _verifier_policy_message(verifier_policy)
        return GateDecision(
            exit_code=0,
            outcome=GateOutcome.pass_,
            message=(
                f"{efficacy_decision.message}{policy_suffix}; evidence-packet={packet.packet_id}"
            ),
            reason_code=efficacy_decision.reason_code,
            artifact_kind=packet.artifact_kind,
            efficacy_evidence=EfficacyEvidenceState.present,
            efficacy_verification=efficacy_decision.efficacy_verification,
            efficacy_required=efficacy_required,
        )
    return _efficacy_gate_decision(
        exit_code=0,
        outcome=GateOutcome.pass_,
        message=f"ci gate pass: evidence-packet {packet.packet_id}",
        evidence=EfficacyEvidenceState.absent,
        verification=EfficacyVerificationMode.not_requested,
        required=False,
        artifact_kind=packet.artifact_kind,
    )


def _packet_gate_message(
    packet: EvidencePacket,
    controlling_decision: GateDecision,
    efficacy_decision: GateDecision | None,
    *,
    verifier_policy: VerifierEfficacyPolicy | None = None,
    efficacy_required: bool,
) -> str:
    parts = [controlling_decision.message]
    if efficacy_decision is not None and controlling_decision is not efficacy_decision:
        report = packet.control_efficacy
        gate = packet.control_efficacy_gate
        if report is not None and gate is not None:
            parts.append(
                "control-efficacy observation: "
                f"efficacy_verification={efficacy_decision.efficacy_verification.value} "
                f"gate_state={gate.state.value} {_efficacy_observation(report)}"
            )
    policy_message = _verifier_policy_message(verifier_policy)
    if policy_message:
        parts.append(policy_message.removeprefix("; "))
    if controlling_decision is not efficacy_decision:
        parts.append(
            _efficacy_context(
                evidence=(
                    EfficacyEvidenceState.present
                    if efficacy_decision is not None
                    else EfficacyEvidenceState.absent
                ),
                verification=(
                    efficacy_decision.efficacy_verification
                    if efficacy_decision is not None
                    else EfficacyVerificationMode.not_requested
                ),
                required=efficacy_required,
            )
        )
    parts.append(f"evidence-packet={packet.packet_id}")
    return "; ".join(parts)


def _missing_packet_efficacy_decision(
    packet: EvidencePacket,
    *,
    strict_efficacy: bool,
) -> GateDecision:
    return _efficacy_gate_decision(
        exit_code=2,
        outcome=GateOutcome.invalid,
        message=(
            "ci gate invalid: evidence-packet "
            f"{packet.packet_id} has no control-efficacy evidence; it is required "
            "by verifier policy or --require-efficacy"
        ),
        evidence=EfficacyEvidenceState.absent,
        verification=_efficacy_mode(strict_efficacy),
        required=True,
        artifact_kind=packet.artifact_kind,
    )


def _missing_verifier_policy_decision(
    artifact_kind: str,
    *,
    required: bool,
) -> GateDecision:
    return _efficacy_gate_decision(
        exit_code=2,
        outcome=GateOutcome.invalid,
        message=(
            "ci gate invalid: strict efficacy verification requires a "
            "separate verifier-owned efficacy policy"
        ),
        evidence=EfficacyEvidenceState.present,
        verification=EfficacyVerificationMode.strict,
        required=required,
        artifact_kind=artifact_kind,
    )


def _missing_verifier_threat_scope_decision(
    artifact_kind: str,
    *,
    required: bool,
) -> GateDecision:
    return _efficacy_gate_decision(
        exit_code=2,
        outcome=GateOutcome.invalid,
        message=(
            "ci gate invalid: strict efficacy verification requires a "
            "verifier-owned threat applicability manifest"
        ),
        evidence=EfficacyEvidenceState.present,
        verification=EfficacyVerificationMode.strict,
        required=required,
        artifact_kind=artifact_kind,
    )


def _verifier_policy_binding_decision(
    report: ControlEfficacyReport,
    policy: VerifierEfficacyPolicy,
    *,
    artifact_kind: str,
    strict_efficacy: bool,
    required: bool,
) -> GateDecision | None:
    mismatches: list[str] = []
    if report.catalog_id != policy.profile.required_catalog:
        mismatches.append("catalog_id")
    if report.catalog_digest != policy.expected_catalog_digest:
        mismatches.append("catalog_digest")
    if report.selected_operator_ids != policy.expected_selected_operator_ids:
        mismatches.append("selected_operator_ids")
    if report.required_operator_ids != policy.profile.required_operators:
        mismatches.append("required_operator_ids")
    if (
        policy.expected_threat_manifest_digest is not None
        and report.threat_manifest_digest != policy.expected_threat_manifest_digest
    ):
        mismatches.append("threat_manifest_digest")
    for mismatch in _verifier_semantic_projection_mismatches(report, policy):
        if mismatch not in mismatches:
            mismatches.append(mismatch)
    if not mismatches:
        return None
    return _efficacy_gate_decision(
        exit_code=2,
        outcome=GateOutcome.invalid,
        message=(
            "ci gate invalid: control-efficacy report does not match verifier-owned "
            f"scope ({','.join(mismatches)})"
        ),
        evidence=EfficacyEvidenceState.present,
        verification=_efficacy_mode(strict_efficacy),
        required=required,
        artifact_kind=artifact_kind,
    )


def _verifier_semantic_projection_mismatches(
    report: ControlEfficacyReport,
    policy: VerifierEfficacyPolicy,
) -> tuple[str, ...]:
    mismatches: list[str] = []

    def note(label: str) -> None:
        if label not in mismatches:
            mismatches.append(label)

    catalog = policy.expected_catalog
    if catalog is not None:
        if catalog.catalog_id != policy.profile.required_catalog:
            note("verifier_catalog_id")
        if catalog.catalog_digest != policy.expected_catalog_digest:
            note("verifier_catalog_digest")
        if report.catalog_id != catalog.catalog_id:
            note("catalog_id")
        if report.catalog_digest != catalog.catalog_digest:
            note("catalog_digest")

        catalog_operator_ids = tuple(item.descriptor.operator_id for item in catalog.operators)
        if report.canonical_operator_ids != catalog_operator_ids:
            note("canonical_operator_ids")
        catalog_families = tuple(sorted({item.invariant_family for item in catalog.operators}))
        if report.canonical_invariant_families != catalog_families:
            note("canonical_invariant_families")

        catalog_by_id = {item.descriptor.operator_id: item for item in catalog.operators}
        for outcome in report.operator_outcomes:
            catalog_item = catalog_by_id.get(outcome.operator_id)
            if catalog_item is None:
                note("operator_outcomes.operator_id")
                continue
            descriptor = catalog_item.descriptor
            if outcome.invariant_family != catalog_item.invariant_family:
                note("operator_outcomes.invariant_family")
            if outcome.independence_class is not descriptor.independence_class:
                note("operator_outcomes.independence_class")
            if outcome.catalog_threat_ids != catalog_item.threat_source_references:
                note("operator_outcomes.catalog_threat_ids")
            if (
                outcome.target_control_ids
                != descriptor.expected_detection_contract.target_control_ids
            ):
                note("operator_outcomes.target_control_ids")

    threat_scope = policy.expected_threat_scope
    if threat_scope is not None:
        if threat_scope.manifest_digest != policy.expected_threat_manifest_digest:
            note("verifier_threat_manifest_digest")
        if report.threat_manifest_digest != threat_scope.manifest_digest:
            note("threat_manifest_digest")
        report_items = tuple(
            (item.threat_id, item.applicability, item.critical) for item in report.threat_coverage
        )
        if report_items != threat_scope.items:
            note("threat_coverage.manifest_projection")

    if catalog is not None and threat_scope is not None:
        for mismatch in _operator_scope_projection_mismatches(
            report,
            catalog,
            threat_scope,
        ):
            note(mismatch)
    return tuple(mismatches)


def _operator_scope_projection_mismatches(
    report: ControlEfficacyReport,
    catalog: AssuranceMutationCatalog,
    threat_scope: VerifierThreatScopeProjection,
) -> tuple[str, ...]:
    mismatches: list[str] = []
    catalog_by_id = {item.descriptor.operator_id: item for item in catalog.operators}
    manifest_by_id = {
        threat_id: (applicability, critical)
        for threat_id, applicability, critical in threat_scope.items
    }
    present_controls = set(threat_scope.present_control_ids)
    for outcome in report.operator_outcomes:
        catalog_item = catalog_by_id.get(outcome.operator_id)
        if catalog_item is None:
            continue
        catalog_threat_ids = catalog_item.threat_source_references
        expected_threat_ids = tuple(
            threat_id for threat_id in catalog_threat_ids if threat_id in manifest_by_id
        )
        expected_unscoped_ids = tuple(
            threat_id for threat_id in catalog_threat_ids if threat_id not in manifest_by_id
        )
        expected_critical_ids = tuple(
            threat_id
            for threat_id in expected_threat_ids
            if manifest_by_id[threat_id][0] is ThreatApplicability.applicable
            and manifest_by_id[threat_id][1]
        )
        target_control_ids = catalog_item.descriptor.expected_detection_contract.target_control_ids
        expected_present_controls = tuple(
            control_id for control_id in target_control_ids if control_id in present_controls
        )
        for label, actual, expected in (
            ("operator_outcomes.threat_ids", outcome.threat_ids, expected_threat_ids),
            (
                "operator_outcomes.unscoped_catalog_threat_ids",
                outcome.unscoped_catalog_threat_ids,
                expected_unscoped_ids,
            ),
            (
                "operator_outcomes.critical_threat_ids",
                outcome.critical_threat_ids,
                expected_critical_ids,
            ),
            (
                "operator_outcomes.present_target_control_ids",
                outcome.present_target_control_ids,
                expected_present_controls,
            ),
        ):
            if actual != expected and label not in mismatches:
                mismatches.append(label)
    return tuple(mismatches)


def _verifier_policy_message(policy: VerifierEfficacyPolicy | None) -> str:
    if policy is None:
        return ""
    return (
        f"; verifier_profile={policy.profile.profile_id} "
        f"verifier_policy_sha256={policy.source_sha256}"
        + (
            ""
            if policy.scope_source_sha256 is None
            else f" verifier_scope_sha256={policy.scope_source_sha256}"
        )
    )


def gate_control_efficacy_report(
    report: ControlEfficacyReport,
    *,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
    verifier_policy: VerifierEfficacyPolicy | None = None,
    strict_efficacy: bool = True,
    require_efficacy: bool = False,
) -> GateDecision:
    """Gate a report using verifier-owned policy when strict verification is requested."""
    efficacy_required = require_efficacy or verifier_policy is not None
    if verifier_policy is None and strict_efficacy:
        return _missing_verifier_policy_decision(
            report.artifact_kind,
            required=efficacy_required,
        )
    if verifier_policy is not None:
        if strict_efficacy and (
            verifier_policy.expected_catalog is None
            or verifier_policy.expected_threat_scope is None
        ):
            return _missing_verifier_threat_scope_decision(
                report.artifact_kind,
                required=efficacy_required,
            )
        binding_error = _verifier_policy_binding_decision(
            report,
            verifier_policy,
            artifact_kind=report.artifact_kind,
            strict_efficacy=strict_efficacy,
            required=efficacy_required,
        )
        if binding_error is not None:
            return binding_error
        profile = verifier_policy.profile
    elif not report.required_operator_ids:
        return _efficacy_gate_decision(
            exit_code=2,
            outcome=GateOutcome.invalid,
            message=("ci gate invalid: control-efficacy-report has no required operator scope"),
            evidence=EfficacyEvidenceState.present,
            verification=_efficacy_mode(strict_efficacy),
            required=efficacy_required,
            artifact_kind=report.artifact_kind,
        )
    else:
        profile = ControlEfficacyGateProfile(
            required_catalog=report.catalog_id,
            required_operators=report.required_operator_ids,
        )
    decision = gate_control_efficacy_decision(
        report,
        evaluate_control_efficacy_gate(report, profile),
        profile=profile,
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
        strict_efficacy=strict_efficacy,
        efficacy_required=efficacy_required,
    )
    if verifier_policy is None:
        return decision
    return GateDecision(
        exit_code=decision.exit_code,
        outcome=decision.outcome,
        message=f"{decision.message}{_verifier_policy_message(verifier_policy)}",
        reason_code=decision.reason_code,
        artifact_kind=decision.artifact_kind,
        efficacy_evidence=decision.efficacy_evidence,
        efficacy_verification=decision.efficacy_verification,
        efficacy_required=decision.efficacy_required,
    )


def gate_control_efficacy_decision(
    report: ControlEfficacyReport,
    decision: ControlEfficacyGateDecision,
    *,
    profile: ControlEfficacyGateProfile,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
    strict_efficacy: bool = False,
    verification_mode: EfficacyVerificationMode | None = None,
    efficacy_required: bool = False,
) -> GateDecision:
    resolved_verification = verification_mode or _efficacy_mode(strict_efficacy)
    try:
        report = ControlEfficacyReport.model_validate(report.model_dump(mode="json"))
        profile = ControlEfficacyGateProfile.model_validate(profile.model_dump(mode="json"))
        decision = ControlEfficacyGateDecision.model_validate(decision.model_dump(mode="json"))
        expected_decision = evaluate_control_efficacy_gate(report, profile)
    except (TypeError, ValueError):
        return _efficacy_gate_decision(
            exit_code=2,
            outcome=GateOutcome.invalid,
            message=(
                "ci gate invalid: control-efficacy report, profile, or decision "
                "could not be validated"
            ),
            evidence=EfficacyEvidenceState.present,
            verification=resolved_verification,
            required=efficacy_required,
            artifact_kind=report.artifact_kind,
        )
    observation = _efficacy_observation(report)
    if decision != expected_decision:
        return _efficacy_gate_decision(
            exit_code=2,
            outcome=GateOutcome.invalid,
            message=(
                "ci gate invalid: control-efficacy decision does not exactly match "
                f"the report and profile; {observation}"
            ),
            evidence=EfficacyEvidenceState.present,
            verification=resolved_verification,
            required=efficacy_required,
            artifact_kind=report.artifact_kind,
        )
    controlling_finding = _controlling_efficacy_finding(decision)
    if decision.state is GateState.fail:
        return _efficacy_gate_decision(
            exit_code=1,
            outcome=GateOutcome.fail,
            message=(
                f"ci gate fail: control-efficacy-report {report.report_digest} gate_state=fail"
                f" {observation}"
            ),
            evidence=EfficacyEvidenceState.present,
            verification=resolved_verification,
            required=efficacy_required,
            reason_code=(
                controlling_finding.reason_code if controlling_finding is not None else None
            ),
            artifact_kind=report.artifact_kind,
        )
    strict_failures = _strict_efficacy_failures(report, decision)
    if strict_efficacy and strict_failures:
        strict_finding = controlling_finding or next(iter(decision.findings), None)
        return _efficacy_gate_decision(
            exit_code=1,
            outcome=GateOutcome.fail,
            message=(
                "ci gate fail: control-efficacy-report "
                f"{report.report_digest} strict_efficacy="
                f"{','.join(strict_failures)} {observation}"
            ),
            evidence=EfficacyEvidenceState.present,
            verification=resolved_verification,
            required=efficacy_required,
            reason_code=(strict_finding.reason_code if strict_finding is not None else None),
            artifact_kind=report.artifact_kind,
        )
    if decision.state is GateState.warn and fail_on_warn:
        return _efficacy_gate_decision(
            exit_code=1,
            outcome=GateOutcome.fail,
            message=(
                f"ci gate fail: control-efficacy-report {report.report_digest} gate_state=warn"
                f" {observation}"
            ),
            evidence=EfficacyEvidenceState.present,
            verification=resolved_verification,
            required=efficacy_required,
            reason_code=(
                controlling_finding.reason_code if controlling_finding is not None else None
            ),
            artifact_kind=report.artifact_kind,
        )
    not_evaluated_dimensions = tuple(
        dimension
        for dimension, is_not_evaluated in (
            (
                "semantic_state",
                report.semantic_state is ControlEfficacySemanticState.not_evaluated,
            ),
            (
                "threat_scope_state",
                report.threat_scope_state is ThreatScopeSemanticState.not_evaluated,
            ),
        )
        if is_not_evaluated
    )
    if fail_on_not_evaluated and not_evaluated_dimensions:
        not_evaluated_finding = next(
            (
                finding
                for finding in decision.findings
                if finding.reason_code is ControlEfficacyGateReason.required_operator_not_evaluated
            ),
            None,
        )
        return _efficacy_gate_decision(
            exit_code=1,
            outcome=GateOutcome.fail,
            message=(
                "ci gate fail: control-efficacy-report "
                f"{report.report_digest} has strict not-evaluated dimension(s)="
                f"{','.join(not_evaluated_dimensions)} {observation}"
            ),
            evidence=EfficacyEvidenceState.present,
            verification=resolved_verification,
            required=efficacy_required,
            reason_code=(
                not_evaluated_finding.reason_code if not_evaluated_finding is not None else None
            ),
            artifact_kind=report.artifact_kind,
        )
    return _efficacy_gate_decision(
        exit_code=0,
        outcome=(GateOutcome.review if decision.state is GateState.warn else GateOutcome.pass_),
        message=(
            "ci gate "
            f"{'review' if decision.state is GateState.warn else 'pass'}: "
            f"control-efficacy-report {report.report_digest} "
            f"gate_state={decision.state.value} {observation}"
        ),
        evidence=EfficacyEvidenceState.present,
        verification=resolved_verification,
        required=efficacy_required,
        reason_code=(
            controlling_finding.reason_code
            if decision.state is GateState.warn and controlling_finding is not None
            else None
        ),
        artifact_kind=report.artifact_kind,
    )


def _strict_efficacy_failures(
    report: ControlEfficacyReport,
    decision: ControlEfficacyGateDecision,
) -> tuple[str, ...]:
    failures: list[str] = []
    if decision.state is not GateState.pass_:
        failures.append(f"gate_state:{decision.state.value}")
    if report.semantic_state is not ControlEfficacySemanticState.all_evaluated_applicable_caught:
        failures.append(f"semantic_state:{report.semantic_state.value}")
    if report.threat_scope_state is not ThreatScopeSemanticState.all_applicable_challenged:
        failures.append(f"threat_scope_state:{report.threat_scope_state.value}")
    if report.required_not_evaluated_operator_ids:
        failures.append("required_operator_not_evaluated")
    if report.invalid_or_error_operator_ids:
        failures.append("invalid_or_error_operator")
    return tuple(failures)


def _controlling_efficacy_finding(
    decision: ControlEfficacyGateDecision,
) -> ControlEfficacyGateFinding | None:
    controlling_effect = {
        GateState.fail: GateEffect.block,
        GateState.warn: GateEffect.review,
    }.get(decision.state)
    if controlling_effect is None:
        return None
    return next(
        (finding for finding in decision.findings if finding.effect == controlling_effect),
        None,
    )


def _efficacy_observation(report: ControlEfficacyReport) -> str:
    return (
        f"semantic_state={report.semantic_state.value} "
        f"threat_scope_state={report.threat_scope_state.value} "
        f"required_survivors={report.required_survivor_count} "
        f"critical_survivors={report.critical_survivor_count} "
        f"unscoped_catalog_threats={report.unscoped_catalog_threat_count}"
    )


def run_ci(
    candidate_runset_path: Path,
    *,
    suite_path: Path,
    out_dir: Path,
    baseline_runset_path: Path | None = None,
    report_mode: ReportMode = "full",
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
    waivers: tuple[Waiver, ...] = (),
    today: date | None = None,
    project_root: Path | None = None,
    source_input_paths: tuple[Path, ...] = (),
) -> CiRunResult:
    _ensure_ci_output_directory_safe(out_dir)
    input_paths = tuple(
        path
        for path in (
            suite_path,
            candidate_runset_path,
            baseline_runset_path,
            *source_input_paths,
        )
        if path is not None
    )
    _ensure_ci_inputs_do_not_alias_outputs(input_paths, out_dir)
    ensure_unlinked_directory(out_dir)
    _remove_previous_ci_outputs(out_dir)
    source_root = (
        project_root.resolve()
        if project_root is not None
        else source_project_root(
            tuple(
                path
                for path in (
                    suite_path,
                    candidate_runset_path,
                    baseline_runset_path,
                )
                if path is not None
            ),
            default_root=Path.cwd(),
        )
    )
    artifact_root = artifact_project_root(
        tuple(
            path
            for path in (
                suite_path,
                candidate_runset_path,
                baseline_runset_path,
                out_dir,
            )
            if path is not None
        ),
        default_root=source_root,
    )
    environment = environment_with_dependency_inventory(
        source_root,
        out_dir,
        artifact_root=artifact_root,
    )
    suite = load_compiled_suite(suite_path)
    candidate = _load_runset(candidate_runset_path)
    candidate_report = attach_evaluation_environment(
        evaluate_runset(
            suite,
            candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=today or date.today(),
        ),
        environment,
    )
    if report_mode == "fail-fast":
        candidate_report = _fail_fast_evaluation_report(candidate_report)
    report_paths = list(_write_evaluation_outputs(candidate_report, out_dir))
    decision = gate_evaluation_summary(candidate_report.candidate_vs_expectations)
    comparison_summary: ComparisonSummary | None = None
    comparison_paths: tuple[Path, ...] = ()

    if not (report_mode == "fail-fast" and decision.exit_code) and baseline_runset_path is not None:
        baseline = _load_runset(baseline_runset_path)
        comparison_report = _compare_for_ci(
            suite=suite,
            baseline=baseline,
            candidate=candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=today or date.today(),
        )
        comparison_report = attach_comparison_environment(comparison_report, environment)
        comparison_paths = _write_comparison_outputs(comparison_report, out_dir)
        report_paths.extend(comparison_paths)
        comparison_summary = comparison_report.comparison_summary
        decision = gate_comparison_summary(comparison_summary)

    try:
        packet_path, packet_markdown_path, graph_path, manifest_path = _write_ci_packet(
            out_dir=out_dir,
            environment=environment,
            evaluation_summary_path=out_dir / "evaluation-summary.json",
            comparison_summary_path=(
                (out_dir / "comparison-summary.json") if comparison_paths else None
            ),
            expected_evaluation_summary=candidate_report.candidate_vs_expectations,
            expected_comparison_summary=comparison_summary,
            suite_path=suite_path,
            candidate_runset_path=candidate_runset_path,
            baseline_runset_path=baseline_runset_path,
            project_root=artifact_root,
        )
    except _CiPacketBindingError as exc:
        packet_path = out_dir / "evidence-packet.json"
        report_paths.append(out_dir / "dependency-inventory.json")
        decision = GateDecision(
            exit_code=2,
            outcome=GateOutcome.invalid,
            message=f"ci gate invalid: {exc}",
            reason_code=ReasonCode.POLICY_FAILED,
            artifact_kind="evidence-packet",
        )
        binding_diagnostics_path = out_dir / "ci-diagnostics.json"
        write_diagnostics(
            decision,
            binding_diagnostics_path,
            report_paths=tuple(report_paths),
        )
        return CiRunResult(
            decision=decision,
            report_paths=tuple((*report_paths, binding_diagnostics_path)),
            packet_path=packet_path,
            diagnostics_path=binding_diagnostics_path,
        )
    packet_decision = gate_evidence_packet(
        load_evidence_packet(packet_path),
        artifact_root=artifact_root,
    )
    if packet_decision.outcome is GateOutcome.invalid or (
        decision.exit_code == 0 and packet_decision.exit_code != 0
    ):
        decision = packet_decision
    report_paths.extend(
        (
            packet_path,
            packet_markdown_path,
            graph_path,
            manifest_path,
            out_dir / "dependency-inventory.json",
        )
    )
    diagnostics_path = None
    if decision.exit_code:
        reason_code = decision.reason_code
        if reason_code is ReasonCode.POLICY_FAILED and candidate_report.failed_controls:
            reason_code = candidate_report.failed_controls[0].reason_code
        diagnostics_path = out_dir / "ci-diagnostics.json"
        decision = GateDecision(
            exit_code=decision.exit_code,
            outcome=decision.outcome,
            message=decision.message,
            reason_code=reason_code,
            artifact_kind=decision.artifact_kind,
            artifact_path=str(packet_path),
            validator=decision.validator,
        )
        write_diagnostics(decision, diagnostics_path, report_paths=tuple(report_paths))
    return CiRunResult(
        decision=decision,
        report_paths=tuple(report_paths),
        packet_path=packet_path,
        diagnostics_path=diagnostics_path,
    )


def _remove_previous_ci_outputs(out_dir: Path) -> None:
    for filename in _CI_OUTPUT_FILENAMES:
        unlink_file_if_exists(out_dir / filename)


def _ensure_ci_output_directory_safe(out_dir: Path) -> None:
    try:
        resolved = out_dir.resolve(strict=False)
    except RuntimeError as exc:
        raise ValueError("CI output directory cannot be safely resolved") from exc
    if resolved == Path(resolved.anchor):
        raise ValueError("CI output directory must not be a filesystem root")


def _ensure_ci_inputs_do_not_alias_outputs(
    input_paths: tuple[Path, ...],
    out_dir: Path,
) -> None:
    for input_path in input_paths:
        input_identity = _resolved_path_identity(input_path, strict=True)
        for filename in _CI_OUTPUT_FILENAMES:
            output_path = out_dir / filename
            if input_identity == _resolved_path_identity(output_path, strict=False) or _same_file(
                input_path, output_path
            ):
                raise ValueError("CI input aliases an owned output path")


def _same_file(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except (OSError, ValueError):
        return False


def _resolved_path_identity(path: Path, *, strict: bool) -> str:
    try:
        resolved = path.resolve(strict=strict)
    except RuntimeError as exc:
        raise ValueError("CI artifact path cannot be safely resolved") from exc
    return os.path.normcase(os.path.abspath(resolved))


def write_diagnostics(
    decision: GateDecision,
    path: Path,
    *,
    report_paths: tuple[Path, ...] = (),
) -> None:
    payload = decision.model_dump()
    payload["report_paths"] = [str(report_path) for report_path in report_paths]
    write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _decision_for_state(
    state: GateState,
    *,
    subject: str,
    fail_on_warn: bool,
    fail_on_not_evaluated: bool,
) -> GateDecision:
    if state is GateState.fail:
        return GateDecision(
            exit_code=1,
            outcome=GateOutcome.fail,
            message=f"ci gate fail: {subject} state=fail",
        )
    if state is GateState.warn:
        if fail_on_warn:
            return GateDecision(
                exit_code=1,
                outcome=GateOutcome.fail,
                message=f"ci gate fail: {subject} state=warn",
            )
        return GateDecision(
            exit_code=0,
            outcome=GateOutcome.review,
            message=f"ci gate review: {subject} state=warn",
        )
    if state is GateState.not_evaluated:
        if fail_on_not_evaluated:
            return GateDecision(
                exit_code=1,
                outcome=GateOutcome.fail,
                message=f"ci gate fail: {subject} state=not_evaluated",
            )
        return GateDecision(
            exit_code=0,
            outcome=GateOutcome.not_evaluated,
            message=f"ci gate not-evaluated: {subject} state=not_evaluated",
        )
    return GateDecision(
        exit_code=0,
        outcome=GateOutcome.pass_,
        message=f"ci gate pass: {subject} state={state.value}",
    )


def _load_runset(path: Path) -> RunSet:
    return project_validated_artifact_payload(
        load_validated_artifact_payload(path, "run-set", label="RunSet JSON"),
        RunSet,
        kind="run-set",
    )


def _compare_for_ci(
    *,
    suite: CompiledSuite,
    baseline: RunSet,
    candidate: RunSet,
    gate_profile: GateProfile,
    waivers: tuple[Waiver, ...],
    today: date,
) -> ComparisonReport:
    try:
        return compare_runsets(
            suite,
            baseline,
            candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=today,
        )
    except InvalidComparisonError as exc:
        if exc.report is None:
            raise
        return exc.report


def _fail_fast_evaluation_report(
    report: EvaluationReport,
) -> EvaluationReport:
    first = next((finding for finding in report.failed_controls), None)
    if first is None:
        return report
    summary = report.candidate_vs_expectations.model_copy(update={"findings": (first,)})
    return report.model_copy(
        update={
            "candidate_vs_expectations": summary,
            "failed_controls": (first,),
            "warning_controls": (),
        }
    )


def _write_evaluation_outputs(report: EvaluationReport, out_dir: Path) -> tuple[Path, ...]:
    report_json, summary_json = write_evaluation_json(report, out_dir)
    report_md = write_evaluation_markdown(report, out_dir)
    return report_json, summary_json, report_md


def _write_comparison_outputs(report: ComparisonReport, out_dir: Path) -> tuple[Path, ...]:
    report_json, summary_json = write_comparison_json(report, out_dir)
    report_md = write_comparison_markdown(report, out_dir)
    return report_json, summary_json, report_md


def _write_ci_packet(
    *,
    out_dir: Path,
    environment: EnvironmentInfo,
    evaluation_summary_path: Path,
    comparison_summary_path: Path | None,
    expected_evaluation_summary: EvaluationSummary,
    expected_comparison_summary: ComparisonSummary | None,
    suite_path: Path,
    candidate_runset_path: Path,
    baseline_runset_path: Path | None,
    project_root: Path,
) -> tuple[Path, Path, Path, Path]:
    evaluation_snapshot = load_evaluation_summary_snapshot(
        evaluation_summary_path,
        root=project_root,
        artifact_root=project_root,
    )
    comparison_snapshot = (
        load_comparison_summary_snapshot(
            comparison_summary_path,
            root=project_root,
            artifact_root=project_root,
        )
        if comparison_summary_path is not None
        else None
    )
    if evaluation_snapshot.summary != expected_evaluation_summary:
        raise ValueError("evaluation summary changed before packet snapshot")
    if (comparison_snapshot is None) is not (expected_comparison_summary is None):
        raise ValueError("comparison summary path and expected model must be present together")
    if (
        comparison_snapshot is not None
        and comparison_snapshot.summary != expected_comparison_summary
    ):
        raise ValueError("comparison summary changed before packet snapshot")
    packet_limitations = DEFAULT_PACKET_LIMITATIONS
    evidence_graph = build_privacy_filtered_evidence_graph(
        evaluation_snapshot.summary,
        comparison=(comparison_snapshot.summary if comparison_snapshot is not None else None),
        limitations=packet_limitations,
    )
    graph_path = out_dir / "assurance-evidence-graph.json"
    manifest_path = out_dir / "release-artifact-manifest.json"
    packet_path = out_dir / "evidence-packet.json"
    packet_markdown_path = out_dir / "evidence-packet.md"
    rollback = OutputPublicationRollback.capture(
        (graph_path, manifest_path, packet_path, packet_markdown_path),
        max_bytes=_MAX_CI_PACKET_ROLLBACK_BYTES,
        label="CI packet output",
        path_resolution_error="CI artifact path cannot be safely resolved",
        concurrent_change_error=(
            "CI packet output changed concurrently; refusing rollback overwrite"
        ),
    )
    try:
        write_evidence_graph(evidence_graph, graph_path)
        rollback.mark_written(graph_path)
        graph_snapshot = load_evidence_graph_snapshot(
            graph_path,
            root=project_root,
            artifact_root=project_root,
        )
        artifact_paths = [
            release_artifact("compiled-suite", suite_path, project_root=project_root),
            release_artifact("candidate-runset", candidate_runset_path, project_root=project_root),
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
                out_dir / "dependency-inventory.json",
                project_root=project_root,
            ),
        ]
        packet_digests = [
            packet_artifact_digest_from_snapshot(
                "evaluation-summary",
                evaluation_snapshot,
            ),
            packet_artifact_digest_from_snapshot(
                "assurance-evidence-graph",
                graph_snapshot,
            ),
        ]
        if baseline_runset_path is not None:
            artifact_paths.append(
                release_artifact(
                    "baseline-runset",
                    baseline_runset_path,
                    project_root=project_root,
                )
            )
        if comparison_snapshot is not None:
            artifact_paths.append(
                release_artifact_from_summary_snapshot(
                    "comparison-summary",
                    comparison_snapshot,
                )
            )
            packet_digests.append(
                packet_artifact_digest_from_snapshot(
                    "comparison-summary",
                    comparison_snapshot,
                )
            )
        manifest = build_release_manifest(tuple(artifact_paths), environment=environment)
        packet = build_evidence_packet(
            evaluation_snapshot.summary,
            comparison=(comparison_snapshot.summary if comparison_snapshot is not None else None),
            environment=environment,
            release_manifest=manifest,
            evidence_graph_digest=evidence_graph.graph_digest,
            artifact_digests=tuple(packet_digests),
            limitations=packet_limitations,
        )
        binding_error = packet_summary_files_binding_error_for_trusted_publication(
            packet,
            artifact_root=project_root,
            expected_graph=evidence_graph,
        )
        if binding_error is not None:
            raise _CiPacketBindingError(binding_error)
        write_release_manifest(manifest, manifest_path)
        rollback.mark_written(manifest_path)
        write_evidence_packet(packet, packet_path)
        rollback.mark_written(packet_path)
        write_evidence_packet_markdown(packet, packet_markdown_path)
        rollback.mark_written(packet_markdown_path)
    except BaseException:
        try:
            rollback.restore()
        except BaseException as rollback_exc:
            raise ValueError(
                "CI packet publication failed and prior outputs could not be restored"
            ) from rollback_exc
        raise
    return packet_path, packet_markdown_path, graph_path, manifest_path
