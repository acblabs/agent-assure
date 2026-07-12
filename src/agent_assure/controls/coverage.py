from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Self
from uuid import uuid5

import yaml
from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.runner.ids import AGENT_ASSURE_NAMESPACE
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import GateState, coerce_enum, coerce_tuple
from agent_assure.schema.controls import (
    ControlConditionEvaluation,
    ControlCoverageItem,
    ControlCoverageReport,
    ControlCoverageState,
    ControlEvidenceRef,
    ControlFramework,
    ControlMappingStrength,
)
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.packet import EvidencePacket

CLAIM_BOUNDARY = (
    "This report maps observed `agent-assure` evidence to selected framework concepts "
    "for human review. It is not a compliance attestation, certification, audit "
    "opinion, legal conclusion, regulatory conclusion, or safety claim."
)
MITRE_ATLAS_BOUNDARY = (
    "MITRE ATLAS mappings are planning crosswalks only and are not adversary-emulation "
    "results, ATLAS coverage claims, validation results, endorsements, or "
    "threat-resistance claims."
)

_MAPPING_FILES: dict[ControlFramework, str] = {
    ControlFramework.nist_ai_rmf: "nist_ai_rmf.yaml",
    ControlFramework.owasp_llm_top_10_2025: "owasp_llm_top_10_2025.yaml",
    ControlFramework.iso_iec_42001: "iso_iec_42001.yaml",
    ControlFramework.mitre_atlas_2026_06: "mitre_atlas_2026_06.yaml",
}


class MappingRequirement(StrictModel):
    signal: str = Field(min_length=1)
    condition: str | None = None

    @model_validator(mode="after")
    def _validate_condition_scoped_signals(self) -> Self:
        if (
            self.signal
            in {
                "control_evaluated",
                "control_failure_observed",
                "control_warning_observed",
            }
            and self.condition is None
        ):
            raise ValueError(f"{self.signal} requires a local control condition")
        return self


class MappingRule(StrictModel):
    rule_id: str = Field(min_length=1)
    requires: tuple[MappingRequirement, ...]
    coverage_state_when_true: ControlCoverageState
    coverage_state_when_false: ControlCoverageState
    limitations: tuple[str, ...] = ()

    @field_validator("requires", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("requires")
    @classmethod
    def _requires_signals(
        cls,
        value: tuple[MappingRequirement, ...],
    ) -> tuple[MappingRequirement, ...]:
        if not value:
            raise ValueError("mapping rules require at least one packet signal")
        return value

    @field_validator("coverage_state_when_true", "coverage_state_when_false", mode="before")
    @classmethod
    def _coerce_coverage_state(cls, value: object) -> ControlCoverageState:
        return coerce_enum(ControlCoverageState, value)

    @model_validator(mode="after")
    def _validate_contradiction_path(self) -> Self:
        if (
            self.coverage_state_when_false
            is ControlCoverageState.contradictory_evidence_observed
        ):
            raise ValueError(
                "contradictory_evidence_observed must be authored on true mapping paths"
            )
        return self


class MappingControl(StrictModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    mapping_strength: ControlMappingStrength | None = None
    atlas_tactic_ids: tuple[str, ...] = ()
    atlas_technique_ids: tuple[str, ...] = ()
    evidence_rules: tuple[MappingRule, ...]
    limitations: tuple[str, ...] = ()

    @field_validator("mapping_strength", mode="before")
    @classmethod
    def _coerce_mapping_strength(
        cls,
        value: object,
    ) -> ControlMappingStrength | None:
        if value is None:
            return None
        return coerce_enum(ControlMappingStrength, value)

    @field_validator(
        "atlas_tactic_ids",
        "atlas_technique_ids",
        "evidence_rules",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class SourceReview(StrictModel):
    reviewed_on: str = Field(min_length=1)
    source_refs: tuple[str, ...]
    notes: tuple[str, ...] = ()

    @field_validator("source_refs", "notes", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class FrameworkMapping(StrictModel):
    framework: ControlFramework
    framework_version: str = Field(min_length=1)
    mapping_version: str = Field(min_length=1)
    source_review: SourceReview
    limitations: tuple[str, ...]
    controls: tuple[MappingControl, ...]

    @field_validator("framework", mode="before")
    @classmethod
    def _coerce_framework(cls, value: object) -> ControlFramework:
        return coerce_enum(ControlFramework, value)

    @field_validator("limitations", "controls", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_framework_specific_controls(self) -> Self:
        if self.framework is ControlFramework.mitre_atlas_2026_06:
            missing_strength = [
                control.id
                for control in self.controls
                if control.mapping_strength is None
            ]
            if missing_strength:
                joined = ", ".join(missing_strength)
                raise ValueError(
                    "MITRE ATLAS mappings require mapping_strength for every "
                    f"control: {joined}"
                )
        return self


@dataclass(frozen=True)
class LoadedFrameworkMapping:
    mapping: FrameworkMapping
    digest: str
    source: str


@dataclass(frozen=True)
class SignalResult:
    observed: bool
    evidence_refs: tuple[ControlEvidenceRef, ...]
    rationale: str


def build_control_coverage_report(
    packet: EvidencePacket,
    *,
    framework: ControlFramework | str,
    evidence_packet_digest: str,
) -> ControlCoverageReport:
    resolved_framework = _coerce_framework(framework)
    loaded = load_framework_mapping(resolved_framework)
    mapping = loaded.mapping
    context = _PacketContext(packet, evidence_packet_digest=evidence_packet_digest)
    items = tuple(_coverage_item(control, context) for control in mapping.controls)
    counts = Counter(item.coverage_state.value for item in items)
    limitations = _report_limitations(mapping)
    report_key = {
        "framework": mapping.framework.value,
        "framework_version": mapping.framework_version,
        "mapping_digest": loaded.digest,
        "evidence_packet_digest": evidence_packet_digest,
        "items": [
            {
                "control_id": item.control_id,
                "coverage_state": item.coverage_state.value,
            }
            for item in items
        ],
    }
    return ControlCoverageReport(
        artifact_kind="control-coverage-report",
        report_id=f"control-map-{sha256_hexdigest(report_key)[:16]}",
        framework=mapping.framework,
        framework_version=mapping.framework_version,
        mapping_version=mapping.mapping_version,
        mapping_digest=loaded.digest,
        evidence_packet_id=packet.packet_id,
        evidence_packet_digest=evidence_packet_digest,
        coverage_state_counts=dict(sorted(counts.items())),
        items=items,
        limitations=limitations,
    )


def load_framework_mapping(framework: ControlFramework | str) -> LoadedFrameworkMapping:
    resolved_framework = _coerce_framework(framework)
    filename = _MAPPING_FILES[resolved_framework]
    payload, source = _mapping_bytes(filename)
    data = yaml.safe_load(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"mapping {filename} must contain a YAML object")
    mapping = FrameworkMapping.model_validate(data)
    if mapping.framework is not resolved_framework:
        raise ValueError(
            f"mapping {filename} declares framework {mapping.framework.value!r}, "
            f"expected {resolved_framework.value!r}"
        )
    return LoadedFrameworkMapping(
        mapping=mapping,
        digest=hashlib.sha256(payload).hexdigest(),
        source=source,
    )


def _coerce_framework(value: ControlFramework | str) -> ControlFramework:
    if isinstance(value, ControlFramework):
        return value
    return ControlFramework(value)


def _mapping_bytes(filename: str) -> tuple[bytes, str]:
    resource_source = f"agent_assure/mappings/{filename}"
    try:
        resource = resources.files("agent_assure").joinpath("mappings", filename)
        return resource.read_bytes(), resource_source
    except (FileNotFoundError, ModuleNotFoundError, NotADirectoryError) as resource_exc:
        repo_path = _source_checkout_mapping_path(filename)
        if repo_path is not None:
            return repo_path.read_bytes(), str(repo_path)
        raise FileNotFoundError(f"built-in mapping file not found: {filename}") from resource_exc


def _source_checkout_mapping_path(filename: str) -> Path | None:
    try:
        repo_root = Path(__file__).resolve().parents[3]
    except IndexError:
        return None
    repo_marker = repo_root / "pyproject.toml"
    package_marker = repo_root / "src" / "agent_assure" / "__init__.py"
    mapping_path = repo_root / "mappings" / filename
    if not repo_marker.is_file() or not package_marker.is_file() or not mapping_path.is_file():
        return None
    try:
        pyproject = repo_marker.read_text(encoding="utf-8")
    except OSError:
        return None
    if 'name = "agent-assure"' not in pyproject:
        return None
    return mapping_path


def _coverage_item(
    control: MappingControl,
    context: _PacketContext,
) -> ControlCoverageItem:
    evaluations: list[ControlConditionEvaluation] = []
    limitations = list(control.limitations)
    for rule in control.evidence_rules:
        evaluation = _evaluate_rule(rule, context)
        evaluations.append(evaluation)
        limitations.extend(rule.limitations)
    state = _aggregate_state(tuple(evaluations))
    evidence_refs = _dedupe_evidence_refs(
        ref
        for evaluation in evaluations
        if evaluation.observed
        for ref in evaluation.evidence_refs
    )
    return ControlCoverageItem(
        artifact_kind="control-coverage-item",
        control_id=control.id,
        title=control.title,
        coverage_state=state,
        mapping_strength=control.mapping_strength,
        atlas_tactic_ids=control.atlas_tactic_ids,
        atlas_technique_ids=control.atlas_technique_ids,
        evidence_refs=evidence_refs,
        condition_evaluations=tuple(evaluations),
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _evaluate_rule(
    rule: MappingRule,
    context: _PacketContext,
) -> ControlConditionEvaluation:
    signal_results = tuple(context.evaluate(requirement) for requirement in rule.requires)
    observed = all(result.observed for result in signal_results)
    state = rule.coverage_state_when_true if observed else rule.coverage_state_when_false
    evidence_refs = _dedupe_evidence_refs(
        ref for result in signal_results for ref in result.evidence_refs
    )
    signal = " AND ".join(requirement.signal for requirement in rule.requires)
    condition = _format_rule_condition(rule.requires)
    rationale = (
        "All required packet signals were observed."
        if observed
        else _missing_signal_rationale(rule.requires, signal_results)
    )
    return ControlConditionEvaluation(
        artifact_kind="control-condition-evaluation",
        rule_id=rule.rule_id,
        signal=signal,
        condition=condition,
        observed=observed,
        coverage_state=state,
        evidence_refs=evidence_refs,
        rationale=rationale,
    )


def _format_requirement(requirement: MappingRequirement) -> str:
    if requirement.condition is None:
        return requirement.signal
    return f"{requirement.signal}:{requirement.condition}"


def _format_rule_condition(requirements: tuple[MappingRequirement, ...]) -> str | None:
    conditions = tuple(
        requirement.condition
        for requirement in requirements
        if requirement.condition is not None
    )
    if not conditions:
        return None
    return " AND ".join(conditions)


def _missing_signal_rationale(
    requirements: tuple[MappingRequirement, ...],
    results: tuple[SignalResult, ...],
) -> str:
    missing = [
        (requirement, result)
        for requirement, result in zip(requirements, results, strict=True)
        if not result.observed
    ]
    if not missing:
        return "Required packet signals were observed."
    missing_labels = ", ".join(
        _format_requirement(requirement)
        for requirement, _result in missing
    )
    rationales = " ".join(result.rationale for _requirement, result in missing)
    return f"Missing packet signals: {missing_labels}. {rationales}"


def _aggregate_state(
    evaluations: tuple[ControlConditionEvaluation, ...],
) -> ControlCoverageState:
    if not evaluations:
        return ControlCoverageState.not_observed
    priority = {
        ControlCoverageState.contradictory_evidence_observed: 80,
        ControlCoverageState.observed: 70,
        ControlCoverageState.conditionally_observed: 60,
        ControlCoverageState.partially_observed: 50,
        ControlCoverageState.not_evaluated: 40,
        ControlCoverageState.not_observed: 30,
        ControlCoverageState.not_applicable: 20,
        ControlCoverageState.out_of_scope: 10,
    }
    true_path_evaluations = tuple(evaluation for evaluation in evaluations if evaluation.observed)
    state_source = true_path_evaluations or evaluations
    return max((evaluation.coverage_state for evaluation in state_source), key=priority.__getitem__)


def _dedupe_evidence_refs(refs: Any) -> tuple[ControlEvidenceRef, ...]:
    deduped: list[ControlEvidenceRef] = []
    seen: set[tuple[str, str, str, str | None]] = set()
    for ref in refs:
        key = (
            ref.evidence_kind,
            ref.evidence_id,
            ref.field_path,
            ref.evidence_digest,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ref)
    return tuple(deduped)


def _report_limitations(mapping: FrameworkMapping) -> tuple[str, ...]:
    limitations = [CLAIM_BOUNDARY, *mapping.limitations]
    if mapping.framework is ControlFramework.mitre_atlas_2026_06:
        limitations.append(MITRE_ATLAS_BOUNDARY)
    return tuple(dict.fromkeys(limitations))


class _PacketContext:
    def __init__(self, packet: EvidencePacket, *, evidence_packet_digest: str) -> None:
        self.packet = packet
        self.evidence_packet_digest = evidence_packet_digest

    def evaluate(self, requirement: MappingRequirement) -> SignalResult:
        signal = requirement.signal
        condition = requirement.condition
        if signal == "evidence_packet_present":
            return self._observed_ref(
                evidence_kind="evidence-packet",
                evidence_id=self.packet.packet_id,
                field_path="$",
                digest=self.evidence_packet_digest,
                description="Evidence packet artifact was provided.",
            )
        if signal == "evidence_packet_digest_present":
            return self._observed_ref(
                evidence_kind="evidence-packet",
                evidence_id=self.packet.packet_id,
                field_path="$.sha256",
                digest=self.evidence_packet_digest,
                description="Evidence packet SHA-256 digest was computed.",
            )
        if signal == "evaluation_summary_present":
            return self._observed_ref(
                evidence_kind="evaluation-summary",
                evidence_id=self.packet.evaluation.runset_id,
                field_path="$.evaluation",
                description="Evidence packet contains an evaluation summary.",
            )
        if signal == "comparison_summary_present":
            if self.packet.comparison is None:
                return _not_observed("Evidence packet does not contain a comparison summary.")
            return self._observed_ref(
                evidence_kind="comparison-summary",
                evidence_id=self.packet.comparison.candidate_runset_id,
                field_path="$.comparison",
                description="Evidence packet contains a comparison summary.",
            )
        if signal == "artifact_digest_present":
            return self._artifact_digest(condition)
        if signal == "usage_summary_present":
            return self._usage_summary()
        if signal == "usage_delta_present":
            return self._usage_delta()
        if signal == "finding_observed":
            return self._finding(condition)
        if signal == "control_failure_observed":
            return self._control_state_finding(
                condition,
                states=(GateState.fail,),
                signal_name=signal,
            )
        if signal == "control_warning_observed":
            return self._control_state_finding(
                condition,
                states=(GateState.warn,),
                signal_name=signal,
            )
        if signal == "control_evaluated":
            return self._control_evaluated(condition)
        if signal == "evaluation_state_observed":
            return self._evaluation_state(condition)
        if signal == "comparison_classification_observed":
            return self._comparison_classification(condition)
        if signal == "scope_boundary":
            return self._scope_boundary(condition)
        raise ValueError(f"unknown mapping signal: {signal}")

    def _observed_ref(
        self,
        *,
        evidence_kind: str,
        evidence_id: str,
        field_path: str,
        description: str,
        digest: str | None = None,
    ) -> SignalResult:
        return SignalResult(
            observed=True,
            evidence_refs=(
                ControlEvidenceRef(
                    artifact_kind="control-evidence-ref",
                    evidence_kind=evidence_kind,
                    evidence_id=evidence_id,
                    field_path=field_path,
                    evidence_digest=digest,
                    description=description,
                ),
            ),
            rationale=description,
        )

    def _artifact_digest(self, role: str | None) -> SignalResult:
        if role is None:
            return _not_observed("Artifact digest rule did not name a packet artifact role.")
        digest = next(
            (artifact for artifact in self.packet.artifact_digests if artifact.role == role),
            None,
        )
        if digest is None:
            return _not_observed(f"Evidence packet has no artifact digest for role {role!r}.")
        return self._observed_ref(
            evidence_kind="packet-artifact-digest",
            evidence_id=role,
            field_path=f"$.artifact_digests[role={role}]",
            digest=digest.sha256,
            description=f"Evidence packet includes a digest for {role}.",
        )

    def _usage_summary(self) -> SignalResult:
        if self.packet.usage_summary is None:
            return _not_observed("Measured usage summary is not present in the packet.")
        return self._observed_ref(
            evidence_kind="usage-summary",
            evidence_id=self.packet.packet_id,
            field_path="$.usage_summary",
            description="Evidence packet includes measured usage summary evidence.",
        )

    def _usage_delta(self) -> SignalResult:
        if self.packet.comparison is None or self.packet.comparison.usage_delta is None:
            return _not_observed("Usage delta is not present in the packet comparison summary.")
        return self._observed_ref(
            evidence_kind="usage-summary-delta",
            evidence_id=self.packet.comparison.candidate_runset_id,
            field_path="$.comparison.usage_delta",
            description="Evidence packet includes measured usage delta evidence.",
        )

    def _finding(
        self,
        control_id: str | None,
        *,
        states: tuple[GateState, ...] | None = None,
    ) -> SignalResult:
        findings = [
            finding
            for finding in self.packet.evaluation.findings
            if (control_id is None or finding.control_id == control_id)
            and (states is None or finding.state in states)
        ]
        if not findings:
            if control_id is None:
                return _not_observed("No evaluation findings match this rule.")
            return _not_observed(f"No evaluation findings match control {control_id!r}.")
        return SignalResult(
            observed=True,
            evidence_refs=tuple(_finding_ref(finding) for finding in findings),
            rationale=f"Observed {len(findings)} matching evaluation finding(s).",
        )

    def _control_state_finding(
        self,
        control_id: str | None,
        *,
        states: tuple[GateState, ...],
        signal_name: str,
    ) -> SignalResult:
        if control_id is None:
            return _not_observed(f"{signal_name} rule did not name a local control.")
        return self._finding(control_id, states=states)

    def _control_evaluated(self, control_id: str | None) -> SignalResult:
        if control_id is None:
            return _not_observed("Control-evaluated rule did not name a local control.")
        findings = [
            finding
            for finding in self.packet.evaluation.findings
            if finding.control_id == control_id
            and finding.state is not GateState.not_evaluated
        ]
        if not findings:
            return _not_observed(
                f"No packet-resident evaluation trace names control {control_id!r}; "
                "passing controls are not inferred from summary state."
            )
        return SignalResult(
            observed=True,
            evidence_refs=tuple(_finding_ref(finding) for finding in findings),
            rationale=(
                f"Observed {len(findings)} control-specific evaluation finding(s)."
            ),
        )

    def _evaluation_state(self, state: str | None) -> SignalResult:
        if state is None:
            return _not_observed("Evaluation-state rule did not name a state.")
        if self.packet.evaluation.state.value != state:
            return _not_observed(
                f"Evaluation state is {self.packet.evaluation.state.value!r}, not {state!r}."
            )
        return self._observed_ref(
            evidence_kind="evaluation-summary",
            evidence_id=self.packet.evaluation.runset_id,
            field_path="$.evaluation.state",
            description=f"Evaluation summary state is {state}.",
        )

    def _comparison_classification(self, classification: str | None) -> SignalResult:
        if classification is None:
            return _not_observed("Comparison-classification rule did not name a state.")
        if self.packet.comparison is None:
            return _not_observed("Evidence packet does not contain a comparison summary.")
        if self.packet.comparison.classification.value != classification:
            return _not_observed(
                "Comparison classification is "
                f"{self.packet.comparison.classification.value!r}, not {classification!r}."
            )
        return self._observed_ref(
            evidence_kind="comparison-summary",
            evidence_id=self.packet.comparison.candidate_runset_id,
            field_path="$.comparison.classification",
            description=f"Comparison classification is {classification}.",
        )

    def _scope_boundary(self, boundary_id: str | None) -> SignalResult:
        evidence_id = boundary_id or self.packet.packet_id
        return self._observed_ref(
            evidence_kind="mapping-scope-boundary",
            evidence_id=evidence_id,
            field_path="$.limitations",
            description="Mapping file declares this concept outside the observed packet scope.",
        )


def _not_observed(rationale: str) -> SignalResult:
    return SignalResult(observed=False, evidence_refs=(), rationale=rationale)


def _finding_ref(finding: Finding) -> ControlEvidenceRef:
    return ControlEvidenceRef(
        artifact_kind="control-evidence-ref",
        evidence_kind="finding",
        evidence_id=finding.finding_id or _finding_id(finding),
        field_path=f"$.evaluation.findings[control_id={finding.control_id}]",
        description=(
            f"Evaluation finding for local control {finding.control_id} "
            f"with reason {finding.reason_code.value}."
        ),
    )


def _finding_id(finding: Finding) -> str:
    stable_key = (
        f"{finding.case_id}:{finding.control_id}:{finding.reason_code.value}:{finding.target}"
    )
    return f"finding-{uuid5(AGENT_ASSURE_NAMESPACE, stable_key)}"
