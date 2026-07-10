from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex, coerce_enum, coerce_tuple


class ControlFramework(StrEnum):
    nist_ai_rmf = "nist-ai-rmf"
    owasp_llm_top_10_2025 = "owasp-llm-top-10-2025"
    iso_iec_42001 = "iso-iec-42001"
    mitre_atlas_2026_06 = "mitre-atlas-2026-06"


class ControlCoverageState(StrEnum):
    observed = "observed"
    partially_observed = "partially_observed"
    conditionally_observed = "conditionally_observed"
    contradictory_evidence_observed = "contradictory_evidence_observed"
    not_observed = "not_observed"
    not_evaluated = "not_evaluated"
    not_applicable = "not_applicable"
    out_of_scope = "out_of_scope"


class ControlMappingStrength(StrEnum):
    direct = "direct"
    partial = "partial"
    adjacent = "adjacent"
    gap = "gap"
    not_applicable = "not_applicable"


class ControlEvidenceRef(PersistedArtifact):
    artifact_kind: Literal["control-evidence-ref"] = "control-evidence-ref"
    evidence_kind: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    field_path: str = Field(min_length=1)
    evidence_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    description: str = Field(min_length=1)


class ControlConditionEvaluation(PersistedArtifact):
    artifact_kind: Literal["control-condition-evaluation"] = (
        "control-condition-evaluation"
    )
    rule_id: str = Field(min_length=1)
    signal: str = Field(min_length=1)
    condition: str | None = Field(default=None, exclude_if=lambda value: value is None)
    observed: bool
    coverage_state: ControlCoverageState
    evidence_refs: tuple[ControlEvidenceRef, ...] = ()
    rationale: str = Field(min_length=1)

    @field_validator("coverage_state", mode="before")
    @classmethod
    def _coerce_coverage_state(cls, value: object) -> ControlCoverageState:
        return coerce_enum(ControlCoverageState, value)

    @field_validator("evidence_refs", mode="before")
    @classmethod
    def _coerce_evidence_refs(cls, value: object) -> object:
        return coerce_tuple(value)


class ControlCoverageItem(PersistedArtifact):
    artifact_kind: Literal["control-coverage-item"] = "control-coverage-item"
    control_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    coverage_state: ControlCoverageState
    mapping_strength: ControlMappingStrength | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    atlas_tactic_ids: tuple[str, ...] = ()
    atlas_technique_ids: tuple[str, ...] = ()
    evidence_refs: tuple[ControlEvidenceRef, ...] = ()
    condition_evaluations: tuple[ControlConditionEvaluation, ...] = ()
    limitations: tuple[str, ...] = ()

    @field_validator("coverage_state", mode="before")
    @classmethod
    def _coerce_coverage_state(cls, value: object) -> ControlCoverageState:
        return coerce_enum(ControlCoverageState, value)

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
        "evidence_refs",
        "condition_evaluations",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class ControlCoverageReport(PersistedArtifact):
    artifact_kind: Literal["control-coverage-report"] = "control-coverage-report"
    report_id: str = Field(min_length=1)
    framework: ControlFramework
    framework_version: str = Field(min_length=1)
    mapping_version: str = Field(min_length=1)
    mapping_digest: DigestHex
    evidence_packet_id: str = Field(min_length=1)
    evidence_packet_digest: DigestHex
    coverage_state_counts: dict[str, int]
    items: tuple[ControlCoverageItem, ...]
    limitations: tuple[str, ...]

    @field_validator("framework", mode="before")
    @classmethod
    def _coerce_framework(cls, value: object) -> ControlFramework:
        return coerce_enum(ControlFramework, value)

    @field_validator("items", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)
