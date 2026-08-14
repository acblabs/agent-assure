from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact
from agent_assure.schema.common import DigestHex, coerce_tuple
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    derive_control_efficacy_gate_decision,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.release import ReleaseArtifactManifest
from agent_assure.schema.usage import (
    UsageSummary,
    UsageSummaryDelta,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)

PacketArtifactRole = Literal[
    "evaluation-summary",
    "comparison-summary",
    "control-efficacy-onboarding-config",
    "control-efficacy-gate-profile",
    "control-efficacy-report",
]
_EVIDENCE_PACKET_USAGE_FIELD_PATHS = (
    ("usage_summary",),
    ("evaluation", "usage_summary"),
    ("comparison", "baseline_usage_summary"),
    ("comparison", "candidate_usage_summary"),
    ("comparison", "usage_delta"),
)
_CONTROL_EFFICACY_PACKET_FIELDS = (
    "control_efficacy",
    "control_efficacy_gate_profile",
    "control_efficacy_gate",
)
_CONTROL_EFFICACY_CONFIG_DIGEST_ROLES = (
    "control-efficacy-onboarding-config",
    "control-efficacy-gate-profile",
)
_CONTROL_EFFICACY_DIGEST_ROLES = (
    "control-efficacy-report",
    *_CONTROL_EFFICACY_CONFIG_DIGEST_ROLES,
)
_EXACT_PACKET_SCHEMA_VERSION_COHERENCE = frozenset({"0.6.1", "0.6.2"})
_USAGE_ARTIFACT_SCHEMA_VERSION = "0.4.3"


def _evidence_packet_json_schema_extra() -> dict[str, Any]:
    schema = usage_container_json_schema_extra(*_EVIDENCE_PACKET_USAGE_FIELD_PATHS)
    efficacy_present = {
        "anyOf": [
            {
                "required": [field_name],
                "properties": {field_name: {"not": {"type": "null"}}},
            }
            for field_name in _CONTROL_EFFICACY_PACKET_FIELDS
        ]
    }
    exact_report_digest_constraint = {
        "contains": {
            "type": "object",
            "required": ["role"],
            "properties": {"role": {"const": "control-efficacy-report"}},
        },
        "minContains": 1,
        "maxContains": 1,
    }
    exact_typed_config_digest_constraint = {
        "contains": {
            "type": "object",
            "required": ["role"],
            "properties": {"role": {"enum": list(_CONTROL_EFFICACY_CONFIG_DIGEST_ROLES)}},
        },
        "minContains": 1,
        "maxContains": 1,
    }
    schema["allOf"].append(
        {
            "if": efficacy_present,
            "then": {
                "required": [*_CONTROL_EFFICACY_PACKET_FIELDS, "artifact_digests"],
                "properties": {
                    **{
                        field_name: {"not": {"type": "null"}}
                        for field_name in _CONTROL_EFFICACY_PACKET_FIELDS
                    },
                    "artifact_digests": {
                        "allOf": [
                            exact_report_digest_constraint,
                            exact_typed_config_digest_constraint,
                        ]
                    },
                },
            },
            "else": {
                "properties": {
                    "artifact_digests": {
                        "not": {
                            "contains": {
                                "type": "object",
                                "required": ["role"],
                                "properties": {
                                    "role": {"enum": list(_CONTROL_EFFICACY_DIGEST_ROLES)}
                                },
                            }
                        }
                    }
                }
            },
        }
    )
    return schema


class PacketArtifactDigest(PersistedArtifact):
    artifact_kind: Literal["packet-artifact-digest"] = "packet-artifact-digest"
    role: PacketArtifactRole
    sha256: DigestHex


class EvidencePacket(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_evidence_packet_json_schema_extra())

    artifact_kind: Literal["evidence-packet"] = "evidence-packet"
    packet_id: str
    interpretation: tuple[str, ...]
    evaluation: EvaluationSummary
    comparison: ComparisonSummary | None = None
    control_efficacy: ControlEfficacyReport | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    control_efficacy_gate_profile: ControlEfficacyGateProfile | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    control_efficacy_gate: ControlEfficacyGateDecision | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    environment: EnvironmentInfo | None = None
    release_manifest: ReleaseArtifactManifest | None = None
    usage_summary: UsageSummary | None = Field(default=None, exclude_if=lambda value: value is None)
    artifact_digests: tuple[PacketArtifactDigest, ...] = ()
    limitations: tuple[str, ...]

    @field_validator("interpretation", "artifact_digests", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_nested_artifact_schema_versions(self) -> EvidencePacket:
        """Keep packet model validation aligned with versioned writer schemas.

        The v0.6.1 and later packet schemas pin every nested persisted artifact
        to the packet version, except the independently versioned usage artifacts,
        which remain pinned to v0.4.3. Enforcing the same relationship here keeps
        current packet construction from accepting a legacy summary that the
        packet writer schema would subsequently reject.
        """
        if self.schema_version not in _EXACT_PACKET_SCHEMA_VERSION_COHERENCE:
            return self
        for path, artifact in _iter_nested_persisted_artifacts(self):
            expected_version = (
                _USAGE_ARTIFACT_SCHEMA_VERSION
                if isinstance(artifact, UsageSummary | UsageSummaryDelta)
                else self.schema_version
            )
            if artifact.schema_version != expected_version:
                raise ValueError(
                    f"evidence packet schema_version {self.schema_version!r} requires "
                    f"{path}.schema_version {expected_version!r}; received "
                    f"{artifact.schema_version!r}"
                )
        return self

    @model_validator(mode="after")
    def _validate_summary_digest_roles(self) -> EvidencePacket:
        error = packet_summary_digest_binding_error(self)
        if error is not None:
            raise ValueError(error)
        return self

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> EvidencePacket:
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="evidence packet",
            root=self,
            field_paths=_EVIDENCE_PACKET_USAGE_FIELD_PATHS,
        )
        if self.comparison is not None:
            if self.evaluation.runset_id != self.comparison.candidate_runset_id:
                raise ValueError(
                    "packet.evaluation.runset_id must match packet.comparison.candidate_runset_id"
                )
            evaluation_profile = (
                self.evaluation.privacy_profile_id,
                self.evaluation.privacy_profile_digest,
            )
            comparison_profile = (
                self.comparison.privacy_profile_id,
                self.comparison.privacy_profile_digest,
            )
            if evaluation_profile != comparison_profile:
                raise ValueError(
                    "evidence packet evaluation and comparison must use the same "
                    "privacy detector profile"
                )
        efficacy_digests = tuple(
            item for item in self.artifact_digests if item.role == "control-efficacy-report"
        )
        efficacy_config_digests = tuple(
            item
            for item in self.artifact_digests
            if item.role in _CONTROL_EFFICACY_CONFIG_DIGEST_ROLES
        )
        efficacy_members = (
            self.control_efficacy,
            self.control_efficacy_gate_profile,
            self.control_efficacy_gate,
        )
        if any(item is None for item in efficacy_members) and any(
            item is not None for item in efficacy_members
        ):
            raise ValueError(
                "evidence packet control efficacy report, gate profile, and gate decision "
                "must be present together"
            )
        if self.control_efficacy is None:
            if efficacy_digests:
                raise ValueError("control-efficacy artifact digest requires a nested report")
            if efficacy_config_digests:
                raise ValueError(
                    "control-efficacy config digest requires a nested report and gate profile"
                )
        else:
            if len(efficacy_digests) != 1:
                raise ValueError("nested control efficacy requires exactly one artifact digest")
            if len(efficacy_config_digests) != 1:
                raise ValueError(
                    "nested control efficacy requires exactly one config artifact digest "
                    "with a typed role"
                )
            if self.control_efficacy_gate_profile is None or self.control_efficacy_gate is None:
                raise ValueError(
                    "nested control efficacy requires a gate profile and gate decision"
                )
            expected_decision = derive_control_efficacy_gate_decision(
                self.control_efficacy,
                self.control_efficacy_gate_profile,
            )
            if self.control_efficacy_gate != expected_decision:
                raise ValueError(
                    "control efficacy gate decision must exactly match the nested "
                    "report and gate profile"
                )
        return self


def packet_summary_digest_binding_error(packet: EvidencePacket) -> str | None:
    """Return an exact-file summary-digest binding error for current packets."""
    if packet.schema_version != SCHEMA_VERSION:
        return None
    expected_comparison_count = int(packet.comparison is not None)
    packet_by_role = {
        role: tuple(item for item in packet.artifact_digests if item.role == role)
        for role in ("evaluation-summary", "comparison-summary")
    }
    if len(packet_by_role["evaluation-summary"]) != 1:
        return "current evidence packets require exactly one evaluation-summary digest"
    if len(packet_by_role["comparison-summary"]) != expected_comparison_count:
        return "current evidence packet comparison-summary digest must match nested comparison"
    if packet.release_manifest is None:
        return None
    manifest_by_role = {
        role: tuple(item for item in packet.release_manifest.artifacts if item.role == role)
        for role in ("evaluation-summary", "comparison-summary")
    }
    if len(manifest_by_role["evaluation-summary"]) != 1:
        return (
            "current evidence packet release manifest requires exactly one "
            "evaluation-summary artifact"
        )
    if len(manifest_by_role["comparison-summary"]) != expected_comparison_count:
        return (
            "current evidence packet release manifest comparison-summary artifact "
            "must match nested comparison"
        )
    for role in ("evaluation-summary", "comparison-summary"):
        if not packet_by_role[role]:
            continue
        if packet_by_role[role][0].sha256 != manifest_by_role[role][0].sha256:
            return f"current evidence packet {role} digest must match release manifest"
    return None


def _iter_nested_persisted_artifacts(
    packet: EvidencePacket,
) -> Iterator[tuple[str, PersistedArtifact]]:
    """Yield persisted descendants with stable, actionable model paths."""
    for field_name in type(packet).model_fields:
        yield from _iter_persisted_artifacts(getattr(packet, field_name), path=field_name)


def _iter_persisted_artifacts(
    value: object,
    *,
    path: str,
) -> Iterator[tuple[str, PersistedArtifact]]:
    if isinstance(value, PersistedArtifact):
        yield path, value
    if isinstance(value, BaseModel):
        for field_name in type(value).model_fields:
            yield from _iter_persisted_artifacts(
                getattr(value, field_name),
                path=f"{path}.{field_name}",
            )
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _iter_persisted_artifacts(item, path=f"{path}[{key!r}]")
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for index, item in enumerate(value):
            yield from _iter_persisted_artifacts(item, path=f"{path}[{index}]")
