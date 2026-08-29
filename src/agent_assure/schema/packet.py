from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import V063_CONTRACT_SCHEMA_VERSIONS, DigestHex, coerce_tuple
from agent_assure.schema.comparison import (
    ComparisonSummary,
    comparison_evaluation_binding_error,
)
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    derive_control_efficacy_gate_decision,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.release import ReleaseArtifactManifest
from agent_assure.schema.sensitivity import RAGSensitivityReport
from agent_assure.schema.stochastic_sensitivity import (
    ArtifactDependency,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
    StochasticGateEffect,
    StochasticSensitivityState,
    SufficiencyState,
)
from agent_assure.schema.usage import (
    UsageSummary,
    UsageSummaryDelta,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)

PacketArtifactRole = Literal[
    "evaluation-summary",
    "comparison-summary",
    "assurance-evidence-graph",
    "control-efficacy-onboarding-config",
    "control-efficacy-gate-profile",
    "control-efficacy-report",
    "evidence-sensitivity-report",
    "statistical-sufficiency-report",
    "stochastic-evidence-sensitivity-report",
    "stochastic-baseline-source-runset",
    "stochastic-counterfactual-source-runset",
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
_EVIDENCE_GRAPH_ARTIFACT_ROLE: PacketArtifactRole = "assurance-evidence-graph"
_EVIDENCE_SENSITIVITY_ARTIFACT_ROLE: PacketArtifactRole = "evidence-sensitivity-report"
_STATISTICAL_SUFFICIENCY_ARTIFACT_ROLE: PacketArtifactRole = "statistical-sufficiency-report"
_STOCHASTIC_SENSITIVITY_ARTIFACT_ROLE: PacketArtifactRole = "stochastic-evidence-sensitivity-report"
_STOCHASTIC_PACKET_FIELDS = (
    "statistical_sufficiency",
    "stochastic_evidence_sensitivity",
)
_STOCHASTIC_PACKET_ARTIFACT_ROLES = (
    _STATISTICAL_SUFFICIENCY_ARTIFACT_ROLE,
    _STOCHASTIC_SENSITIVITY_ARTIFACT_ROLE,
    "stochastic-baseline-source-runset",
    "stochastic-counterfactual-source-runset",
)
_EXACT_PACKET_SCHEMA_VERSION_COHERENCE = frozenset({"0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5"})
_USAGE_ARTIFACT_SCHEMA_VERSION = "0.4.3"


def _canonical_model_digest(model: BaseModel) -> str:
    # Import lazily so schema package initialization cannot cycle through the
    # canonical layer while that layer is importing schema.common.
    from agent_assure.canonical.digests import sha256_hexdigest

    return sha256_hexdigest(model.model_dump(mode="json"))


def stochastic_packet_subject_binding_error(
    evaluation: EvaluationSummary,
    stochastic: StochasticEvidenceSensitivityReport | None,
    *,
    comparison: ComparisonSummary | None = None,
) -> str | None:
    """Return a fail-closed packet subject/configuration binding error.

    A stochastic result's dependency on its sufficiency report is necessary but
    not sufficient for packet use. The exact counterfactual source RunSet must
    also be the packet's authenticated evaluation subject, and an optional
    comparison must name both exact source RunSets. Configuration identities
    remain anchored by the predeclared protocol arm bindings.
    """
    if stochastic is None:
        return None
    sufficiency = stochastic.sufficiency_report
    source_by_arm = {item.arm_id: item for item in sufficiency.source_runsets}
    if set(source_by_arm) != {"baseline_evidence", "counterfactual_evidence"}:
        return (
            "packet-bound stochastic evidence sensitivity requires exact baseline "
            "and counterfactual source RunSet dependencies"
        )
    baseline = source_by_arm["baseline_evidence"]
    candidate = source_by_arm["counterfactual_evidence"]
    protocol = sufficiency.protocol
    if (
        baseline.execution_configuration_digest != protocol.baseline_arm.configuration_digest
        or candidate.execution_configuration_digest
        != protocol.counterfactual_arm.configuration_digest
    ):
        return (
            "stochastic source RunSet execution configurations must match the "
            "exact predeclared protocol arm configurations"
        )
    if evaluation.runset_digest is None:
        return (
            "packet-bound stochastic evidence sensitivity requires an authenticated "
            "evaluation RunSet digest"
        )
    if (evaluation.runset_id, evaluation.runset_digest) != (
        candidate.runset_id,
        candidate.runset_digest,
    ):
        return (
            "stochastic counterfactual source RunSet id and digest must match the "
            "packet evaluation subject"
        )
    if comparison is not None and (
        comparison.baseline_runset_id,
        comparison.baseline_runset_digest,
        comparison.candidate_runset_id,
        comparison.candidate_runset_digest,
    ) != (
        baseline.runset_id,
        baseline.runset_digest,
        candidate.runset_id,
        candidate.runset_digest,
    ):
        return (
            "stochastic source RunSet identities and digests must match the packet "
            "comparison baseline and candidate subjects"
        )
    return None


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
    graph_digest_present = {
        "required": ["evidence_graph_digest"],
        "properties": {"evidence_graph_digest": {"not": {"type": "null"}}},
    }
    exact_graph_digest_constraint = {
        "contains": {
            "type": "object",
            "required": ["role"],
            "properties": {"role": {"const": _EVIDENCE_GRAPH_ARTIFACT_ROLE}},
        },
        "minContains": 1,
        "maxContains": 1,
    }
    no_graph_digest_constraint = {
        "not": {
            "contains": {
                "type": "object",
                "required": ["role"],
                "properties": {"role": {"const": _EVIDENCE_GRAPH_ARTIFACT_ROLE}},
            }
        }
    }
    # JSON Schema can express graph-binding presence and cardinality, but not
    # equality between digest values selected from two independent arrays.
    # packet_summary_digest_binding_error enforces that cross-object equality.
    schema["allOf"].append(
        {
            "if": graph_digest_present,
            "then": {
                "required": ["artifact_digests"],
                "properties": {
                    "artifact_digests": exact_graph_digest_constraint,
                    "release_manifest": {
                        "anyOf": [
                            {"type": "null"},
                            {
                                "type": "object",
                                "required": ["artifacts"],
                                "properties": {
                                    "artifacts": exact_graph_digest_constraint,
                                },
                            },
                        ]
                    },
                },
            },
            "else": {
                "properties": {
                    "artifact_digests": no_graph_digest_constraint,
                    "release_manifest": {
                        "anyOf": [
                            {"type": "null"},
                            {
                                "type": "object",
                                "required": ["artifacts"],
                                "properties": {
                                    "artifacts": no_graph_digest_constraint,
                                },
                            },
                        ]
                    },
                }
            },
        }
    )
    sensitivity_present = {
        "required": ["evidence_sensitivity"],
        "properties": {"evidence_sensitivity": {"not": {"type": "null"}}},
    }
    exact_sensitivity_digest_constraint = {
        "contains": {
            "type": "object",
            "required": ["role"],
            "properties": {"role": {"const": _EVIDENCE_SENSITIVITY_ARTIFACT_ROLE}},
        },
        "minContains": 1,
        "maxContains": 1,
    }
    no_sensitivity_digest_constraint = {
        "not": {
            "contains": {
                "type": "object",
                "required": ["role"],
                "properties": {"role": {"const": _EVIDENCE_SENSITIVITY_ARTIFACT_ROLE}},
            }
        }
    }
    schema["allOf"].append(
        {
            "if": sensitivity_present,
            "then": {
                "required": ["artifact_digests"],
                "properties": {
                    "artifact_digests": exact_sensitivity_digest_constraint,
                    "release_manifest": {
                        "anyOf": [
                            {"type": "null"},
                            {
                                "type": "object",
                                "required": ["artifacts"],
                                "properties": {
                                    "artifacts": exact_sensitivity_digest_constraint,
                                },
                            },
                        ]
                    },
                },
            },
            "else": {
                "properties": {
                    "artifact_digests": no_sensitivity_digest_constraint,
                    "release_manifest": {
                        "anyOf": [
                            {"type": "null"},
                            {
                                "type": "object",
                                "required": ["artifacts"],
                                "properties": {
                                    "artifacts": no_sensitivity_digest_constraint,
                                },
                            },
                        ]
                    },
                }
            },
        }
    )
    stochastic_present = {
        "anyOf": [
            {
                "required": [field_name],
                "properties": {field_name: {"not": {"type": "null"}}},
            }
            for field_name in _STOCHASTIC_PACKET_FIELDS
        ]
    }
    exact_stochastic_digest_constraints = [
        {
            "contains": {
                "type": "object",
                "required": ["role"],
                "properties": {"role": {"const": role}},
            },
            "minContains": 1,
            "maxContains": 1,
        }
        for role in _STOCHASTIC_PACKET_ARTIFACT_ROLES
    ]
    no_stochastic_digest_constraint = {
        "not": {
            "contains": {
                "type": "object",
                "required": ["role"],
                "properties": {"role": {"enum": list(_STOCHASTIC_PACKET_ARTIFACT_ROLES)}},
            }
        }
    }
    schema["allOf"].append(
        {
            "if": stochastic_present,
            "then": {
                "required": [*_STOCHASTIC_PACKET_FIELDS, "artifact_digests"],
                "properties": {
                    **{
                        field_name: {"not": {"type": "null"}}
                        for field_name in _STOCHASTIC_PACKET_FIELDS
                    },
                    "artifact_digests": {
                        "allOf": exact_stochastic_digest_constraints,
                    },
                    "release_manifest": {
                        "anyOf": [
                            {"type": "null"},
                            {
                                "type": "object",
                                "required": ["artifacts"],
                                "properties": {
                                    "artifacts": {
                                        "allOf": exact_stochastic_digest_constraints,
                                    }
                                },
                            },
                        ]
                    },
                },
            },
            "else": {
                "properties": {
                    "artifact_digests": no_stochastic_digest_constraint,
                    "release_manifest": {
                        "anyOf": [
                            {"type": "null"},
                            {
                                "type": "object",
                                "required": ["artifacts"],
                                "properties": {
                                    "artifacts": no_stochastic_digest_constraint,
                                },
                            },
                        ]
                    },
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
    evidence_sensitivity: RAGSensitivityReport | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    statistical_sufficiency: StatisticalSufficiencyReport | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    stochastic_evidence_sensitivity: StochasticEvidenceSensitivityReport | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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
    evidence_graph_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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
    def _validate_stochastic_sensitivity_dependency(self) -> EvidencePacket:
        sufficiency = self.statistical_sufficiency
        stochastic = self.stochastic_evidence_sensitivity
        if (sufficiency is None) != (stochastic is None):
            raise ValueError(
                "statistical sufficiency and stochastic evidence sensitivity "
                "must be present together"
            )
        if sufficiency is None or stochastic is None:
            return self
        subject_binding_error = stochastic_packet_subject_binding_error(
            self.evaluation,
            stochastic,
            comparison=self.comparison,
        )
        if subject_binding_error is not None:
            raise ValueError(subject_binding_error)
        sufficiency = StatisticalSufficiencyReport.model_validate(
            sufficiency.model_dump(mode="json")
        )
        stochastic = StochasticEvidenceSensitivityReport.model_validate(
            stochastic.model_dump(mode="json")
        )
        if stochastic.sufficiency_report != sufficiency:
            raise ValueError(
                "stochastic evidence sensitivity must embed the exact packet "
                "statistical sufficiency report"
            )
        protocol = sufficiency.protocol
        if (stochastic.protocol_id, stochastic.protocol_digest) != (
            protocol.protocol_id,
            protocol.protocol_digest,
        ):
            raise ValueError(
                "stochastic evidence sensitivity must bind the exact sufficiency protocol"
            )
        expected_dependency = ArtifactDependency(
            target_artifact_id=sufficiency.report_id,
            target_digest=sufficiency.report_digest,
        )
        if stochastic.verdict_bearing:
            if sufficiency.state is not SufficiencyState.satisfied:
                raise ValueError(
                    "verdict-bearing stochastic evidence requires satisfied sufficiency"
                )
            if stochastic.dependency != expected_dependency:
                raise ValueError(
                    "verdict-bearing stochastic evidence requires the exact packet "
                    "sufficiency dependency"
                )
            if stochastic.state not in {
                StochasticSensitivityState.pass_,
                StochasticSensitivityState.block,
            } or stochastic.gate_effect not in {
                StochasticGateEffect.pass_,
                StochasticGateEffect.block,
            }:
                raise ValueError(
                    "verdict-bearing stochastic evidence has an incoherent verdict state"
                )
        elif (
            sufficiency.state is SufficiencyState.satisfied
            or stochastic.dependency is not None
            or stochastic.state
            not in {
                StochasticSensitivityState.prerequisites_unmet,
                StochasticSensitivityState.inconclusive,
            }
            or stochastic.gate_effect is not StochasticGateEffect.non_verdict
        ):
            raise ValueError(
                "underpowered or otherwise non-verdict stochastic evidence must remain non-verdict"
            )
        return self

    @model_validator(mode="after")
    def _validate_summary_digest_roles(self) -> EvidencePacket:
        error = packet_summary_digest_binding_error(self)
        if error is not None:
            raise ValueError(error)
        return self

    @model_validator(mode="after")
    def _validate_evidence_sensitivity_subject(self) -> EvidencePacket:
        report = self.evidence_sensitivity
        if report is None:
            return self
        report = RAGSensitivityReport.model_validate(report.model_dump(mode="json"))
        counterfactual = report.counterfactual_arm
        if self.evaluation.runset_digest is None:
            raise ValueError(
                "evidence sensitivity requires an authenticated evaluation runset digest"
            )
        if (
            self.evaluation.runset_id,
            self.evaluation.runset_digest,
        ) != (
            counterfactual.runset_id,
            counterfactual.runset_digest,
        ):
            raise ValueError(
                "evidence sensitivity counterfactual arm must match the packet evaluation"
            )
        if _canonical_model_digest(self.evaluation) != (counterfactual.evaluation_summary_digest):
            raise ValueError(
                "evidence sensitivity counterfactual evaluation digest must match the "
                "packet evaluation"
            )
        if self.comparison is not None and (
            self.comparison.baseline_runset_id,
            self.comparison.candidate_runset_id,
        ) != (
            report.baseline_arm.runset_id,
            counterfactual.runset_id,
        ):
            raise ValueError("evidence sensitivity arms must match the packet comparison run sets")
        if self.comparison is not None:
            from agent_assure.sensitivity_comparison import (
                sensitivity_comparison_binding_error,
            )

            comparison_error = sensitivity_comparison_binding_error(
                self.comparison,
                report,
            )
            if comparison_error is not None:
                raise ValueError(comparison_error)
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
            binding_error = comparison_evaluation_binding_error(
                self.comparison,
                self.evaluation,
                role="candidate",
            )
            if binding_error is not None:
                raise ValueError(f"evidence packet {binding_error}")
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
    """Return an exact-file summary-digest binding error for governed packets."""
    if packet.schema_version not in V063_CONTRACT_SCHEMA_VERSIONS:
        return None
    expected_comparison_count = int(packet.comparison is not None)
    expected_graph_count = int(packet.evidence_graph_digest is not None)
    expected_sensitivity_count = int(packet.evidence_sensitivity is not None)
    expected_statistical_count = int(packet.statistical_sufficiency is not None)
    expected_stochastic_count = int(packet.stochastic_evidence_sensitivity is not None)
    expected_stochastic_source_count = expected_stochastic_count
    stochastic_source_roles: tuple[PacketArtifactRole, PacketArtifactRole] = (
        "stochastic-baseline-source-runset",
        "stochastic-counterfactual-source-runset",
    )
    packet_by_role = {
        role: tuple(item for item in packet.artifact_digests if item.role == role)
        for role in (
            "evaluation-summary",
            "comparison-summary",
            _EVIDENCE_GRAPH_ARTIFACT_ROLE,
            _EVIDENCE_SENSITIVITY_ARTIFACT_ROLE,
            _STATISTICAL_SUFFICIENCY_ARTIFACT_ROLE,
            _STOCHASTIC_SENSITIVITY_ARTIFACT_ROLE,
            "stochastic-baseline-source-runset",
            "stochastic-counterfactual-source-runset",
        )
    }
    if len(packet_by_role["evaluation-summary"]) != 1:
        return "current evidence packets require exactly one evaluation-summary digest"
    if len(packet_by_role["comparison-summary"]) != expected_comparison_count:
        return "current evidence packet comparison-summary digest must match nested comparison"
    if len(packet_by_role[_EVIDENCE_GRAPH_ARTIFACT_ROLE]) != expected_graph_count:
        return (
            "current evidence packet assurance-evidence-graph digest must match "
            "evidence_graph_digest presence"
        )
    if len(packet_by_role[_EVIDENCE_SENSITIVITY_ARTIFACT_ROLE]) != expected_sensitivity_count:
        return (
            "current evidence packet evidence-sensitivity-report digest must match "
            "nested evidence sensitivity"
        )
    if len(packet_by_role[_STATISTICAL_SUFFICIENCY_ARTIFACT_ROLE]) != expected_statistical_count:
        return (
            "current evidence packet statistical-sufficiency-report digest must match "
            "nested statistical sufficiency"
        )
    if len(packet_by_role[_STOCHASTIC_SENSITIVITY_ARTIFACT_ROLE]) != expected_stochastic_count:
        return (
            "current evidence packet stochastic-evidence-sensitivity-report digest "
            "must match nested stochastic evidence sensitivity"
        )
    for role in stochastic_source_roles:
        if len(packet_by_role[role]) != expected_stochastic_source_count:
            return (
                f"current evidence packet {role} digest must match nested "
                "stochastic evidence sensitivity"
            )
    if packet.release_manifest is None:
        return None
    manifest_by_role = {
        role: tuple(item for item in packet.release_manifest.artifacts if item.role == role)
        for role in (
            "evaluation-summary",
            "comparison-summary",
            _EVIDENCE_GRAPH_ARTIFACT_ROLE,
            _EVIDENCE_SENSITIVITY_ARTIFACT_ROLE,
            _STATISTICAL_SUFFICIENCY_ARTIFACT_ROLE,
            _STOCHASTIC_SENSITIVITY_ARTIFACT_ROLE,
            "stochastic-baseline-source-runset",
            "stochastic-counterfactual-source-runset",
        )
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
    if len(manifest_by_role[_EVIDENCE_GRAPH_ARTIFACT_ROLE]) != expected_graph_count:
        return (
            "current evidence packet release manifest assurance-evidence-graph artifact "
            "must match evidence_graph_digest presence"
        )
    if len(manifest_by_role[_EVIDENCE_SENSITIVITY_ARTIFACT_ROLE]) != expected_sensitivity_count:
        return (
            "current evidence packet release manifest evidence-sensitivity-report "
            "artifact must match nested evidence sensitivity"
        )
    if len(manifest_by_role[_STATISTICAL_SUFFICIENCY_ARTIFACT_ROLE]) != expected_statistical_count:
        return (
            "current evidence packet release manifest statistical-sufficiency-report "
            "artifact must match nested statistical sufficiency"
        )
    if len(manifest_by_role[_STOCHASTIC_SENSITIVITY_ARTIFACT_ROLE]) != expected_stochastic_count:
        return (
            "current evidence packet release manifest "
            "stochastic-evidence-sensitivity-report artifact must match nested "
            "stochastic evidence sensitivity"
        )
    for role in stochastic_source_roles:
        if len(manifest_by_role[role]) != expected_stochastic_source_count:
            return (
                f"current evidence packet release manifest {role} artifact must "
                "match nested stochastic evidence sensitivity"
            )
    for role in (
        "evaluation-summary",
        "comparison-summary",
        _EVIDENCE_GRAPH_ARTIFACT_ROLE,
        _EVIDENCE_SENSITIVITY_ARTIFACT_ROLE,
        _STATISTICAL_SUFFICIENCY_ARTIFACT_ROLE,
        _STOCHASTIC_SENSITIVITY_ARTIFACT_ROLE,
        "stochastic-baseline-source-runset",
        "stochastic-counterfactual-source-runset",
    ):
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
