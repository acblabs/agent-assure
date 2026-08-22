from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Literal, Self, assert_never

from pydantic import Field, field_validator, model_validator

from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.campaign import MutationApplicability
from agent_assure.schema.common import (
    ComparisonClassification,
    DigestHex,
    GateState,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.efficacy import (
    INDEPENDENCE_CLASS_ORDER,
    INDEPENDENT_CHALLENGE_CLASSES,
    MAX_CATALOG_THREAT_REFERENCES,
    MAX_EFFICACY_OPERATORS,
    MAX_THREAT_CATEGORIES,
    ControlEfficacyGateReason,
    ControlEfficacySemanticState,
    EfficacyStratum,
    ExactRate,
    MutationStateCounts,
    ThreatApplicability,
    ThreatScopeSemanticState,
    control_efficacy_semantic_state,
    threat_scope_semantic_state,
)
from agent_assure.schema.mutation import (
    BoundedSummary,
    EvidenceEvaluationBasis,
    EvidenceState,
    ExactJsonPointer,
    GateEffect,
    MachineIdentifier,
    MutationResultState,
    SelfDigestedArtifact,
)
from agent_assure.schema.sensitivity import (
    DetectorTestStatus,
    EvidenceSensitivityExpectedRelation,
    EvidenceSensitivityGateEffect,
    EvidenceSensitivityObservedRelation,
    EvidenceSensitivityOutcomeClassification,
    EvidenceSensitivityReasonCode,
    EvidenceSensitivityState,
    RAGSensitivityDecision,
    SyntheticDataProvenance,
    derive_sensitivity_directional_outcome_classification,
    derive_sensitivity_outcome_message,
)
from agent_assure.sensitivity_contract import (
    SENSITIVITY_PROVENANCE_BINDING,
    SENSITIVITY_SUBJECT_EXECUTION_SCOPE,
    SensitivityProvenanceBinding,
    SensitivitySubjectExecutionScope,
)

GRAPH_CONTRACT_ID: Literal["AssuranceEvidenceGraph/v1"] = "AssuranceEvidenceGraph/v1"
GRAPH_CONTRACT_VERSION: Literal["1.0.0"] = "1.0.0"
GRAPH_SCHEMA_VERSION: Literal["0.6.4"] = "0.6.4"
MAX_GRAPH_NODES = 131_072
MAX_GRAPH_EDGES = 524_288
MAX_GRAPH_REFERENCES = MAX_CATALOG_THREAT_REFERENCES + 1
MAX_GRAPH_REASON_CODES = 64
MAX_GRAPH_LIMITATIONS = 32_768
MAX_GRAPH_MESSAGES = 32_768


class EvidenceGraphNodeKind(StrEnum):
    subject = "subject"
    requirement = "requirement"
    evidence = "evidence"
    finding = "finding"


class EvidenceGraphEdgeKind(StrEnum):
    supports = "supports"
    contradicts = "contradicts"
    targets = "targets"
    derived_from = "derived_from"
    scoped_to = "scoped_to"


class EvidenceGraphRequirementType(StrEnum):
    declared_expectations = "declared_expectations"
    control = "control"
    comparison = "comparison"
    mutation_detector = "mutation_detector"
    control_efficacy = "control_efficacy"
    threat_scope = "threat_scope"
    gate_profile = "gate_profile"
    expected_decision_response = "expected_decision_response"


class EvidenceGraphEvidenceType(StrEnum):
    evaluation = "evaluation"
    comparison = "comparison"
    mutation_result = "mutation_result"
    control_efficacy = "control_efficacy"
    gate_profile = "gate_profile"
    gate_decision = "gate_decision"
    packet_limitations = "packet_limitations"
    evidence_sensitivity = "evidence_sensitivity"


class EvidenceGraphFindingType(StrEnum):
    evaluation = "evaluation"
    comparison_verdict = "comparison_verdict"
    comparison_provenance = "comparison_provenance"
    mutation_result = "mutation_result"
    mutation_observed_finding = "mutation_observed_finding"
    control_efficacy_outcome = "control_efficacy_outcome"
    control_efficacy_threat = "control_efficacy_threat"
    control_efficacy_gate = "control_efficacy_gate"
    limitation = "limitation"
    evidence_sensitivity_outcome = "evidence_sensitivity_outcome"


class EvidenceGraphReferenceRole(StrEnum):
    diagnostic = "diagnostic"
    applicability = "applicability"
    baseline_subject = "baseline_subject"
    candidate_subject = "candidate_subject"
    case = "case"
    catalog = "catalog"
    critical_threat = "critical_threat"
    control = "control"
    gate_profile = "gate_profile"
    independence_class = "independence_class"
    independent_challenger = "independent_challenger"
    invariant_family = "invariant_family"
    matched_finding = "matched_finding"
    operator = "operator"
    present_control = "present_control"
    scoped_threat = "scoped_threat"
    source_digest = "source_digest"
    target = "target"
    threat = "threat"
    unscoped_threat = "unscoped_threat"


class EvidenceGraphProjectionDisposition(StrEnum):
    represented = "represented"
    unsupported = "unsupported"


GraphReferenceValue = Annotated[
    str,
    Field(min_length=1, max_length=MAX_ARTIFACT_JSON_BYTES),
]
GraphSourceId = Annotated[
    str,
    Field(min_length=1, max_length=(2 * MAX_ARTIFACT_JSON_BYTES) + 2),
]
GraphMessage = Annotated[
    str,
    Field(min_length=0, max_length=MAX_ARTIFACT_JSON_BYTES),
]
GraphNodeId = Annotated[
    str,
    Field(pattern=r"^(?:subject|requirement|evidence|finding):[a-f0-9]{64}$"),
]


class EvidenceGraphProjectionReason(StrEnum):
    evidence_scope_limitation = "EVIDENCE_SCOPE_LIMITATION"
    mutation_caught = "MUTATION_CAUGHT"
    mutation_execution_error = "MUTATION_EXECUTION_ERROR"
    mutation_inapplicable = "MUTATION_INAPPLICABLE"
    mutation_invalid_operator = "MUTATION_INVALID_OPERATOR"
    mutation_invalid_subject = "MUTATION_INVALID_SUBJECT"
    mutation_survived = "MUTATION_SURVIVED"
    threat_applicability_unknown = "THREAT_APPLICABILITY_UNKNOWN"
    threat_challenged = "THREAT_CHALLENGED"
    threat_not_applicable = "THREAT_NOT_APPLICABLE"
    threat_uncovered = "THREAT_UNCOVERED"


class EvidenceGraphSubjectIdentityProjection(FrozenStrictModel):
    identity_kind: Literal["subject"] = "subject"
    subject_type: Literal["agent_release", "run_set"]
    subject_id: GraphSourceId
    subject_digest: DigestHex | None = None


class EvidenceGraphRequirementIdentityProjection(FrozenStrictModel):
    identity_kind: Literal["requirement"] = "requirement"
    subject_node_id: GraphNodeId
    requirement_type: EvidenceGraphRequirementType
    requirement_id: GraphSourceId

    @field_validator("requirement_type", mode="before")
    @classmethod
    def _coerce_requirement_type(cls, value: object) -> EvidenceGraphRequirementType:
        return coerce_enum(EvidenceGraphRequirementType, value)


class EvidenceGraphEvidenceIdentityProjection(FrozenStrictModel):
    identity_kind: Literal["evidence"] = "evidence"
    subject_node_id: GraphNodeId
    evidence_type: EvidenceGraphEvidenceType
    source_artifact_kind: MachineIdentifier
    source_id: GraphSourceId

    @field_validator("evidence_type", mode="before")
    @classmethod
    def _coerce_evidence_type(cls, value: object) -> EvidenceGraphEvidenceType:
        return coerce_enum(EvidenceGraphEvidenceType, value)


class EvidenceGraphFindingIdentityProjection(FrozenStrictModel):
    identity_kind: Literal["finding"] = "finding"
    subject_node_id: GraphNodeId
    parent_evidence_node_id: GraphNodeId
    finding_type: EvidenceGraphFindingType
    source_artifact_kind: MachineIdentifier
    source_id: GraphSourceId
    source_path: ExactJsonPointer

    @field_validator("finding_type", mode="before")
    @classmethod
    def _coerce_finding_type(cls, value: object) -> EvidenceGraphFindingType:
        return coerce_enum(EvidenceGraphFindingType, value)


EvidenceGraphIdentityProjection = Annotated[
    EvidenceGraphSubjectIdentityProjection
    | EvidenceGraphRequirementIdentityProjection
    | EvidenceGraphEvidenceIdentityProjection
    | EvidenceGraphFindingIdentityProjection,
    Field(discriminator="identity_kind"),
]


class EvidenceGraphReference(FrozenStrictModel):
    role: EvidenceGraphReferenceRole
    value: GraphReferenceValue

    @field_validator("role", mode="before")
    @classmethod
    def _coerce_role(cls, value: object) -> EvidenceGraphReferenceRole:
        return coerce_enum(EvidenceGraphReferenceRole, value)


class EvidenceGraphSubjectPayload(FrozenStrictModel):
    payload_kind: Literal["subject"] = "subject"
    subject_type: Literal["agent_release", "run_set"]
    subject_id: GraphSourceId
    subject_digest: DigestHex | None = None


class EvidenceGraphRequirementPayload(FrozenStrictModel):
    payload_kind: Literal["requirement"] = "requirement"
    requirement_type: EvidenceGraphRequirementType
    requirement_id: GraphSourceId
    references: tuple[EvidenceGraphReference, ...] = Field(
        default=(),
        max_length=MAX_GRAPH_REFERENCES,
    )

    @field_validator("requirement_type", mode="before")
    @classmethod
    def _coerce_requirement_type(cls, value: object) -> EvidenceGraphRequirementType:
        return coerce_enum(EvidenceGraphRequirementType, value)

    @field_validator("references", mode="before")
    @classmethod
    def _coerce_references(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_reference_order(self) -> Self:
        _require_canonical_references(self.references)
        return self


class EvidenceGraphComparisonProjection(FrozenStrictModel):
    classification: ComparisonClassification
    fixture_equivalence_state: GateState
    baseline_state: GateState
    candidate_state: GateState

    @field_validator("classification", mode="before")
    @classmethod
    def _coerce_classification(cls, value: object) -> ComparisonClassification:
        return coerce_enum(ComparisonClassification, value)

    @field_validator(
        "fixture_equivalence_state",
        "baseline_state",
        "candidate_state",
        mode="before",
    )
    @classmethod
    def _coerce_gate_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)


class EvidenceGraphSensitivityProjection(FrozenStrictModel):
    state: EvidenceSensitivityState
    gate_effect: EvidenceSensitivityGateEffect
    endpoint: Literal["expected_decision_response"] = "expected_decision_response"
    endpoint_value: bool | None
    expected_relation: EvidenceSensitivityExpectedRelation
    observed_relation: EvidenceSensitivityObservedRelation
    outcome_classification: EvidenceSensitivityOutcomeClassification
    baseline_expected_decision: RAGSensitivityDecision | None
    counterfactual_expected_decision: RAGSensitivityDecision | None
    baseline_observed_decision: RAGSensitivityDecision
    counterfactual_observed_decision: RAGSensitivityDecision
    deterministic: Literal[True] = True
    detector_test_status: DetectorTestStatus
    subject_execution_scope: SensitivitySubjectExecutionScope = SENSITIVITY_SUBJECT_EXECUTION_SCOPE
    provenance_binding: SensitivityProvenanceBinding = SENSITIVITY_PROVENANCE_BINDING
    synthetic_data_provenance: SyntheticDataProvenance
    synthetic_data_attestation_digest: DigestHex | None = None
    raw_content_persistence: Literal["exact_corpus_and_fixture_utf8_embedded"]
    claim_scope: Literal["controlled_evidence_sensitivity_not_causal_guarantee"]
    population_claim: Literal[
        "none_bundled_synthetic_fixture_only",
        "none_operator_attested_synthetic_fixture_only",
    ]
    protocol_digest: DigestHex
    knowledge_contract_digest: DigestHex
    baseline_runset_id: GraphSourceId
    baseline_runset_digest: DigestHex
    counterfactual_runset_id: GraphSourceId
    counterfactual_runset_digest: DigestHex
    decision_inertia_detected: bool
    reason_codes: tuple[EvidenceSensitivityReasonCode, ...] = Field(
        default=(),
        max_length=MAX_GRAPH_REASON_CODES,
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> EvidenceSensitivityState:
        return coerce_enum(EvidenceSensitivityState, value)

    @field_validator("gate_effect", mode="before")
    @classmethod
    def _coerce_gate_effect(cls, value: object) -> EvidenceSensitivityGateEffect:
        return coerce_enum(EvidenceSensitivityGateEffect, value)

    @field_validator("expected_relation", mode="before")
    @classmethod
    def _coerce_expected_relation(
        cls,
        value: object,
    ) -> EvidenceSensitivityExpectedRelation:
        return coerce_enum(EvidenceSensitivityExpectedRelation, value)

    @field_validator("observed_relation", mode="before")
    @classmethod
    def _coerce_observed_relation(
        cls,
        value: object,
    ) -> EvidenceSensitivityObservedRelation:
        return coerce_enum(EvidenceSensitivityObservedRelation, value)

    @field_validator("outcome_classification", mode="before")
    @classmethod
    def _coerce_outcome_classification(
        cls,
        value: object,
    ) -> EvidenceSensitivityOutcomeClassification:
        return coerce_enum(EvidenceSensitivityOutcomeClassification, value)

    @field_validator(
        "baseline_expected_decision",
        "counterfactual_expected_decision",
        "baseline_observed_decision",
        "counterfactual_observed_decision",
        mode="before",
    )
    @classmethod
    def _coerce_sensitivity_decisions(cls, value: object) -> object:
        if value is None:
            return None
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("detector_test_status", mode="before")
    @classmethod
    def _coerce_detector_test_status(cls, value: object) -> DetectorTestStatus:
        return coerce_enum(DetectorTestStatus, value)

    @field_validator("synthetic_data_provenance", mode="before")
    @classmethod
    def _coerce_synthetic_data_provenance(
        cls,
        value: object,
    ) -> SyntheticDataProvenance:
        return coerce_enum(SyntheticDataProvenance, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(EvidenceSensitivityReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    def _validate_projection(self) -> Self:
        expected_population_claim = {
            SyntheticDataProvenance.bundled_digest_verified: (
                "none_bundled_synthetic_fixture_only"
            ),
            SyntheticDataProvenance.operator_attested: (
                "none_operator_attested_synthetic_fixture_only"
            ),
        }[self.synthetic_data_provenance]
        if self.population_claim != expected_population_claim:
            raise ValueError(
                "sensitivity projection population claim must match synthetic-data provenance"
            )
        if (self.synthetic_data_attestation_digest is not None) is not (
            self.synthetic_data_provenance is SyntheticDataProvenance.operator_attested
        ):
            raise ValueError(
                "operator-attested sensitivity projection requires exactly one "
                "synthetic-data attestation digest"
            )
        if self.reason_codes != tuple(sorted(set(self.reason_codes), key=lambda item: item.value)):
            raise ValueError("sensitivity projection reason codes must be unique and sorted")
        if (
            self.baseline_runset_id,
            self.baseline_runset_digest,
        ) == (
            self.counterfactual_runset_id,
            self.counterfactual_runset_digest,
        ):
            raise ValueError("sensitivity projection arms must have distinct run-set identities")
        if self.baseline_runset_id == self.counterfactual_runset_id:
            raise ValueError("sensitivity projection arms must have distinct run-set IDs")
        expected_endpoint = {
            EvidenceSensitivityState.responsive: True,
            EvidenceSensitivityState.evidence_insensitive: False,
            EvidenceSensitivityState.confounded: None,
            EvidenceSensitivityState.prerequisites_unmet: None,
        }[self.state]
        expected_gate_effect = {
            EvidenceSensitivityState.responsive: EvidenceSensitivityGateEffect.pass_,
            EvidenceSensitivityState.evidence_insensitive: (EvidenceSensitivityGateEffect.block),
            EvidenceSensitivityState.confounded: (EvidenceSensitivityGateEffect.non_verdict),
            EvidenceSensitivityState.prerequisites_unmet: (
                EvidenceSensitivityGateEffect.non_verdict
            ),
        }[self.state]
        expected_reason_role = {
            EvidenceSensitivityState.responsive: self.reason_codes == (),
            EvidenceSensitivityState.evidence_insensitive: self.reason_codes
            == (EvidenceSensitivityReasonCode.expected_response_missing,),
            EvidenceSensitivityState.confounded: {
                EvidenceSensitivityReasonCode.confounded,
                EvidenceSensitivityReasonCode.prerequisites_unmet,
            }.issubset(self.reason_codes)
            and EvidenceSensitivityReasonCode.expected_response_missing not in self.reason_codes,
            EvidenceSensitivityState.prerequisites_unmet: (
                EvidenceSensitivityReasonCode.prerequisites_unmet in self.reason_codes
                and EvidenceSensitivityReasonCode.confounded not in self.reason_codes
                and EvidenceSensitivityReasonCode.expected_response_missing not in self.reason_codes
            ),
        }[self.state]
        if (
            self.endpoint_value is not expected_endpoint
            or self.gate_effect is not expected_gate_effect
            or not expected_reason_role
        ):
            raise ValueError(
                "sensitivity projection state contradicts its endpoint, gate, or reason role"
            )
        if (
            self.state is EvidenceSensitivityState.responsive
            and self.observed_relation is not EvidenceSensitivityObservedRelation.decision_flip
        ):
            raise ValueError("responsive sensitivity projection requires a decision flip")
        observed_relation = (
            EvidenceSensitivityObservedRelation.incomparable
            if RAGSensitivityDecision.escalate
            in {self.baseline_observed_decision, self.counterfactual_observed_decision}
            else EvidenceSensitivityObservedRelation.decision_same
            if self.baseline_observed_decision is self.counterfactual_observed_decision
            else EvidenceSensitivityObservedRelation.decision_flip
        )
        if self.observed_relation is not observed_relation:
            raise ValueError("sensitivity projection relation must match its directional decisions")
        expected_outputs_bound = (
            self.baseline_expected_decision is not None
            and self.counterfactual_expected_decision is not None
        )
        expected_response_observed = expected_outputs_bound and (
            self.baseline_observed_decision,
            self.counterfactual_observed_decision,
        ) == (
            self.baseline_expected_decision,
            self.counterfactual_expected_decision,
        )
        if self.endpoint_value is not None and (
            self.endpoint_value is not expected_response_observed
        ):
            raise ValueError("sensitivity projection endpoint must match its directional decisions")
        expected_outcome_classification = derive_sensitivity_directional_outcome_classification(
            state=self.state,
            observed_relation=self.observed_relation,
            baseline_expected_decision=self.baseline_expected_decision,
            counterfactual_expected_decision=self.counterfactual_expected_decision,
            baseline_observed_decision=self.baseline_observed_decision,
            counterfactual_observed_decision=self.counterfactual_observed_decision,
        )
        if self.outcome_classification is not expected_outcome_classification:
            raise ValueError(
                "sensitivity projection outcome classification contradicts state and relation"
            )
        expected_inertia = (
            self.state is EvidenceSensitivityState.evidence_insensitive
            and self.observed_relation is EvidenceSensitivityObservedRelation.decision_same
        )
        if self.decision_inertia_detected is not expected_inertia:
            raise ValueError(
                "sensitivity projection decision inertia contradicts state and relation"
            )
        return self


class EvidenceGraphControlEfficacyProjection(FrozenStrictModel):
    semantic_state: ControlEfficacySemanticState
    threat_scope_state: ThreatScopeSemanticState
    canonical_operator_ids: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_EFFICACY_OPERATORS,
    )
    canonical_invariant_families: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_EFFICACY_OPERATORS,
    )
    selected_operator_ids: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_EFFICACY_OPERATORS,
    )
    pending_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    required_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    state_counts: MutationStateCounts
    applicable_operator_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    caught_operator_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    survived_operator_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    inapplicable_operator_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    invalid_operator_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    invalid_subject_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    execution_error_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    catalog_kill_rate: ExactRate
    required_survivor_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    critical_survivor_count: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    required_survivor_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    critical_survivor_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    required_not_evaluated_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    invalid_or_error_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    kill_rate_by_invariant_family: tuple[EfficacyStratum, ...] = Field(
        min_length=1,
        max_length=MAX_EFFICACY_OPERATORS,
    )
    kill_rate_by_independence_class: tuple[EfficacyStratum, ...] = Field(
        min_length=len(INDEPENDENCE_CLASS_ORDER),
        max_length=len(INDEPENDENCE_CLASS_ORDER),
    )
    applicable_threat_category_count: int = Field(ge=0, le=MAX_THREAT_CATEGORIES)
    challenged_threat_category_count: int = Field(ge=0, le=MAX_THREAT_CATEGORIES)
    independently_challenged_threat_category_count: int = Field(
        ge=0,
        le=MAX_THREAT_CATEGORIES,
    )
    critical_uncovered_threat_count: int = Field(ge=0, le=MAX_THREAT_CATEGORIES)
    unknown_applicability_count: int = Field(ge=0, le=MAX_THREAT_CATEGORIES)
    critical_uncovered_threat_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_THREAT_CATEGORIES,
    )
    unknown_applicability_threat_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_THREAT_CATEGORIES,
    )
    unscoped_catalog_threat_count: int = Field(
        ge=0,
        le=MAX_CATALOG_THREAT_REFERENCES,
    )
    unscoped_catalog_threat_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_CATALOG_THREAT_REFERENCES,
    )
    threat_coverage_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_THREAT_CATEGORIES,
    )
    threat_challenge_rate: ExactRate
    independent_threat_challenge_rate: ExactRate

    @field_validator("semantic_state", mode="before")
    @classmethod
    def _coerce_semantic_state(cls, value: object) -> ControlEfficacySemanticState:
        return coerce_enum(ControlEfficacySemanticState, value)

    @field_validator("threat_scope_state", mode="before")
    @classmethod
    def _coerce_threat_scope_state(cls, value: object) -> ThreatScopeSemanticState:
        return coerce_enum(ThreatScopeSemanticState, value)

    @field_validator(
        "canonical_operator_ids",
        "canonical_invariant_families",
        "selected_operator_ids",
        "pending_operator_ids",
        "required_operator_ids",
        "required_survivor_operator_ids",
        "critical_survivor_operator_ids",
        "required_not_evaluated_operator_ids",
        "invalid_or_error_operator_ids",
        "kill_rate_by_invariant_family",
        "kill_rate_by_independence_class",
        "critical_uncovered_threat_ids",
        "unknown_applicability_threat_ids",
        "unscoped_catalog_threat_ids",
        "threat_coverage_ids",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_canonical_sets(self) -> Self:
        identifier_sets = (
            self.canonical_operator_ids,
            self.canonical_invariant_families,
            self.selected_operator_ids,
            self.pending_operator_ids,
            self.required_operator_ids,
            self.required_survivor_operator_ids,
            self.critical_survivor_operator_ids,
            self.required_not_evaluated_operator_ids,
            self.invalid_or_error_operator_ids,
            self.critical_uncovered_threat_ids,
            self.unknown_applicability_threat_ids,
            self.unscoped_catalog_threat_ids,
            self.threat_coverage_ids,
        )
        if any(values != tuple(sorted(set(values))) for values in identifier_sets):
            raise ValueError("control-efficacy graph identifier sets must be canonical")
        family_keys = tuple(item.stratum for item in self.kill_rate_by_invariant_family)
        if family_keys != tuple(sorted(set(family_keys))):
            raise ValueError("control-efficacy invariant-family strata must be canonical")
        independence_keys = tuple(item.stratum for item in self.kill_rate_by_independence_class)
        expected_independence = tuple(item.value for item in INDEPENDENCE_CLASS_ORDER)
        if independence_keys != expected_independence:
            raise ValueError("control-efficacy independence strata must be complete")
        if family_keys != self.canonical_invariant_families:
            raise ValueError("control-efficacy family strata must be complete")
        direct_counts = (
            self.applicable_operator_count,
            self.caught_operator_count,
            self.survived_operator_count,
            self.inapplicable_operator_count,
            self.invalid_operator_count,
            self.invalid_subject_count,
            self.execution_error_count,
        )
        expected_direct_counts = (
            self.state_counts.applicable,
            self.state_counts.caught,
            self.state_counts.survived,
            self.state_counts.inapplicable,
            self.state_counts.invalid_operator,
            self.state_counts.invalid_subject,
            self.state_counts.execution_error,
        )
        if direct_counts != expected_direct_counts:
            raise ValueError("control-efficacy counts must match state counts")
        if self.catalog_kill_rate != ExactRate.from_counts(
            self.state_counts.caught,
            self.state_counts.applicable,
        ):
            raise ValueError("control-efficacy catalog rate must match state counts")
        count_id_pairs = (
            (self.required_survivor_count, self.required_survivor_operator_ids),
            (self.critical_survivor_count, self.critical_survivor_operator_ids),
            (
                self.critical_uncovered_threat_count,
                self.critical_uncovered_threat_ids,
            ),
            (
                self.unknown_applicability_count,
                self.unknown_applicability_threat_ids,
            ),
            (
                self.unscoped_catalog_threat_count,
                self.unscoped_catalog_threat_ids,
            ),
        )
        if any(count != len(identifiers) for count, identifiers in count_id_pairs):
            raise ValueError("control-efficacy counts must match their identifier sets")
        if self.threat_challenge_rate != ExactRate.from_counts(
            self.challenged_threat_category_count,
            self.applicable_threat_category_count,
        ):
            raise ValueError("threat challenge rate must match threat counts")
        if self.independent_threat_challenge_rate != ExactRate.from_counts(
            self.independently_challenged_threat_category_count,
            self.applicable_threat_category_count,
        ):
            raise ValueError("independent threat rate must match threat counts")
        if self.semantic_state is not control_efficacy_semantic_state(
            self.state_counts,
            pending_count=len(self.pending_operator_ids),
        ):
            raise ValueError("control-efficacy semantic state must match counts")
        if self.threat_scope_state is not threat_scope_semantic_state(
            applicable_count=self.applicable_threat_category_count,
            challenged_count=self.challenged_threat_category_count,
            critical_uncovered_count=self.critical_uncovered_threat_count,
            unknown_count=self.unknown_applicability_count,
            unscoped_catalog_threat_count=self.unscoped_catalog_threat_count,
        ):
            raise ValueError("control-efficacy threat scope state must match counts")
        canonical_set = set(self.canonical_operator_ids)
        for values in (
            self.selected_operator_ids,
            self.pending_operator_ids,
            self.required_operator_ids,
        ):
            if not set(values).issubset(canonical_set):
                raise ValueError("control-efficacy operator scopes must be canonical subsets")
        if self.state_counts.total + len(self.pending_operator_ids) != len(
            self.selected_operator_ids
        ):
            raise ValueError(
                "control-efficacy outcomes and pending operators must partition selection"
            )
        selected_set = set(self.selected_operator_ids)
        pending_set = set(self.pending_operator_ids)
        required_set = set(self.required_operator_ids)
        diagnostic_subsets = (
            (self.required_survivor_operator_ids, required_set & selected_set),
            (self.critical_survivor_operator_ids, selected_set),
            (self.required_not_evaluated_operator_ids, required_set),
            (self.invalid_or_error_operator_ids, selected_set),
        )
        if any(not set(values).issubset(allowed) for values, allowed in diagnostic_subsets):
            raise ValueError("control-efficacy diagnostic IDs must remain in their source scopes")
        if (
            pending_set & set(self.required_survivor_operator_ids)
            or pending_set & set(self.critical_survivor_operator_ids)
            or pending_set & set(self.invalid_or_error_operator_ids)
            or set(self.required_survivor_operator_ids)
            & set(self.required_not_evaluated_operator_ids)
        ):
            raise ValueError("control-efficacy diagnostic operator states must be disjoint")
        invalid_or_error_count = (
            self.state_counts.invalid_operator
            + self.state_counts.invalid_subject
            + self.state_counts.execution_error
        )
        if len(self.invalid_or_error_operator_ids) != invalid_or_error_count:
            raise ValueError("invalid-or-error IDs must match invalid and error counts")
        if (
            self.required_survivor_count > self.state_counts.survived
            or self.critical_survivor_count > self.state_counts.survived
        ):
            raise ValueError("survivor diagnostic counts cannot exceed survivor outcomes")
        if not (
            self.independently_challenged_threat_category_count
            <= self.challenged_threat_category_count
            <= self.applicable_threat_category_count
        ):
            raise ValueError("threat challenge counts must form valid subsets")
        if self.critical_uncovered_threat_count > (
            self.applicable_threat_category_count - self.challenged_threat_category_count
        ):
            raise ValueError("critical uncovered threats must be applicable and unchallenged")
        if (
            _sum_stratum_counts(self.kill_rate_by_invariant_family) != self.state_counts
            or _sum_stratum_counts(self.kill_rate_by_independence_class) != self.state_counts
        ):
            raise ValueError("control-efficacy strata must total to state counts")
        for independence_class, stratum in zip(
            INDEPENDENCE_CLASS_ORDER,
            self.kill_rate_by_independence_class,
            strict=True,
        ):
            expected_eligible = independence_class in INDEPENDENT_CHALLENGE_CLASSES
            if stratum.independent_challenge_eligible is not expected_eligible:
                raise ValueError("independence eligibility must match the fixed policy")
        return self


def _sum_stratum_counts(
    strata: tuple[EfficacyStratum, ...],
) -> MutationStateCounts:
    return MutationStateCounts(
        caught=sum(item.state_counts.caught for item in strata),
        survived=sum(item.state_counts.survived for item in strata),
        inapplicable=sum(item.state_counts.inapplicable for item in strata),
        invalid_operator=sum(item.state_counts.invalid_operator for item in strata),
        invalid_subject=sum(item.state_counts.invalid_subject for item in strata),
        execution_error=sum(item.state_counts.execution_error for item in strata),
    )


def _comparison_evidence_state(
    projection: EvidenceGraphComparisonProjection,
) -> EvidenceState:
    if projection.fixture_equivalence_state is GateState.fail:
        return EvidenceState.error
    if projection.fixture_equivalence_state is GateState.warn:
        return EvidenceState.inconclusive
    if projection.fixture_equivalence_state is GateState.not_evaluated:
        return EvidenceState.not_evaluated
    if projection.fixture_equivalence_state is not GateState.pass_:
        assert_never(projection.fixture_equivalence_state)
    match projection.classification:
        case ComparisonClassification.invalid_comparison:
            return EvidenceState.error
        case ComparisonClassification.new_failure | ComparisonClassification.persistent_failure:
            return EvidenceState.violated
        case ComparisonClassification.not_evaluated:
            return EvidenceState.not_evaluated
        case (
            ComparisonClassification.unchanged
            | ComparisonClassification.resolved_failure
            | ComparisonClassification.allowed_behavioral_change
            | ComparisonClassification.allowed_behavioral_and_provenance_change
            | ComparisonClassification.provenance_only_change
        ):
            return _gate_evidence_state(projection.candidate_state)
        case _ as unreachable:
            assert_never(unreachable)


def _comparison_evidence_is_verdict_bearing(
    projection: EvidenceGraphComparisonProjection,
) -> bool:
    return (
        projection.fixture_equivalence_state is GateState.pass_
        and projection.classification
        not in {
            ComparisonClassification.invalid_comparison,
            ComparisonClassification.not_evaluated,
        }
    )


def _gate_evidence_state(state: GateState) -> EvidenceState:
    match state:
        case GateState.pass_:
            return EvidenceState.supported
        case GateState.fail:
            return EvidenceState.violated
        case GateState.warn:
            return EvidenceState.inconclusive
        case GateState.not_evaluated:
            return EvidenceState.not_evaluated
        case _ as unreachable:
            assert_never(unreachable)


def _control_efficacy_evidence_state(
    state: ControlEfficacySemanticState,
) -> EvidenceState:
    match state:
        case ControlEfficacySemanticState.survivor_observed:
            return EvidenceState.contradicted
        case ControlEfficacySemanticState.indeterminate:
            return EvidenceState.inconclusive
        case ControlEfficacySemanticState.not_evaluated:
            return EvidenceState.not_evaluated
        case ControlEfficacySemanticState.all_evaluated_applicable_caught:
            return EvidenceState.supported
        case _ as unreachable:
            assert_never(unreachable)


def _evidence_sensitivity_role(
    state: EvidenceSensitivityState,
) -> tuple[EvidenceState, bool]:
    match state:
        case EvidenceSensitivityState.responsive:
            return EvidenceState.supported, True
        case EvidenceSensitivityState.evidence_insensitive:
            return EvidenceState.violated, True
        case EvidenceSensitivityState.confounded:
            return EvidenceState.inconclusive, False
        case EvidenceSensitivityState.prerequisites_unmet:
            return EvidenceState.prerequisites_unmet, False
        case _ as unreachable:
            assert_never(unreachable)


class EvidenceGraphEvidencePayload(FrozenStrictModel):
    payload_kind: Literal["evidence"] = "evidence"
    evidence_type: EvidenceGraphEvidenceType
    source_artifact_kind: MachineIdentifier
    source_id: GraphSourceId
    source_digest: DigestHex
    state: EvidenceState
    verdict_bearing: bool
    privacy_profile_id: GraphSourceId | None = None
    privacy_profile_digest: DigestHex | None = None
    evaluation_basis: EvidenceEvaluationBasis | None = None
    comparison_projection: EvidenceGraphComparisonProjection | None = None
    control_efficacy_projection: EvidenceGraphControlEfficacyProjection | None = None
    evidence_sensitivity_projection: EvidenceGraphSensitivityProjection | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    references: tuple[EvidenceGraphReference, ...] = Field(
        default=(),
        max_length=MAX_GRAPH_REFERENCES,
    )
    limitations: tuple[BoundedSummary, ...] = Field(
        default=(),
        max_length=MAX_GRAPH_LIMITATIONS,
    )

    @field_validator("evidence_type", mode="before")
    @classmethod
    def _coerce_evidence_type(cls, value: object) -> EvidenceGraphEvidenceType:
        return coerce_enum(EvidenceGraphEvidenceType, value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> EvidenceState:
        return coerce_enum(EvidenceState, value)

    @field_validator("evaluation_basis", mode="before")
    @classmethod
    def _coerce_evaluation_basis(
        cls,
        value: object,
    ) -> EvidenceEvaluationBasis | None:
        if value is None:
            return None
        return coerce_enum(EvidenceEvaluationBasis, value)

    @field_validator("references", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_reference_order(self) -> Self:
        _require_canonical_references(self.references)
        if (self.privacy_profile_id is None) != (self.privacy_profile_digest is None):
            raise ValueError("graph privacy profile ID and digest must be present together")
        if (
            self.evidence_type
            not in {
                EvidenceGraphEvidenceType.evaluation,
                EvidenceGraphEvidenceType.comparison,
            }
            and self.privacy_profile_id is not None
        ):
            raise ValueError("privacy profile provenance belongs to summary evidence")
        if (self.evaluation_basis is not None) is not (
            self.evidence_type is EvidenceGraphEvidenceType.mutation_result
        ):
            raise ValueError("evaluation_basis belongs exactly to mutation-result evidence")
        if (self.comparison_projection is not None) != (
            self.evidence_type is EvidenceGraphEvidenceType.comparison
        ):
            raise ValueError("comparison evidence requires exactly one comparison projection")
        if (self.control_efficacy_projection is not None) != (
            self.evidence_type is EvidenceGraphEvidenceType.control_efficacy
        ):
            raise ValueError("control-efficacy evidence requires exactly one efficacy projection")
        if (self.evidence_sensitivity_projection is not None) != (
            self.evidence_type is EvidenceGraphEvidenceType.evidence_sensitivity
        ):
            raise ValueError(
                "evidence-sensitivity evidence requires exactly one sensitivity projection"
            )
        if self.comparison_projection is not None:
            expected_state = _comparison_evidence_state(self.comparison_projection)
            if self.state is not expected_state:
                raise ValueError("comparison evidence state contradicts its projection")
            expected_verdict = _comparison_evidence_is_verdict_bearing(self.comparison_projection)
            if self.verdict_bearing is not expected_verdict:
                raise ValueError("comparison verdict-bearing state contradicts its projection")
        if self.control_efficacy_projection is not None:
            expected_state = _control_efficacy_evidence_state(
                self.control_efficacy_projection.semantic_state
            )
            if self.state is not expected_state:
                raise ValueError("efficacy evidence state contradicts its projection")
            expected_verdict = (
                self.control_efficacy_projection.semantic_state
                is not ControlEfficacySemanticState.not_evaluated
            )
            if self.verdict_bearing is not expected_verdict:
                raise ValueError("efficacy verdict-bearing state contradicts its projection")
        if self.evidence_sensitivity_projection is not None:
            expected_state, expected_verdict = _evidence_sensitivity_role(
                self.evidence_sensitivity_projection.state
            )
            if (self.state, self.verdict_bearing) != (
                expected_state,
                expected_verdict,
            ):
                raise ValueError(
                    "sensitivity evidence state or verdict role contradicts its projection"
                )
            if self.source_artifact_kind != "evidence-sensitivity-report":
                raise ValueError(
                    "sensitivity evidence requires the evidence-sensitivity-report source kind"
                )
            if not self.limitations:
                raise ValueError("sensitivity evidence must preserve report limitations")
        exact_state_roles = {
            EvidenceGraphEvidenceType.gate_profile: (
                EvidenceState.inconclusive,
                False,
            ),
            EvidenceGraphEvidenceType.packet_limitations: (
                EvidenceState.inconclusive,
                False,
            ),
        }
        exact_role = exact_state_roles.get(self.evidence_type)
        if (
            exact_role is not None
            and (
                self.state,
                self.verdict_bearing,
            )
            != exact_role
        ):
            raise ValueError("graph evidence state contradicts its declared evidence type")
        if self.evidence_type is EvidenceGraphEvidenceType.evaluation:
            allowed = {
                EvidenceState.supported,
                EvidenceState.violated,
                EvidenceState.inconclusive,
                EvidenceState.not_evaluated,
            }
            if self.state not in allowed or self.verdict_bearing is (
                self.state is EvidenceState.not_evaluated
            ):
                raise ValueError("evaluation evidence state and verdict role must be coherent")
        if self.evidence_type is EvidenceGraphEvidenceType.mutation_result:
            if self.evaluation_basis is EvidenceEvaluationBasis.deterministic:
                expected_mutation_roles = {
                    EvidenceState.supported: True,
                    EvidenceState.contradicted: True,
                    EvidenceState.out_of_scope: False,
                    EvidenceState.error: False,
                }
            else:
                expected_mutation_roles = {
                    EvidenceState.inconclusive: False,
                    EvidenceState.out_of_scope: False,
                    EvidenceState.error: False,
                }
            if expected_mutation_roles.get(self.state) is not self.verdict_bearing:
                raise ValueError("mutation-result evidence state and verdict role must be coherent")
        if self.evidence_type is EvidenceGraphEvidenceType.gate_decision:
            if (
                self.state
                not in {
                    EvidenceState.supported,
                    EvidenceState.violated,
                    EvidenceState.inconclusive,
                }
                or not self.verdict_bearing
            ):
                raise ValueError("gate-decision evidence state and verdict role must be coherent")
        return self


class EvidenceGraphFindingPayload(FrozenStrictModel):
    payload_kind: Literal["finding"] = "finding"
    finding_type: EvidenceGraphFindingType
    source_artifact_kind: MachineIdentifier
    source_id: GraphSourceId
    source_path: ExactJsonPointer
    state: EvidenceState
    verdict_bearing: bool
    reason_codes: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_GRAPH_REASON_CODES,
    )
    references: tuple[EvidenceGraphReference, ...] = Field(
        default=(),
        max_length=MAX_GRAPH_REFERENCES,
    )
    gate_effect: GateEffect | None = None
    required: bool | None = None
    critical: bool | None = None
    independently_challenged: bool | None = None
    messages: tuple[GraphMessage, ...] = Field(
        default=(),
        max_length=MAX_GRAPH_MESSAGES,
    )

    @field_validator("finding_type", mode="before")
    @classmethod
    def _coerce_finding_type(cls, value: object) -> EvidenceGraphFindingType:
        return coerce_enum(EvidenceGraphFindingType, value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> EvidenceState:
        return coerce_enum(EvidenceState, value)

    @field_validator("gate_effect", mode="before")
    @classmethod
    def _coerce_gate_effect(cls, value: object) -> GateEffect | None:
        if value is None:
            return None
        return coerce_enum(GateEffect, value)

    @field_validator("reason_codes", "references", "messages", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_set_order(self) -> Self:
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("graph finding reason codes must be unique and sorted")
        _require_canonical_references(self.references)
        matched_markers = _reference_values(
            self.references,
            EvidenceGraphReferenceRole.matched_finding,
        )
        observed_finding = self.finding_type is EvidenceGraphFindingType.mutation_observed_finding
        if observed_finding:
            if matched_markers not in {(), (self.source_id,)} or (
                self.verdict_bearing and not matched_markers
            ):
                raise ValueError("mutation observed-finding verdict role must match its marker")
        elif matched_markers:
            raise ValueError("matched-finding references belong only to mutation observations")
        if self.finding_type is EvidenceGraphFindingType.evaluation:
            if self.state not in {
                EvidenceState.violated,
                EvidenceState.inconclusive,
                EvidenceState.not_evaluated,
            } or self.verdict_bearing is (self.state is EvidenceState.not_evaluated):
                raise ValueError("evaluation finding state and verdict role must be coherent")
        if self.finding_type in {
            EvidenceGraphFindingType.comparison_provenance,
            EvidenceGraphFindingType.limitation,
        } and (self.state, self.verdict_bearing) != (
            EvidenceState.inconclusive,
            False,
        ):
            raise ValueError("non-verdict graph finding state contradicts its declared type")
        if self.finding_type is EvidenceGraphFindingType.limitation and self.reason_codes != (
            EvidenceGraphProjectionReason.evidence_scope_limitation.value,
        ):
            raise ValueError("limitation finding requires its exact registered reason")
        if self.finding_type is EvidenceGraphFindingType.evidence_sensitivity_outcome:
            try:
                tuple(EvidenceSensitivityReasonCode(item) for item in self.reason_codes)
            except ValueError as exc:
                raise ValueError("evidence-sensitivity finding reason is not registered") from exc
            if self.source_artifact_kind != "evidence-sensitivity-report":
                raise ValueError("evidence-sensitivity findings require their typed report source")
            if (self.state, self.verdict_bearing) not in {
                (EvidenceState.supported, True),
                (EvidenceState.violated, True),
                (EvidenceState.inconclusive, False),
                (EvidenceState.prerequisites_unmet, False),
            }:
                raise ValueError(
                    "evidence-sensitivity finding state and verdict role are incoherent"
                )
        gate_finding = self.finding_type is EvidenceGraphFindingType.control_efficacy_gate
        if (self.gate_effect is not None) is not gate_finding:
            raise ValueError("gate_effect belongs exactly to control-efficacy gate findings")
        if gate_finding:
            if len(self.reason_codes) != 1:
                raise ValueError("control-efficacy gate findings require one gate reason")
            try:
                ControlEfficacyGateReason(self.reason_codes[0])
            except ValueError as exc:
                raise ValueError("control-efficacy gate finding reason is not declared") from exc
            expected_gate_state = (
                EvidenceState.violated
                if self.gate_effect is GateEffect.block
                else EvidenceState.inconclusive
            )
            if self.state is not expected_gate_state or not self.verdict_bearing:
                raise ValueError("control-efficacy gate state must match its exact gate effect")
        outcome_finding = self.finding_type is EvidenceGraphFindingType.control_efficacy_outcome
        if (self.required is not None) is not outcome_finding:
            raise ValueError("required belongs exactly to control-efficacy outcome findings")
        threat_finding = self.finding_type is EvidenceGraphFindingType.control_efficacy_threat
        if (self.critical is not None) is not threat_finding or (
            (self.independently_challenged is not None) is not threat_finding
        ):
            raise ValueError(
                "critical and independently_challenged belong exactly to "
                "control-efficacy threat findings"
            )
        mutation_outcome = self.finding_type in {
            EvidenceGraphFindingType.mutation_result,
            EvidenceGraphFindingType.control_efficacy_outcome,
        }
        applicability_references = _reference_values(
            self.references,
            EvidenceGraphReferenceRole.applicability,
        )
        diagnostic_references = _reference_values(
            self.references,
            EvidenceGraphReferenceRole.diagnostic,
        )
        if applicability_references and not (outcome_finding or threat_finding):
            raise ValueError("applicability references are reserved for typed efficacy findings")
        if self.finding_type is EvidenceGraphFindingType.mutation_result:
            if len(diagnostic_references) > 1:
                raise ValueError("mutation-result findings allow at most one diagnostic")
        elif diagnostic_references:
            raise ValueError("diagnostic references belong only to mutation-result findings")
        if mutation_outcome:
            result_state = (
                _mutation_result_state_from_reason(self.reason_codes[0])
                if len(self.reason_codes) == 1
                else None
            )
            expected_roles = (
                {_deterministic_mutation_outcome_role(result_state)}
                if result_state is not None
                else set()
            )
            if self.finding_type is EvidenceGraphFindingType.mutation_result and result_state in {
                MutationResultState.caught,
                MutationResultState.survived,
            }:
                expected_roles.add((EvidenceState.inconclusive, False))
            if (self.state, self.verdict_bearing) not in expected_roles:
                raise ValueError("mutation outcome state must match its exact mutation reason")
        if outcome_finding:
            applicability = _reference_values(
                self.references,
                EvidenceGraphReferenceRole.applicability,
            )
            operators = _reference_values(
                self.references,
                EvidenceGraphReferenceRole.operator,
            )
            if len(applicability) != 1 or len(operators) != 1:
                raise ValueError("control-efficacy outcomes require one applicability and operator")
            invariant_families = _reference_values(
                self.references,
                EvidenceGraphReferenceRole.invariant_family,
            )
            independence_classes = _reference_values(
                self.references,
                EvidenceGraphReferenceRole.independence_class,
            )
            if (
                len(invariant_families) != 1
                or len(independence_classes) != 1
                or independence_classes[0] not in {item.value for item in INDEPENDENCE_CLASS_ORDER}
            ):
                raise ValueError("control-efficacy outcomes require one declared stratum identity")
            catalog_threats = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.threat,
                )
            )
            scoped_threats = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.scoped_threat,
                )
            )
            unscoped_threats = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.unscoped_threat,
                )
            )
            critical_threats = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.critical_threat,
                )
            )
            target_controls = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.control,
                )
            )
            present_controls = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.present_control,
                )
            )
            if (
                scoped_threats & unscoped_threats
                or scoped_threats | unscoped_threats != catalog_threats
                or not critical_threats.issubset(scoped_threats)
                or not present_controls.issubset(target_controls)
            ):
                raise ValueError("control-efficacy outcome reference sets are inconsistent")
            mutation_applicability = MutationApplicability(applicability[0])
            result_state = _mutation_result_state_from_reason(self.reason_codes[0])
            if (
                result_state
                in {
                    MutationResultState.caught,
                    MutationResultState.survived,
                }
                and mutation_applicability is not MutationApplicability.applicable
            ):
                raise ValueError("verdict-bearing efficacy outcomes must be applicable")
            if result_state is MutationResultState.inapplicable and (
                mutation_applicability is not MutationApplicability.inapplicable
            ):
                raise ValueError("out-of-scope efficacy outcomes must be inapplicable")
            if result_state is MutationResultState.invalid_subject and (
                mutation_applicability is not MutationApplicability.not_evaluated
            ):
                raise ValueError("invalid-subject efficacy outcomes must not claim applicability")
            if (
                mutation_applicability is MutationApplicability.inapplicable
                and result_state is not MutationResultState.inapplicable
            ):
                raise ValueError(
                    "inapplicable efficacy applicability is reserved for inapplicable outcomes"
                )
        if threat_finding:
            applicability = _reference_values(
                self.references,
                EvidenceGraphReferenceRole.applicability,
            )
            threats = _reference_values(
                self.references,
                EvidenceGraphReferenceRole.threat,
            )
            challengers = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.operator,
                )
            )
            independent = set(
                _reference_values(
                    self.references,
                    EvidenceGraphReferenceRole.independent_challenger,
                )
            )
            if (
                len(applicability) != 1
                or len(threats) != 1
                or not independent.issubset(challengers)
            ):
                raise ValueError(
                    "efficacy threat findings require coherent applicability and challengers"
                )
            threat_applicability = ThreatApplicability(applicability[0])
            if threat_applicability is not ThreatApplicability.applicable and challengers:
                raise ValueError("non-applicable efficacy threats cannot claim challengers")
            expected_threat = {
                ThreatApplicability.not_applicable: (
                    EvidenceState.out_of_scope,
                    False,
                ),
                ThreatApplicability.unknown: (
                    EvidenceState.inconclusive,
                    False,
                ),
                ThreatApplicability.applicable: (
                    EvidenceState.supported if challengers else EvidenceState.contradicted,
                    True,
                ),
            }[threat_applicability]
            if (self.state, self.verdict_bearing) != expected_threat:
                raise ValueError("efficacy threat state must match applicability and challengers")
            expected_reason = (
                EvidenceGraphProjectionReason.threat_not_applicable
                if threat_applicability is ThreatApplicability.not_applicable
                else (
                    EvidenceGraphProjectionReason.threat_applicability_unknown
                    if threat_applicability is ThreatApplicability.unknown
                    else (
                        EvidenceGraphProjectionReason.threat_challenged
                        if challengers
                        else EvidenceGraphProjectionReason.threat_uncovered
                    )
                )
            )
            if self.reason_codes != (expected_reason.value,):
                raise ValueError("efficacy threat reason must match applicability and challengers")
            if self.independently_challenged is not bool(independent):
                raise ValueError("independent threat flag must match independent challengers")
        return self


EvidenceGraphPayload = Annotated[
    EvidenceGraphSubjectPayload
    | EvidenceGraphRequirementPayload
    | EvidenceGraphEvidencePayload
    | EvidenceGraphFindingPayload,
    Field(discriminator="payload_kind"),
]


def evidence_graph_identity_projection(
    payload: EvidenceGraphPayload,
    *,
    subject_node_id: str | None = None,
    parent_evidence_node_id: str | None = None,
) -> EvidenceGraphIdentityProjection:
    if isinstance(payload, EvidenceGraphSubjectPayload):
        if subject_node_id is not None or parent_evidence_node_id is not None:
            raise ValueError("subject identity cannot carry graph topology")
        return EvidenceGraphSubjectIdentityProjection(
            subject_type=payload.subject_type,
            subject_id=payload.subject_id,
            subject_digest=payload.subject_digest,
        )
    if subject_node_id is None:
        raise ValueError("non-subject identity requires its scoped subject")
    if isinstance(payload, EvidenceGraphRequirementPayload):
        if parent_evidence_node_id is not None:
            raise ValueError("requirement identity cannot carry an evidence parent")
        return EvidenceGraphRequirementIdentityProjection(
            subject_node_id=subject_node_id,
            requirement_type=payload.requirement_type,
            requirement_id=payload.requirement_id,
        )
    if isinstance(payload, EvidenceGraphEvidencePayload):
        if parent_evidence_node_id is not None:
            raise ValueError("evidence identity cannot carry an evidence parent")
        return EvidenceGraphEvidenceIdentityProjection(
            subject_node_id=subject_node_id,
            evidence_type=payload.evidence_type,
            source_artifact_kind=payload.source_artifact_kind,
            source_id=payload.source_id,
        )
    if parent_evidence_node_id is None:
        raise ValueError("finding identity requires its parent evidence")
    return EvidenceGraphFindingIdentityProjection(
        subject_node_id=subject_node_id,
        parent_evidence_node_id=parent_evidence_node_id,
        finding_type=payload.finding_type,
        source_artifact_kind=payload.source_artifact_kind,
        source_id=payload.source_id,
        source_path=payload.source_path,
    )


def calculate_evidence_graph_node_id(
    identity: EvidenceGraphIdentityProjection,
) -> str:
    digest = _canonical_sha256(
        {
            "domain": "agent-assure/assurance-evidence-graph-node/v1",
            "kind": identity.identity_kind,
            "identity": identity.model_dump(mode="json"),
        }
    )
    return f"{identity.identity_kind}:{digest}"


class EvidenceGraphNode(FrozenStrictModel):
    node_id: GraphNodeId
    kind: EvidenceGraphNodeKind
    identity: EvidenceGraphIdentityProjection
    payload_digest: DigestHex
    payload: EvidenceGraphPayload

    @field_validator("kind", mode="before")
    @classmethod
    def _coerce_kind(cls, value: object) -> EvidenceGraphNodeKind:
        return coerce_enum(EvidenceGraphNodeKind, value)

    @model_validator(mode="after")
    def _validate_payload(self) -> Self:
        if self.kind.value != self.identity.identity_kind:
            raise ValueError("graph node kind must match its identity projection")
        expected_node_id = calculate_evidence_graph_node_id(self.identity)
        if self.node_id != expected_node_id:
            raise ValueError("graph node ID does not match its canonical identity projection")
        expected_identity = evidence_graph_identity_projection(
            self.payload,
            subject_node_id=(
                self.identity.subject_node_id
                if not isinstance(self.identity, EvidenceGraphSubjectIdentityProjection)
                else None
            ),
            parent_evidence_node_id=(
                self.identity.parent_evidence_node_id
                if isinstance(self.identity, EvidenceGraphFindingIdentityProjection)
                else None
            ),
        )
        if self.identity != expected_identity:
            raise ValueError("graph identity projection contradicts its typed payload")
        if self.kind.value != self.payload.payload_kind:
            raise ValueError("graph node kind must match its typed payload")
        if not self.node_id.startswith(f"{self.kind.value}:"):
            raise ValueError("graph node ID prefix must match its node kind")
        expected = _canonical_sha256(self.payload.model_dump(mode="json"))
        if self.payload_digest != expected:
            raise ValueError("graph node payload_digest does not match its canonical payload")
        return self

    @classmethod
    def build(
        cls,
        *,
        kind: EvidenceGraphNodeKind,
        payload: EvidenceGraphPayload,
        subject_node_id: GraphNodeId | None = None,
        parent_evidence_node_id: GraphNodeId | None = None,
    ) -> Self:
        identity = evidence_graph_identity_projection(
            payload,
            subject_node_id=subject_node_id,
            parent_evidence_node_id=parent_evidence_node_id,
        )
        return cls(
            node_id=calculate_evidence_graph_node_id(identity),
            kind=kind,
            identity=identity,
            payload_digest=_canonical_sha256(payload.model_dump(mode="json")),
            payload=payload,
        )


class EvidenceGraphEdge(FrozenStrictModel):
    kind: EvidenceGraphEdgeKind
    source_node_id: GraphNodeId
    target_node_id: GraphNodeId

    @field_validator("kind", mode="before")
    @classmethod
    def _coerce_kind(cls, value: object) -> EvidenceGraphEdgeKind:
        return coerce_enum(EvidenceGraphEdgeKind, value)

    @model_validator(mode="after")
    def _reject_self_edge(self) -> Self:
        if self.source_node_id == self.target_node_id:
            raise ValueError("graph edges cannot be self-referential")
        return self


class EvidenceGraphFieldCompatibility(FrozenStrictModel):
    source_path: ExactJsonPointer
    verdict_bearing: bool
    disposition: EvidenceGraphProjectionDisposition
    target_node_kinds: tuple[EvidenceGraphNodeKind, ...] = ()
    reason_code: MachineIdentifier | None = None

    @field_validator("disposition", mode="before")
    @classmethod
    def _coerce_disposition(cls, value: object) -> EvidenceGraphProjectionDisposition:
        return coerce_enum(EvidenceGraphProjectionDisposition, value)

    @field_validator("target_node_kinds", mode="before")
    @classmethod
    def _coerce_target_kinds(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(coerce_enum(EvidenceGraphNodeKind, item) for item in value)
        if isinstance(value, tuple):
            return tuple(coerce_enum(EvidenceGraphNodeKind, item) for item in value)
        return value

    @model_validator(mode="after")
    def _validate_disposition(self) -> Self:
        expected_kinds = tuple(sorted(set(self.target_node_kinds), key=lambda item: item.value))
        if self.target_node_kinds != expected_kinds:
            raise ValueError("compatibility target node kinds must be unique and sorted")
        if self.disposition is EvidenceGraphProjectionDisposition.represented:
            if not self.target_node_kinds or self.reason_code is not None:
                raise ValueError(
                    "represented packet fields require target node kinds and no reason code"
                )
            return self
        if self.verdict_bearing:
            raise ValueError("verdict-bearing legacy packet fields cannot be unsupported")
        if self.target_node_kinds or self.reason_code is None:
            raise ValueError(
                "unsupported packet fields require a reason code and no target node kinds"
            )
        return self


LegacyPacketSchemaVersion = Literal["0.5.0", "0.6.0", "0.6.1", "0.6.2"]
LEGACY_PACKET_SCHEMA_VERSIONS: tuple[LegacyPacketSchemaVersion, ...] = (
    "0.5.0",
    "0.6.0",
    "0.6.1",
    "0.6.2",
)
LEGACY_PACKET_FIELD_PATHS = (
    "/artifact_digests",
    "/artifact_kind",
    "/comparison",
    "/control_efficacy",
    "/control_efficacy_gate",
    "/control_efficacy_gate_profile",
    "/environment",
    "/evaluation",
    "/interpretation",
    "/limitations",
    "/packet_id",
    "/release_manifest",
    "/schema_version",
    "/usage_summary",
)


class EvidenceGraphCompatibilityManifest(FrozenStrictModel):
    contract_id: Literal["EvidencePacketGraphProjection/v1"] = "EvidencePacketGraphProjection/v1"
    source_artifact_kind: Literal["evidence-packet"] = "evidence-packet"
    projection_scope: Literal["decision_fields"] = "decision_fields"
    source_schema_versions: tuple[LegacyPacketSchemaVersion, ...] = LEGACY_PACKET_SCHEMA_VERSIONS
    fields: tuple[EvidenceGraphFieldCompatibility, ...] = Field(
        min_length=len(LEGACY_PACKET_FIELD_PATHS),
        max_length=len(LEGACY_PACKET_FIELD_PATHS),
    )

    @field_validator("source_schema_versions", "fields", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_completeness(self) -> Self:
        if self.source_schema_versions != LEGACY_PACKET_SCHEMA_VERSIONS:
            raise ValueError("legacy packet schema versions must be complete and canonical")
        paths = tuple(item.source_path for item in self.fields)
        if paths != LEGACY_PACKET_FIELD_PATHS:
            raise ValueError("legacy packet compatibility fields must be complete and sorted")
        return self


_EDGE_SHAPES: dict[
    EvidenceGraphEdgeKind,
    tuple[frozenset[EvidenceGraphNodeKind], frozenset[EvidenceGraphNodeKind]],
] = {
    EvidenceGraphEdgeKind.supports: (
        frozenset({EvidenceGraphNodeKind.evidence, EvidenceGraphNodeKind.finding}),
        frozenset({EvidenceGraphNodeKind.requirement}),
    ),
    EvidenceGraphEdgeKind.contradicts: (
        frozenset({EvidenceGraphNodeKind.evidence, EvidenceGraphNodeKind.finding}),
        frozenset({EvidenceGraphNodeKind.requirement}),
    ),
    EvidenceGraphEdgeKind.targets: (
        frozenset({EvidenceGraphNodeKind.finding}),
        frozenset({EvidenceGraphNodeKind.requirement}),
    ),
    EvidenceGraphEdgeKind.derived_from: (
        frozenset({EvidenceGraphNodeKind.finding}),
        frozenset({EvidenceGraphNodeKind.evidence}),
    ),
    EvidenceGraphEdgeKind.scoped_to: (
        frozenset(
            {
                EvidenceGraphNodeKind.requirement,
                EvidenceGraphNodeKind.evidence,
                EvidenceGraphNodeKind.finding,
            }
        ),
        frozenset({EvidenceGraphNodeKind.subject}),
    ),
}


class AssuranceEvidenceGraph(SelfDigestedArtifact):
    _digest_field = "graph_digest"

    artifact_kind: Literal["assurance-evidence-graph"] = "assurance-evidence-graph"
    schema_version: Literal["0.6.3", "0.6.4"] = GRAPH_SCHEMA_VERSION
    schema_name: Literal["assurance-evidence-graph"] = "assurance-evidence-graph"
    contract_id: Literal["AssuranceEvidenceGraph/v1"] = GRAPH_CONTRACT_ID
    contract_version: Literal["1.0.0"] = GRAPH_CONTRACT_VERSION
    graph_digest: DigestHex
    primary_subject_node_id: GraphNodeId = Field(
        description=(
            "Primary subject identity anchor. A graph may contain separate digest-scoped "
            "components, so this is not a complete traversal root and does not imply that "
            "gate-decision evidence is reachable from it."
        )
    )
    nodes: tuple[EvidenceGraphNode, ...] = Field(min_length=1, max_length=MAX_GRAPH_NODES)
    edges: tuple[EvidenceGraphEdge, ...] = Field(default=(), max_length=MAX_GRAPH_EDGES)
    compatibility: EvidenceGraphCompatibilityManifest
    limitations: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_GRAPH_LIMITATIONS,
    )

    @field_validator("nodes", "edges", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_graph(self) -> Self:
        if self.schema_version != GRAPH_SCHEMA_VERSION and any(
            (
                isinstance(node.payload, EvidenceGraphEvidencePayload)
                and (
                    node.payload.evidence_type is EvidenceGraphEvidenceType.evidence_sensitivity
                    or node.payload.evidence_sensitivity_projection is not None
                )
            )
            or (
                isinstance(node.payload, EvidenceGraphFindingPayload)
                and node.payload.finding_type
                is EvidenceGraphFindingType.evidence_sensitivity_outcome
            )
            or (
                isinstance(node.payload, EvidenceGraphRequirementPayload)
                and node.payload.requirement_type
                is EvidenceGraphRequirementType.expected_decision_response
            )
            for node in self.nodes
        ):
            raise ValueError(
                "evidence-sensitivity graph content requires schema_version "
                f"{GRAPH_SCHEMA_VERSION!r}"
            )
        expected_nodes = tuple(sorted(self.nodes, key=evidence_graph_node_sort_key))
        if self.nodes != expected_nodes:
            raise ValueError("graph nodes must use canonical kind-and-ID ordering")
        node_ids = tuple(node.node_id for node in self.nodes)
        if len(set(node_ids)) != len(node_ids):
            raise ValueError("graph node IDs must be unique")
        nodes_by_id = {node.node_id: node for node in self.nodes}
        primary = nodes_by_id.get(self.primary_subject_node_id)
        if primary is None or primary.kind is not EvidenceGraphNodeKind.subject:
            raise ValueError("primary_subject_node_id must reference a present subject node")

        expected_edges = tuple(sorted(self.edges, key=evidence_graph_edge_sort_key))
        if self.edges != expected_edges:
            raise ValueError("graph edges must use canonical kind-and-endpoint ordering")
        edge_keys = tuple(evidence_graph_edge_sort_key(edge) for edge in self.edges)
        if len(set(edge_keys)) != len(edge_keys):
            raise ValueError("graph edges must be unique")
        node_scopes: dict[str, list[str]] = {}
        for edge in self.edges:
            source = nodes_by_id.get(edge.source_node_id)
            target = nodes_by_id.get(edge.target_node_id)
            if source is None or target is None:
                raise ValueError("graph edges cannot reference missing nodes")
            allowed_sources, allowed_targets = _EDGE_SHAPES[edge.kind]
            if source.kind not in allowed_sources or target.kind not in allowed_targets:
                raise ValueError(f"graph edge {edge.kind.value} has invalid endpoint kinds")
            if edge.kind is EvidenceGraphEdgeKind.scoped_to:
                node_scopes.setdefault(edge.source_node_id, []).append(edge.target_node_id)
            if edge.kind in {
                EvidenceGraphEdgeKind.supports,
                EvidenceGraphEdgeKind.contradicts,
            }:
                source_payload = source.payload
                if not isinstance(
                    source_payload,
                    EvidenceGraphEvidencePayload | EvidenceGraphFindingPayload,
                ):
                    raise ValueError("semantic graph edges require evidence or findings")
                expected_states = (
                    {EvidenceState.supported}
                    if edge.kind is EvidenceGraphEdgeKind.supports
                    else {EvidenceState.contradicted, EvidenceState.violated}
                )
                if (
                    source_payload.state not in expected_states
                    or not source_payload.verdict_bearing
                ):
                    raise ValueError(
                        "semantic graph edge contradicts its source state or verdict role"
                    )
        for node in self.nodes:
            if node.kind is EvidenceGraphNodeKind.subject:
                continue
            if len(node_scopes.get(node.node_id, ())) != 1:
                raise ValueError("every non-subject graph node must have exactly one subject scope")
        for node in self.nodes:
            if node.kind is EvidenceGraphNodeKind.subject:
                continue
            if isinstance(node.identity, EvidenceGraphSubjectIdentityProjection):
                raise ValueError("non-subject node cannot carry subject identity")
            if node.identity.subject_node_id != node_scopes[node.node_id][0]:
                raise ValueError("graph identity subject must match its scoped-to relationship")
        for edge in self.edges:
            if edge.kind not in {
                EvidenceGraphEdgeKind.supports,
                EvidenceGraphEdgeKind.contradicts,
                EvidenceGraphEdgeKind.targets,
                EvidenceGraphEdgeKind.derived_from,
            }:
                continue
            if node_scopes[edge.source_node_id][0] != node_scopes[edge.target_node_id][0]:
                raise ValueError("graph relationship edges cannot cross subject scopes")
        derived_targets: dict[str, list[EvidenceGraphNode]] = {}
        derived_children: dict[str, list[EvidenceGraphNode]] = {}
        for edge in self.edges:
            if edge.kind is EvidenceGraphEdgeKind.derived_from:
                derived_targets.setdefault(edge.source_node_id, []).append(
                    nodes_by_id[edge.target_node_id]
                )
                derived_children.setdefault(edge.target_node_id, []).append(
                    nodes_by_id[edge.source_node_id]
                )
        for node in self.nodes:
            payload = node.payload
            if not isinstance(payload, EvidenceGraphFindingPayload):
                continue
            parents = derived_targets.get(node.node_id, [])
            if len(parents) != 1 or not isinstance(
                parents[0].payload,
                EvidenceGraphEvidencePayload,
            ):
                raise ValueError("graph findings require exactly one source evidence")
            parent = parents[0].payload
            if not isinstance(node.identity, EvidenceGraphFindingIdentityProjection):
                raise ValueError("finding node requires a finding identity projection")
            if node.identity.parent_evidence_node_id != parents[0].node_id:
                raise ValueError("finding identity parent must match its derived-from relationship")
            expected_parent_types = {
                EvidenceGraphFindingType.evaluation: (EvidenceGraphEvidenceType.evaluation),
                EvidenceGraphFindingType.comparison_verdict: (EvidenceGraphEvidenceType.comparison),
                EvidenceGraphFindingType.comparison_provenance: (
                    EvidenceGraphEvidenceType.comparison
                ),
                EvidenceGraphFindingType.mutation_result: (
                    EvidenceGraphEvidenceType.mutation_result
                ),
                EvidenceGraphFindingType.mutation_observed_finding: (
                    EvidenceGraphEvidenceType.mutation_result
                ),
                EvidenceGraphFindingType.control_efficacy_outcome: (
                    EvidenceGraphEvidenceType.control_efficacy
                ),
                EvidenceGraphFindingType.control_efficacy_threat: (
                    EvidenceGraphEvidenceType.control_efficacy
                ),
                EvidenceGraphFindingType.control_efficacy_gate: (
                    EvidenceGraphEvidenceType.gate_decision
                ),
                EvidenceGraphFindingType.evidence_sensitivity_outcome: (
                    EvidenceGraphEvidenceType.evidence_sensitivity
                ),
            }
            expected_parent = expected_parent_types.get(payload.finding_type)
            if expected_parent is not None and parent.evidence_type is not expected_parent:
                raise ValueError("graph finding derives from an incompatible evidence type")
            if payload.finding_type is EvidenceGraphFindingType.mutation_result:
                if parent.evaluation_basis is None:
                    raise ValueError("mutation outcome parent requires an evaluation basis")
                result_state = _mutation_result_state_from_reason(payload.reason_codes[0])
                expected_role = _deterministic_mutation_outcome_role(result_state)
                if (
                    result_state in {MutationResultState.caught, MutationResultState.survived}
                    and parent.evaluation_basis is not EvidenceEvaluationBasis.deterministic
                ):
                    expected_role = (EvidenceState.inconclusive, False)
                if (parent.state, parent.verdict_bearing) != expected_role or (
                    payload.state,
                    payload.verdict_bearing,
                ) != expected_role:
                    raise ValueError(
                        "mutation outcome and evidence must match result basis and reason"
                    )
                continue
            if payload.finding_type is EvidenceGraphFindingType.mutation_observed_finding:
                matched = bool(
                    _reference_values(
                        payload.references,
                        EvidenceGraphReferenceRole.matched_finding,
                    )
                )
                expected_verdict = (
                    matched and parent.evaluation_basis is EvidenceEvaluationBasis.deterministic
                )
                if payload.verdict_bearing is not expected_verdict:
                    raise ValueError(
                        "mutation observation verdict role must match its parent basis"
                    )
                continue
            if payload.finding_type is EvidenceGraphFindingType.comparison_verdict:
                if (
                    payload.state is not parent.state
                    or payload.verdict_bearing is not parent.verdict_bearing
                ):
                    raise ValueError("comparison finding must match its comparison evidence")
                continue
            if payload.finding_type is not EvidenceGraphFindingType.control_efficacy_outcome:
                continue
            if parent.control_efficacy_projection is None:
                raise ValueError("efficacy outcome must derive from control-efficacy evidence")
            operators = _reference_values(
                payload.references,
                EvidenceGraphReferenceRole.operator,
            )
            expected_required = (
                operators[0] in parent.control_efficacy_projection.required_operator_ids
            )
            if payload.required is not expected_required:
                raise ValueError("efficacy outcome required flag contradicts its report projection")
        for node in self.nodes:
            payload = node.payload
            if not isinstance(payload, EvidenceGraphEvidencePayload):
                continue
            children = derived_children.get(node.node_id, [])
            if payload.evidence_type is EvidenceGraphEvidenceType.evaluation:
                evaluation_findings = tuple(
                    child.payload
                    for child in children
                    if isinstance(child.payload, EvidenceGraphFindingPayload)
                    and child.payload.finding_type is EvidenceGraphFindingType.evaluation
                )
                expected_state = _evaluation_aggregate_state(evaluation_findings)
                if expected_state is not None and (
                    payload.state is not expected_state
                    or payload.verdict_bearing is (expected_state is EvidenceState.not_evaluated)
                ):
                    raise ValueError("evaluation evidence must match its aggregate findings")
            if payload.evidence_type is EvidenceGraphEvidenceType.mutation_result:
                mutation_outcomes = tuple(
                    child.payload
                    for child in children
                    if isinstance(child.payload, EvidenceGraphFindingPayload)
                    and child.payload.finding_type is EvidenceGraphFindingType.mutation_result
                )
                if len(mutation_outcomes) != 1:
                    raise ValueError(
                        "mutation-result evidence requires exactly one outcome finding"
                    )
            if payload.evidence_type is EvidenceGraphEvidenceType.evidence_sensitivity:
                sensitivity_outcomes = tuple(
                    child.payload
                    for child in children
                    if isinstance(child.payload, EvidenceGraphFindingPayload)
                    and child.payload.finding_type
                    is EvidenceGraphFindingType.evidence_sensitivity_outcome
                )
                if len(sensitivity_outcomes) != 1:
                    raise ValueError(
                        "evidence-sensitivity evidence requires exactly one outcome finding"
                    )
                sensitivity_projection = payload.evidence_sensitivity_projection
                if sensitivity_projection is None:
                    raise ValueError("evidence-sensitivity outcome requires its typed projection")
                outcome = sensitivity_outcomes[0]
                if (
                    outcome.state,
                    outcome.verdict_bearing,
                    outcome.reason_codes,
                ) != (
                    payload.state,
                    payload.verdict_bearing,
                    tuple(item.value for item in sensitivity_projection.reason_codes),
                ):
                    raise ValueError(
                        "evidence-sensitivity outcome must match its report projection"
                    )
                expected_outcome_message = derive_sensitivity_outcome_message(
                    classification=sensitivity_projection.outcome_classification,
                    state=sensitivity_projection.state,
                    observed_relation=sensitivity_projection.observed_relation,
                    baseline_expected_decision=(sensitivity_projection.baseline_expected_decision),
                    counterfactual_expected_decision=(
                        sensitivity_projection.counterfactual_expected_decision
                    ),
                    baseline_observed_decision=(sensitivity_projection.baseline_observed_decision),
                    counterfactual_observed_decision=(
                        sensitivity_projection.counterfactual_observed_decision
                    ),
                )
                if outcome.messages != (expected_outcome_message,):
                    raise ValueError(
                        "evidence-sensitivity outcome message must match its typed projection"
                    )
                limitation_findings = tuple(
                    child.payload
                    for child in children
                    if isinstance(child.payload, EvidenceGraphFindingPayload)
                    and child.payload.finding_type is EvidenceGraphFindingType.limitation
                )
                expected_limitations = {
                    f"/limitations/{index}": (
                        f"limitation-{index}",
                        payload.source_artifact_kind,
                        (limitation,),
                    )
                    for index, limitation in enumerate(payload.limitations)
                }
                observed_limitations = {
                    finding.source_path: (
                        finding.source_id,
                        finding.source_artifact_kind,
                        finding.messages,
                    )
                    for finding in limitation_findings
                }
                if observed_limitations != expected_limitations:
                    raise ValueError(
                        "evidence-sensitivity limitations require exact finding projections"
                    )
        for node in self.nodes:
            payload = node.payload
            if (
                not isinstance(payload, EvidenceGraphEvidencePayload)
                or payload.evidence_type is not EvidenceGraphEvidenceType.control_efficacy
                or payload.control_efficacy_projection is None
            ):
                continue
            projection = payload.control_efficacy_projection
            children = derived_children.get(node.node_id, [])
            outcomes = tuple(
                child.payload
                for child in children
                if isinstance(child.payload, EvidenceGraphFindingPayload)
                and child.payload.finding_type is EvidenceGraphFindingType.control_efficacy_outcome
            )
            outcome_operators = tuple(
                _reference_values(
                    outcome.references,
                    EvidenceGraphReferenceRole.operator,
                )[0]
                for outcome in outcomes
            )
            expected_operators = tuple(
                sorted(set(projection.selected_operator_ids) - set(projection.pending_operator_ids))
            )
            if (
                len(set(outcome_operators)) != len(outcome_operators)
                or tuple(sorted(outcome_operators)) != expected_operators
            ):
                raise ValueError("efficacy outcome findings must exactly cover evaluated operators")
            result_states = tuple(
                _mutation_result_state_from_reason(outcome.reason_codes[0]) for outcome in outcomes
            )
            observed_counts = MutationStateCounts(
                caught=result_states.count(MutationResultState.caught),
                survived=result_states.count(MutationResultState.survived),
                inapplicable=result_states.count(MutationResultState.inapplicable),
                invalid_operator=result_states.count(MutationResultState.invalid_operator),
                invalid_subject=result_states.count(MutationResultState.invalid_subject),
                execution_error=result_states.count(MutationResultState.execution_error),
            )
            if observed_counts != projection.state_counts:
                raise ValueError(
                    "efficacy outcome findings must exactly match projected state counts"
                )
            outcome_by_operator = dict(zip(outcome_operators, outcomes, strict=True))
            state_by_operator = {
                operator_id: _mutation_result_state_from_reason(outcome.reason_codes[0])
                for operator_id, outcome in outcome_by_operator.items()
            }
            completed_states = {
                MutationResultState.caught,
                MutationResultState.survived,
            }
            (
                states_by_invariant_family,
                states_by_independence_class,
                challengers_by_threat,
                independent_challengers_by_threat,
                unscoped_threat_ids,
                references_by_operator,
            ) = _index_efficacy_outcomes(
                outcome_by_operator,
                state_by_operator,
            )
            required_survivors = tuple(
                sorted(
                    operator_id
                    for operator_id, outcome in outcome_by_operator.items()
                    if outcome.required
                    and state_by_operator[operator_id] is MutationResultState.survived
                )
            )
            critical_survivors = tuple(
                sorted(
                    operator_id
                    for operator_id, outcome in outcome_by_operator.items()
                    if references_by_operator[operator_id].get(
                        EvidenceGraphReferenceRole.critical_threat,
                        (),
                    )
                    and state_by_operator[operator_id] is MutationResultState.survived
                )
            )
            required_not_evaluated = tuple(
                operator_id
                for operator_id in projection.required_operator_ids
                if operator_id not in state_by_operator
                or state_by_operator[operator_id] not in completed_states
            )
            invalid_states = {
                MutationResultState.invalid_operator,
                MutationResultState.invalid_subject,
                MutationResultState.execution_error,
            }
            invalid_or_error = tuple(
                sorted(
                    operator_id
                    for operator_id, state in state_by_operator.items()
                    if state in invalid_states
                )
            )
            if (
                required_survivors != projection.required_survivor_operator_ids
                or critical_survivors != projection.critical_survivor_operator_ids
                or required_not_evaluated != projection.required_not_evaluated_operator_ids
                or invalid_or_error != projection.invalid_or_error_operator_ids
                or len(required_survivors) != projection.required_survivor_count
                or len(critical_survivors) != projection.critical_survivor_count
            ):
                raise ValueError("efficacy outcome findings must match projected diagnostic sets")
            for stratum in projection.kill_rate_by_invariant_family:
                stratum_states = tuple(states_by_invariant_family.get(stratum.stratum, ()))
                if _mutation_state_counts_from_states(stratum_states) != stratum.state_counts:
                    raise ValueError("efficacy invariant-family strata must match outcome evidence")
            for stratum in projection.kill_rate_by_independence_class:
                stratum_states = tuple(states_by_independence_class.get(stratum.stratum, ()))
                if _mutation_state_counts_from_states(stratum_states) != stratum.state_counts:
                    raise ValueError("efficacy independence strata must match outcome evidence")
            threats = tuple(
                child.payload
                for child in children
                if isinstance(child.payload, EvidenceGraphFindingPayload)
                and child.payload.finding_type is EvidenceGraphFindingType.control_efficacy_threat
            )
            threat_ids = tuple(
                _reference_values(
                    threat.references,
                    EvidenceGraphReferenceRole.threat,
                )[0]
                for threat in threats
            )
            if (
                len(set(threat_ids)) != len(threat_ids)
                or tuple(sorted(threat_ids)) != projection.threat_coverage_ids
            ):
                raise ValueError("efficacy threat findings must exactly cover projected threats")
            threat_by_id = dict(zip(threat_ids, threats, strict=True))
            applicable_ids = {
                threat_id
                for threat_id, threat in threat_by_id.items()
                if _single_threat_applicability(threat) is ThreatApplicability.applicable
            }
            unknown_ids = {
                threat_id
                for threat_id, threat in threat_by_id.items()
                if _single_threat_applicability(threat) is ThreatApplicability.unknown
            }
            challenged_ids = {
                threat_id
                for threat_id, threat in threat_by_id.items()
                if _reference_values(
                    threat.references,
                    EvidenceGraphReferenceRole.operator,
                )
            }
            independent_ids = {
                threat_id
                for threat_id, threat in threat_by_id.items()
                if threat.independently_challenged
            }
            critical_uncovered_ids = {
                threat_id
                for threat_id, threat in threat_by_id.items()
                if (
                    threat.critical
                    and threat_id in applicable_ids
                    and threat_id not in challenged_ids
                )
            }
            for threat_id, threat in threat_by_id.items():
                is_applicable = (
                    _single_threat_applicability(threat) is ThreatApplicability.applicable
                )
                expected_challengers = (
                    tuple(sorted(challengers_by_threat.get(threat_id, ()))) if is_applicable else ()
                )
                expected_independent = (
                    tuple(sorted(independent_challengers_by_threat.get(threat_id, ())))
                    if is_applicable
                    else ()
                )
                if (
                    _reference_values(
                        threat.references,
                        EvidenceGraphReferenceRole.operator,
                    )
                    != expected_challengers
                    or _reference_values(
                        threat.references,
                        EvidenceGraphReferenceRole.independent_challenger,
                    )
                    != expected_independent
                ):
                    raise ValueError("efficacy threat challengers must match outcome evidence")
            unscoped_threats = tuple(sorted(unscoped_threat_ids))
            if (
                len(applicable_ids) != projection.applicable_threat_category_count
                or len(challenged_ids) != projection.challenged_threat_category_count
                or len(independent_ids) != projection.independently_challenged_threat_category_count
                or tuple(sorted(unknown_ids)) != projection.unknown_applicability_threat_ids
                or tuple(sorted(critical_uncovered_ids)) != projection.critical_uncovered_threat_ids
                or unscoped_threats != projection.unscoped_catalog_threat_ids
            ):
                raise ValueError(
                    "efficacy threat findings must match projected coverage aggregates"
                )
        for node in self.nodes:
            payload = node.payload
            if (
                not isinstance(payload, EvidenceGraphEvidencePayload)
                or payload.evidence_type is not EvidenceGraphEvidenceType.gate_decision
            ):
                continue
            gate_findings = tuple(
                child.payload
                for child in derived_children.get(node.node_id, [])
                if isinstance(child.payload, EvidenceGraphFindingPayload)
                and child.payload.finding_type is EvidenceGraphFindingType.control_efficacy_gate
            )
            reasons = tuple(finding.reason_codes[0] for finding in gate_findings)
            if len(set(reasons)) != len(reasons):
                raise ValueError("gate-decision findings must have unique reasons")
            effects = tuple(finding.gate_effect for finding in gate_findings)
            expected_state = (
                EvidenceState.violated
                if GateEffect.block in effects
                else (
                    EvidenceState.inconclusive
                    if GateEffect.review in effects
                    else EvidenceState.supported
                )
            )
            if payload.state is not expected_state:
                raise ValueError("gate-decision evidence state must match child finding effects")
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("graph limitations must be unique and sorted")
        return self

    @classmethod
    def from_parts(
        cls,
        *,
        primary_subject_node_id: GraphNodeId,
        nodes: tuple[EvidenceGraphNode, ...],
        edges: tuple[EvidenceGraphEdge, ...],
        compatibility: EvidenceGraphCompatibilityManifest,
        limitations: tuple[BoundedSummary, ...],
    ) -> Self:
        return super().build(
            primary_subject_node_id=primary_subject_node_id,
            nodes=tuple(sorted(nodes, key=evidence_graph_node_sort_key)),
            edges=tuple(sorted(edges, key=evidence_graph_edge_sort_key)),
            compatibility=compatibility,
            limitations=tuple(sorted(set(limitations))),
        )


def evidence_graph_node_sort_key(node: EvidenceGraphNode) -> tuple[str, str]:
    return (node.kind.value, node.node_id)


def evidence_graph_edge_sort_key(edge: EvidenceGraphEdge) -> tuple[str, str, str]:
    return (edge.kind.value, edge.source_node_id, edge.target_node_id)


def calculate_evidence_graph_digest(
    value: AssuranceEvidenceGraph | Mapping[str, object],
) -> str:
    """Calculate the graph digest from an explicitly digest-free projection.

    Persisted graphs validate their own digest. Mapping callers must remove the
    field themselves so a digest value can never be accidentally hashed into
    its own identity.
    """
    if isinstance(value, AssuranceEvidenceGraph):
        digest_free = value.model_dump(mode="json", exclude={"graph_digest"})
    else:
        if "graph_digest" in value:
            raise ValueError("graph digest input must exclude graph_digest")
        digest_free = dict(value)
    try:
        validated = AssuranceEvidenceGraph.model_validate(
            {**digest_free, "graph_digest": "0" * 64},
            context={"skip_self_digest": True},
        )
    except RecursionError as exc:
        raise ValueError("graph digest input must be finite and acyclic") from exc
    projection = validated.model_dump(mode="json", exclude={"graph_digest"})
    return _canonical_sha256(projection)


def _require_canonical_references(references: tuple[EvidenceGraphReference, ...]) -> None:
    keys = tuple((item.role.value, item.value) for item in references)
    if keys != tuple(sorted(set(keys))):
        raise ValueError("graph references must be unique and canonically sorted")


def _reference_values(
    references: tuple[EvidenceGraphReference, ...],
    role: EvidenceGraphReferenceRole,
) -> tuple[str, ...]:
    return tuple(item.value for item in references if item.role is role)


def _mutation_result_state_from_reason(reason_code: str) -> MutationResultState:
    prefix = "MUTATION_"
    try:
        registered = EvidenceGraphProjectionReason(reason_code)
    except ValueError as exc:
        raise ValueError("mutation outcome reason is not registered") from exc
    if not registered.value.startswith(prefix):
        raise ValueError("mutation outcome reason must use the declared prefix")
    return MutationResultState(registered.value.removeprefix(prefix).lower())


def _deterministic_mutation_outcome_role(
    state: MutationResultState,
) -> tuple[EvidenceState, bool]:
    match state:
        case MutationResultState.caught:
            return EvidenceState.supported, True
        case MutationResultState.survived:
            return EvidenceState.contradicted, True
        case MutationResultState.inapplicable:
            return EvidenceState.out_of_scope, False
        case (
            MutationResultState.invalid_operator
            | MutationResultState.invalid_subject
            | MutationResultState.execution_error
        ):
            return EvidenceState.error, False
        case _ as unreachable:
            assert_never(unreachable)


def _evaluation_aggregate_state(
    findings: tuple[EvidenceGraphFindingPayload, ...],
) -> EvidenceState | None:
    states = {finding.state for finding in findings}
    if not states:
        return None
    if EvidenceState.violated in states:
        return EvidenceState.violated
    if EvidenceState.inconclusive in states:
        return EvidenceState.inconclusive
    if EvidenceState.not_evaluated in states:
        return EvidenceState.not_evaluated
    raise ValueError("evaluation findings contain an unsupported aggregate state")


def _single_threat_applicability(
    finding: EvidenceGraphFindingPayload,
) -> ThreatApplicability:
    values = _reference_values(
        finding.references,
        EvidenceGraphReferenceRole.applicability,
    )
    if len(values) != 1:
        raise ValueError("efficacy threat finding requires one applicability")
    return ThreatApplicability(values[0])


def _index_efficacy_outcomes(
    outcome_by_operator: Mapping[str, EvidenceGraphFindingPayload],
    state_by_operator: Mapping[str, MutationResultState],
) -> tuple[
    dict[str, tuple[MutationResultState, ...]],
    dict[str, tuple[MutationResultState, ...]],
    dict[str, frozenset[str]],
    dict[str, frozenset[str]],
    frozenset[str],
    dict[str, dict[EvidenceGraphReferenceRole, tuple[str, ...]]],
]:
    completed_states = {
        MutationResultState.caught,
        MutationResultState.survived,
    }
    independent_classes = {item.value for item in INDEPENDENT_CHALLENGE_CLASSES}
    states_by_invariant_family: dict[str, list[MutationResultState]] = {}
    states_by_independence_class: dict[str, list[MutationResultState]] = {}
    challengers_by_threat: dict[str, set[str]] = {}
    independent_challengers_by_threat: dict[str, set[str]] = {}
    unscoped_threat_ids: set[str] = set()
    references_by_operator: dict[
        str,
        dict[EvidenceGraphReferenceRole, tuple[str, ...]],
    ] = {}
    for operator_id, outcome in outcome_by_operator.items():
        state = state_by_operator[operator_id]
        reference_index = _index_reference_values(outcome.references)
        references_by_operator[operator_id] = reference_index
        invariant_family = reference_index[EvidenceGraphReferenceRole.invariant_family][0]
        independence_class = reference_index[EvidenceGraphReferenceRole.independence_class][0]
        states_by_invariant_family.setdefault(invariant_family, []).append(state)
        states_by_independence_class.setdefault(independence_class, []).append(state)
        unscoped_threat_ids.update(
            reference_index.get(EvidenceGraphReferenceRole.unscoped_threat, ())
        )
        if state not in completed_states or not reference_index.get(
            EvidenceGraphReferenceRole.present_control,
            (),
        ):
            continue
        for threat_id in reference_index.get(
            EvidenceGraphReferenceRole.scoped_threat,
            (),
        ):
            challengers_by_threat.setdefault(threat_id, set()).add(operator_id)
            if independence_class in independent_classes:
                independent_challengers_by_threat.setdefault(threat_id, set()).add(operator_id)
    return (
        {key: tuple(states) for key, states in states_by_invariant_family.items()},
        {key: tuple(states) for key, states in states_by_independence_class.items()},
        {key: frozenset(operators) for key, operators in challengers_by_threat.items()},
        {key: frozenset(operators) for key, operators in independent_challengers_by_threat.items()},
        frozenset(unscoped_threat_ids),
        references_by_operator,
    )


def _index_reference_values(
    references: tuple[EvidenceGraphReference, ...],
) -> dict[EvidenceGraphReferenceRole, tuple[str, ...]]:
    values_by_role: dict[EvidenceGraphReferenceRole, list[str]] = {}
    for reference in references:
        values_by_role.setdefault(reference.role, []).append(reference.value)
    return {role: tuple(values) for role, values in values_by_role.items()}


def _mutation_state_counts_from_states(
    states: tuple[MutationResultState, ...],
) -> MutationStateCounts:
    return MutationStateCounts(
        caught=states.count(MutationResultState.caught),
        survived=states.count(MutationResultState.survived),
        inapplicable=states.count(MutationResultState.inapplicable),
        invalid_operator=states.count(MutationResultState.invalid_operator),
        invalid_subject=states.count(MutationResultState.invalid_subject),
        execution_error=states.count(MutationResultState.execution_error),
    )


def _canonical_sha256(value: object) -> str:
    # Imported lazily so schema package initialization cannot cycle through the
    # canonical layer while that layer is importing schema.common.
    from agent_assure.canonical.digests import sha256_hexdigest

    return sha256_hexdigest(value)
