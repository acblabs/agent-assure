from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from agent_assure.io_limits import loads_json_bounded
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.rooted_io import portable_relative_path_parts
from agent_assure.schema.base import FrozenStrictModel, SchemaVersion
from agent_assure.schema.common import (
    PACKAGE_RELEASE_VERSION_PATTERN,
    DigestHex,
    ExecutionMode,
    GateState,
    MachineIdentifier,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.mutation import BoundedSummary, SelfDigestedArtifact
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    ClaimRecord,
    EvidenceItem,
    EvidenceRef,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, FixtureManifest
from agent_assure.sensitivity_contract import (
    MAX_SENSITIVITY_CORPUS_BYTES,
    MAX_SENSITIVITY_FIXTURE_BYTES,
    SENSITIVITY_EVALUATION_DATE,
    SENSITIVITY_HARNESS_NOTICE,
    SENSITIVITY_PROVENANCE_BINDING,
    SENSITIVITY_SUBJECT_EXECUTION_SCOPE,
    SensitivityProvenanceBinding,
    SensitivitySubjectExecutionScope,
    bundled_sensitivity_identity_set,
)

SENSITIVITY_SCHEMA_VERSION: Literal["0.6.5"] = "0.6.5"
SENSITIVITY_CONTRACT_VERSION: Literal["1.0.0"] = "1.0.0"
_V064_PRIVACY_PROFILE_BINDING = (
    "agent-assure/privacy-detectors/v2",
    "3213eeb63ecbb2ad0bf9681f83eb987c2638abff079955e75988af6b34b3ae53",
)
MAX_SENSITIVITY_DOCUMENTS = 256
MAX_SENSITIVITY_RETRIEVED_DOCUMENTS = 256
MAX_SENSITIVITY_CHECKS = 64
MAX_SENSITIVITY_LIMITATIONS = 256
MAX_SENSITIVITY_CASE_AUTHORITY_BINDINGS = 10_000
_SENSITIVITY_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
REQUIRED_SENSITIVITY_LIMITATIONS: tuple[BoundedSummary, ...] = (
    "This deterministic synthetic detector contract test does not estimate real-model prevalence.",
    "Controlled evidence sensitivity is an observed response relation under declared "
    "conditions, not a causal guarantee.",
    SENSITIVITY_HARNESS_NOTICE,
    "Agent implementation, prompt, model, and tool-schema digests are fixture-declared "
    "identifiers; this protocol does not verify them against implementation, prompt, model, "
    "or tool-schema bytes.",
    "Exact raw corpus and fixture UTF-8 is embedded verbatim in reports and packets; bundled "
    "synthetic status is digest-verified, while custom synthetic status is operator-attested "
    "and not semantically verified.",
)
SensitivityDifferenceBasis = Literal["protocol_fixed", "arm_observed"]
CONTROLLED_DIFFERENCE_DIMENSIONS: tuple[tuple[str, bool, SensitivityDifferenceBasis], ...] = (
    ("agent_implementation_digest", True, "protocol_fixed"),
    ("corpus_digest", False, "arm_observed"),
    ("corpus_document_catalog_digest", True, "arm_observed"),
    ("deterministic_subject", True, "protocol_fixed"),
    ("fixture_manifest_digest", True, "protocol_fixed"),
    ("governing_evidence_digest", False, "arm_observed"),
    ("governing_retrieval_identity_digest", True, "arm_observed"),
    ("knowledge_contract_digest", True, "protocol_fixed"),
    ("model_digest", True, "protocol_fixed"),
    ("non_governing_evidence_digest", True, "arm_observed"),
    ("prompt_template_digest", True, "protocol_fixed"),
    ("producer_version", True, "protocol_fixed"),
    ("query_digest", True, "protocol_fixed"),
    ("query_family_id", True, "arm_observed"),
    ("request_digest", True, "protocol_fixed"),
    ("retrieval_algorithm", True, "arm_observed"),
    ("retrieval_top_k", True, "arm_observed"),
    ("subject_configuration_digest", True, "protocol_fixed"),
    ("suite_digest", True, "protocol_fixed"),
    ("tool_configuration_digest", True, "protocol_fixed"),
    ("tool_schema_digest", True, "protocol_fixed"),
)
SENSITIVITY_PREREQUISITE_CHECK_IDS = (
    "arm-evaluations-pass",
    "authority-contract-valid",
    "comparable-decision-output",
    "controlled-differences-only",
    "deterministic-subject",
    "evidence-links-present-both-arms",
    "fixture-identity-bound",
    "governing-evidence-supported-both-arms",
    "retrieval-succeeded-both-arms",
)


class EvidenceSensitivityReasonCode(StrEnum):
    expected_response_missing = "EVIDENCE_SENSITIVITY_EXPECTED_RESPONSE_MISSING"
    confounded = "EVIDENCE_SENSITIVITY_CONFOUNDED"
    evidence_not_retrieved = "EVIDENCE_NOT_RETRIEVED_IN_BOTH_ARMS"
    evidence_link_not_present = "EVIDENCE_LINK_NOT_PRESENT_IN_BOTH_ARMS"
    authority_contract_invalid = "EVIDENCE_AUTHORITY_CONTRACT_INVALID"
    prerequisites_unmet = "EVIDENCE_SENSITIVITY_PREREQUISITES_UNMET"


class EvidenceSensitivityExpectedRelation(StrEnum):
    decision_flip = "decision_flip"


class EvidenceSensitivityObservedRelation(StrEnum):
    decision_flip = "decision_flip"
    decision_same = "decision_same"
    incomparable = "incomparable"


class EvidenceSensitivityOutcomeClassification(StrEnum):
    expected_response_observed = "expected_response_observed"
    decision_inertia = "decision_inertia"
    wrong_direction_flip = "wrong_direction_flip"
    incomparable_response = "incomparable_response"
    not_evaluated = "not_evaluated"


class EvidenceSensitivityState(StrEnum):
    responsive = "responsive"
    evidence_insensitive = "evidence_insensitive"
    confounded = "confounded"
    prerequisites_unmet = "prerequisites_unmet"


class EvidenceSensitivityGateEffect(StrEnum):
    pass_ = "pass"
    block = "block"
    non_verdict = "non_verdict"


class EvidenceSensitivityArmRole(StrEnum):
    baseline = "baseline"
    counterfactual = "counterfactual"


class EvidenceSensitivityDifferenceState(StrEnum):
    controlled = "controlled"
    expected_difference = "expected_difference"
    confounding = "confounding"


class EvidenceSensitivityPrerequisiteState(StrEnum):
    satisfied = "satisfied"
    unmet = "unmet"


class DetectorTestStatus(StrEnum):
    synthetic_detector_contract_test = "synthetic_detector_contract_test"


class SyntheticDataProvenance(StrEnum):
    bundled_digest_verified = "bundled_digest_verified"
    operator_attested = "operator_attested"


class RAGSensitivitySyntheticDataAttestation(SelfDigestedArtifact):
    _digest_field = "attestation_digest"

    artifact_kind: Literal["rag-sensitivity-synthetic-data-attestation"] = (
        "rag-sensitivity-synthetic-data-attestation"
    )
    schema_version: Literal["0.6.4", "0.6.5"] = SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["rag-sensitivity-synthetic-data-attestation"] = (
        "rag-sensitivity-synthetic-data-attestation"
    )
    contract_id: Literal["RAGSensitivitySyntheticDataAttestation/v1"] = (
        "RAGSensitivitySyntheticDataAttestation/v1"
    )
    contract_version: Literal["1.0.0"] = SENSITIVITY_CONTRACT_VERSION
    attestation_digest: DigestHex
    attestation_id: MachineIdentifier
    attestor_role: Literal["artifact_author"] = "artifact_author"
    data_classification: Literal["synthetic"] = "synthetic"
    attestation_scope: Literal["exact_digest_bound_inputs"] = "exact_digest_bound_inputs"
    suite_digest: DigestHex
    fixture_manifest_digest: DigestHex
    knowledge_contract_digest: DigestHex
    corpus_digests: tuple[DigestHex, ...] = Field(min_length=2, max_length=2)
    corpus_snapshot_digests: tuple[DigestHex, ...] = Field(
        min_length=2,
        max_length=2,
    )
    raw_content_persistence_acknowledged: Literal[True] = True
    no_real_personal_confidential_or_production_data_attested: Literal[True] = True

    @field_validator("corpus_digests", "corpus_snapshot_digests", mode="before")
    @classmethod
    def _coerce_corpus_digests(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_corpus_digests(self) -> Self:
        for label, digests in (
            ("corpus", self.corpus_digests),
            ("corpus snapshot", self.corpus_snapshot_digests),
        ):
            if digests != tuple(sorted(set(digests))):
                raise ValueError(f"attested {label} digests must be distinct and sorted")
        return self


class RAGSensitivityDecision(StrEnum):
    approve = "approve"
    deny = "deny"
    escalate = "escalate"


class RAGSensitivityOutcome(StrEnum):
    approved = "approved"
    denied = "denied"
    escalated = "escalated"


def _outcome_for_decision(decision: RAGSensitivityDecision) -> RAGSensitivityOutcome:
    return {
        RAGSensitivityDecision.approve: RAGSensitivityOutcome.approved,
        RAGSensitivityDecision.deny: RAGSensitivityOutcome.denied,
        RAGSensitivityDecision.escalate: RAGSensitivityOutcome.escalated,
    }[decision]


def derive_sensitivity_outcome_classification(
    state: EvidenceSensitivityState,
    observed_relation: EvidenceSensitivityObservedRelation,
) -> EvidenceSensitivityOutcomeClassification:
    if state is EvidenceSensitivityState.responsive:
        if observed_relation is not EvidenceSensitivityObservedRelation.decision_flip:
            raise ValueError("responsive sensitivity outcome requires a decision flip")
        return EvidenceSensitivityOutcomeClassification.expected_response_observed
    if state is EvidenceSensitivityState.evidence_insensitive:
        if observed_relation is EvidenceSensitivityObservedRelation.decision_same:
            return EvidenceSensitivityOutcomeClassification.decision_inertia
        if observed_relation is EvidenceSensitivityObservedRelation.decision_flip:
            return EvidenceSensitivityOutcomeClassification.wrong_direction_flip
        raise ValueError("verdict-bearing sensitivity output cannot be incomparable")
    if (
        state is EvidenceSensitivityState.prerequisites_unmet
        and observed_relation is EvidenceSensitivityObservedRelation.incomparable
    ):
        return EvidenceSensitivityOutcomeClassification.incomparable_response
    return EvidenceSensitivityOutcomeClassification.not_evaluated


def _relation_for_directional_decisions(
    baseline: RAGSensitivityDecision,
    counterfactual: RAGSensitivityDecision,
) -> EvidenceSensitivityObservedRelation:
    if RAGSensitivityDecision.escalate in {baseline, counterfactual}:
        return EvidenceSensitivityObservedRelation.incomparable
    if baseline is counterfactual:
        return EvidenceSensitivityObservedRelation.decision_same
    return EvidenceSensitivityObservedRelation.decision_flip


def derive_sensitivity_directional_outcome_classification(
    *,
    state: EvidenceSensitivityState,
    observed_relation: EvidenceSensitivityObservedRelation,
    baseline_expected_decision: RAGSensitivityDecision | None,
    counterfactual_expected_decision: RAGSensitivityDecision | None,
    baseline_observed_decision: RAGSensitivityDecision,
    counterfactual_observed_decision: RAGSensitivityDecision,
) -> EvidenceSensitivityOutcomeClassification:
    derived_relation = _relation_for_directional_decisions(
        baseline_observed_decision,
        counterfactual_observed_decision,
    )
    if observed_relation is not derived_relation:
        raise ValueError("sensitivity observed relation contradicts directional decisions")
    classification = derive_sensitivity_outcome_classification(state, derived_relation)
    expected_decisions = (
        baseline_expected_decision,
        counterfactual_expected_decision,
    )
    expected_outputs_bound = None not in expected_decisions
    if RAGSensitivityDecision.escalate in expected_decisions:
        raise ValueError("sensitivity expected decisions must be approve or deny when bound")
    if expected_outputs_bound and baseline_expected_decision is counterfactual_expected_decision:
        raise ValueError("fully bound sensitivity expected decisions must define a decision flip")
    if state not in {
        EvidenceSensitivityState.responsive,
        EvidenceSensitivityState.evidence_insensitive,
    }:
        return classification
    if not expected_outputs_bound:
        raise ValueError(
            "verdict-bearing sensitivity outcome requires distinct bound approve/deny "
            "expected decisions"
        )
    expected_response_observed = (
        baseline_observed_decision,
        counterfactual_observed_decision,
    ) == expected_decisions
    if (state is EvidenceSensitivityState.responsive and not expected_response_observed) or (
        state is EvidenceSensitivityState.evidence_insensitive and expected_response_observed
    ):
        raise ValueError(
            "sensitivity outcome state contradicts expected and observed decision paths"
        )
    return classification


def derive_sensitivity_outcome_message(
    *,
    classification: EvidenceSensitivityOutcomeClassification,
    state: EvidenceSensitivityState,
    observed_relation: EvidenceSensitivityObservedRelation,
    baseline_expected_decision: RAGSensitivityDecision | None,
    counterfactual_expected_decision: RAGSensitivityDecision | None,
    baseline_observed_decision: RAGSensitivityDecision,
    counterfactual_observed_decision: RAGSensitivityDecision,
) -> BoundedSummary:
    expected_classification = derive_sensitivity_directional_outcome_classification(
        state=state,
        observed_relation=observed_relation,
        baseline_expected_decision=baseline_expected_decision,
        counterfactual_expected_decision=counterfactual_expected_decision,
        baseline_observed_decision=baseline_observed_decision,
        counterfactual_observed_decision=counterfactual_observed_decision,
    )
    if classification is not expected_classification:
        raise ValueError("sensitivity outcome classification contradicts state and relation")
    expected_path = _sensitivity_decision_path(
        baseline_expected_decision,
        counterfactual_expected_decision,
    )
    observed_path = _sensitivity_decision_path(
        baseline_observed_decision,
        counterfactual_observed_decision,
    )
    prefix = (
        f"Expected decisions (baseline -> counterfactual): {expected_path}; "
        f"observed decisions: {observed_path}. "
    )
    if classification is EvidenceSensitivityOutcomeClassification.expected_response_observed:
        return prefix + "The expected governing-evidence response was observed in both arms."
    if classification is EvidenceSensitivityOutcomeClassification.decision_inertia:
        return prefix + (
            "The subject returned the same decision fields after authoritative governing "
            "evidence changed."
        )
    if classification is EvidenceSensitivityOutcomeClassification.wrong_direction_flip:
        return prefix + (
            "The subject changed decision fields, but in the wrong direction relative to the "
            "authority contract."
        )
    if classification is EvidenceSensitivityOutcomeClassification.incomparable_response:
        return prefix + (
            "At least one observed arm decision was incomparable, so the expected response "
            f"was not evaluated under state {state.value}."
        )
    if state is EvidenceSensitivityState.confounded:
        return prefix + (
            "The expected response was not evaluated because the controlled-difference "
            "protocol was confounded."
        )
    return prefix + (
        "The expected response was not evaluated because one or more protocol prerequisites "
        "were unmet."
    )


def _sensitivity_decision_path(
    baseline: RAGSensitivityDecision | None,
    counterfactual: RAGSensitivityDecision | None,
) -> str:
    baseline_value = baseline.value if baseline is not None else "unbound"
    counterfactual_value = counterfactual.value if counterfactual is not None else "unbound"
    return f"{baseline_value} -> {counterfactual_value}"


class RAGSensitivitySubjectMode(StrEnum):
    responsive = "responsive"
    evidence_reversed = "evidence_reversed"
    evidence_inertial = "evidence_inertial"


class RAGSensitivityFixtureRole(StrEnum):
    request = "request"
    subject_configuration = "subject_configuration"
    tool_configuration = "tool_configuration"


class RAGSensitivityCorpusDocument(FrozenStrictModel):
    path: str = Field(min_length=1, max_length=1024)
    source_id: MachineIdentifier
    content_digest: DigestHex

    @field_validator("path")
    @classmethod
    def _validate_portable_path(cls, value: str) -> str:
        portable_relative_path_parts(value)
        return value.replace("\\", "/")


class RAGSensitivityCorpusManifest(SelfDigestedArtifact):
    _digest_field = "corpus_digest"

    artifact_kind: Literal["rag-sensitivity-corpus-manifest"] = "rag-sensitivity-corpus-manifest"
    schema_version: Literal["0.6.4", "0.6.5"] = SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["rag-sensitivity-corpus-manifest"] = "rag-sensitivity-corpus-manifest"
    contract_id: Literal["RAGSensitivityCorpusManifest/v1"] = "RAGSensitivityCorpusManifest/v1"
    contract_version: Literal["1.0.0"] = SENSITIVITY_CONTRACT_VERSION
    corpus_digest: DigestHex
    corpus_id: MachineIdentifier
    corpus_version: str = Field(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
    query_family_id: MachineIdentifier
    retrieval_algorithm_id: MachineIdentifier
    retrieval_algorithm_version: str = Field(
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
    )
    top_k: int = Field(ge=1, le=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS)
    documents: tuple[RAGSensitivityCorpusDocument, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_DOCUMENTS,
    )

    @field_validator("documents", mode="before")
    @classmethod
    def _coerce_documents(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_document_catalog(self) -> Self:
        expected = tuple(sorted(self.documents, key=lambda item: (item.source_id, item.path)))
        if self.documents != expected:
            raise ValueError("corpus documents must use canonical source-ID and path ordering")
        if len({item.path for item in self.documents}) != len(self.documents):
            raise ValueError("corpus document paths must be unique")
        if len({item.source_id for item in self.documents}) != len(self.documents):
            raise ValueError("corpus document source IDs must be unique")
        return self


class RAGSensitivityAuthorityAssignment(FrozenStrictModel):
    corpus_digest: DigestHex
    expected_decision: RAGSensitivityDecision
    expected_outcome: RAGSensitivityOutcome
    governing_source_id: MachineIdentifier
    governing_ref_id: MachineIdentifier
    governing_content_digest: DigestHex
    claim_id: MachineIdentifier

    @field_validator("expected_decision", mode="before")
    @classmethod
    def _coerce_decision(cls, value: object) -> RAGSensitivityDecision:
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("expected_outcome", mode="before")
    @classmethod
    def _coerce_outcome(cls, value: object) -> RAGSensitivityOutcome:
        return coerce_enum(RAGSensitivityOutcome, value)

    @model_validator(mode="after")
    def _validate_expected_output(self) -> Self:
        if self.expected_outcome is not _outcome_for_decision(self.expected_decision):
            raise ValueError("authority expected recommendation and outcome are incoherent")
        return self


class RAGSensitivityCaseAuthorityBinding(FrozenStrictModel):
    """Exact authority assignment pair for one explicitly covered case."""

    case_id: MachineIdentifier
    query_family_id: MachineIdentifier
    assignments: tuple[RAGSensitivityAuthorityAssignment, ...] = Field(
        min_length=2,
        max_length=2,
    )

    @field_validator("assignments", mode="before")
    @classmethod
    def _coerce_assignments(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_authority_mapping(self) -> Self:
        expected = tuple(sorted(self.assignments, key=lambda item: item.corpus_digest))
        if self.assignments != expected:
            raise ValueError("authority assignments must use canonical corpus-digest ordering")
        if len({item.corpus_digest for item in self.assignments}) != 2:
            raise ValueError("authority assignments must bind two distinct corpus digests")
        decisions = {item.expected_decision for item in self.assignments}
        if len(decisions) != 2 or RAGSensitivityDecision.escalate in decisions:
            raise ValueError(
                "decision_flip authority assignments require distinct approve and deny decisions"
            )
        if (
            len({item.governing_source_id for item in self.assignments}) != 1
            or len({item.governing_ref_id for item in self.assignments}) != 1
            or len({item.claim_id for item in self.assignments}) != 1
        ):
            raise ValueError(
                "authority assignments must preserve the logical evidence and claim target"
            )
        if len({item.governing_content_digest for item in self.assignments}) != 2:
            raise ValueError("authority assignments require different governing evidence content")
        return self


class RAGSensitivityKnowledgeContract(SelfDigestedArtifact):
    _digest_field = "knowledge_contract_digest"

    artifact_kind: Literal["rag-sensitivity-knowledge-contract"] = (
        "rag-sensitivity-knowledge-contract"
    )
    schema_version: Literal["0.6.4", "0.6.5"] = SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["rag-sensitivity-knowledge-contract"] = (
        "rag-sensitivity-knowledge-contract"
    )
    contract_id: Literal["RAGSensitivityKnowledgeAuthority/v1"] = (
        "RAGSensitivityKnowledgeAuthority/v1"
    )
    contract_version: Literal["1.0.0"] = SENSITIVITY_CONTRACT_VERSION
    knowledge_contract_digest: DigestHex
    governing_source: Literal["contextual_evidence"] = "contextual_evidence"
    authority_level: Literal["authoritative"] = "authoritative"
    expected_behavior: Literal["follow_governing_context"] = "follow_governing_context"
    conflict_direction: Literal["context_overrides_parametric_memory"] = (
        "context_overrides_parametric_memory"
    )
    expected_response_relation: EvidenceSensitivityExpectedRelation
    case_id: MachineIdentifier
    query_family_id: MachineIdentifier
    assignments: tuple[RAGSensitivityAuthorityAssignment, ...] = Field(
        min_length=2,
        max_length=2,
    )
    case_authority_bindings: tuple[RAGSensitivityCaseAuthorityBinding, ...] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_SENSITIVITY_CASE_AUTHORITY_BINDINGS,
        exclude_if=lambda value: value is None,
    )
    limitations: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_LIMITATIONS,
    )

    @field_validator("expected_response_relation", mode="before")
    @classmethod
    def _coerce_relation(cls, value: object) -> EvidenceSensitivityExpectedRelation:
        return coerce_enum(EvidenceSensitivityExpectedRelation, value)

    @field_validator(
        "assignments",
        "case_authority_bindings",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_authority_mapping(self) -> Self:
        if self.schema_version == "0.6.4" and self.case_authority_bindings is not None:
            raise ValueError("case_authority_bindings were introduced in schema version 0.6.5")
        legacy_binding = RAGSensitivityCaseAuthorityBinding(
            case_id=self.case_id,
            query_family_id=self.query_family_id,
            assignments=self.assignments,
        )
        if self.case_authority_bindings is not None:
            expected = tuple(sorted(self.case_authority_bindings, key=lambda item: item.case_id))
            if self.case_authority_bindings != expected:
                raise ValueError("case authority bindings must use canonical case-ID ordering")
            if len({item.case_id for item in self.case_authority_bindings}) != len(
                self.case_authority_bindings
            ):
                raise ValueError("case authority bindings must use unique case IDs")
            matching_legacy = tuple(
                item for item in self.case_authority_bindings if item.case_id == self.case_id
            )
            if matching_legacy != (legacy_binding,):
                raise ValueError(
                    "legacy case/query/assignment fields must exactly mirror their "
                    "case authority binding"
                )
            if {item.query_family_id for item in self.case_authority_bindings} != {
                self.query_family_id
            }:
                raise ValueError("v1 case authority bindings must share the contract query family")
        return self


def knowledge_contract_case_authority_bindings(
    contract: RAGSensitivityKnowledgeContract,
) -> tuple[RAGSensitivityCaseAuthorityBinding, ...]:
    """Return explicit bindings, or the safe one-case legacy projection."""

    if contract.case_authority_bindings is not None:
        return contract.case_authority_bindings
    return (
        RAGSensitivityCaseAuthorityBinding(
            case_id=contract.case_id,
            query_family_id=contract.query_family_id,
            assignments=contract.assignments,
        ),
    )


class RAGSensitivitySubjectConfig(FrozenStrictModel):
    subject_id: MachineIdentifier
    deterministic: Literal[True] = True
    mode: RAGSensitivitySubjectMode
    fixed_decision: RAGSensitivityDecision | None = None
    fixed_outcome: RAGSensitivityOutcome | None = None
    emit_evidence_links: bool = True
    agent_implementation_id: MachineIdentifier
    agent_implementation_digest: DigestHex
    prompt_template_id: MachineIdentifier
    prompt_template_digest: DigestHex
    model_id: MachineIdentifier
    model_digest: DigestHex

    @field_validator("mode", mode="before")
    @classmethod
    def _coerce_mode(cls, value: object) -> RAGSensitivitySubjectMode:
        return coerce_enum(RAGSensitivitySubjectMode, value)

    @field_validator("fixed_decision", mode="before")
    @classmethod
    def _coerce_fixed_decision(cls, value: object) -> RAGSensitivityDecision | None:
        if value is None:
            return None
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("fixed_outcome", mode="before")
    @classmethod
    def _coerce_fixed_outcome(cls, value: object) -> RAGSensitivityOutcome | None:
        if value is None:
            return None
        return coerce_enum(RAGSensitivityOutcome, value)

    @model_validator(mode="after")
    def _validate_mode(self) -> Self:
        if self.mode is RAGSensitivitySubjectMode.evidence_inertial:
            if self.fixed_decision not in {
                RAGSensitivityDecision.approve,
                RAGSensitivityDecision.deny,
            }:
                raise ValueError("evidence-inertial subjects require an approve or deny decision")
            if self.fixed_outcome is not _outcome_for_decision(self.fixed_decision):
                raise ValueError("fixed recommendation and outcome are incoherent")
        elif self.fixed_decision is not None or self.fixed_outcome is not None:
            raise ValueError("retrieval-derived subjects cannot declare a fixed decision output")
        return self


class RAGSensitivityRequest(FrozenStrictModel):
    request_id: MachineIdentifier
    query_family_id: MachineIdentifier
    query: str = Field(min_length=1, max_length=8192)
    claim_id: MachineIdentifier


class RAGSensitivityToolConfig(FrozenStrictModel):
    tool_id: MachineIdentifier
    tool_schema_digest: DigestHex
    retrieval_algorithm_id: Literal["deterministic-term-overlap"] = "deterministic-term-overlap"
    retrieval_algorithm_version: Literal["1.0.0"] = "1.0.0"
    top_k: int = Field(ge=1, le=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS)


class RAGSensitivityFixtureFileSnapshot(FrozenStrictModel):
    role: RAGSensitivityFixtureRole
    path: str = Field(min_length=1, max_length=1024)
    sha256: DigestHex
    size_bytes: int = Field(ge=2, le=MAX_SENSITIVITY_FIXTURE_BYTES)
    content_utf8: str = Field(min_length=2, max_length=MAX_SENSITIVITY_FIXTURE_BYTES)

    @field_validator("role", mode="before")
    @classmethod
    def _coerce_role(cls, value: object) -> RAGSensitivityFixtureRole:
        return coerce_enum(RAGSensitivityFixtureRole, value)

    @field_validator("path")
    @classmethod
    def _validate_portable_path(cls, value: str) -> str:
        portable_relative_path_parts(value)
        return value.replace(chr(92), "/")

    @model_validator(mode="after")
    def _validate_exact_content(self) -> Self:
        encoded = self.content_utf8.encode("utf-8")
        if len(encoded) != self.size_bytes:
            raise ValueError("fixture snapshot size does not match exact UTF-8 content")
        if len(encoded) > MAX_SENSITIVITY_FIXTURE_BYTES:
            raise ValueError("fixture snapshot exceeds the UTF-8 byte limit")
        if hashlib.sha256(encoded).hexdigest() != self.sha256:
            raise ValueError("fixture snapshot digest does not match exact UTF-8 content")
        return self


class RAGSensitivityDocumentPayload(FrozenStrictModel):
    source_id: MachineIdentifier
    ref_id: MachineIdentifier
    title: BoundedSummary
    safe_summary: BoundedSummary
    retrieval_terms: tuple[MachineIdentifier, ...] = Field(min_length=1, max_length=256)
    governing_decision: RAGSensitivityDecision
    governing_outcome: RAGSensitivityOutcome

    @field_validator("retrieval_terms", mode="before")
    @classmethod
    def _coerce_terms(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("governing_decision", mode="before")
    @classmethod
    def _coerce_decision(cls, value: object) -> RAGSensitivityDecision:
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("governing_outcome", mode="before")
    @classmethod
    def _coerce_outcome(cls, value: object) -> RAGSensitivityOutcome:
        return coerce_enum(RAGSensitivityOutcome, value)

    @model_validator(mode="after")
    def _validate_terms(self) -> Self:
        if self.retrieval_terms != tuple(sorted(set(self.retrieval_terms))):
            raise ValueError("retrieval terms must be unique and sorted")
        if self.governing_outcome is not _outcome_for_decision(self.governing_decision):
            raise ValueError("document governing recommendation and outcome are incoherent")
        return self


class RAGSensitivityCorpusSnapshotDocument(FrozenStrictModel):
    descriptor: RAGSensitivityCorpusDocument
    payload: RAGSensitivityDocumentPayload
    content_utf8: str = Field(
        min_length=2,
        max_length=MAX_SENSITIVITY_CORPUS_BYTES,
    )

    @model_validator(mode="after")
    def _validate_exact_content(self) -> Self:
        if hashlib.sha256(self.content_utf8.encode("utf-8")).hexdigest() != (
            self.descriptor.content_digest
        ):
            raise ValueError("corpus snapshot document content digest does not match")
        parsed_payload = self.parsed_payload()
        if parsed_payload != self.payload:
            raise ValueError("corpus snapshot decoded payload does not match exact content")
        if self.payload.source_id != self.descriptor.source_id:
            raise ValueError("corpus snapshot document source identity does not match")
        return self

    def parsed_payload(self) -> RAGSensitivityDocumentPayload:
        payload = loads_json_bounded(
            self.content_utf8,
            label="sensitivity corpus snapshot document",
        )
        return RAGSensitivityDocumentPayload.model_validate(payload)


class RAGSensitivityCorpusSnapshot(SelfDigestedArtifact):
    _digest_field = "snapshot_digest"

    artifact_kind: Literal["rag-sensitivity-corpus-snapshot"] = "rag-sensitivity-corpus-snapshot"
    schema_version: Literal["0.6.4", "0.6.5"] = SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["rag-sensitivity-corpus-snapshot"] = "rag-sensitivity-corpus-snapshot"
    contract_id: Literal["RAGSensitivityCorpusSnapshot/v1"] = "RAGSensitivityCorpusSnapshot/v1"
    contract_version: Literal["1.0.0"] = SENSITIVITY_CONTRACT_VERSION
    snapshot_digest: DigestHex
    corpus_manifest: RAGSensitivityCorpusManifest
    corpus_manifest_file_sha256: DigestHex
    corpus_manifest_utf8: str = Field(
        min_length=2,
        max_length=MAX_SENSITIVITY_CORPUS_BYTES,
    )
    documents: tuple[RAGSensitivityCorpusSnapshotDocument, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_DOCUMENTS,
    )

    @field_validator("documents", mode="before")
    @classmethod
    def _coerce_documents(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_snapshot(self) -> Self:
        aggregate_bytes = len(self.corpus_manifest_utf8.encode("utf-8")) + sum(
            len(document.content_utf8.encode("utf-8")) for document in self.documents
        )
        if aggregate_bytes > MAX_SENSITIVITY_CORPUS_BYTES:
            raise ValueError("corpus snapshot exceeds the aggregate UTF-8 byte limit")
        if hashlib.sha256(self.corpus_manifest_utf8.encode("utf-8")).hexdigest() != (
            self.corpus_manifest_file_sha256
        ):
            raise ValueError("corpus snapshot manifest file digest does not match")
        manifest_payload = loads_json_bounded(
            self.corpus_manifest_utf8,
            label="sensitivity corpus snapshot manifest",
        )
        if RAGSensitivityCorpusManifest.model_validate(manifest_payload) != (self.corpus_manifest):
            raise ValueError("corpus snapshot manifest text and model do not match")
        if tuple(item.descriptor for item in self.documents) != (self.corpus_manifest.documents):
            raise ValueError("corpus snapshot documents must exactly match the manifest")
        return self


class RAGSensitivityCorpusControlProjection(FrozenStrictModel):
    document_catalog_digest: DigestHex
    non_governing_evidence_digest: DigestHex
    governing_retrieval_identity_digest: DigestHex
    governing_evidence_digest: DigestHex


def derive_corpus_control_projection(
    snapshot: RAGSensitivityCorpusSnapshot,
    contract: RAGSensitivityKnowledgeContract,
) -> RAGSensitivityCorpusControlProjection:
    authority = contract.assignments[0]
    catalog: list[dict[str, object]] = []
    non_governing: list[dict[str, object]] = []
    governing_retrieval: list[dict[str, object]] = []
    governing_content_digests: list[str] = []
    for snapshot_document in snapshot.documents:
        descriptor = snapshot_document.descriptor
        document = snapshot_document.payload
        catalog_entry: dict[str, object] = {
            "path": descriptor.path,
            "source_id": document.source_id,
            "ref_id": document.ref_id,
        }
        catalog.append(catalog_entry)
        is_governing = (
            document.source_id,
            document.ref_id,
        ) == (
            authority.governing_source_id,
            authority.governing_ref_id,
        )
        if is_governing:
            governing_entry: dict[str, object] = {
                **catalog_entry,
                "retrieval_terms": document.retrieval_terms,
            }
            governing_retrieval.append(governing_entry)
            governing_content_digests.append(descriptor.content_digest)
        else:
            non_governing.append(
                {
                    **catalog_entry,
                    "content_digest": descriptor.content_digest,
                }
            )
    governing_evidence_digest = (
        governing_content_digests[0]
        if len(governing_content_digests) == 1
        else _canonical_sha256(tuple(governing_content_digests))
    )
    return RAGSensitivityCorpusControlProjection(
        document_catalog_digest=_canonical_sha256(tuple(catalog)),
        non_governing_evidence_digest=_canonical_sha256(tuple(non_governing)),
        governing_retrieval_identity_digest=_canonical_sha256(tuple(governing_retrieval)),
        governing_evidence_digest=governing_evidence_digest,
    )


class EvidenceSensitivityDifferenceCheck(FrozenStrictModel):
    dimension: MachineIdentifier
    baseline_value: str = Field(min_length=1, max_length=8192)
    counterfactual_value: str = Field(min_length=1, max_length=8192)
    expected_equal: bool
    basis: SensitivityDifferenceBasis
    state: EvidenceSensitivityDifferenceState

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> EvidenceSensitivityDifferenceState:
        return coerce_enum(EvidenceSensitivityDifferenceState, value)

    @model_validator(mode="after")
    def _validate_state(self) -> Self:
        equal = self.baseline_value == self.counterfactual_value
        expected_state = (
            EvidenceSensitivityDifferenceState.controlled
            if self.expected_equal and equal
            else EvidenceSensitivityDifferenceState.confounding
            if self.expected_equal
            else EvidenceSensitivityDifferenceState.confounding
            if equal
            else EvidenceSensitivityDifferenceState.expected_difference
        )
        if self.state is not expected_state:
            raise ValueError("controlled-difference check state contradicts its values")
        return self


class EvidenceSensitivityDifferenceManifest(FrozenStrictModel):
    checks: tuple[EvidenceSensitivityDifferenceCheck, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_CHECKS,
    )
    only_declared_differences: bool
    confounding_dimensions: tuple[MachineIdentifier, ...]

    @field_validator("checks", "confounding_dimensions", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_manifest(self) -> Self:
        expected_dimensions = tuple(item[0] for item in CONTROLLED_DIFFERENCE_DIMENSIONS)
        if tuple(item.dimension for item in self.checks) != expected_dimensions:
            raise ValueError("controlled-difference checks must use the complete v1 vocabulary")
        expected_polarity = {
            dimension: expected_equal
            for dimension, expected_equal, _basis in CONTROLLED_DIFFERENCE_DIMENSIONS
        }
        if any(
            item.expected_equal is not expected_polarity[item.dimension] for item in self.checks
        ):
            raise ValueError("controlled-difference check polarity is fixed by the v1 contract")
        expected_basis = {
            dimension: basis
            for dimension, _expected_equal, basis in CONTROLLED_DIFFERENCE_DIMENSIONS
        }
        if any(item.basis != expected_basis[item.dimension] for item in self.checks):
            raise ValueError("controlled-difference check basis is fixed by the v1 contract")
        expected_confounders = tuple(
            item.dimension
            for item in self.checks
            if item.state is EvidenceSensitivityDifferenceState.confounding
        )
        if self.confounding_dimensions != expected_confounders:
            raise ValueError("confounding dimensions must match controlled-difference checks")
        if self.only_declared_differences is bool(expected_confounders):
            raise ValueError("only_declared_differences contradicts confounding checks")
        return self


class RAGSensitivityProtocol(SelfDigestedArtifact):
    _digest_field = "protocol_digest"

    artifact_kind: Literal["evidence-sensitivity-protocol"] = "evidence-sensitivity-protocol"
    schema_version: Literal["0.6.4", "0.6.5"] = SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["evidence-sensitivity-protocol"] = "evidence-sensitivity-protocol"
    contract_id: Literal["RAGSensitivityProtocol/v1"] = "RAGSensitivityProtocol/v1"
    contract_version: Literal["1.0.0"] = SENSITIVITY_CONTRACT_VERSION
    protocol_digest: DigestHex
    protocol_id: MachineIdentifier
    suite_id: MachineIdentifier
    suite_digest: DigestHex
    fixture_manifest_digest: DigestHex
    case_id: MachineIdentifier
    fixture_id: MachineIdentifier
    subject_id: MachineIdentifier
    provider: Literal["synthetic-fixture"] = "synthetic-fixture"
    model_id: MachineIdentifier
    tool_id: MachineIdentifier
    fixture_manifest: FixtureManifest
    fixture_snapshots: tuple[RAGSensitivityFixtureFileSnapshot, ...] = Field(
        min_length=3,
        max_length=3,
    )
    request: RAGSensitivityRequest
    subject_configuration: RAGSensitivitySubjectConfig
    tool_configuration: RAGSensitivityToolConfig
    request_digest: DigestHex
    query_family_id: MachineIdentifier
    query_digest: DigestHex
    subject_configuration_digest: DigestHex
    agent_implementation_digest: DigestHex
    prompt_template_digest: DigestHex
    model_digest: DigestHex
    tool_configuration_digest: DigestHex
    tool_schema_digest: DigestHex
    retrieval_algorithm_id: Literal["deterministic-term-overlap"] = "deterministic-term-overlap"
    retrieval_algorithm_version: Literal["1.0.0"] = "1.0.0"
    retrieval_top_k: int = Field(ge=1, le=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS)
    producer_version: str = Field(
        default=SENSITIVITY_SCHEMA_VERSION,
        pattern=PACKAGE_RELEASE_VERSION_PATTERN,
    )
    deterministic: Literal[True] = True
    detector_test_status: DetectorTestStatus = DetectorTestStatus.synthetic_detector_contract_test
    subject_execution_scope: SensitivitySubjectExecutionScope = SENSITIVITY_SUBJECT_EXECUTION_SCOPE
    provenance_binding: SensitivityProvenanceBinding = SENSITIVITY_PROVENANCE_BINDING
    synthetic_data_provenance: SyntheticDataProvenance
    synthetic_data_attestation_digest: DigestHex | None = None
    synthetic_data_attestation: RAGSensitivitySyntheticDataAttestation | None = None
    endpoint: Literal["expected_decision_response"] = "expected_decision_response"
    baseline_corpus_digest: DigestHex
    counterfactual_corpus_digest: DigestHex
    baseline_corpus_snapshot_digest: DigestHex
    counterfactual_corpus_snapshot_digest: DigestHex
    baseline_corpus_document_catalog_digest: DigestHex
    counterfactual_corpus_document_catalog_digest: DigestHex
    baseline_non_governing_evidence_digest: DigestHex
    counterfactual_non_governing_evidence_digest: DigestHex
    baseline_governing_retrieval_identity_digest: DigestHex
    counterfactual_governing_retrieval_identity_digest: DigestHex
    baseline_governing_evidence_digest: DigestHex
    counterfactual_governing_evidence_digest: DigestHex
    baseline_corpus_query_family_id: MachineIdentifier
    counterfactual_corpus_query_family_id: MachineIdentifier
    baseline_retrieval_algorithm_id: MachineIdentifier
    counterfactual_retrieval_algorithm_id: MachineIdentifier
    baseline_retrieval_algorithm_version: str = Field(
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
    )
    counterfactual_retrieval_algorithm_version: str = Field(
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
    )
    baseline_retrieval_top_k: int = Field(
        ge=1,
        le=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS,
    )
    counterfactual_retrieval_top_k: int = Field(
        ge=1,
        le=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS,
    )
    baseline_corpus_manifest_file_sha256: DigestHex
    counterfactual_corpus_manifest_file_sha256: DigestHex
    baseline_evidence_set_digest: DigestHex
    counterfactual_evidence_set_digest: DigestHex
    knowledge_contract_digest: DigestHex
    expected_relation: EvidenceSensitivityExpectedRelation
    controlled_difference_manifest: EvidenceSensitivityDifferenceManifest
    assumptions: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_LIMITATIONS,
    )
    limitations: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_LIMITATIONS,
    )

    @field_validator("detector_test_status", mode="before")
    @classmethod
    def _coerce_detector_status(cls, value: object) -> DetectorTestStatus:
        return coerce_enum(DetectorTestStatus, value)

    @field_validator("synthetic_data_provenance", mode="before")
    @classmethod
    def _coerce_synthetic_data_provenance(
        cls,
        value: object,
    ) -> SyntheticDataProvenance:
        return coerce_enum(SyntheticDataProvenance, value)

    @field_validator("expected_relation", mode="before")
    @classmethod
    def _coerce_expected_relation(cls, value: object) -> EvidenceSensitivityExpectedRelation:
        return coerce_enum(EvidenceSensitivityExpectedRelation, value)

    @field_validator("assumptions", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("fixture_snapshots", mode="before")
    @classmethod
    def _coerce_fixture_snapshots(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_corpora(self) -> Self:
        if self.synthetic_data_provenance is SyntheticDataProvenance.bundled_digest_verified:
            if (
                self.synthetic_data_attestation is not None
                or self.synthetic_data_attestation_digest is not None
            ):
                raise ValueError("bundled synthetic provenance must not carry an attestation")
        else:
            attestation = self.synthetic_data_attestation
            if attestation is None or self.synthetic_data_attestation_digest is None:
                raise ValueError("custom sensitivity inputs require a synthetic-data attestation")
            if self.synthetic_data_attestation_digest != attestation.attestation_digest:
                raise ValueError("synthetic-data attestation digest does not match")
            if (
                attestation.suite_digest,
                attestation.fixture_manifest_digest,
                attestation.knowledge_contract_digest,
                attestation.corpus_digests,
                attestation.corpus_snapshot_digests,
            ) != (
                self.suite_digest,
                self.fixture_manifest_digest,
                self.knowledge_contract_digest,
                tuple(sorted((self.baseline_corpus_digest, self.counterfactual_corpus_digest))),
                tuple(
                    sorted(
                        (
                            self.baseline_corpus_snapshot_digest,
                            self.counterfactual_corpus_snapshot_digest,
                        )
                    )
                ),
            ):
                raise ValueError(
                    "synthetic-data attestation must bind the exact suite, fixtures, "
                    "authority contract, corpus digests, and corpus-snapshot digests"
                )
        if self.fixture_manifest_digest != _canonical_sha256(
            self.fixture_manifest.model_dump(mode="json")
        ):
            raise ValueError(
                "protocol fixture-manifest digest must derive from the exact embedded manifest"
            )
        if self.fixture_manifest.suite_id != self.suite_id:
            raise ValueError("embedded fixture manifest must match the protocol suite identity")
        expected_roles = (
            RAGSensitivityFixtureRole.request,
            RAGSensitivityFixtureRole.subject_configuration,
            RAGSensitivityFixtureRole.tool_configuration,
        )
        if tuple(snapshot.role for snapshot in self.fixture_snapshots) != expected_roles:
            raise ValueError("protocol fixture snapshots must use the canonical complete role set")
        if len({snapshot.path for snapshot in self.fixture_snapshots}) != len(
            self.fixture_snapshots
        ):
            raise ValueError("protocol fixture snapshot paths must be unique")
        manifest_entries = {
            entry.path: (entry.sha256, entry.size_bytes) for entry in self.fixture_manifest.entries
        }
        if len(manifest_entries) != len(self.fixture_manifest.entries):
            raise ValueError("embedded fixture manifest paths must be unique")
        role_subdirectories = {
            RAGSensitivityFixtureRole.request: "requests",
            RAGSensitivityFixtureRole.subject_configuration: "model_outputs",
            RAGSensitivityFixtureRole.tool_configuration: "tool_outputs",
        }
        matching_roots: list[tuple[str, ...]] = []
        for root in self.fixture_manifest.fixture_roots:
            expected_paths = tuple(
                f"{root}/{role_subdirectories[role]}/{self.fixture_id}.json"
                for role in expected_roles
            )
            for expected_path in expected_paths:
                portable_relative_path_parts(expected_path)
            if all(path in manifest_entries for path in expected_paths):
                matching_roots.append(expected_paths)
        if len(matching_roots) != 1:
            raise ValueError(
                "protocol fixture identity must resolve exactly one complete manifest root"
            )
        if tuple(snapshot.path for snapshot in self.fixture_snapshots) != matching_roots[0]:
            raise ValueError(
                "protocol fixture snapshot roles must match the suite-selected fixture identity"
            )
        for snapshot in self.fixture_snapshots:
            if manifest_entries.get(snapshot.path) != (snapshot.sha256, snapshot.size_bytes):
                raise ValueError(
                    "protocol fixture snapshots must match exact embedded manifest entries"
                )
        fixture_payloads: dict[RAGSensitivityFixtureRole, object] = {}
        for snapshot in self.fixture_snapshots:
            fixture_payloads[snapshot.role] = loads_json_bounded(
                snapshot.content_utf8,
                label=f"sensitivity {snapshot.role.value} fixture snapshot",
            )
        if (
            RAGSensitivityRequest.model_validate(
                fixture_payloads[RAGSensitivityFixtureRole.request]
            )
            != self.request
        ):
            raise ValueError("protocol request must derive from the exact fixture snapshot")
        if (
            RAGSensitivitySubjectConfig.model_validate(
                fixture_payloads[RAGSensitivityFixtureRole.subject_configuration]
            )
            != self.subject_configuration
        ):
            raise ValueError(
                "protocol subject configuration must derive from the exact fixture snapshot"
            )
        if (
            RAGSensitivityToolConfig.model_validate(
                fixture_payloads[RAGSensitivityFixtureRole.tool_configuration]
            )
            != self.tool_configuration
        ):
            raise ValueError(
                "protocol tool configuration must derive from the exact fixture snapshot"
            )
        if self.request_digest != _canonical_sha256(self.request.model_dump(mode="json")):
            raise ValueError("protocol request digest must derive from the exact request")
        normalized_query = normalize_sensitivity_query(self.request.query)
        if self.query_digest != _canonical_sha256({"normalized_query": normalized_query}):
            raise ValueError("protocol query digest must derive from the exact request query")
        if self.query_family_id != self.request.query_family_id:
            raise ValueError("protocol query family must match the exact request")
        if (
            self.subject_id,
            self.subject_configuration_digest,
            self.agent_implementation_digest,
            self.prompt_template_digest,
            self.model_id,
            self.model_digest,
        ) != (
            self.subject_configuration.subject_id,
            _canonical_sha256(self.subject_configuration.model_dump(mode="json")),
            self.subject_configuration.agent_implementation_digest,
            self.subject_configuration.prompt_template_digest,
            self.subject_configuration.model_id,
            self.subject_configuration.model_digest,
        ):
            raise ValueError(
                "protocol subject identities must derive from the exact subject configuration"
            )
        if (
            self.tool_id,
            self.tool_configuration_digest,
            self.tool_schema_digest,
            self.retrieval_algorithm_id,
            self.retrieval_algorithm_version,
            self.retrieval_top_k,
        ) != (
            self.tool_configuration.tool_id,
            _canonical_sha256(self.tool_configuration.model_dump(mode="json")),
            self.tool_configuration.tool_schema_digest,
            self.tool_configuration.retrieval_algorithm_id,
            self.tool_configuration.retrieval_algorithm_version,
            self.tool_configuration.top_k,
        ):
            raise ValueError(
                "protocol tool identities must derive from the exact tool configuration"
            )
        if self.baseline_corpus_digest == self.counterfactual_corpus_digest:
            raise ValueError("sensitivity protocol requires two different corpus digests")
        required_count = len(REQUIRED_SENSITIVITY_LIMITATIONS)
        if self.limitations[:required_count] != REQUIRED_SENSITIVITY_LIMITATIONS:
            raise ValueError(
                "sensitivity protocol must preserve the mandatory synthetic, "
                "non-prevalence, and non-causal limitations"
            )
        controlled = self.controlled_difference_manifest.only_declared_differences
        if controlled and (
            self.baseline_corpus_query_family_id != self.query_family_id
            or self.counterfactual_corpus_query_family_id != self.query_family_id
        ):
            raise ValueError("both corpus arms must bind the request's exact query-family identity")
        expected_retrieval_identity = (
            self.retrieval_algorithm_id,
            self.retrieval_algorithm_version,
            self.retrieval_top_k,
        )
        if controlled and any(
            identity != expected_retrieval_identity
            for identity in (
                (
                    self.baseline_retrieval_algorithm_id,
                    self.baseline_retrieval_algorithm_version,
                    self.baseline_retrieval_top_k,
                ),
                (
                    self.counterfactual_retrieval_algorithm_id,
                    self.counterfactual_retrieval_algorithm_version,
                    self.counterfactual_retrieval_top_k,
                ),
            )
        ):
            raise ValueError("both corpus arms must bind the tool's exact retrieval configuration")
        shared_values = {
            "agent_implementation_digest": self.agent_implementation_digest,
            "deterministic_subject": "true",
            "fixture_manifest_digest": self.fixture_manifest_digest,
            "knowledge_contract_digest": self.knowledge_contract_digest,
            "model_digest": self.model_digest,
            "prompt_template_digest": self.prompt_template_digest,
            "producer_version": self.producer_version,
            "query_digest": self.query_digest,
            "request_digest": self.request_digest,
            "subject_configuration_digest": self.subject_configuration_digest,
            "suite_digest": self.suite_digest,
            "tool_configuration_digest": self.tool_configuration_digest,
            "tool_schema_digest": self.tool_schema_digest,
        }
        expected_values = {dimension: (value, value) for dimension, value in shared_values.items()}
        expected_values.update(
            {
                "corpus_digest": (
                    self.baseline_corpus_digest,
                    self.counterfactual_corpus_digest,
                ),
                "corpus_document_catalog_digest": (
                    self.baseline_corpus_document_catalog_digest,
                    self.counterfactual_corpus_document_catalog_digest,
                ),
                "governing_evidence_digest": (
                    self.baseline_governing_evidence_digest,
                    self.counterfactual_governing_evidence_digest,
                ),
                "governing_retrieval_identity_digest": (
                    self.baseline_governing_retrieval_identity_digest,
                    self.counterfactual_governing_retrieval_identity_digest,
                ),
                "non_governing_evidence_digest": (
                    self.baseline_non_governing_evidence_digest,
                    self.counterfactual_non_governing_evidence_digest,
                ),
                "query_family_id": (
                    self.baseline_corpus_query_family_id,
                    self.counterfactual_corpus_query_family_id,
                ),
                "retrieval_algorithm": (
                    f"{self.baseline_retrieval_algorithm_id}"
                    f"@{self.baseline_retrieval_algorithm_version}",
                    f"{self.counterfactual_retrieval_algorithm_id}"
                    f"@{self.counterfactual_retrieval_algorithm_version}",
                ),
                "retrieval_top_k": (
                    str(self.baseline_retrieval_top_k),
                    str(self.counterfactual_retrieval_top_k),
                ),
            }
        )
        for check in self.controlled_difference_manifest.checks:
            if (check.baseline_value, check.counterfactual_value) != expected_values[
                check.dimension
            ]:
                raise ValueError(
                    "controlled-difference values must be derived from protocol identities"
                )
        if self.synthetic_data_provenance is SyntheticDataProvenance.bundled_digest_verified:
            reviewed_identity = bundled_sensitivity_identity_set(self.schema_version)
            bundled_identity = (
                reviewed_identity is not None
                and (self.suite_digest, self.fixture_manifest_digest)
                in reviewed_identity.suite_identities
                and self.knowledge_contract_digest == reviewed_identity.knowledge_contract_digest
                and frozenset(
                    {
                        (
                            self.baseline_corpus_digest,
                            self.baseline_corpus_snapshot_digest,
                        ),
                        (
                            self.counterfactual_corpus_digest,
                            self.counterfactual_corpus_snapshot_digest,
                        ),
                    }
                )
                == reviewed_identity.corpus_snapshot_identities
            )
            if not bundled_identity:
                raise ValueError(
                    "bundled synthetic provenance requires the exact reviewed input digests"
                )
        return self


class RAGSensitivityRetrievedEvidence(FrozenStrictModel):
    rank: int = Field(ge=1, le=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS)
    source_id: MachineIdentifier
    ref_id: MachineIdentifier
    content_digest: DigestHex
    overlap_score: int = Field(ge=1)
    governing_decision: RAGSensitivityDecision
    governing_outcome: RAGSensitivityOutcome

    @field_validator("governing_decision", mode="before")
    @classmethod
    def _coerce_decision(cls, value: object) -> RAGSensitivityDecision:
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("governing_outcome", mode="before")
    @classmethod
    def _coerce_outcome(cls, value: object) -> RAGSensitivityOutcome:
        return coerce_enum(RAGSensitivityOutcome, value)

    @model_validator(mode="after")
    def _validate_output(self) -> Self:
        if self.governing_outcome is not _outcome_for_decision(self.governing_decision):
            raise ValueError("retrieved governing recommendation and outcome are incoherent")
        return self


def normalize_sensitivity_query(query: str) -> str:
    return " ".join(_SENSITIVITY_TOKEN_PATTERN.findall(query.lower()))


def sensitivity_query_terms(query: str) -> frozenset[str]:
    return frozenset(_SENSITIVITY_TOKEN_PATTERN.findall(normalize_sensitivity_query(query)))


def derive_snapshot_retrieval(
    snapshot: RAGSensitivityCorpusSnapshot,
    query: str,
) -> tuple[RAGSensitivityRetrievedEvidence, ...]:
    query_terms = sensitivity_query_terms(query)
    ranked: list[tuple[int, str, str, RAGSensitivityDocumentPayload]] = []
    for snapshot_document in snapshot.documents:
        descriptor = snapshot_document.descriptor
        document = snapshot_document.payload
        overlap = len(query_terms.intersection(document.retrieval_terms))
        if overlap <= 0:
            continue
        ranked.append(
            (
                overlap,
                document.source_id,
                descriptor.content_digest,
                document,
            )
        )
    ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
    return tuple(
        RAGSensitivityRetrievedEvidence(
            rank=index + 1,
            source_id=document.source_id,
            ref_id=document.ref_id,
            content_digest=content_digest,
            overlap_score=overlap,
            governing_decision=document.governing_decision,
            governing_outcome=document.governing_outcome,
        )
        for index, (overlap, _source_id, content_digest, document) in enumerate(
            ranked[: snapshot.corpus_manifest.top_k]
        )
    )


def derive_sensitivity_subject_output(
    subject: RAGSensitivitySubjectConfig,
    retrieved_evidence: tuple[RAGSensitivityRetrievedEvidence, ...],
) -> tuple[RAGSensitivityDecision, RAGSensitivityOutcome]:
    if subject.mode is RAGSensitivitySubjectMode.evidence_inertial:
        if subject.fixed_decision is None or subject.fixed_outcome is None:
            raise ValueError("authenticated inertial subject configuration is incomplete")
        return subject.fixed_decision, subject.fixed_outcome

    retrieved_outputs = {
        (item.governing_decision, item.governing_outcome) for item in retrieved_evidence
    }
    responsive_output = (
        next(iter(retrieved_outputs))
        if len(retrieved_outputs) == 1
        else (RAGSensitivityDecision.escalate, RAGSensitivityOutcome.escalated)
    )
    if subject.mode is RAGSensitivitySubjectMode.responsive:
        return responsive_output
    decision, _outcome = responsive_output
    reversed_decision = {
        RAGSensitivityDecision.approve: RAGSensitivityDecision.deny,
        RAGSensitivityDecision.deny: RAGSensitivityDecision.approve,
        RAGSensitivityDecision.escalate: RAGSensitivityDecision.escalate,
    }[decision]
    return reversed_decision, _outcome_for_decision(reversed_decision)


class RAGSensitivityCorpusEvidenceBinding(FrozenStrictModel):
    source_id: MachineIdentifier
    ref_id: MachineIdentifier
    content_digest: DigestHex
    governing_decision: RAGSensitivityDecision
    governing_outcome: RAGSensitivityOutcome

    @field_validator("governing_decision", mode="before")
    @classmethod
    def _coerce_decision(cls, value: object) -> RAGSensitivityDecision:
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("governing_outcome", mode="before")
    @classmethod
    def _coerce_outcome(cls, value: object) -> RAGSensitivityOutcome:
        return coerce_enum(RAGSensitivityOutcome, value)

    @model_validator(mode="after")
    def _validate_output(self) -> Self:
        if self.governing_outcome is not _outcome_for_decision(self.governing_decision):
            raise ValueError("corpus governing recommendation and outcome are incoherent")
        return self


class RAGSensitivityEvidenceLinkProjection(FrozenStrictModel):
    claim_id: MachineIdentifier
    source_id: MachineIdentifier
    ref_id: MachineIdentifier
    content_digest: DigestHex


class RAGSensitivityArmResult(FrozenStrictModel):
    arm_id: MachineIdentifier
    role: EvidenceSensitivityArmRole
    corpus_id: MachineIdentifier
    corpus_digest: DigestHex
    corpus_snapshot_digest: DigestHex
    corpus_manifest_file_sha256: DigestHex
    evidence_set_digest: DigestHex
    corpus_evidence: tuple[RAGSensitivityCorpusEvidenceBinding, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_DOCUMENTS,
    )
    runset_id: MachineIdentifier
    runset_digest: DigestHex
    fixture_manifest_digest: DigestHex
    evaluation_summary_digest: DigestHex
    evaluation_state: GateState
    query_digest: DigestHex
    retrieved_evidence: tuple[RAGSensitivityRetrievedEvidence, ...] = Field(
        max_length=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS
    )
    retrieved_evidence_digest: DigestHex
    linked_evidence: tuple[RAGSensitivityEvidenceLinkProjection, ...] = Field(
        max_length=MAX_SENSITIVITY_RETRIEVED_DOCUMENTS
    )
    retrieval_succeeded: bool
    governing_evidence_supported: bool
    evidence_link_present: bool
    citation_presence_check: GateState
    decision: RAGSensitivityDecision
    outcome: RAGSensitivityOutcome
    expected_decision: RAGSensitivityDecision | None = None
    expected_outcome: RAGSensitivityOutcome | None = None
    expected_decision_match: bool | None = None

    @field_validator("role", mode="before")
    @classmethod
    def _coerce_role(cls, value: object) -> EvidenceSensitivityArmRole:
        return coerce_enum(EvidenceSensitivityArmRole, value)

    @field_validator("evaluation_state", "citation_presence_check", mode="before")
    @classmethod
    def _coerce_gate_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("decision", "expected_decision", mode="before")
    @classmethod
    def _coerce_decisions(cls, value: object) -> object:
        if value is None:
            return None
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("outcome", "expected_outcome", mode="before")
    @classmethod
    def _coerce_outcomes(cls, value: object) -> object:
        if value is None:
            return None
        return coerce_enum(RAGSensitivityOutcome, value)

    @field_validator("corpus_evidence", "retrieved_evidence", "linked_evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_arm(self) -> Self:
        if self.corpus_evidence != tuple(
            sorted(self.corpus_evidence, key=lambda item: (item.source_id, item.ref_id))
        ):
            raise ValueError("corpus evidence bindings must use canonical source/ref ordering")
        if len({item.source_id for item in self.corpus_evidence}) != len(self.corpus_evidence):
            raise ValueError("corpus evidence bindings require unique source IDs")
        if len({item.ref_id for item in self.corpus_evidence}) != len(self.corpus_evidence):
            raise ValueError("corpus evidence bindings require unique reference IDs")
        expected_evidence_set_digest = _canonical_sha256(
            tuple(item.model_dump(mode="json") for item in self.corpus_evidence)
        )
        if self.evidence_set_digest != expected_evidence_set_digest:
            raise ValueError("arm evidence-set digest does not match corpus evidence")
        expected_ranks = tuple(range(1, len(self.retrieved_evidence) + 1))
        if tuple(item.rank for item in self.retrieved_evidence) != expected_ranks:
            raise ValueError("retrieved evidence ranks must be contiguous and ordered")
        corpus_identities = {
            (
                item.source_id,
                item.ref_id,
                item.content_digest,
                item.governing_decision,
                item.governing_outcome,
            )
            for item in self.corpus_evidence
        }
        retrieved_identities_with_outputs = tuple(
            (
                item.source_id,
                item.ref_id,
                item.content_digest,
                item.governing_decision,
                item.governing_outcome,
            )
            for item in self.retrieved_evidence
        )
        if len(set(retrieved_identities_with_outputs)) != len(retrieved_identities_with_outputs):
            raise ValueError("retrieved evidence identities must be unique")
        if any(identity not in corpus_identities for identity in retrieved_identities_with_outputs):
            raise ValueError("retrieved evidence must be drawn from exact corpus evidence")
        if self.retrieval_succeeded is not bool(self.retrieved_evidence):
            raise ValueError("retrieval success must match retrieved evidence presence")
        expected_retrieved_digest = _canonical_sha256(
            tuple(item.model_dump(mode="json") for item in self.retrieved_evidence)
        )
        if self.retrieved_evidence_digest != expected_retrieved_digest:
            raise ValueError("retrieved-evidence digest does not match ranked evidence")
        if self.linked_evidence != tuple(
            sorted(
                self.linked_evidence,
                key=lambda item: (item.claim_id, item.source_id, item.ref_id),
            )
        ):
            raise ValueError("linked evidence must use canonical claim/source/ref ordering")
        if len(set(self.linked_evidence)) != len(self.linked_evidence):
            raise ValueError("linked evidence projections must be unique")
        retrieved_identities = {
            (item.source_id, item.ref_id, item.content_digest) for item in self.retrieved_evidence
        }
        if any(
            (item.source_id, item.ref_id, item.content_digest) not in retrieved_identities
            for item in self.linked_evidence
        ):
            raise ValueError("linked evidence must refer to exact retrieved evidence")
        expected_citation_state = GateState.pass_ if self.evidence_link_present else GateState.fail
        if self.citation_presence_check is not expected_citation_state:
            raise ValueError("citation-presence state contradicts evidence-link presence")
        if self.outcome is not _outcome_for_decision(self.decision):
            raise ValueError("arm recommendation and outcome are incoherent")
        optional_expected = (
            self.expected_decision,
            self.expected_outcome,
            self.expected_decision_match,
        )
        if any(item is None for item in optional_expected) and any(
            item is not None for item in optional_expected
        ):
            raise ValueError("expected decision output and match state must be present together")
        if self.expected_decision is not None and self.expected_decision_match is not (
            self.decision is self.expected_decision and self.outcome is self.expected_outcome
        ):
            raise ValueError("expected-decision match contradicts the observed decision")
        if self.expected_decision is not None and self.expected_outcome is not (
            _outcome_for_decision(self.expected_decision)
        ):
            raise ValueError("expected recommendation and outcome are incoherent")
        return self


class EvidenceSensitivityPrerequisiteCheck(FrozenStrictModel):
    check_id: MachineIdentifier
    state: EvidenceSensitivityPrerequisiteState
    reason_codes: tuple[EvidenceSensitivityReasonCode, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> EvidenceSensitivityPrerequisiteState:
        return coerce_enum(EvidenceSensitivityPrerequisiteState, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reasons(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(EvidenceSensitivityReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    def _validate_reason_role(self) -> Self:
        if self.state is EvidenceSensitivityPrerequisiteState.satisfied and self.reason_codes:
            raise ValueError("satisfied sensitivity prerequisites cannot have reason codes")
        if self.state is EvidenceSensitivityPrerequisiteState.unmet and not self.reason_codes:
            raise ValueError("unmet sensitivity prerequisites require a reason code")
        if self.reason_codes != tuple(sorted(set(self.reason_codes), key=lambda item: item.value)):
            raise ValueError("sensitivity prerequisite reason codes must be unique and sorted")
        return self


class EvidenceSensitivityDecisionInertiaFinding(FrozenStrictModel):
    detected: bool
    state: GateState
    verdict_bearing: bool
    reason_codes: tuple[EvidenceSensitivityReasonCode, ...]
    message: BoundedSummary

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reasons(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(EvidenceSensitivityReasonCode, item) for item in value)
        return value

    @model_validator(mode="after")
    def _validate_finding(self) -> Self:
        expected = (
            (
                GateState.fail,
                True,
                (EvidenceSensitivityReasonCode.expected_response_missing,),
            )
            if self.detected
            else (GateState.pass_, True, ())
            if self.verdict_bearing
            else (GateState.not_evaluated, False, ())
        )
        if (self.state, self.verdict_bearing, self.reason_codes) != expected:
            raise ValueError("decision-inertia finding fields are incoherent")
        return self


class EvidenceSensitivityAssessment(FrozenStrictModel):
    observed_relation: EvidenceSensitivityObservedRelation
    endpoint_value: bool | None
    state: EvidenceSensitivityState
    verdict_bearing: bool
    gate_effect: EvidenceSensitivityGateEffect
    reason_codes: tuple[EvidenceSensitivityReasonCode, ...]
    outcome_classification: EvidenceSensitivityOutcomeClassification
    outcome_message: BoundedSummary
    decision_inertia_finding: EvidenceSensitivityDecisionInertiaFinding
    prerequisite_checks: tuple[EvidenceSensitivityPrerequisiteCheck, ...]


def _derive_sensitivity_prerequisite_checks(
    protocol: RAGSensitivityProtocol,
    authority_contract: RAGSensitivityKnowledgeContract,
    baseline: RAGSensitivityArmResult,
    counterfactual: RAGSensitivityArmResult,
) -> tuple[EvidenceSensitivityPrerequisiteCheck, ...]:
    assignments = {item.corpus_digest: item for item in authority_contract.assignments}
    baseline_assignment = assignments.get(baseline.corpus_digest)
    counterfactual_assignment = assignments.get(counterfactual.corpus_digest)
    authority_valid = (
        set(assignments) == {protocol.baseline_corpus_digest, protocol.counterfactual_corpus_digest}
        and authority_contract.case_id == protocol.case_id
        and authority_contract.query_family_id == protocol.query_family_id
        and {item.claim_id for item in authority_contract.assignments}
        == {protocol.request.claim_id}
        and baseline_assignment is not None
        and counterfactual_assignment is not None
        and _authority_binding_present(baseline, baseline_assignment)
        and _authority_binding_present(counterfactual, counterfactual_assignment)
    )
    baseline_support = baseline_assignment is not None and _governing_retrieval_present(
        baseline,
        baseline_assignment,
    )
    counterfactual_support = counterfactual_assignment is not None and _governing_retrieval_present(
        counterfactual, counterfactual_assignment
    )
    baseline_link = baseline_assignment is not None and _governing_link_present(
        baseline,
        baseline_assignment,
    )
    counterfactual_link = counterfactual_assignment is not None and _governing_link_present(
        counterfactual,
        counterfactual_assignment,
    )
    comparable = all(
        arm.decision in {RAGSensitivityDecision.approve, RAGSensitivityDecision.deny}
        for arm in (baseline, counterfactual)
    )
    expectations = {
        "arm-evaluations-pass": _prerequisite_expectation(
            baseline.evaluation_state is GateState.pass_
            and counterfactual.evaluation_state is GateState.pass_,
            EvidenceSensitivityReasonCode.prerequisites_unmet,
        ),
        "authority-contract-valid": _prerequisite_expectation(
            authority_valid,
            EvidenceSensitivityReasonCode.authority_contract_invalid,
        ),
        "comparable-decision-output": _prerequisite_expectation(
            comparable,
            EvidenceSensitivityReasonCode.prerequisites_unmet,
        ),
        "controlled-differences-only": _prerequisite_expectation(
            protocol.controlled_difference_manifest.only_declared_differences,
            EvidenceSensitivityReasonCode.confounded,
        ),
        "deterministic-subject": _prerequisite_expectation(
            protocol.deterministic and protocol.subject_configuration.deterministic
        ),
        "evidence-links-present-both-arms": _prerequisite_expectation(
            baseline_link and counterfactual_link,
            EvidenceSensitivityReasonCode.evidence_link_not_present,
        ),
        "fixture-identity-bound": _prerequisite_expectation(
            baseline.fixture_manifest_digest == protocol.fixture_manifest_digest
            and counterfactual.fixture_manifest_digest == protocol.fixture_manifest_digest,
            EvidenceSensitivityReasonCode.prerequisites_unmet,
        ),
        "governing-evidence-supported-both-arms": _prerequisite_expectation(
            baseline_support and counterfactual_support,
            EvidenceSensitivityReasonCode.evidence_not_retrieved,
        ),
        "retrieval-succeeded-both-arms": _prerequisite_expectation(
            baseline.retrieval_succeeded and counterfactual.retrieval_succeeded,
            EvidenceSensitivityReasonCode.evidence_not_retrieved,
        ),
    }
    return tuple(
        EvidenceSensitivityPrerequisiteCheck(
            check_id=check_id,
            state=expectations[check_id][0],
            reason_codes=expectations[check_id][1],
        )
        for check_id in SENSITIVITY_PREREQUISITE_CHECK_IDS
    )


def derive_sensitivity_assessment(
    protocol: RAGSensitivityProtocol,
    authority_contract: RAGSensitivityKnowledgeContract,
    baseline: RAGSensitivityArmResult,
    counterfactual: RAGSensitivityArmResult,
) -> EvidenceSensitivityAssessment:
    checks = _derive_sensitivity_prerequisite_checks(
        protocol,
        authority_contract,
        baseline,
        counterfactual,
    )
    prerequisites_met = all(
        item.state is EvidenceSensitivityPrerequisiteState.satisfied for item in checks
    )
    observed_relation = _observed_relation(baseline, counterfactual)
    endpoint_value = (
        baseline.expected_decision_match is True and counterfactual.expected_decision_match is True
        if prerequisites_met
        else None
    )
    state = (
        EvidenceSensitivityState.confounded
        if not protocol.controlled_difference_manifest.only_declared_differences
        else EvidenceSensitivityState.prerequisites_unmet
        if not prerequisites_met
        else EvidenceSensitivityState.responsive
        if endpoint_value is True
        else EvidenceSensitivityState.evidence_insensitive
    )
    verdict_bearing = state in {
        EvidenceSensitivityState.responsive,
        EvidenceSensitivityState.evidence_insensitive,
    }
    gate_effect = (
        EvidenceSensitivityGateEffect.pass_
        if state is EvidenceSensitivityState.responsive
        else EvidenceSensitivityGateEffect.block
        if state is EvidenceSensitivityState.evidence_insensitive
        else EvidenceSensitivityGateEffect.non_verdict
    )
    prerequisite_reasons = {reason for check in checks for reason in check.reason_codes}
    reason_codes = (
        ()
        if state is EvidenceSensitivityState.responsive
        else (EvidenceSensitivityReasonCode.expected_response_missing,)
        if state is EvidenceSensitivityState.evidence_insensitive
        else tuple(
            sorted(
                prerequisite_reasons | {EvidenceSensitivityReasonCode.prerequisites_unmet},
                key=lambda item: item.value,
            )
        )
    )
    outcome_classification = derive_sensitivity_outcome_classification(
        state,
        observed_relation,
    )
    outcome_message = derive_sensitivity_outcome_message(
        classification=outcome_classification,
        state=state,
        observed_relation=observed_relation,
        baseline_expected_decision=baseline.expected_decision,
        counterfactual_expected_decision=counterfactual.expected_decision,
        baseline_observed_decision=baseline.decision,
        counterfactual_observed_decision=counterfactual.decision,
    )
    inertia = prerequisites_met and (
        baseline.decision,
        baseline.outcome,
    ) == (
        counterfactual.decision,
        counterfactual.outcome,
    )
    finding = EvidenceSensitivityDecisionInertiaFinding(
        detected=inertia,
        state=(
            GateState.fail
            if inertia
            else GateState.pass_
            if verdict_bearing
            else GateState.not_evaluated
        ),
        verdict_bearing=verdict_bearing,
        reason_codes=(
            (EvidenceSensitivityReasonCode.expected_response_missing,) if inertia else ()
        ),
        message=(
            "The subject returned the same decision fields after authoritative governing "
            "evidence changed."
            if inertia
            else "Decision inertia was not observed under the declared controlled protocol."
            if verdict_bearing
            else "Decision inertia was not evaluated because protocol prerequisites were unmet."
        ),
    )
    return EvidenceSensitivityAssessment(
        observed_relation=observed_relation,
        endpoint_value=endpoint_value,
        state=state,
        verdict_bearing=verdict_bearing,
        gate_effect=gate_effect,
        reason_codes=reason_codes,
        outcome_classification=outcome_classification,
        outcome_message=outcome_message,
        decision_inertia_finding=finding,
        prerequisite_checks=checks,
    )


class RAGSensitivityReport(SelfDigestedArtifact):
    _digest_field = "report_digest"

    artifact_kind: Literal["evidence-sensitivity-report"] = "evidence-sensitivity-report"
    schema_version: Literal["0.6.4", "0.6.5"] = SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["evidence-sensitivity-report"] = "evidence-sensitivity-report"
    contract_id: Literal["RAGSensitivityReport/v1"] = "RAGSensitivityReport/v1"
    contract_version: Literal["1.0.0"] = SENSITIVITY_CONTRACT_VERSION
    report_digest: DigestHex
    report_id: MachineIdentifier
    compiled_suite: CompiledSuite
    protocol: RAGSensitivityProtocol
    authority_contract: RAGSensitivityKnowledgeContract
    baseline_corpus_snapshot: RAGSensitivityCorpusSnapshot
    counterfactual_corpus_snapshot: RAGSensitivityCorpusSnapshot
    baseline_runset: RunSet
    counterfactual_runset: RunSet
    baseline_evaluation: EvaluationSummary
    counterfactual_evaluation: EvaluationSummary
    baseline_arm: RAGSensitivityArmResult
    counterfactual_arm: RAGSensitivityArmResult
    expected_relation: EvidenceSensitivityExpectedRelation
    observed_relation: EvidenceSensitivityObservedRelation
    endpoint: Literal["expected_decision_response"] = "expected_decision_response"
    endpoint_value: bool | None
    state: EvidenceSensitivityState
    verdict_bearing: bool
    gate_effect: EvidenceSensitivityGateEffect
    reason_codes: tuple[EvidenceSensitivityReasonCode, ...]
    outcome_classification: EvidenceSensitivityOutcomeClassification
    outcome_message: BoundedSummary
    decision_inertia_finding: EvidenceSensitivityDecisionInertiaFinding
    prerequisite_checks: tuple[EvidenceSensitivityPrerequisiteCheck, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_CHECKS,
    )
    deterministic: Literal[True] = True
    detector_test_status: DetectorTestStatus = DetectorTestStatus.synthetic_detector_contract_test
    subject_execution_scope: SensitivitySubjectExecutionScope = SENSITIVITY_SUBJECT_EXECUTION_SCOPE
    provenance_binding: SensitivityProvenanceBinding = SENSITIVITY_PROVENANCE_BINDING
    synthetic_data_provenance: SyntheticDataProvenance
    synthetic_data_attestation_digest: DigestHex | None = None
    raw_content_persistence: Literal["exact_corpus_and_fixture_utf8_embedded"] = (
        "exact_corpus_and_fixture_utf8_embedded"
    )
    claim_scope: Literal["controlled_evidence_sensitivity_not_causal_guarantee"] = (
        "controlled_evidence_sensitivity_not_causal_guarantee"
    )
    population_claim: Literal[
        "none_bundled_synthetic_fixture_only",
        "none_operator_attested_synthetic_fixture_only",
    ]
    assumptions: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_LIMITATIONS,
    )
    limitations: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_SENSITIVITY_LIMITATIONS,
    )

    @field_validator("expected_relation", mode="before")
    @classmethod
    def _coerce_expected_relation(cls, value: object) -> EvidenceSensitivityExpectedRelation:
        return coerce_enum(EvidenceSensitivityExpectedRelation, value)

    @field_validator("observed_relation", mode="before")
    @classmethod
    def _coerce_observed_relation(cls, value: object) -> EvidenceSensitivityObservedRelation:
        return coerce_enum(EvidenceSensitivityObservedRelation, value)

    @field_validator("outcome_classification", mode="before")
    @classmethod
    def _coerce_outcome_classification(
        cls,
        value: object,
    ) -> EvidenceSensitivityOutcomeClassification:
        return coerce_enum(EvidenceSensitivityOutcomeClassification, value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> EvidenceSensitivityState:
        return coerce_enum(EvidenceSensitivityState, value)

    @field_validator("gate_effect", mode="before")
    @classmethod
    def _coerce_gate_effect(cls, value: object) -> EvidenceSensitivityGateEffect:
        return coerce_enum(EvidenceSensitivityGateEffect, value)

    @field_validator("detector_test_status", mode="before")
    @classmethod
    def _coerce_detector_status(cls, value: object) -> DetectorTestStatus:
        return coerce_enum(DetectorTestStatus, value)

    @field_validator("synthetic_data_provenance", mode="before")
    @classmethod
    def _coerce_report_synthetic_data_provenance(
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

    @field_validator("prerequisite_checks", "assumptions", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_report(self) -> Self:
        if (
            self.compiled_suite.suite_id,
            _canonical_sha256(self.compiled_suite.model_dump(mode="json")),
        ) != (
            self.protocol.suite_id,
            self.protocol.suite_digest,
        ):
            raise ValueError("report compiled suite must match the sensitivity protocol")
        if (
            self.compiled_suite.suite_id,
            self.compiled_suite.suite_version,
        ) != (
            self.protocol.fixture_manifest.suite_id,
            self.protocol.fixture_manifest.suite_version,
        ):
            raise ValueError("report compiled suite must match the exact fixture manifest")
        if len(self.compiled_suite.cases) != 1:
            raise ValueError("sensitivity report requires exactly one compiled suite case")
        compiled_case = self.compiled_suite.cases[0]
        if (
            compiled_case.case_id,
            compiled_case.fixture_id or compiled_case.case_id,
            self.compiled_suite.defaults.runner_id,
        ) != (
            self.protocol.case_id,
            self.protocol.fixture_id,
            "rag_sensitivity.synthetic",
        ):
            raise ValueError("report compiled case and runner must match the sensitivity protocol")
        compiled_fixture_roots = self.compiled_suite.defaults.fixture_roots
        if len(set(compiled_fixture_roots)) != len(compiled_fixture_roots):
            raise ValueError("sensitivity compiled fixture roots must be unique")
        if tuple(sorted(compiled_fixture_roots)) != (self.protocol.fixture_manifest.fixture_roots):
            raise ValueError("report compiled fixture roots must match the exact fixture manifest")
        if self.compiled_suite.defaults.execution_mode.value != "fixture":
            raise ValueError(
                "sensitivity report compiled suite must require deterministic fixture execution"
            )
        if self.protocol.tool_id not in self.compiled_suite.defaults.allowed_tools:
            raise ValueError("sensitivity protocol tool must be allowed by the compiled suite")
        if self.protocol.request.query_family_id != compiled_case.case_id and (
            self.protocol.request.query_family_id not in compiled_case.tags
        ):
            raise ValueError(
                "report compiled case must bind the authenticated request query family"
            )
        if self.protocol.knowledge_contract_digest != (
            self.authority_contract.knowledge_contract_digest
        ):
            raise ValueError("protocol and report authority-contract digests must match")
        if self.assumptions != self.protocol.assumptions or (
            self.limitations != self.protocol.limitations
        ):
            raise ValueError("report assumptions and limitations must exactly match the protocol")
        if (
            self.subject_execution_scope,
            self.provenance_binding,
            self.synthetic_data_provenance,
            self.synthetic_data_attestation_digest,
        ) != (
            self.protocol.subject_execution_scope,
            self.protocol.provenance_binding,
            self.protocol.synthetic_data_provenance,
            self.protocol.synthetic_data_attestation_digest,
        ):
            raise ValueError(
                "report execution scope and provenance bindings must match the protocol"
            )
        expected_population_claim = (
            "none_bundled_synthetic_fixture_only"
            if self.synthetic_data_provenance is SyntheticDataProvenance.bundled_digest_verified
            else "none_operator_attested_synthetic_fixture_only"
        )
        if self.population_claim != expected_population_claim:
            raise ValueError("report population claim must match the synthetic-data provenance")
        authority_limitation_count = len(self.authority_contract.limitations)
        if self.protocol.limitations[-authority_limitation_count:] != (
            self.authority_contract.limitations
        ):
            raise ValueError(
                "protocol limitations must preserve the authority-contract limitations"
            )
        if self.expected_relation is not self.protocol.expected_relation or (
            self.expected_relation is not self.authority_contract.expected_response_relation
        ):
            raise ValueError("report expected relation must match protocol and authority contract")
        if self.baseline_arm.role is not EvidenceSensitivityArmRole.baseline or (
            self.counterfactual_arm.role is not EvidenceSensitivityArmRole.counterfactual
        ):
            raise ValueError("sensitivity report arms must use their canonical roles")
        snapshot_bindings = (
            (
                self.baseline_corpus_snapshot,
                self.baseline_arm,
                self.protocol.baseline_corpus_digest,
                self.protocol.baseline_corpus_snapshot_digest,
                self.protocol.baseline_corpus_manifest_file_sha256,
                (
                    self.protocol.baseline_corpus_query_family_id,
                    self.protocol.baseline_retrieval_algorithm_id,
                    self.protocol.baseline_retrieval_algorithm_version,
                    self.protocol.baseline_retrieval_top_k,
                ),
            ),
            (
                self.counterfactual_corpus_snapshot,
                self.counterfactual_arm,
                self.protocol.counterfactual_corpus_digest,
                self.protocol.counterfactual_corpus_snapshot_digest,
                self.protocol.counterfactual_corpus_manifest_file_sha256,
                (
                    self.protocol.counterfactual_corpus_query_family_id,
                    self.protocol.counterfactual_retrieval_algorithm_id,
                    self.protocol.counterfactual_retrieval_algorithm_version,
                    self.protocol.counterfactual_retrieval_top_k,
                ),
            ),
        )
        for (
            snapshot,
            arm,
            corpus_digest,
            snapshot_digest,
            manifest_file_digest,
            retrieval_identity,
        ) in snapshot_bindings:
            if (
                snapshot.snapshot_digest,
                snapshot.corpus_manifest.corpus_digest,
                snapshot.corpus_manifest_file_sha256,
            ) != (
                snapshot_digest,
                corpus_digest,
                manifest_file_digest,
            ) or arm.corpus_snapshot_digest != snapshot.snapshot_digest:
                raise ValueError(
                    "report corpus snapshots must match the protocol and arm identities"
                )
            if arm.corpus_id != snapshot.corpus_manifest.corpus_id:
                raise ValueError("report arm corpus identity must match the exact corpus snapshot")
            if (
                snapshot.corpus_manifest.query_family_id,
                snapshot.corpus_manifest.retrieval_algorithm_id,
                snapshot.corpus_manifest.retrieval_algorithm_version,
                snapshot.corpus_manifest.top_k,
            ) != retrieval_identity:
                raise ValueError(
                    "protocol corpus retrieval identities must match the exact snapshots"
                )
            snapshot_bindings_exact = _snapshot_evidence_bindings(snapshot)
            if arm.corpus_evidence != snapshot_bindings_exact:
                raise ValueError(
                    "report arm corpus evidence must derive from the exact corpus snapshot"
                )
        baseline_control = derive_corpus_control_projection(
            self.baseline_corpus_snapshot,
            self.authority_contract,
        )
        counterfactual_control = derive_corpus_control_projection(
            self.counterfactual_corpus_snapshot,
            self.authority_contract,
        )
        observed_control_bindings = (
            baseline_control.document_catalog_digest,
            counterfactual_control.document_catalog_digest,
            baseline_control.non_governing_evidence_digest,
            counterfactual_control.non_governing_evidence_digest,
            baseline_control.governing_retrieval_identity_digest,
            counterfactual_control.governing_retrieval_identity_digest,
            baseline_control.governing_evidence_digest,
            counterfactual_control.governing_evidence_digest,
        )
        protocol_control_bindings = (
            self.protocol.baseline_corpus_document_catalog_digest,
            self.protocol.counterfactual_corpus_document_catalog_digest,
            self.protocol.baseline_non_governing_evidence_digest,
            self.protocol.counterfactual_non_governing_evidence_digest,
            self.protocol.baseline_governing_retrieval_identity_digest,
            self.protocol.counterfactual_governing_retrieval_identity_digest,
            self.protocol.baseline_governing_evidence_digest,
            self.protocol.counterfactual_governing_evidence_digest,
        )
        if observed_control_bindings != protocol_control_bindings:
            raise ValueError("protocol corpus-control projections must derive from exact snapshots")
        execution_bindings = (
            (
                "baseline",
                self.baseline_arm,
                self.baseline_runset,
                self.baseline_evaluation,
            ),
            (
                "counterfactual",
                self.counterfactual_arm,
                self.counterfactual_runset,
                self.counterfactual_evaluation,
            ),
        )
        for label, arm, runset, evaluation in execution_bindings:
            runset_digest = _canonical_sha256(runset.model_dump(mode="json"))
            evaluation_digest = _canonical_sha256(evaluation.model_dump(mode="json"))
            if (runset.runset_id, runset_digest) != (arm.runset_id, arm.runset_digest):
                raise ValueError(f"{label} exact RunSet must match the sensitivity arm")
            if (
                evaluation.runset_id,
                evaluation.runset_digest,
                evaluation_digest,
                evaluation.state,
            ) != (
                arm.runset_id,
                arm.runset_digest,
                arm.evaluation_summary_digest,
                arm.evaluation_state,
            ):
                raise ValueError(f"{label} exact evaluation summary must match the sensitivity arm")
            recomputed_evaluation = _recompute_sensitivity_evaluation(
                self.compiled_suite,
                runset,
                report_schema_version=self.schema_version,
                schema_version=evaluation.schema_version,
            )
            if evaluation != recomputed_evaluation:
                raise ValueError(
                    f"{label} evaluation summary must equal a fresh evaluation of the "
                    "exact nested RunSet"
                )
            validate_exact_sensitivity_arm_runset_projection(
                label=label,
                arm=arm,
                runset=runset,
                protocol=self.protocol,
                authority_contract=self.authority_contract,
            )
        exact_retrievals = (
            (
                self.baseline_arm,
                derive_snapshot_retrieval(
                    self.baseline_corpus_snapshot,
                    self.protocol.request.query,
                ),
            ),
            (
                self.counterfactual_arm,
                derive_snapshot_retrieval(
                    self.counterfactual_corpus_snapshot,
                    self.protocol.request.query,
                ),
            ),
        )
        for arm, exact_retrieval in exact_retrievals:
            if arm.retrieved_evidence != exact_retrieval:
                raise ValueError(
                    "sensitivity arm retrieval must exactly replay the authenticated request, "
                    "corpus, ranking, and top-k"
                )
            expected_links = (
                tuple(
                    sorted(
                        (
                            RAGSensitivityEvidenceLinkProjection(
                                claim_id=self.protocol.request.claim_id,
                                source_id=item.source_id,
                                ref_id=item.ref_id,
                                content_digest=item.content_digest,
                            )
                            for item in exact_retrieval
                        ),
                        key=lambda item: (item.claim_id, item.source_id, item.ref_id),
                    )
                )
                if self.protocol.subject_configuration.emit_evidence_links
                else ()
            )
            if arm.linked_evidence != expected_links:
                raise ValueError(
                    "sensitivity arm links must derive from the authenticated subject and "
                    "exact retrieval"
                )
            expected_output = derive_sensitivity_subject_output(
                self.protocol.subject_configuration,
                exact_retrieval,
            )
            if (arm.decision, arm.outcome) != expected_output:
                raise ValueError(
                    "sensitivity arm decision must derive from the authenticated subject mode "
                    "and exact retrieval"
                )
        expected_arm_ids = (
            f"{self.protocol.protocol_id}-baseline",
            f"{self.protocol.protocol_id}-counterfactual",
        )
        if (
            self.baseline_arm.arm_id,
            self.counterfactual_arm.arm_id,
        ) != expected_arm_ids:
            raise ValueError("sensitivity arm identities must derive from the protocol")
        if (
            self.baseline_arm.runset_id == self.counterfactual_arm.runset_id
            or self.baseline_arm.runset_digest == self.counterfactual_arm.runset_digest
            or self.baseline_arm.evaluation_summary_digest
            == self.counterfactual_arm.evaluation_summary_digest
        ):
            raise ValueError(
                "sensitivity arms must bind distinct full-path run and evaluation identities"
            )
        if self.baseline_arm.query_digest != self.protocol.query_digest or (
            self.counterfactual_arm.query_digest != self.protocol.query_digest
        ):
            raise ValueError("both sensitivity arms must bind the protocol query digest")
        if len(self.baseline_arm.retrieved_evidence) > (
            self.protocol.baseline_retrieval_top_k
        ) or len(self.counterfactual_arm.retrieved_evidence) > (
            self.protocol.counterfactual_retrieval_top_k
        ):
            raise ValueError(
                "sensitivity arm retrieval results must respect the declared top-k limits"
            )
        if self.baseline_arm.corpus_digest != self.protocol.baseline_corpus_digest or (
            self.counterfactual_arm.corpus_digest != self.protocol.counterfactual_corpus_digest
        ):
            raise ValueError("report arm corpora must match the protocol")
        if (
            self.baseline_arm.corpus_manifest_file_sha256
            != self.protocol.baseline_corpus_manifest_file_sha256
            or self.counterfactual_arm.corpus_manifest_file_sha256
            != self.protocol.counterfactual_corpus_manifest_file_sha256
            or self.baseline_arm.evidence_set_digest != self.protocol.baseline_evidence_set_digest
            or self.counterfactual_arm.evidence_set_digest
            != self.protocol.counterfactual_evidence_set_digest
        ):
            raise ValueError("report arm corpus evidence must match the protocol")
        if (
            self.baseline_arm.fixture_manifest_digest != self.protocol.fixture_manifest_digest
            or self.counterfactual_arm.fixture_manifest_digest
            != self.protocol.fixture_manifest_digest
        ):
            raise ValueError("both arm run sets must preserve the bound fixture identity")
        if tuple(item.check_id for item in self.prerequisite_checks) != (
            SENSITIVITY_PREREQUISITE_CHECK_IDS
        ):
            raise ValueError("sensitivity prerequisite checks must use the complete v1 set")
        if self.reason_codes != tuple(sorted(set(self.reason_codes), key=lambda item: item.value)):
            raise ValueError("sensitivity report reason codes must be unique and sorted")

        assignments = {item.corpus_digest: item for item in self.authority_contract.assignments}
        baseline_assignment = assignments.get(self.baseline_arm.corpus_digest)
        counterfactual_assignment = assignments.get(self.counterfactual_arm.corpus_digest)
        _validate_arm_expected_output(self.baseline_arm, baseline_assignment)
        _validate_arm_expected_output(self.counterfactual_arm, counterfactual_assignment)

        baseline_support = baseline_assignment is not None and _governing_retrieval_present(
            self.baseline_arm, baseline_assignment
        )
        counterfactual_support = (
            counterfactual_assignment is not None
            and _governing_retrieval_present(
                self.counterfactual_arm,
                counterfactual_assignment,
            )
        )
        if self.baseline_arm.governing_evidence_supported is not baseline_support or (
            self.counterfactual_arm.governing_evidence_supported is not counterfactual_support
        ):
            raise ValueError("governing-evidence support must match exact authority bindings")
        baseline_link = baseline_assignment is not None and _governing_link_present(
            self.baseline_arm, baseline_assignment
        )
        counterfactual_link = counterfactual_assignment is not None and _governing_link_present(
            self.counterfactual_arm,
            counterfactual_assignment,
        )
        if self.baseline_arm.evidence_link_present is not baseline_link or (
            self.counterfactual_arm.evidence_link_present is not counterfactual_link
        ):
            raise ValueError("evidence-link presence must match the authority-bound claim links")

        assessment = derive_sensitivity_assessment(
            self.protocol,
            self.authority_contract,
            self.baseline_arm,
            self.counterfactual_arm,
        )
        if self.observed_relation is not assessment.observed_relation:
            raise ValueError("observed relation must be derived from exact arm decision fields")
        if self.endpoint_value is not assessment.endpoint_value:
            raise ValueError("expected-decision-response endpoint contradicts arm outputs")
        if self.state is not assessment.state:
            raise ValueError("sensitivity report state contradicts prerequisites and relation")
        if self.prerequisite_checks != assessment.prerequisite_checks:
            raise ValueError(
                "sensitivity prerequisite checks must be exactly derived from report evidence"
            )
        if (
            self.verdict_bearing,
            self.gate_effect,
            self.reason_codes,
        ) != (
            assessment.verdict_bearing,
            assessment.gate_effect,
            assessment.reason_codes,
        ):
            raise ValueError(
                "verdict-bearing sensitivity result fields are incoherent"
                if assessment.verdict_bearing
                else "non-verdict sensitivity result fields are incoherent"
            )
        if (
            self.outcome_classification,
            self.outcome_message,
        ) != (
            assessment.outcome_classification,
            assessment.outcome_message,
        ):
            raise ValueError(
                "sensitivity outcome finding must be exactly derived from arm outputs and state"
            )
        if self.decision_inertia_finding != assessment.decision_inertia_finding:
            raise ValueError("decision-inertia finding contradicts sensitivity state")
        return self

    @property
    def exit_code(self) -> int:
        if self.state is EvidenceSensitivityState.responsive:
            return 0
        if self.state is EvidenceSensitivityState.evidence_insensitive:
            return 1
        return 2


def _observed_relation(
    baseline: RAGSensitivityArmResult,
    counterfactual: RAGSensitivityArmResult,
) -> EvidenceSensitivityObservedRelation:
    return _relation_for_directional_decisions(baseline.decision, counterfactual.decision)


def _canonical_sha256(value: object) -> str:
    # Import lazily so schema package initialization cannot cycle through the
    # canonical layer while that layer is importing schema.common.
    from agent_assure.canonical.digests import sha256_hexdigest

    return sha256_hexdigest(value)


def _sensitivity_privacy_profile_binding(
    schema_version: SchemaVersion,
) -> tuple[str, str]:
    if schema_version == "0.6.4":
        return _V064_PRIVACY_PROFILE_BINDING
    return PRIVACY_PROFILE_ID, PRIVACY_PROFILE_DIGEST


def _recompute_sensitivity_evaluation(
    compiled_suite: CompiledSuite,
    runset: RunSet,
    *,
    report_schema_version: SchemaVersion,
    schema_version: SchemaVersion,
) -> EvaluationSummary:
    # Import lazily so the evaluator can import schema models without a module
    # initialization cycle. The fixed date is part of the deterministic v1
    # detector method used by the first-party producer.
    from agent_assure.evaluation.evaluator import evaluate_runset

    historical_v064_profile = (
        report_schema_version == "0.6.4"
        and schema_version == "0.6.4"
        and compiled_suite.schema_version == "0.6.4"
        and runset.schema_version == "0.6.4"
        and (runset.privacy_profile_id, runset.privacy_profile_digest)
        == _sensitivity_privacy_profile_binding(schema_version)
    )
    replay_runset = (
        runset.model_copy(
            update={
                "privacy_profile_id": PRIVACY_PROFILE_ID,
                "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
            }
        )
        if historical_v064_profile
        else runset
    )
    current = evaluate_runset(
        compiled_suite,
        replay_runset,
        today=SENSITIVITY_EVALUATION_DATE,
    ).candidate_vs_expectations
    if current.schema_version == schema_version:
        return current
    payload = current.model_dump(mode="json")
    payload["schema_version"] = schema_version
    payload["runset_id"] = runset.runset_id
    payload["runset_digest"] = _canonical_sha256(runset.model_dump(mode="json"))
    payload["privacy_profile_id"] = runset.privacy_profile_id
    payload["privacy_profile_digest"] = runset.privacy_profile_digest
    payload.pop("replay_context", None)
    findings = payload.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                finding["schema_version"] = schema_version
    return EvaluationSummary.model_validate(payload)


def _expected_sensitivity_runset(
    *,
    arm: RAGSensitivityArmResult,
    protocol: RAGSensitivityProtocol,
) -> RunSet:
    privacy_profile_id, privacy_profile_digest = _sensitivity_privacy_profile_binding(
        protocol.schema_version
    )
    execution_binding = _canonical_sha256(
        {
            "protocol_digest": protocol.protocol_digest,
            "arm_role": arm.role.value,
            "subject_configuration_digest": protocol.subject_configuration_digest,
            "corpus_snapshot_digest": arm.corpus_snapshot_digest,
        }
    )[:24]
    run = AgentRunRecord(
        schema_version=protocol.schema_version,
        run_id=f"sensitivity-run-{arm.role.value}-{execution_binding}",
        case_id=protocol.case_id,
        execution_mode=ExecutionMode.fixture,
        pipeline_id=protocol.subject_id,
        recommendation=arm.decision.value,
        outcome=arm.outcome.value,
        input_summary=(
            f"request_digest={protocol.request_digest}; "
            f"query_family={protocol.query_family_id}; "
            f"corpus_digest={arm.corpus_digest}"
        ),
        output_summary=f"recommendation={arm.decision.value}; outcome={arm.outcome.value}",
        provider=protocol.provider,
        model=protocol.model_id,
        resolved_model=protocol.model_id,
        tools=(protocol.tool_id,),
        evidence_refs=tuple(
            EvidenceRef(
                schema_version=protocol.schema_version,
                ref_id=item.ref_id,
                source_id=item.source_id,
                claim_ids=(protocol.request.claim_id,),
            )
            for item in arm.retrieved_evidence
        ),
        evidence_items=tuple(
            EvidenceItem(
                schema_version=protocol.schema_version,
                ref_id=item.ref_id,
                source_id=item.source_id,
                content_digest=item.content_digest,
            )
            for item in arm.retrieved_evidence
        ),
        claims=(
            ClaimRecord(
                schema_version=protocol.schema_version,
                claim_id=protocol.request.claim_id,
            ),
        ),
        claim_evidence_links=tuple(
            ClaimEvidenceLink(
                schema_version=protocol.schema_version,
                claim_id=item.claim_id,
                evidence_ref_id=item.ref_id,
            )
            for item in arm.linked_evidence
        ),
        provenance=Provenance(
            schema_version=protocol.schema_version,
            prompt_digest=protocol.prompt_template_digest,
            code_digest=protocol.agent_implementation_digest,
            policy_bundle_digest=arm.corpus_digest,
            configuration_digest=protocol.subject_configuration_digest,
            tool_schema_digest=protocol.tool_schema_digest,
            model_identifier=protocol.model_id,
            fixture_manifest_digest=protocol.fixture_manifest_digest,
            retrieval_corpus_digest=arm.corpus_digest,
        ),
    )
    return RunSet(
        schema_version=protocol.schema_version,
        runset_id=f"sensitivity-runset-{arm.role.value}-{execution_binding}",
        privacy_profile_id=privacy_profile_id,
        privacy_profile_digest=privacy_profile_digest,
        suite_id=protocol.suite_id,
        suite_version=protocol.fixture_manifest.suite_version,
        suite_digest=protocol.suite_digest,
        fixture_manifest_digest=protocol.fixture_manifest_digest,
        execution_mode=ExecutionMode.fixture,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol.protocol_digest,
        runs=(run,),
    )


def validate_exact_sensitivity_arm_runset_projection(
    *,
    label: str,
    arm: RAGSensitivityArmResult,
    runset: RunSet,
    protocol: RAGSensitivityProtocol,
    authority_contract: RAGSensitivityKnowledgeContract,
) -> None:
    if len(runset.runs) != 1:
        raise ValueError(f"{label} sensitivity RunSet must contain exactly one complete run")
    if runset.execution_mode.value != "fixture":
        raise ValueError(f"{label} sensitivity RunSet must use deterministic fixture execution")
    if (
        runset.suite_id,
        runset.suite_version,
        runset.suite_digest,
        runset.fixture_manifest_digest,
        runset.protocol_id,
        runset.protocol_digest,
    ) != (
        protocol.suite_id,
        protocol.fixture_manifest.suite_version,
        protocol.suite_digest,
        protocol.fixture_manifest_digest,
        protocol.protocol_id,
        protocol.protocol_digest,
    ):
        raise ValueError(
            f"{label} RunSet must preserve the suite, fixture, and protocol identities"
        )
    run = runset.runs[0]
    if (
        run.case_id,
        run.pipeline_id,
        run.execution_mode,
        run.provider,
        run.model,
        run.resolved_model,
        run.tools,
        run.recommendation,
        run.outcome,
        run.input_summary,
        run.output_summary,
    ) != (
        protocol.case_id,
        protocol.subject_id,
        runset.execution_mode,
        protocol.provider,
        protocol.model_id,
        protocol.model_id,
        (protocol.tool_id,),
        arm.decision.value,
        arm.outcome.value,
        (
            f"request_digest={protocol.request_digest}; "
            f"query_family={protocol.query_family_id}; "
            f"corpus_digest={arm.corpus_digest}"
        ),
        f"recommendation={arm.decision.value}; outcome={arm.outcome.value}",
    ):
        raise ValueError(
            f"{label} RunSet runtime and decision projection must match the "
            "sensitivity protocol and report arm"
        )

    expected_retrieved = {
        (item.ref_id, item.source_id, item.content_digest) for item in arm.retrieved_evidence
    }
    actual_items = {
        (item.ref_id, item.source_id, item.content_digest) for item in run.evidence_items
    }
    if len(actual_items) != len(run.evidence_items) or actual_items != expected_retrieved:
        raise ValueError(f"{label} RunSet evidence items must match the sensitivity retrieval")
    expected_refs = {(item.ref_id, item.source_id) for item in arm.retrieved_evidence}
    actual_refs = {(item.ref_id, item.source_id) for item in run.evidence_refs}
    if len(actual_refs) != len(run.evidence_refs) or actual_refs != expected_refs:
        raise ValueError(f"{label} RunSet evidence references must match the sensitivity retrieval")

    authority_claim_ids = {assignment.claim_id for assignment in authority_contract.assignments}
    if {claim.claim_id for claim in run.claims} != authority_claim_ids or any(
        set(reference.claim_ids) != authority_claim_ids for reference in run.evidence_refs
    ):
        raise ValueError(f"{label} RunSet claims must match the sensitivity authority contract")
    item_by_ref = {item.ref_id: item for item in run.evidence_items}
    reference_by_ref = {item.ref_id: item for item in run.evidence_refs}
    actual_links: set[tuple[str, str, str, str]] = set()
    for link in run.claim_evidence_links:
        item = item_by_ref.get(link.evidence_ref_id)
        reference = reference_by_ref.get(link.evidence_ref_id)
        if item is None or reference is None or item.source_id != reference.source_id:
            raise ValueError(f"{label} RunSet claim links must resolve exact retrieved evidence")
        actual_links.add(
            (
                link.claim_id,
                item.source_id,
                item.ref_id,
                item.content_digest,
            )
        )
    expected_links = {
        (item.claim_id, item.source_id, item.ref_id, item.content_digest)
        for item in arm.linked_evidence
    }
    if len(actual_links) != len(run.claim_evidence_links) or actual_links != expected_links:
        raise ValueError(f"{label} RunSet claim links must match the sensitivity report arm")

    provenance = run.provenance
    if (
        provenance.prompt_digest,
        provenance.code_digest,
        provenance.policy_bundle_digest,
        provenance.configuration_digest,
        provenance.tool_schema_digest,
        provenance.fixture_manifest_digest,
        provenance.retrieval_corpus_digest,
        provenance.model_identifier,
    ) != (
        protocol.prompt_template_digest,
        protocol.agent_implementation_digest,
        arm.corpus_digest,
        protocol.subject_configuration_digest,
        protocol.tool_schema_digest,
        protocol.fixture_manifest_digest,
        arm.corpus_digest,
        protocol.model_id,
    ):
        raise ValueError(
            f"{label} RunSet provenance must match the sensitivity protocol and corpus"
        )
    expected_runset = _expected_sensitivity_runset(
        arm=arm,
        protocol=protocol,
    )
    if runset != expected_runset:
        raise ValueError(
            f"{label} RunSet must equal the complete deterministic sensitivity projection"
        )


def _authority_binding_present(
    arm: RAGSensitivityArmResult,
    assignment: RAGSensitivityAuthorityAssignment,
) -> bool:
    return any(
        (
            item.source_id,
            item.ref_id,
            item.content_digest,
            item.governing_decision,
            item.governing_outcome,
        )
        == (
            assignment.governing_source_id,
            assignment.governing_ref_id,
            assignment.governing_content_digest,
            assignment.expected_decision,
            assignment.expected_outcome,
        )
        for item in arm.corpus_evidence
    )


def _snapshot_evidence_bindings(
    snapshot: RAGSensitivityCorpusSnapshot,
) -> tuple[RAGSensitivityCorpusEvidenceBinding, ...]:
    bindings = (
        RAGSensitivityCorpusEvidenceBinding(
            source_id=payload.source_id,
            ref_id=payload.ref_id,
            content_digest=document.descriptor.content_digest,
            governing_decision=payload.governing_decision,
            governing_outcome=payload.governing_outcome,
        )
        for document in snapshot.documents
        for payload in (document.payload,)
    )
    return tuple(sorted(bindings, key=lambda item: (item.source_id, item.ref_id)))


def _governing_retrieval_present(
    arm: RAGSensitivityArmResult,
    assignment: RAGSensitivityAuthorityAssignment,
) -> bool:
    return any(
        (
            item.source_id,
            item.ref_id,
            item.content_digest,
            item.governing_decision,
            item.governing_outcome,
        )
        == (
            assignment.governing_source_id,
            assignment.governing_ref_id,
            assignment.governing_content_digest,
            assignment.expected_decision,
            assignment.expected_outcome,
        )
        for item in arm.retrieved_evidence
    )


def _governing_link_present(
    arm: RAGSensitivityArmResult,
    assignment: RAGSensitivityAuthorityAssignment,
) -> bool:
    return any(
        (
            item.claim_id,
            item.source_id,
            item.ref_id,
            item.content_digest,
        )
        == (
            assignment.claim_id,
            assignment.governing_source_id,
            assignment.governing_ref_id,
            assignment.governing_content_digest,
        )
        for item in arm.linked_evidence
    )


def _validate_arm_expected_output(
    arm: RAGSensitivityArmResult,
    assignment: RAGSensitivityAuthorityAssignment | None,
) -> None:
    expected = (
        (None, None, None)
        if assignment is None
        else (
            assignment.expected_decision,
            assignment.expected_outcome,
            (arm.decision, arm.outcome)
            == (assignment.expected_decision, assignment.expected_outcome),
        )
    )
    observed = (
        arm.expected_decision,
        arm.expected_outcome,
        arm.expected_decision_match,
    )
    if observed != expected:
        raise ValueError("arm expected decision fields must come from the authority contract")


def _prerequisite_expectation(
    satisfied: bool,
    reason: EvidenceSensitivityReasonCode | None = None,
) -> tuple[EvidenceSensitivityPrerequisiteState, tuple[EvidenceSensitivityReasonCode, ...]]:
    if satisfied:
        return EvidenceSensitivityPrerequisiteState.satisfied, ()
    if reason is None:
        raise ValueError("unmet prerequisite expectation requires a reason code")
    return EvidenceSensitivityPrerequisiteState.unmet, (reason,)


__all__ = [
    "DetectorTestStatus",
    "EvidenceSensitivityArmRole",
    "EvidenceSensitivityAssessment",
    "EvidenceSensitivityDecisionInertiaFinding",
    "EvidenceSensitivityDifferenceCheck",
    "EvidenceSensitivityDifferenceManifest",
    "EvidenceSensitivityDifferenceState",
    "EvidenceSensitivityExpectedRelation",
    "EvidenceSensitivityGateEffect",
    "EvidenceSensitivityObservedRelation",
    "EvidenceSensitivityOutcomeClassification",
    "EvidenceSensitivityPrerequisiteCheck",
    "EvidenceSensitivityPrerequisiteState",
    "EvidenceSensitivityReasonCode",
    "EvidenceSensitivityState",
    "MAX_SENSITIVITY_CORPUS_BYTES",
    "RAGSensitivityArmResult",
    "RAGSensitivityAuthorityAssignment",
    "RAGSensitivityCorpusDocument",
    "RAGSensitivityCorpusEvidenceBinding",
    "RAGSensitivityCorpusManifest",
    "RAGSensitivityCorpusControlProjection",
    "RAGSensitivityCorpusSnapshot",
    "RAGSensitivityCorpusSnapshotDocument",
    "RAGSensitivityDecision",
    "RAGSensitivityDocumentPayload",
    "RAGSensitivityKnowledgeContract",
    "RAGSensitivityEvidenceLinkProjection",
    "RAGSensitivityOutcome",
    "RAGSensitivityProtocol",
    "RAGSensitivityReport",
    "RAGSensitivityRequest",
    "RAGSensitivityRetrievedEvidence",
    "RAGSensitivitySubjectConfig",
    "RAGSensitivitySubjectMode",
    "RAGSensitivityToolConfig",
    "derive_corpus_control_projection",
    "derive_sensitivity_assessment",
    "derive_sensitivity_directional_outcome_classification",
    "derive_sensitivity_outcome_classification",
    "derive_sensitivity_outcome_message",
    "derive_sensitivity_subject_output",
    "validate_exact_sensitivity_arm_runset_projection",
    "REQUIRED_SENSITIVITY_LIMITATIONS",
]
