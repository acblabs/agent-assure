from __future__ import annotations

from collections import Counter
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, localcontext
from enum import StrEnum
from typing import Annotated, Any, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationInfo, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.io_limits import MAX_PERSISTED_OBSERVATIONS
from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.common import (
    DigestHex,
    MachineIdentifier,
    coerce_enum,
    coerce_tuple,
    decimal_string,
)
from agent_assure.schema.mutation import SelfDigestedArtifact
from agent_assure.schema.sensitivity import (
    RAGSensitivityCaseAuthorityBinding,
    RAGSensitivityDecision,
    RAGSensitivityOutcome,
)
from agent_assure.statistics.cluster_binomial import (
    MAX_MONTE_CARLO_BERNOULLI_DRAWS,
    PROBABILITY_SCALE,
    RATIONAL_BERNOULLI_SAMPLER_ID,
    SHA256_COUNTER_BITSTREAM_ID,
    analyze_cluster_binomial,
    cluster_binomial_rejection_region_contains,
    exact_binomial_upper_tail,
    plan_cluster_binomial_design,
)

STOCHASTIC_SENSITIVITY_SCHEMA_VERSION: Literal["0.6.5"] = "0.6.5"
STOCHASTIC_SENSITIVITY_CONTRACT_VERSION: Literal["1.0.0"] = "1.0.0"
MAX_PAIRED_OBSERVATIONS = MAX_PERSISTED_OBSERVATIONS
# Exact binomial expressions and standalone power planning retain their
# separately bounded 10,000-trial analytical domain. Executable protocols are
# constrained by MAX_PAIRED_OBSERVATIONS, so they cannot allocate or persist
# more than the RunSet observation envelope.
MAX_PLANNED_CASES = 10_000
MAX_COUPLING_DIMENSIONS = 64
MAX_MONTE_CARLO_RESAMPLES = 1_000_000
CONFIRMATORY_STOCHASTIC_ADAPTER_IDS = frozenset({"openai-chat-completions"})
UnitDecimalString = Annotated[str, Field(pattern=r"^(0|1)\.[0-9]{6}$")]
PositiveDecimalString = Annotated[
    str,
    Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$"),
]

_LIVE_REQUIRED_COUPLING_DIMENSIONS = (
    "provider_sampling_randomness",
    "temporal_execution_order",
)


def _array_contains(value: str) -> dict[str, Any]:
    return {"contains": {"const": value}}


def _array_excludes_any(values: tuple[str, ...]) -> dict[str, Any]:
    return {"not": {"contains": {"enum": list(values)}}}


def _declares_unshared_dimension(value: str) -> dict[str, Any]:
    return {
        "anyOf": [
            {
                "required": [partition],
                "properties": {partition: _array_contains(value)},
            }
            for partition in ("intentionally_different", "not_shared", "unknown")
        ]
    }


def _coupling_descriptor_json_schema_extra(schema: dict[str, Any]) -> None:
    """Expose v1 coupling safety invariants to schema-only consumers."""

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise TypeError("coupling descriptor JSON Schema properties must be an object")
    seed_evidence = properties.get("provider_seed_sharing_evidence_digest")
    variance_claim = properties.get("variance_reduction_claim_permitted")
    if not isinstance(seed_evidence, dict) or not isinstance(variance_claim, dict):
        raise TypeError("coupling descriptor JSON Schema safety fields are unavailable")
    seed_evidence["const"] = None
    variance_claim["const"] = False

    rules = schema.setdefault("allOf", [])
    if not isinstance(rules, list):
        raise TypeError("coupling descriptor JSON Schema allOf must be a list")
    rules.extend(
        (
            {
                "if": {
                    "required": ["pairing_identity_verified"],
                    "properties": {"pairing_identity_verified": {"const": False}},
                },
                "then": {
                    "required": ["classification"],
                    "properties": {"classification": {"const": "unpaired"}},
                },
            },
            {
                "if": {
                    "required": ["pairing_identity_verified"],
                    "properties": {"pairing_identity_verified": {"const": True}},
                },
                "then": {
                    "required": ["classification"],
                    "properties": {"classification": {"not": {"const": "unpaired"}}},
                },
            },
        )
    )
    for condition in CouplingCondition:
        condition_value = condition.value
        rules.append(
            {
                "if": {
                    "required": ["classification", "stochastic_dimensions"],
                    "properties": {
                        "classification": {"const": "fully_coupled"},
                        "stochastic_dimensions": _array_contains(condition_value),
                    },
                },
                "then": {
                    "required": ["shared"],
                    "properties": {
                        "shared": _array_contains(condition_value),
                        "intentionally_different": {"not": _array_contains(condition_value)},
                        "not_shared": {"not": _array_contains(condition_value)},
                        "unknown": {"not": _array_contains(condition_value)},
                    },
                },
            }
        )


def _repeated_protocol_json_schema_extra(schema: dict[str, Any]) -> None:
    """Expose live coupling and confirmatory requirements to schema-only readers."""

    rules = schema.setdefault("allOf", [])
    if not isinstance(rules, list):
        raise TypeError("repeated protocol JSON Schema allOf must be a list")
    supported_adapters = sorted(CONFIRMATORY_STOCHASTIC_ADAPTER_IDS)
    rules.append(
        {
            "if": {
                "required": ["execution_mode", "interpretation"],
                "properties": {
                    "execution_mode": {"const": "stochastic_live"},
                    "interpretation": {"const": "confirmatory"},
                },
            },
            "then": {
                "required": ["case_authority_bindings"],
                "properties": {
                    "case_authority_bindings": {"minItems": 1},
                    "baseline_arm": {
                        "required": ["adapter_id"],
                        "properties": {
                            "adapter_id": {"enum": supported_adapters},
                        },
                    },
                    "counterfactual_arm": {
                        "required": ["adapter_id"],
                        "properties": {
                            "adapter_id": {"enum": supported_adapters},
                        },
                    },
                    "coupling": {
                        "required": ["classification"],
                        "properties": {
                            "classification": {"not": {"enum": ["unpaired", "unknown"]}},
                            "unknown": _array_excludes_any(_LIVE_REQUIRED_COUPLING_DIMENSIONS),
                        },
                    },
                },
            },
        }
    )
    rules.append(
        {
            "if": {
                "required": ["execution_mode"],
                "properties": {
                    "execution_mode": {"const": "stochastic_live"},
                },
            },
            "then": {
                "properties": {
                    "coupling": {
                        "required": ["stochastic_dimensions"],
                        "allOf": [
                            *(
                                {
                                    "properties": {
                                        "stochastic_dimensions": _array_contains(dimension)
                                    }
                                }
                                for dimension in _LIVE_REQUIRED_COUPLING_DIMENSIONS
                            ),
                            {
                                "properties": {
                                    "shared": _array_excludes_any(
                                        _LIVE_REQUIRED_COUPLING_DIMENSIONS
                                    )
                                }
                            },
                            *(
                                _declares_unshared_dimension(dimension)
                                for dimension in _LIVE_REQUIRED_COUPLING_DIMENSIONS
                            ),
                        ],
                    }
                }
            },
        }
    )


class CouplingClassification(StrEnum):
    fully_coupled = "fully_coupled"
    partially_coupled = "partially_coupled"
    nominally_paired = "nominally_paired"
    unpaired = "unpaired"
    unknown = "unknown"


class SensitivityInterpretation(StrEnum):
    confirmatory = "confirmatory"
    exploratory = "exploratory"


class SensitivityExecutionMode(StrEnum):
    stochastic_live = "stochastic_live"
    deterministic_fixture = "deterministic_fixture"


class PairDisposition(StrEnum):
    included = "included"
    missing_both = "missing_both"
    missing_baseline = "missing_baseline"
    missing_counterfactual = "missing_counterfactual"
    excluded_baseline = "excluded_baseline"
    excluded_counterfactual = "excluded_counterfactual"
    excluded_both = "excluded_both"
    invalid_baseline = "invalid_baseline"
    invalid_counterfactual = "invalid_counterfactual"
    invalid_both = "invalid_both"
    identity_mismatch = "identity_mismatch"
    undeclared_arm_difference = "undeclared_arm_difference"


class SufficiencyState(StrEnum):
    satisfied = "satisfied"
    prerequisites_unmet = "prerequisites_unmet"
    inconclusive = "inconclusive"


class PrerequisiteCheckState(StrEnum):
    satisfied = "satisfied"
    unmet = "unmet"
    not_evaluated = "not_evaluated"


class StochasticSensitivityState(StrEnum):
    pass_ = "pass"
    block = "block"
    prerequisites_unmet = "prerequisites_unmet"
    inconclusive = "inconclusive"


class StochasticGateEffect(StrEnum):
    pass_ = "pass"
    block = "block"
    non_verdict = "non_verdict"


class CouplingCondition(StrEnum):
    case_identity = "case_identity"
    non_intervened_fixture_fields = "non_intervened_fixture_fields"
    tool_schema_digest = "tool_schema_digest"
    provider_configuration = "provider_configuration"
    governing_corpus_digest = "governing_corpus_digest"
    provider_sampling_randomness = "provider_sampling_randomness"
    retrieval_randomness = "retrieval_randomness"
    tool_randomness = "tool_randomness"
    temporal_execution_order = "temporal_execution_order"
    deterministic_fixture_execution = "deterministic_fixture_execution"


class CouplingDescriptor(FrozenStrictModel):
    model_config = ConfigDict(json_schema_extra=_coupling_descriptor_json_schema_extra)

    pairing_identity_verified: bool
    stochastic_dimensions: tuple[CouplingCondition, ...] = Field(
        min_length=1,
        max_length=MAX_COUPLING_DIMENSIONS,
    )
    shared: tuple[CouplingCondition, ...] = Field(
        default=(),
        max_length=MAX_COUPLING_DIMENSIONS,
    )
    intentionally_different: tuple[CouplingCondition, ...] = Field(
        default=(),
        max_length=MAX_COUPLING_DIMENSIONS,
    )
    not_shared: tuple[CouplingCondition, ...] = Field(
        default=(),
        max_length=MAX_COUPLING_DIMENSIONS,
    )
    unknown: tuple[CouplingCondition, ...] = Field(
        default=(),
        max_length=MAX_COUPLING_DIMENSIONS,
    )
    requested_provider_seed: bool = False
    provider_seed_sharing_evidence_digest: DigestHex | None = None
    classification: CouplingClassification
    variance_reduction_claim_permitted: bool = False

    @field_validator(
        "stochastic_dimensions",
        "shared",
        "intentionally_different",
        "not_shared",
        "unknown",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        values = coerce_tuple(value)
        if isinstance(values, tuple):
            return tuple(coerce_enum(CouplingCondition, item) for item in values)
        return values

    @field_validator("classification", mode="before")
    @classmethod
    def _coerce_classification(cls, value: object) -> CouplingClassification:
        return coerce_enum(CouplingClassification, value)

    @model_validator(mode="after")
    def _validate_descriptor(self) -> Self:
        partitions = (
            self.stochastic_dimensions,
            self.shared,
            self.intentionally_different,
            self.not_shared,
            self.unknown,
        )
        if any(part != tuple(sorted(set(part))) for part in partitions):
            raise ValueError("coupling dimensions must be unique and canonically sorted")
        classified = (self.shared, self.intentionally_different, self.not_shared, self.unknown)
        for index, left in enumerate(classified):
            for right in classified[index + 1 :]:
                if set(left) & set(right):
                    raise ValueError("coupling dimension partitions must be disjoint")
        stochastic = set(self.stochastic_dimensions)
        declared = set().union(*(set(part) for part in classified))
        if not stochastic <= declared:
            raise ValueError("every stochastic dimension must have a declared coupling disposition")
        if self.provider_seed_sharing_evidence_digest is not None:
            raise ValueError(
                "v1 protocols cannot establish provider seed sharing from an authored "
                "digest; returned-metadata coupling evidence is not yet supported"
            )
        expected = derive_coupling_classification(
            pairing_identity_verified=self.pairing_identity_verified,
            stochastic_dimensions=self.stochastic_dimensions,
            shared=self.shared,
            intentionally_different=self.intentionally_different,
            not_shared=self.not_shared,
            unknown=self.unknown,
        )
        if self.classification is not expected:
            raise ValueError("coupling classification does not match the declared conditions")
        if self.variance_reduction_claim_permitted:
            raise ValueError("v1 repeated protocols do not permit a variance-reduction claim")
        return self


def derive_coupling_classification(
    *,
    pairing_identity_verified: bool,
    stochastic_dimensions: tuple[str | CouplingCondition, ...],
    shared: tuple[str | CouplingCondition, ...],
    intentionally_different: tuple[str | CouplingCondition, ...],
    not_shared: tuple[str | CouplingCondition, ...],
    unknown: tuple[str | CouplingCondition, ...],
) -> CouplingClassification:
    if not pairing_identity_verified:
        return CouplingClassification.unpaired
    stochastic = set(stochastic_dimensions)
    if stochastic & set(unknown):
        return CouplingClassification.unknown
    shared_stochastic = stochastic & set(shared)
    unshared_stochastic = stochastic & (set(intentionally_different) | set(not_shared))
    if shared_stochastic and not unshared_stochastic:
        return CouplingClassification.fully_coupled
    if shared_stochastic and unshared_stochastic:
        return CouplingClassification.partially_coupled
    if unshared_stochastic:
        return CouplingClassification.nominally_paired
    return CouplingClassification.unknown


class SensitivityArmBinding(FrozenStrictModel):
    arm_id: Literal["baseline_evidence", "counterfactual_evidence"]
    configuration_digest: DigestHex
    corpus_digest: DigestHex
    expected_recommendation: RAGSensitivityDecision
    expected_outcome: RAGSensitivityOutcome
    prompt_manifest_digest: DigestHex
    case_manifest_digest: DigestHex
    knowledge_contract_digest: DigestHex
    provider: MachineIdentifier
    requested_model: MachineIdentifier
    resolved_model: MachineIdentifier | None = None
    provider_api_version: MachineIdentifier | None = None
    provider_sdk: MachineIdentifier | None = None
    provider_region: MachineIdentifier | None = None
    adapter_id: MachineIdentifier
    pipeline_id: MachineIdentifier
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex

    @field_validator("expected_recommendation", mode="before")
    @classmethod
    def _coerce_expected_recommendation(cls, value: object) -> RAGSensitivityDecision:
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator("expected_outcome", mode="before")
    @classmethod
    def _coerce_expected_outcome(cls, value: object) -> RAGSensitivityOutcome:
        return coerce_enum(RAGSensitivityOutcome, value)

    @model_validator(mode="after")
    def _validate_expected_decision(self) -> Self:
        expected_outcome = {
            RAGSensitivityDecision.approve: RAGSensitivityOutcome.approved,
            RAGSensitivityDecision.deny: RAGSensitivityOutcome.denied,
            RAGSensitivityDecision.escalate: RAGSensitivityOutcome.escalated,
        }[self.expected_recommendation]
        if self.expected_outcome is not expected_outcome:
            raise ValueError("expected recommendation and outcome must be coherent")
        return self


class CaseClusterBinding(FrozenStrictModel):
    case_id: MachineIdentifier
    cluster_id: MachineIdentifier


class BinaryPairedDesignPlan(FrozenStrictModel):
    analysis_method: Literal["cluster_binary_exact"] = "cluster_binary_exact"
    exchangeability_assumption: Literal["independent_exchangeable_binary_cluster_endpoints"] = (
        "independent_exchangeable_binary_cluster_endpoints"
    )
    cluster_endpoint_aggregation: Literal["all_planned_pairs_expected_response"] = (
        "all_planned_pairs_expected_response"
    )
    confirmatory_cluster_frame: Literal["all_frozen_planned_clusters"] = (
        "all_frozen_planned_clusters"
    )
    non_analyzable_cluster_policy: Literal["score_zero"] = "score_zero"
    familywise_alpha: UnitDecimalString
    adjusted_alpha: UnitDecimalString
    desired_power: UnitDecimalString
    null_response_rate: UnitDecimalString
    alternative_response_rate: UnitDecimalString
    minimum_detectable_difference: UnitDecimalString
    maximum_exclusion_rate: UnitDecimalString = "0.000000"
    planned_inferential_clusters: int = Field(ge=2, le=MAX_PLANNED_CASES)
    critical_cluster_responses: int = Field(ge=1)
    achieved_type_i_error: UnitDecimalString
    achieved_power: UnitDecimalString
    monte_carlo_diagnostic_threshold_clusters: int = Field(
        default=20,
        ge=2,
        le=MAX_PLANNED_CASES,
    )
    monte_carlo_resamples: int = Field(
        default=1_000,
        ge=1_000,
        le=MAX_MONTE_CARLO_RESAMPLES,
    )

    @model_validator(mode="after")
    def _validate_design(self) -> Self:
        alpha = Decimal(self.familywise_alpha)
        adjusted_alpha = Decimal(self.adjusted_alpha)
        power = Decimal(self.desired_power)
        null_rate = Decimal(self.null_response_rate)
        alternative = Decimal(self.alternative_response_rate)
        difference = alternative - null_rate
        exclusion = Decimal(self.maximum_exclusion_rate)
        if not Decimal("0") < alpha < Decimal("1"):
            raise ValueError("familywise_alpha must be between zero and one")
        if not Decimal("0") < adjusted_alpha <= alpha:
            raise ValueError("adjusted_alpha must be positive and no greater than familywise_alpha")
        if not Decimal("0") < power < Decimal("1"):
            raise ValueError("desired_power must be between zero and one")
        if not Decimal("0") <= null_rate < alternative <= Decimal("1"):
            raise ValueError("response-rate alternative must be greater than the null")
        if self.minimum_detectable_difference != decimal_string(difference):
            raise ValueError(
                "minimum_detectable_difference must equal alternative_response_rate "
                "minus null_response_rate"
            )
        if exclusion >= Decimal("1"):
            raise ValueError("maximum_exclusion_rate must be less than one")
        if self.critical_cluster_responses > self.planned_inferential_clusters:
            raise ValueError(
                "critical_cluster_responses cannot exceed planned_inferential_clusters"
            )
        if Decimal(self.achieved_power) < power:
            raise ValueError("achieved_power must meet desired_power")
        try:
            exact_design = plan_cluster_binomial_design(
                adjusted_alpha=adjusted_alpha,
                desired_power=power,
                null_response_rate=null_rate,
                alternative_response_rate=alternative,
                min_clusters=self.planned_inferential_clusters,
                max_clusters=self.planned_inferential_clusters,
            )
        except ValueError as error:
            raise ValueError(
                "planned_inferential_clusters does not meet desired_power under "
                "the exact fixed-frame test"
            ) from error
        expected_derived = (
            exact_design.required_clusters,
            exact_design.critical_successes,
            _probability_ceiling(exact_design.exact_type_i_error),
            _probability_floor(exact_design.achieved_power),
        )
        observed_derived = (
            self.planned_inferential_clusters,
            self.critical_cluster_responses,
            self.achieved_type_i_error,
            self.achieved_power,
        )
        if observed_derived != expected_derived:
            raise ValueError(
                "binary cluster design derived values do not match the exact powered analysis"
            )
        return self


class RepeatedEvidenceSensitivityProtocol(SelfDigestedArtifact):
    _digest_field = "protocol_digest"
    model_config = ConfigDict(json_schema_extra=_repeated_protocol_json_schema_extra)

    artifact_kind: Literal["repeated-evidence-sensitivity-protocol"] = (
        "repeated-evidence-sensitivity-protocol"
    )
    schema_version: Literal["0.6.5"] = STOCHASTIC_SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["repeated-evidence-sensitivity-protocol"] = (
        "repeated-evidence-sensitivity-protocol"
    )
    contract_id: Literal["RepeatedEvidenceSensitivityProtocol/v1"] = (
        "RepeatedEvidenceSensitivityProtocol/v1"
    )
    contract_version: Literal["1.0.0"] = STOCHASTIC_SENSITIVITY_CONTRACT_VERSION
    protocol_id: MachineIdentifier
    protocol_digest: DigestHex
    design_commitment_digest: DigestHex
    endpoint: Literal["expected_decision_response"] = "expected_decision_response"
    expected_relation: Literal["decision_flip"] = "decision_flip"
    inferential_unit: Literal["case_id", "source_group_id"] = "case_id"
    pair_identity: Literal["case_id_repetition_index"] = "case_id_repetition_index"
    cluster_by: Literal["case_id", "source_group_id"] = "case_id"
    arm_execution_order: Literal["baseline_then_counterfactual"] = "baseline_then_counterfactual"
    interpretation: SensitivityInterpretation
    execution_mode: SensitivityExecutionMode
    baseline_arm: SensitivityArmBinding
    counterfactual_arm: SensitivityArmBinding
    planned_case_ids: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_PLANNED_CASES,
    )
    planned_cluster_ids: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_PLANNED_CASES,
    )
    case_cluster_bindings: tuple[CaseClusterBinding, ...] = Field(
        min_length=1,
        max_length=MAX_PLANNED_CASES,
    )
    case_authority_bindings: tuple[RAGSensitivityCaseAuthorityBinding, ...] = Field(
        default=(),
        max_length=MAX_PLANNED_CASES,
        exclude_if=lambda value: not value,
    )
    repetitions_per_arm: int = Field(ge=1)
    planned_pairs: int = Field(ge=1, le=MAX_PAIRED_OBSERVATIONS)
    multiplicity_family: MachineIdentifier
    multiplicity_method: Literal["single_endpoint", "bonferroni"] = "single_endpoint"
    multiplicity_family_size: int = Field(default=1, ge=1)
    coupling: CouplingDescriptor
    design: BinaryPairedDesignPlan
    allowed_exclusion_reasons: tuple[MachineIdentifier, ...] = ()
    limitations: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator(
        "planned_case_ids",
        "planned_cluster_ids",
        "case_cluster_bindings",
        "case_authority_bindings",
        "allowed_exclusion_reasons",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("interpretation", mode="before")
    @classmethod
    def _coerce_interpretation(cls, value: object) -> SensitivityInterpretation:
        return coerce_enum(SensitivityInterpretation, value)

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _coerce_execution_mode(cls, value: object) -> SensitivityExecutionMode:
        return coerce_enum(SensitivityExecutionMode, value)

    @classmethod
    def build(cls, **values: object) -> Self:
        """Build both the non-circular design commitment and artifact digest."""
        prepared = {
            "artifact_kind": "repeated-evidence-sensitivity-protocol",
            "schema_version": STOCHASTIC_SENSITIVITY_SCHEMA_VERSION,
            "schema_name": "repeated-evidence-sensitivity-protocol",
            "contract_id": "RepeatedEvidenceSensitivityProtocol/v1",
            "contract_version": STOCHASTIC_SENSITIVITY_CONTRACT_VERSION,
            **values,
            "protocol_digest": "0" * 64,
            "design_commitment_digest": "0" * 64,
        }
        provisional = cls.model_validate(
            prepared,
            context={
                "skip_self_digest": True,
                "skip_design_commitment": True,
            },
        )
        payload = provisional.model_dump(mode="json")
        payload["design_commitment_digest"] = calculate_repeated_design_commitment(provisional)
        payload["protocol_digest"] = _canonical_sha256(
            {key: value for key, value in payload.items() if key != "protocol_digest"}
        )
        return cls.model_validate(payload)

    @model_validator(mode="after")
    def _validate_protocol(self, info: ValidationInfo) -> Self:
        for name, values in (
            ("planned_case_ids", self.planned_case_ids),
            ("planned_cluster_ids", self.planned_cluster_ids),
            ("allowed_exclusion_reasons", self.allowed_exclusion_reasons),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{name} must be unique and canonically sorted")
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("limitations must be unique and canonically sorted")
        binding_case_ids = tuple(item.case_id for item in self.case_cluster_bindings)
        if binding_case_ids != tuple(sorted(set(binding_case_ids))):
            raise ValueError("case_cluster_bindings must be unique and sorted by case_id")
        if binding_case_ids != self.planned_case_ids:
            raise ValueError("case_cluster_bindings must exactly cover planned_case_ids")
        authority_case_ids = tuple(item.case_id for item in self.case_authority_bindings)
        if authority_case_ids != tuple(sorted(set(authority_case_ids))):
            raise ValueError("case_authority_bindings must be unique and sorted by case_id")
        if self.case_authority_bindings and authority_case_ids != self.planned_case_ids:
            raise ValueError("case_authority_bindings must exactly cover planned_case_ids")
        if (
            self.case_authority_bindings
            and len({item.query_family_id for item in self.case_authority_bindings}) != 1
        ):
            raise ValueError("v1 case authority bindings must share one corpus query family")
        bound_clusters = {item.cluster_id for item in self.case_cluster_bindings}
        if bound_clusters != set(self.planned_cluster_ids):
            raise ValueError("case_cluster_bindings must exactly realize planned_cluster_ids")
        cluster_case_counts = Counter(item.cluster_id for item in self.case_cluster_bindings)
        if len(set(cluster_case_counts.values())) != 1:
            raise ValueError(
                "v1 requires every planned cluster to contain the same number of cases"
            )
        if self.planned_pairs != len(self.planned_case_ids) * self.repetitions_per_arm:
            raise ValueError("planned_pairs must equal cases times repetitions_per_arm")
        if self.baseline_arm.arm_id != "baseline_evidence":
            raise ValueError("baseline_arm must use baseline_evidence identity")
        if self.counterfactual_arm.arm_id != "counterfactual_evidence":
            raise ValueError("counterfactual_arm must use counterfactual_evidence identity")
        if self.baseline_arm.corpus_digest == self.counterfactual_arm.corpus_digest:
            raise ValueError("paired evidence arms require distinct governing corpus digests")
        if self.baseline_arm.configuration_digest == self.counterfactual_arm.configuration_digest:
            raise ValueError("paired evidence arms require distinct exact configuration digests")
        expected_arm_decisions = {
            (
                self.baseline_arm.expected_recommendation,
                self.baseline_arm.expected_outcome,
            ),
            (
                self.counterfactual_arm.expected_recommendation,
                self.counterfactual_arm.expected_outcome,
            ),
        }
        if expected_arm_decisions != {
            (RAGSensitivityDecision.approve, RAGSensitivityOutcome.approved),
            (RAGSensitivityDecision.deny, RAGSensitivityOutcome.denied),
        }:
            raise ValueError(
                "decision_flip requires one expected approve arm and one expected deny arm"
            )
        fixed_fields = (
            "prompt_manifest_digest",
            "case_manifest_digest",
            "knowledge_contract_digest",
            "provider",
            "requested_model",
            "resolved_model",
            "provider_api_version",
            "provider_sdk",
            "provider_region",
            "adapter_id",
            "pipeline_id",
            "tool_schema_digest",
            "policy_bundle_digest",
        )
        mismatches = tuple(
            field_name
            for field_name in fixed_fields
            if getattr(self.baseline_arm, field_name)
            != getattr(self.counterfactual_arm, field_name)
        )
        if mismatches:
            raise ValueError("undeclared paired-arm identity differences: " + ", ".join(mismatches))
        expected_corpora = {
            self.baseline_arm.corpus_digest,
            self.counterfactual_arm.corpus_digest,
        }
        for binding in self.case_authority_bindings:
            assignments = {item.corpus_digest: item for item in binding.assignments}
            if set(assignments) != expected_corpora:
                raise ValueError(
                    "each case authority binding must exactly cover both arm corpus digests"
                )
            baseline_assignment = assignments[self.baseline_arm.corpus_digest]
            counterfactual_assignment = assignments[self.counterfactual_arm.corpus_digest]
            if (
                baseline_assignment.expected_decision,
                baseline_assignment.expected_outcome,
            ) != (
                self.baseline_arm.expected_recommendation,
                self.baseline_arm.expected_outcome,
            ) or (
                counterfactual_assignment.expected_decision,
                counterfactual_assignment.expected_outcome,
            ) != (
                self.counterfactual_arm.expected_recommendation,
                self.counterfactual_arm.expected_outcome,
            ):
                raise ValueError(
                    "case authority assignments must match the frozen arm expectations"
                )
        if "governing_corpus_digest" not in self.coupling.intentionally_different:
            raise ValueError(
                "coupling descriptor must declare governing_corpus_digest intentionally different"
            )
        if self.multiplicity_method == "single_endpoint" and self.multiplicity_family_size != 1:
            raise ValueError("single_endpoint multiplicity requires family size one")
        expected_adjusted = (
            Decimal(
                _probability_floor(
                    Decimal(self.design.familywise_alpha) / Decimal(self.multiplicity_family_size)
                )
            )
            if self.multiplicity_method == "bonferroni"
            else Decimal(self.design.familywise_alpha)
        )
        if self.design.adjusted_alpha != decimal_string(expected_adjusted):
            raise ValueError("design adjusted_alpha does not match multiplicity declaration")
        if (
            self.execution_mode is SensitivityExecutionMode.deterministic_fixture
            and self.interpretation is not SensitivityInterpretation.exploratory
        ):
            raise ValueError("deterministic fixture execution is explicitly exploratory")
        if (
            self.interpretation is SensitivityInterpretation.confirmatory
            and self.coupling.classification
            in {CouplingClassification.unpaired, CouplingClassification.unknown}
        ):
            raise ValueError("confirmatory interpretation requires a resolved paired design")
        if (
            self.execution_mode is SensitivityExecutionMode.stochastic_live
            and self.interpretation is SensitivityInterpretation.confirmatory
        ):
            if not self.case_authority_bindings:
                raise ValueError(
                    "confirmatory stochastic sensitivity requires exact per-case authority bindings"
                )
            if self.baseline_arm.adapter_id not in CONFIRMATORY_STOCHASTIC_ADAPTER_IDS:
                raise ValueError(
                    "confirmatory stochastic sensitivity requires a supported stochastic adapter"
                )
        if self.inferential_unit != self.cluster_by:
            raise ValueError("inferential_unit must equal the predeclared cluster identity")
        if self.cluster_by == "case_id" and (
            self.planned_cluster_ids != self.planned_case_ids
            or any(item.case_id != item.cluster_id for item in self.case_cluster_bindings)
        ):
            raise ValueError("case_id clustering requires an identity case-to-cluster mapping")
        if self.design.planned_inferential_clusters != len(self.planned_cluster_ids):
            raise ValueError("planned cluster identities must exactly realize the power plan")
        if (
            len(self.planned_cluster_ids) > self.design.monte_carlo_diagnostic_threshold_clusters
            and len(self.planned_cluster_ids) * self.design.monte_carlo_resamples
            > MAX_MONTE_CARLO_BERNOULLI_DRAWS
        ):
            raise ValueError(
                "planned Monte Carlo diagnostic exceeds the bounded Bernoulli-draw budget"
            )
        live_required_dimensions = {
            CouplingCondition.provider_sampling_randomness,
            CouplingCondition.temporal_execution_order,
        }
        if (
            self.execution_mode is SensitivityExecutionMode.stochastic_live
            and not live_required_dimensions <= set(self.coupling.stochastic_dimensions)
        ):
            raise ValueError(
                "stochastic_live coupling must classify provider sampling randomness "
                "and temporal execution order"
            )
        if (
            self.execution_mode is SensitivityExecutionMode.stochastic_live
            and CouplingCondition.provider_sampling_randomness in self.coupling.shared
        ):
            raise ValueError("v1 live protocols cannot claim verified shared provider randomness")
        if (
            self.execution_mode is SensitivityExecutionMode.stochastic_live
            and CouplingCondition.temporal_execution_order in self.coupling.shared
        ):
            raise ValueError("sequential v1 arm execution cannot claim shared temporal conditions")
        context = info.context if isinstance(info.context, dict) else {}
        if not context.get("skip_design_commitment") and (
            self.design_commitment_digest != calculate_repeated_design_commitment(self)
        ):
            raise ValueError(
                "design_commitment_digest does not match the pre-execution design projection"
            )
        return self


def calculate_repeated_design_commitment(
    protocol: RepeatedEvidenceSensitivityProtocol,
) -> str:
    payload = protocol.model_dump(
        mode="json",
        exclude={"protocol_digest", "design_commitment_digest"},
    )
    return _canonical_sha256(
        {
            "purpose": "repeated-evidence-sensitivity-design-commitment/v1",
            "protocol": payload,
        }
    )


def _canonical_sha256(value: object) -> str:
    # Lazy import prevents schema package initialization from cycling through
    # canonical.normalize while schema.common is only partially initialized.
    from agent_assure.canonical.digests import sha256_hexdigest

    return sha256_hexdigest(value)


def _six_place_probability(value: Decimal, *, rounding: str) -> str:
    if not value.is_finite() or not Decimal("0") <= value <= Decimal("1"):
        raise ValueError("probability must be finite and in [0, 1]")
    with localcontext() as context:
        context.prec = max(32, len(value.as_tuple().digits) + 2)
        rendered = value.quantize(Decimal("0.000001"), rounding=rounding)
    return f"{rendered:.6f}"


def _probability_ceiling(value: Decimal) -> str:
    return _six_place_probability(value, rounding=ROUND_CEILING)


def _probability_floor(value: Decimal) -> str:
    return _six_place_probability(value, rounding=ROUND_FLOOR)


class PairedSensitivityObservation(FrozenStrictModel):
    case_id: MachineIdentifier
    repetition_index: int = Field(ge=0)
    cluster_id: MachineIdentifier
    disposition: PairDisposition
    disposition_reason: MachineIdentifier | None = None
    baseline_exclusion_reason: MachineIdentifier | None = None
    counterfactual_exclusion_reason: MachineIdentifier | None = None
    baseline_run_id: MachineIdentifier | None = None
    baseline_run_digest: DigestHex | None = None
    counterfactual_run_id: MachineIdentifier | None = None
    counterfactual_run_digest: DigestHex | None = None
    baseline_recommendation: str | None = Field(default=None, max_length=512)
    baseline_outcome: str | None = Field(default=None, max_length=512)
    counterfactual_recommendation: str | None = Field(default=None, max_length=512)
    counterfactual_outcome: str | None = Field(default=None, max_length=512)
    baseline_expected_recommendation: RAGSensitivityDecision | None = None
    baseline_expected_outcome: RAGSensitivityOutcome | None = None
    counterfactual_expected_recommendation: RAGSensitivityDecision | None = None
    counterfactual_expected_outcome: RAGSensitivityOutcome | None = None
    endpoint_value: Literal[0, 1] | None = None

    @field_validator("disposition", mode="before")
    @classmethod
    def _coerce_disposition(cls, value: object) -> PairDisposition:
        return coerce_enum(PairDisposition, value)

    @field_validator(
        "baseline_expected_recommendation",
        "counterfactual_expected_recommendation",
        mode="before",
    )
    @classmethod
    def _coerce_expected_recommendations(
        cls,
        value: object,
    ) -> RAGSensitivityDecision | None:
        if value is None:
            return None
        return coerce_enum(RAGSensitivityDecision, value)

    @field_validator(
        "baseline_expected_outcome",
        "counterfactual_expected_outcome",
        mode="before",
    )
    @classmethod
    def _coerce_expected_outcomes(cls, value: object) -> RAGSensitivityOutcome | None:
        if value is None:
            return None
        return coerce_enum(RAGSensitivityOutcome, value)

    @model_validator(mode="after")
    def _validate_observation(self) -> Self:
        decisions = (
            self.baseline_recommendation,
            self.baseline_outcome,
            self.counterfactual_recommendation,
            self.counterfactual_outcome,
        )
        expectations = (
            self.baseline_expected_recommendation,
            self.baseline_expected_outcome,
            self.counterfactual_expected_recommendation,
            self.counterfactual_expected_outcome,
        )
        if self.disposition is PairDisposition.included:
            if any(value is None for value in (*decisions, *expectations)):
                raise ValueError(
                    "included pairs require observed and predeclared expected arm decisions"
                )
            expected_endpoint = derive_expected_decision_response(
                baseline_recommendation=cast(str, self.baseline_recommendation),
                baseline_outcome=cast(str, self.baseline_outcome),
                counterfactual_recommendation=cast(str, self.counterfactual_recommendation),
                counterfactual_outcome=cast(str, self.counterfactual_outcome),
                baseline_expected_recommendation=cast(
                    RAGSensitivityDecision,
                    self.baseline_expected_recommendation,
                ),
                baseline_expected_outcome=cast(
                    RAGSensitivityOutcome,
                    self.baseline_expected_outcome,
                ),
                counterfactual_expected_recommendation=cast(
                    RAGSensitivityDecision,
                    self.counterfactual_expected_recommendation,
                ),
                counterfactual_expected_outcome=cast(
                    RAGSensitivityOutcome,
                    self.counterfactual_expected_outcome,
                ),
            )
            if self.endpoint_value != expected_endpoint:
                raise ValueError(
                    "endpoint_value must be exactly derived from the declared "
                    "decision_flip relation"
                )
            if self.disposition_reason is not None:
                raise ValueError("included pairs cannot carry a disposition reason")
            if (
                self.baseline_exclusion_reason is not None
                or self.counterfactual_exclusion_reason is not None
            ):
                raise ValueError("included pairs cannot carry arm exclusion reasons")
            if any(
                value is None
                for value in (
                    self.baseline_run_id,
                    self.baseline_run_digest,
                    self.counterfactual_run_id,
                    self.counterfactual_run_digest,
                )
            ):
                raise ValueError("included pairs require exact source run dependencies")
        else:
            if self.endpoint_value is not None:
                raise ValueError("non-included pairs cannot carry an endpoint value")
            if self.disposition_reason is None:
                raise ValueError("non-included pairs require a bounded reason code")
            if any(value is not None for value in (*decisions, *expectations)):
                raise ValueError(
                    "non-included pairs must not persist observed or expected arm decisions"
                )
            if (self.baseline_run_id is None) != (self.baseline_run_digest is None):
                raise ValueError("baseline run identity and digest must be atomic")
            if (self.counterfactual_run_id is None) != (self.counterfactual_run_digest is None):
                raise ValueError("counterfactual run identity and digest must be atomic")
            excluded_baseline = self.disposition in {
                PairDisposition.excluded_baseline,
                PairDisposition.excluded_both,
            }
            excluded_counterfactual = self.disposition in {
                PairDisposition.excluded_counterfactual,
                PairDisposition.excluded_both,
            }
            arm_reasons_present = (
                self.baseline_exclusion_reason is not None
                or self.counterfactual_exclusion_reason is not None
            )
            if arm_reasons_present and (
                (self.baseline_exclusion_reason is not None) is not excluded_baseline
                or (self.counterfactual_exclusion_reason is not None) is not excluded_counterfactual
            ):
                raise ValueError(
                    "arm exclusion reasons must exactly match the excluded disposition"
                )
        return self


def derive_expected_decision_response(
    *,
    baseline_recommendation: str,
    baseline_outcome: str,
    counterfactual_recommendation: str,
    counterfactual_outcome: str,
    baseline_expected_recommendation: RAGSensitivityDecision,
    baseline_expected_outcome: RAGSensitivityOutcome,
    counterfactual_expected_recommendation: RAGSensitivityDecision,
    counterfactual_expected_outcome: RAGSensitivityOutcome,
) -> Literal[0, 1]:
    """Score only the predeclared directional response for both exact arms."""

    return cast(
        Literal[0, 1],
        int(
            (baseline_recommendation, baseline_outcome)
            == (baseline_expected_recommendation.value, baseline_expected_outcome.value)
            and (counterfactual_recommendation, counterfactual_outcome)
            == (
                counterfactual_expected_recommendation.value,
                counterfactual_expected_outcome.value,
            )
        ),
    )


class PairDispositionCount(FrozenStrictModel):
    disposition: PairDisposition
    reason_code: MachineIdentifier
    count: int = Field(ge=1)

    @field_validator("disposition", mode="before")
    @classmethod
    def _coerce_disposition(cls, value: object) -> PairDisposition:
        return coerce_enum(PairDisposition, value)


class SufficiencyPrerequisite(FrozenStrictModel):
    check_id: MachineIdentifier
    state: PrerequisiteCheckState
    reason_code: MachineIdentifier | None = None

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> PrerequisiteCheckState:
        return coerce_enum(PrerequisiteCheckState, value)

    @model_validator(mode="after")
    def _validate_reason(self) -> Self:
        if self.state is PrerequisiteCheckState.satisfied and self.reason_code is not None:
            raise ValueError("satisfied prerequisite checks cannot carry a reason")
        if self.state is not PrerequisiteCheckState.satisfied and self.reason_code is None:
            raise ValueError("non-satisfied prerequisite checks require a reason")
        return self


class ExactBinomialTailExpression(FrozenStrictModel):
    """Compact, lossless representation of an exact binomial upper tail."""

    distribution: Literal["binomial"] = "binomial"
    relation: Literal["successes_greater_than_or_equal"] = "successes_greater_than_or_equal"
    trials: int = Field(ge=2, le=MAX_PLANNED_CASES)
    threshold: int = Field(ge=0, le=MAX_PLANNED_CASES)
    probability_numerator: int = Field(ge=0, le=PROBABILITY_SCALE)
    probability_denominator: Literal[1_000_000] = PROBABILITY_SCALE

    @model_validator(mode="after")
    def _validate_expression(self) -> Self:
        if self.threshold > self.trials:
            raise ValueError("exact binomial threshold cannot exceed trials")
        return self

    def evaluate(self) -> Decimal:
        return exact_binomial_upper_tail(
            self.trials,
            self.threshold,
            Decimal(self.probability_numerator) / Decimal(self.probability_denominator),
        )


class ClusterBinomialAnalysisResult(FrozenStrictModel):
    method: Literal[
        "cluster_binomial_exact",
        "cluster_binomial_exact_with_monte_carlo_diagnostic",
    ]
    exchangeability_assumption: Literal["independent_exchangeable_binary_cluster_endpoints"] = (
        "independent_exchangeable_binary_cluster_endpoints"
    )
    cluster_endpoint_aggregation: Literal["all_planned_pairs_expected_response"] = (
        "all_planned_pairs_expected_response"
    )
    confirmatory_cluster_frame: Literal["all_frozen_planned_clusters"] = (
        "all_frozen_planned_clusters"
    )
    non_analyzable_cluster_policy: Literal["score_zero"] = "score_zero"
    compared_clusters: int = Field(ge=2)
    analyzable_clusters: int = Field(ge=0)
    non_analyzable_clusters_scored_zero: int = Field(ge=0)
    responding_clusters: int = Field(ge=0)
    included_pairs: int = Field(ge=0)
    planned_cluster_response_rate: UnitDecimalString
    planned_cluster_difference_from_null: Annotated[
        str,
        Field(pattern=r"^-?(0|1)\.[0-9]{6}$"),
    ]
    exact_p_value_expression: ExactBinomialTailExpression
    p_value_upper_bound: UnitDecimalString
    adjusted_alpha: UnitDecimalString
    exact_p_value: Literal[True] = True
    gate_uses_exact_rejection_region: Literal[True] = True
    monte_carlo_resamples: int = Field(ge=0)
    monte_carlo_extreme_count: int | None = Field(default=None, ge=0)
    monte_carlo_estimate: UnitDecimalString | None = None
    monte_carlo_seed: DigestHex | None = None
    monte_carlo_bitstream_id: Literal[
        "agent-assure/statistics/cluster-binomial/sha256-counter-msb/v1",
        "not_used",
    ]
    monte_carlo_sampler_id: Literal[
        "uint20-rejection-denominator-1000000/v1",
        "not_used",
    ]
    limitations: tuple[str, ...] = Field(min_length=1, max_length=16)

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_method(self) -> Self:
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("analysis limitations must be unique and sorted")
        if self.responding_clusters > self.compared_clusters:
            raise ValueError("responding_clusters cannot exceed compared_clusters")
        if (
            self.analyzable_clusters + self.non_analyzable_clusters_scored_zero
            != self.compared_clusters
        ):
            raise ValueError(
                "analyzable and zero-scored non-analyzable clusters must partition "
                "compared_clusters"
            )
        if self.responding_clusters > self.analyzable_clusters:
            raise ValueError("responding_clusters cannot exceed analyzable_clusters")
        if (
            self.exact_p_value_expression.trials != self.compared_clusters
            or self.exact_p_value_expression.threshold != self.responding_clusters
        ):
            raise ValueError("exact p-value expression must bind the observed cluster counts")
        if self.p_value_upper_bound != _probability_ceiling(
            self.exact_p_value_expression.evaluate()
        ):
            raise ValueError("p_value_upper_bound must conservatively render the exact p-value")
        if self.method == "cluster_binomial_exact":
            if (
                self.monte_carlo_resamples != 0
                or self.monte_carlo_extreme_count is not None
                or self.monte_carlo_estimate is not None
                or self.monte_carlo_seed is not None
                or self.monte_carlo_bitstream_id != "not_used"
                or self.monte_carlo_sampler_id != "not_used"
            ):
                raise ValueError("small exact analysis must not manufacture MC fields")
        else:
            if (
                self.monte_carlo_resamples < 1_000
                or self.monte_carlo_extreme_count is None
                or self.monte_carlo_estimate is None
                or self.monte_carlo_seed is None
                or self.monte_carlo_bitstream_id != SHA256_COUNTER_BITSTREAM_ID
                or self.monte_carlo_sampler_id != RATIONAL_BERNOULLI_SAMPLER_ID
            ):
                raise ValueError(
                    "large exact analysis requires a complete reproducible Monte Carlo diagnostic"
                )
            if self.monte_carlo_extreme_count > self.monte_carlo_resamples:
                raise ValueError("Monte Carlo extreme count cannot exceed diagnostic resamples")
        return self


def derive_cluster_binomial_analysis(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
) -> ClusterBinomialAnalysisResult:
    """Derive the authoritative exact cluster analysis and optional MC check."""
    analyzable_responses = derive_cluster_response_vector(protocol, observations)
    cluster_responses = derive_confirmatory_cluster_response_vector(
        protocol,
        observations,
    )
    if len(cluster_responses) < 2:
        raise ValueError("cluster-binomial analysis requires at least two clusters")
    raw = analyze_cluster_binomial(
        cluster_responses,
        null_response_rate=Decimal(protocol.design.null_response_rate),
        diagnostic_seed_material=(
            f"repeated-evidence-sensitivity/cluster-binomial/v1:{protocol.protocol_digest}"
        ),
        exact_diagnostic_cap=(protocol.design.monte_carlo_diagnostic_threshold_clusters),
        monte_carlo_resamples=protocol.design.monte_carlo_resamples,
    )
    planned_rate = Decimal(raw.success_count) / Decimal(raw.cluster_count)
    diagnostic = raw.monte_carlo_diagnostic
    limitations = [
        (
            "Exact inference treats the predeclared composite cluster endpoints as "
            "independent and exchangeable with a common null response rate; that "
            "assumption is authored and not empirically verified by this software."
        ),
        (
            "The cluster endpoint is one only when every planned pair in that "
            "cluster exhibits the expected decision response."
        ),
        (
            "Every planned cluster occupies one confirmatory trial; a non-analyzable "
            "cluster is assigned response zero and remains in the fixed denominator."
        ),
        (
            "Pair identity and repeated calls do not create additional "
            "independent inferential units."
        ),
        (
            "The declared null and alternative rates apply to the planned-frame "
            "composite endpoint, not response conditional on analyzability."
        ),
        "No stochastic-coupling variance-reduction claim is made.",
    ]
    if diagnostic is not None:
        limitations.append(
            "The SHA-256 Monte Carlo estimate is a reproducibility diagnostic; "
            "the gate uses only the analytic exact p-value."
        )
    return ClusterBinomialAnalysisResult(
        method=(
            "cluster_binomial_exact_with_monte_carlo_diagnostic"
            if diagnostic is not None
            else "cluster_binomial_exact"
        ),
        compared_clusters=raw.cluster_count,
        analyzable_clusters=len(analyzable_responses),
        non_analyzable_clusters_scored_zero=raw.cluster_count - len(analyzable_responses),
        responding_clusters=raw.success_count,
        included_pairs=sum(item.disposition is PairDisposition.included for item in observations),
        planned_cluster_response_rate=decimal_string(planned_rate),
        planned_cluster_difference_from_null=decimal_string(
            planned_rate - Decimal(protocol.design.null_response_rate)
        ),
        exact_p_value_expression=ExactBinomialTailExpression(
            trials=raw.cluster_count,
            threshold=raw.success_count,
            probability_numerator=(
                int(Decimal(protocol.design.null_response_rate) * PROBABILITY_SCALE)
            ),
        ),
        p_value_upper_bound=_probability_ceiling(raw.exact_p_value),
        adjusted_alpha=protocol.design.adjusted_alpha,
        monte_carlo_resamples=diagnostic.resamples if diagnostic is not None else 0,
        monte_carlo_extreme_count=(diagnostic.extreme_count if diagnostic is not None else None),
        monte_carlo_estimate=(
            _probability_ceiling(diagnostic.plus_one_estimate) if diagnostic is not None else None
        ),
        monte_carlo_seed=(diagnostic.seed_digest if diagnostic is not None else None),
        monte_carlo_bitstream_id=(
            diagnostic.bitstream_id if diagnostic is not None else "not_used"
        ),
        monte_carlo_sampler_id=(diagnostic.sampler_id if diagnostic is not None else "not_used"),
        limitations=tuple(sorted(limitations)),
    )


class RunRecordArtifactDependency(FrozenStrictModel):
    case_id: MachineIdentifier
    repetition_index: int = Field(ge=0)
    run_id: MachineIdentifier
    run_digest: DigestHex


class RunSetArtifactDependency(FrozenStrictModel):
    arm_id: Literal["baseline_evidence", "counterfactual_evidence"]
    runset_id: MachineIdentifier
    runset_digest: DigestHex
    execution_configuration_digest: DigestHex
    operational_protocol_id: MachineIdentifier
    operational_protocol_digest: DigestHex
    evidence_sensitivity_design_digest: DigestHex
    completion_status: Literal["complete", "incomplete"] = "complete"
    stop_reasons: tuple[MachineIdentifier, ...] = ()
    records: tuple[RunRecordArtifactDependency, ...] = Field(
        min_length=1,
        max_length=MAX_PAIRED_OBSERVATIONS,
    )

    @field_validator("records", "stop_reasons", mode="before")
    @classmethod
    def _coerce_records(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_records(self) -> Self:
        if self.stop_reasons != tuple(sorted(set(self.stop_reasons))):
            raise ValueError("RunSet dependency stop reasons must be unique and sorted")
        if (self.completion_status == "incomplete") != bool(self.stop_reasons):
            raise ValueError("RunSet dependency completion status and stop reasons must be atomic")
        keys = tuple(
            (item.case_id, item.repetition_index, item.run_id, item.run_digest)
            for item in self.records
        )
        if keys != tuple(sorted(set(keys))):
            raise ValueError("RunSet record dependencies must be unique and canonically sorted")
        if len({item.run_id for item in self.records}) != len(self.records):
            raise ValueError("RunSet record dependency run IDs must be unique")
        return self


STRUCTURAL_STOCHASTIC_PREREQUISITES = frozenset(
    {
        "arm_configuration_comparability",
        "cluster_identity",
        "coupling_resolved",
        "exclusion_policy",
        "record_validity",
        "source_runset_binding",
        "source_record_binding",
    }
)


def has_structural_prerequisite_failure(
    prerequisites: tuple[SufficiencyPrerequisite, ...],
) -> bool:
    return any(
        item.check_id in STRUCTURAL_STOCHASTIC_PREREQUISITES
        and item.state is PrerequisiteCheckState.unmet
        for item in prerequisites
    )


class StatisticalSufficiencyReport(SelfDigestedArtifact):
    _digest_field = "report_digest"

    artifact_kind: Literal["statistical-sufficiency-report"] = "statistical-sufficiency-report"
    schema_version: Literal["0.6.5"] = STOCHASTIC_SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["statistical-sufficiency-report"] = "statistical-sufficiency-report"
    contract_id: Literal["StatisticalSufficiencyReport/v1"] = "StatisticalSufficiencyReport/v1"
    contract_version: Literal["1.0.0"] = STOCHASTIC_SENSITIVITY_CONTRACT_VERSION
    report_id: MachineIdentifier
    report_digest: DigestHex
    protocol: RepeatedEvidenceSensitivityProtocol
    source_runsets: tuple[RunSetArtifactDependency, ...] = ()
    observations: tuple[PairedSensitivityObservation, ...] = Field(
        min_length=1,
        max_length=MAX_PAIRED_OBSERVATIONS,
    )
    state: SufficiencyState
    planned_pairs: int = Field(ge=1)
    actual_pairs: int = Field(ge=0)
    included_pairs: int = Field(ge=0)
    missing_pairs: int = Field(ge=0)
    excluded_pairs: int = Field(ge=0)
    planned_clusters: int = Field(ge=1)
    actual_clusters: int = Field(ge=0)
    analyzable_clusters: int = Field(ge=0)
    disposition_counts: tuple[PairDispositionCount, ...] = ()
    prerequisites: tuple[SufficiencyPrerequisite, ...] = Field(min_length=1)
    analysis: ClusterBinomialAnalysisResult | None = None
    population_claim_permitted: bool = False
    limitations: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator(
        "observations",
        "source_runsets",
        "disposition_counts",
        "prerequisites",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> SufficiencyState:
        return coerce_enum(SufficiencyState, value)

    @model_validator(mode="after")
    def _validate_report(self) -> Self:
        if self.report_id != f"{self.protocol.protocol_id}/sufficiency":
            raise ValueError("sufficiency report_id must derive from protocol_id")
        observation_keys = tuple(
            (item.case_id, item.repetition_index) for item in self.observations
        )
        if observation_keys != tuple(sorted(set(observation_keys))):
            raise ValueError("paired observations must be unique and canonically sorted")
        expected_keys = tuple(
            (case_id, repetition)
            for case_id in self.protocol.planned_case_ids
            for repetition in range(self.protocol.repetitions_per_arm)
        )
        if observation_keys != expected_keys:
            raise ValueError("observations must exactly cover the predeclared pair manifest")
        included = tuple(
            item for item in self.observations if item.disposition is PairDisposition.included
        )
        frozen_expectations = (
            self.protocol.baseline_arm.expected_recommendation,
            self.protocol.baseline_arm.expected_outcome,
            self.protocol.counterfactual_arm.expected_recommendation,
            self.protocol.counterfactual_arm.expected_outcome,
        )
        if any(
            (
                item.baseline_expected_recommendation,
                item.baseline_expected_outcome,
                item.counterfactual_expected_recommendation,
                item.counterfactual_expected_outcome,
            )
            != frozen_expectations
            for item in included
        ):
            raise ValueError(
                "included endpoint expectations must match the protocol arm assignments"
            )
        missing_dispositions = {
            PairDisposition.missing_both,
            PairDisposition.missing_baseline,
            PairDisposition.missing_counterfactual,
        }
        excluded_dispositions = {
            PairDisposition.excluded_baseline,
            PairDisposition.excluded_counterfactual,
            PairDisposition.excluded_both,
        }
        missing = sum(item.disposition in missing_dispositions for item in self.observations)
        excluded = sum(item.disposition in excluded_dispositions for item in self.observations)
        nonmissing = tuple(
            item for item in self.observations if item.disposition not in missing_dispositions
        )
        actual = len(nonmissing)
        expected_counts = (
            self.protocol.planned_pairs,
            actual,
            len(included),
            missing,
            excluded,
            len(self.protocol.planned_cluster_ids),
            len({item.cluster_id for item in nonmissing}),
            _count_analyzable_clusters(self.protocol, self.observations),
        )
        observed_counts = (
            self.planned_pairs,
            self.actual_pairs,
            self.included_pairs,
            self.missing_pairs,
            self.excluded_pairs,
            self.planned_clusters,
            self.actual_clusters,
            self.analyzable_clusters,
        )
        if observed_counts != expected_counts:
            raise ValueError("sufficiency sample-size fields do not match paired observations")
        reason_counter = Counter(
            (item.disposition, item.disposition_reason)
            for item in self.observations
            if item.disposition is not PairDisposition.included
        )
        expected_dispositions = tuple(
            PairDispositionCount(
                disposition=disposition,
                reason_code=reason or "unspecified",
                count=count,
            )
            for (disposition, reason), count in sorted(
                reason_counter.items(),
                key=lambda item: (item[0][0].value, item[0][1] or ""),
            )
        )
        if self.disposition_counts != expected_dispositions:
            raise ValueError("disposition_counts must exactly summarize missing and excluded pairs")
        if self.source_runsets and not _source_runset_dependencies_canonical(
            self.protocol,
            self.source_runsets,
        ):
            raise ValueError("source_runsets must be canonical and match the protocol bindings")
        expected_prerequisites = derive_sufficiency_prerequisites(
            self.protocol,
            self.observations,
            source_runsets=self.source_runsets,
            excluded_pairs=self.excluded_pairs,
            missing_pairs=self.missing_pairs,
        )
        if self.prerequisites != expected_prerequisites:
            raise ValueError(
                "prerequisite checks must exactly derive from the protocol and observations"
            )
        structural_unmet = has_structural_prerequisite_failure(self.prerequisites)
        all_satisfied = all(
            check.state is PrerequisiteCheckState.satisfied for check in self.prerequisites
        )
        expected_state = (
            SufficiencyState.prerequisites_unmet
            if structural_unmet
            else SufficiencyState.satisfied
            if all_satisfied
            else SufficiencyState.inconclusive
        )
        if self.state is not expected_state:
            raise ValueError("sufficiency state does not match prerequisite checks")
        expected_population_claim = (
            self.state is SufficiencyState.satisfied
            and self.protocol.execution_mode is SensitivityExecutionMode.stochastic_live
            and self.protocol.interpretation is SensitivityInterpretation.confirmatory
        )
        if self.population_claim_permitted is not expected_population_claim:
            raise ValueError("population claim permission does not match sufficiency state")
        if self.state is SufficiencyState.satisfied and self.analysis is None:
            raise ValueError("satisfied stochastic sufficiency requires an analysis")
        if (
            self.protocol.execution_mode is SensitivityExecutionMode.stochastic_live
            and self.state is SufficiencyState.inconclusive
            and self.analysis is None
        ):
            raise ValueError(
                "inconclusive stochastic-live sufficiency requires planned-frame analysis"
            )
        if self.protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture:
            if self.analysis is not None or self.population_claim_permitted:
                raise ValueError("deterministic fixture mode bypasses inferential machinery")
        if self.analysis is not None:
            expected_analysis = derive_cluster_binomial_analysis(
                self.protocol,
                self.observations,
            )
            if self.analysis != expected_analysis:
                raise ValueError(
                    "analysis must exactly recompute from the embedded protocol and observations"
                )
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("sufficiency limitations must be unique and sorted")
        return self


def derive_sufficiency_prerequisites(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
    *,
    source_runsets: tuple[RunSetArtifactDependency, ...],
    excluded_pairs: int,
    missing_pairs: int,
) -> tuple[SufficiencyPrerequisite, ...]:
    excluded_dispositions = {
        PairDisposition.excluded_baseline,
        PairDisposition.excluded_counterfactual,
        PairDisposition.excluded_both,
    }
    invalid_dispositions = {
        PairDisposition.invalid_baseline,
        PairDisposition.invalid_counterfactual,
        PairDisposition.invalid_both,
    }
    arm_difference_dispositions = {
        PairDisposition.identity_mismatch,
        PairDisposition.undeclared_arm_difference,
    }
    expected_cluster_by_case = {
        item.case_id: item.cluster_id for item in protocol.case_cluster_bindings
    }
    cluster_identity_valid = all(
        item.cluster_id == expected_cluster_by_case[item.case_id] for item in observations
    )
    unapproved_exclusion = any(
        item.disposition in excluded_dispositions
        and (
            not _observation_exclusion_reasons(item)
            or any(
                reason not in protocol.allowed_exclusion_reasons
                for reason in _observation_exclusion_reasons(item)
            )
        )
        for item in observations
    )
    exclusion_rate = Decimal(excluded_pairs) / Decimal(protocol.planned_pairs)
    checks: dict[str, tuple[PrerequisiteCheckState, str | None]] = {
        "arm_configuration_comparability": _prerequisite_state(
            not any(item.disposition in arm_difference_dispositions for item in observations),
            "undeclared-arm-difference",
        ),
        "cluster_identity": _prerequisite_state(
            cluster_identity_valid,
            "case-cluster-binding-mismatch",
        ),
        "coupling_resolved": _prerequisite_state(
            protocol.coupling.classification
            not in {CouplingClassification.unpaired, CouplingClassification.unknown},
            "coupling-unresolved",
        ),
        "exclusion_policy": _prerequisite_state(
            not unapproved_exclusion,
            "exclusion-reason-not-predeclared",
        ),
        "missing_pair_policy": _prerequisite_state(
            missing_pairs == 0,
            "missing-pairs-observed",
        ),
        "pair_exclusion_rate": _prerequisite_state(
            exclusion_rate <= Decimal(protocol.design.maximum_exclusion_rate),
            "exclusion-rate-exceeded",
        ),
        "record_validity": _prerequisite_state(
            not any(item.disposition in invalid_dispositions for item in observations),
            "invalid-run-record",
        ),
        "source_runset_binding": _prerequisite_state(
            (
                not source_runsets
                if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
                else _source_runset_dependencies_canonical(protocol, source_runsets)
            ),
            "source-runset-binding-unavailable",
        ),
        "source_record_binding": _prerequisite_state(
            (
                not source_runsets
                if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
                else _observation_sources_match_dependencies(
                    protocol,
                    observations,
                    source_runsets,
                )
            ),
            "source-record-membership-mismatch",
        ),
        "source_execution_complete": _prerequisite_state(
            (
                not source_runsets
                if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
                else all(
                    dependency.completion_status == "complete" for dependency in source_runsets
                )
            ),
            "source-runset-incomplete",
        ),
        "stochastic_confirmatory_mode": _prerequisite_state(
            protocol.execution_mode is SensitivityExecutionMode.stochastic_live
            and protocol.interpretation is SensitivityInterpretation.confirmatory,
            (
                "deterministic-fixture-no-population-inference"
                if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
                else "exploratory-protocol"
            ),
        ),
    }
    return tuple(
        SufficiencyPrerequisite(
            check_id=check_id,
            state=state,
            reason_code=reason,
        )
        for check_id, (state, reason) in sorted(checks.items())
    )


def _source_runset_dependencies_canonical(
    protocol: RepeatedEvidenceSensitivityProtocol,
    dependencies: tuple[RunSetArtifactDependency, ...],
) -> bool:
    if protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture:
        return not dependencies
    if tuple(item.arm_id for item in dependencies) != (
        "baseline_evidence",
        "counterfactual_evidence",
    ):
        return False
    baseline, counterfactual = dependencies
    if (
        baseline.execution_configuration_digest != protocol.baseline_arm.configuration_digest
        or counterfactual.execution_configuration_digest
        != protocol.counterfactual_arm.configuration_digest
        or baseline.evidence_sensitivity_design_digest != protocol.design_commitment_digest
        or counterfactual.evidence_sensitivity_design_digest != protocol.design_commitment_digest
    ):
        return False
    planned_cells = {
        (case_id, repetition_index)
        for case_id in protocol.planned_case_ids
        for repetition_index in range(protocol.repetitions_per_arm)
    }
    for dependency in dependencies:
        record_cells = tuple(
            (record.case_id, record.repetition_index) for record in dependency.records
        )
        record_cell_set = set(record_cells)
        if len(record_cells) != len(record_cell_set):
            return False
        if not record_cell_set <= planned_cells:
            return False
        if dependency.completion_status == "complete" and record_cell_set != planned_cells:
            return False
    return (
        baseline.operational_protocol_id == counterfactual.operational_protocol_id
        and baseline.operational_protocol_digest == counterfactual.operational_protocol_digest
        and baseline.runset_id != counterfactual.runset_id
        and baseline.runset_digest != counterfactual.runset_digest
    )


def _observation_sources_match_dependencies(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
    dependencies: tuple[RunSetArtifactDependency, ...],
) -> bool:
    if not _source_runset_dependencies_canonical(protocol, dependencies):
        return False
    by_arm = {dependency.arm_id: dependency for dependency in dependencies}
    for arm_id, id_field, digest_field in (
        ("baseline_evidence", "baseline_run_id", "baseline_run_digest"),
        (
            "counterfactual_evidence",
            "counterfactual_run_id",
            "counterfactual_run_digest",
        ),
    ):
        typed_arm_id = cast(
            Literal["baseline_evidence", "counterfactual_evidence"],
            arm_id,
        )
        records_by_cell = {
            (record.case_id, record.repetition_index): record
            for record in by_arm[typed_arm_id].records
        }
        if len(records_by_cell) != len(by_arm[typed_arm_id].records):
            return False
        observed_sources = {
            (observation.case_id, observation.repetition_index): (
                getattr(observation, id_field),
                getattr(observation, digest_field),
            )
            for observation in observations
            if getattr(observation, id_field) is not None
        }
        if set(records_by_cell) != set(observed_sources):
            return False
        for observation in observations:
            record = records_by_cell.get((observation.case_id, observation.repetition_index))
            observed_id = getattr(observation, id_field)
            observed_digest = getattr(observation, digest_field)
            if record is None:
                if observed_id is not None or observed_digest is not None:
                    return False
                continue
            if (observed_id, observed_digest) != (record.run_id, record.run_digest):
                return False
    return True


def derive_cluster_response_vector(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
) -> tuple[Literal[0, 1], ...]:
    observation_by_key = {(item.case_id, item.repetition_index): item for item in observations}
    cases_by_cluster: dict[str, list[str]] = {
        cluster_id: [] for cluster_id in protocol.planned_cluster_ids
    }
    for binding in protocol.case_cluster_bindings:
        cases_by_cluster[binding.cluster_id].append(binding.case_id)
    responses: list[Literal[0, 1]] = []
    for cluster_id in protocol.planned_cluster_ids:
        cluster_observations = tuple(
            observation_by_key.get((case_id, repetition))
            for case_id in cases_by_cluster[cluster_id]
            for repetition in range(protocol.repetitions_per_arm)
        )
        if not all(
            item is not None
            and item.cluster_id == cluster_id
            and item.disposition is PairDisposition.included
            for item in cluster_observations
        ):
            continue
        response: Literal[0, 1] = (
            1
            if all(item is not None and item.endpoint_value == 1 for item in cluster_observations)
            else 0
        )
        responses.append(response)
    return tuple(responses)


def derive_confirmatory_cluster_response_vector(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
) -> tuple[Literal[0, 1], ...]:
    """Return one conservative response bit for every frozen planned cluster.

    Descriptive aggregation omits non-analyzable clusters. Confirmatory
    aggregation instead retains the fixed planned denominator and assigns zero
    whenever any planned pair is absent, excluded, structurally mismatched, or
    not an observed response. The resulting success count is no greater than
    the success count under any completion of those unavailable endpoints.
    """

    observation_by_key = {(item.case_id, item.repetition_index): item for item in observations}
    cases_by_cluster: dict[str, list[str]] = {
        cluster_id: [] for cluster_id in protocol.planned_cluster_ids
    }
    for binding in protocol.case_cluster_bindings:
        cases_by_cluster[binding.cluster_id].append(binding.case_id)
    responses: list[Literal[0, 1]] = []
    for cluster_id in protocol.planned_cluster_ids:
        cluster_observations = tuple(
            observation_by_key.get((case_id, repetition))
            for case_id in cases_by_cluster[cluster_id]
            for repetition in range(protocol.repetitions_per_arm)
        )
        response: Literal[0, 1] = (
            1
            if all(
                item is not None
                and item.cluster_id == cluster_id
                and item.disposition is PairDisposition.included
                and item.endpoint_value == 1
                for item in cluster_observations
            )
            else 0
        )
        responses.append(response)
    return tuple(responses)


def _count_analyzable_clusters(
    protocol: RepeatedEvidenceSensitivityProtocol,
    observations: tuple[PairedSensitivityObservation, ...],
) -> int:
    return len(derive_cluster_response_vector(protocol, observations))


def _observation_exclusion_reasons(
    observation: PairedSensitivityObservation,
) -> tuple[str, ...]:
    explicit = tuple(
        reason
        for reason in (
            observation.baseline_exclusion_reason,
            observation.counterfactual_exclusion_reason,
        )
        if reason is not None
    )
    if explicit:
        return explicit
    # Backward-compatible single-code artifacts are safe only when the exact
    # persisted code itself was predeclared. New writers persist both arm
    # reasons separately for mixed exclusions.
    return (observation.disposition_reason,) if observation.disposition_reason is not None else ()


def _prerequisite_state(
    condition: bool,
    reason: str,
) -> tuple[PrerequisiteCheckState, str | None]:
    if condition:
        return PrerequisiteCheckState.satisfied, None
    return PrerequisiteCheckState.unmet, reason


class ArtifactDependency(FrozenStrictModel):
    edge_kind: Literal["depends_on"] = "depends_on"
    target_artifact_kind: Literal["statistical-sufficiency-report"] = (
        "statistical-sufficiency-report"
    )
    target_artifact_id: MachineIdentifier
    target_digest: DigestHex


class StochasticEvidenceSensitivityReport(SelfDigestedArtifact):
    _digest_field = "report_digest"

    artifact_kind: Literal["stochastic-evidence-sensitivity-report"] = (
        "stochastic-evidence-sensitivity-report"
    )
    schema_version: Literal["0.6.5"] = STOCHASTIC_SENSITIVITY_SCHEMA_VERSION
    schema_name: Literal["stochastic-evidence-sensitivity-report"] = (
        "stochastic-evidence-sensitivity-report"
    )
    contract_id: Literal["StochasticEvidenceSensitivityReport/v1"] = (
        "StochasticEvidenceSensitivityReport/v1"
    )
    contract_version: Literal["1.0.0"] = STOCHASTIC_SENSITIVITY_CONTRACT_VERSION
    report_id: MachineIdentifier
    report_digest: DigestHex
    protocol_id: MachineIdentifier
    protocol_digest: DigestHex
    endpoint: Literal["expected_decision_response"] = "expected_decision_response"
    sufficiency_report: StatisticalSufficiencyReport
    dependency: ArtifactDependency | None = None
    state: StochasticSensitivityState
    gate_effect: StochasticGateEffect
    verdict_bearing: bool
    population_claim: Literal[
        "none",
        "expected_decision_response_cluster_rate_above_null_supported",
        "expected_decision_response_cluster_rate_above_null_not_supported",
    ] = "none"
    observed_pair_count: int = Field(ge=0)
    observed_response_count: int = Field(ge=0)
    observed_counterexample_count: int = Field(ge=0)
    observed_cluster_count: int = Field(ge=0)
    observed_cluster_response_count: int = Field(ge=0)
    estimated_response_unit: Literal["independent_cluster"] = "independent_cluster"
    estimated_response_rate: UnitDecimalString | None = None
    limitations: tuple[str, ...] = Field(min_length=1, max_length=32)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> StochasticSensitivityState:
        return coerce_enum(StochasticSensitivityState, value)

    @field_validator("gate_effect", mode="before")
    @classmethod
    def _coerce_gate_effect(cls, value: object) -> StochasticGateEffect:
        return coerce_enum(StochasticGateEffect, value)

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_result(self) -> Self:
        protocol = self.sufficiency_report.protocol
        if self.report_id != f"{protocol.protocol_id}/stochastic-result":
            raise ValueError("stochastic report_id must derive from protocol_id")
        if (self.protocol_id, self.protocol_digest) != (
            protocol.protocol_id,
            protocol.protocol_digest,
        ):
            raise ValueError("stochastic result must bind the embedded protocol")
        included = tuple(
            item
            for item in self.sufficiency_report.observations
            if item.disposition is PairDisposition.included
        )
        responses = sum(item.endpoint_value == 1 for item in included)
        counterexamples = len(included) - responses
        if (
            self.observed_pair_count,
            self.observed_response_count,
            self.observed_counterexample_count,
        ) != (len(included), responses, counterexamples):
            raise ValueError("observed endpoint counts must derive from paired observations")
        cluster_responses = derive_cluster_response_vector(
            protocol,
            self.sufficiency_report.observations,
        )
        responding_clusters = sum(cluster_responses)
        if (
            self.observed_cluster_count,
            self.observed_cluster_response_count,
        ) != (len(cluster_responses), responding_clusters):
            raise ValueError(
                "observed cluster counts must derive from the frozen cluster aggregation"
            )
        expected_rate = (
            self.sufficiency_report.analysis.planned_cluster_response_rate
            if self.sufficiency_report.analysis is not None
            else None
        )
        if (
            protocol.execution_mode is SensitivityExecutionMode.deterministic_fixture
            or self.sufficiency_report.state is SufficiencyState.prerequisites_unmet
        ):
            expected_rate = None
        if self.estimated_response_rate != expected_rate:
            raise ValueError(
                "estimated_response_rate must be distinct from deterministic observed counts"
            )
        sufficiency_state = self.sufficiency_report.state
        if sufficiency_state is SufficiencyState.prerequisites_unmet:
            expected_state = StochasticSensitivityState.prerequisites_unmet
        elif sufficiency_state is SufficiencyState.inconclusive:
            expected_state = StochasticSensitivityState.inconclusive
        else:
            analysis = self.sufficiency_report.analysis
            if analysis is None:
                raise ValueError("satisfied sufficiency must carry an analysis")
            supported = cluster_binomial_rejection_region_contains(
                trials=analysis.compared_clusters,
                successes=analysis.responding_clusters,
                critical_successes=protocol.design.critical_cluster_responses,
            )
            expected_state = (
                StochasticSensitivityState.pass_ if supported else StochasticSensitivityState.block
            )
        if self.state is not expected_state:
            raise ValueError("stochastic sensitivity state is not derived from sufficiency")
        expected_verdict = expected_state in {
            StochasticSensitivityState.pass_,
            StochasticSensitivityState.block,
        }
        expected_gate = (
            StochasticGateEffect.pass_
            if expected_state is StochasticSensitivityState.pass_
            else StochasticGateEffect.block
            if expected_state is StochasticSensitivityState.block
            else StochasticGateEffect.non_verdict
        )
        if self.verdict_bearing is not expected_verdict or self.gate_effect is not expected_gate:
            raise ValueError("stochastic verdict role and gate effect must match state")
        expected_claim = (
            "expected_decision_response_cluster_rate_above_null_supported"
            if expected_state is StochasticSensitivityState.pass_
            else "expected_decision_response_cluster_rate_above_null_not_supported"
            if expected_state is StochasticSensitivityState.block
            else "none"
        )
        if self.population_claim != expected_claim:
            raise ValueError("population_claim must match the fail-closed result state")
        if expected_verdict:
            expected_dependency = ArtifactDependency(
                target_artifact_id=self.sufficiency_report.report_id,
                target_digest=self.sufficiency_report.report_digest,
            )
            if self.dependency != expected_dependency:
                raise ValueError(
                    "verdict-bearing stochastic evidence requires the exact satisfied "
                    "sufficiency dependency"
                )
            if not self.sufficiency_report.population_claim_permitted:
                raise ValueError("verdict-bearing stochastic evidence requires claim permission")
        elif self.dependency is not None:
            raise ValueError("non-verdict stochastic results do not manufacture dependencies")
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("stochastic report limitations must be unique and sorted")
        return self


__all__ = [
    "ArtifactDependency",
    "BinaryPairedDesignPlan",
    "CaseClusterBinding",
    "ClusterBinomialAnalysisResult",
    "CouplingClassification",
    "CouplingCondition",
    "CouplingDescriptor",
    "ExactBinomialTailExpression",
    "PairDisposition",
    "PairDispositionCount",
    "PairedSensitivityObservation",
    "PrerequisiteCheckState",
    "RepeatedEvidenceSensitivityProtocol",
    "RunSetArtifactDependency",
    "RunRecordArtifactDependency",
    "SensitivityArmBinding",
    "SensitivityExecutionMode",
    "SensitivityInterpretation",
    "StatisticalSufficiencyReport",
    "StochasticEvidenceSensitivityReport",
    "StochasticGateEffect",
    "StochasticSensitivityState",
    "SufficiencyPrerequisite",
    "SufficiencyState",
    "derive_coupling_classification",
    "derive_expected_decision_response",
    "derive_confirmatory_cluster_response_vector",
    "derive_cluster_response_vector",
    "derive_cluster_binomial_analysis",
    "derive_sufficiency_prerequisites",
    "has_structural_prerequisite_failure",
    "calculate_repeated_design_commitment",
]
