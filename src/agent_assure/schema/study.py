from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation
from enum import StrEnum
from re import findall, finditer
from typing import Annotated, Any, Literal, Self

from pydantic import ConfigDict, Field, ValidationInfo, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.common import (
    STRICT_RFC3339_TIMESTAMP_PATTERN,
    DigestHex,
    MachineIdentifier,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.mutation import SelfDigestedArtifact
from agent_assure.schema.sensitivity import EvidenceSensitivityExpectedRelation
from agent_assure.schema.stochastic_sensitivity import (
    CONFIRMATORY_STOCHASTIC_ADAPTER_IDS,
    CouplingDescriptor,
    PairedSensitivityObservation,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
    SufficiencyState,
)
from agent_assure.statistics.binomial_intervals import (
    MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS,
    clopper_pearson_interval_pair_work_units,
    clopper_pearson_one_sided,
    validate_clopper_pearson_work_budget,
)
from agent_assure.statistics.study_serialization import (
    bonferroni_adjusted_alpha,
    format_six_place_rate,
    format_twelve_place_bound,
)
from agent_assure.timestamps import parse_rfc3339_timestamp

STUDY_SCHEMA_VERSION: Literal["0.6.6"] = "0.6.6"
STUDY_CONTRACT_VERSION: Literal["1.0.0"] = "1.0.0"
MAX_STUDY_CONDITIONS = 64
MAX_STUDY_TASKS = 4_096
MAX_STUDY_DEVIATIONS = 128
MAX_STUDY_LIMITATIONS = 64
MAX_FAILURE_EXAMPLES = 3
MAX_STUDY_OBSERVED_MODEL_IDENTITIES = 32
_PLACEHOLDER_REVIEW_TOKENS = frozenset(
    {"lorem", "placeholder", "replace", "tbd", "todo", "unresolved"}
)
UNRESOLVED_INDEPENDENCE_BASIS = (
    "UNRESOLVED AUTHORING PLACEHOLDER: replace this text with a positive "
    "design-based argument before real-provider preregistration."
)

UnitDecimalString = Annotated[str, Field(pattern=r"^(0|1)\.[0-9]{6}$")]
BoundDecimalString = Annotated[str, Field(pattern=r"^(0|1)\.[0-9]{12}$")]
Timestamp = Annotated[
    str,
    Field(max_length=64, pattern=STRICT_RFC3339_TIMESTAMP_PATTERN),
]
BoundedStudyText = Annotated[str, Field(min_length=1, max_length=4_096)]
SubstantiveStudyText = Annotated[str, Field(min_length=32, max_length=4_096)]


def _validator_field_name(info: ValidationInfo) -> str:
    """Return the field name for a field validator without weakening typing."""

    if info.field_name is None:
        raise RuntimeError("study field validator requires a named model field")
    return info.field_name


def _require_substantive_non_placeholder_text(value: str, *, field_name: str) -> str:
    """Reject normalized-but-placeholder prose in human trust-root fields."""

    if value != value.strip() or not any(character.isalnum() for character in value):
        raise ValueError(f"{field_name} must be substantive normalized text")
    normalized_tokens = {token.lower() for token in findall(r"[A-Za-z]+", value)}
    rejected = tuple(sorted(normalized_tokens & _PLACEHOLDER_REVIEW_TOKENS))
    if rejected:
        raise ValueError(
            f"{field_name} contains unresolved authoring token(s): " + ", ".join(rejected)
        )
    if len(normalized_tokens) < 6:
        raise ValueError(f"{field_name} must contain a specific positive basis")
    return value


def _require_non_placeholder_digest(value: str, *, field_name: str) -> str:
    """Reject obvious repeated-character stand-ins in human evidence commitments."""

    if len(set(value.lower())) < 8:
        raise ValueError(f"{field_name} must commit to actual evidence bytes")
    return value


_CONDITION_OPTIONAL_EVIDENCE_FIELDS = (
    "observed_execution_window",
    "observed_execution_provenance",
    "decision_response_cluster_count",
    "decision_inertia_cluster_count",
    "decision_wrong_direction_cluster_count",
    "decision_other_non_inertia_cluster_count",
    "decision_inertia_descriptive_breakdown",
    "decision_response_rate",
    "decision_inertia_rate",
    "decision_inertia_interval",
    "control_expected_stability_cluster_count",
    "control_unexpected_change_cluster_count",
    "control_unexpected_change_rate",
    "control_unexpected_change_interval",
    "coupling",
    "sufficiency_report",
    "expected_response_diagnostic",
)
_INERTIA_STATISTICAL_FIELDS = (
    "decision_response_cluster_count",
    "decision_inertia_cluster_count",
    "decision_wrong_direction_cluster_count",
    "decision_other_non_inertia_cluster_count",
    "decision_inertia_descriptive_breakdown",
    "decision_response_rate",
    "decision_inertia_rate",
    "decision_inertia_interval",
)
_CONTROL_STATISTICAL_FIELDS = (
    "control_expected_stability_cluster_count",
    "control_unexpected_change_cluster_count",
    "control_unexpected_change_rate",
    "control_unexpected_change_interval",
)
_CONDITION_STATISTICAL_FIELDS = (
    *_INERTIA_STATISTICAL_FIELDS,
    *_CONTROL_STATISTICAL_FIELDS,
)
_CONDITION_DERIVED_REPORT_FIELDS = ("sufficiency_report", "expected_response_diagnostic")
_OPERATIONAL_OPTIONAL_FIELDS = (
    "total_estimated_cost_microusd",
    "total_cost_budget_committed_microusd",
    "total_latency_ms",
    "minimum_latency_ms",
    "maximum_latency_ms",
)


def _forbid_present_properties(field_names: tuple[str, ...]) -> dict[str, Any]:
    return {"not": {"anyOf": [{"required": [name]} for name in field_names]}}


def _forbid_explicit_null(field_name: str) -> dict[str, Any]:
    return {
        "not": {
            "required": [field_name],
            "properties": {field_name: {"type": "null"}},
        }
    }


def _operational_summary_json_schema_extra(schema: dict[str, Any]) -> None:
    rules = schema.setdefault("allOf", [])
    if not isinstance(rules, list):
        raise TypeError("study operational-summary JSON Schema allOf must be a list")
    rules.extend(_forbid_explicit_null(name) for name in _OPERATIONAL_OPTIONAL_FIELDS)


def _condition_binding_json_schema_extra(schema: dict[str, Any]) -> None:
    rules = schema.setdefault("allOf", [])
    if not isinstance(rules, list):
        raise TypeError("study condition-binding JSON Schema allOf must be a list")
    rules.append(
        {
            "if": {
                "required": ["execution_origin"],
                "properties": {"execution_origin": {"const": "real_provider"}},
            },
            "then": {"required": ["execution_attempt_id"]},
            "else": _forbid_present_properties(("execution_attempt_id",)),
        }
    )


def _condition_result_json_schema_extra(schema: dict[str, Any]) -> None:
    rules = schema.setdefault("allOf", [])
    if not isinstance(rules, list):
        raise TypeError("study condition JSON Schema allOf must be a list")
    rules.extend(_forbid_explicit_null(name) for name in _CONDITION_OPTIONAL_EVIDENCE_FIELDS)
    rules.extend(
        (
            {
                "if": {
                    "required": ["state"],
                    "properties": {"state": {"enum": ["analyzed", "control_failed"]}},
                },
                "then": {
                    "required": [
                        "coupling",
                        "sufficiency_report",
                        "expected_response_diagnostic",
                        "observed_execution_window",
                        "observed_execution_provenance",
                    ],
                    "properties": {
                        "observed_model_identities": {"minItems": 1},
                    },
                },
            },
            {
                "if": {
                    "required": ["state"],
                    "properties": {"state": {"const": "analyzed"}},
                },
                "then": {
                    "properties": {"deviation_codes": {"maxItems": 0}},
                },
            },
            {
                "if": {
                    "required": ["state", "analysis_role"],
                    "properties": {
                        "state": {"enum": ["analyzed", "control_failed"]},
                        "analysis_role": {"const": "inertia_estimand"},
                    },
                },
                "then": {
                    "required": list(_INERTIA_STATISTICAL_FIELDS),
                    **_forbid_present_properties(_CONTROL_STATISTICAL_FIELDS),
                },
            },
            {
                "if": {
                    "required": ["state", "analysis_role"],
                    "properties": {
                        "state": {"enum": ["analyzed", "control_failed"]},
                        "analysis_role": {"const": "invariant_negative_control"},
                    },
                },
                "then": {
                    "required": list(_CONTROL_STATISTICAL_FIELDS),
                    **_forbid_present_properties(_INERTIA_STATISTICAL_FIELDS),
                },
            },
            {
                "if": {
                    "required": ["state"],
                    "properties": {"state": {"const": "control_failed"}},
                },
                "then": {
                    "properties": {
                        "deviation_codes": {
                            "contains": {"const": "invariant-control-violation-observed"}
                        },
                        "analysis_role": {"const": "invariant_negative_control"},
                    }
                },
            },
            {
                "if": {
                    "required": ["state"],
                    "properties": {
                        "state": {"enum": ["underpowered", "invalidated", "not_executed"]}
                    },
                },
                "then": {
                    **_forbid_present_properties(_CONDITION_STATISTICAL_FIELDS),
                },
            },
            {
                "if": {
                    "required": ["state"],
                    "properties": {"state": {"const": "underpowered"}},
                },
                "then": {
                    "required": [
                        "coupling",
                        "sufficiency_report",
                        "expected_response_diagnostic",
                        "observed_execution_window",
                        "observed_execution_provenance",
                    ],
                    "properties": {
                        "deviation_codes": {"maxItems": 0},
                        "observed_model_identities": {"minItems": 1},
                    },
                },
            },
            {
                "if": {
                    "required": ["state"],
                    "properties": {"state": {"const": "invalidated"}},
                },
                "then": {
                    "properties": {"deviation_codes": {"minItems": 1}},
                    **_forbid_present_properties(_CONDITION_DERIVED_REPORT_FIELDS),
                },
            },
            {
                "if": {
                    "required": ["state"],
                    "properties": {"state": {"const": "not_executed"}},
                },
                "then": {
                    "properties": {
                        "actual_pairs": {"const": 0},
                        "included_pairs": {"const": 0},
                        "excluded_pairs": {"const": 0},
                        "invalid_pairs": {"const": 0},
                        "actual_clusters": {"const": 0},
                        "analyzable_clusters": {"const": 0},
                        "observed_model_identities": {"maxItems": 0},
                        "failure_summaries": {"maxItems": 0},
                        "deviation_codes": {"minItems": 1},
                    },
                    **_forbid_present_properties(
                        (
                            "coupling",
                            "sufficiency_report",
                            "expected_response_diagnostic",
                            "observed_execution_window",
                            "observed_execution_provenance",
                        )
                    ),
                },
            },
        )
    )


def derive_study_cluster_endpoint_counts(
    sufficiency: StatisticalSufficiencyReport,
) -> tuple[int, int, int, int, int, int, int]:
    """Return exact endpoint partitions for estimands and negative controls."""

    protocol = sufficiency.protocol
    observation_by_key = {
        (item.case_id, item.repetition_index): item for item in sufficiency.observations
    }
    cases_by_cluster: dict[str, list[str]] = {
        cluster_id: [] for cluster_id in protocol.planned_cluster_ids
    }
    for binding in protocol.case_cluster_bindings:
        cases_by_cluster[binding.cluster_id].append(binding.case_id)
    response_count = 0
    inertia_count = 0
    wrong_direction_count = 0
    other_non_inertia_count = 0
    stability_count = 0
    change_count = 0
    invalid_count = 0
    for cluster_id in protocol.planned_cluster_ids:
        observations = tuple(
            observation_by_key.get((case_id, repetition))
            for case_id in cases_by_cluster[cluster_id]
            for repetition in range(protocol.repetitions_per_arm)
        )
        if not observations or any(
            item is None or item.cluster_id != cluster_id or item.disposition.value != "included"
            for item in observations
        ):
            continue
        present = tuple(item for item in observations if item is not None)
        if protocol.expected_relation is EvidenceSensitivityExpectedRelation.decision_flip:
            kinds = tuple(_flip_endpoint_kind(item) for item in present)
            if any(kind == "invalid" for kind in kinds):
                invalid_count += 1
            elif all(kind == "inertia" for kind in kinds):
                inertia_count += 1
            elif all(kind == "response" for kind in kinds):
                response_count += 1
            elif all(kind == "wrong_direction" for kind in kinds):
                wrong_direction_count += 1
            else:
                other_non_inertia_count += 1
        else:
            kinds = tuple(_invariant_control_endpoint_kind(item) for item in present)
            if any(kind == "invalid" for kind in kinds):
                invalid_count += 1
            elif any(kind == "change" for kind in kinds):
                change_count += 1
            else:
                stability_count += 1
    return (
        response_count,
        inertia_count,
        wrong_direction_count,
        other_non_inertia_count,
        stability_count,
        change_count,
        invalid_count,
    )


def derive_study_inertia_descriptive_counts(
    sufficiency: StatisticalSufficiencyReport,
) -> tuple[int, int, int]:
    """Partition same-decision inertia clusters by baseline correctness.

    The returned counts are descriptive only. In order they count inertia
    clusters whose included members are all baseline-correct, all
    baseline-incorrect, or mixed with respect to baseline correctness. Their
    sum is the direct same-decision inertia count used by the confirmatory
    estimand.
    """

    protocol = sufficiency.protocol
    if protocol.expected_relation is not EvidenceSensitivityExpectedRelation.decision_flip:
        return (0, 0, 0)
    observation_by_key = {
        (item.case_id, item.repetition_index): item for item in sufficiency.observations
    }
    cases_by_cluster: dict[str, list[str]] = {
        cluster_id: [] for cluster_id in protocol.planned_cluster_ids
    }
    for binding in protocol.case_cluster_bindings:
        cases_by_cluster[binding.cluster_id].append(binding.case_id)
    baseline_correct_count = 0
    baseline_incorrect_count = 0
    mixed_baseline_correctness_count = 0
    for cluster_id in protocol.planned_cluster_ids:
        observations = tuple(
            observation_by_key.get((case_id, repetition))
            for case_id in cases_by_cluster[cluster_id]
            for repetition in range(protocol.repetitions_per_arm)
        )
        if not observations or any(
            item is None or item.cluster_id != cluster_id or item.disposition.value != "included"
            for item in observations
        ):
            continue
        present = tuple(item for item in observations if item is not None)
        if not all(_flip_endpoint_kind(item) == "inertia" for item in present):
            continue
        baseline_correctness = tuple(_flip_inertia_baseline_is_correct(item) for item in present)
        if all(baseline_correctness):
            baseline_correct_count += 1
        elif not any(baseline_correctness):
            baseline_incorrect_count += 1
        else:
            mixed_baseline_correctness_count += 1
    return (
        baseline_correct_count,
        baseline_incorrect_count,
        mixed_baseline_correctness_count,
    )


def _flip_endpoint_kind(observation: PairedSensitivityObservation) -> str:
    baseline = (
        observation.baseline_recommendation,
        observation.baseline_outcome,
    )
    counterfactual = (
        observation.counterfactual_recommendation,
        observation.counterfactual_outcome,
    )
    baseline_expected = (
        observation.baseline_expected_recommendation,
        observation.baseline_expected_outcome,
    )
    counterfactual_expected = (
        observation.counterfactual_expected_recommendation,
        observation.counterfactual_expected_outcome,
    )
    if any(
        value is None
        for value in (*baseline, *counterfactual, *baseline_expected, *counterfactual_expected)
    ):
        return "invalid"
    normalized_baseline_expected = tuple(
        item.value for item in baseline_expected if item is not None
    )
    normalized_counterfactual_expected = tuple(
        item.value for item in counterfactual_expected if item is not None
    )
    valid_decisions = {("approve", "approved"), ("deny", "denied")}
    if baseline not in valid_decisions or counterfactual not in valid_decisions:
        return "invalid"
    if (
        baseline == normalized_baseline_expected
        and counterfactual == normalized_counterfactual_expected
    ):
        return "response"
    if baseline == counterfactual:
        return "inertia"
    return "wrong_direction"


def _flip_inertia_baseline_is_correct(
    observation: PairedSensitivityObservation,
) -> bool:
    baseline_expected = (
        observation.baseline_expected_recommendation,
        observation.baseline_expected_outcome,
    )
    if any(value is None for value in baseline_expected):
        raise ValueError("same-decision inertia baseline expectation is incomplete")
    normalized_baseline_expected = tuple(
        item.value for item in baseline_expected if item is not None
    )
    baseline = (
        observation.baseline_recommendation,
        observation.baseline_outcome,
    )
    return baseline == normalized_baseline_expected


def _invariant_control_endpoint_kind(
    observation: PairedSensitivityObservation,
) -> str:
    baseline = (
        observation.baseline_recommendation,
        observation.baseline_outcome,
    )
    counterfactual = (
        observation.counterfactual_recommendation,
        observation.counterfactual_outcome,
    )
    expected = (
        observation.baseline_expected_recommendation,
        observation.baseline_expected_outcome,
    )
    if any(value is None for value in (*baseline, *counterfactual, *expected)):
        return "invalid"
    normalized_expected = tuple(item.value for item in expected if item is not None)
    valid_decisions = {("approve", "approved"), ("deny", "denied")}
    if baseline not in valid_decisions or counterfactual not in valid_decisions:
        return "invalid"
    if baseline == normalized_expected and counterfactual == normalized_expected:
        return "stability"
    if baseline != counterfactual:
        return "change"
    return "invalid"


def _reject_explicit_nulls(
    value: object,
    *,
    field_names: tuple[str, ...],
    owner: str,
) -> object:
    if not isinstance(value, Mapping):
        return value
    explicit_nulls = tuple(name for name in field_names if name in value and value[name] is None)
    if explicit_nulls:
        raise ValueError(
            f"{owner} optional fields must be omitted instead of null: " + ", ".join(explicit_nulls)
        )
    return value


class StudyRegistrationMethod(StrEnum):
    version_control_commit = "version_control_commit"
    append_only_registry = "append_only_registry"
    local_digest_commitment = "local_digest_commitment"


class StudyHypothesisClassification(StrEnum):
    supported = "supported"
    contradicted = "contradicted"
    inconclusive = "inconclusive"
    not_measured = "not_measured"


class StudyConditionState(StrEnum):
    analyzed = "analyzed"
    control_failed = "control_failed"
    underpowered = "underpowered"
    invalidated = "invalidated"
    not_executed = "not_executed"


class StudyConditionAnalysisRole(StrEnum):
    inertia_estimand = "inertia_estimand"
    invariant_negative_control = "invariant_negative_control"


class StudyExecutionOrigin(StrEnum):
    real_provider = "real_provider"
    synthetic_fixture = "synthetic_fixture"


class StudyProviderFingerprintReviewStatus(StrEnum):
    complete_and_stable = "complete_and_stable"
    not_exposed_by_provider = "not_exposed_by_provider"


class StudyRegistration(FrozenStrictModel):
    method: StudyRegistrationMethod
    reference_id: MachineIdentifier
    evidence_digest: DigestHex
    registered_at_utc: Timestamp
    immutable_record_claimed: Literal[True] = True

    @field_validator("method", mode="before")
    @classmethod
    def _coerce_method(cls, value: object) -> StudyRegistrationMethod:
        return coerce_enum(StudyRegistrationMethod, value)

    @field_validator("registered_at_utc")
    @classmethod
    def _validate_registered_at(cls, value: str) -> str:
        parse_rfc3339_timestamp(value, field_name="registered_at_utc")
        return value


class StudyRegistrationReviewReceipt(SelfDigestedArtifact):
    """Operator-attested review of the exact preregistration record bytes."""

    _digest_field = "review_receipt_digest"

    artifact_kind: Literal["real-model-study-registration-review"] = (
        "real-model-study-registration-review"
    )
    schema_version: Literal["0.6.6"] = STUDY_SCHEMA_VERSION
    schema_name: Literal["real-model-study-registration-review"] = (
        "real-model-study-registration-review"
    )
    contract_id: Literal["StudyRegistrationReviewReceipt/v1"] = "StudyRegistrationReviewReceipt/v1"
    contract_version: Literal["1.0.0"] = STUDY_CONTRACT_VERSION
    receipt_id: MachineIdentifier
    review_receipt_digest: DigestHex
    study_id: MachineIdentifier
    study_manifest_digest: DigestHex
    registration_method: StudyRegistrationMethod
    registration_reference_id: MachineIdentifier
    registration_evidence_sha256: DigestHex
    registered_at_utc: Timestamp
    reviewed_at_utc: Timestamp
    reviewer_pseudonym: MachineIdentifier
    registration_record_coverage_confirmed: Literal[True]
    pre_observation_ordering_confirmed: Literal[True]
    registration_reference_resolved: Literal[True]
    registration_record_digest_match_confirmed: Literal[True]
    registration_record_immutability_confirmed: Literal[True]
    attestation_basis: Literal["human_operator_attestation"] = "human_operator_attestation"
    reviewer_identity_authentication: Literal["out_of_band_not_machine_verified"] = (
        "out_of_band_not_machine_verified"
    )

    @field_validator("registration_method", mode="before")
    @classmethod
    def _coerce_method(cls, value: object) -> StudyRegistrationMethod:
        return coerce_enum(StudyRegistrationMethod, value)

    @model_validator(mode="after")
    def _validate_review(self) -> Self:
        registered = parse_rfc3339_timestamp(
            self.registered_at_utc,
            field_name="registration_review.registered_at_utc",
        )
        reviewed = parse_rfc3339_timestamp(
            self.reviewed_at_utc,
            field_name="registration_review.reviewed_at_utc",
        )
        if reviewed <= registered:
            raise ValueError("registration review must occur after the registered timestamp")
        return self


class StudyExecutionReviewCondition(FrozenStrictModel):
    """Exact per-condition evidence reviewed against provider-side records."""

    condition_id: MachineIdentifier
    execution_attempt_id: MachineIdentifier
    execution_attempt_journal_digest: DigestHex
    baseline_runset_artifact: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^condition-[0-9]{3}\.baseline\.source\.runset\.json$",
        ),
    ]
    baseline_runset_id: str = Field(min_length=1, max_length=1_024)
    baseline_runset_sha256: DigestHex
    counterfactual_runset_artifact: Annotated[
        str,
        Field(
            min_length=1,
            max_length=128,
            pattern=r"^condition-[0-9]{3}\.counterfactual\.source\.runset\.json$",
        ),
    ]
    counterfactual_runset_id: str = Field(min_length=1, max_length=1_024)
    counterfactual_runset_sha256: DigestHex
    observed_provenance_digest: DigestHex
    provider_response_id_set_digest: DigestHex
    provider_response_records: int = Field(ge=1, le=2 * MAX_STUDY_TASKS)
    provider_serving_fingerprint_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    provider_serving_fingerprint_status: StudyProviderFingerprintReviewStatus

    @field_validator("provider_serving_fingerprint_status", mode="before")
    @classmethod
    def _coerce_fingerprint_status(
        cls,
        value: object,
    ) -> StudyProviderFingerprintReviewStatus:
        return coerce_enum(StudyProviderFingerprintReviewStatus, value)

    @model_validator(mode="after")
    def _validate_fingerprint_coverage(self) -> Self:
        expected_records = (
            self.provider_response_records
            if self.provider_serving_fingerprint_status
            is StudyProviderFingerprintReviewStatus.complete_and_stable
            else 0
        )
        if self.provider_serving_fingerprint_records != expected_records:
            raise ValueError("fingerprint review status must match response-record coverage")
        return self


class StudyExecutionReviewReceipt(SelfDigestedArtifact):
    """Independent post-execution review of exact provider-backed evidence."""

    _digest_field = "execution_review_receipt_digest"

    artifact_kind: Literal["real-model-study-execution-review"] = (
        "real-model-study-execution-review"
    )
    schema_version: Literal["0.6.6"] = STUDY_SCHEMA_VERSION
    schema_name: Literal["real-model-study-execution-review"] = "real-model-study-execution-review"
    contract_id: Literal["StudyExecutionReviewReceipt/v1"] = "StudyExecutionReviewReceipt/v1"
    contract_version: Literal["1.0.0"] = STUDY_CONTRACT_VERSION
    receipt_id: MachineIdentifier
    execution_review_receipt_digest: DigestHex
    study_id: MachineIdentifier
    study_manifest_digest: DigestHex
    study_manifest_sha256: DigestHex
    study_report_digest: DigestHex
    study_report_sha256: DigestHex
    execution_window_end_utc: Timestamp
    reviewed_at_utc: Timestamp
    reviewer_pseudonym: MachineIdentifier
    reviewer_independent_of_execution: Literal[True]
    reviewer_independence_rationale: BoundedStudyText
    provider_log_review_scope: SubstantiveStudyText
    provider_log_evidence_digest: DigestHex
    provider_account_review_scope: SubstantiveStudyText
    provider_account_evidence_digest: DigestHex
    conditions: tuple[StudyExecutionReviewCondition, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_CONDITIONS,
    )
    provider_log_and_account_review_confirmed: Literal[True]
    provider_log_time_window_coverage_confirmed: Literal[True]
    provider_account_usage_reconciled: Literal[True]
    exhaustive_attempt_failure_retry_accounting_confirmed: Literal[True]
    provider_response_id_matches_confirmed: Literal[True]
    exact_runset_artifact_digest_matches_confirmed: Literal[True]
    provider_serving_fingerprint_availability_reviewed: Literal[True]
    provider_serving_fingerprint_absence_acknowledged: bool
    attestation_basis: Literal["human_operator_attestation"] = "human_operator_attestation"
    reviewer_identity_authentication: Literal["out_of_band_not_machine_verified"] = (
        "out_of_band_not_machine_verified"
    )

    @field_validator("conditions", mode="before")
    @classmethod
    def _coerce_conditions(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator(
        "reviewer_independence_rationale",
        "provider_log_review_scope",
        "provider_account_review_scope",
    )
    @classmethod
    def _validate_review_text(cls, value: str, info: ValidationInfo) -> str:
        return _require_substantive_non_placeholder_text(
            value,
            field_name=_validator_field_name(info),
        )

    @field_validator("provider_log_evidence_digest", "provider_account_evidence_digest")
    @classmethod
    def _validate_review_evidence_digest(cls, value: str, info: ValidationInfo) -> str:
        return _require_non_placeholder_digest(
            value,
            field_name=_validator_field_name(info),
        )

    @model_validator(mode="after")
    def _validate_review(self) -> Self:
        condition_ids = tuple(item.condition_id for item in self.conditions)
        if condition_ids != tuple(sorted(set(condition_ids))):
            raise ValueError("execution review conditions must be unique and sorted")
        fingerprint_absent = any(
            item.provider_serving_fingerprint_status
            is StudyProviderFingerprintReviewStatus.not_exposed_by_provider
            for item in self.conditions
        )
        if self.provider_serving_fingerprint_absence_acknowledged is not fingerprint_absent:
            raise ValueError(
                "fingerprint-absence acknowledgement must derive from reviewed conditions"
            )
        execution_end = parse_rfc3339_timestamp(
            self.execution_window_end_utc,
            field_name="execution_review.execution_window_end_utc",
        )
        reviewed = parse_rfc3339_timestamp(
            self.reviewed_at_utc,
            field_name="execution_review.reviewed_at_utc",
        )
        if reviewed <= execution_end:
            raise ValueError("execution review must occur after the planned execution window")
        return self


class StudyStatisticalMethodReviewCondition(FrozenStrictModel):
    """Exact preregistered condition design reviewed by a statistician."""

    condition_id: MachineIdentifier
    analysis_role: StudyConditionAnalysisRole
    execution_attempt_id: MachineIdentifier | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    protocol_digest: DigestHex
    design_commitment_digest: DigestHex
    registered_protocol_sha256: DigestHex
    planned_independent_clusters: int = Field(ge=2, le=1_000)

    @field_validator("analysis_role", mode="before")
    @classmethod
    def _coerce_analysis_role(cls, value: object) -> StudyConditionAnalysisRole:
        return coerce_enum(StudyConditionAnalysisRole, value)


class StudyReviewerQualificationBasisType(StrEnum):
    graduate_statistics_training = "graduate_statistics_training"
    professional_statistical_practice = "professional_statistical_practice"
    peer_reviewed_methodology_authorship = "peer_reviewed_methodology_authorship"
    documented_equivalent = "documented_equivalent"


class StudyMethodReviewApprovalDisposition(StrEnum):
    approved_confirmatory_independent_clusters = "approved_confirmatory_independent_clusters"
    approved_fixed_frame_descriptive_conformance = "approved_fixed_frame_descriptive_conformance"


class StudyStatisticalMethodReviewReceipt(SelfDigestedArtifact):
    """Qualified independent approval of the exact preregistered study design.

    The receipt cryptographically binds the local artifacts that were
    reviewed. Reviewer identity, qualifications, independence, and the truth
    of the review confirmations remain human attestations authenticated out
    of band.
    """

    _digest_field = "method_review_receipt_digest"

    artifact_kind: Literal["real-model-study-statistical-method-review"] = (
        "real-model-study-statistical-method-review"
    )
    schema_version: Literal["0.6.6"] = STUDY_SCHEMA_VERSION
    schema_name: Literal["real-model-study-statistical-method-review"] = (
        "real-model-study-statistical-method-review"
    )
    contract_id: Literal["StudyStatisticalMethodReviewReceipt/v1"] = (
        "StudyStatisticalMethodReviewReceipt/v1"
    )
    contract_version: Literal["1.0.0"] = STUDY_CONTRACT_VERSION
    receipt_id: MachineIdentifier
    method_review_receipt_digest: DigestHex
    study_id: MachineIdentifier
    study_manifest_digest: DigestHex
    study_manifest_sha256: DigestHex
    benchmark_digest: DigestHex
    benchmark_sha256: DigestHex
    protocol_set_digest: DigestHex
    hypothesis_decision_rule_digest: DigestHex
    registered_at_utc: Timestamp
    execution_window_start_utc: Timestamp
    reviewed_at_utc: Timestamp
    reviewer_pseudonym: MachineIdentifier
    reviewer_statistical_qualification_confirmed: Literal[True]
    reviewer_qualification_basis_types: tuple[StudyReviewerQualificationBasisType, ...] = Field(
        min_length=1,
        max_length=4,
    )
    reviewer_qualification_evidence_digest: DigestHex
    reviewer_qualification_basis: SubstantiveStudyText
    reviewer_independent_of_design_execution_and_analysis: Literal[True]
    reviewer_independence_rationale: SubstantiveStudyText
    approved_inference_scope: StudyInferenceScope
    independence_design_basis: StudyIndependenceDesignBasis
    independence_audit_artifact_sha256: DigestHex
    independence_design_basis_reviewed_and_accepted: Literal[True]
    independence_acceptance_rationale: SubstantiveStudyText
    semantic_near_duplicate_disposition: StudySemanticNearDuplicateDisposition
    semantic_near_duplicate_audit_reviewed: Literal[True]
    semantic_near_duplicate_pseudoreplication_rejected: Literal[True]
    semantic_near_duplicate_review_rationale: SubstantiveStudyText
    conditions: tuple[StudyStatisticalMethodReviewCondition, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_CONDITIONS,
    )
    benchmark_cluster_assignments_reviewed: Literal[True]
    independence_and_exchangeability_assumptions_reviewed: Literal[True]
    sampling_frame_and_estimand_reviewed: Literal[True]
    multiplicity_and_interval_method_reviewed: Literal[True]
    power_and_decision_boundary_reachability_reviewed: Literal[True]
    negative_control_design_reviewed: Literal[True]
    approval_disposition: StudyMethodReviewApprovalDisposition
    unresolved_methodological_concerns: tuple[BoundedStudyText, ...] = Field(
        default=(),
        max_length=0,
    )
    attestation_basis: Literal["qualified_human_statistical_review"] = (
        "qualified_human_statistical_review"
    )
    reviewer_identity_authentication: Literal["out_of_band_not_machine_verified"] = (
        "out_of_band_not_machine_verified"
    )

    @field_validator(
        "conditions",
        "reviewer_qualification_basis_types",
        "unresolved_methodological_concerns",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("reviewer_qualification_basis_types", mode="before")
    @classmethod
    def _coerce_qualification_basis_types(cls, value: object) -> object:
        values = coerce_tuple(value)
        if not isinstance(values, tuple):
            return values
        return tuple(coerce_enum(StudyReviewerQualificationBasisType, item) for item in values)

    @field_validator("approved_inference_scope", mode="before")
    @classmethod
    def _coerce_approved_scope(cls, value: object) -> StudyInferenceScope:
        return coerce_enum(StudyInferenceScope, value)

    @field_validator("independence_design_basis", mode="before")
    @classmethod
    def _coerce_independence_design_basis(
        cls,
        value: object,
    ) -> StudyIndependenceDesignBasis:
        return coerce_enum(StudyIndependenceDesignBasis, value)

    @field_validator("semantic_near_duplicate_disposition", mode="before")
    @classmethod
    def _coerce_near_duplicate_disposition(
        cls,
        value: object,
    ) -> StudySemanticNearDuplicateDisposition:
        return coerce_enum(StudySemanticNearDuplicateDisposition, value)

    @field_validator("approval_disposition", mode="before")
    @classmethod
    def _coerce_approval_disposition(
        cls,
        value: object,
    ) -> StudyMethodReviewApprovalDisposition:
        return coerce_enum(StudyMethodReviewApprovalDisposition, value)

    @field_validator(
        "reviewer_qualification_basis",
        "reviewer_independence_rationale",
        "independence_acceptance_rationale",
        "semantic_near_duplicate_review_rationale",
    )
    @classmethod
    def _validate_substantive_review_text(cls, value: str, info: ValidationInfo) -> str:
        return _require_substantive_non_placeholder_text(
            value,
            field_name=_validator_field_name(info),
        )

    @field_validator(
        "reviewer_qualification_evidence_digest",
        "independence_audit_artifact_sha256",
    )
    @classmethod
    def _validate_review_evidence_digest(cls, value: str, info: ValidationInfo) -> str:
        return _require_non_placeholder_digest(
            value,
            field_name=_validator_field_name(info),
        )

    @model_validator(mode="after")
    def _validate_review(self) -> Self:
        if self.reviewer_qualification_basis_types != tuple(
            sorted(set(self.reviewer_qualification_basis_types), key=lambda item: item.value)
        ):
            raise ValueError("reviewer qualification basis types must be unique and sorted")
        condition_ids = tuple(item.condition_id for item in self.conditions)
        if condition_ids != tuple(sorted(set(condition_ids))):
            raise ValueError("statistical-method review conditions must be unique and sorted")
        expected_disposition = (
            StudyMethodReviewApprovalDisposition.approved_confirmatory_independent_clusters
            if self.approved_inference_scope
            is StudyInferenceScope.confirmatory_independent_clusters
            else StudyMethodReviewApprovalDisposition.approved_fixed_frame_descriptive_conformance
        )
        if self.approval_disposition is not expected_disposition:
            raise ValueError("method-review approval must match the approved inference scope")
        fixed_frame = (
            self.semantic_near_duplicate_disposition
            is StudySemanticNearDuplicateDisposition.fixed_frame_descriptive_only
        )
        if fixed_frame is (
            self.approved_inference_scope is StudyInferenceScope.confirmatory_independent_clusters
        ):
            raise ValueError("near-duplicate disposition must match the approved inference scope")
        registered = parse_rfc3339_timestamp(
            self.registered_at_utc,
            field_name="statistical_method_review.registered_at_utc",
        )
        reviewed = parse_rfc3339_timestamp(
            self.reviewed_at_utc,
            field_name="statistical_method_review.reviewed_at_utc",
        )
        execution_start = parse_rfc3339_timestamp(
            self.execution_window_start_utc,
            field_name="statistical_method_review.execution_window_start_utc",
        )
        if not registered < reviewed < execution_start:
            raise ValueError(
                "statistical-method review must occur after registration and before execution"
            )
        return self


class StudyExecutionWindow(FrozenStrictModel):
    start: Timestamp
    end: Timestamp

    @model_validator(mode="after")
    def _validate_window(self) -> Self:
        if parse_rfc3339_timestamp(
            self.start, field_name="execution_window.start"
        ) >= parse_rfc3339_timestamp(
            self.end,
            field_name="execution_window.end",
        ):
            raise ValueError("execution window start must be before end")
        return self


class StudyKnowledgeContract(FrozenStrictModel):
    governing_source: Literal["contextual_evidence"] = "contextual_evidence"
    authority_level: Literal["authoritative"] = "authoritative"
    expected_behavior: Literal["follow_governing_context"] = "follow_governing_context"


def calculate_study_knowledge_contract_digest(contract: StudyKnowledgeContract) -> str:
    return _canonical_sha256(
        {
            "purpose": "real-model-study-knowledge-contract/v1",
            "contract": contract.model_dump(mode="json"),
        }
    )


class StudyInferenceScope(StrEnum):
    confirmatory_independent_clusters = "confirmatory_independent_clusters"
    fixed_frame_descriptive_conformance = "fixed_frame_descriptive_conformance"


class StudyAnalysisDeclaration(FrozenStrictModel):
    primary: StudyInferenceScope = StudyInferenceScope.confirmatory_independent_clusters
    exploratory_secondary_analyses_allowed: bool = True
    pooling_permitted: Literal[False] = False
    llm_judge_endpoint_permitted: Literal[False] = False

    @field_validator("primary", mode="before")
    @classmethod
    def _coerce_primary(cls, value: object) -> StudyInferenceScope:
        return coerce_enum(StudyInferenceScope, value)


class StudyIndependenceJustificationStatus(StrEnum):
    unresolved_authoring_placeholder = "unresolved_authoring_placeholder"
    author_asserted_design_basis_pending_qualified_review = (
        "author_asserted_design_basis_pending_qualified_review"
    )
    fixed_frame_dependence_acknowledged = "fixed_frame_dependence_acknowledged"


class StudyIndependenceDesignBasis(StrEnum):
    unresolved = "unresolved"
    randomized_independent_sampling = "randomized_independent_sampling"
    independently_generated_task_clusters = "independently_generated_task_clusters"
    externally_validated_exchangeable_clusters = "externally_validated_exchangeable_clusters"
    shared_template_parameter_grid = "shared_template_parameter_grid"


class StudySemanticNearDuplicateDisposition(StrEnum):
    unresolved = "unresolved"
    none_detected_by_digest_bound_audit = "none_detected_by_digest_bound_audit"
    collapsed_to_independent_clusters = "collapsed_to_independent_clusters"
    excluded_before_preregistration = "excluded_before_preregistration"
    fixed_frame_descriptive_only = "fixed_frame_descriptive_only"


class StudyIndependenceJustification(FrozenStrictModel):
    """Structured author assertion; never machine proof of independence."""

    status: StudyIndependenceJustificationStatus
    design_basis: StudyIndependenceDesignBasis
    semantic_near_duplicate_disposition: StudySemanticNearDuplicateDisposition
    independence_audit_artifact_sha256: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    inferential_unit_definition: SubstantiveStudyText
    independence_basis: SubstantiveStudyText
    dependence_risks_and_mitigations: SubstantiveStudyText
    residual_scope_limitation: SubstantiveStudyText
    software_verification_scope: Literal["structure_and_presence_only_not_independence_truth"] = (
        "structure_and_presence_only_not_independence_truth"
    )

    @field_validator("status", mode="before")
    @classmethod
    def _coerce_status(cls, value: object) -> StudyIndependenceJustificationStatus:
        return coerce_enum(StudyIndependenceJustificationStatus, value)

    @field_validator("design_basis", mode="before")
    @classmethod
    def _coerce_design_basis(cls, value: object) -> StudyIndependenceDesignBasis:
        return coerce_enum(StudyIndependenceDesignBasis, value)

    @field_validator("semantic_near_duplicate_disposition", mode="before")
    @classmethod
    def _coerce_duplicate_disposition(
        cls,
        value: object,
    ) -> StudySemanticNearDuplicateDisposition:
        return coerce_enum(StudySemanticNearDuplicateDisposition, value)

    @field_validator("independence_audit_artifact_sha256")
    @classmethod
    def _validate_independence_audit_digest(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return _require_non_placeholder_digest(
            value,
            field_name="independence_audit_artifact_sha256",
        )

    @field_validator(
        "inferential_unit_definition",
        "independence_basis",
        "dependence_risks_and_mitigations",
        "residual_scope_limitation",
    )
    @classmethod
    def _validate_text(cls, value: str, info: ValidationInfo) -> str:
        if value == UNRESOLVED_INDEPENDENCE_BASIS:
            return value
        return _require_substantive_non_placeholder_text(
            value,
            field_name=_validator_field_name(info),
        )

    @model_validator(mode="after")
    def _validate_status(self) -> Self:
        is_unresolved = (
            self.status is StudyIndependenceJustificationStatus.unresolved_authoring_placeholder
        )
        if is_unresolved != (self.independence_basis == UNRESOLVED_INDEPENDENCE_BASIS):
            raise ValueError(
                "unresolved independence status and the canonical authoring placeholder "
                "must be used together"
            )
        if is_unresolved:
            if (
                self.design_basis is not StudyIndependenceDesignBasis.unresolved
                or self.semantic_near_duplicate_disposition
                is not StudySemanticNearDuplicateDisposition.unresolved
                or self.independence_audit_artifact_sha256 is not None
            ):
                raise ValueError(
                    "unresolved independence status requires unresolved structured audit fields"
                )
            return self
        if self.independence_audit_artifact_sha256 is None:
            raise ValueError("resolved independence scope requires a digest-bound audit artifact")
        if self.status is StudyIndependenceJustificationStatus.fixed_frame_dependence_acknowledged:
            if (
                self.design_basis is not StudyIndependenceDesignBasis.shared_template_parameter_grid
                or self.semantic_near_duplicate_disposition
                is not StudySemanticNearDuplicateDisposition.fixed_frame_descriptive_only
            ):
                raise ValueError(
                    "fixed-frame downscope must acknowledge the shared-template parameter grid"
                )
            return self
        if self.design_basis in {
            StudyIndependenceDesignBasis.unresolved,
            StudyIndependenceDesignBasis.shared_template_parameter_grid,
        }:
            raise ValueError("confirmatory independence requires a positive non-grid design basis")
        if self.semantic_near_duplicate_disposition not in {
            StudySemanticNearDuplicateDisposition.none_detected_by_digest_bound_audit,
            StudySemanticNearDuplicateDisposition.collapsed_to_independent_clusters,
            StudySemanticNearDuplicateDisposition.excluded_before_preregistration,
        }:
            raise ValueError("confirmatory independence requires resolved near-duplicate handling")
        return self


def require_resolved_independence_justification(
    justification: StudyIndependenceJustification,
) -> None:
    """Reject draft rationale before real-provider use or human approval."""

    if (
        justification.status
        is StudyIndependenceJustificationStatus.unresolved_authoring_placeholder
    ):
        raise ValueError(
            "real-provider study requires a positive design-based independence "
            "justification before qualified statistical review"
        )


class StudyHypothesisDecisionRule(FrozenStrictModel):
    estimand: Literal["decision_inertia_rate"] = "decision_inertia_rate"
    inference_scope: StudyInferenceScope = StudyInferenceScope.confirmatory_independent_clusters
    derivation: Literal["direct_same_decision_rate_on_decision_flip_conditions"] = (
        "direct_same_decision_rate_on_decision_flip_conditions"
    )
    target_task_model_conditions: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_CONDITIONS,
    )
    negative_control_conditions: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_CONDITIONS,
    )
    invariant_control_gate: Literal["zero_observed_unexpected_arm_changes"] = (
        "zero_observed_unexpected_arm_changes"
    )
    inferential_unit: Literal["case_cluster"] = "case_cluster"
    minimum_independent_clusters: int = Field(ge=2, le=1_000)
    materiality_threshold: UnitDecimalString
    familywise_alpha: UnitDecimalString
    interval_method: Literal["clopper_pearson_exact_one_sided"] = "clopper_pearson_exact_one_sided"
    adjusted_alpha_serialization: Literal["conservative_floor_6_decimal"] = (
        "conservative_floor_6_decimal"
    )
    interval_bound_serialization: Literal["conservative_outward_12_decimal"] = (
        "conservative_outward_12_decimal"
    )
    multiplicity_method: Literal["bonferroni"] = "bonferroni"
    multiplicity_family_scope: Literal["target_task_model_conditions_only"] = (
        "target_task_model_conditions_only"
    )
    directional_error_control: Literal[
        "each_direction_separately_fwer_controlled_not_joint_two_sided_alpha"
    ] = "each_direction_separately_fwer_controlled_not_joint_two_sided_alpha"
    sampling_frame: Literal["finite_frozen_conformance_frame"] = "finite_frozen_conformance_frame"
    exchangeability_assumption: Literal[
        "independent_exchangeable_binary_cluster_endpoints_within_condition",
        "not_assumed_fixed_frame_descriptive_only",
    ] = "independent_exchangeable_binary_cluster_endpoints_within_condition"
    decision_boundary_rationale: SubstantiveStudyText
    independence_justification: StudyIndependenceJustification
    supported_when: Literal["any_adjusted_lower_bound_above_threshold"] = (
        "any_adjusted_lower_bound_above_threshold"
    )
    contradicted_when: Literal["all_adjusted_upper_bounds_at_or_below_threshold"] = (
        "all_adjusted_upper_bounds_at_or_below_threshold"
    )
    inconclusive_when: Literal["otherwise_after_valid_sufficient_execution"] = (
        "otherwise_after_valid_sufficient_execution"
    )

    @field_validator(
        "target_task_model_conditions",
        "negative_control_conditions",
        mode="before",
    )
    @classmethod
    def _coerce_targets(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("inference_scope", mode="before")
    @classmethod
    def _coerce_inference_scope(cls, value: object) -> StudyInferenceScope:
        return coerce_enum(StudyInferenceScope, value)

    @field_validator("decision_boundary_rationale")
    @classmethod
    def _validate_substantive_rationale(cls, value: str, info: ValidationInfo) -> str:
        if value != value.strip() or not any(character.isalnum() for character in value):
            raise ValueError(f"{info.field_name} must be substantive normalized text")
        return value

    @model_validator(mode="after")
    def _validate_rule(self) -> Self:
        for field_name in (
            "target_task_model_conditions",
            "negative_control_conditions",
        ):
            condition_ids = getattr(self, field_name)
            if condition_ids != tuple(sorted(set(condition_ids))):
                raise ValueError(f"{field_name} must be unique and sorted")
        if set(self.target_task_model_conditions) & set(self.negative_control_conditions):
            raise ValueError("inertia targets and negative controls must be disjoint")
        confirmatory = self.inference_scope is StudyInferenceScope.confirmatory_independent_clusters
        expected_exchangeability = (
            "independent_exchangeable_binary_cluster_endpoints_within_condition"
            if confirmatory
            else "not_assumed_fixed_frame_descriptive_only"
        )
        if self.exchangeability_assumption != expected_exchangeability:
            raise ValueError("exchangeability assumption must match the declared inference scope")
        fixed_frame = (
            self.independence_justification.status
            is StudyIndependenceJustificationStatus.fixed_frame_dependence_acknowledged
        )
        if fixed_frame is confirmatory:
            raise ValueError("independence justification must match the declared inference scope")
        threshold = Decimal(self.materiality_threshold)
        alpha = Decimal(self.familywise_alpha)
        if not Decimal("0") <= threshold < Decimal("1"):
            raise ValueError("materiality_threshold must be in [0, 1)")
        if not Decimal("0") < alpha <= Decimal("0.5"):
            raise ValueError("familywise_alpha must be greater than zero and at most 0.5")
        return self


class StudyBudget(FrozenStrictModel):
    maximum_estimated_cost_microusd: int = Field(ge=0)
    credentials_source: Literal["environment_variable_only"] = "environment_variable_only"
    persist_credentials: Literal[False] = False
    persist_credential_digests: Literal[False] = False


class StudyPublicationPolicy(FrozenStrictModel):
    redact_raw_outputs: Literal[True] = True
    publish_privacy_filtered_runsets: Literal[True] = True
    publish_raw_prompts: Literal[False] = False
    publish_raw_completions: Literal[False] = False
    publish_credentials: Literal[False] = False


def _has_dated_snapshot_identifier(value: str) -> bool:
    for match in finditer(
        r"(?<![0-9])20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$",
        value,
    ):
        try:
            date.fromisoformat(match.group(0))
        except ValueError:
            continue
        return True
    return False


class StudyConditionBinding(FrozenStrictModel):
    model_config = ConfigDict(json_schema_extra=_condition_binding_json_schema_extra)

    condition_id: MachineIdentifier
    justification: BoundedStudyText
    analysis_role: StudyConditionAnalysisRole
    execution_origin: StudyExecutionOrigin = StudyExecutionOrigin.synthetic_fixture
    task_ids: tuple[MachineIdentifier, ...] = Field(min_length=1, max_length=MAX_STUDY_TASKS)
    benchmark_case_ids: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_TASKS,
    )
    protocol_id: MachineIdentifier
    execution_attempt_id: MachineIdentifier | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    protocol_digest: DigestHex
    design_commitment_digest: DigestHex
    provider: MachineIdentifier
    requested_model: MachineIdentifier
    expected_resolved_model: MachineIdentifier
    resolved_model_version_policy: Literal["dated_provider_snapshot_identifier"] = (
        "dated_provider_snapshot_identifier"
    )
    provider_serving_fingerprint_policy: Literal[
        "all_absent_or_complete_and_stable_across_model_matched_condition_group"
    ] = "all_absent_or_complete_and_stable_across_model_matched_condition_group"
    provider_api_version: MachineIdentifier | None = None
    provider_sdk: MachineIdentifier | None = None
    provider_region: MachineIdentifier | None = None
    adapter_id: MachineIdentifier
    pipeline_id: MachineIdentifier
    baseline_configuration_digest: DigestHex
    counterfactual_configuration_digest: DigestHex
    baseline_provider_input_manifest_digest: DigestHex
    counterfactual_provider_input_manifest_digest: DigestHex
    # Digest of the executable RAG knowledge contract bound by both protocol
    # arms. This is intentionally distinct from the study-level semantic
    # contract, whose compact digest is recorded below.
    knowledge_contract_digest: DigestHex
    study_knowledge_contract_digest: DigestHex
    planned_pairs: int = Field(ge=1, le=4_096)
    planned_independent_clusters: int = Field(ge=2, le=1_000)

    @field_validator("task_ids", "benchmark_case_ids", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("execution_origin", mode="before")
    @classmethod
    def _coerce_execution_origin(cls, value: object) -> StudyExecutionOrigin:
        return coerce_enum(StudyExecutionOrigin, value)

    @field_validator("analysis_role", mode="before")
    @classmethod
    def _coerce_analysis_role(cls, value: object) -> StudyConditionAnalysisRole:
        return coerce_enum(StudyConditionAnalysisRole, value)

    @model_validator(mode="after")
    def _validate_binding(self) -> Self:
        for field_name in ("task_ids", "benchmark_case_ids"):
            values = getattr(self, field_name)
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{field_name} must be unique and sorted")
        if self.baseline_configuration_digest == self.counterfactual_configuration_digest:
            raise ValueError("study condition requires two distinct arm configurations")
        if self.planned_independent_clusters > self.planned_pairs:
            raise ValueError("planned independent clusters cannot exceed planned pairs")
        if (self.execution_origin is StudyExecutionOrigin.real_provider) != (
            self.execution_attempt_id is not None
        ):
            raise ValueError(
                "execution_attempt_id is required exactly for real-provider conditions"
            )
        if (
            self.execution_origin is StudyExecutionOrigin.real_provider
            and not _has_dated_snapshot_identifier(self.expected_resolved_model)
        ):
            raise ValueError(
                "real-provider expected_resolved_model must contain a valid YYYY-MM-DD "
                "provider snapshot identifier; mutable or versionless aliases are not "
                "confirmatory identities"
            )
        return self


def _study_condition_execution_identity(
    condition: StudyConditionBinding,
) -> tuple[
    StudyExecutionOrigin,
    str,
    str,
    str,
    str | None,
    str | None,
    str | None,
    str,
    str,
]:
    """Return the frozen identity that must span both targets and controls."""

    return (
        condition.execution_origin,
        condition.provider,
        condition.requested_model,
        condition.expected_resolved_model,
        condition.provider_api_version,
        condition.provider_sdk,
        condition.provider_region,
        condition.adapter_id,
        condition.pipeline_id,
    )


def _validate_study_interval_design_work_budget(
    conditions: tuple[StudyConditionBinding, ...],
) -> None:
    """Reject designs whose possible interval workload exceeds the fixed cap."""

    total = 0
    for condition in conditions:
        trials = condition.planned_independent_clusters
        # The lower+upper pair reaches its maximum recurrence width at floor(n/2).
        total += clopper_pearson_interval_pair_work_units(trials // 2, trials)
        if total > MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS:
            raise ValueError(
                "planned Clopper-Pearson exact-tail work exceeds the "
                f"{MAX_CLOPPER_PEARSON_AGGREGATE_WORK_UNITS} unit resource limit"
            )


def _validate_decision_rule_reachability(
    rule: StudyHypothesisDecisionRule,
    conditions: tuple[StudyConditionBinding, ...],
) -> None:
    """Require both terminal interval decisions to be attainable at planned N."""

    # Only the decision-flip targets produce confirmatory interval decisions.
    # Invariant controls are exact zero-change validity gates, so charging them
    # Bonferroni alpha would make the persisted family disagree with the
    # preregistered inferential family.
    adjusted_alpha = bonferroni_adjusted_alpha(
        rule.familywise_alpha,
        len(rule.target_task_model_conditions),
    )
    threshold = Decimal(rule.materiality_threshold)
    target_ids = set(rule.target_task_model_conditions)
    for condition in conditions:
        if condition.condition_id not in target_ids:
            continue
        clusters = condition.planned_independent_clusters
        best_case_upper = format_twelve_place_bound(
            clopper_pearson_one_sided(
                0,
                clusters,
                adjusted_alpha,
                side="upper",
            ).bound,
            rounding=ROUND_CEILING,
        )
        worst_case_lower = format_twelve_place_bound(
            clopper_pearson_one_sided(
                clusters,
                clusters,
                adjusted_alpha,
                side="lower",
            ).bound,
            rounding=ROUND_FLOOR,
        )
        if Decimal(best_case_upper) > threshold:
            raise ValueError(
                f"condition {condition.condition_id} cannot reach the contradicted branch "
                "at its planned cluster count under the frozen exact interval rule"
            )
        if Decimal(worst_case_lower) <= threshold:
            raise ValueError(
                f"condition {condition.condition_id} cannot reach the supported branch "
                "at its planned cluster count under the frozen exact interval rule"
            )


def calculate_study_protocol_set_digest(
    conditions: tuple[StudyConditionBinding, ...],
) -> str:
    return _canonical_sha256(
        {
            "purpose": "real-model-study-protocol-set/v1",
            "conditions": [
                {
                    "condition_id": item.condition_id,
                    "protocol_id": item.protocol_id,
                    "execution_attempt_id": item.execution_attempt_id,
                    "protocol_digest": item.protocol_digest,
                    "design_commitment_digest": item.design_commitment_digest,
                }
                for item in conditions
            ],
        }
    )


def calculate_hypothesis_decision_rule_digest(rule: StudyHypothesisDecisionRule) -> str:
    return _canonical_sha256(
        {
            "purpose": "real-model-study-hypothesis-decision-rule/v1",
            "rule": rule.model_dump(mode="json"),
        }
    )


def _canonical_sha256(value: object) -> str:
    # Lazy import keeps schema package initialization acyclic when canonical
    # normalization imports shared schema primitives.
    from agent_assure.canonical.digests import sha256_hexdigest

    return sha256_hexdigest(value)


class RealModelStudyManifest(SelfDigestedArtifact):
    _digest_field = "manifest_digest"

    artifact_kind: Literal["real-model-study-manifest"] = "real-model-study-manifest"
    schema_version: Literal["0.6.6"] = STUDY_SCHEMA_VERSION
    schema_name: Literal["real-model-study-manifest"] = "real-model-study-manifest"
    contract_id: Literal["RealModelStudyManifest/v1"] = "RealModelStudyManifest/v1"
    contract_version: Literal["1.0.0"] = STUDY_CONTRACT_VERSION
    study_id: MachineIdentifier
    manifest_digest: DigestHex
    status: Literal["preregistered"] = "preregistered"
    registration: StudyRegistration
    execution_window: StudyExecutionWindow
    benchmark_id: MachineIdentifier
    benchmark_version: Literal["0.2.0"] = "0.2.0"
    benchmark_digest: DigestHex
    protocol_set_digest: DigestHex
    primary_endpoint: Literal["direct_same_decision_inertia"] = "direct_same_decision_inertia"
    knowledge_contract: StudyKnowledgeContract = StudyKnowledgeContract()
    analysis_status: StudyAnalysisDeclaration = StudyAnalysisDeclaration()
    conditions: tuple[StudyConditionBinding, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_CONDITIONS,
    )
    hypothesis_decision_rule: StudyHypothesisDecisionRule
    hypothesis_decision_rule_digest: DigestHex
    budget: StudyBudget
    publication: StudyPublicationPolicy = StudyPublicationPolicy()
    limitations: tuple[BoundedStudyText, ...] = Field(min_length=1, max_length=32)

    @field_validator("conditions", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @classmethod
    def build(cls, **values: object) -> Self:
        prepared = dict(values)
        raw_conditions = coerce_tuple(prepared.get("conditions"))
        if not isinstance(raw_conditions, tuple):
            raise TypeError("conditions must be a sequence")
        conditions = tuple(StudyConditionBinding.model_validate(item) for item in raw_conditions)
        rule = StudyHypothesisDecisionRule.model_validate(prepared.get("hypothesis_decision_rule"))
        prepared["conditions"] = conditions
        prepared["hypothesis_decision_rule"] = rule
        prepared["protocol_set_digest"] = calculate_study_protocol_set_digest(conditions)
        prepared["hypothesis_decision_rule_digest"] = calculate_hypothesis_decision_rule_digest(
            rule
        )
        return super().build(**prepared)

    @model_validator(mode="after")
    def _validate_manifest(self) -> Self:
        if self.analysis_status.primary is not self.hypothesis_decision_rule.inference_scope:
            raise ValueError("analysis declaration must match the hypothesis inference scope")
        condition_ids = tuple(item.condition_id for item in self.conditions)
        if condition_ids != tuple(sorted(set(condition_ids))):
            raise ValueError("study conditions must be unique and sorted by condition_id")
        real_provider_attempt_ids = tuple(
            item.execution_attempt_id
            for item in self.conditions
            if item.execution_origin is StudyExecutionOrigin.real_provider
        )
        if len(real_provider_attempt_ids) != len(set(real_provider_attempt_ids)):
            raise ValueError("real-provider execution_attempt_id values must be unique")
        if real_provider_attempt_ids:
            require_resolved_independence_justification(
                self.hypothesis_decision_rule.independence_justification
            )
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("study limitations must be unique and sorted")
        rule_conditions = tuple(
            sorted(
                (
                    *self.hypothesis_decision_rule.target_task_model_conditions,
                    *self.hypothesis_decision_rule.negative_control_conditions,
                )
            )
        )
        if rule_conditions != condition_ids:
            raise ValueError(
                "hypothesis inertia targets and negative controls must exactly cover the study"
            )
        inertia_conditions = tuple(
            item.condition_id
            for item in self.conditions
            if item.analysis_role is StudyConditionAnalysisRole.inertia_estimand
        )
        control_conditions = tuple(
            item.condition_id
            for item in self.conditions
            if item.analysis_role is StudyConditionAnalysisRole.invariant_negative_control
        )
        if (
            self.hypothesis_decision_rule.target_task_model_conditions != inertia_conditions
            or self.hypothesis_decision_rule.negative_control_conditions != control_conditions
        ):
            raise ValueError(
                "hypothesis condition roles must exactly match their frozen rule membership"
            )
        identity_by_condition = {
            item.condition_id: _study_condition_execution_identity(item) for item in self.conditions
        }
        estimand_identities = {
            identity_by_condition[condition_id] for condition_id in inertia_conditions
        }
        control_identities = {
            identity_by_condition[condition_id] for condition_id in control_conditions
        }
        if estimand_identities != control_identities:
            raise ValueError(
                "every study provider/model execution identity must have both an inertia "
                "estimand and a model-matched invariant negative control"
            )
        _validate_study_interval_design_work_budget(self.conditions)
        _validate_decision_rule_reachability(
            self.hypothesis_decision_rule,
            self.conditions,
        )
        if any(
            item.planned_independent_clusters
            < self.hypothesis_decision_rule.minimum_independent_clusters
            for item in self.conditions
        ):
            raise ValueError("every target condition must meet the minimum cluster declaration")
        expected_knowledge_digest = calculate_study_knowledge_contract_digest(
            self.knowledge_contract
        )
        if any(
            item.study_knowledge_contract_digest != expected_knowledge_digest
            for item in self.conditions
        ):
            raise ValueError("every condition must bind the manifest semantic knowledge contract")
        if self.protocol_set_digest != calculate_study_protocol_set_digest(self.conditions):
            raise ValueError("protocol_set_digest does not match the condition commitments")
        if self.hypothesis_decision_rule_digest != calculate_hypothesis_decision_rule_digest(
            self.hypothesis_decision_rule
        ):
            raise ValueError("hypothesis_decision_rule_digest does not match the frozen rule")
        registered = parse_rfc3339_timestamp(
            self.registration.registered_at_utc,
            field_name="registration.registered_at_utc",
        )
        starts = parse_rfc3339_timestamp(
            self.execution_window.start,
            field_name="execution_window.start",
        )
        if registered >= starts:
            raise ValueError("registration must occur before the execution window starts")
        return self


class StudyObservedModelIdentity(FrozenStrictModel):
    provider: MachineIdentifier
    requested_model: MachineIdentifier
    resolved_model: MachineIdentifier | None = None
    provider_api_version: MachineIdentifier | None = None
    provider_sdk: MachineIdentifier | None = None
    provider_region: MachineIdentifier | None = None
    provider_serving_fingerprint: MachineIdentifier | None = None
    adapter_id: MachineIdentifier
    pipeline_id: MachineIdentifier


class StudyObservedExecutionProvenance(FrozenStrictModel):
    """Digest-bound local evidence for how a study condition was executed.

    This is a deterministic projection of the exact source RunSets and their
    privacy-filtered records. It is intentionally evidence of the local runner
    path, not a cryptographic attestation from a remote provider.
    """

    observation_method: Literal["agent-assure-runset-dispatch-metadata/v1"] = (
        "agent-assure-runset-dispatch-metadata/v1"
    )
    provenance_digest: DigestHex
    condition_id: MachineIdentifier
    study_manifest_digest: DigestHex
    declared_origin: StudyExecutionOrigin
    observed_origin: StudyExecutionOrigin
    baseline_runset_id: str = Field(min_length=1, max_length=1_024)
    baseline_runset_digest: DigestHex
    counterfactual_runset_id: str = Field(min_length=1, max_length=1_024)
    counterfactual_runset_digest: DigestHex
    planned_run_records: int = Field(ge=2, le=2 * MAX_STUDY_TASKS)
    run_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    included_run_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    live_runsets: int = Field(ge=0, le=2)
    complete_runsets: int = Field(ge=0, le=2)
    binding_consistent_runsets: int = Field(ge=0, le=2)
    execution_attempt_journal_verified: bool
    live_run_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    approved_adapter_run_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    binding_consistent_run_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    timing_complete_run_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    provider_response_id_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    provider_response_metadata_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    provider_serving_fingerprint_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    distinct_provider_serving_fingerprints: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    provider_serving_fingerprint_set_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    provider_serving_fingerprint_policy: Literal[
        "all_absent_or_complete_and_stable_across_condition"
    ] = "all_absent_or_complete_and_stable_across_condition"
    normal_termination_run_records: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    distinct_provider_response_ids: int = Field(ge=0, le=2 * MAX_STUDY_TASKS)
    provider_response_id_set_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    adapter_ids: tuple[str, ...] = Field(default=(), max_length=16)

    @classmethod
    def build(cls, **values: object) -> Self:
        prepared = dict(values)
        provisional = cls.model_validate(
            {**prepared, "provenance_digest": "0" * 64},
            context={"skip_provenance_digest": True},
        )
        payload = provisional.model_dump(mode="json", exclude={"provenance_digest"})
        return cls.model_validate(
            {
                **payload,
                "provenance_digest": _canonical_sha256(payload),
            }
        )

    @field_validator("declared_origin", "observed_origin", mode="before")
    @classmethod
    def _coerce_origins(cls, value: object) -> StudyExecutionOrigin:
        return coerce_enum(StudyExecutionOrigin, value)

    @field_validator("adapter_ids", mode="before")
    @classmethod
    def _coerce_adapter_ids(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_provenance(self, info: ValidationInfo) -> Self:
        if self.adapter_ids != tuple(sorted(set(self.adapter_ids))):
            raise ValueError("observed execution adapter IDs must be unique and sorted")
        bounded_counts = (
            self.included_run_records,
            self.live_run_records,
            self.approved_adapter_run_records,
            self.binding_consistent_run_records,
            self.timing_complete_run_records,
            self.provider_response_id_records,
            self.provider_response_metadata_records,
            self.provider_serving_fingerprint_records,
            self.normal_termination_run_records,
        )
        if any(value > self.run_records for value in bounded_counts):
            raise ValueError("observed execution coverage counts cannot exceed run_records")
        if self.distinct_provider_response_ids > self.provider_response_id_records:
            raise ValueError("distinct provider response IDs cannot exceed response-ID records")
        if self.distinct_provider_serving_fingerprints > self.provider_serving_fingerprint_records:
            raise ValueError(
                "distinct provider serving fingerprints cannot exceed fingerprint records"
            )
        if (self.provider_response_id_records == 0) != (
            self.provider_response_id_set_digest is None
        ):
            raise ValueError("provider response ID count and set digest must be present together")
        if (self.provider_serving_fingerprint_records == 0) != (
            self.provider_serving_fingerprint_set_digest is None
        ):
            raise ValueError(
                "provider serving-fingerprint count and set digest must be present together"
            )
        fingerprint_policy_satisfied = (
            self.provider_serving_fingerprint_records == 0
            and self.distinct_provider_serving_fingerprints == 0
        ) or (
            self.provider_serving_fingerprint_records == self.run_records
            and self.distinct_provider_serving_fingerprints == 1
        )
        supports_real_provider = (
            self.live_runsets == 2
            and self.complete_runsets == 2
            and self.binding_consistent_runsets == 2
            and self.execution_attempt_journal_verified
            and self.run_records == self.planned_run_records
            and self.included_run_records == self.run_records
            and self.live_run_records == self.run_records
            and self.approved_adapter_run_records == self.run_records
            and self.binding_consistent_run_records == self.run_records
            and self.timing_complete_run_records == self.run_records
            and self.provider_response_id_records == self.run_records
            and self.provider_response_metadata_records == self.run_records
            and fingerprint_policy_satisfied
            and self.normal_termination_run_records == self.run_records
            and self.distinct_provider_response_ids == self.run_records
            and bool(self.adapter_ids)
            and set(self.adapter_ids) <= CONFIRMATORY_STOCHASTIC_ADAPTER_IDS
        )
        expected_origin = (
            StudyExecutionOrigin.real_provider
            if supports_real_provider
            else StudyExecutionOrigin.synthetic_fixture
        )
        if self.observed_origin is not expected_origin:
            raise ValueError(
                "observed execution origin must derive from complete local dispatch evidence"
            )
        if not (
            isinstance(info.context, dict) and info.context.get("skip_provenance_digest") is True
        ):
            expected_digest = _canonical_sha256(
                self.model_dump(mode="json", exclude={"provenance_digest"})
            )
            if self.provenance_digest != expected_digest:
                raise ValueError(
                    "provenance_digest does not match the canonical observed execution projection"
                )
        return self


class StudyOneSidedInterval(FrozenStrictModel):
    method: Literal["clopper_pearson_exact_one_sided"] = "clopper_pearson_exact_one_sided"
    multiplicity_method: Literal["bonferroni"] = "bonferroni"
    familywise_alpha: UnitDecimalString
    family_size: int = Field(ge=1, le=MAX_STUDY_CONDITIONS)
    adjusted_alpha: BoundDecimalString
    trials: int = Field(ge=2, le=1_000)
    successes: int = Field(ge=0, le=1_000)
    lower_bound: BoundDecimalString
    upper_bound: BoundDecimalString
    serialization: Literal["conservative_outward_12_decimal"] = "conservative_outward_12_decimal"

    @model_validator(mode="after")
    def _validate_interval(self) -> Self:
        if self.successes > self.trials:
            raise ValueError("interval successes cannot exceed trials")
        if Decimal(self.adjusted_alpha) <= 0:
            raise ValueError("adjusted_alpha must be positive")
        if (
            not Decimal("0")
            <= Decimal(self.lower_bound)
            <= Decimal(self.upper_bound)
            <= Decimal("1")
        ):
            raise ValueError("interval bounds must be ordered inside [0, 1]")
        adjusted = bonferroni_adjusted_alpha(self.familywise_alpha, self.family_size)
        if self.adjusted_alpha != f"{adjusted:.12f}":
            raise ValueError("adjusted_alpha must derive from the Bonferroni rule")
        lower = clopper_pearson_one_sided(
            self.successes,
            self.trials,
            adjusted,
            side="lower",
        )
        upper = clopper_pearson_one_sided(
            self.successes,
            self.trials,
            adjusted,
            side="upper",
        )
        if (
            self.lower_bound,
            self.upper_bound,
        ) != (
            format_twelve_place_bound(lower.bound, rounding=ROUND_FLOOR),
            format_twelve_place_bound(upper.bound, rounding=ROUND_CEILING),
        ):
            raise ValueError("interval bounds must exactly derive from the declared counts")
        return self


class StudyOperationalSummary(FrozenStrictModel):
    model_config = ConfigDict(json_schema_extra=_operational_summary_json_schema_extra)

    run_records: int = Field(ge=0)
    cost_reported_records: int = Field(ge=0)
    total_estimated_cost_microusd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    cost_budget_committed_records: int = Field(ge=0)
    total_cost_budget_committed_microusd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    latency_reported_records: int = Field(ge=0)
    total_latency_ms: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    minimum_latency_ms: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    maximum_latency_ms: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="before")
    @classmethod
    def _reject_null_summaries(cls, value: object) -> object:
        return _reject_explicit_nulls(
            value,
            field_names=_OPERATIONAL_OPTIONAL_FIELDS,
            owner="study operational summary",
        )

    @model_validator(mode="after")
    def _validate_summary(self) -> Self:
        if self.cost_reported_records > self.run_records:
            raise ValueError("cost_reported_records cannot exceed run_records")
        if (self.cost_reported_records == 0) != (self.total_estimated_cost_microusd is None):
            raise ValueError("reported cost count and total must be present together")
        if self.cost_budget_committed_records > self.run_records:
            raise ValueError("cost_budget_committed_records cannot exceed run_records")
        if (self.cost_budget_committed_records == 0) != (
            self.total_cost_budget_committed_microusd is None
        ):
            raise ValueError("committed cost count and total must be present together")
        if (
            self.total_estimated_cost_microusd is not None
            and self.total_cost_budget_committed_microusd is not None
            and self.total_cost_budget_committed_microusd < self.total_estimated_cost_microusd
        ):
            raise ValueError("committed cost cannot be below estimated cost")
        if self.latency_reported_records > self.run_records:
            raise ValueError("latency_reported_records cannot exceed run_records")
        latency_values = (
            self.total_latency_ms,
            self.minimum_latency_ms,
            self.maximum_latency_ms,
        )
        if (self.latency_reported_records == 0) != all(item is None for item in latency_values):
            raise ValueError("reported latency count and summaries must be present together")
        if self.latency_reported_records and any(item is None for item in latency_values):
            raise ValueError("latency summaries must be atomic")
        if (
            self.minimum_latency_ms is not None
            and self.maximum_latency_ms is not None
            and self.minimum_latency_ms > self.maximum_latency_ms
        ):
            raise ValueError("minimum latency cannot exceed maximum latency")
        if (
            self.latency_reported_records
            and self.total_latency_ms is not None
            and self.minimum_latency_ms is not None
            and self.maximum_latency_ms is not None
            and not (
                self.minimum_latency_ms * self.latency_reported_records
                <= self.total_latency_ms
                <= self.maximum_latency_ms * self.latency_reported_records
            )
        ):
            raise ValueError("latency total must be bounded by the reported range")
        return self


class StudyFailureSummary(FrozenStrictModel):
    reason_code: MachineIdentifier
    count: int = Field(ge=1)
    example_case_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_FAILURE_EXAMPLES,
    )

    @field_validator("example_case_ids", mode="before")
    @classmethod
    def _coerce_examples(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_examples(self) -> Self:
        if self.example_case_ids != tuple(sorted(set(self.example_case_ids))):
            raise ValueError("failure example case IDs must be unique and sorted")
        return self


class StudyDecisionInertiaDescriptiveBreakdown(FrozenStrictModel):
    """Non-inferential partition of the direct same-decision endpoint."""

    interpretation: Literal[
        "descriptive_non_inferential_partition_of_direct_same_decision_inertia"
    ] = "descriptive_non_inferential_partition_of_direct_same_decision_inertia"
    denominator: Literal["frozen_planned_clusters"] = "frozen_planned_clusters"
    planned_clusters: int = Field(ge=2, le=1_000)
    baseline_correct_same_decision_cluster_count: int = Field(ge=0, le=1_000)
    baseline_incorrect_same_decision_cluster_count: int = Field(ge=0, le=1_000)
    mixed_baseline_correctness_same_decision_cluster_count: int = Field(
        ge=0,
        le=1_000,
    )
    baseline_correct_same_decision_rate: UnitDecimalString
    baseline_incorrect_same_decision_rate: UnitDecimalString
    mixed_baseline_correctness_same_decision_rate: UnitDecimalString

    @model_validator(mode="after")
    def _validate_breakdown(self) -> Self:
        counts = (
            self.baseline_correct_same_decision_cluster_count,
            self.baseline_incorrect_same_decision_cluster_count,
            self.mixed_baseline_correctness_same_decision_cluster_count,
        )
        if sum(counts) > self.planned_clusters:
            raise ValueError("descriptive same-decision counts cannot exceed planned clusters")
        rates = (
            self.baseline_correct_same_decision_rate,
            self.baseline_incorrect_same_decision_rate,
            self.mixed_baseline_correctness_same_decision_rate,
        )
        expected_rates = tuple(
            format_six_place_rate(count, self.planned_clusters) for count in counts
        )
        if rates != expected_rates:
            raise ValueError(
                "descriptive same-decision rates must derive from frozen planned clusters"
            )
        return self


class StudyExpectedResponseDiagnostic(FrozenStrictModel):
    """Neutral Sprint 7 projection of the relation-specific Sprint 6 report."""

    diagnostic_kind: Literal["sprint6_expected_response_replay"] = (
        "sprint6_expected_response_replay"
    )
    endpoint: Literal["expected_decision_response"] = "expected_decision_response"
    diagnostic_state: Literal[
        "expected_response_supported",
        "expected_response_not_supported",
        "prerequisites_unmet",
        "inconclusive",
    ]
    sprint7_hypothesis_effect: Literal["non_verdict"] = "non_verdict"
    polarity_relative_to_sprint7_hypothesis: Literal[
        "inverse_signal_for_direct_same_decision_inertia",
        "not_applicable_to_inertia_estimand_aligned_with_invariant_control",
    ]
    source_report: StochasticEvidenceSensitivityReport

    @staticmethod
    def _expected_polarity(
        source_report: StochasticEvidenceSensitivityReport,
    ) -> Literal[
        "inverse_signal_for_direct_same_decision_inertia",
        "not_applicable_to_inertia_estimand_aligned_with_invariant_control",
    ]:
        relation = source_report.sufficiency_report.protocol.expected_relation
        if relation is EvidenceSensitivityExpectedRelation.decision_flip:
            return "inverse_signal_for_direct_same_decision_inertia"
        return "not_applicable_to_inertia_estimand_aligned_with_invariant_control"

    @classmethod
    def from_source_report(
        cls,
        source_report: StochasticEvidenceSensitivityReport,
    ) -> Self:
        source = StochasticEvidenceSensitivityReport.model_validate(
            source_report.model_dump(mode="json")
        )
        state_map: dict[
            str,
            Literal[
                "expected_response_supported",
                "expected_response_not_supported",
                "prerequisites_unmet",
                "inconclusive",
            ],
        ] = {
            "pass": "expected_response_supported",
            "block": "expected_response_not_supported",
            "prerequisites_unmet": "prerequisites_unmet",
            "inconclusive": "inconclusive",
        }
        return cls(
            diagnostic_state=state_map[source.state.value],
            polarity_relative_to_sprint7_hypothesis=cls._expected_polarity(source),
            source_report=source,
        )

    @model_validator(mode="after")
    def _validate_projection(self) -> Self:
        expected_state = {
            "pass": "expected_response_supported",
            "block": "expected_response_not_supported",
            "prerequisites_unmet": "prerequisites_unmet",
            "inconclusive": "inconclusive",
        }[self.source_report.state.value]
        if self.diagnostic_state != expected_state:
            raise ValueError(
                "expected-response diagnostic state must derive from its source report"
            )
        if self.polarity_relative_to_sprint7_hypothesis != self._expected_polarity(
            self.source_report
        ):
            raise ValueError(
                "expected-response diagnostic polarity must derive from its protocol relation"
            )
        return self


class StudyConditionResult(FrozenStrictModel):
    model_config = ConfigDict(json_schema_extra=_condition_result_json_schema_extra)

    condition_id: MachineIdentifier
    state: StudyConditionState
    analysis_role: StudyConditionAnalysisRole
    protocol_digest: DigestHex
    design_commitment_digest: DigestHex
    observed_model_identities: tuple[StudyObservedModelIdentity, ...] = Field(
        default=(),
        max_length=MAX_STUDY_OBSERVED_MODEL_IDENTITIES,
    )
    observed_execution_window: StudyExecutionWindow | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    observed_execution_provenance: StudyObservedExecutionProvenance | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    planned_pairs: int = Field(ge=1, le=4_096)
    actual_pairs: int = Field(ge=0, le=4_096)
    included_pairs: int = Field(ge=0, le=4_096)
    missing_pairs: int = Field(ge=0, le=4_096)
    excluded_pairs: int = Field(ge=0, le=4_096)
    invalid_pairs: int = Field(ge=0, le=4_096)
    planned_clusters: int = Field(ge=2, le=1_000)
    actual_clusters: int = Field(ge=0, le=1_000)
    analyzable_clusters: int = Field(ge=0, le=1_000)
    decision_response_cluster_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    decision_inertia_cluster_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    decision_wrong_direction_cluster_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    decision_other_non_inertia_cluster_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    decision_inertia_descriptive_breakdown: StudyDecisionInertiaDescriptiveBreakdown | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    decision_response_rate: UnitDecimalString | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    decision_inertia_rate: UnitDecimalString | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    decision_inertia_interval: StudyOneSidedInterval | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    control_expected_stability_cluster_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    control_unexpected_change_cluster_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    control_unexpected_change_rate: UnitDecimalString | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    control_unexpected_change_interval: StudyOneSidedInterval | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    coupling: CouplingDescriptor | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    sufficiency_report: StatisticalSufficiencyReport | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    expected_response_diagnostic: StudyExpectedResponseDiagnostic | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    operational_summary: StudyOperationalSummary
    failure_summaries: tuple[StudyFailureSummary, ...] = Field(
        default=(),
        max_length=MAX_STUDY_DEVIATIONS,
    )
    deviation_codes: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_STUDY_DEVIATIONS,
    )

    @model_validator(mode="before")
    @classmethod
    def _reject_null_evidence(cls, value: object) -> object:
        return _reject_explicit_nulls(
            value,
            field_names=_CONDITION_OPTIONAL_EVIDENCE_FIELDS,
            owner="study condition result",
        )

    @field_validator(
        "state",
        mode="before",
    )
    @classmethod
    def _coerce_state(cls, value: object) -> StudyConditionState:
        return coerce_enum(StudyConditionState, value)

    @field_validator("analysis_role", mode="before")
    @classmethod
    def _coerce_analysis_role(cls, value: object) -> StudyConditionAnalysisRole:
        return coerce_enum(StudyConditionAnalysisRole, value)

    @field_validator(
        "observed_model_identities",
        "failure_summaries",
        "deviation_codes",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_result(self) -> Self:
        if self.planned_pairs != self.actual_pairs + self.missing_pairs:
            raise ValueError("planned pairs must partition into actual and missing pairs")
        if self.actual_pairs != (self.included_pairs + self.excluded_pairs + self.invalid_pairs):
            raise ValueError(
                "actual pairs must partition into included, excluded, and invalid pairs"
            )
        if not (self.analyzable_clusters <= self.actual_clusters <= self.planned_clusters):
            raise ValueError("cluster counts must be monotonically bounded by the plan")
        if self.deviation_codes != tuple(sorted(set(self.deviation_codes))):
            raise ValueError("deviation codes must be unique and sorted")
        identity_keys = tuple(
            (
                item.provider,
                item.requested_model,
                item.resolved_model or "",
                item.provider_api_version or "",
                item.provider_sdk or "",
                item.provider_region or "",
                item.provider_serving_fingerprint or "",
                item.adapter_id,
                item.pipeline_id,
            )
            for item in self.observed_model_identities
        )
        if identity_keys != tuple(sorted(set(identity_keys))):
            raise ValueError("observed model identities must be unique and sorted")
        failure_keys = tuple(item.reason_code for item in self.failure_summaries)
        if failure_keys != tuple(sorted(set(failure_keys))):
            raise ValueError("failure summaries must be unique and sorted by reason_code")
        if self.sufficiency_report is None:
            if self.expected_response_diagnostic is not None:
                raise ValueError("expected-response diagnostic requires its sufficiency report")
        else:
            sufficiency = self.sufficiency_report
            if (
                sufficiency.protocol.protocol_digest != self.protocol_digest
                or sufficiency.protocol.design_commitment_digest != self.design_commitment_digest
            ):
                raise ValueError("condition reports must bind the declared protocol")
            if self.expected_response_diagnostic is None:
                raise ValueError("derived condition evidence requires both source reports")
            if self.expected_response_diagnostic.source_report.sufficiency_report != sufficiency:
                raise ValueError(
                    "expected-response diagnostic must embed the exact sufficiency report"
                )
            if self.coupling != sufficiency.protocol.coupling:
                raise ValueError("condition coupling must derive from its frozen protocol")
            if sum(item.count for item in self.failure_summaries) != (
                self.planned_pairs - self.included_pairs
            ):
                raise ValueError("failure summaries must count every non-included planned pair")
            expected_counts = (
                sufficiency.planned_pairs,
                sufficiency.actual_pairs,
                sufficiency.included_pairs,
                sufficiency.missing_pairs,
                sufficiency.excluded_pairs,
                (
                    sufficiency.actual_pairs
                    - sufficiency.included_pairs
                    - sufficiency.excluded_pairs
                ),
                sufficiency.planned_clusters,
                sufficiency.actual_clusters,
                sufficiency.analyzable_clusters,
            )
            observed_counts = (
                self.planned_pairs,
                self.actual_pairs,
                self.included_pairs,
                self.missing_pairs,
                self.excluded_pairs,
                self.invalid_pairs,
                self.planned_clusters,
                self.actual_clusters,
                self.analyzable_clusters,
            )
            if observed_counts != expected_counts:
                raise ValueError("condition sample counts must derive from sufficiency evidence")
        inertia_statistical_fields = (
            self.decision_response_cluster_count,
            self.decision_inertia_cluster_count,
            self.decision_wrong_direction_cluster_count,
            self.decision_other_non_inertia_cluster_count,
            self.decision_inertia_descriptive_breakdown,
            self.decision_response_rate,
            self.decision_inertia_rate,
            self.decision_inertia_interval,
        )
        control_statistical_fields = (
            self.control_expected_stability_cluster_count,
            self.control_unexpected_change_cluster_count,
            self.control_unexpected_change_rate,
            self.control_unexpected_change_interval,
        )
        statistical_fields = (*inertia_statistical_fields, *control_statistical_fields)
        if self.state in {
            StudyConditionState.analyzed,
            StudyConditionState.control_failed,
        }:
            if self.sufficiency_report is None or self.expected_response_diagnostic is None:
                raise ValueError("analyzed condition requires reproducible source reports")
            if self.sufficiency_report.state is not SufficiencyState.satisfied:
                raise ValueError("analyzed condition requires satisfied statistical sufficiency")
            if self.state is StudyConditionState.analyzed and self.deviation_codes:
                raise ValueError("analyzed condition cannot carry protocol deviations")
            if self.state is StudyConditionState.control_failed and self.deviation_codes != (
                "invariant-control-violation-observed",
            ):
                raise ValueError(
                    "control-failed condition requires only its invariant-control finding"
                )
            analysis = self.sufficiency_report.analysis
            if analysis is None:
                raise ValueError("analyzed condition requires embedded exact analysis")
            (
                derived_response_count,
                derived_inertia_count,
                derived_wrong_direction_count,
                derived_other_non_inertia_count,
                derived_stability_count,
                derived_change_count,
                invalid_endpoint_count,
            ) = derive_study_cluster_endpoint_counts(self.sufficiency_report)
            derived_inertia_breakdown = derive_study_inertia_descriptive_counts(
                self.sufficiency_report
            )
            if invalid_endpoint_count:
                raise ValueError(
                    "analyzed condition cannot contain unclassifiable decision endpoints"
                )
            expected_role = (
                StudyConditionAnalysisRole.inertia_estimand
                if self.sufficiency_report.protocol.expected_relation
                is EvidenceSensitivityExpectedRelation.decision_flip
                else StudyConditionAnalysisRole.invariant_negative_control
            )
            if self.analysis_role is not expected_role:
                raise ValueError(
                    "condition analysis role must derive from the frozen expected relation"
                )
            if self.analysis_role is StudyConditionAnalysisRole.inertia_estimand:
                if any(value is None for value in inertia_statistical_fields) or any(
                    value is not None for value in control_statistical_fields
                ):
                    raise ValueError("inertia-estimand condition requires only inertia statistics")
                response_count = self.decision_response_cluster_count
                inertia_count = self.decision_inertia_cluster_count
                wrong_direction_count = self.decision_wrong_direction_cluster_count
                other_non_inertia_count = self.decision_other_non_inertia_cluster_count
                inertia_breakdown = self.decision_inertia_descriptive_breakdown
                assert (
                    response_count is not None
                    and inertia_count is not None
                    and wrong_direction_count is not None
                    and other_non_inertia_count is not None
                    and inertia_breakdown is not None
                )
                if (
                    response_count,
                    inertia_count,
                    wrong_direction_count,
                    other_non_inertia_count,
                ) != (
                    derived_response_count,
                    derived_inertia_count,
                    derived_wrong_direction_count,
                    derived_other_non_inertia_count,
                ):
                    raise ValueError(
                        "response and inertia counts must derive from exact cluster endpoints"
                    )
                if (
                    response_count + inertia_count + wrong_direction_count + other_non_inertia_count
                    != self.planned_clusters
                ):
                    raise ValueError("inertia endpoint categories must partition planned clusters")
                observed_inertia_breakdown = (
                    inertia_breakdown.baseline_correct_same_decision_cluster_count,
                    inertia_breakdown.baseline_incorrect_same_decision_cluster_count,
                    inertia_breakdown.mixed_baseline_correctness_same_decision_cluster_count,
                )
                if (
                    inertia_breakdown.planned_clusters != self.planned_clusters
                    or observed_inertia_breakdown != derived_inertia_breakdown
                    or sum(observed_inertia_breakdown) != inertia_count
                ):
                    raise ValueError(
                        "descriptive same-decision inertia breakdown must exactly "
                        "partition the confirmatory inertia count"
                    )
                if response_count != analysis.responding_clusters:
                    raise ValueError(
                        "decision response count must derive from the embedded exact analysis"
                    )
                if self.decision_inertia_interval is None or (
                    self.decision_inertia_interval.trials,
                    self.decision_inertia_interval.successes,
                ) != (self.planned_clusters, inertia_count):
                    raise ValueError("inertia interval must bind the exact condition counts")
                if self.decision_response_rate != format_six_place_rate(
                    response_count,
                    self.planned_clusters,
                ):
                    raise ValueError("decision_response_rate must derive from planned clusters")
                if self.decision_inertia_rate != format_six_place_rate(
                    inertia_count,
                    self.planned_clusters,
                ):
                    raise ValueError("decision_inertia_rate must derive from planned clusters")
            else:
                if any(value is None for value in control_statistical_fields) or any(
                    value is not None for value in inertia_statistical_fields
                ):
                    raise ValueError("invariant negative control requires only control statistics")
                stability_count = self.control_expected_stability_cluster_count
                change_count = self.control_unexpected_change_cluster_count
                assert stability_count is not None and change_count is not None
                if (
                    stability_count,
                    change_count,
                ) != (
                    derived_stability_count,
                    derived_change_count,
                ):
                    raise ValueError(
                        "invariant control counts must derive from exact cluster endpoints"
                    )
                if stability_count + change_count != self.planned_clusters:
                    raise ValueError(
                        "invariant stability and change counts must partition planned clusters"
                    )
                if stability_count != analysis.responding_clusters:
                    raise ValueError(
                        "invariant stability count must derive from the embedded exact analysis"
                    )
                interval = self.control_unexpected_change_interval
                if interval is None or (
                    interval.trials,
                    interval.successes,
                ) != (self.planned_clusters, change_count):
                    raise ValueError("control-change interval must bind the exact condition counts")
                if self.control_unexpected_change_rate != format_six_place_rate(
                    change_count,
                    self.planned_clusters,
                ):
                    raise ValueError(
                        "control_unexpected_change_rate must derive from planned clusters"
                    )
                if self.state is StudyConditionState.analyzed and change_count != 0:
                    raise ValueError(
                        "analyzed invariant control cannot contain an unexpected arm change"
                    )
                if self.state is StudyConditionState.control_failed and change_count == 0:
                    raise ValueError(
                        "control-failed state requires an observed unexpected arm change"
                    )
            if (
                self.state is StudyConditionState.control_failed
                and self.analysis_role is not StudyConditionAnalysisRole.invariant_negative_control
            ):
                raise ValueError("only invariant negative controls can enter control-failed state")
        elif any(value is not None for value in statistical_fields):
            raise ValueError("inapplicable condition statistics must be omitted")
        if self.state is StudyConditionState.not_executed:
            if (
                self.sufficiency_report is not None
                or self.actual_pairs != 0
                or self.included_pairs != 0
                or self.excluded_pairs != 0
                or self.invalid_pairs != 0
                or self.actual_clusters != 0
                or self.analyzable_clusters != 0
                or self.missing_pairs != self.planned_pairs
                or self.operational_summary.run_records != 0
                or self.observed_model_identities
                or self.observed_execution_window is not None
                or self.observed_execution_provenance is not None
                or self.coupling is not None
                or self.failure_summaries
            ):
                raise ValueError("not-executed conditions cannot contain observed evidence")
            if not self.deviation_codes:
                raise ValueError("not-executed conditions require a reason code")
        if self.state is StudyConditionState.underpowered and (
            self.sufficiency_report is None
            or self.sufficiency_report.state is not SufficiencyState.inconclusive
        ):
            raise ValueError("underpowered condition requires inconclusive sufficiency evidence")
        if self.state is StudyConditionState.underpowered and self.deviation_codes:
            raise ValueError("underpowered condition cannot carry protocol deviations")
        if self.state is StudyConditionState.invalidated and not self.deviation_codes:
            raise ValueError("invalidated conditions require a declared deviation")
        if self.state is StudyConditionState.invalidated and (
            self.sufficiency_report is not None or self.expected_response_diagnostic is not None
        ):
            raise ValueError("invalidated conditions cannot retain derived verdict reports")
        if (
            self.state is not StudyConditionState.not_executed
            and self.operational_summary.run_records
            and self.observed_execution_provenance is None
        ):
            raise ValueError("executed conditions require observed execution provenance")
        if (
            self.observed_execution_provenance is not None
            and self.observed_execution_provenance.run_records
            != self.operational_summary.run_records
        ):
            raise ValueError("observed execution provenance must cover the operational run records")
        return self


class RealModelStudyReport(SelfDigestedArtifact):
    _digest_field = "report_digest"

    artifact_kind: Literal["real-model-study-report"] = "real-model-study-report"
    schema_version: Literal["0.6.6"] = STUDY_SCHEMA_VERSION
    schema_name: Literal["real-model-study-report"] = "real-model-study-report"
    contract_id: Literal["RealModelStudyReport/v1"] = "RealModelStudyReport/v1"
    contract_version: Literal["1.0.0"] = STUDY_CONTRACT_VERSION
    report_id: MachineIdentifier
    report_digest: DigestHex
    manifest: RealModelStudyManifest
    manifest_digest: DigestHex
    benchmark_digest: DigestHex
    protocol_set_digest: DigestHex
    hypothesis_decision_rule_digest: DigestHex
    registration_evidence_verified: Literal[False] = False
    registration_evidence_verification: Literal["closed_bundle_operator_review_required"] = (
        "closed_bundle_operator_review_required"
    )
    registration_reviewer_identity_authentication: Literal["out_of_band_not_machine_verified"] = (
        "out_of_band_not_machine_verified"
    )
    conditions: tuple[StudyConditionResult, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_CONDITIONS,
    )
    inferential_statistics_applicable: bool
    protocol_valid: bool
    statistical_sufficiency_satisfied: bool
    invariant_controls_satisfied: bool
    hypothesis_classification: StudyHypothesisClassification
    confirmatory_conclusion_permitted: Literal[False] = False
    publication_eligible: Literal[False] = False
    total_planned_pairs: int = Field(ge=1)
    total_actual_pairs: int = Field(ge=0)
    total_included_pairs: int = Field(ge=0)
    total_missing_pairs: int = Field(ge=0)
    total_excluded_pairs: int = Field(ge=0)
    total_invalid_pairs: int = Field(ge=0)
    total_planned_clusters: int = Field(ge=2)
    total_analyzable_clusters: int = Field(ge=0)
    deviations: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_STUDY_DEVIATIONS,
    )
    limitations: tuple[BoundedStudyText, ...] = Field(
        min_length=1,
        max_length=MAX_STUDY_LIMITATIONS,
    )
    drift_boundary: BoundedStudyText

    @model_validator(mode="before")
    @classmethod
    def _validate_aggregate_interval_work(cls, value: object) -> object:
        """Reject excessive exact-tail work before nested interval validation."""

        if not isinstance(value, Mapping):
            return value
        raw_conditions = value.get("conditions")
        if not isinstance(raw_conditions, (list, tuple)):
            return value
        if len(raw_conditions) > MAX_STUDY_CONDITIONS:
            raise ValueError("study report exceeds the supported condition count")
        intervals: list[tuple[int, int, Decimal]] = []
        for condition in raw_conditions:
            if not isinstance(condition, Mapping):
                continue
            for field_name in (
                "decision_inertia_interval",
                "control_unexpected_change_interval",
            ):
                interval = condition.get(field_name)
                if not isinstance(interval, Mapping):
                    continue
                successes = interval.get("successes")
                trials = interval.get("trials")
                raw_alpha = interval.get("adjusted_alpha")
                if (
                    type(successes) is not int
                    or type(trials) is not int
                    or not 0 <= successes <= 1_000
                    or not 2 <= trials <= 1_000
                    or not isinstance(raw_alpha, str)
                    or len(raw_alpha) > 32
                ):
                    continue
                try:
                    alpha = Decimal(raw_alpha)
                except InvalidOperation:
                    continue
                intervals.append((successes, trials, alpha))
        validate_clopper_pearson_work_budget(intervals)
        return value

    @field_validator("conditions", "deviations", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("hypothesis_classification", mode="before")
    @classmethod
    def _coerce_classification(cls, value: object) -> StudyHypothesisClassification:
        return coerce_enum(StudyHypothesisClassification, value)

    @model_validator(mode="after")
    def _validate_report(self) -> Self:
        expected_inferential_applicability = (
            self.manifest.hypothesis_decision_rule.inference_scope
            is StudyInferenceScope.confirmatory_independent_clusters
        )
        if self.inferential_statistics_applicable is not expected_inferential_applicability:
            raise ValueError(
                "inferential_statistics_applicable must derive from the manifest scope"
            )
        if self.report_id != f"{self.manifest.study_id}/report":
            raise ValueError("study report_id must derive from study_id")
        if (
            self.manifest_digest,
            self.benchmark_digest,
            self.protocol_set_digest,
            self.hypothesis_decision_rule_digest,
        ) != (
            self.manifest.manifest_digest,
            self.manifest.benchmark_digest,
            self.manifest.protocol_set_digest,
            self.manifest.hypothesis_decision_rule_digest,
        ):
            raise ValueError("study report digests must exactly bind the manifest")
        condition_ids = tuple(item.condition_id for item in self.conditions)
        manifest_ids = tuple(item.condition_id for item in self.manifest.conditions)
        if condition_ids != manifest_ids:
            raise ValueError("study report conditions must exactly cover the frozen manifest")
        fingerprints_by_execution_identity: dict[
            tuple[
                StudyExecutionOrigin,
                str,
                str,
                str,
                str | None,
                str | None,
                str | None,
                str,
                str,
            ],
            list[str | None],
        ] = {}
        for result, binding in zip(self.conditions, self.manifest.conditions, strict=True):
            observed_provenance = result.observed_execution_provenance
            if observed_provenance is not None and (
                observed_provenance.condition_id,
                observed_provenance.study_manifest_digest,
                observed_provenance.declared_origin,
                observed_provenance.planned_run_records,
            ) != (
                binding.condition_id,
                self.manifest_digest,
                binding.execution_origin,
                2 * binding.planned_pairs,
            ):
                raise ValueError(
                    "condition observed execution provenance does not match its manifest binding"
                )
            if (
                result.protocol_digest,
                result.design_commitment_digest,
                result.planned_pairs,
                result.planned_clusters,
            ) != (
                binding.protocol_digest,
                binding.design_commitment_digest,
                binding.planned_pairs,
                binding.planned_independent_clusters,
            ):
                raise ValueError("condition result does not match its manifest binding")
            if result.state in {
                StudyConditionState.analyzed,
                StudyConditionState.control_failed,
                StudyConditionState.underpowered,
            }:
                if len(result.observed_model_identities) != 1:
                    raise ValueError(
                        "valid observed model identity must be stable across the condition"
                    )
                observed_identity = result.observed_model_identities[0]
                if (
                    observed_identity.provider,
                    observed_identity.requested_model,
                    observed_identity.resolved_model,
                    observed_identity.provider_api_version,
                    observed_identity.provider_sdk,
                    observed_identity.provider_region,
                    observed_identity.adapter_id,
                    observed_identity.pipeline_id,
                ) != (
                    binding.provider,
                    binding.requested_model,
                    binding.expected_resolved_model,
                    binding.provider_api_version,
                    binding.provider_sdk,
                    binding.provider_region,
                    binding.adapter_id,
                    binding.pipeline_id,
                ):
                    raise ValueError(
                        "valid observed model identity must exactly match the manifest"
                    )
                if observed_provenance is None:
                    raise ValueError("valid condition requires observed execution provenance")
                fingerprint_present = observed_identity.provider_serving_fingerprint is not None
                fingerprint_complete = (
                    observed_provenance.provider_serving_fingerprint_records
                    == observed_provenance.run_records
                    and observed_provenance.distinct_provider_serving_fingerprints == 1
                )
                fingerprint_absent = (
                    observed_provenance.provider_serving_fingerprint_records == 0
                    and observed_provenance.distinct_provider_serving_fingerprints == 0
                )
                if (fingerprint_present, fingerprint_complete, fingerprint_absent) not in {
                    (True, True, False),
                    (False, False, True),
                }:
                    raise ValueError(
                        "valid provider serving fingerprint must be all absent or "
                        "complete and stable across the condition"
                    )
                expected_fingerprint_digest = (
                    _canonical_sha256(
                        {
                            "purpose": "study-provider-serving-fingerprints/v1",
                            "fingerprints": (observed_identity.provider_serving_fingerprint,),
                        }
                    )
                    if fingerprint_present
                    else None
                )
                if (
                    observed_provenance.provider_serving_fingerprint_set_digest
                    != expected_fingerprint_digest
                ):
                    raise ValueError(
                        "observed provider serving-fingerprint digest must bind the "
                        "exposed stable identity"
                    )
                if binding.execution_origin is StudyExecutionOrigin.real_provider:
                    fingerprints_by_execution_identity.setdefault(
                        _study_condition_execution_identity(binding),
                        [],
                    ).append(observed_identity.provider_serving_fingerprint)
                if result.observed_execution_window is None or not (
                    parse_rfc3339_timestamp(
                        self.manifest.execution_window.start,
                        field_name="manifest.execution_window.start",
                    )
                    <= parse_rfc3339_timestamp(
                        result.observed_execution_window.start,
                        field_name="condition.observed_execution_window.start",
                    )
                    < parse_rfc3339_timestamp(
                        result.observed_execution_window.end,
                        field_name="condition.observed_execution_window.end",
                    )
                    <= parse_rfc3339_timestamp(
                        self.manifest.execution_window.end,
                        field_name="manifest.execution_window.end",
                    )
                ):
                    raise ValueError(
                        "valid observed execution window must be inside the frozen window"
                    )
                if result.sufficiency_report is None:
                    raise ValueError("valid condition requires bound source dependencies")
                if (
                    result.operational_summary.cost_reported_records
                    != result.operational_summary.run_records
                    or result.operational_summary.cost_budget_committed_records
                    != result.operational_summary.run_records
                ):
                    raise ValueError(
                        "valid condition requires complete estimated and committed cost accounting"
                    )
                if (
                    binding.execution_origin is StudyExecutionOrigin.real_provider
                    and result.operational_summary.latency_reported_records
                    != result.operational_summary.run_records
                ):
                    raise ValueError(
                        "valid real-provider condition requires complete latency accounting"
                    )
                if (
                    result.state
                    in {StudyConditionState.analyzed, StudyConditionState.control_failed}
                    and result.operational_summary.run_records != 2 * result.planned_pairs
                ):
                    raise ValueError(
                        "analyzed condition requires both records for every planned pair"
                    )
                dependencies = result.sufficiency_report.source_runsets
                if tuple(item.arm_id for item in dependencies) != (
                    "baseline_evidence",
                    "counterfactual_evidence",
                ):
                    raise ValueError("valid condition requires both ordered source RunSets")
                expected_configurations = (
                    binding.baseline_configuration_digest,
                    binding.counterfactual_configuration_digest,
                )
                if (
                    tuple(item.execution_configuration_digest for item in dependencies)
                    != expected_configurations
                ):
                    raise ValueError(
                        "valid condition source configurations must match the manifest"
                    )
                if any(item.study_manifest_digest != self.manifest_digest for item in dependencies):
                    raise ValueError("valid condition source RunSets must bind the study manifest")
                if observed_provenance is None:
                    raise ValueError("valid condition requires observed execution provenance")
                observed_runsets = (
                    (
                        observed_provenance.baseline_runset_id,
                        observed_provenance.baseline_runset_digest,
                    ),
                    (
                        observed_provenance.counterfactual_runset_id,
                        observed_provenance.counterfactual_runset_digest,
                    ),
                )
                dependency_runsets = tuple(
                    (item.runset_id, item.runset_digest) for item in dependencies
                )
                if observed_runsets != dependency_runsets:
                    raise ValueError(
                        "observed execution provenance must bind the exact source RunSets"
                    )
            if any(
                case_id not in set(binding.benchmark_case_ids)
                for failure in result.failure_summaries
                for case_id in failure.example_case_ids
            ):
                raise ValueError("condition failure examples must belong to its benchmark frame")
            inferential_family_size = len(
                self.manifest.hypothesis_decision_rule.target_task_model_conditions
            )
            if result.decision_inertia_interval is not None and (
                result.decision_inertia_interval.familywise_alpha
                != self.manifest.hypothesis_decision_rule.familywise_alpha
                or result.decision_inertia_interval.family_size != inferential_family_size
            ):
                raise ValueError("condition interval does not match the frozen multiplicity rule")
            if result.control_unexpected_change_interval is not None and (
                result.control_unexpected_change_interval.familywise_alpha
                != self.manifest.hypothesis_decision_rule.familywise_alpha
                or result.control_unexpected_change_interval.family_size != inferential_family_size
            ):
                raise ValueError("control interval does not match the frozen multiplicity rule")
            if result.analysis_role is not binding.analysis_role:
                raise ValueError("condition analysis role must match its frozen manifest binding")
        for fingerprints in fingerprints_by_execution_identity.values():
            reported = tuple(value for value in fingerprints if value is not None)
            if reported and len(reported) != len(fingerprints):
                raise ValueError(
                    "valid model-matched conditions must either all omit or all report "
                    "a provider serving fingerprint"
                )
            if len(set(reported)) > 1:
                raise ValueError(
                    "valid model-matched conditions must share one provider serving fingerprint"
                )
        expected_totals = (
            sum(item.planned_pairs for item in self.conditions),
            sum(item.actual_pairs for item in self.conditions),
            sum(item.included_pairs for item in self.conditions),
            sum(item.missing_pairs for item in self.conditions),
            sum(item.excluded_pairs for item in self.conditions),
            sum(item.invalid_pairs for item in self.conditions),
            sum(item.planned_clusters for item in self.conditions),
            sum(item.analyzable_clusters for item in self.conditions),
        )
        observed_totals = (
            self.total_planned_pairs,
            self.total_actual_pairs,
            self.total_included_pairs,
            self.total_missing_pairs,
            self.total_excluded_pairs,
            self.total_invalid_pairs,
            self.total_planned_clusters,
            self.total_analyzable_clusters,
        )
        if observed_totals != expected_totals:
            raise ValueError("study aggregate counts must derive from condition results")
        reported_estimated_cost = sum(
            item.operational_summary.total_estimated_cost_microusd or 0 for item in self.conditions
        )
        reported_committed_cost = sum(
            item.operational_summary.total_cost_budget_committed_microusd or 0
            for item in self.conditions
        )
        budget_exceeded = (
            max(reported_estimated_cost, reported_committed_cost)
            > self.manifest.budget.maximum_estimated_cost_microusd
        )
        budget_code = "study-budget-exceeded"
        executed_conditions = tuple(
            item for item in self.conditions if item.operational_summary.run_records
        )
        if budget_exceeded and (
            not executed_conditions
            or any(
                item.state is not StudyConditionState.invalidated
                or budget_code not in item.deviation_codes
                for item in executed_conditions
            )
        ):
            raise ValueError("over-budget study reports must invalidate every executed condition")
        if not budget_exceeded and any(
            budget_code in item.deviation_codes for item in self.conditions
        ):
            raise ValueError("study-budget-exceeded requires an actual aggregate budget overrun")
        protocol_valid = all(
            item.state not in {StudyConditionState.invalidated, StudyConditionState.not_executed}
            for item in self.conditions
        )
        sufficient = all(
            item.state in {StudyConditionState.analyzed, StudyConditionState.control_failed}
            for item in self.conditions
        )
        invariant_controls_satisfied = all(
            item.state is StudyConditionState.analyzed
            and item.control_unexpected_change_cluster_count == 0
            for item in self.conditions
            if item.analysis_role is StudyConditionAnalysisRole.invariant_negative_control
        )
        if self.protocol_valid is not protocol_valid:
            raise ValueError("protocol_valid must derive from condition states")
        if self.statistical_sufficiency_satisfied is not sufficient:
            raise ValueError("statistical sufficiency must derive from every target condition")
        if self.invariant_controls_satisfied is not invariant_controls_satisfied:
            raise ValueError(
                "invariant control validity must derive from every negative-control condition"
            )
        if (
            sufficient
            and invariant_controls_satisfied
            and self.manifest.hypothesis_decision_rule.inference_scope
            is StudyInferenceScope.confirmatory_independent_clusters
        ):
            threshold = Decimal(self.manifest.hypothesis_decision_rule.materiality_threshold)
            intervals = tuple(
                item.decision_inertia_interval
                for item in self.conditions
                if item.analysis_role is StudyConditionAnalysisRole.inertia_estimand
            )
            if not intervals:
                raise ValueError("sufficient study requires an inertia-estimand condition")
            if any(item is None for item in intervals):
                raise ValueError("sufficient study is missing a condition interval")
            lower_bounds = tuple(Decimal(item.lower_bound) for item in intervals if item)
            upper_bounds = tuple(Decimal(item.upper_bound) for item in intervals if item)
            expected_classification = (
                StudyHypothesisClassification.supported
                if any(value > threshold for value in lower_bounds)
                else StudyHypothesisClassification.contradicted
                if all(value <= threshold for value in upper_bounds)
                else StudyHypothesisClassification.inconclusive
            )
        else:
            expected_classification = StudyHypothesisClassification.not_measured
        if self.hypothesis_classification is not expected_classification:
            raise ValueError("hypothesis classification does not match the frozen decision rule")
        # This artifact intentionally cannot attest to separate registration
        # record bytes or a human review receipt. Publication permission is
        # derived only by the closed-bundle readiness verifier.
        expected_permission = False
        if (
            self.confirmatory_conclusion_permitted is not expected_permission
            or self.publication_eligible is not expected_permission
        ):
            raise ValueError("confirmatory and publication eligibility must fail closed")
        expected_deviations = tuple(
            sorted({code for item in self.conditions for code in item.deviation_codes})
        )
        if self.deviations != expected_deviations:
            raise ValueError("study deviations must exactly summarize condition deviations")
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("study report limitations must be unique and sorted")
        if not set(self.manifest.limitations) <= set(self.limitations):
            raise ValueError("study report must preserve every preregistered limitation")
        return self


__all__ = [
    "RealModelStudyManifest",
    "RealModelStudyReport",
    "StudyAnalysisDeclaration",
    "StudyBudget",
    "StudyConditionBinding",
    "StudyConditionAnalysisRole",
    "StudyDecisionInertiaDescriptiveBreakdown",
    "StudyConditionResult",
    "StudyConditionState",
    "StudyExecutionOrigin",
    "StudyExecutionReviewCondition",
    "StudyExecutionReviewReceipt",
    "StudyStatisticalMethodReviewCondition",
    "StudyStatisticalMethodReviewReceipt",
    "StudyExecutionWindow",
    "StudyFailureSummary",
    "StudyExpectedResponseDiagnostic",
    "StudyHypothesisClassification",
    "StudyHypothesisDecisionRule",
    "StudyInferenceScope",
    "StudyIndependenceDesignBasis",
    "StudyIndependenceJustification",
    "StudyIndependenceJustificationStatus",
    "StudyMethodReviewApprovalDisposition",
    "StudyKnowledgeContract",
    "StudyObservedModelIdentity",
    "StudyObservedExecutionProvenance",
    "StudyOneSidedInterval",
    "StudyOperationalSummary",
    "StudyPublicationPolicy",
    "StudyProviderFingerprintReviewStatus",
    "StudyRegistration",
    "StudyRegistrationReviewReceipt",
    "StudyRegistrationMethod",
    "StudyReviewerQualificationBasisType",
    "StudySemanticNearDuplicateDisposition",
    "calculate_hypothesis_decision_rule_digest",
    "derive_study_cluster_endpoint_counts",
    "derive_study_inertia_descriptive_counts",
    "require_resolved_independence_justification",
    "calculate_study_knowledge_contract_digest",
    "calculate_study_protocol_set_digest",
    "MAX_STUDY_OBSERVED_MODEL_IDENTITIES",
    "UNRESOLVED_INDEPENDENCE_BASIS",
]
