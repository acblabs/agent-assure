from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from agent_assure.schema.base import RFC8785_SAFE_INTEGER_MAX, FrozenStrictModel
from agent_assure.schema.campaign import MutationApplicability
from agent_assure.schema.common import DigestHex, GateState, coerce_enum, coerce_tuple
from agent_assure.schema.mutation import (
    BoundedSummary,
    GateEffect,
    IndependenceClass,
    MachineIdentifier,
    MutationResultState,
    SelfDigestedArtifact,
)

EFFICACY_SCHEMA_VERSION = "0.6.2"
MAX_EFFICACY_OPERATORS = 256
MAX_THREAT_CATEGORIES = 4096
MAX_CATALOG_THREAT_REFERENCES = MAX_EFFICACY_OPERATORS * 32
MAX_EFFICACY_LIMITATIONS = 32

INDEPENDENCE_CLASS_ORDER = tuple(IndependenceClass)
INDEPENDENT_CHALLENGE_CLASSES = frozenset(
    {
        IndependenceClass.external_preexisting,
        IndependenceClass.third_party_contributed,
        IndependenceClass.first_party_precontrol,
    }
)


class ExactRateState(StrEnum):
    defined = "defined"
    undefined_zero_denominator = "undefined_zero_denominator"


class ThreatApplicability(StrEnum):
    applicable = "applicable"
    not_applicable = "not_applicable"
    unknown = "unknown"


class ControlEfficacySemanticState(StrEnum):
    survivor_observed = "survivor_observed"
    indeterminate = "indeterminate"
    not_evaluated = "not_evaluated"
    all_evaluated_applicable_caught = "all_evaluated_applicable_caught"


class ThreatScopeSemanticState(StrEnum):
    critical_gap_observed = "critical_gap_observed"
    unknown_applicability = "unknown_applicability"
    unscoped_catalog_references = "unscoped_catalog_references"
    not_evaluated = "not_evaluated"
    gap_observed = "gap_observed"
    all_applicable_challenged = "all_applicable_challenged"


class ControlEfficacyGateReason(StrEnum):
    required_operator_survived = "REQUIRED_OPERATOR_SURVIVED"
    critical_operator_survived = "CRITICAL_OPERATOR_SURVIVED"
    applicable_operator_survived = "APPLICABLE_OPERATOR_SURVIVED"
    critical_threat_uncovered = "CRITICAL_THREAT_UNCOVERED"
    applicable_threat_uncovered = "APPLICABLE_THREAT_UNCOVERED"
    invalid_or_error_operator = "INVALID_OR_ERROR_OPERATOR"
    required_operator_not_evaluated = "REQUIRED_OPERATOR_NOT_EVALUATED"
    unknown_threat_applicability = "UNKNOWN_THREAT_APPLICABILITY"
    unscoped_catalog_threat_reference = "UNSCOPED_CATALOG_THREAT_REFERENCE"


CONTROL_EFFICACY_GATE_REASON_ORDER = (
    ControlEfficacyGateReason.required_operator_survived,
    ControlEfficacyGateReason.critical_operator_survived,
    ControlEfficacyGateReason.applicable_operator_survived,
    ControlEfficacyGateReason.critical_threat_uncovered,
    ControlEfficacyGateReason.applicable_threat_uncovered,
    ControlEfficacyGateReason.invalid_or_error_operator,
    ControlEfficacyGateReason.required_operator_not_evaluated,
    ControlEfficacyGateReason.unknown_threat_applicability,
    ControlEfficacyGateReason.unscoped_catalog_threat_reference,
)


def _exact_rate_json_schema_extra(schema: dict[str, Any]) -> None:
    schema["$comment"] = (
        "JSON Schema enforces the denominator/state relationship and the zero-denominator "
        "numerator. Runtime model validation additionally enforces numerator <= denominator "
        "for nonzero denominators."
    )
    schema.setdefault("allOf", []).append(
        {
            "if": {
                "properties": {"denominator": {"const": 0}},
                "required": ["denominator"],
            },
            "then": {
                "properties": {
                    "numerator": {"const": 0},
                    "state": {"const": ExactRateState.undefined_zero_denominator.value},
                },
                "required": ["numerator", "state"],
            },
            "else": {
                "properties": {"state": {"const": ExactRateState.defined.value}},
                "required": ["state"],
            },
        }
    )


class ExactRate(FrozenStrictModel):
    """An exact ratio which never substitutes a numeric value for 0/0."""

    model_config = ConfigDict(json_schema_extra=_exact_rate_json_schema_extra)

    numerator: int = Field(ge=0, le=RFC8785_SAFE_INTEGER_MAX)
    denominator: int = Field(ge=0, le=RFC8785_SAFE_INTEGER_MAX)
    state: ExactRateState

    @classmethod
    def from_counts(cls, numerator: int, denominator: int) -> Self:
        return cls(
            numerator=numerator,
            denominator=denominator,
            state=(
                ExactRateState.undefined_zero_denominator
                if denominator == 0
                else ExactRateState.defined
            ),
        )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> ExactRateState:
        return coerce_enum(ExactRateState, value)

    @model_validator(mode="after")
    def _validate_ratio(self) -> ExactRate:
        if self.numerator > self.denominator:
            raise ValueError("rate numerator cannot exceed its denominator")
        expected = (
            ExactRateState.undefined_zero_denominator
            if self.denominator == 0
            else ExactRateState.defined
        )
        if self.state is not expected:
            raise ValueError("rate state does not match its denominator")
        return self


class MutationStateCounts(FrozenStrictModel):
    caught: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    survived: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    inapplicable: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    invalid_operator: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    invalid_subject: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)
    execution_error: int = Field(ge=0, le=MAX_EFFICACY_OPERATORS)

    @property
    def applicable(self) -> int:
        """Return the verdict-bearing denominator: caught plus survived."""
        return self.caught + self.survived

    @property
    def total(self) -> int:
        return sum(
            (
                self.caught,
                self.survived,
                self.inapplicable,
                self.invalid_operator,
                self.invalid_subject,
                self.execution_error,
            )
        )


class ThreatSourceIdentity(FrozenStrictModel):
    name: MachineIdentifier
    version: str = Field(min_length=1, max_length=128)


class ThreatApplicabilityItem(FrozenStrictModel):
    threat_id: MachineIdentifier
    applicability: ThreatApplicability
    critical: bool
    rationale: BoundedSummary | None = None
    owner: MachineIdentifier | None = None
    reviewed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")

    @field_validator("applicability", mode="before")
    @classmethod
    def _coerce_applicability(cls, value: object) -> ThreatApplicability:
        return coerce_enum(ThreatApplicability, value)

    @field_validator("reviewed_at")
    @classmethod
    def _validate_reviewed_at(cls, value: str) -> str:
        try:
            datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("reviewed_at must be a valid ISO 8601 calendar date") from exc
        return value

    @model_validator(mode="after")
    def _validate_not_applicable_accountability(self) -> ThreatApplicabilityItem:
        if self.applicability is ThreatApplicability.not_applicable and (
            self.rationale is None or not self.rationale.strip() or self.owner is None
        ):
            raise ValueError("not_applicable threats require both rationale and owner")
        return self


class ThreatApplicabilityManifest(SelfDigestedArtifact):
    _digest_field = "manifest_digest"

    artifact_kind: Literal["threat-applicability-manifest"] = "threat-applicability-manifest"
    schema_version: Literal["0.6.2"] = "0.6.2"
    schema_name: Literal["threat-applicability-manifest"] = "threat-applicability-manifest"
    contract_id: Literal["ThreatApplicabilityManifest/v1"] = "ThreatApplicabilityManifest/v1"
    contract_version: Literal["1.0.0"] = "1.0.0"
    manifest_digest: DigestHex
    threat_source: ThreatSourceIdentity
    present_control_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    items: tuple[ThreatApplicabilityItem, ...] = Field(
        min_length=1,
        max_length=MAX_THREAT_CATEGORIES,
    )
    limitations: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_EFFICACY_LIMITATIONS,
    )

    @field_validator("present_control_ids", "items", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_manifest_order(self) -> ThreatApplicabilityManifest:
        if self.present_control_ids != tuple(sorted(set(self.present_control_ids))):
            raise ValueError("present control IDs must be unique and canonically sorted")
        threat_ids = tuple(item.threat_id for item in self.items)
        if threat_ids != tuple(sorted(set(threat_ids))):
            raise ValueError("threat items must have unique IDs in canonical order")
        return self


class OperatorEfficacyOutcome(FrozenStrictModel):
    operator_id: MachineIdentifier
    invariant_family: MachineIdentifier
    independence_class: IndependenceClass
    applicability: MutationApplicability
    state: MutationResultState
    required: bool
    catalog_threat_ids: tuple[MachineIdentifier, ...] = Field(min_length=1, max_length=32)
    threat_ids: tuple[MachineIdentifier, ...] = Field(default=(), max_length=32)
    unscoped_catalog_threat_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=32,
    )
    critical_threat_ids: tuple[MachineIdentifier, ...] = Field(default=(), max_length=32)
    target_control_ids: tuple[MachineIdentifier, ...] = Field(min_length=1, max_length=32)
    present_target_control_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=32,
    )

    @field_validator("independence_class", mode="before")
    @classmethod
    def _coerce_independence_class(cls, value: object) -> IndependenceClass:
        return coerce_enum(IndependenceClass, value)

    @field_validator("applicability", mode="before")
    @classmethod
    def _coerce_applicability(cls, value: object) -> MutationApplicability:
        return coerce_enum(MutationApplicability, value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_result_state(cls, value: object) -> MutationResultState:
        return coerce_enum(MutationResultState, value)

    @field_validator(
        "catalog_threat_ids",
        "threat_ids",
        "unscoped_catalog_threat_ids",
        "critical_threat_ids",
        "target_control_ids",
        "present_target_control_ids",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_outcome(self) -> OperatorEfficacyOutcome:
        for label, values in (
            ("catalog threat IDs", self.catalog_threat_ids),
            ("threat IDs", self.threat_ids),
            ("unscoped catalog threat IDs", self.unscoped_catalog_threat_ids),
            ("critical threat IDs", self.critical_threat_ids),
            ("target control IDs", self.target_control_ids),
            ("present target control IDs", self.present_target_control_ids),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be unique and canonically sorted")
        if set(self.threat_ids) & set(self.unscoped_catalog_threat_ids):
            raise ValueError("scoped and unscoped catalog threat IDs must be disjoint")
        if tuple(sorted((*self.threat_ids, *self.unscoped_catalog_threat_ids))) != (
            self.catalog_threat_ids
        ):
            raise ValueError("scoped and unscoped threat IDs must partition catalog threat IDs")
        if not set(self.critical_threat_ids).issubset(self.threat_ids):
            raise ValueError("critical threat IDs must be a subset of operator threat IDs")
        if not set(self.present_target_control_ids).issubset(self.target_control_ids):
            raise ValueError("present target controls must be a subset of target controls")
        if self.state in {MutationResultState.caught, MutationResultState.survived} and (
            self.applicability is not MutationApplicability.applicable
        ):
            raise ValueError("caught and survived outcomes must be applicable")
        if self.state is MutationResultState.inapplicable and (
            self.applicability is not MutationApplicability.inapplicable
        ):
            raise ValueError("inapplicable outcomes must have inapplicable applicability")
        if self.state is MutationResultState.invalid_subject and (
            self.applicability is not MutationApplicability.not_evaluated
        ):
            raise ValueError("invalid_subject outcomes must not claim applicability")
        if self.applicability is MutationApplicability.inapplicable and (
            self.state is not MutationResultState.inapplicable
        ):
            raise ValueError("inapplicable applicability is reserved for inapplicable outcomes")
        return self

    @property
    def independent_challenge_eligible(self) -> bool:
        return self.independence_class in INDEPENDENT_CHALLENGE_CLASSES

    @property
    def completed_challenge(self) -> bool:
        return self.state in {MutationResultState.caught, MutationResultState.survived}


class EfficacyStratum(FrozenStrictModel):
    stratum: MachineIdentifier
    independent_challenge_eligible: bool | None = None
    state_counts: MutationStateCounts
    kill_rate: ExactRate

    @model_validator(mode="after")
    def _validate_stratum_rate(self) -> EfficacyStratum:
        expected = ExactRate.from_counts(
            self.state_counts.caught,
            self.state_counts.applicable,
        )
        if self.kill_rate != expected:
            raise ValueError("stratum kill rate does not match its state counts")
        return self


class ThreatCoverageItem(FrozenStrictModel):
    threat_id: MachineIdentifier
    applicability: ThreatApplicability
    critical: bool
    challenging_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    independent_challenging_operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )

    @field_validator("applicability", mode="before")
    @classmethod
    def _coerce_applicability(cls, value: object) -> ThreatApplicability:
        return coerce_enum(ThreatApplicability, value)

    @field_validator(
        "challenging_operator_ids",
        "independent_challenging_operator_ids",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_coverage(self) -> ThreatCoverageItem:
        for label, values in (
            ("challenging operator IDs", self.challenging_operator_ids),
            (
                "independent challenging operator IDs",
                self.independent_challenging_operator_ids,
            ),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"{label} must be unique and canonically sorted")
        if not set(self.independent_challenging_operator_ids).issubset(
            self.challenging_operator_ids
        ):
            raise ValueError("independent challenging operators must be challenging operators")
        if self.applicability is not ThreatApplicability.applicable and (
            self.challenging_operator_ids
        ):
            raise ValueError("non-applicable threats cannot claim challenge coverage")
        return self

    @property
    def challenged(self) -> bool:
        return bool(self.challenging_operator_ids)

    @property
    def independently_challenged(self) -> bool:
        return bool(self.independent_challenging_operator_ids)


class ControlEfficacyReport(SelfDigestedArtifact):
    """Standalone deterministic projection of one mutation campaign."""

    _digest_field = "report_digest"

    artifact_kind: Literal["control-efficacy-report"] = "control-efficacy-report"
    schema_version: Literal["0.6.2"] = "0.6.2"
    schema_name: Literal["control-efficacy-report"] = "control-efficacy-report"
    contract_id: Literal["ControlEfficacyReport/v1"] = "ControlEfficacyReport/v1"
    contract_version: Literal["1.0.0"] = "1.0.0"
    report_digest: DigestHex
    campaign_digest: DigestHex
    source_digest: DigestHex
    suite_digest: DigestHex
    catalog_id: MachineIdentifier
    catalog_digest: DigestHex
    threat_manifest_digest: DigestHex
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
    operator_outcomes: tuple[OperatorEfficacyOutcome, ...] = Field(
        min_length=1,
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
    threat_coverage: tuple[ThreatCoverageItem, ...] = Field(
        min_length=1,
        max_length=MAX_THREAT_CATEGORIES,
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
    unscoped_catalog_threat_count: int = Field(ge=0, le=MAX_CATALOG_THREAT_REFERENCES)
    unscoped_catalog_threat_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_CATALOG_THREAT_REFERENCES,
    )
    threat_challenge_rate: ExactRate
    independent_threat_challenge_rate: ExactRate
    limitations: tuple[BoundedSummary, ...] = Field(
        min_length=1,
        max_length=MAX_EFFICACY_LIMITATIONS,
    )

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
        "operator_outcomes",
        "required_survivor_operator_ids",
        "critical_survivor_operator_ids",
        "required_not_evaluated_operator_ids",
        "invalid_or_error_operator_ids",
        "kill_rate_by_invariant_family",
        "kill_rate_by_independence_class",
        "threat_coverage",
        "critical_uncovered_threat_ids",
        "unknown_applicability_threat_ids",
        "unscoped_catalog_threat_ids",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_report_projection(self) -> ControlEfficacyReport:
        self._validate_operator_projection()
        self._validate_strata()
        self._validate_threat_projection()
        return self

    def _validate_operator_projection(self) -> None:
        canonical = self.canonical_operator_ids
        selected = self.selected_operator_ids
        pending = self.pending_operator_ids
        required = self.required_operator_ids
        if canonical != tuple(sorted(set(canonical))):
            raise ValueError("canonical operator IDs must be unique and lexicographic")
        for label, values in (
            ("selected operator IDs", selected),
            ("pending operator IDs", pending),
            ("required operator IDs", required),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} must be unique")
            value_set = set(values)
            if values != tuple(item for item in canonical if item in value_set):
                raise ValueError(f"{label} must be a canonical catalog subsequence")
        outcome_ids = tuple(item.operator_id for item in self.operator_outcomes)
        if (*outcome_ids, *pending) != selected:
            raise ValueError("operator outcomes and pending IDs must partition selection")
        required_set = set(required)
        if any(
            item.required is not (item.operator_id in required_set)
            for item in self.operator_outcomes
        ):
            raise ValueError("operator required flags do not match required operator IDs")

        expected_counts = mutation_state_counts(self.operator_outcomes)
        if self.state_counts != expected_counts:
            raise ValueError("state counts do not match operator outcomes")
        direct_counts = (
            self.applicable_operator_count,
            self.caught_operator_count,
            self.survived_operator_count,
            self.inapplicable_operator_count,
            self.invalid_operator_count,
            self.invalid_subject_count,
            self.execution_error_count,
        )
        expected_direct = (
            expected_counts.applicable,
            expected_counts.caught,
            expected_counts.survived,
            expected_counts.inapplicable,
            expected_counts.invalid_operator,
            expected_counts.invalid_subject,
            expected_counts.execution_error,
        )
        if direct_counts != expected_direct:
            raise ValueError("top-level operator counts do not match state counts")
        if self.catalog_kill_rate != ExactRate.from_counts(
            expected_counts.caught,
            expected_counts.applicable,
        ):
            raise ValueError("catalog kill rate does not match operator outcomes")

        expected_required_survivors = tuple(
            item.operator_id
            for item in self.operator_outcomes
            if item.required and item.state is MutationResultState.survived
        )
        expected_critical_survivors = tuple(
            item.operator_id
            for item in self.operator_outcomes
            if item.critical_threat_ids and item.state is MutationResultState.survived
        )
        invalid_states = {
            MutationResultState.invalid_operator,
            MutationResultState.invalid_subject,
            MutationResultState.execution_error,
        }
        expected_invalid = tuple(
            item.operator_id for item in self.operator_outcomes if item.state in invalid_states
        )
        outcome_by_id = {item.operator_id: item for item in self.operator_outcomes}
        expected_required_not_evaluated = tuple(
            operator_id
            for operator_id in required
            if operator_id not in outcome_by_id
            or outcome_by_id[operator_id].state
            not in {MutationResultState.caught, MutationResultState.survived}
        )
        expected_id_fields = (
            expected_required_survivors,
            expected_critical_survivors,
            expected_required_not_evaluated,
            expected_invalid,
        )
        actual_id_fields = (
            self.required_survivor_operator_ids,
            self.critical_survivor_operator_ids,
            self.required_not_evaluated_operator_ids,
            self.invalid_or_error_operator_ids,
        )
        if actual_id_fields != expected_id_fields:
            raise ValueError("operator diagnostic ID sets do not match outcomes")
        if self.required_survivor_count != len(expected_required_survivors):
            raise ValueError("required survivor count does not match its IDs")
        if self.critical_survivor_count != len(expected_critical_survivors):
            raise ValueError("critical survivor count does not match its IDs")
        expected_state = control_efficacy_semantic_state(
            expected_counts,
            pending_count=len(pending),
        )
        if self.semantic_state is not expected_state:
            raise ValueError("semantic state does not match operator outcomes")

    def _validate_strata(self) -> None:
        canonical_families = self.canonical_invariant_families
        if canonical_families != tuple(sorted(set(canonical_families))):
            raise ValueError("canonical invariant families must be unique and lexicographic")
        family_names = tuple(item.stratum for item in self.kill_rate_by_invariant_family)
        if family_names != canonical_families:
            raise ValueError(
                "all canonical invariant-family strata must be present in canonical order"
            )
        outcomes_by_family: dict[str, list[OperatorEfficacyOutcome]] = {
            family: [] for family in canonical_families
        }
        for outcome in self.operator_outcomes:
            family_outcomes = outcomes_by_family.get(outcome.invariant_family)
            if family_outcomes is None:
                raise ValueError("operator outcome references an absent invariant-family stratum")
            family_outcomes.append(outcome)
        for stratum in self.kill_rate_by_invariant_family:
            expected = mutation_state_counts(outcomes_by_family[stratum.stratum])
            if stratum.state_counts != expected:
                raise ValueError("invariant-family stratum counts do not match outcomes")
            if stratum.independent_challenge_eligible is not None:
                raise ValueError("invariant-family strata cannot claim independence eligibility")

        independence_names = tuple(item.stratum for item in self.kill_rate_by_independence_class)
        expected_names = tuple(item.value for item in INDEPENDENCE_CLASS_ORDER)
        if independence_names != expected_names:
            raise ValueError("all independence strata must be present in canonical order")
        outcomes_by_independence: dict[IndependenceClass, list[OperatorEfficacyOutcome]] = {
            independence_class: [] for independence_class in INDEPENDENCE_CLASS_ORDER
        }
        for outcome in self.operator_outcomes:
            outcomes_by_independence[outcome.independence_class].append(outcome)
        for independence_class, stratum in zip(
            INDEPENDENCE_CLASS_ORDER,
            self.kill_rate_by_independence_class,
            strict=True,
        ):
            expected = mutation_state_counts(outcomes_by_independence[independence_class])
            if stratum.state_counts != expected:
                raise ValueError("independence stratum counts do not match outcomes")
            if stratum.independent_challenge_eligible is not (
                independence_class in INDEPENDENT_CHALLENGE_CLASSES
            ):
                raise ValueError("independence eligibility does not match the fixed policy")

    def _validate_threat_projection(self) -> None:
        threat_ids = tuple(item.threat_id for item in self.threat_coverage)
        if threat_ids != tuple(sorted(set(threat_ids))):
            raise ValueError("threat coverage must have unique IDs in canonical order")
        coverage_by_id = {item.threat_id: item for item in self.threat_coverage}
        for outcome in self.operator_outcomes:
            if not set(outcome.threat_ids).issubset(coverage_by_id):
                raise ValueError("operator outcome references a threat absent from coverage")
            if set(outcome.unscoped_catalog_threat_ids) & coverage_by_id.keys():
                raise ValueError(
                    "unscoped catalog threat IDs must be absent from manifest coverage"
                )
            expected_critical = tuple(
                threat_id
                for threat_id in outcome.threat_ids
                if coverage_by_id[threat_id].applicability is ThreatApplicability.applicable
                and coverage_by_id[threat_id].critical
            )
            if outcome.critical_threat_ids != expected_critical:
                raise ValueError("operator critical threats do not match threat coverage")

        challengers_by_threat: dict[str, list[str]] = {
            threat_id: [] for threat_id in coverage_by_id
        }
        independent_challengers_by_threat: dict[str, list[str]] = {
            threat_id: [] for threat_id in coverage_by_id
        }
        for outcome in self.operator_outcomes:
            if not outcome.present_target_control_ids or not outcome.completed_challenge:
                continue
            for threat_id in outcome.threat_ids:
                coverage = coverage_by_id[threat_id]
                if coverage.applicability is not ThreatApplicability.applicable:
                    continue
                challengers_by_threat[threat_id].append(outcome.operator_id)
                if outcome.independent_challenge_eligible:
                    independent_challengers_by_threat[threat_id].append(outcome.operator_id)

        for coverage in self.threat_coverage:
            expected_challengers = tuple(sorted(set(challengers_by_threat[coverage.threat_id])))
            expected_independent = tuple(
                sorted(set(independent_challengers_by_threat[coverage.threat_id]))
            )
            if coverage.challenging_operator_ids != expected_challengers:
                raise ValueError("threat challengers do not match operator outcomes")
            if coverage.independent_challenging_operator_ids != expected_independent:
                raise ValueError("independent threat challengers do not match outcomes")

        applicable = tuple(
            item
            for item in self.threat_coverage
            if item.applicability is ThreatApplicability.applicable
        )
        challenged = tuple(item for item in applicable if item.challenged)
        independent = tuple(item for item in applicable if item.independently_challenged)
        critical_uncovered = tuple(
            item.threat_id for item in applicable if item.critical and not item.challenged
        )
        unknown = tuple(
            item.threat_id
            for item in self.threat_coverage
            if item.applicability is ThreatApplicability.unknown
        )
        unscoped = tuple(
            sorted(
                {
                    threat_id
                    for outcome in self.operator_outcomes
                    for threat_id in outcome.unscoped_catalog_threat_ids
                }
            )
        )
        actual_counts = (
            self.applicable_threat_category_count,
            self.challenged_threat_category_count,
            self.independently_challenged_threat_category_count,
            self.critical_uncovered_threat_count,
            self.unknown_applicability_count,
        )
        expected_counts = (
            len(applicable),
            len(challenged),
            len(independent),
            len(critical_uncovered),
            len(unknown),
        )
        if actual_counts != expected_counts:
            raise ValueError("threat counts do not match threat coverage")
        if self.critical_uncovered_threat_ids != critical_uncovered:
            raise ValueError("critical uncovered threat IDs do not match coverage")
        if self.unknown_applicability_threat_ids != unknown:
            raise ValueError("unknown-applicability threat IDs do not match coverage")
        if self.unscoped_catalog_threat_ids != unscoped:
            raise ValueError("unscoped catalog threat IDs do not match operator outcomes")
        if self.unscoped_catalog_threat_count != len(unscoped):
            raise ValueError("unscoped catalog threat count does not match its IDs")
        if self.threat_challenge_rate != ExactRate.from_counts(
            len(challenged),
            len(applicable),
        ):
            raise ValueError("threat challenge rate does not match coverage")
        if self.independent_threat_challenge_rate != ExactRate.from_counts(
            len(independent),
            len(applicable),
        ):
            raise ValueError("independent threat challenge rate does not match coverage")
        expected_state = threat_scope_semantic_state(
            applicable_count=len(applicable),
            challenged_count=len(challenged),
            critical_uncovered_count=len(critical_uncovered),
            unknown_count=len(unknown),
            unscoped_catalog_threat_count=len(unscoped),
        )
        if self.threat_scope_state is not expected_state:
            raise ValueError("threat scope state does not match coverage")


class ControlEfficacyGateProfile(FrozenStrictModel):
    profile_id: MachineIdentifier = "control-efficacy/default"
    required_catalog: MachineIdentifier
    required_operators: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_EFFICACY_OPERATORS,
    )
    surviving_required_operator: Literal[GateEffect.block] = GateEffect.block
    surviving_critical_operator: Literal[GateEffect.block] = GateEffect.block
    surviving_applicable_operator: GateEffect = GateEffect.review
    critical_threat_uncovered: GateEffect = GateEffect.review
    applicable_threat_uncovered: GateEffect = GateEffect.review
    invalid_or_error_operator: Literal[GateEffect.block] = GateEffect.block
    unevaluated_required_operator: Literal[GateEffect.block] = GateEffect.block
    unknown_threat_applicability: GateEffect = GateEffect.review
    unscoped_catalog_threat_reference: GateEffect = GateEffect.review

    @field_validator("required_operators", mode="before")
    @classmethod
    def _coerce_required_operators(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator(
        "surviving_required_operator",
        "surviving_critical_operator",
        "surviving_applicable_operator",
        "critical_threat_uncovered",
        "applicable_threat_uncovered",
        "invalid_or_error_operator",
        "unevaluated_required_operator",
        "unknown_threat_applicability",
        "unscoped_catalog_threat_reference",
        mode="before",
    )
    @classmethod
    def _coerce_effect(cls, value: object) -> GateEffect:
        return coerce_enum(GateEffect, value)

    @model_validator(mode="after")
    def _validate_profile(self) -> ControlEfficacyGateProfile:
        if self.required_operators != tuple(sorted(set(self.required_operators))):
            raise ValueError("required operators must be unique and canonically sorted")
        return self


class ControlEfficacyGateFinding(FrozenStrictModel):
    reason_code: ControlEfficacyGateReason
    effect: GateEffect
    operator_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_EFFICACY_OPERATORS,
    )
    threat_ids: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_CATALOG_THREAT_REFERENCES,
    )

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason(cls, value: object) -> ControlEfficacyGateReason:
        return coerce_enum(ControlEfficacyGateReason, value)

    @field_validator("effect", mode="before")
    @classmethod
    def _coerce_effect(cls, value: object) -> GateEffect:
        return coerce_enum(GateEffect, value)

    @field_validator("operator_ids", "threat_ids", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_finding(self) -> ControlEfficacyGateFinding:
        operator_subject_reasons = {
            ControlEfficacyGateReason.required_operator_survived,
            ControlEfficacyGateReason.critical_operator_survived,
            ControlEfficacyGateReason.applicable_operator_survived,
            ControlEfficacyGateReason.invalid_or_error_operator,
            ControlEfficacyGateReason.required_operator_not_evaluated,
        }
        threat_subject_reasons = {
            ControlEfficacyGateReason.critical_threat_uncovered,
            ControlEfficacyGateReason.applicable_threat_uncovered,
            ControlEfficacyGateReason.unknown_threat_applicability,
            ControlEfficacyGateReason.unscoped_catalog_threat_reference,
        }
        if self.reason_code in operator_subject_reasons:
            if not self.operator_ids or self.threat_ids:
                raise ValueError("operator gate findings must identify only affected operators")
        elif self.reason_code in threat_subject_reasons:
            if not self.threat_ids or self.operator_ids:
                raise ValueError("threat gate findings must identify only affected threats")
        else:
            raise ValueError("gate finding reason has no declared subject type")
        for label, values in (
            ("operator IDs", self.operator_ids),
            ("threat IDs", self.threat_ids),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"gate finding {label} must be unique and sorted")
        if (
            self.reason_code
            in {
                ControlEfficacyGateReason.required_operator_survived,
                ControlEfficacyGateReason.critical_operator_survived,
                ControlEfficacyGateReason.invalid_or_error_operator,
                ControlEfficacyGateReason.required_operator_not_evaluated,
            }
            and self.effect is not GateEffect.block
        ):
            raise ValueError(
                "required and critical survivor findings must block; "
                "invalid/error findings must block; "
                "required not-evaluated findings must block"
            )
        return self


class ControlEfficacyGateDecision(FrozenStrictModel):
    report_digest: DigestHex
    profile_id: MachineIdentifier
    state: GateState
    findings: tuple[ControlEfficacyGateFinding, ...] = Field(
        default=(),
        max_length=len(CONTROL_EFFICACY_GATE_REASON_ORDER),
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("findings", mode="before")
    @classmethod
    def _coerce_findings(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_decision(self) -> ControlEfficacyGateDecision:
        reasons = tuple(item.reason_code for item in self.findings)
        expected_order = tuple(
            reason for reason in CONTROL_EFFICACY_GATE_REASON_ORDER if reason in set(reasons)
        )
        if reasons != expected_order:
            raise ValueError("gate findings must be unique and in stable reason order")
        expected_state = gate_state_for_effects(tuple(item.effect for item in self.findings))
        if self.state is not expected_state:
            raise ValueError("gate state does not match finding effects")
        return self


def mutation_state_counts(
    outcomes: Iterable[OperatorEfficacyOutcome],
) -> MutationStateCounts:
    """Count every mutation terminal state without merging invalid_subject."""
    states = tuple(item.state for item in outcomes)
    return MutationStateCounts(
        caught=states.count(MutationResultState.caught),
        survived=states.count(MutationResultState.survived),
        inapplicable=states.count(MutationResultState.inapplicable),
        invalid_operator=states.count(MutationResultState.invalid_operator),
        invalid_subject=states.count(MutationResultState.invalid_subject),
        execution_error=states.count(MutationResultState.execution_error),
    )


def control_efficacy_semantic_state(
    counts: MutationStateCounts,
    *,
    pending_count: int,
) -> ControlEfficacySemanticState:
    if counts.survived:
        return ControlEfficacySemanticState.survivor_observed
    if counts.invalid_operator or counts.invalid_subject or counts.execution_error or pending_count:
        return ControlEfficacySemanticState.indeterminate
    if counts.applicable == 0:
        return ControlEfficacySemanticState.not_evaluated
    return ControlEfficacySemanticState.all_evaluated_applicable_caught


def threat_scope_semantic_state(
    *,
    applicable_count: int,
    challenged_count: int,
    critical_uncovered_count: int,
    unknown_count: int,
    unscoped_catalog_threat_count: int = 0,
) -> ThreatScopeSemanticState:
    if critical_uncovered_count:
        return ThreatScopeSemanticState.critical_gap_observed
    if unknown_count:
        return ThreatScopeSemanticState.unknown_applicability
    if unscoped_catalog_threat_count:
        return ThreatScopeSemanticState.unscoped_catalog_references
    if applicable_count == 0:
        return ThreatScopeSemanticState.not_evaluated
    if challenged_count < applicable_count:
        return ThreatScopeSemanticState.gap_observed
    return ThreatScopeSemanticState.all_applicable_challenged


def gate_state_for_effects(effects: tuple[GateEffect, ...]) -> GateState:
    if GateEffect.block in effects:
        return GateState.fail
    if GateEffect.review in effects:
        return GateState.warn
    return GateState.pass_


def control_efficacy_gate_finding_subjects(
    report: ControlEfficacyReport,
) -> tuple[
    tuple[
        ControlEfficacyGateReason,
        tuple[MachineIdentifier, ...],
        tuple[MachineIdentifier, ...],
    ],
    ...,
]:
    """Return every report-backed finding subject in canonical reason order."""
    protected_survivors = set(report.required_survivor_operator_ids) | set(
        report.critical_survivor_operator_ids
    )
    remaining_survivors = tuple(
        outcome.operator_id
        for outcome in report.operator_outcomes
        if outcome.state is MutationResultState.survived
        and outcome.operator_id not in protected_survivors
    )
    applicable_uncovered = tuple(
        item.threat_id
        for item in report.threat_coverage
        if item.applicability is ThreatApplicability.applicable
        and not item.critical
        and not item.challenged
    )
    subjects = {
        ControlEfficacyGateReason.required_operator_survived: (
            report.required_survivor_operator_ids,
            (),
        ),
        ControlEfficacyGateReason.critical_operator_survived: (
            report.critical_survivor_operator_ids,
            (),
        ),
        ControlEfficacyGateReason.applicable_operator_survived: (
            remaining_survivors,
            (),
        ),
        ControlEfficacyGateReason.critical_threat_uncovered: (
            (),
            report.critical_uncovered_threat_ids,
        ),
        ControlEfficacyGateReason.applicable_threat_uncovered: (
            (),
            applicable_uncovered,
        ),
        ControlEfficacyGateReason.invalid_or_error_operator: (
            report.invalid_or_error_operator_ids,
            (),
        ),
        ControlEfficacyGateReason.required_operator_not_evaluated: (
            report.required_not_evaluated_operator_ids,
            (),
        ),
        ControlEfficacyGateReason.unknown_threat_applicability: (
            (),
            report.unknown_applicability_threat_ids,
        ),
        ControlEfficacyGateReason.unscoped_catalog_threat_reference: (
            (),
            report.unscoped_catalog_threat_ids,
        ),
    }
    return tuple(
        (reason, *subjects[reason])
        for reason in CONTROL_EFFICACY_GATE_REASON_ORDER
        if any(subjects[reason])
    )


def derive_control_efficacy_gate_decision(
    report: ControlEfficacyReport,
    profile: ControlEfficacyGateProfile,
) -> ControlEfficacyGateDecision:
    """Derive the complete policy projection for a report and exact profile."""
    profile = ControlEfficacyGateProfile.model_validate(profile.model_dump(mode="json"))
    if profile.required_catalog != report.catalog_id:
        raise ValueError("gate profile required catalog does not match the report")
    if profile.required_operators != report.required_operator_ids:
        raise ValueError("gate profile required operators do not match the report scope")

    effects = {
        ControlEfficacyGateReason.required_operator_survived: (profile.surviving_required_operator),
        ControlEfficacyGateReason.critical_operator_survived: (profile.surviving_critical_operator),
        ControlEfficacyGateReason.applicable_operator_survived: (
            profile.surviving_applicable_operator
        ),
        ControlEfficacyGateReason.critical_threat_uncovered: (profile.critical_threat_uncovered),
        ControlEfficacyGateReason.applicable_threat_uncovered: (
            profile.applicable_threat_uncovered
        ),
        ControlEfficacyGateReason.invalid_or_error_operator: (profile.invalid_or_error_operator),
        ControlEfficacyGateReason.required_operator_not_evaluated: (
            profile.unevaluated_required_operator
        ),
        ControlEfficacyGateReason.unknown_threat_applicability: (
            profile.unknown_threat_applicability
        ),
        ControlEfficacyGateReason.unscoped_catalog_threat_reference: (
            profile.unscoped_catalog_threat_reference
        ),
    }
    finding_tuple = tuple(
        ControlEfficacyGateFinding(
            reason_code=reason,
            effect=effects[reason],
            operator_ids=operator_ids,
            threat_ids=threat_ids,
        )
        for reason, operator_ids, threat_ids in control_efficacy_gate_finding_subjects(report)
    )
    return ControlEfficacyGateDecision(
        report_digest=report.report_digest,
        profile_id=profile.profile_id,
        state=gate_state_for_effects(tuple(item.effect for item in finding_tuple)),
        findings=finding_tuple,
    )
