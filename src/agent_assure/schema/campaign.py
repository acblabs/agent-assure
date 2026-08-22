from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from agent_assure.schema.base import FrozenStrictModel
from agent_assure.schema.common import (
    PACKAGE_RELEASE_VERSION_PATTERN,
    DigestHex,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.mutation import (
    AssuranceMutationOperator,
    AssuranceMutationResult,
    BoundedSummary,
    ExpectedDetectionContract,
    MachineIdentifier,
    MutationResultState,
    SelfDigestedArtifact,
    finding_target_digest,
)

CORE_MUTATION_CATALOG_ID: Literal["core/v1"] = "core/v1"
CORE_MUTATION_CATALOG_ORDERING: Literal["operator-id-lexicographic/v1"] = (
    "operator-id-lexicographic/v1"
)
MAX_CAMPAIGN_OPERATORS = 256
CORE_MUTATION_OPERATOR_IDS = (
    "bypass-required-human-review",
    "drop-material-evidence-link",
    "inject-forbidden-tool",
    "inject-synthetic-sensitive-summary",
    "mark-incomplete-budget-stop",
    "replay-duplicate-case-observation",
    "skew-evidence-source-identity",
)
CORE_MUTATION_OPERATOR_COUNT = len(CORE_MUTATION_OPERATOR_IDS)


def _core_catalog_json_schema_extra(schema: dict[str, Any]) -> None:
    schema["$comment"] = (
        "core/v1 is a closed catalog. JSON Schema fixes each operator ID in "
        "canonical order; runtime validation additionally enforces relational "
        "digest, provenance, and ordering constraints."
    )
    schema.setdefault("allOf", []).append(
        {
            "properties": {
                "operators": {
                    "prefixItems": [
                        {
                            "required": ["descriptor"],
                            "properties": {
                                "descriptor": {
                                    "required": ["operator_id"],
                                    "properties": {"operator_id": {"const": operator_id}},
                                }
                            },
                        }
                        for operator_id in CORE_MUTATION_OPERATOR_IDS
                    ]
                }
            }
        }
    )


class MutationCampaignMode(StrEnum):
    full_report = "full_report"
    fail_fast = "fail_fast"


class MutationCampaignCompletion(StrEnum):
    complete = "complete"
    stopped_early = "stopped_early"


class MutationApplicability(StrEnum):
    applicable = "applicable"
    inapplicable = "inapplicable"
    not_evaluated = "not_evaluated"


FAIL_FAST_MUTATION_STATES = frozenset(
    {
        MutationResultState.survived,
        MutationResultState.invalid_operator,
        MutationResultState.invalid_subject,
        MutationResultState.execution_error,
    }
)
# These diagnostics occur only after target selection established that an
# operator applies. ``operator_mutated_source`` is deliberately absent: it is
# detected during target resolution, whose output is untrustworthy after the
# operator violates source immutability, so applicability remains not_evaluated.
_APPLICABLE_DIAGNOSTIC_CODES = frozenset(
    {
        "candidate_evaluation_error",
        "confounded_operator_output",
        "invalid_operator_evaluation",
        "operator_output_application_error",
        "operator_output_noop",
        "operator_output_not_canonical",
        "operator_output_path_invalid",
        "operator_output_path_undeclared",
        "operator_output_privacy_violation",
        "operator_output_schema_invalid",
        "operator_target_not_evaluable",
        "result_construction_error",
    }
)


def mutation_result_applicability(
    result: AssuranceMutationResult,
) -> MutationApplicability:
    """Project one mutation result to its canonical applicability state."""
    if result.state is MutationResultState.inapplicable:
        return MutationApplicability.inapplicable
    if result.state in {
        MutationResultState.caught,
        MutationResultState.survived,
    }:
        return MutationApplicability.applicable
    if result.state is MutationResultState.invalid_subject:
        return MutationApplicability.not_evaluated
    if result.diagnostic_code in _APPLICABLE_DIAGNOSTIC_CODES:
        return MutationApplicability.applicable
    return MutationApplicability.not_evaluated


class MutationCatalogOperator(FrozenStrictModel):
    descriptor: AssuranceMutationOperator
    invariant_family: MachineIdentifier
    threat_source_references: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=32,
    )
    stable: Literal[True] = True

    @field_validator("threat_source_references", mode="before")
    @classmethod
    def _coerce_threat_source_references(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_catalog_metadata(self) -> MutationCatalogOperator:
        if self.threat_source_references != tuple(sorted(set(self.threat_source_references))):
            raise ValueError(
                "operator threat-source references must be unique and canonically sorted"
            )
        return self


class AssuranceMutationCatalog(SelfDigestedArtifact):
    _digest_field = "catalog_digest"

    model_config = ConfigDict(json_schema_extra=_core_catalog_json_schema_extra)

    artifact_kind: Literal["assurance-mutation-catalog"] = "assurance-mutation-catalog"
    schema_version: Literal["0.6.1", "0.6.2", "0.6.3", "0.6.4"] = "0.6.4"
    schema_name: Literal["assurance-mutation-catalog"] = "assurance-mutation-catalog"
    contract_id: Literal["AssuranceMutationCatalog/v1"] = "AssuranceMutationCatalog/v1"
    contract_version: Literal["1.0.0"] = "1.0.0"
    catalog_digest: DigestHex
    catalog_id: Literal["core/v1"] = CORE_MUTATION_CATALOG_ID
    ordering_semantics: Literal["operator-id-lexicographic/v1"] = CORE_MUTATION_CATALOG_ORDERING
    operators: tuple[MutationCatalogOperator, ...] = Field(
        min_length=CORE_MUTATION_OPERATOR_COUNT,
        max_length=CORE_MUTATION_OPERATOR_COUNT,
    )
    limitations: tuple[BoundedSummary, ...] = Field(min_length=1, max_length=32)

    @field_validator("operators", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_operator_order(self) -> AssuranceMutationCatalog:
        if any(item.descriptor.schema_version != self.schema_version for item in self.operators):
            raise ValueError("catalog and nested operator schema versions must match")
        operator_ids = tuple(item.descriptor.operator_id for item in self.operators)
        if operator_ids != tuple(sorted(set(operator_ids))):
            raise ValueError(
                "catalog operators must have unique IDs in canonical lexicographic order"
            )
        if operator_ids != CORE_MUTATION_OPERATOR_IDS:
            raise ValueError(
                "core/v1 must contain exactly the closed canonical operator identities"
            )
        if len({item.invariant_family for item in self.operators}) < 6:
            raise ValueError("core/v1 must span at least six distinct invariant families")
        return self


class MutationCampaignOperatorResult(FrozenStrictModel):
    operator_id: MachineIdentifier
    invariant_family: MachineIdentifier
    seed: int = Field(ge=0, le=(1 << 53) - 1)
    applicability: MutationApplicability
    expected_detection_contract: ExpectedDetectionContract
    result: AssuranceMutationResult
    prohibited_substitute_finding_ids: tuple[MachineIdentifier, ...] = ()

    @field_validator("applicability", mode="before")
    @classmethod
    def _coerce_applicability(cls, value: object) -> MutationApplicability:
        return coerce_enum(MutationApplicability, value)

    @field_validator("prohibited_substitute_finding_ids", mode="before")
    @classmethod
    def _coerce_prohibited_finding_ids(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_result_binding(self) -> MutationCampaignOperatorResult:
        if (
            self.operator_id != self.result.operator_id
            or self.operator_id != self.expected_detection_contract.operator_id
        ):
            raise ValueError(
                "campaign entry operator, expected contract, and result IDs must match"
            )
        if self.seed != self.result.seed:
            raise ValueError("campaign entry seed must match its mutation result")
        if (
            self.expected_detection_contract.contract_digest
            != self.result.expected_detection_contract_digest
        ):
            raise ValueError(
                "campaign entry expected contract digest must match its mutation result"
            )

        prohibited_ids = self.prohibited_substitute_finding_ids
        if prohibited_ids != tuple(sorted(set(prohibited_ids))):
            raise ValueError(
                "prohibited substitute finding IDs must be unique and canonically sorted"
            )
        matching_prohibited_ids = tuple(
            sorted(
                finding.finding_id
                for finding in self.result.observed_findings
                if any(
                    finding.control_id == selector.control_id
                    and finding.reason_code is selector.reason_code
                    and (
                        selector.target is None
                        or finding.target_digest == finding_target_digest(selector.target)
                    )
                    for selector in (self.expected_detection_contract.prohibited_substitutes)
                )
            )
        )
        if prohibited_ids != matching_prohibited_ids:
            raise ValueError(
                "prohibited substitute finding IDs must identify every matching observed finding"
            )

        expected_applicability = mutation_result_applicability(self.result)
        if self.applicability is not expected_applicability:
            raise ValueError(
                "campaign entry applicability must match its canonical result projection"
            )
        return self


class AssuranceMutationCampaign(SelfDigestedArtifact):
    _digest_field = "campaign_digest"

    artifact_kind: Literal["assurance-mutation-campaign"] = "assurance-mutation-campaign"
    schema_version: Literal["0.6.1", "0.6.2", "0.6.3", "0.6.4"] = "0.6.4"
    schema_name: Literal["assurance-mutation-campaign"] = "assurance-mutation-campaign"
    contract_id: Literal["AssuranceMutationCampaign/v1"] = "AssuranceMutationCampaign/v1"
    contract_version: Literal["1.0.0"] = "1.0.0"
    campaign_digest: DigestHex
    source_artifact_kind: Literal["run-set"] = "run-set"
    source_digest: DigestHex
    suite_digest: DigestHex
    catalog_id: MachineIdentifier
    catalog_digest: DigestHex
    producer_version: str = Field(pattern=PACKAGE_RELEASE_VERSION_PATTERN)
    mode: MutationCampaignMode
    completion: MutationCampaignCompletion
    campaign_seed: int = Field(ge=0, le=(1 << 53) - 1)
    canonical_operator_order: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_CAMPAIGN_OPERATORS,
    )
    selected_operator_order: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_CAMPAIGN_OPERATORS,
    )
    executed_operator_order: tuple[MachineIdentifier, ...] = Field(
        min_length=1,
        max_length=MAX_CAMPAIGN_OPERATORS,
    )
    pending_operator_order: tuple[MachineIdentifier, ...] = Field(
        default=(),
        max_length=MAX_CAMPAIGN_OPERATORS,
    )
    operator_results: tuple[MutationCampaignOperatorResult, ...] = Field(
        min_length=1,
        max_length=MAX_CAMPAIGN_OPERATORS,
    )
    limitations: tuple[BoundedSummary, ...] = Field(min_length=1, max_length=32)

    @field_validator("mode", mode="before")
    @classmethod
    def _coerce_mode(cls, value: object) -> MutationCampaignMode:
        return coerce_enum(MutationCampaignMode, value)

    @field_validator("completion", mode="before")
    @classmethod
    def _coerce_completion(cls, value: object) -> MutationCampaignCompletion:
        return coerce_enum(MutationCampaignCompletion, value)

    @field_validator(
        "canonical_operator_order",
        "selected_operator_order",
        "executed_operator_order",
        "pending_operator_order",
        "operator_results",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_campaign_order_and_bindings(self) -> AssuranceMutationCampaign:
        canonical = self.canonical_operator_order
        selected = self.selected_operator_order
        executed = self.executed_operator_order
        pending = self.pending_operator_order
        if canonical != tuple(sorted(set(canonical))):
            raise ValueError("canonical operator order must be unique and lexicographic")
        selected_ids = set(selected)
        if len(selected_ids) != len(selected):
            raise ValueError("selected operator IDs must be unique")
        if selected != tuple(
            operator_id for operator_id in canonical if operator_id in selected_ids
        ):
            raise ValueError("selected operator order must be a canonical catalog subsequence")
        if (*executed, *pending) != selected:
            raise ValueError(
                "executed and pending operator order must partition the selected order"
            )
        result_ids = tuple(item.operator_id for item in self.operator_results)
        if result_ids != executed:
            raise ValueError("campaign result order must match executed operator order")
        if any(item.seed != self.campaign_seed for item in self.operator_results):
            raise ValueError("every v1 campaign entry must use the declared campaign seed")
        for item in self.operator_results:
            if (
                item.expected_detection_contract.schema_version != self.schema_version
                or item.result.schema_version != self.schema_version
            ):
                raise ValueError("campaign and nested contract/result schema versions must match")
            result_source_digest = item.result.source_digest
            if result_source_digest is not None and result_source_digest != self.source_digest:
                raise ValueError(
                    "every campaign operator must execute against the same source digest"
                )
        if self.completion is MutationCampaignCompletion.complete and pending:
            raise ValueError("complete campaigns cannot have pending operators")
        if self.completion is MutationCampaignCompletion.stopped_early and not pending:
            raise ValueError("stopped campaigns must identify pending operators")
        if (
            self.mode is MutationCampaignMode.full_report
            and self.completion is not MutationCampaignCompletion.complete
        ):
            raise ValueError("full-report campaigns must execute every selected operator")
        if self.mode is MutationCampaignMode.fail_fast:
            if any(
                item.result.state in FAIL_FAST_MUTATION_STATES
                for item in self.operator_results[:-1]
            ):
                raise ValueError("fail-fast campaigns cannot continue after a stopping result")
            if pending and self.operator_results[-1].result.state not in FAIL_FAST_MUTATION_STATES:
                raise ValueError("stopped fail-fast campaigns must end with a stopping result")
        return self
