from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact
from agent_assure.schema.common import (
    ComparisonClassification,
    GateState,
    coerce_enum,
    coerce_tuple,
    current_non_empty_fields_json_schema_extra,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.privacy import (
    PrivacyProfileDigest,
    PrivacyProfileId,
    prepare_privacy_profile_input,
    privacy_profile_json_schema_extra,
    validate_privacy_profile_binding,
)
from agent_assure.schema.usage import (
    UsageSummary,
    UsageSummaryDelta,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)

_COMPARISON_SUMMARY_USAGE_FIELD_PATHS = (
    ("baseline_usage_summary",),
    ("candidate_usage_summary",),
    ("usage_delta",),
)
_COMPARISON_SUMMARY_JSON_SCHEMA_EXTRA = usage_container_json_schema_extra(
    *_COMPARISON_SUMMARY_USAGE_FIELD_PATHS
)
_COMPARISON_SUMMARY_JSON_SCHEMA_EXTRA["allOf"].extend(
    current_non_empty_fields_json_schema_extra(
        "baseline_runset_id",
        "candidate_runset_id",
    )["allOf"]
)


class ComparisonSummary(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=privacy_profile_json_schema_extra(_COMPARISON_SUMMARY_JSON_SCHEMA_EXTRA)
    )

    artifact_kind: Literal["comparison-summary"] = "comparison-summary"
    baseline_runset_id: str
    candidate_runset_id: str
    privacy_profile_id: PrivacyProfileId = Field(
        exclude_if=lambda value: value is None,
    )
    privacy_profile_digest: PrivacyProfileDigest = Field(
        exclude_if=lambda value: value is None,
    )
    classification: ComparisonClassification
    fixture_equivalence_state: GateState = GateState.not_evaluated
    baseline_state: GateState = GateState.not_evaluated
    candidate_state: GateState = GateState.not_evaluated
    provenance_changes: tuple[str, ...] = ()
    verdict_findings: tuple[str, ...] = ()
    environment: EnvironmentInfo | None = None
    baseline_usage_summary: UsageSummary | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    candidate_usage_summary: UsageSummary | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    usage_delta: UsageSummaryDelta | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="before")
    @classmethod
    def _prepare_privacy_profile(cls, value: object) -> object:
        return prepare_privacy_profile_input(value, owner="comparison summary")

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
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @model_validator(mode="after")
    def _require_current_runset_identities(self) -> ComparisonSummary:
        if self.schema_version == SCHEMA_VERSION and (
            not self.baseline_runset_id or not self.candidate_runset_id
        ):
            raise ValueError(
                "current comparison summaries require non-empty baseline and candidate runset IDs"
            )
        return self

    @field_validator("provenance_changes", "verdict_findings", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> ComparisonSummary:
        validate_privacy_profile_binding(
            self.schema_version,
            self.privacy_profile_id,
            self.privacy_profile_digest,
            owner="comparison summary",
        )
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="comparison summary",
            root=self,
            field_paths=_COMPARISON_SUMMARY_USAGE_FIELD_PATHS,
        )
        return self
