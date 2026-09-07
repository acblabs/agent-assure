from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact
from agent_assure.schema.common import (
    V063_CONTRACT_SCHEMA_VERSIONS,
    ComparisonClassification,
    DigestHex,
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

if TYPE_CHECKING:
    from agent_assure.schema.evaluation import EvaluationSummary

_COMPARISON_SUMMARY_USAGE_FIELD_PATHS = (
    ("baseline_usage_summary",),
    ("candidate_usage_summary",),
    ("usage_delta",),
)

# v0.6.4 introduces authenticated identities for both compared RunSets. Keep
# the governed versions explicit so advancing the current writer cannot
# silently weaken the pinned v0.6.4 model contract.
_COMPARISON_DIGEST_CONTRACT_SCHEMA_VERSIONS = ("0.6.4", "0.6.5", "0.6.6")
_COMPARISON_SUMMARY_JSON_SCHEMA_EXTRA = usage_container_json_schema_extra(
    *_COMPARISON_SUMMARY_USAGE_FIELD_PATHS
)
_COMPARISON_SUMMARY_JSON_SCHEMA_EXTRA["allOf"].extend(
    current_non_empty_fields_json_schema_extra(
        "baseline_runset_id",
        "candidate_runset_id",
    )["allOf"]
)
_COMPARISON_SUMMARY_JSON_SCHEMA_EXTRA["allOf"].append(
    {
        "if": {
            "required": ["schema_version"],
            "properties": {"schema_version": {"const": SCHEMA_VERSION}},
        },
        "then": {
            "required": ["baseline_runset_digest", "candidate_runset_digest"],
            "properties": {
                "baseline_runset_digest": {"type": "string"},
                "candidate_runset_digest": {"type": "string"},
            },
        },
    }
)


class ComparisonSummary(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=privacy_profile_json_schema_extra(_COMPARISON_SUMMARY_JSON_SCHEMA_EXTRA)
    )

    artifact_kind: Literal["comparison-summary"] = "comparison-summary"
    baseline_runset_id: str
    candidate_runset_id: str
    baseline_runset_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "Canonical digest of the baseline RunSet. Required by the v0.6.4 "
            "comparison contract and omitted only when projecting compatible older summaries."
        ),
    )
    candidate_runset_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "Canonical digest of the candidate RunSet. Required by the v0.6.4 "
            "comparison contract and omitted only when projecting compatible older summaries."
        ),
    )
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
        if self.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and (
            not self.baseline_runset_id or not self.candidate_runset_id
        ):
            raise ValueError(
                "current comparison summaries require non-empty baseline and candidate runset IDs"
            )
        has_baseline_digest = self.baseline_runset_digest is not None
        has_candidate_digest = self.candidate_runset_digest is not None
        if self.schema_version not in _COMPARISON_DIGEST_CONTRACT_SCHEMA_VERSIONS and (
            has_baseline_digest or has_candidate_digest
        ):
            raise ValueError(
                f"comparison summary schema version {self.schema_version!r} does not support "
                "authenticated RunSet digests"
            )
        if has_baseline_digest != has_candidate_digest:
            raise ValueError(
                "comparison summary RunSet digests must either both be present or both be absent"
            )
        if (
            self.schema_version in _COMPARISON_DIGEST_CONTRACT_SCHEMA_VERSIONS
            and self.baseline_runset_digest is None
        ):
            raise ValueError(
                f"comparison summaries at schema_version={self.schema_version} require "
                "authenticated baseline and candidate RunSet digests"
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


def comparison_evaluation_binding_error(
    comparison: ComparisonSummary,
    evaluation: EvaluationSummary,
    *,
    role: Literal["baseline", "candidate"],
) -> str | None:
    """Return an error for contradictory comparison/evaluation RunSet identities.

    RunSet digests remain optional on independently produced and legacy
    evaluation summaries. Once a comparison carries an authenticated digest,
    however, pairing it with an unbound evaluation would silently downgrade the
    comparison identity to its human-readable ID. Such pairs are rejected.
    """
    comparison_runset_id = (
        comparison.baseline_runset_id if role == "baseline" else comparison.candidate_runset_id
    )
    comparison_runset_digest = (
        comparison.baseline_runset_digest
        if role == "baseline"
        else comparison.candidate_runset_digest
    )
    if comparison_runset_id != evaluation.runset_id:
        return f"comparison {role}_runset_id must match evaluation runset_id"
    if comparison_runset_digest is not None and evaluation.runset_digest is None:
        return f"comparison {role}_runset_digest requires an authenticated evaluation runset_digest"
    if (
        comparison_runset_digest is not None
        and comparison_runset_digest != evaluation.runset_digest
    ):
        return f"comparison {role}_runset_digest must match evaluation runset_digest"
    return None
