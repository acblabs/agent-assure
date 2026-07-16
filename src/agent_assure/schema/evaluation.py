from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import GateState, ReasonCode, coerce_enum, coerce_tuple
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
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)

_EVALUATION_SUMMARY_USAGE_FIELD_PATHS = (("usage_summary",),)


class Finding(PersistedArtifact):
    artifact_kind: Literal["finding"] = "finding"
    finding_id: str
    case_id: str
    control_id: str = ""
    target: str = ""
    state: GateState
    reason_code: ReasonCode
    message: str

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)


class EvaluationSummary(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=privacy_profile_json_schema_extra(
            usage_container_json_schema_extra(*_EVALUATION_SUMMARY_USAGE_FIELD_PATHS)
        )
    )

    artifact_kind: Literal["evaluation-summary"] = "evaluation-summary"
    runset_id: str
    privacy_profile_id: PrivacyProfileId = Field(
        exclude_if=lambda value: value is None,
    )
    privacy_profile_digest: PrivacyProfileDigest = Field(
        exclude_if=lambda value: value is None,
    )
    state: GateState
    findings: tuple[Finding, ...] = ()
    environment: EnvironmentInfo | None = None
    usage_summary: UsageSummary | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="before")
    @classmethod
    def _prepare_privacy_profile(cls, value: object) -> object:
        return prepare_privacy_profile_input(value, owner="evaluation summary")

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("findings", mode="before")
    @classmethod
    def _coerce_findings(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> EvaluationSummary:
        validate_privacy_profile_binding(
            self.schema_version,
            self.privacy_profile_id,
            self.privacy_profile_digest,
            owner="evaluation summary",
        )
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="evaluation summary",
            root=self,
            field_paths=_EVALUATION_SUMMARY_USAGE_FIELD_PATHS,
        )
        return self
