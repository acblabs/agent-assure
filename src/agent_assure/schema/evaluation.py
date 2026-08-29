from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import SCHEMA_VERSION, FrozenStrictModel, PersistedArtifact
from agent_assure.schema.common import (
    MAX_LABEL_CHARS,
    MAX_SUMMARY_CHARS,
    V063_CONTRACT_SCHEMA_VERSIONS,
    DigestHex,
    GateState,
    ReasonCode,
    Severity,
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
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)

_EVALUATION_SUMMARY_USAGE_FIELD_PATHS = (("usage_summary",),)
MAX_WAIVER_DISPOSITIONS = 4096
_EVALUATION_SUMMARY_JSON_SCHEMA_EXTRA = usage_container_json_schema_extra(
    *_EVALUATION_SUMMARY_USAGE_FIELD_PATHS
)
_EVALUATION_SUMMARY_JSON_SCHEMA_EXTRA["allOf"].extend(
    current_non_empty_fields_json_schema_extra("runset_id")["allOf"]
)
_EVALUATION_SUMMARY_JSON_SCHEMA_EXTRA["allOf"].append(
    {
        "if": {
            "required": ["schema_version"],
            "properties": {"schema_version": {"const": SCHEMA_VERSION}},
        },
        "then": {
            "required": ["runset_digest"],
            "properties": {"runset_digest": {"type": "string"}},
        },
    }
)


class WaiverDispositionStatus(StrEnum):
    matched = "matched"
    unmatched_artifact = "unmatched_artifact"
    unmatched_finding = "unmatched_finding"
    unmatched_reason = "unmatched_reason"
    expired = "expired"


class WaiverDisposition(FrozenStrictModel):
    """Privacy-minimized audit projection for one supplied waiver."""

    waiver_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    status: WaiverDispositionStatus
    reason_code: ReasonCode
    finding_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    expires_on: date

    @field_validator("status", mode="before")
    @classmethod
    def _coerce_status(cls, value: object) -> WaiverDispositionStatus:
        return coerce_enum(WaiverDispositionStatus, value)

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)

    @field_validator("expires_on", mode="before")
    @classmethod
    def _coerce_expires_on(cls, value: object) -> date:
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            return date.fromisoformat(value)
        raise ValueError("expires_on must be an ISO date")


class EvaluationGateProfileContext(FrozenStrictModel):
    """Complete scoring-relevant GateProfile projection for deterministic replay."""

    profile_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    fail_severities: tuple[Severity, ...] = Field(max_length=len(Severity))
    fail_reason_codes: tuple[ReasonCode, ...] = Field(max_length=len(ReasonCode))
    fail_on_warn: bool
    fail_on_not_evaluated: bool

    @field_validator("fail_severities", mode="before")
    @classmethod
    def _coerce_severities(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            values = tuple(coerce_enum(Severity, item) for item in value)
            return tuple(sorted(set(values), key=lambda item: item.value))
        return coerce_tuple(value)

    @field_validator("fail_reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            values = tuple(coerce_enum(ReasonCode, item) for item in value)
            return tuple(sorted(set(values), key=lambda item: item.value))
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _require_fail_filter(self) -> EvaluationGateProfileContext:
        if not self.fail_severities and not self.fail_reason_codes:
            raise ValueError(
                "evaluation replay gate profile requires at least one fail filter"
            )
        return self


class EvaluationWaiverContext(FrozenStrictModel):
    """Privacy-minimized waiver fields that can affect evaluation semantics."""

    waiver_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    reason_code: ReasonCode
    finding_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    artifact_digest: DigestHex
    expires_on: date

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)

    @field_validator("expires_on", mode="before")
    @classmethod
    def _coerce_expires_on(cls, value: object) -> date:
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            return date.fromisoformat(value)
        raise ValueError("expires_on must be an ISO date")


class EvaluationReplayContext(FrozenStrictModel):
    """Authenticated, scoring-complete inputs for exact evaluation replay."""

    suite_digest: DigestHex
    gate_profile: EvaluationGateProfileContext
    waivers: tuple[EvaluationWaiverContext, ...] = Field(
        default=(),
        max_length=MAX_WAIVER_DISPOSITIONS,
    )
    evaluation_date: date
    report_mode: Literal["full", "fail-fast"] = "full"

    @field_validator("waivers", mode="before")
    @classmethod
    def _coerce_waivers(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("evaluation_date", mode="before")
    @classmethod
    def _coerce_evaluation_date(cls, value: object) -> date:
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            return date.fromisoformat(value)
        raise ValueError("evaluation_date must be an ISO date")


class Finding(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=current_non_empty_fields_json_schema_extra("finding_id")
    )

    artifact_kind: Literal["finding"] = "finding"
    finding_id: str
    case_id: str
    control_id: str = ""
    target: str = ""
    state: GateState
    reason_code: ReasonCode
    message: str = Field(max_length=MAX_SUMMARY_CHARS)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)

    @model_validator(mode="after")
    def _require_current_identity(self) -> Finding:
        if self.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not self.finding_id:
            raise ValueError("current findings require a non-empty finding_id")
        return self


def evaluation_summary_coherence_error(
    *,
    state: GateState,
    findings: tuple[Finding, ...],
) -> str | None:
    """Return an error when finding verdicts contradict the summary verdict."""
    finding_states = {finding.state for finding in findings}
    if GateState.pass_ in finding_states:
        return "evaluation summaries must not carry pass-state findings"
    if not finding_states:
        return None
    if GateState.fail in finding_states:
        expected = GateState.fail
    elif GateState.warn in finding_states:
        expected = GateState.warn
    elif GateState.not_evaluated in finding_states:
        expected = GateState.not_evaluated
    else:
        return "evaluation summaries contain unsupported finding states"
    if state is not expected:
        return (
            f"evaluation summary state {state.value!r} contradicts "
            f"finding-derived state {expected.value!r}"
        )
    return None


class EvaluationSummary(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=privacy_profile_json_schema_extra(_EVALUATION_SUMMARY_JSON_SCHEMA_EXTRA)
    )

    artifact_kind: Literal["evaluation-summary"] = "evaluation-summary"
    runset_id: str
    runset_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "Canonical digest of the evaluated RunSet when the producer can authenticate "
            "that source identity. The first-party evaluator emits it so packet graph "
            "evidence can share one authenticated run-set subject."
        ),
    )
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
    replay_context: EvaluationReplayContext | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "Scoring-relevant suite, gate-profile, waiver, date, and report-mode "
            "inputs emitted by the first-party evaluator for exact source replay."
        ),
    )

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
    def _require_current_runset_identity(self) -> EvaluationSummary:
        if self.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not self.runset_id:
            raise ValueError("current evaluation summaries require a non-empty runset_id")
        if self.schema_version == SCHEMA_VERSION and self.runset_digest is None:
            raise ValueError(
                "current evaluation summaries require an authenticated runset_digest"
            )
        return self

    @model_validator(mode="after")
    def _validate_state_finding_coherence(self) -> EvaluationSummary:
        if self.schema_version not in V063_CONTRACT_SCHEMA_VERSIONS:
            return self
        error = evaluation_summary_coherence_error(
            state=self.state,
            findings=self.findings,
        )
        if error is not None:
            raise ValueError(error)
        return self

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
