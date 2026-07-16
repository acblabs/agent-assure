from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    MAX_LABEL_CHARS,
    MAX_SUMMARY_CHARS,
    DigestHex,
    ExecutionMode,
    GateState,
    ReasonCode,
    Severity,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.privacy import (
    PrivacyProfileDigest,
    PrivacyProfileId,
    prepare_privacy_profile_input,
    privacy_profile_json_schema_extra,
    validate_privacy_profile_binding,
)
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.runtime import EmergencyProcessRecord
from agent_assure.schema.usage import (
    UsageLedger,
    UsageSummary,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
    validate_usage_summary_consistency,
)
from agent_assure.telemetry.context import TRACEPARENT_FIELD_PATTERN, validate_traceparent

_RUN_RECORD_USAGE_FIELD_PATHS = (
    ("usage_ledger",),
    ("usage_summary",),
)
_RUN_SET_USAGE_FIELD_PATHS = (
    ("usage_ledger",),
    ("usage_summary",),
    ("runs", "*", "usage_ledger"),
    ("runs", "*", "usage_summary"),
)


class EvidenceRef(PersistedArtifact):
    artifact_kind: Literal["evidence-ref"] = "evidence-ref"
    ref_id: str
    source_id: str
    claim_ids: tuple[str, ...] = ()

    @field_validator("claim_ids", mode="before")
    @classmethod
    def _coerce_claim_ids(cls, value: object) -> object:
        return coerce_tuple(value)


class EvidenceItem(PersistedArtifact):
    artifact_kind: Literal["evidence-item"] = "evidence-item"
    ref_id: str
    source_id: str
    content_digest: DigestHex


class ClaimRecord(PersistedArtifact):
    artifact_kind: Literal["claim-record"] = "claim-record"
    claim_id: str


class ClaimEvidenceLink(PersistedArtifact):
    artifact_kind: Literal["claim-evidence-link"] = "claim-evidence-link"
    claim_id: str
    evidence_ref_id: str


class PolicyResult(PersistedArtifact):
    artifact_kind: Literal["policy-result"] = "policy-result"
    policy_id: str
    state: GateState
    reason_codes: tuple[ReasonCode, ...] = ()
    severity: Severity = Severity.info
    gate_profile: str = Field(default="default", max_length=MAX_LABEL_CHARS)
    message: str = Field(default="", max_length=MAX_SUMMARY_CHARS)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("severity", mode="before")
    @classmethod
    def _coerce_severity(cls, value: object) -> Severity:
        return coerce_enum(Severity, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value


class AgentRunRecord(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=usage_container_json_schema_extra(*_RUN_RECORD_USAGE_FIELD_PATHS)
    )

    artifact_kind: Literal["agent-run-record"] = "agent-run-record"
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    execution_mode: ExecutionMode = ExecutionMode.fixture
    pipeline_id: str = Field(min_length=1)
    recommendation: str = Field(max_length=MAX_LABEL_CHARS)
    outcome: str = Field(max_length=MAX_LABEL_CHARS)
    input_summary: str = Field(max_length=MAX_SUMMARY_CHARS)
    output_summary: str = Field(max_length=MAX_SUMMARY_CHARS)
    observation_status: Literal["included", "excluded"] = "included"
    observation_id: str | None = None
    repetition_index: int | None = Field(default=None, ge=0)
    schedule_index: int | None = Field(default=None, ge=0)
    randomization_block_id: str | None = None
    cluster_id: str | None = None
    source_group_id: str | None = None
    adapter_id: str | None = None
    provider: str | None = None
    model: str | None = None
    resolved_model: str | None = None
    provider_api_version: str | None = None
    provider_sdk: str | None = None
    provider_region: str | None = None
    provider_response_id: str | None = None
    traceparent: str | None = Field(default=None, pattern=TRACEPARENT_FIELD_PATTERN)
    tracestate: str | None = None
    started_at_utc: str | None = None
    completed_at_utc: str | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    attempt_count: int | None = Field(default=None, ge=1)
    retry_count: int | None = Field(default=None, ge=0)
    rate_limit_events: int | None = Field(default=None, ge=0)
    exclusion_reason: str | None = Field(default=None, max_length=MAX_SUMMARY_CHARS)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    estimated_cost_usd: str | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    estimated_cost_source: Literal[
        "adapter_reported",
        "local_estimate",
        "not_reported",
        "provider_reported",
    ] | None = None
    tools: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    evidence_items: tuple[EvidenceItem, ...] = ()
    claims: tuple[ClaimRecord, ...] = ()
    claim_evidence_links: tuple[ClaimEvidenceLink, ...] = ()
    policy_results: tuple[PolicyResult, ...] = ()
    human_review_required: bool = False
    human_review_performed: bool = False
    usage_ledger: UsageLedger | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    usage_summary: UsageSummary | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    provenance: Provenance = Provenance()

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _coerce_execution_mode(cls, value: object) -> ExecutionMode:
        return coerce_enum(ExecutionMode, value)

    @field_validator(
        "tools",
        "evidence_refs",
        "evidence_items",
        "claims",
        "claim_evidence_links",
        "policy_results",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("traceparent")
    @classmethod
    def _validate_traceparent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_traceparent(value)

    @model_validator(mode="after")
    def _validate_live_metadata(self) -> AgentRunRecord:
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="run record",
            root=self,
            field_paths=_RUN_RECORD_USAGE_FIELD_PATHS,
        )
        validate_usage_summary_consistency(
            self.usage_ledger,
            self.usage_summary,
            owner="run record",
        )
        if self.execution_mode is ExecutionMode.fixture:
            return self
        missing = [
            field_name
            for field_name in (
                "observation_id",
                "repetition_index",
                "schedule_index",
                "adapter_id",
                "cluster_id",
            )
            if getattr(self, field_name) is None
        ]
        if missing:
            raise ValueError("live run records require: " + ", ".join(missing))
        if self.observation_status == "excluded" and not self.exclusion_reason:
            raise ValueError("excluded live run records require exclusion_reason")
        if self.total_tokens is not None:
            component_total = (self.prompt_tokens or 0) + (self.completion_tokens or 0)
            if component_total and component_total != self.total_tokens:
                raise ValueError("total_tokens must equal prompt_tokens + completion_tokens")
        return self


class RunSet(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=privacy_profile_json_schema_extra(
            usage_container_json_schema_extra(*_RUN_SET_USAGE_FIELD_PATHS)
        )
    )

    artifact_kind: Literal["run-set"] = "run-set"
    runset_id: str
    privacy_profile_id: PrivacyProfileId = Field(
        exclude_if=lambda value: value is None,
    )
    privacy_profile_digest: PrivacyProfileDigest = Field(
        exclude_if=lambda value: value is None,
    )
    suite_id: str
    suite_version: str
    suite_digest: DigestHex
    fixture_manifest_digest: DigestHex
    execution_mode: ExecutionMode = ExecutionMode.fixture
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    completion_status: Literal["complete", "incomplete"] = "complete"
    stop_reasons: tuple[str, ...] = ()
    emergency_records: tuple[EmergencyProcessRecord, ...] = Field(
        default=(),
        exclude_if=lambda value: len(value) == 0,
    )
    usage_ledger: UsageLedger | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    usage_summary: UsageSummary | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    runs: tuple[AgentRunRecord, ...]

    @model_validator(mode="before")
    @classmethod
    def _prepare_privacy_profile(cls, value: object) -> object:
        return prepare_privacy_profile_input(value, owner="run set")

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _coerce_execution_mode(cls, value: object) -> ExecutionMode:
        return coerce_enum(ExecutionMode, value)

    @field_validator("runs", "stop_reasons", "emergency_records", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_live_protocol_binding(self) -> RunSet:
        validate_privacy_profile_binding(
            self.schema_version,
            self.privacy_profile_id,
            self.privacy_profile_digest,
            owner="run set",
        )
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="run set",
            root=self,
            field_paths=_RUN_SET_USAGE_FIELD_PATHS,
        )
        validate_usage_summary_consistency(
            self.usage_ledger,
            self.usage_summary,
            owner="run set",
        )
        if self.execution_mode is not ExecutionMode.live:
            return self
        missing = [
            field_name
            for field_name in ("protocol_id", "protocol_digest")
            if getattr(self, field_name) is None
        ]
        if missing:
            raise ValueError("live run sets require: " + ", ".join(missing))
        if self.completion_status == "incomplete" and not self.stop_reasons:
            raise ValueError("incomplete live run sets require stop_reasons")
        for run in self.runs:
            if run.execution_mode is not ExecutionMode.live:
                raise ValueError("live run sets may contain only live run records")
        return self
