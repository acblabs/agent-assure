from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_SCHEMA_VERSIONS,
    MAX_LABEL_CHARS,
    MAX_SUMMARY_CHARS,
    STRICT_RFC3339_TIMESTAMP_PATTERN,
    V063_CONTRACT_SCHEMA_VERSIONS,
    DigestHex,
    ExecutionMode,
    GateState,
    ReasonCode,
    Severity,
    coerce_enum,
    coerce_tuple,
    current_machine_identifier_json_schema_extra,
    current_non_empty_fields_json_schema_extra,
    validate_machine_identifier,
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
from agent_assure.telemetry.context import (
    TRACEPARENT_FIELD_PATTERN,
    validate_traceparent,
    validate_tracestate,
)

_RUN_RECORD_USAGE_FIELD_PATHS = (
    ("usage_ledger",),
    ("usage_summary",),
)
_BUDGET_COMMITMENT_SCHEMA_VERSIONS = frozenset(
    {"0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5"}
)
_EVIDENCE_SENSITIVITY_DESIGN_SCHEMA_VERSIONS = frozenset({"0.6.5"})
_RUN_RECORD_JSON_SCHEMA_EXTRA = usage_container_json_schema_extra(*_RUN_RECORD_USAGE_FIELD_PATHS)
_RUN_RECORD_JSON_SCHEMA_EXTRA["allOf"].append(
    {
        "if": {
            "required": ["schema_version", "execution_mode"],
            "properties": {
                "schema_version": {
                    "enum": sorted(_BUDGET_COMMITMENT_SCHEMA_VERSIONS),
                },
                "execution_mode": {"const": "live"},
            },
        },
        "then": {
            "required": [
                "cost_budget_committed_usd",
                "generated_token_budget_committed",
                "total_token_budget_committed",
            ],
            "properties": {
                "cost_budget_committed_usd": {"type": "string"},
                "generated_token_budget_committed": {"type": "integer"},
                "total_token_budget_committed": {"type": "integer"},
            },
        },
    }
)
_RUN_SET_USAGE_FIELD_PATHS = (
    ("usage_ledger",),
    ("usage_summary",),
    ("runs", "*", "usage_ledger"),
    ("runs", "*", "usage_summary"),
)
_RUN_SET_JSON_SCHEMA_EXTRA = usage_container_json_schema_extra(*_RUN_SET_USAGE_FIELD_PATHS)
_RUN_SET_JSON_SCHEMA_EXTRA["allOf"].extend(
    current_non_empty_fields_json_schema_extra("runset_id")["allOf"]
)
_EVIDENCE_GRAPH_MEMBER_FIELDS = (
    "evidence_refs",
    "evidence_items",
    "claims",
    "claim_evidence_links",
)
_RUN_RECORD_JSON_SCHEMA_EXTRA["allOf"].extend(
    {
        "if": {
            "required": ["schema_version"],
            "properties": {
                "schema_version": {"const": schema_version},
            },
        },
        "then": {
            "properties": {
                field_name: {
                    "items": {
                        "properties": {
                            "schema_version": {
                                "const": schema_version,
                            }
                        }
                    }
                }
                for field_name in _EVIDENCE_GRAPH_MEMBER_FIELDS
            }
        },
    }
    for schema_version in MACHINE_IDENTIFIER_SCHEMA_VERSIONS
)


class EvidenceRef(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=current_machine_identifier_json_schema_extra(
            scalar_fields=("ref_id", "source_id"),
            sequence_fields=("claim_ids",),
        )
    )

    artifact_kind: Literal["evidence-ref"] = "evidence-ref"
    ref_id: str
    source_id: str
    claim_ids: tuple[str, ...] = ()

    @field_validator("claim_ids", mode="before")
    @classmethod
    def _coerce_claim_ids(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_current_identifiers(self) -> EvidenceRef:
        if self.schema_version in MACHINE_IDENTIFIER_SCHEMA_VERSIONS:
            validate_machine_identifier(self.ref_id, field_name="ref_id")
            validate_machine_identifier(self.source_id, field_name="source_id")
            for index, claim_id in enumerate(self.claim_ids):
                validate_machine_identifier(
                    claim_id,
                    field_name=f"claim_ids[{index}]",
                )
        return self


class EvidenceItem(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=current_machine_identifier_json_schema_extra(
            scalar_fields=("ref_id", "source_id"),
        )
    )

    artifact_kind: Literal["evidence-item"] = "evidence-item"
    ref_id: str
    source_id: str
    content_digest: DigestHex

    @model_validator(mode="after")
    def _validate_current_identifiers(self) -> EvidenceItem:
        if self.schema_version in MACHINE_IDENTIFIER_SCHEMA_VERSIONS:
            validate_machine_identifier(self.ref_id, field_name="ref_id")
            validate_machine_identifier(self.source_id, field_name="source_id")
        return self


class ClaimRecord(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=current_machine_identifier_json_schema_extra(
            scalar_fields=("claim_id",),
        )
    )

    artifact_kind: Literal["claim-record"] = "claim-record"
    claim_id: str

    @model_validator(mode="after")
    def _validate_current_identifier(self) -> ClaimRecord:
        if self.schema_version in MACHINE_IDENTIFIER_SCHEMA_VERSIONS:
            validate_machine_identifier(self.claim_id, field_name="claim_id")
        return self


class ClaimEvidenceLink(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=current_machine_identifier_json_schema_extra(
            scalar_fields=("claim_id", "evidence_ref_id"),
        )
    )

    artifact_kind: Literal["claim-evidence-link"] = "claim-evidence-link"
    claim_id: str
    evidence_ref_id: str

    @model_validator(mode="after")
    def _validate_current_identifiers(self) -> ClaimEvidenceLink:
        if self.schema_version in MACHINE_IDENTIFIER_SCHEMA_VERSIONS:
            validate_machine_identifier(self.claim_id, field_name="claim_id")
            validate_machine_identifier(
                self.evidence_ref_id,
                field_name="evidence_ref_id",
            )
        return self


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
    model_config = ConfigDict(json_schema_extra=_RUN_RECORD_JSON_SCHEMA_EXTRA)

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
    started_at_utc: str | None = Field(
        default=None,
        max_length=MAX_LABEL_CHARS,
        pattern=STRICT_RFC3339_TIMESTAMP_PATTERN,
    )
    completed_at_utc: str | None = Field(
        default=None,
        max_length=MAX_LABEL_CHARS,
        pattern=STRICT_RFC3339_TIMESTAMP_PATTERN,
    )
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
    estimated_cost_source: (
        Literal[
            "adapter_reported",
            "local_estimate",
            "not_reported",
            "provider_reported",
        ]
        | None
    ) = None
    cost_budget_committed_usd: str | None = Field(
        default=None,
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
        exclude_if=lambda value: value is None,
    )
    generated_token_budget_committed: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    total_token_budget_committed: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
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

    @field_validator("tracestate")
    @classmethod
    def _validate_tracestate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_tracestate(value)

    @field_validator("run_id", "case_id", "pipeline_id")
    @classmethod
    def _validate_exported_identifier(cls, value: str) -> str:
        if len(value) > MAX_LABEL_CHARS:
            raise ValueError(f"identifier must contain no more than {MAX_LABEL_CHARS} characters")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise ValueError("identifier must not contain control characters")
        return value

    @field_validator("started_at_utc", "completed_at_utc")
    @classmethod
    def _validate_rfc3339_timestamp(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp is not a valid RFC 3339 date-time") from exc
        return value

    @model_validator(mode="after")
    def _validate_evidence_item_content_identity(self) -> AgentRunRecord:
        if self.schema_version not in V063_CONTRACT_SCHEMA_VERSIONS:
            return self
        content_by_identity: dict[tuple[str, str], set[str]] = {}
        for item in self.evidence_items:
            identity = (
                item.ref_id,
                item.source_id,
            )
            content_by_identity.setdefault(identity, set()).add(item.content_digest)
        if any(len(content_digests) != 1 for content_digests in content_by_identity.values()):
            raise ValueError(
                "evidence items with the same ref_id and source_id must have one content_digest"
            )
        return self

    @model_validator(mode="after")
    def _validate_evidence_graph_member_versions(self) -> AgentRunRecord:
        if self.schema_version not in MACHINE_IDENTIFIER_SCHEMA_VERSIONS:
            return self
        mismatches = [
            f"{field_name}[{index}]"
            for field_name in _EVIDENCE_GRAPH_MEMBER_FIELDS
            for index, member in enumerate(getattr(self, field_name))
            if member.schema_version != self.schema_version
        ]
        if mismatches:
            raise ValueError(
                "current run records require current-version evidence graph members: "
                + ", ".join(mismatches)
            )
        return self

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
        if self.total_tokens is not None:
            component_total = (self.prompt_tokens or 0) + (self.completion_tokens or 0)
            both_components_observed = (
                self.prompt_tokens is not None and self.completion_tokens is not None
            )
            if both_components_observed and component_total != self.total_tokens:
                raise ValueError("total_tokens must equal prompt_tokens + completion_tokens")
            if not both_components_observed and component_total > self.total_tokens:
                raise ValueError("observed token components cannot exceed total_tokens")
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
        if (
            self.schema_version in _BUDGET_COMMITMENT_SCHEMA_VERSIONS
            and self.cost_budget_committed_usd is None
        ):
            missing.append("cost_budget_committed_usd")
        if (
            self.schema_version in _BUDGET_COMMITMENT_SCHEMA_VERSIONS
            and self.generated_token_budget_committed is None
        ):
            missing.append("generated_token_budget_committed")
        if (
            self.schema_version in _BUDGET_COMMITMENT_SCHEMA_VERSIONS
            and self.total_token_budget_committed is None
        ):
            missing.append("total_token_budget_committed")
        if missing:
            raise ValueError("live run records require: " + ", ".join(missing))
        if (
            self.estimated_cost_usd is not None
            and self.cost_budget_committed_usd is not None
            and Decimal(self.cost_budget_committed_usd) < Decimal(self.estimated_cost_usd)
        ):
            raise ValueError("cost budget commitment cannot be below estimated cost")
        if (
            self.completion_tokens is not None
            and self.generated_token_budget_committed is not None
            and self.generated_token_budget_committed < self.completion_tokens
        ):
            raise ValueError("generated-token budget commitment cannot be below completion_tokens")
        if (
            self.total_tokens is not None
            and self.total_token_budget_committed is not None
            and self.total_token_budget_committed < self.total_tokens
        ):
            raise ValueError("total-token budget commitment cannot be below total_tokens")
        if (
            self.generated_token_budget_committed is not None
            and self.total_token_budget_committed is not None
            and self.generated_token_budget_committed > self.total_token_budget_committed
        ):
            raise ValueError(
                "generated-token budget commitment cannot exceed total-token commitment"
            )
        if self.observation_status == "excluded" and not self.exclusion_reason:
            raise ValueError("excluded live run records require exclusion_reason")
        return self


class RunSet(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=privacy_profile_json_schema_extra(_RUN_SET_JSON_SCHEMA_EXTRA)
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
    evidence_sensitivity_design_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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
        if self.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not self.runset_id:
            raise ValueError("current run sets require a non-empty runset_id")
        if self.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not self.runs:
            raise ValueError("run sets require at least one run record")
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
        mismatched_modes = tuple(
            run.run_id for run in self.runs if run.execution_mode is not self.execution_mode
        )
        if mismatched_modes:
            raise ValueError(
                f"{self.execution_mode.value} run sets may contain only "
                f"{self.execution_mode.value} run records"
            )
        if self.execution_mode is not ExecutionMode.live:
            return self
        if self.schema_version in _EVIDENCE_SENSITIVITY_DESIGN_SCHEMA_VERSIONS:
            mismatched_commitments = tuple(
                run.run_id
                for run in self.runs
                if run.provenance.evidence_sensitivity_design_digest
                != self.evidence_sensitivity_design_digest
            )
            if mismatched_commitments:
                raise ValueError(
                    "current live run sets require every run provenance "
                    "evidence_sensitivity_design_digest to exactly match the RunSet "
                    "commitment, including absence; mismatched runs: "
                    + ", ".join(mismatched_commitments)
                )
        missing = [
            field_name
            for field_name in ("protocol_id", "protocol_digest")
            if getattr(self, field_name) is None
        ]
        if missing:
            raise ValueError("live run sets require: " + ", ".join(missing))
        if self.completion_status == "incomplete" and not self.stop_reasons:
            raise ValueError("incomplete live run sets require stop_reasons")
        return self
