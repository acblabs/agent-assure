from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    DigestHex,
    ExecutionMode,
    GateState,
    ReasonCode,
    Severity,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.provenance import Provenance


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
    gate_profile: str = "default"
    message: str = ""

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
    artifact_kind: Literal["agent-run-record"] = "agent-run-record"
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    execution_mode: ExecutionMode = ExecutionMode.fixture
    pipeline_id: str = Field(min_length=1)
    recommendation: str
    outcome: str
    input_summary: str
    output_summary: str
    provider: str | None = None
    model: str | None = None
    tools: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    evidence_items: tuple[EvidenceItem, ...] = ()
    claims: tuple[ClaimRecord, ...] = ()
    claim_evidence_links: tuple[ClaimEvidenceLink, ...] = ()
    policy_results: tuple[PolicyResult, ...] = ()
    human_review_required: bool = False
    human_review_performed: bool = False
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

    @field_validator("input_summary", "output_summary")
    @classmethod
    def _validate_summary_type(cls, value: str) -> str:
        return value


class RunSet(PersistedArtifact):
    artifact_kind: Literal["run-set"] = "run-set"
    runset_id: str
    suite_id: str
    suite_version: str
    suite_digest: DigestHex
    fixture_manifest_digest: DigestHex
    execution_mode: ExecutionMode = ExecutionMode.fixture
    runs: tuple[AgentRunRecord, ...]

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _coerce_execution_mode(cls, value: object) -> ExecutionMode:
        return coerce_enum(ExecutionMode, value)

    @field_validator("runs", mode="before")
    @classmethod
    def _coerce_runs(cls, value: object) -> object:
        return coerce_tuple(value)
