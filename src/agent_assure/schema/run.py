from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    ExecutionMode,
    GateState,
    ReasonCode,
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


class PolicyResult(PersistedArtifact):
    artifact_kind: Literal["policy-result"] = "policy-result"
    policy_id: str
    state: GateState
    reason_codes: tuple[ReasonCode, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

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
    policy_results: tuple[PolicyResult, ...] = ()
    human_review_required: bool = False
    human_review_performed: bool = False
    provenance: Provenance = Provenance()

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _coerce_execution_mode(cls, value: object) -> ExecutionMode:
        return coerce_enum(ExecutionMode, value)

    @field_validator("tools", "evidence_refs", "policy_results", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("input_summary", "output_summary")
    @classmethod
    def _reject_sensitive_summaries(cls, value: str) -> str:
        if contains_sensitive_value(value):
            raise ValueError(
                "summary contains sensitive-looking content; redact before persistence"
            )
        return value


class RunSet(PersistedArtifact):
    artifact_kind: Literal["run-set"] = "run-set"
    runset_id: str
    suite_id: str
    runs: tuple[AgentRunRecord, ...]

    @field_validator("runs", mode="before")
    @classmethod
    def _coerce_runs(cls, value: object) -> object:
        return coerce_tuple(value)
