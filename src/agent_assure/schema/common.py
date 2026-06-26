from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, TypeVar

from pydantic import Field

from agent_assure.schema.base import PersistedArtifact

EnumT = TypeVar("EnumT", bound=StrEnum)


class ExecutionMode(StrEnum):
    fixture = "fixture"
    live = "live"


class GateState(StrEnum):
    pass_ = "pass"
    fail = "fail"
    warn = "warn"
    not_evaluated = "not_evaluated"


class Severity(StrEnum):
    info = "info"
    warning = "warning"
    error = "error"
    blocker = "blocker"


class ComparisonClassification(StrEnum):
    new_failure = "new_failure"
    resolved_failure = "resolved_failure"
    persistent_failure = "persistent_failure"
    allowed_behavioral_change = "allowed_behavioral_change"
    provenance_only_change = "provenance_only_change"
    invalid_comparison = "invalid_comparison"
    not_evaluated = "not_evaluated"


class ReasonCode(StrEnum):
    EXPECTED_OUTCOME_MISMATCH = "EXPECTED_OUTCOME_MISMATCH"
    FORBIDDEN_OUTCOME = "FORBIDDEN_OUTCOME"
    MATERIAL_CLAIM_MISSING_EVIDENCE = "MATERIAL_CLAIM_MISSING_EVIDENCE"
    REQUIRED_SOURCE_MISSING = "REQUIRED_SOURCE_MISSING"
    POLICY_FAILED = "POLICY_FAILED"
    REQUIRED_HUMAN_REVIEW_ABSENT = "REQUIRED_HUMAN_REVIEW_ABSENT"
    REVIEW_BOUNDARY_FAILED = "REVIEW_BOUNDARY_FAILED"
    FORBIDDEN_PROVIDER = "FORBIDDEN_PROVIDER"
    FORBIDDEN_TOOL = "FORBIDDEN_TOOL"
    STRUCTURED_OUTPUT_INVALID = "STRUCTURED_OUTPUT_INVALID"
    REDACTION_FAILED = "REDACTION_FAILED"
    RAW_SENSITIVE_CONTENT = "RAW_SENSITIVE_CONTENT"
    PROMPT_INJECTION_BOUNDARY = "PROMPT_INJECTION_BOUNDARY"
    RUNTIME_FAILED = "RUNTIME_FAILED"
    VALID_RECORD_MISSING = "VALID_RECORD_MISSING"
    FIXTURE_EQUIVALENCE_FAILED = "FIXTURE_EQUIVALENCE_FAILED"
    NON_NFC_STRING = "NON_NFC_STRING"
    NON_FINITE_NUMBER = "NON_FINITE_NUMBER"
    NOT_EVALUATED = "NOT_EVALUATED"


DigestHex = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


def coerce_enum(enum_type: type[EnumT], value: object) -> EnumT:
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        return enum_type(value)
    raise ValueError(f"expected {enum_type.__name__} value")


def coerce_tuple(value: object) -> object:
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    return value


class Digest(PersistedArtifact):
    artifact_kind: Literal["digest"] = "digest"
    algorithm: Literal["sha256", "hmac-sha256"] = "sha256"
    value: DigestHex


class SourceLocation(PersistedArtifact):
    artifact_kind: Literal["source-location"] = "source-location"
    path: str
    line: int = Field(ge=1)
    column: int = Field(ge=1)
