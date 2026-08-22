from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from enum import StrEnum
from re import fullmatch
from typing import Annotated, Any, Literal, TypeVar

from pydantic import Field

from agent_assure.schema.base import PersistedArtifact

EnumT = TypeVar("EnumT", bound=StrEnum)


BLOCKED_PROVIDER_SELECTION = "agent-assure.blocked-provider-selection"


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
    unchanged = "unchanged"
    allowed_behavioral_change = "allowed_behavioral_change"
    allowed_behavioral_and_provenance_change = "allowed_behavioral_and_provenance_change"
    provenance_only_change = "provenance_only_change"
    invalid_comparison = "invalid_comparison"
    not_evaluated = "not_evaluated"


class ReasonCode(StrEnum):
    EXPECTED_OUTCOME_MISMATCH = "EXPECTED_OUTCOME_MISMATCH"
    FORBIDDEN_OUTCOME = "FORBIDDEN_OUTCOME"
    MATERIAL_CLAIM_MISSING_EVIDENCE = "MATERIAL_CLAIM_MISSING_EVIDENCE"
    EVIDENCE_PROVENANCE_MISMATCH = "EVIDENCE_PROVENANCE_MISMATCH"
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
    RUNSET_INCOMPLETE = "RUNSET_INCOMPLETE"
    VALID_RECORD_MISSING = "VALID_RECORD_MISSING"
    FIXTURE_EQUIVALENCE_FAILED = "FIXTURE_EQUIVALENCE_FAILED"
    NON_NFC_STRING = "NON_NFC_STRING"
    NON_FINITE_NUMBER = "NON_FINITE_NUMBER"
    LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED = "LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED"
    NOT_EVALUATED = "NOT_EVALUATED"


DigestHex = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
MAX_SUMMARY_CHARS = 8192
MAX_LABEL_CHARS = 512
MACHINE_IDENTIFIER_MAX_CHARS = 256
MACHINE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
MACHINE_IDENTIFIER_SCHEMA_VERSION = "0.6.4"
# v0.6.1 introduced the bounded ASCII machine-identifier contract. Keep the
# version set explicit so compatibility projection cannot silently weaken that
# released contract when the current writer version advances.
MACHINE_IDENTIFIER_SCHEMA_VERSIONS = (
    "0.6.1",
    "0.6.2",
    "0.6.3",
    MACHINE_IDENTIFIER_SCHEMA_VERSION,
)
# These relational and non-empty identity requirements were introduced on the
# v0.6.3 writer surface. Keep every governed version explicit so advancing the
# current writer cannot silently disable an already released contract.
V063_CONTRACT_SCHEMA_VERSIONS = (
    "0.6.3",
    "0.6.4",
)
_MACHINE_IDENTIFIER_JSON_SCHEMA_PATTERN = (
    MACHINE_IDENTIFIER_PATTERN.removesuffix("$") + r"(?![\s\S])"
)
_MACHINE_IDENTIFIER_JSON_SCHEMA: dict[str, object] = {
    "minLength": 1,
    "maxLength": MACHINE_IDENTIFIER_MAX_CHARS,
    "pattern": _MACHINE_IDENTIFIER_JSON_SCHEMA_PATTERN,
}
PACKAGE_RELEASE_VERSION_PATTERN = (
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:rc[1-9][0-9]*)?$"
)
STRICT_RFC3339_TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?"
    r"(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
_SIX_DECIMAL_PLACES = Decimal("0.000001")


def current_machine_identifier_json_schema_extra(
    *,
    scalar_fields: tuple[str, ...] = (),
    sequence_fields: tuple[str, ...] = (),
) -> Callable[[dict[str, Any]], None]:
    """Constrain every schema version governed by the machine-ID contract."""
    overlapping_fields = set(scalar_fields) & set(sequence_fields)
    if overlapping_fields:
        raise ValueError("machine identifier fields cannot be scalar and sequence fields")

    def update_schema(schema: dict[str, Any]) -> None:
        rules = schema.get("allOf")
        if not isinstance(rules, list):
            rules = []
        constrained_properties: dict[str, object] = {
            field_name: dict(_MACHINE_IDENTIFIER_JSON_SCHEMA) for field_name in scalar_fields
        }
        constrained_properties.update(
            {
                field_name: {"items": dict(_MACHINE_IDENTIFIER_JSON_SCHEMA)}
                for field_name in sequence_fields
            }
        )
        rules.append(
            {
                "if": {
                    "required": ["schema_version"],
                    "properties": {
                        "schema_version": {
                            "enum": list(MACHINE_IDENTIFIER_SCHEMA_VERSIONS),
                        }
                    },
                },
                "then": {"properties": constrained_properties},
            }
        )
        schema["allOf"] = rules

    return update_schema


def current_non_empty_fields_json_schema_extra(
    *field_names: str,
) -> dict[str, Any]:
    """Require selected strings to be non-empty on every governed writer schema."""
    return {
        "allOf": [
            {
                "if": {
                    "required": ["schema_version"],
                    "properties": {
                        "schema_version": {
                            "enum": list(V063_CONTRACT_SCHEMA_VERSIONS),
                        }
                    },
                },
                "then": {
                    "properties": {field_name: {"minLength": 1} for field_name in field_names}
                },
            }
        ]
    }


def validate_machine_identifier(value: str, *, field_name: str) -> str:
    """Validate one identifier against the shared ASCII machine-ID grammar."""
    if (
        len(value) > MACHINE_IDENTIFIER_MAX_CHARS
        or fullmatch(MACHINE_IDENTIFIER_PATTERN, value) is None
    ):
        raise ValueError(f"{field_name} must use the ASCII machine-identifier grammar")
    return value


def decimal_string(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    if projected == Decimal("-0"):
        projected = Decimal("0")
    quantized = projected.quantize(_SIX_DECIMAL_PLACES)
    if quantized == Decimal("-0.000000"):
        quantized = Decimal("0.000000")
    return f"{quantized:f}"


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
