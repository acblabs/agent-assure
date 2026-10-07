from __future__ import annotations

from collections.abc import Callable
from decimal import (
    ROUND_HALF_EVEN,
    Clamped,
    Context,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    Rounded,
    Subnormal,
    Underflow,
    localcontext,
)
from enum import StrEnum
from re import fullmatch
from typing import Annotated, Any, Literal, TypeVar

from pydantic import AfterValidator, Field, WithJsonSchema

from agent_assure.schema.base import PersistedArtifact
from agent_assure.timestamps import (
    STRICT_RFC3339_TIMESTAMP_PATTERN as STRICT_RFC3339_TIMESTAMP_PATTERN,
)

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
STRICT_JSON_SCHEMA_END = r"(?![\s\S])"
FRACTION_6_PATTERN = r"^0\.[0-9]{6}(?![\s\S])"
NONNEGATIVE_DECIMAL_6_PATTERN = r"^(?:0|[1-9][0-9]*)\.[0-9]{6}(?![\s\S])"
SIGNED_DECIMAL_6_PATTERN = r"^-?(?:0|[1-9][0-9]*)\.[0-9]{6}(?![\s\S])"
ZERO_ONE_TWO_DECIMAL_6_PATTERN = r"^(?:0|1|2)\.[0-9]{6}(?![\s\S])"
TEMPERATURE_DECIMAL_6_PATTERN = r"^(?:[01]\.[0-9]{6}|2\.000000)(?![\s\S])"
UNIT_INTERVAL_6_PATTERN = r"^(?:0\.[0-9]{6}|1\.000000)(?![\s\S])"
SIGNED_UNIT_INTERVAL_6_PATTERN = r"^-?(?:0\.[0-9]{6}|1\.000000)(?![\s\S])"
UNIT_INTERVAL_12_PATTERN = r"^(?:0\.[0-9]{12}|1\.000000000000)(?![\s\S])"


def strict_json_schema_pattern_end(pattern: str) -> str:
    """Replace an unescaped terminal dollar with an absolute ECMA-262 end.

    JSON Schema regular expressions use ECMA-262 semantics, where dollar also
    matches immediately before a final line terminator. That is weaker than
    the full-string validation performed by our runtime models. The negative
    lookahead cannot match at any position with a remaining UTF-16 code unit,
    including before LF, CR, CRLF, U+2028, or U+2029.

    This function is for emitted JSON Schemas only. Pydantic's Rust regex
    engine does not support lookaround, so source Field patterns intentionally
    retain their runtime-compatible expressions.
    """

    if not pattern.endswith("$"):
        return pattern
    preceding_backslashes = 0
    for character in reversed(pattern[:-1]):
        if character != "\\":
            break
        preceding_backslashes += 1
    if preceding_backslashes % 2:
        return pattern
    return pattern[:-1] + STRICT_JSON_SCHEMA_END


def harden_json_schema_pattern_ends(schema: object) -> None:
    """Harden JSON Schema patterns and pattern-property keys in place."""

    pending = [schema]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "pattern" and isinstance(child, str):
                    value[key] = strict_json_schema_pattern_end(child)
                elif key == "patternProperties" and isinstance(child, dict):
                    hardened_properties: dict[object, object] = {}
                    for property_pattern, declaration in child.items():
                        hardened_pattern = (
                            strict_json_schema_pattern_end(property_pattern)
                            if isinstance(property_pattern, str)
                            else property_pattern
                        )
                        if hardened_pattern in hardened_properties:
                            raise ValueError(
                                "strict JSON Schema pattern hardening produced "
                                "duplicate patternProperties keys"
                            )
                        hardened_properties[hardened_pattern] = declaration
                    value[key] = hardened_properties
                    pending.append(hardened_properties)
                else:
                    pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)


def _require_fraction_6(value: str) -> str:
    if fullmatch(r"0\.[0-9]{6}", value) is None:
        raise ValueError("value must be a canonical six-place number in [0, 1)")
    return value


def _require_nonnegative_decimal_6(value: str) -> str:
    if fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{6}", value) is None:
        raise ValueError("value must be a canonical nonnegative six-place number")
    return value


def _require_signed_decimal_6(value: str) -> str:
    if fullmatch(r"-?(?:0|[1-9][0-9]*)\.[0-9]{6}", value) is None:
        raise ValueError("value must be a canonical signed six-place number")
    return value


def _require_zero_one_two_decimal_6(value: str) -> str:
    if fullmatch(r"(?:0|1|2)\.[0-9]{6}", value) is None:
        raise ValueError("value must have a 0, 1, or 2 whole part and six decimal places")
    return value


def _require_temperature_decimal_6(value: str) -> str:
    if fullmatch(r"(?:[01]\.[0-9]{6}|2\.000000)", value) is None:
        raise ValueError("temperature must be a canonical six-place number in [0, 2]")
    return value


def _require_unit_interval_6(value: str) -> str:
    if fullmatch(r"(?:0\.[0-9]{6}|1\.000000)", value) is None:
        raise ValueError("value must be a canonical six-place number in [0, 1]")
    return value


def _require_signed_unit_interval_6(value: str) -> str:
    if fullmatch(r"-?(?:0\.[0-9]{6}|1\.000000)", value) is None:
        raise ValueError("value must be a canonical six-place number in [-1, 1]")
    return value


def _require_unit_interval_12(value: str) -> str:
    if fullmatch(r"(?:0\.[0-9]{12}|1\.000000000000)", value) is None:
        raise ValueError("value must be a canonical twelve-place number in [0, 1]")
    return value


Fraction6String = Annotated[
    str,
    AfterValidator(_require_fraction_6),
    WithJsonSchema({"type": "string", "pattern": FRACTION_6_PATTERN}),
]
NonnegativeDecimal6String = Annotated[
    str,
    AfterValidator(_require_nonnegative_decimal_6),
    WithJsonSchema({"type": "string", "pattern": NONNEGATIVE_DECIMAL_6_PATTERN}),
]
SignedDecimal6String = Annotated[
    str,
    AfterValidator(_require_signed_decimal_6),
    WithJsonSchema({"type": "string", "pattern": SIGNED_DECIMAL_6_PATTERN}),
]
ZeroOneTwoDecimal6String = Annotated[
    str,
    AfterValidator(_require_zero_one_two_decimal_6),
    WithJsonSchema({"type": "string", "pattern": ZERO_ONE_TWO_DECIMAL_6_PATTERN}),
]
TemperatureDecimal6String = Annotated[
    str,
    AfterValidator(_require_temperature_decimal_6),
    WithJsonSchema({"type": "string", "pattern": TEMPERATURE_DECIMAL_6_PATTERN}),
]
UnitInterval6String = Annotated[
    str,
    AfterValidator(_require_unit_interval_6),
    WithJsonSchema({"type": "string", "pattern": UNIT_INTERVAL_6_PATTERN}),
]
SignedUnitInterval6String = Annotated[
    str,
    AfterValidator(_require_signed_unit_interval_6),
    WithJsonSchema({"type": "string", "pattern": SIGNED_UNIT_INTERVAL_6_PATTERN}),
]
UnitInterval12String = Annotated[
    str,
    AfterValidator(_require_unit_interval_12),
    WithJsonSchema({"type": "string", "pattern": UNIT_INTERVAL_12_PATTERN}),
]
MAX_SUMMARY_CHARS = 8192
MAX_LABEL_CHARS = 512
MACHINE_IDENTIFIER_MAX_CHARS = 256
MACHINE_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
PROVIDER_MODEL_IDENTIFIER_PATTERN = (
    r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"
    r"(?:@[A-Za-z0-9][A-Za-z0-9._:/-]{0,254})?$"
)
MachineIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MACHINE_IDENTIFIER_MAX_CHARS,
        pattern=MACHINE_IDENTIFIER_PATTERN,
    ),
]
ProviderModelIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=MACHINE_IDENTIFIER_MAX_CHARS,
        pattern=PROVIDER_MODEL_IDENTIFIER_PATTERN,
    ),
]

# Each value names the exact byte sequence committed by a live adapter. The
# custom-adapter scope is intentionally weaker provenance: it describes bytes
# supplied by that adapter and is never sufficient for confirmatory studies.
ProviderResponsePayloadScope = Literal[
    "complete_http_response_body",
    "complete_external_script_stdout",
    "complete_static_jsonl_record",
    "complete_adapter_declared_response_bytes",
]
MACHINE_IDENTIFIER_SCHEMA_VERSION = "0.6.6"
# v0.6.1 introduced the bounded ASCII machine-identifier contract. Keep the
# version set explicit so compatibility projection cannot silently weaken that
# released contract when the current writer version advances.
MACHINE_IDENTIFIER_SCHEMA_VERSIONS = (
    "0.6.1",
    "0.6.2",
    "0.6.3",
    "0.6.4",
    "0.6.5",
    "0.6.6",
)
# These relational and non-empty identity requirements were introduced on the
# v0.6.3 writer surface. Keep every governed version explicit so advancing the
# current writer cannot silently disable an already released contract.
V063_CONTRACT_SCHEMA_VERSIONS = (
    "0.6.3",
    "0.6.4",
    "0.6.5",
    "0.6.6",
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
_SIX_DECIMAL_PLACES = Decimal("0.000001")
_MAX_DECIMAL_STRING_DIGITS = 4_096


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


def validate_provider_model_identifier(value: str, *, field_name: str) -> str:
    """Validate a bounded ASCII provider model ID, including one version separator."""
    if (
        len(value) > MACHINE_IDENTIFIER_MAX_CHARS
        or fullmatch(PROVIDER_MODEL_IDENTIFIER_PATTERN, value) is None
    ):
        raise ValueError(
            f"{field_name} must use the ASCII machine-identifier grammar for provider models"
        )
    return value


def decimal_string(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    if not projected.is_finite():
        raise ValueError("decimal value must be finite")
    if len(projected.as_tuple().digits) > _MAX_DECIMAL_STRING_DIGITS:
        raise ValueError("decimal value exceeds the supported precision bound")
    if projected == Decimal("-0"):
        projected = Decimal("0")
    required_precision = max(32, projected.adjusted() + 7)
    if required_precision > _MAX_DECIMAL_STRING_DIGITS:
        raise ValueError("decimal value exceeds the supported precision bound")
    decimal_context = Context(
        prec=required_precision,
        rounding=ROUND_HALF_EVEN,
        Emin=-_MAX_DECIMAL_STRING_DIGITS,
        Emax=_MAX_DECIMAL_STRING_DIGITS,
        capitals=1,
        clamp=0,
        flags=[],
        # Pin every trap instead of inheriting process- or thread-local state.
        # Invalid arithmetic remains exceptional; representational status
        # signals produced by quantization are deliberately non-trapping.
        traps=[DivisionByZero, InvalidOperation, Overflow],
    )
    for signal in (Clamped, Inexact, Rounded, Subnormal, Underflow):
        decimal_context.traps[signal] = False
    with localcontext(decimal_context):
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
