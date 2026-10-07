from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from agent_assure.live.adapters import LiveProviderResponse
from agent_assure.live.config import LiveAdapterConfig, LiveRunConfig
from agent_assure.schema.common import (
    Fraction6String,
    NonnegativeDecimal6String,
    SignedDecimal6String,
    SignedUnitInterval6String,
    TemperatureDecimal6String,
    UnitInterval6String,
    UnitInterval12String,
    ZeroOneTwoDecimal6String,
)
from agent_assure.schema.export import SCHEMA_MODELS, SchemaModel

_LEGACY_NEWLINE_PERMISSIVE_DECIMAL_PATTERNS = frozenset(
    {
        r"^0\.[0-9]{6}$",
        r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
        r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
        r"^(0|1|2)\.[0-9]{6}$",
        r"^(0|1)\.[0-9]{6}$",
        r"^-?(0|1)\.[0-9]{6}$",
        r"^(0|1)\.[0-9]{12}$",
        r"^(0\.[0-9]{6}|1\.000000)$",
    }
)


def _schema_patterns(value: object) -> tuple[str, ...]:
    patterns: list[str] = []
    pending = [value]
    while pending:
        candidate = pending.pop()
        if isinstance(candidate, dict):
            pattern = candidate.get("pattern")
            if isinstance(pattern, str):
                patterns.append(pattern)
            pending.extend(candidate.values())
        elif isinstance(candidate, list):
            pending.extend(candidate)
    return tuple(patterns)


@pytest.mark.parametrize(
    ("domain", "valid_values", "invalid_values"),
    (
        (
            Fraction6String,
            ("0.000000", "0.999999"),
            ("1.000000", "-0.000001", "0.000000\n"),
        ),
        (
            NonnegativeDecimal6String,
            ("0.000000", "1.000000", "999999.999999"),
            ("-0.000001", "00.000000", "+1.000000", "0.000000\n"),
        ),
        (
            SignedDecimal6String,
            ("-999999.999999", "-0.000000", "0.000000", "999999.999999"),
            ("+0.000000", "00.000000", "0.000000\n"),
        ),
        (
            ZeroOneTwoDecimal6String,
            ("0.000000", "1.999999", "2.999999"),
            ("3.000000", "-0.000000", "2.000000\n"),
        ),
        (
            TemperatureDecimal6String,
            ("0.000000", "1.999999", "2.000000"),
            ("-0.000001", "2.000001", "2.999999", "2.000000\n"),
        ),
        (
            UnitInterval6String,
            ("0.000000", "0.999999", "1.000000"),
            (
                "1.000001",
                "1.999999",
                "-0.000001",
                "0.00000",
                "0.0000000",
                "1e-6",
                " 0.500000",
                "0.500000\n",
            ),
        ),
        (
            SignedUnitInterval6String,
            ("-1.000000", "-0.999999", "-0.000000", "0.000000", "1.000000"),
            (
                "-1.000001",
                "-1.999999",
                "1.000001",
                "1.999999",
                "+0.500000",
                "0.500000\n",
            ),
        ),
        (
            UnitInterval12String,
            ("0.000000000000", "0.999999999999", "1.000000000000"),
            (
                "1.000000000001",
                "1.999999999999",
                "-0.000000000001",
                "0.000000",
                "0.500000000000\n",
            ),
        ),
    ),
)
def test_fixed_decimal_domains_match_runtime_and_json_schema(
    domain: object,
    valid_values: tuple[str, ...],
    invalid_values: tuple[str, ...],
) -> None:
    adapter: TypeAdapter[object] = TypeAdapter(domain)
    schema_validator = Draft202012Validator(adapter.json_schema(mode="validation"))

    for value in valid_values:
        assert adapter.validate_python(value, strict=True) == value
        schema_validator.validate(value)

    for value in invalid_values:
        with pytest.raises(ValidationError):
            adapter.validate_python(value, strict=True)
        with pytest.raises(JsonSchemaValidationError):
            schema_validator.validate(value)


@pytest.mark.parametrize(("artifact_kind", "model"), tuple(SCHEMA_MODELS.items()))
def test_current_writer_schemas_do_not_reintroduce_newline_permissive_decimal_patterns(
    artifact_kind: str,
    model: SchemaModel,
) -> None:
    schema = model.model_json_schema(mode="validation")
    bad_patterns = sorted(
        set(_schema_patterns(schema)) & _LEGACY_NEWLINE_PERMISSIVE_DECIMAL_PATTERNS
    )

    assert bad_patterns == [], (
        f"{artifact_kind} contains newline-permissive patterns: {bad_patterns}"
    )


@pytest.mark.parametrize(
    "model",
    (LiveAdapterConfig, LiveRunConfig, LiveProviderResponse),
)
def test_live_input_schemas_do_not_reintroduce_newline_permissive_decimal_patterns(
    model: SchemaModel,
) -> None:
    patterns = set(_schema_patterns(model.model_json_schema(mode="validation")))

    assert patterns.isdisjoint(_LEGACY_NEWLINE_PERMISSIVE_DECIMAL_PATTERNS)


def test_live_adapter_temperature_json_schema_matches_runtime_range() -> None:
    schema = LiveAdapterConfig.model_json_schema(mode="validation")
    temperature_schema = schema["properties"]["temperature"]
    validator = Draft202012Validator(temperature_schema)

    validator.validate("2.000000")
    for invalid in ("2.000001", "2.500000", "2.999999"):
        with pytest.raises(JsonSchemaValidationError):
            validator.validate(invalid)
