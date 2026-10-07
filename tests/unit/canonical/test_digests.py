from __future__ import annotations

from decimal import ROUND_UP, Decimal, Inexact, Rounded, localcontext

import pytest

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.canonical.normalize import (
    CanonicalizationError,
    digest_projection,
    normalize_decimal,
)
from agent_assure.schema.common import ReasonCode


def test_decimal_variants_project_to_same_string() -> None:
    assert normalize_decimal(Decimal("0.7")) == "0.700000"
    assert normalize_decimal(Decimal("0.70")) == "0.700000"
    assert digest_projection({"value": Decimal("0.700")}) == {"value": "0.700000"}
    assert sha256_hexdigest({"value": Decimal("0.7")}) == sha256_hexdigest(
        {"value": Decimal("0.700")}
    )


@pytest.mark.parametrize("value", ("-0", "-0.000000", "-0.0000004"))
def test_negative_zero_has_one_canonical_representation(value: str) -> None:
    assert normalize_decimal(Decimal(value)) == "0.000000"
    assert sha256_hexdigest({"value": Decimal(value)}) == sha256_hexdigest({"value": Decimal("0")})


def test_large_decimal_normalization_does_not_depend_on_default_context_precision() -> None:
    value = Decimal("123456789012345678901234567890.1234564")
    assert normalize_decimal(value) == "123456789012345678901234567890.123456"
    carry = Decimal("999999999999999999999999999999.9999996")
    assert normalize_decimal(carry) == "1000000000000000000000000000000.000000"


def test_decimal_normalization_rejects_resource_exhausting_magnitude() -> None:
    with pytest.raises(ValueError, match="supported precision bound"):
        normalize_decimal(Decimal("1e999999999999"))


def test_decimal_normalization_does_not_inherit_rounding_or_traps() -> None:
    value = Decimal("1.2345665")
    expected = "1.234566"

    with localcontext() as context:
        context.prec = 3
        context.rounding = ROUND_UP
        context.traps[Inexact] = True
        context.traps[Rounded] = True

        assert normalize_decimal(value) == expected
        assert sha256_hexdigest({"value": value}) == sha256_hexdigest({"value": Decimal(expected)})


def test_decomposed_unicode_fails_with_reason_code() -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        digest_projection("e\u0301")
    assert exc_info.value.reason_code is ReasonCode.NON_NFC_STRING


def test_non_finite_decimal_fails_with_reason_code() -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        normalize_decimal(Decimal("Infinity"))
    assert exc_info.value.reason_code is ReasonCode.NON_FINITE_NUMBER


def test_non_finite_float_fails_with_reason_code() -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        digest_projection(float("inf"))
    assert exc_info.value.reason_code is ReasonCode.NON_FINITE_NUMBER


def test_finite_float_must_be_converted_to_decimal_before_projection() -> None:
    with pytest.raises(TypeError, match="converted to Decimal"):
        digest_projection(0.7)


def test_canonical_digest_is_order_independent() -> None:
    assert sha256_hexdigest({"b": 2, "a": 1}) == sha256_hexdigest({"a": 1, "b": 2})


@pytest.mark.parametrize(
    "value",
    (
        {1: "integer-key"},
        {True: "boolean-key"},
        {"nested": {1: "integer-key"}},
    ),
)
def test_digest_projection_rejects_non_string_object_keys(value: object) -> None:
    with pytest.raises(TypeError, match="object keys must be strings"):
        digest_projection(value)


def test_integer_key_cannot_alias_the_equivalent_string_key() -> None:
    assert digest_projection({"1": "value"}) == {"1": "value"}
    with pytest.raises(TypeError, match="object keys must be strings"):
        sha256_hexdigest({1: "value"})


def test_none_is_preserved_as_digest_identity_data() -> None:
    assert digest_projection({"optional": None}) == {"optional": None}
    assert sha256_hexdigest({"optional": None}) != sha256_hexdigest({})
