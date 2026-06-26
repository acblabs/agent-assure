from __future__ import annotations

from decimal import Decimal

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


def test_large_decimal_normalization_does_not_depend_on_default_context_precision() -> None:
    value = Decimal("123456789012345678901234567890.1234564")
    assert normalize_decimal(value) == "123456789012345678901234567890.123456"
    carry = Decimal("999999999999999999999999999999.9999996")
    assert normalize_decimal(carry) == "1000000000000000000000000000000.000000"


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
