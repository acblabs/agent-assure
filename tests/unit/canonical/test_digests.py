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
    assert normalize_decimal(Decimal("0.7")) == "0.7"
    assert normalize_decimal(Decimal("0.70")) == "0.7"
    assert digest_projection({"value": Decimal("0.700")}) == {"value": "0.7"}
    assert sha256_hexdigest({"value": Decimal("0.7")}) == sha256_hexdigest(
        {"value": Decimal("0.700")}
    )


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


def test_canonical_digest_is_order_independent() -> None:
    assert sha256_hexdigest({"b": 2, "a": 1}) == sha256_hexdigest({"a": 1, "b": 2})
