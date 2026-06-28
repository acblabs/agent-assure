from __future__ import annotations

import unicodedata
from decimal import Decimal, localcontext
from math import isfinite
from typing import Any

from agent_assure.schema.common import ReasonCode

DECIMAL_QUANTUM = Decimal("0.000001")


class CanonicalizationError(ValueError):
    def __init__(self, reason_code: ReasonCode, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


def normalize_decimal(value: Decimal | str) -> str:
    decimal = Decimal(str(value))
    if not decimal.is_finite():
        raise CanonicalizationError(ReasonCode.NON_FINITE_NUMBER, "decimal is not finite")
    quantum_exponent = DECIMAL_QUANTUM.as_tuple().exponent
    if not isinstance(quantum_exponent, int):
        raise CanonicalizationError(ReasonCode.NON_FINITE_NUMBER, "decimal quantum is not finite")
    fractional_places = abs(quantum_exponent)
    integer_digits = max(decimal.adjusted() + 1, 1)
    with localcontext() as context:
        context.prec = max(context.prec, integer_digits + fractional_places + 1)
        return format(decimal.quantize(DECIMAL_QUANTUM), "f")


def ensure_nfc(value: str) -> str:
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalizationError(ReasonCode.NON_NFC_STRING, "string is not NFC-normalized")
    return value


def digest_projection(value: Any) -> Any:
    """Project typed values into deterministic canonical digest material.

    Explicit ``None`` values are preserved as identity data. Digest roles that
    need missing fields and null fields to be equivalent must apply a
    role-specific projection before using this generic path.
    """
    if isinstance(value, Decimal):
        return normalize_decimal(value)
    if isinstance(value, str):
        return ensure_nfc(value)
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise CanonicalizationError(ReasonCode.NON_FINITE_NUMBER, "float is not finite")
        raise TypeError("float values must be converted to Decimal before digest projection")
    if isinstance(value, tuple | list):
        return [digest_projection(item) for item in value]
    if isinstance(value, dict):
        projected_items: list[tuple[str, Any]] = []
        seen_keys: set[str] = set()
        for key, item in value.items():
            projected_key = ensure_nfc(str(key))
            if projected_key in seen_keys:
                raise TypeError(f"duplicate projected object key: {projected_key!r}")
            seen_keys.add(projected_key)
            projected_items.append((projected_key, digest_projection(item)))
        return {key: item for key, item in sorted(projected_items, key=lambda pair: pair[0])}
    if hasattr(value, "model_dump"):
        return digest_projection(value.model_dump(mode="json"))
    raise TypeError(f"unsupported digest projection type: {type(value).__name__}")
