from __future__ import annotations

import hashlib
import hmac
import unicodedata

MIN_HMAC_KEY_BYTES = 32
_HMAC_TOKEN_CONTRACT = b"AgentAssureHMACToken/v1\x00"


def hmac_sha256_token(value: str, *, key: bytes, context: str) -> str:
    """Return a domain-separated token for a normalized identifier value."""
    _validate_hmac_key(key)
    value_bytes = _normalized_utf8(value, label="HMAC value")
    context_bytes = _normalized_utf8(context, label="HMAC context")
    if len(context_bytes) > 255:
        raise ValueError("HMAC context must be at most 255 UTF-8 bytes")
    message = b"".join(
        (
            _HMAC_TOKEN_CONTRACT,
            len(context_bytes).to_bytes(1, "big"),
            context_bytes,
            len(value_bytes).to_bytes(8, "big"),
            value_bytes,
        )
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac_token(
    received_token: str,
    value: str,
    *,
    key: bytes,
    context: str,
) -> bool:
    expected_token = hmac_sha256_token(value, key=key, context=context)
    return hmac.compare_digest(received_token, expected_token)


def _validate_hmac_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise TypeError("HMAC key must be bytes")
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise ValueError(f"HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes")


def _normalized_utf8(value: str, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        raise ValueError(f"{label} must not be empty")
    return normalized.encode("utf-8")
