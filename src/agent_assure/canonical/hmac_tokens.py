from __future__ import annotations

import hashlib
import hmac

MIN_HMAC_KEY_BYTES = 32


def hmac_sha256_token(value: str, key: bytes) -> str:
    _validate_hmac_key(key)
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_hmac_token(received_token: str, value: str, key: bytes) -> bool:
    expected_token = hmac_sha256_token(value, key)
    return hmac.compare_digest(received_token, expected_token)


def _validate_hmac_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise TypeError("HMAC key must be bytes")
    if len(key) < MIN_HMAC_KEY_BYTES:
        raise ValueError(f"HMAC key must be at least {MIN_HMAC_KEY_BYTES} bytes")
