from __future__ import annotations

from agent_assure.policies.privacy import _iter_sensitive_strings


def test_privacy_scan_skips_digest_like_values_only() -> None:
    payload = {
        "valid_digest": "a" * 64,
        "misnamed_digest": "patient ssn: 123-45-6789",
        "valid_hash": "b" * 64,
        "misnamed_hash": "api_key=abcdef1234567890",
    }

    sensitive = dict(_iter_sensitive_strings(payload))

    assert "valid_digest" not in sensitive
    assert "valid_hash" not in sensitive
    assert sensitive["misnamed_digest"] == "patient ssn: 123-45-6789"
    assert sensitive["misnamed_hash"] == "api_key=abcdef1234567890"
