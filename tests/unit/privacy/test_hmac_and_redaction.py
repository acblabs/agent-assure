from __future__ import annotations

import pytest

from agent_assure.canonical.hmac_tokens import hmac_sha256_token, verify_hmac_token
from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.privacy.redaction import redact_text
from agent_assure.privacy.safe_errors import safe_error

TEST_HMAC_KEY = b"agent-assure-test-suite-key"


def test_hmac_requires_explicit_key_and_is_stable() -> None:
    assert hmac_sha256_token("member-001", key=TEST_HMAC_KEY) == hmac_sha256_token(
        "member-001", key=TEST_HMAC_KEY
    )
    assert hmac_sha256_token("member-001", key=TEST_HMAC_KEY) != hmac_sha256_token(
        "member-002", key=TEST_HMAC_KEY
    )


def test_hmac_has_no_default_key() -> None:
    with pytest.raises(TypeError):
        hmac_sha256_token("member-001")  # type: ignore[call-arg]


def test_hmac_rejects_empty_key() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        hmac_sha256_token("member-001", key=b"")


def test_hmac_verify_uses_constant_time_helper() -> None:
    token = hmac_sha256_token("member-001", key=TEST_HMAC_KEY)
    assert verify_hmac_token(token, "member-001", key=TEST_HMAC_KEY)
    assert not verify_hmac_token(token, "member-002", key=TEST_HMAC_KEY)


def test_redaction_removes_sensitive_values() -> None:
    raw = "patient=Jane ssn: 123-45-6789 jane@example.com"
    redacted = redact_text(raw)
    assert "123-45-6789" not in redacted
    assert "jane@example.com" not in redacted
    assert not contains_sensitive_value(redacted)


def test_redaction_handles_multi_word_patient_and_dob() -> None:
    raw = "patient: John Smith DOB 1990-01-01"
    redacted = redact_text(raw)
    assert "John" not in redacted
    assert "Smith" not in redacted
    assert "1990-01-01" not in redacted
    assert not contains_sensitive_value(redacted)


def test_redaction_card_pattern_handles_long_digit_sequences() -> None:
    raw = "card 4111 1111 1111 1111"
    redacted = redact_text(raw)
    assert "4111 1111 1111 1111" not in redacted


def test_redaction_is_idempotent() -> None:
    raw = "patient: John Smith DOB 1990-01-01 jane@example.com"
    once = redact_text(raw)
    assert redact_text(once) == once


def test_safe_error_redacts_message() -> None:
    err = safe_error("BAD_INPUT", "failed for ssn: 123-45-6789")
    assert err.safe_category == "BAD_INPUT"
    assert err.exception_class == "Error"
    assert "123-45-6789" not in err.redacted_message
    assert len(err.redacted_stack_digest) == 64
    assert err.local_debug_reference.startswith("debug-")
