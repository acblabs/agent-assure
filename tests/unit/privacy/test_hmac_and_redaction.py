from __future__ import annotations

import pytest

from agent_assure.canonical.hmac_tokens import hmac_sha256_token, verify_hmac_token
from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.privacy.redaction import (
    redact_packet_payload,
    redact_runset_payload,
    redact_text,
)
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.reporting.usage import usage_summary_lines
from agent_assure.schema.usage import UsageSummary

TEST_HMAC_KEY = b"agent-assure-test-suite-key-32-bytes"


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


def test_hmac_rejects_short_key() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        hmac_sha256_token("member-001", key=b"")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        hmac_sha256_token("member-001", key=b"short-key")


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


def test_redaction_removes_common_secret_tokens() -> None:
    slack_token = "xoxb-" + "123456789012-123456789012-secretTOKEN"
    google_key = "AIza" + "1234567890ABCDEFGHIJKLMNOPQRSTUVWXY"
    stripe_key = "sk" + "_live_" + "abcdefghijklmnopqrstuvwxyz"
    raw = (
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 "
        "token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH "
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABC "
        f"slack={slack_token} "
        f"google={google_key} "
        f"stripe={stripe_key}"
    )
    redacted = redact_text(raw)

    assert "Bearer abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH" not in redacted
    assert "eyJhbGci" not in redacted
    assert slack_token not in redacted
    assert google_key not in redacted
    assert stripe_key not in redacted
    assert not contains_sensitive_value(redacted)


def test_runset_redaction_recurses_persisted_record_fields() -> None:
    payload = {
        "artifact_kind": "run-set",
        "runs": [
            {
                "input_summary": "plain",
                "output_summary": "plain",
                "traceparent": "00-11111111111111111111111111111111-2222222222222222-01",
                "claims": [{"claim_id": "c1", "text": "api_key=abcdef1234567890"}],
                "provenance": {"configuration_digest": "a" * 64},
            }
        ],
    }

    redacted = redact_runset_payload(payload)

    assert "abcdef1234567890" not in str(redacted)
    assert redacted["runs"][0]["provenance"]["configuration_digest"] == "a" * 64
    assert (
        redacted["runs"][0]["traceparent"]
        == "00-11111111111111111111111111111111-2222222222222222-01"
    )


def test_redaction_recurses_nested_values_under_preserved_keys() -> None:
    payload = {
        "artifact_kind": "run-set",
        "runs": [
            {
                "local_debug_reference": {
                    "nested_error": "patient ssn: 123-45-6789",
                },
                "provenance": {
                    "configuration_digest": {
                        "debug_note": "api_key=abcdef1234567890",
                    }
                },
            }
        ],
    }

    redacted = redact_runset_payload(payload)

    assert "123-45-6789" not in str(redacted)
    assert "abcdef1234567890" not in str(redacted)
    assert redacted["runs"][0]["local_debug_reference"]["nested_error"] == "patient [REDACTED]"


def test_runset_redaction_scrubs_sensitive_exclusion_reason() -> None:
    payload = {
        "artifact_kind": "run-set",
        "runs": [
            {
                "exclusion_reason": "patient ssn: 123-45-6789",
            }
        ],
    }

    redacted = redact_runset_payload(payload)

    assert redacted["runs"][0]["exclusion_reason"] == "patient [REDACTED]"


def test_redaction_still_preserves_scalar_structural_values() -> None:
    payload = {
        "artifact_kind": "run-set",
        "runs": [
            {
                "local_debug_reference": "debug-001",
                "provenance": {"configuration_digest": "a" * 64},
            }
        ],
    }

    redacted = redact_runset_payload(payload)

    assert redacted["artifact_kind"] == "run-set"
    assert redacted["runs"][0]["local_debug_reference"] == "debug-001"
    assert redacted["runs"][0]["provenance"]["configuration_digest"] == "a" * 64


def test_redaction_scrubs_sensitive_usage_provenance_sequence_values() -> None:
    payload = {
        "usage_summary": {
            "cost_basis_ids": ["api_key=abcdef1234567890"],
            "pricing_snapshot_ids": ["ssn: 123-45-6789"],
            "pricing_snapshot_digests": ["a" * 64],
            "notes": ["ssn: 987-65-4321"],
        }
    }

    redacted = redact_packet_payload(payload)

    usage_summary = redacted["usage_summary"]
    assert usage_summary["cost_basis_ids"] == ["[REDACTED]"]
    assert usage_summary["pricing_snapshot_ids"] == ["[REDACTED]"]
    assert usage_summary["pricing_snapshot_digests"] == ["a" * 64]
    assert "987-65-4321" not in usage_summary["notes"][0]


def test_usage_markdown_redacts_sensitive_provenance_ids() -> None:
    summary = UsageSummary(
        cost_basis_ids=("api_key=abcdef1234567890",),
        pricing_snapshot_ids=("ssn: 123-45-6789",),
    )

    rendered = "\n".join(usage_summary_lines(summary))

    assert "abcdef1234567890" not in rendered
    assert "123-45-6789" not in rendered
    assert "[REDACTED]" in rendered


def test_redaction_rejects_malformed_digest_sequence_values() -> None:
    payload = {"usage_summary": {"pricing_snapshot_digests": ["api_key=abcdef1234567890"]}}

    redacted = redact_packet_payload(payload)

    assert redacted["usage_summary"]["pricing_snapshot_digests"] == ["[REDACTED]"]


def test_runset_redaction_rejects_malformed_digest_without_corrupting_ids() -> None:
    payload = {
        "artifact_kind": "run-set",
        "runs": [
            {
                "provider_response_id": "1234567890123456",
                "provenance": {
                    "configuration_digest": "api_key=abcdef1234567890",
                    "fixture_manifest_digest": "b" * 64,
                },
            }
        ],
    }

    redacted = redact_runset_payload(payload)

    dumped = str(redacted)
    assert "abcdef1234567890" not in dumped
    assert redacted["runs"][0]["provider_response_id"] == "1234567890123456"
    assert redacted["runs"][0]["provenance"]["configuration_digest"] == "[REDACTED]"
    assert redacted["runs"][0]["provenance"]["fixture_manifest_digest"] == "b" * 64


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
