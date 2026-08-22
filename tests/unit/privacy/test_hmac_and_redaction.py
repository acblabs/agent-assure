from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import pytest
import rfc8785

import agent_assure.privacy.detectors as privacy_detectors
from agent_assure.canonical.hmac_tokens import hmac_sha256_token, verify_hmac_token
from agent_assure.policies.privacy import evaluate_redaction
from agent_assure.privacy.detectors import (
    MAX_PRIVACY_SCAN_CHARS,
    PRIVACY_PROFILE_DIGEST,
    PRIVACY_PROFILE_ID,
    contains_sensitive_value,
    privacy_profile_manifest,
)
from agent_assure.privacy.redaction import (
    assert_runset_payload_safe_for_persistence,
    redact_artifact_payload,
    redact_packet_payload,
    redact_runset_payload,
    redact_text,
)
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.reporting.usage import usage_summary_lines
from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.sensitivity import (
    RAGSensitivityFixtureFileSnapshot,
    RAGSensitivityFixtureRole,
)
from agent_assure.schema.usage import UsageSummary
from agent_assure.sensitivity_contract import MAX_SENSITIVITY_FIXTURE_BYTES

TEST_HMAC_KEY = b"agent-assure-test-suite-key-32-bytes"
TEST_HMAC_CONTEXT = "agent-assure/tests/member-token/v1"


def test_privacy_profile_digest_pins_canonical_detector_semantics() -> None:
    manifest = privacy_profile_manifest()

    assert manifest["profile_id"] == PRIVACY_PROFILE_ID
    assert PRIVACY_PROFILE_DIGEST == hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    assert PRIVACY_PROFILE_DIGEST == (
        "3213eeb63ecbb2ad0bf9681f83eb987c2638abff079955e75988af6b34b3ae53"
    )
    assert manifest["unicode_scan_normalization"] == "NFKC"
    assert manifest["unicode_category_c_action"].startswith("remove-with-")
    assert [item["pattern_id"] for item in manifest["detectors"]] == [
        "us-ssn",
        "email-address",
        "payment-card-like-number",
        "labeled-date-of-birth",
        "labeled-sensitive-record-value",
        "bearer-token",
        "json-web-token",
        "aws-access-key-id",
        "github-token",
        "openai-api-key",
        "anthropic-api-key",
        "slack-token",
        "google-api-key",
        "stripe-live-key",
        "http-basic-authorization",
        "aws-secret-access-key-assignment",
        "generic-secret-assignment",
        "generic-secret-prose",
        "url-query-secret",
        "labeled-north-american-phone-number",
        "medical-record-number",
        "patient-name",
        "private-key-header",
    ]
    markers_by_detector = {
        item["pattern_id"]: item["required_markers"] for item in manifest["detectors"]
    }
    assert markers_by_detector["email-address"] == ["@"]
    assert markers_by_detector["payment-card-like-number"] == []


def test_privacy_profile_manifest_identity_changes_with_required_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = hashlib.sha256(rfc8785.dumps(privacy_profile_manifest())).hexdigest()
    monkeypatch.setitem(
        privacy_detectors._REQUIRED_MARKERS,
        "email-address",
        ("@", "mailto:"),
    )

    after = hashlib.sha256(rfc8785.dumps(privacy_profile_manifest())).hexdigest()

    assert after != before


def test_hmac_requires_explicit_key_and_is_stable() -> None:
    assert hmac_sha256_token(
        "member-001", key=TEST_HMAC_KEY, context=TEST_HMAC_CONTEXT
    ) == hmac_sha256_token("member-001", key=TEST_HMAC_KEY, context=TEST_HMAC_CONTEXT)
    assert hmac_sha256_token(
        "member-001", key=TEST_HMAC_KEY, context=TEST_HMAC_CONTEXT
    ) != hmac_sha256_token("member-002", key=TEST_HMAC_KEY, context=TEST_HMAC_CONTEXT)


def test_hmac_has_no_default_key_or_context() -> None:
    with pytest.raises(TypeError):
        hmac_sha256_token("member-001")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        hmac_sha256_token("member-001", key=TEST_HMAC_KEY)  # type: ignore[call-arg]


def test_hmac_rejects_short_key() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        hmac_sha256_token("member-001", key=b"", context=TEST_HMAC_CONTEXT)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        hmac_sha256_token("member-001", key=b"short-key", context=TEST_HMAC_CONTEXT)


def test_hmac_verify_uses_constant_time_helper() -> None:
    token = hmac_sha256_token("member-001", key=TEST_HMAC_KEY, context=TEST_HMAC_CONTEXT)
    assert verify_hmac_token(
        token,
        "member-001",
        key=TEST_HMAC_KEY,
        context=TEST_HMAC_CONTEXT,
    )
    assert not verify_hmac_token(
        token,
        "member-002",
        key=TEST_HMAC_KEY,
        context=TEST_HMAC_CONTEXT,
    )


def test_hmac_tokens_are_domain_separated_and_nfc_normalized() -> None:
    first = hmac_sha256_token(
        "caf\N{LATIN SMALL LETTER E WITH ACUTE}",
        key=TEST_HMAC_KEY,
        context="agent-assure/tests/first-field/v1",
    )
    canonically_equivalent = hmac_sha256_token(
        "cafe\N{COMBINING ACUTE ACCENT}",
        key=TEST_HMAC_KEY,
        context="agent-assure/tests/first-field/v1",
    )
    other_domain = hmac_sha256_token(
        "caf\N{LATIN SMALL LETTER E WITH ACUTE}",
        key=TEST_HMAC_KEY,
        context="agent-assure/tests/second-field/v1",
    )

    assert first == canonically_equivalent
    assert first != other_domain


def test_redaction_removes_sensitive_values() -> None:
    raw = "patient=Jane ssn: 123-45-6789 jane@example.com"
    redacted = redact_text(raw)
    assert "123-45-6789" not in redacted
    assert "jane@example.com" not in redacted
    assert not contains_sensitive_value(redacted)


@pytest.mark.parametrize(
    "raw",
    (
        "Contact jane\u202e@example.com",
        "SSN 123-45-\u200f6789",
        "key=sk-proj-abcde\u200ffghijklmnopqrstuvwxyz",
        "Contact jane\u200b@example.com",
    ),
)
def test_privacy_scan_reconstructs_unicode_format_obfuscated_values(raw: str) -> None:
    assert contains_sensitive_value(raw)
    assert redact_text(raw) == "[REDACTED]"


@pytest.mark.parametrize("ensure_ascii", (False, True))
def test_authenticated_raw_json_mirror_rejects_unicode_obfuscated_secret(
    ensure_ascii: bool,
) -> None:
    payload = {"safe_summary": "Contact jane\u202e@example.com"}
    content_utf8 = json.dumps(
        payload,
        ensure_ascii=ensure_ascii,
        separators=(",", ":"),
    )
    owner = {
        "descriptor": {"content_digest": hashlib.sha256(content_utf8.encode("utf-8")).hexdigest()},
        "payload": payload,
        "content_utf8": content_utf8,
    }

    redacted = redact_packet_payload(owner)

    assert redacted != owner
    assert redacted["payload"]["safe_summary"] == "[REDACTED]"


def test_privacy_scan_preserves_benign_unicode_formatting_without_a_secret() -> None:
    raw = "Family emoji: \U0001f469\u200d\U0001f4bb; café; العربية"

    assert not contains_sensitive_value(raw)
    assert redact_text(raw) == raw


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
    anthropic_key = "sk-ant-" + "abcdefghijklmnopqrstuvwxyz123456"
    raw = (
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 "
        "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ== "
        "token=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH "
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABC "
        f"slack={slack_token} "
        f"google={google_key} "
        f"stripe={stripe_key} "
        f"anthropic={anthropic_key} "
        "aws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890 "
        "password is CorrectHorseBatteryStaple "
        "mrn: MRN-123456 "
        "Patient Name: Jane Example"
    )
    redacted = redact_text(raw)

    assert "Bearer abcdefghijklmnopqrstuvwxyz123456" not in redacted
    assert "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" not in redacted
    assert "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH" not in redacted
    assert "eyJhbGci" not in redacted
    assert slack_token not in redacted
    assert google_key not in redacted
    assert stripe_key not in redacted
    assert anthropic_key not in redacted
    assert "abcdefghijklmnopqrstuvwxyz1234567890" not in redacted
    assert "CorrectHorseBatteryStaple" not in redacted
    assert "MRN-123456" not in redacted
    assert "Jane Example" not in redacted
    assert not contains_sensitive_value(redacted)


def test_redaction_removes_url_secret_after_prior_query_params() -> None:
    raw = "see https://example.test/path?foo=one&access_token=abcdefghijklmnopqrstuvwxyz"

    redacted = redact_text(raw)

    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "[REDACTED]" in redacted


def test_redaction_removes_url_secret_when_path_contains_ampersand() -> None:
    raw = "see https://example.test/path&audit?token=abcdefghijklmnopqrstuvwxyz"

    redacted = redact_text(raw)

    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "[REDACTED]" in redacted


def test_url_secret_redaction_rejects_long_nonsecret_url_quickly() -> None:
    raw = "https://" + ("a" * 64_000)

    started = time.perf_counter()
    redacted = redact_text(raw)
    elapsed = time.perf_counter() - started

    assert redacted == "[REDACTED]"
    assert elapsed < 0.5


def test_privacy_scan_fails_closed_on_adversarial_overlong_email_shape() -> None:
    raw = ("a." * MAX_PRIVACY_SCAN_CHARS) + "@"

    started = time.perf_counter()
    sensitive = contains_sensitive_value(raw)
    elapsed = time.perf_counter() - started

    assert sensitive is True
    assert redact_text(raw) == "[REDACTED]"
    assert elapsed < 0.1


@pytest.mark.parametrize(
    "raw",
    (
        ("a." * ((MAX_PRIVACY_SCAN_CHARS - 1) // 2)) + "@",
        ("http://a?tokenx" * 2_000)[:MAX_PRIVACY_SCAN_CHARS],
    ),
)
def test_privacy_scan_handles_bounded_near_misses_linearly(raw: str) -> None:
    started = time.perf_counter()
    sensitive = contains_sensitive_value(raw)
    elapsed = time.perf_counter() - started

    assert sensitive is False
    assert elapsed < 0.5


def test_redaction_scans_mapping_keys_without_silent_collision() -> None:
    redacted = redact_artifact_payload({"jane@example.com": "safe"})

    assert redacted == {"[REDACTED]": "safe"}

    with pytest.raises(ValueError, match="duplicate mapping keys"):
        redact_artifact_payload(
            {
                "jane@example.com": "first",
                "john@example.com": "second",
            }
        )


def test_runset_persistence_rejects_sensitive_and_control_mapping_keys() -> None:
    with pytest.raises(ValueError, match="mapping key"):
        assert_runset_payload_safe_for_persistence({"jane@example.com": "safe"})
    with pytest.raises(ValueError, match="mapping key"):
        assert_runset_payload_safe_for_persistence({"unsafe\nkey": "safe"})


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


def test_runset_persistence_rejects_sensitive_stop_reasons() -> None:
    payload = {
        "artifact_kind": "run-set",
        "stop_reasons": ("aborted for patient john.doe@example.com",),
        "runs": [],
    }

    with pytest.raises(ValueError, match="stop_reasons"):
        assert_runset_payload_safe_for_persistence(payload)


@pytest.mark.parametrize("field_name", ("started_at_utc", "completed_at_utc"))
def test_runset_persistence_fail_closes_on_sensitive_timestamp_fields(
    field_name: str,
) -> None:
    payload = {
        "artifact_kind": "run-set",
        "runs": [{field_name: "patient: Alice"}],
    }

    redacted = redact_runset_payload(payload)
    assert redacted["runs"][0][field_name] == "patient: Alice"
    with pytest.raises(ValueError, match=field_name):
        assert_runset_payload_safe_for_persistence(redacted)


def test_redaction_policy_scans_timestamp_fields_even_after_model_copy() -> None:
    run = AgentRunRecord(
        run_id="run-001",
        case_id="case-001",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="summary",
        output_summary="summary",
    ).model_copy(update={"started_at_utc": "patient: Alice"})

    findings = evaluate_redaction(run)

    assert any(finding.target == "started_at_utc" for finding in findings)


def test_redaction_policy_scans_identifiers_and_tracestate() -> None:
    run = AgentRunRecord(
        run_id="run-001",
        case_id="case-001",
        pipeline_id="pipeline",
        recommendation="approve",
        outcome="approve",
        input_summary="summary",
        output_summary="summary",
    ).model_copy(
        update={
            "run_id": "jane@example.com",
            "tracestate": "vendor=john@example.com",
        }
    )

    findings = evaluate_redaction(run)

    assert any(finding.target == "run_id" for finding in findings)
    assert any(finding.target == "tracestate" for finding in findings)


def test_runset_persistence_fail_closes_on_sensitive_privacy_profile_id() -> None:
    payload = {
        "artifact_kind": "run-set",
        "privacy_profile_id": "profile jane@example.com",
        "privacy_profile_digest": "1" * 64,
        "runs": [],
    }

    with pytest.raises(ValueError, match="privacy_profile_id"):
        assert_runset_payload_safe_for_persistence(payload)


def test_runset_persistence_does_not_scan_schema_constrained_profile_digest() -> None:
    payload = {
        "artifact_kind": "run-set",
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": "1" * 64,
        "runs": [],
    }

    assert_runset_payload_safe_for_persistence(payload)


def test_runset_persistence_rejects_sensitive_content_in_redactable_summary() -> None:
    payload: dict[str, Any] = {
        "artifact_kind": "run-set",
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "runs": [
            {
                "input_summary": "Bearer abcdefghijklmnopqrstuvwxyz123456",
                "provenance": {"configuration_digest": "a" * 64},
            }
        ],
    }

    with pytest.raises(ValueError, match="input_summary"):
        assert_runset_payload_safe_for_persistence(payload)

    assert payload["privacy_profile_digest"] == PRIVACY_PROFILE_DIGEST
    assert payload["runs"][0]["provenance"]["configuration_digest"] == "a" * 64


def test_redaction_still_preserves_scalar_structural_values() -> None:
    payload = {
        "artifact_kind": "run-set",
        "privacy_profile_id": PRIVACY_PROFILE_ID,
        "privacy_profile_digest": PRIVACY_PROFILE_DIGEST,
        "runs": [
            {
                "local_debug_reference": "debug-001",
                "provenance": {"configuration_digest": "a" * 64},
            }
        ],
    }

    redacted = redact_runset_payload(payload)

    assert redacted["artifact_kind"] == "run-set"
    assert redacted["privacy_profile_id"] == PRIVACY_PROFILE_ID
    assert redacted["privacy_profile_digest"] == PRIVACY_PROFILE_DIGEST
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


def test_packet_redaction_does_not_blindly_preserve_sensitive_paths() -> None:
    payload = {
        "artifact_kind": "fixture-manifest-entry",
        "path": "fixtures/123-45-6789.json",
        "sha256": "a" * 64,
    }

    redacted = redact_packet_payload(payload)

    assert redacted["path"] == "[REDACTED]"
    assert redacted["sha256"] == "a" * 64


def test_packet_redaction_preserves_large_authenticated_corpus_raw_mirrors() -> None:
    decoded_document = {
        "title": "Synthetic " + ("A" * 8_180),
        "safe_summary": "Synthetic " + ("B" * 8_180),
    }
    raw_document = json.dumps(decoded_document, sort_keys=True)
    assert len(raw_document) > MAX_PRIVACY_SCAN_CHARS
    document = {
        "descriptor": {
            "content_digest": hashlib.sha256(raw_document.encode("utf-8")).hexdigest(),
        },
        "payload": decoded_document,
        "content_utf8": raw_document,
    }
    decoded_manifest = {
        "documents": [
            {"path": f"synthetic-{index:03d}.json", "sha256": "a" * 64} for index in range(256)
        ]
    }
    raw_manifest = json.dumps(decoded_manifest, sort_keys=True)
    assert len(raw_manifest) > MAX_PRIVACY_SCAN_CHARS
    snapshot = {
        "artifact_kind": "rag-sensitivity-corpus-snapshot",
        "corpus_manifest": decoded_manifest,
        "corpus_manifest_file_sha256": hashlib.sha256(raw_manifest.encode("utf-8")).hexdigest(),
        "corpus_manifest_utf8": raw_manifest,
        "documents": [document],
    }

    assert redact_packet_payload(snapshot) == snapshot


def test_packet_redaction_does_not_preserve_unauthenticated_large_raw_mirror() -> None:
    decoded = {
        "title": "Synthetic " + ("A" * 8_180),
        "safe_summary": "Synthetic " + ("B" * 8_180),
    }
    raw = json.dumps(decoded, sort_keys=True)
    payload = {
        "descriptor": {"content_digest": "0" * 64},
        "payload": decoded,
        "content_utf8": raw,
    }

    redacted = redact_packet_payload(payload)

    assert redacted["content_utf8"] == "[REDACTED]"


def _authenticated_fixture_snapshot(
    role: RAGSensitivityFixtureRole,
    *,
    target_size: int,
    sensitive: bool = False,
) -> dict[str, object]:
    decoded = {
        "synthetic_summary": (
            "Contact second@example.com" if sensitive else "Synthetic fixture content"
        )
    }
    compact = json.dumps(decoded, sort_keys=True, separators=(",", ":"))
    assert len(compact.encode("utf-8")) <= target_size
    raw = (" " * (target_size - len(compact.encode("utf-8")))) + compact
    encoded = raw.encode("utf-8")
    snapshot = RAGSensitivityFixtureFileSnapshot(
        role=role,
        path=f"fixtures/{role.value}.json",
        sha256=hashlib.sha256(encoded).hexdigest(),
        size_bytes=len(encoded),
        content_utf8=raw,
    )
    return snapshot.model_dump(mode="json")


@pytest.mark.parametrize("role", tuple(RAGSensitivityFixtureRole))
@pytest.mark.parametrize("target_size", (MAX_PRIVACY_SCAN_CHARS, MAX_PRIVACY_SCAN_CHARS + 1))
def test_packet_redaction_preserves_authenticated_fixture_utf8_across_role_and_scan_boundaries(
    role: RAGSensitivityFixtureRole,
    target_size: int,
) -> None:
    snapshot = _authenticated_fixture_snapshot(role, target_size=target_size)

    assert redact_packet_payload(snapshot) == snapshot


@pytest.mark.parametrize("role", tuple(RAGSensitivityFixtureRole))
@pytest.mark.parametrize("target_size", (MAX_PRIVACY_SCAN_CHARS, MAX_PRIVACY_SCAN_CHARS + 1))
def test_packet_redaction_rejects_sensitive_authenticated_fixture_utf8_across_roles(
    role: RAGSensitivityFixtureRole,
    target_size: int,
) -> None:
    snapshot = _authenticated_fixture_snapshot(
        role,
        target_size=target_size,
        sensitive=True,
    )

    redacted = redact_packet_payload(snapshot)

    assert redacted != snapshot
    assert "second@example.com" not in str(redacted)


@pytest.mark.parametrize("legacy_role", ("subject", "tool"))
def test_packet_redaction_does_not_exempt_non_schema_fixture_roles(legacy_role: str) -> None:
    raw = (" " * MAX_PRIVACY_SCAN_CHARS) + '{"synthetic_summary":"safe"}'
    encoded = raw.encode("utf-8")
    snapshot = {
        "role": legacy_role,
        "path": f"fixtures/{legacy_role}.json",
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size_bytes": len(encoded),
        "content_utf8": raw,
    }

    assert redact_packet_payload(snapshot)["content_utf8"] == "[REDACTED]"


def test_packet_redaction_preserves_authenticated_fixture_utf8_at_schema_byte_limit() -> None:
    snapshot = _authenticated_fixture_snapshot(
        RAGSensitivityFixtureRole.subject_configuration,
        target_size=MAX_SENSITIVITY_FIXTURE_BYTES,
    )

    assert redact_packet_payload(snapshot) == snapshot


@pytest.mark.parametrize("mirror_kind", ("fixture", "corpus-manifest"))
def test_packet_redaction_rejects_multibyte_raw_mirror_over_schema_byte_limit_before_hash(
    mirror_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = '{"synthetic_summary":"'
    suffix = '"}'
    minimum_characters = (
        MAX_SENSITIVITY_FIXTURE_BYTES - len(prefix.encode("utf-8")) - len(suffix.encode("utf-8"))
    ) // len("é".encode()) + 1
    raw = prefix + ("é" * minimum_characters) + suffix
    encoded = raw.encode("utf-8")
    assert len(raw) < MAX_SENSITIVITY_FIXTURE_BYTES
    assert len(encoded) > MAX_SENSITIVITY_FIXTURE_BYTES
    digest = hashlib.sha256(encoded).hexdigest()
    if mirror_kind == "fixture":
        owner = {
            "role": RAGSensitivityFixtureRole.tool_configuration.value,
            "path": "fixtures/tool.json",
            "sha256": digest,
            "size_bytes": len(encoded),
            "content_utf8": raw,
        }
    else:
        owner = {
            "artifact_kind": "rag-sensitivity-corpus-snapshot",
            "corpus_manifest": {"synthetic_summary": "safe"},
            "corpus_manifest_file_sha256": digest,
            "corpus_manifest_utf8": raw,
        }

    def unexpected_hash(_value: bytes) -> object:
        raise AssertionError("over-limit raw mirror reached hashing")

    monkeypatch.setattr("agent_assure.privacy.redaction.hashlib.sha256", unexpected_hash)

    redacted = redact_packet_payload(owner)

    raw_key = "content_utf8" if mirror_kind == "fixture" else "corpus_manifest_utf8"
    assert redacted[raw_key] == "[REDACTED]"


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
