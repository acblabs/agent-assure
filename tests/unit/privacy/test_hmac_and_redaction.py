from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import pytest
import rfc8785

import agent_assure.privacy.detectors as privacy_detectors
import agent_assure.privacy.redaction as privacy_redaction
from agent_assure.adapters.base import validate_privacy_filtered_mapping
from agent_assure.canonical.hmac_tokens import hmac_sha256_token, verify_hmac_token
from agent_assure.policies.privacy import evaluate_redaction
from agent_assure.privacy.credential_uri import MAX_DURABLE_CREDENTIAL_SCAN_CHARS
from agent_assure.privacy.detectors import (
    MAX_PRIVACY_SCAN_CHARS,
    PRIVACY_PROFILE_DIGEST,
    PRIVACY_PROFILE_ID,
    contains_sensitive_value,
    privacy_profile_manifest,
    url_query_secret_spans,
)
from agent_assure.privacy.persistence import (
    UnsafePersistedTextError,
    assert_persisted_payload_safe,
    assert_persisted_text_safe,
)
from agent_assure.privacy.redaction import (
    assert_runset_payload_safe_for_persistence,
    assert_stream_payload_safe_for_persistence,
    mask_sensitive_text_preserving_length,
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
from agent_assure.telemetry.privacy_filter import safe_attribute

TEST_HMAC_KEY = b"agent-assure-test-suite-key-32-bytes"
TEST_HMAC_CONTEXT = "agent-assure/tests/member-token/v1"
MAX_PRIVACY_SCAN_REGRESSION_SECONDS = 0.25
MAX_PRIVACY_SCAN_CONTROL_MULTIPLIER = 25.0


def _minimum_privacy_scan_seconds(raw: str, *, expected: bool) -> float:
    """Return a warmed best-of-three time while checking every scan result."""

    assert contains_sensitive_value(raw) is expected
    elapsed_samples: list[float] = []
    for _ in range(3):
        started = time.perf_counter()
        observed = contains_sensitive_value(raw)
        elapsed_samples.append(time.perf_counter() - started)
        assert observed is expected
    return min(elapsed_samples)


def _assert_privacy_scan_tracks_ordinary_control(
    raw: str,
    *,
    expected: bool,
) -> None:
    ordinary = ("ordinary-value-" * ((len(raw) // 15) + 1))[: len(raw)]
    control_elapsed = _minimum_privacy_scan_seconds(ordinary, expected=False)
    adversarial_elapsed = _minimum_privacy_scan_seconds(raw, expected=expected)
    ceiling = max(
        MAX_PRIVACY_SCAN_REGRESSION_SECONDS,
        control_elapsed * MAX_PRIVACY_SCAN_CONTROL_MULTIPLIER,
    )
    assert adversarial_elapsed < ceiling


def test_privacy_profile_digest_pins_canonical_detector_semantics() -> None:
    manifest = privacy_profile_manifest()

    assert manifest["profile_id"] == PRIVACY_PROFILE_ID
    assert PRIVACY_PROFILE_DIGEST == hashlib.sha256(rfc8785.dumps(manifest)).hexdigest()
    assert PRIVACY_PROFILE_DIGEST == (
        "c14c0f46e64c25be871235d93c6123c3a3bf3e92fa86824bbf33dbe8bc2a720d"
    )
    assert manifest["unicode_scan_normalization"] == "NFKC"
    assert manifest["unicode_category_c_action"].startswith("remove-with-")
    assert manifest["unicode_dash_action"] == "map-category-pd-and-u+2212-to-ascii-hyphen"
    assert manifest["non_ascii_marker_policy"] == (
        "run-all-python-regex-detectors-and-url-python-ignorecase-equivalent-fold"
    )
    assert manifest["structured_mapping_action"] == (
        "treat-nonempty-value-under-sensitive-or-non-ascii-key-as-sensitive"
    )
    assert manifest["structured_mapping_key_flags"] == ["IGNORECASE"]
    assert "api[ ._-]*key" in manifest["structured_mapping_key_expression"]
    assert manifest["structured_mapping_non_ascii_key_action"].startswith("treat-nonempty-")
    assert manifest["structured_mapping_value_exemptions"] == ["", "[REDACTED]"]
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
        "github-fine-grained-token",
        "gitlab-personal-access-token",
        "hugging-face-token",
        "google-oauth-access-token",
        "npm-access-token",
        "pypi-api-token",
        "openai-api-key",
        "anthropic-api-key",
        "slack-token",
        "google-api-key",
        "stripe-live-key",
        "http-basic-authorization",
        "aws-secret-access-key-assignment",
        "azure-shared-key-assignment",
        "sendgrid-api-key",
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
    assert manifest["payment_card_engine"] == "bounded-forward-scanner-with-luhn-filter"
    assert manifest["payment_card_digit_bounds"] == [13, 19]
    assert manifest["payment_card_digit_alphabet"] == "ascii-0-9-with-nfkc-secondary-view"
    assert manifest["payment_card_boundary_policy"] == ("not-immediately-adjacent-to-ascii-digit")
    assert manifest["payment_card_separator_policy"] == (
        "zero-or-one-ascii-space-or-hyphen-between-digits"
    )
    assert manifest["payment_card_candidate_selection"] == (
        "per-start-longest-to-shortest-first-valid-luhn"
    )
    assert manifest["email_syntax_bounds"] == {
        "local_characters": 64,
        "domain_prefix_characters": 250,
        "top_level_domain_characters": 63,
    }
    assert manifest["url_query_secret_engine"] == (
        "bounded-forward-scanner-with-original-span-map-and-all-secret-components"
    )
    assert manifest["url_query_secret_component_action"] == (
        "redact-first-url-prefix-and-every-later-secret-key-value"
    )
    assert manifest["url_query_secret_preflight"] == [
        "question-mark",
        "http-or-https-scheme",
        "configured-secret-marker-or-percent-escape",
    ]
    assert manifest["url_query_secret_percent_decode_depth"] == 2
    assert manifest["url_query_secret_percent_decode"].startswith("credential-syntax-")
    assert "dotless-i" in manifest["url_query_secret_casefold"]
    assert "transformed-over-limit" in manifest["redaction_algorithm"]
    assert markers_by_detector["url-query-secret"]
    assert (
        next(
            item["engine"]
            for item in manifest["detectors"]
            if item["pattern_id"] == "url-query-secret"
        )
        == "bounded-forward-scanner"
    )
    assert (
        next(
            item["engine"]
            for item in manifest["detectors"]
            if item["pattern_id"] == "payment-card-like-number"
        )
        == "bounded-forward-scanner-with-luhn-filter"
    )


@pytest.mark.parametrize(
    "assignment",
    (
        "openai_api_key=abcdefgh",
        "OPENAI_API_KEY=abcdefgh",
        "service_client_secret=abcdefgh",
    ),
)
def test_generic_secret_assignment_detects_underscore_prefixed_names(
    assignment: str,
) -> None:
    assert contains_sensitive_value(assignment)


def test_payment_card_detector_requires_a_valid_luhn_checksum() -> None:
    assert contains_sensitive_value("card 4111 1111 1111 1111")
    assert redact_text("card 4111 1111 1111 1111") == "card [REDACTED]"
    assert not contains_sensitive_value("req-1727712000000")
    assert redact_text("req-1727712000000") == "req-1727712000000"


@pytest.mark.parametrize(
    "pan",
    (
        "4000000000006",
        "40000000000002",
        "400000000000006",
        "4000000000000002",
        "40000000000000006",
        "400000000000000002",
        "4000000000000000006",
    ),
)
@pytest.mark.parametrize("separator", ("", " ", "-"))
def test_payment_card_detector_covers_luhn_valid_13_through_19_digit_pans(
    pan: str,
    separator: str,
) -> None:
    candidate = separator.join(pan) if separator else pan

    assert contains_sensitive_value(candidate)
    assert redact_text(candidate) == "[REDACTED]"
    with pytest.raises(UnsafePersistedTextError, match="credential material"):
        assert_persisted_payload_safe({"content": candidate}, owner="test report")


@pytest.mark.parametrize(
    "invalid_pan",
    (
        "4000000000007",
        "40000000000003",
        "400000000000007",
        "4000000000000003",
        "40000000000000007",
        "400000000000000003",
        "4000000000000000007",
    ),
)
def test_payment_card_detector_rejects_invalid_checksums_across_supported_lengths(
    invalid_pan: str,
) -> None:
    assert not contains_sensitive_value(invalid_pan)
    assert redact_text(invalid_pan) == invalid_pan


@pytest.mark.parametrize(
    ("prefix", "suffix"),
    (
        ("x", "y"),
        ("_", "_"),
        ("\u6f22", "\u5b57"),
    ),
)
def test_payment_card_detector_uses_digit_boundaries_not_unicode_word_boundaries(
    prefix: str,
    suffix: str,
) -> None:
    pan = "4111111111111111"
    raw = f"{prefix}{pan}{suffix}"

    assert contains_sensitive_value(raw)
    assert redact_text(raw) == f"{prefix}[REDACTED]{suffix}"


@pytest.mark.parametrize("separator", (" ", "-"))
@pytest.mark.parametrize("numeric_suffix", ("1", "12", "123"))
def test_payment_card_detector_retries_shorter_luhn_valid_pan_before_numeric_field(
    separator: str,
    numeric_suffix: str,
) -> None:
    pan = "4111111111111111"
    raw = f"{pan}{separator}{numeric_suffix}"

    assert contains_sensitive_value(raw)
    assert redact_text(raw) == f"[REDACTED]{separator}{numeric_suffix}"


@pytest.mark.parametrize(
    "raw",
    (
        "41111111111111111234",
        "12344111111111111111",
    ),
)
def test_payment_card_detector_does_not_match_inside_longer_contiguous_digit_run(
    raw: str,
) -> None:
    assert not contains_sensitive_value(raw)
    assert redact_text(raw) == raw


_AZURE_ASSIGNMENT_MARKER = "AccountKey="
_SYNTHETIC_ENTROPY_FRAGMENT = "11AA22BB33CC44DD55EE66FF"


@pytest.mark.parametrize(
    "credential",
    (
        "github_pat_11AA22BB33CC44DD55EE66FF77GG88HH",
        "gl" + "pat-11AA22BB33CC44DD55EE66FF",
        "hf_11AA22BB33CC44DD55EE66FF",
        "ya29.11AA22BB33CC44DD55EE66FF",
        "npm_11AA22BB33CC44DD55EE66FF",
        "pypi-11AA22BB33CC44DD55EE66FF",
        "sig=11AA22BB33CC44DD55EE66FF",
        _AZURE_ASSIGNMENT_MARKER + _SYNTHETIC_ENTROPY_FRAGMENT,
        "SG.11AA22BB33CC44DD.11AA22BB33CC44DD55EE66FF77GG88HH99II00JJ",
    ),
)
def test_reported_provider_credentials_are_detected_and_redacted(credential: str) -> None:
    assert contains_sensitive_value(credential)
    assert redact_text(f"credential {credential}") == "credential [REDACTED]"


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


def test_privacy_profile_manifest_identity_changes_with_structured_key_expression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = hashlib.sha256(rfc8785.dumps(privacy_profile_manifest())).hexdigest()
    monkeypatch.setattr(
        privacy_detectors,
        "_SENSITIVE_MAPPING_KEY_DEFINITION",
        privacy_detectors.PrivacyDetectorDefinition(
            "structured-sensitive-mapping-key",
            r"^(?:secret|password)$",
            ("IGNORECASE",),
        ),
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


@pytest.mark.parametrize(
    "raw",
    (
        "ap\u0131_key=abcdefgh1234",
        "pat\u0131ent: Jane Example",
    ),
)
def test_privacy_scan_does_not_optimize_away_unicode_ignorecase_matches(raw: str) -> None:
    assert contains_sensitive_value(raw)
    assert redact_text(raw) == "[REDACTED]"


@pytest.mark.parametrize("dash", ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"))
def test_privacy_scan_reconstructs_unicode_dash_identifiers(dash: str) -> None:
    ssn = dash.join(("123", "45", "6789"))
    card = dash.join(("4111", "1111", "1111", "1111"))

    assert contains_sensitive_value(ssn)
    assert contains_sensitive_value(card)
    assert redact_text(ssn) == "[REDACTED]"
    assert redact_text(card) == "[REDACTED]"


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


def test_url_query_scanner_redacts_short_values_not_matched_by_assignment_detector() -> None:
    raw = "see https://example.test/path?token=x now"

    assert contains_sensitive_value(raw)
    assert redact_text(raw) == "see [REDACTED] now"


@pytest.mark.parametrize("scheme", ("http", "https"))
@pytest.mark.parametrize(
    "key",
    (
        "api_key",
        "api-key",
        "apikey",
        "access_token",
        "access-token",
        "accesstoken",
        "token",
        "secret",
        "password",
    ),
)
@pytest.mark.parametrize("hex_case", ("upper", "lower"))
def test_url_query_scanner_redacts_percent_encoded_secret_key_characters(
    scheme: str,
    key: str,
    hex_case: str,
) -> None:
    escape = f"%{ord(key[0]):02X}"
    if hex_case == "lower":
        escape = escape.lower()
    encoded_key = escape + key[1:]
    raw = f"{scheme}://example.test/path?ordinary=1&{encoded_key}=x"

    assert url_query_secret_spans(raw) == ((0, len(raw)),)
    assert contains_sensitive_value(raw)
    assert redact_text(raw) == "[REDACTED]"
    assert safe_attribute(raw) == "[REDACTED]"
    with pytest.raises(UnsafePersistedTextError, match="credential material"):
        assert_persisted_payload_safe({"content": raw}, owner="test telemetry payload")


@pytest.mark.parametrize(
    "encoded_query",
    (
        "api%5Fkey=x",
        "api%2Dkey=x",
        "access%5Ftoken=x",
        "access%2Dtoken=x",
        "token%3Dx",
        "api%255Fkey%253Dx",
        "%2574oken%253dx",
    ),
)
def test_url_query_scanner_redacts_encoded_separators_operators_and_two_layers(
    encoded_query: str,
) -> None:
    prefix = "before "
    url = f"https://example.test/path?{encoded_query}"
    suffix = " after"
    raw = prefix + url + suffix

    assert url_query_secret_spans(raw) == ((len(prefix), len(prefix) + len(url)),)
    assert redact_text(raw) == f"{prefix}[REDACTED]{suffix}"


@pytest.mark.parametrize(
    "encoded_query",
    (
        "ap%C4%B1_key=x",
        "ap%C4%B0_key=x",
        "%C5%BFecret=x",
        "to%E2%84%AAen=x",
        "%EF%BD%94oken=x",
        "to%E2%80%8Bken=x",
        "ap%25C4%25B1_key=x",
    ),
)
def test_url_query_scanner_normalizes_utf8_percent_encoded_secret_keys(
    encoded_query: str,
) -> None:
    prefix = "before "
    url = f"https://example.test/path?{encoded_query}"
    suffix = " after"
    raw = prefix + url + suffix

    assert url_query_secret_spans(raw) == ((len(prefix), len(prefix) + len(url)),)
    assert contains_sensitive_value(raw)
    assert redact_text(raw) == f"{prefix}[REDACTED]{suffix}"


@pytest.mark.parametrize(
    ("query", "second_key"),
    (
        ("token=x&ordinary=ok&password=y", "password=y"),
        ("%74oken=x&ordinary=ok&%73ecret=y", "%73ecret=y"),
    ),
)
def test_url_query_scanner_redacts_every_secret_component_in_one_url(
    query: str,
    second_key: str,
) -> None:
    prefix = "before "
    url = f"https://example.test/path?{query}"
    suffix = " after"
    raw = prefix + url + suffix
    first_end = url.index("&ordinary")
    second_start = url.index(second_key)
    expected_spans = (
        (len(prefix), len(prefix) + first_end),
        (len(prefix) + second_start, len(prefix) + len(url)),
    )
    expected = f"{prefix}[REDACTED]&ordinary=ok&[REDACTED]{suffix}"

    assert url_query_secret_spans(raw) == expected_spans
    redacted = redact_text(raw)
    assert redacted == expected
    assert not contains_sensitive_value(redacted)


@pytest.mark.parametrize(
    ("query", "second_key"),
    (
        ("token=x&ordinary=ok&password=y", "password=y"),
        ("%74oken=x&ordinary=ok&%73ecret=y", "%73ecret=y"),
    ),
)
def test_url_query_scanner_masks_every_secret_component_without_moving_text(
    query: str,
    second_key: str,
) -> None:
    prefix = "before "
    url = f"https://example.test/path?{query}"
    suffix = " after"
    raw = prefix + url + suffix
    first_end = url.index("&ordinary")
    second_start = url.index(second_key)
    expected = (
        prefix
        + ("\u2588" * first_end)
        + "&ordinary=ok&"
        + ("\u2588" * (len(url) - second_start))
        + suffix
    )

    masked = mask_sensitive_text_preserving_length(raw)

    assert masked == expected
    assert len(masked) == len(raw)
    assert not contains_sensitive_value(masked)


@pytest.mark.parametrize(
    "query",
    (
        "ap\u0131_key=x",
        "ap\u0130_key=x",
        "\u017fecret=x",
        "to\u212aen=x",
    ),
)
def test_url_query_scanner_matches_python_ignorecase_unicode_equivalents(query: str) -> None:
    raw = f"https://example.test/path?{query}"

    assert url_query_secret_spans(raw) == ((0, len(raw)),)
    assert contains_sensitive_value(raw)
    assert redact_text(raw) == "[REDACTED]"


@pytest.mark.parametrize(
    "raw",
    (
        "https://example.test/path?api%5Gkey=x",
        "https://example.test/path?ap%C4_key=x",
        "https://example.test/path?%FFoken=x",
        "https://example.test/path?ordinary%3Dx",
        "https://example.test/path/api%5Fkey=x",
        "https://example.test/path#api%5Fkey=x",
    ),
)
def test_url_query_scanner_preserves_malformed_or_nonquery_percent_near_misses(raw: str) -> None:
    assert url_query_secret_spans(raw) == ()
    assert not contains_sensitive_value(raw)
    assert redact_text(raw) == raw


def test_redaction_fails_closed_when_earlier_replacements_expand_past_scan_limit() -> None:
    card = "4111 1111 1111 1111"
    url_secret = "https://example.test/path?token=SUPERSECRETVALUE123"
    suffix = f" card={card} url={url_secret}"
    emails = "a@b.co " * 2_000
    padding = "x" * (MAX_PRIVACY_SCAN_CHARS - len(emails) - len(suffix))
    raw = emails + padding + suffix

    assert len(raw) == MAX_PRIVACY_SCAN_CHARS
    assert redact_text(raw) == "[REDACTED]"


def test_redaction_fails_closed_when_final_url_replacements_expand_past_scan_limit() -> None:
    url_secrets = "https://a.co/?token=x" + ("&token=x" * 10)
    padding = "x" * (MAX_PRIVACY_SCAN_CHARS - len(url_secrets))
    raw = padding + url_secrets

    assert len(raw) == MAX_PRIVACY_SCAN_CHARS
    assert redact_text(raw) == "[REDACTED]"


@pytest.mark.parametrize(
    ("raw_length", "expected_length"),
    (
        (MAX_PRIVACY_SCAN_CHARS - 19, MAX_PRIVACY_SCAN_CHARS),
        (MAX_PRIVACY_SCAN_CHARS - 18, None),
    ),
)
def test_redaction_enforces_the_exact_post_url_transformation_boundary(
    raw_length: int,
    expected_length: int | None,
) -> None:
    url_secrets = "https://a.co/?token=x" + ("&token=x" * 10)
    raw = ("x" * (raw_length - len(url_secrets))) + url_secrets

    redacted = redact_text(raw)

    assert len(raw) == raw_length
    if expected_length is None:
        assert redacted == "[REDACTED]"
    else:
        assert len(redacted) == expected_length
        assert "token=x" not in redacted


def test_redaction_fails_closed_if_card_replacement_expands_past_scan_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def expand_past_limit(_value: str, *, preserve_length: bool) -> str:
        assert preserve_length is False
        return "x" * (MAX_PRIVACY_SCAN_CHARS + 1)

    monkeypatch.setattr(privacy_redaction, "_replace_payment_cards", expand_past_limit)

    assert redact_text("bounded input") == "[REDACTED]"


@pytest.mark.parametrize(
    "raw",
    (
        "ordinary prose without a URL",
        "https://example.test/path-without-a-query",
        "https://example.test/path?ordinary=value",
        "not-a-url?token=secret-value",
    ),
)
def test_url_query_scanner_cheap_preflight_preserves_nonmatch_semantics(raw: str) -> None:
    assert url_query_secret_spans(raw) == ()


def test_url_query_scanner_bounds_repeated_scheme_adversary() -> None:
    raw = (("http://a?" * 2_000)[: MAX_PRIVACY_SCAN_CHARS - 8]) + "token=x"

    _assert_privacy_scan_tracks_ordinary_control(raw, expected=True)


def test_url_secret_redaction_fails_closed_on_overlimit_url() -> None:
    raw = "https://" + ("a" * 64_000)

    redacted = redact_text(raw)

    assert redacted == "[REDACTED]"


def test_privacy_scan_fails_closed_on_adversarial_overlong_email_shape() -> None:
    raw = ("a." * MAX_PRIVACY_SCAN_CHARS) + "@"

    sensitive = contains_sensitive_value(raw)

    assert sensitive is True
    assert redact_text(raw) == "[REDACTED]"


@pytest.mark.parametrize(
    "raw",
    (
        ("a." * ((MAX_PRIVACY_SCAN_CHARS - 1) // 2)) + "@",
        ("http://a?tokenx" * 2_000)[:MAX_PRIVACY_SCAN_CHARS],
    ),
)
def test_privacy_scan_handles_bounded_near_misses_linearly(raw: str) -> None:
    _assert_privacy_scan_tracks_ordinary_control(raw, expected=False)


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


@pytest.mark.parametrize(
    "label",
    (
        "api_key",
        "api key",
        "api  key",
        "api.key",
        "access token",
        "private key",
        "api_k\u0435y",
        "c\u04cfient secret",
    ),
)
def test_structured_key_value_pairs_are_scanned_as_assignments(label: str) -> None:
    payload = {label: "abc123"}

    assert redact_artifact_payload(payload) == {label: "[REDACTED]"}
    with pytest.raises(ValueError, match="mapping entry"):
        assert_runset_payload_safe_for_persistence(payload)
    with pytest.raises(ValueError, match="mapping entry"):
        assert_stream_payload_safe_for_persistence(payload)
    with pytest.raises(ValueError, match="mapping keys|compact filtered token"):
        validate_privacy_filtered_mapping(payload, owner="attributes")


def test_sensitive_mapping_labels_redact_short_values_and_preserve_only_sentinels() -> None:
    assert redact_packet_payload({"password": "hunter2"}) == {"password": "[REDACTED]"}
    assert redact_packet_payload({"api key": "x"}) == {"api key": "[REDACTED]"}
    assert redact_packet_payload({"password": ""}) == {"password": ""}
    assert redact_packet_payload({"password": "[REDACTED]"}) == {"password": "[REDACTED]"}


def test_non_ascii_mapping_keys_fail_closed_for_nonempty_values() -> None:
    assert redact_packet_payload({"caf\u00e9": "menu"}) == {"caf\u00e9": "[REDACTED]"}


def test_runset_persistence_rejects_sensitive_and_control_mapping_keys() -> None:
    with pytest.raises(ValueError, match="mapping key"):
        assert_runset_payload_safe_for_persistence({"jane@example.com": "safe"})
    with pytest.raises(ValueError, match="mapping key"):
        assert_runset_payload_safe_for_persistence({"unsafe\nkey": "safe"})


@pytest.mark.parametrize(
    "confusing_key",
    (
        "nested.state",
        "nested[0].state",
        "nested/total_tokens",
    ),
)
def test_runset_preserve_list_uses_actual_mapping_key(confusing_key: str) -> None:
    sensitive_assignment = "aws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890"

    with pytest.raises(ValueError, match="sensitive-looking content"):
        assert_runset_payload_safe_for_persistence({confusing_key: sensitive_assignment})


@pytest.mark.parametrize("pseudonym_name", ("subject_token", "employee_token"))
def test_runset_persistence_accepts_canonical_hmac_pseudonym_summary(
    pseudonym_name: str,
) -> None:
    payload = {
        "runs": [
            {"input_summary": (f"case=case-1; {pseudonym_name}={'a' * 32}; fixture=fixture-1")}
        ]
    }

    assert_runset_payload_safe_for_persistence(payload)
    assert_persisted_payload_safe(payload, owner="test RunSet")


def test_runset_persistence_accepts_canonical_rag_hmac_pseudonym_summary() -> None:
    payload = {
        "runs": [
            {
                "input_summary": (
                    f"case=case-1; subject_token={'a' * 32}; fixture=fixture-1; "
                    f"query_digest={'b' * 64}; corpus_version=policy-b-v1"
                )
            }
        ]
    }

    assert_runset_payload_safe_for_persistence(payload)
    assert_persisted_payload_safe(payload, owner="test RunSet")


@pytest.mark.parametrize(
    "ordinary_prose",
    (
        "See signature: ok",
        "retry after broken token: none",
        "Digital signature: valid",
    ),
)
def test_persisted_credential_scan_does_not_treat_ordinary_prose_as_a_field_name(
    ordinary_prose: str,
) -> None:
    assert_persisted_text_safe(
        ordinary_prose,
        owner="test RunSet",
        field_name="stop_reasons",
    )


def test_persisted_document_scan_accepts_many_markdown_headings() -> None:
    document = "\n".join(
        f"### Synthetic condition {index:03d}\n\n- State: not measured" for index in range(200)
    )

    assert len(document) < MAX_PRIVACY_SCAN_CHARS
    assert_persisted_payload_safe({"content": document}, owner="test Markdown report")


def test_persisted_document_scan_accepts_safe_text_above_scalar_limit() -> None:
    document = "\n".join(
        f"### Synthetic condition {index:03d}\n- State: not measured" for index in range(400)
    )

    assert MAX_PRIVACY_SCAN_CHARS < len(document) < MAX_DURABLE_CREDENTIAL_SCAN_CHARS
    assert_persisted_payload_safe({"content": document}, owner="test Markdown report")


def test_persisted_document_scan_reports_exhaustion_distinctly() -> None:
    document = "safe\n" * (MAX_DURABLE_CREDENTIAL_SCAN_CHARS // 5 + 1)

    with pytest.raises(UnsafePersistedTextError, match="bounded credential scan") as exc_info:
        assert_persisted_payload_safe({"content": document}, owner="test Markdown report")

    assert "credential material" not in str(exc_info.value)


def test_persisted_document_scan_preflights_field_budget_without_a_large_document() -> None:
    document = "safe\n" * 32_769

    assert len(document) < MAX_DURABLE_CREDENTIAL_SCAN_CHARS
    with pytest.raises(UnsafePersistedTextError, match="bounded credential scan") as exc_info:
        assert_persisted_payload_safe({"content": document}, owner="test Markdown report")

    assert "credential material" not in str(exc_info.value)


def test_persisted_document_scan_detects_secret_across_window_boundary() -> None:
    document = "a" * (MAX_PRIVACY_SCAN_CHARS - 10) + " sk-proj-abcdefghijklmnopqrstuvwxyz123456\n"

    with pytest.raises(UnsafePersistedTextError, match="credential material"):
        assert_persisted_payload_safe({"content": document}, owner="test Markdown report")


@pytest.mark.parametrize(
    "window_boundary",
    (MAX_PRIVACY_SCAN_CHARS, MAX_PRIVACY_SCAN_CHARS + 4_096, MAX_PRIVACY_SCAN_CHARS + 8_192),
)
def test_persisted_document_scan_detects_rfc_bounded_email_across_windows(
    window_boundary: int,
) -> None:
    email = ("a" * 64) + "@" + ("b" * 63) + "." + ("c" * 61) + ".com"
    assert len(email) <= 254
    prefix = ("x" * (window_boundary - 101)) + " "
    document = prefix + email + " " + ("z" * 256)
    assert len(document) > MAX_PRIVACY_SCAN_CHARS

    with pytest.raises(UnsafePersistedTextError, match="credential material"):
        assert_persisted_payload_safe({"content": document}, owner="test Markdown report")


@pytest.mark.parametrize(
    ("field_value", "rejected"),
    (
        ("1234567", False),
        ("12345678", True),
    ),
)
def test_persisted_document_scan_handles_structural_credentials_split_across_windows(
    field_value: str,
    rejected: bool,
) -> None:
    document = "database-password:" + (" " * MAX_PRIVACY_SCAN_CHARS) + field_value

    if rejected:
        with pytest.raises(UnsafePersistedTextError, match="credential material"):
            assert_persisted_payload_safe({"content": document}, owner="test Markdown report")
    else:
        assert_persisted_payload_safe({"content": document}, owner="test Markdown report")


def test_persisted_credential_scan_retains_compact_identifier_suffix_detection() -> None:
    with pytest.raises(ValueError, match="credential material"):
        assert_persisted_text_safe(
            "requestSignature: hunter2-value",
            owner="test RunSet",
            field_name="stop_reasons",
        )


@pytest.mark.parametrize(
    "credential_field",
    (
        "service access token=hunter2-value",
        "my api key: hunter2-value",
    ),
)
def test_persisted_credential_scan_rejects_spaced_structural_names(
    credential_field: str,
) -> None:
    with pytest.raises(ValueError, match="credential material"):
        assert_persisted_text_safe(
            credential_field,
            owner="test RunSet",
            field_name="stop_reasons",
        )


def test_runset_and_generic_persistence_share_mapping_key_policy() -> None:
    payload = {"runs": [{"api_key": ""}]}

    with pytest.raises(ValueError, match="mapping key"):
        assert_runset_payload_safe_for_persistence(payload)
    with pytest.raises(ValueError, match="mapping key"):
        assert_persisted_payload_safe(payload, owner="test RunSet")


@pytest.mark.parametrize(
    "input_summary",
    (
        "case=case-1; subject_token=short; fixture=fixture-1",
        f"case=case-1; subject_token={'a' * 32}; api_key=short",
        f"https://safe.example/callback?subject_token={'a' * 32}",
    ),
)
def test_runset_persistence_does_not_generalize_pseudonym_summary_exception(
    input_summary: str,
) -> None:
    with pytest.raises(ValueError, match="input_summary"):
        assert_runset_payload_safe_for_persistence({"runs": [{"input_summary": input_summary}]})


@pytest.mark.parametrize(
    "credential_reference",
    (
        "https://provider.example/response?sig=x",
        "//user:password@provider.example/response",
        ("https://safe.example/response?redirect=https%3A%2F%2Fprovider.example%2F%3Ftoken%3Dx"),
    ),
)
def test_runset_persistence_rejects_structural_credentials_in_provider_metadata(
    credential_reference: str,
) -> None:
    payload = {"runs": [{"provider_response_id": credential_reference}]}

    with pytest.raises(ValueError, match="provider_response_id") as exc_info:
        assert_runset_payload_safe_for_persistence(payload)

    assert credential_reference not in str(exc_info.value)
    with pytest.raises(ValueError, match="provider_response_id") as stream_exc_info:
        assert_stream_payload_safe_for_persistence(payload)
    assert credential_reference not in str(stream_exc_info.value)


def test_runset_redaction_recurses_persisted_record_fields() -> None:
    design_digest = "b" * 64
    payload = {
        "artifact_kind": "run-set",
        "evidence_sensitivity_design_digest": design_digest,
        "runs": [
            {
                "input_summary": "plain",
                "output_summary": "plain",
                "traceparent": "00-11111111111111111111111111111111-2222222222222222-01",
                "claims": [{"claim_id": "c1", "text": "api_key=abcdef1234567890"}],
                "provenance": {
                    "configuration_digest": "a" * 64,
                    "evidence_sensitivity_design_digest": design_digest,
                },
            }
        ],
    }

    redacted = redact_runset_payload(payload)

    assert "abcdef1234567890" not in str(redacted)
    assert redacted["evidence_sensitivity_design_digest"] == design_digest
    assert redacted["runs"][0]["provenance"]["configuration_digest"] == "a" * 64
    assert redacted["runs"][0]["provenance"]["evidence_sensitivity_design_digest"] == design_digest
    assert (
        redacted["runs"][0]["traceparent"]
        == "00-11111111111111111111111111111111-2222222222222222-01"
    )
    assert_runset_payload_safe_for_persistence(redacted)


def test_runset_design_commitment_digest_fails_closed_on_raw_secret() -> None:
    payload = {
        "artifact_kind": "run-set",
        "evidence_sensitivity_design_digest": "api_key=abcdef1234567890",
        "runs": [],
    }

    redacted = redact_runset_payload(payload)

    assert redacted["evidence_sensitivity_design_digest"] == "[REDACTED]"
    with pytest.raises(ValueError, match="evidence_sensitivity_design_digest"):
        assert_runset_payload_safe_for_persistence(payload)


@pytest.mark.parametrize("field_name", ("registration_record_sha256", "sha256"))
def test_sha256_field_uses_the_same_digest_contract_at_both_privacy_boundaries(
    field_name: str,
) -> None:
    # This value contains a Luhn-valid 13-digit run. A canonical digest remains
    # structural only under an explicitly recognized digest field.
    digest = "c646deba739b87a9e0497482330808d2e500e84dfab7b893a75224e2bca4957a"
    payload = {field_name: digest}

    assert redact_packet_payload(payload) == payload
    assert_persisted_payload_safe(payload, owner="registration record")

    synthetic_marker = "api_key="
    synthetic_value = "abcdef1234567890"
    synthetic_assignment = synthetic_marker + synthetic_value
    unsafe = {field_name: synthetic_assignment}
    assert redact_packet_payload(unsafe) == {field_name: "[REDACTED]"}
    with pytest.raises(UnsafePersistedTextError, match="sensitive or credential material"):
        assert_persisted_payload_safe(unsafe, owner="registration record")


@pytest.mark.parametrize(
    "field_name",
    ("source_revision", "remediation_source_revision", "git_commit"),
)
def test_generic_privacy_boundary_does_not_exempt_git_shaped_fields(field_name: str) -> None:
    revision = "f8b553e1722d1f4789092253776fc22044e6fce7"
    payload = {field_name: revision}

    assert redact_packet_payload(payload) != payload
    with pytest.raises(UnsafePersistedTextError, match="sensitive or credential material"):
        assert_persisted_payload_safe(payload, owner="untyped Git-shaped record")


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
