from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

import rfc8785

PRIVACY_PROFILE_ID = "agent-assure/privacy-detectors/v1"
PRIVACY_REDACTION_TEXT = "[REDACTED]"
# Privacy scanning is intentionally fail-closed above this per-scalar bound.  This
# prevents a single JSON string from turning the backtracking regular-expression
# engine into an unbounded CPU sink. Persisted model fields are normally much
# smaller than this limit.
MAX_PRIVACY_SCAN_CHARS = 16_384


@dataclass(frozen=True)
class PrivacyDetectorDefinition:
    pattern_id: str
    expression: str
    flags: tuple[str, ...] = ()


PRIVACY_DETECTOR_DEFINITIONS: tuple[PrivacyDetectorDefinition, ...] = (
    PrivacyDetectorDefinition("us-ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    PrivacyDetectorDefinition(
        "email-address",
        r"(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"
        r"(?![A-Z0-9._%+-])",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition("payment-card-like-number", r"\b(?:\d[ -]?){12,15}\d\b"),
    PrivacyDetectorDefinition(
        "labeled-date-of-birth",
        r"\b(?:dob|date of birth)\s*[:=]?\s*\d{4}-\d{2}-\d{2}\b",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "labeled-sensitive-record-value",
        r"\b(?:patient|member|ssn|dob)\s*[:=]\s*[^\r\n;]+",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "bearer-token",
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "json-web-token",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    ),
    PrivacyDetectorDefinition("aws-access-key-id", r"\bA(?:KIA|SIA)[A-Z0-9]{16}\b"),
    PrivacyDetectorDefinition("github-token", r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    PrivacyDetectorDefinition(
        "openai-api-key",
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
    ),
    PrivacyDetectorDefinition("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    PrivacyDetectorDefinition("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    PrivacyDetectorDefinition("google-api-key", r"\bAIza[A-Za-z0-9_-]{35}\b"),
    PrivacyDetectorDefinition("stripe-live-key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    PrivacyDetectorDefinition(
        "http-basic-authorization",
        r"\bAuthorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{12,}",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "aws-secret-access-key-assignment",
        r"(?:^|[^A-Za-z0-9])(?:aws[_-]?)?secret[_-]?access[_-]?key\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9/+=]{20,}",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "generic-secret-assignment",
        r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|secret|"
        r"password|passwd|authorization)\s*[:=]\s*"
        r"['\"]?[^'\"\s,;]{8,}",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "generic-secret-prose",
        r"\b(?:password|passwd|secret|token)\s+(?:is|was)\s+['\"]?[^'\"\s,;]{8,}",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "url-query-secret",
        r"https?://[^\s?#]{0,4096}\?[^\s#]{0,8192}?"
        r"(?:api[_-]?key|access[_-]?token|token|secret|password)="
        r"[^\s&#]+",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "labeled-north-american-phone-number",
        r"\b(?:phone|tel|mobile)\s*[:=]?\s*(?:\+?1[-.\s]?)?"
        r"\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "medical-record-number",
        r"\bmrn\s*[:=]\s*[A-Za-z0-9-]{4,}",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "patient-name",
        r"\bpatient\s+name\s*[:=]\s*[^\r\n;]+",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "private-key-header",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    ),
)

_REGEX_FLAGS: dict[str, re.RegexFlag] = {"IGNORECASE": re.IGNORECASE}


def _compile_detector(definition: PrivacyDetectorDefinition) -> re.Pattern[str]:
    flags = re.RegexFlag(0)
    for flag_name in definition.flags:
        flags |= _REGEX_FLAGS[flag_name]
    return re.compile(definition.expression, flags)


SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    _compile_detector(definition) for definition in PRIVACY_DETECTOR_DEFINITIONS
)

# These are semantics-preserving guards: every corresponding expression requires
# at least one listed marker. Avoiding a regex search when its required marker is
# absent removes the worst common adversarial shape (for example, a long dotted
# string with no ``@`` for the email detector).
_REQUIRED_MARKERS: dict[str, tuple[str, ...]] = {
    "us-ssn": ("-",),
    "email-address": ("@",),
    "labeled-date-of-birth": ("dob", "date of birth"),
    "labeled-sensitive-record-value": ("patient", "member", "ssn", "dob"),
    "bearer-token": ("bearer",),
    "json-web-token": ("eyj",),
    "aws-access-key-id": ("akia", "asia"),
    "github-token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "openai-api-key": ("sk-",),
    "anthropic-api-key": ("sk-ant-",),
    "slack-token": ("xox",),
    "google-api-key": ("aiza",),
    "stripe-live-key": ("_live_",),
    "http-basic-authorization": ("authorization",),
    "aws-secret-access-key-assignment": ("secret",),
    "generic-secret-assignment": (
        "api",
        "access",
        "client",
        "private",
        "secret",
        "password",
        "passwd",
        "authorization",
    ),
    "generic-secret-prose": ("password", "passwd", "secret", "token"),
    "url-query-secret": (
        "api_key=",
        "api-key=",
        "apikey=",
        "access_token=",
        "access-token=",
        "accesstoken=",
        "token=",
        "secret=",
        "password=",
    ),
    "labeled-north-american-phone-number": ("phone", "tel", "mobile"),
    "medical-record-number": ("mrn",),
    "patient-name": ("patient",),
    "private-key-header": ("private key",),
}


def privacy_profile_manifest() -> dict[str, Any]:
    """Return the canonical detector semantics bound to persisted artifacts."""
    return {
        "profile_id": PRIVACY_PROFILE_ID,
        "detector_engine": "python-re-unicode",
        "detection_algorithm": "ordered-any-search",
        "redaction_algorithm": "ordered-sequential-substitution",
        "redaction_text": PRIVACY_REDACTION_TEXT,
        "max_scalar_characters": MAX_PRIVACY_SCAN_CHARS,
        "over_limit_action": "treat-sensitive-and-redact-entire-scalar",
        "detectors": [
            {
                "pattern_id": definition.pattern_id,
                "expression": definition.expression,
                "flags": list(definition.flags),
            }
            for definition in PRIVACY_DETECTOR_DEFINITIONS
        ],
    }


PRIVACY_PROFILE_DIGEST = hashlib.sha256(
    rfc8785.dumps(privacy_profile_manifest())
).hexdigest()


def contains_sensitive_value(value: str) -> bool:
    if len(value) > MAX_PRIVACY_SCAN_CHARS:
        return True
    return any(pattern.search(value) is not None for pattern in sensitive_patterns_for(value))


def sensitive_patterns_for(value: str) -> tuple[re.Pattern[str], ...]:
    """Return detectors whose mandatory literal marker is present in ``value``."""
    lowered = value.lower()
    return tuple(
        pattern
        for definition, pattern in zip(
            PRIVACY_DETECTOR_DEFINITIONS,
            SENSITIVE_PATTERNS,
            strict=True,
        )
        if not (markers := _REQUIRED_MARKERS.get(definition.pattern_id))
        or any(marker in lowered for marker in markers)
    )
