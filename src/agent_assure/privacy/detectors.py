from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

import rfc8785

PRIVACY_PROFILE_ID = "agent-assure/privacy-detectors/v9"
PRIVACY_REDACTION_TEXT = "[REDACTED]"
# Privacy scanning is intentionally fail-closed above this per-scalar bound.  This
# prevents a single JSON string from turning the backtracking regular-expression
# engine into an unbounded CPU sink. Persisted model fields are normally much
# smaller than this limit.
MAX_PRIVACY_SCAN_CHARS = 16_384
MIN_PAYMENT_CARD_DIGITS = 13
MAX_PAYMENT_CARD_DIGITS = 19
MAX_EMAIL_LOCAL_CHARS = 64
MAX_EMAIL_DOMAIN_PREFIX_CHARS = 250
MAX_EMAIL_TLD_CHARS = 63
URL_QUERY_SECRET_PERCENT_DECODE_DEPTH = 2
_PRIVACY_SCAN_SAFE_WHITESPACE_CONTROLS = frozenset({"\t", "\n", "\r"})


@dataclass(frozen=True)
class PrivacyDetectorDefinition:
    pattern_id: str
    expression: str
    flags: tuple[str, ...] = ()


PRIVACY_DETECTOR_DEFINITIONS: tuple[PrivacyDetectorDefinition, ...] = (
    PrivacyDetectorDefinition("us-ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    PrivacyDetectorDefinition(
        "email-address",
        rf"(?<![A-Z0-9._%+-])[A-Z0-9._%+-]{{1,{MAX_EMAIL_LOCAL_CHARS}}}"
        rf"@[A-Z0-9.-]{{1,{MAX_EMAIL_DOMAIN_PREFIX_CHARS}}}\."
        rf"[A-Z]{{2,{MAX_EMAIL_TLD_CHARS}}}"
        r"(?![A-Z0-9._%+-])",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "payment-card-like-number",
        rf"(?<![0-9])(?:[0-9][ -]?){{{MIN_PAYMENT_CARD_DIGITS - 1},"
        rf"{MAX_PAYMENT_CARD_DIGITS - 1}}}[0-9](?![0-9])",
    ),
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
        "github-fine-grained-token",
        r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,}(?![A-Za-z0-9_])",
    ),
    PrivacyDetectorDefinition(
        "gitlab-personal-access-token",
        r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
    ),
    PrivacyDetectorDefinition(
        "hugging-face-token",
        r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{20,}(?![A-Za-z0-9])",
    ),
    PrivacyDetectorDefinition(
        "google-oauth-access-token",
        r"(?<![A-Za-z0-9.])ya29\.[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
    ),
    PrivacyDetectorDefinition(
        "npm-access-token",
        r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{20,}(?![A-Za-z0-9])",
    ),
    PrivacyDetectorDefinition(
        "pypi-api-token",
        r"(?<![A-Za-z0-9-])pypi-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])",
    ),
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
        "azure-shared-key-assignment",
        r"(?<![A-Za-z0-9])(?:sig|accountkey)\s*=\s*['\"]?"
        r"[A-Za-z0-9%+/=_-]{16,}",
        ("IGNORECASE",),
    ),
    PrivacyDetectorDefinition(
        "sendgrid-api-key",
        r"(?<![A-Za-z0-9.])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}"
        r"(?![A-Za-z0-9_-])",
    ),
    PrivacyDetectorDefinition(
        "generic-secret-assignment",
        r"(?<![A-Za-z0-9])(?:api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|secret|"
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
_URL_IGNORECASE_TRANSLATION = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ\u0130\u0131\u017f\u212a",
    "abcdefghijklmnopqrstuvwxyziisk",
)
_URL_PERCENT_DECODE_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=%"
)


def _compile_detector(definition: PrivacyDetectorDefinition) -> re.Pattern[str]:
    flags = re.RegexFlag(0)
    for flag_name in definition.flags:
        flags |= _REGEX_FLAGS[flag_name]
    return re.compile(definition.expression, flags)


_REGEX_DETECTOR_DEFINITIONS = tuple(
    definition
    for definition in PRIVACY_DETECTOR_DEFINITIONS
    if definition.pattern_id not in {"payment-card-like-number", "url-query-secret"}
)
SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    _compile_detector(definition) for definition in _REGEX_DETECTOR_DEFINITIONS
)

_SENSITIVE_MAPPING_KEY_DEFINITION = PrivacyDetectorDefinition(
    "structured-sensitive-mapping-key",
    r"^(?:patient|member|ssn|dob|mrn|patient[ ._-]*name|date[ ._-]*of[ ._-]*birth|"
    r"authorization|(?:aws[ ._-]*)?secret[ ._-]*access[ ._-]*key|api[ ._-]*key|"
    r"access[ ._-]*token|client[ ._-]*secret|private[ ._-]*key|secret|password|passwd)$",
    ("IGNORECASE",),
)
_SENSITIVE_MAPPING_KEY_PATTERN = _compile_detector(_SENSITIVE_MAPPING_KEY_DEFINITION)

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
    "github-fine-grained-token": ("github_pat_",),
    "gitlab-personal-access-token": ("glpat-",),
    "hugging-face-token": ("hf_",),
    "google-oauth-access-token": ("ya29.",),
    "npm-access-token": ("npm_",),
    "pypi-api-token": ("pypi-",),
    "openai-api-key": ("sk-",),
    "anthropic-api-key": ("sk-ant-",),
    "slack-token": ("xox",),
    "google-api-key": ("aiza",),
    "stripe-live-key": ("_live_",),
    "http-basic-authorization": ("authorization",),
    "aws-secret-access-key-assignment": ("secret",),
    "azure-shared-key-assignment": ("sig", "accountkey"),
    "sendgrid-api-key": ("sg.",),
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
        "detector_engine": "python-re-unicode-and-bounded-forward-scanners",
        "detection_algorithm": (
            "raw-unicode-deobfuscated-and-bounded-url-utf8-percent-decoded-ordered-any-search"
        ),
        "redaction_algorithm": (
            "whole-scalar-on-input-or-transformed-over-limit-or-deobfuscated-match-"
            "else-ordered-regex-and-url-substitution"
        ),
        "url_query_secret_engine": (
            "bounded-forward-scanner-with-original-span-map-and-all-secret-components"
        ),
        "url_query_secret_preflight": [
            "question-mark",
            "http-or-https-scheme",
            "configured-secret-marker-or-percent-escape",
        ],
        "url_query_secret_casefold": (
            "ascii-lower-plus-python-ignorecase-i-dotless-i-long-s-kelvin"
        ),
        "url_query_secret_percent_decode": (
            "credential-syntax-utf8-percent-triplets-nfkc-and-confusable-fold-malformed-literal"
        ),
        "url_query_secret_percent_decode_depth": URL_QUERY_SECRET_PERCENT_DECODE_DEPTH,
        "url_query_secret_component_action": (
            "redact-first-url-prefix-and-every-later-secret-key-value"
        ),
        "payment_card_engine": "bounded-forward-scanner-with-luhn-filter",
        "payment_card_digit_bounds": [MIN_PAYMENT_CARD_DIGITS, MAX_PAYMENT_CARD_DIGITS],
        "payment_card_digit_alphabet": "ascii-0-9-with-nfkc-secondary-view",
        "payment_card_boundary_policy": "not-immediately-adjacent-to-ascii-digit",
        "payment_card_separator_policy": ("zero-or-one-ascii-space-or-hyphen-between-digits"),
        "payment_card_candidate_selection": ("per-start-longest-to-shortest-first-valid-luhn"),
        "email_syntax_bounds": {
            "local_characters": MAX_EMAIL_LOCAL_CHARS,
            "domain_prefix_characters": MAX_EMAIL_DOMAIN_PREFIX_CHARS,
            "top_level_domain_characters": MAX_EMAIL_TLD_CHARS,
        },
        "unicode_scan_normalization": "NFKC",
        "unicode_category_c_action": (
            "remove-with-tab-line-feed-carriage-return-normalized-to-space"
        ),
        "unicode_dash_action": "map-category-pd-and-u+2212-to-ascii-hyphen",
        "non_ascii_marker_policy": (
            "run-all-python-regex-detectors-and-url-python-ignorecase-equivalent-fold"
        ),
        "structured_mapping_action": (
            "treat-nonempty-value-under-sensitive-or-non-ascii-key-as-sensitive"
        ),
        "structured_mapping_key_expression": _SENSITIVE_MAPPING_KEY_DEFINITION.expression,
        "structured_mapping_key_flags": list(_SENSITIVE_MAPPING_KEY_DEFINITION.flags),
        "structured_mapping_key_normalization": "privacy-scan-views-then-ascii-fullmatch",
        "structured_mapping_non_ascii_key_action": (
            "treat-nonempty-non-redaction-sentinel-value-as-sensitive"
        ),
        "structured_mapping_value_exemptions": [
            "",
            PRIVACY_REDACTION_TEXT,
        ],
        "redaction_text": PRIVACY_REDACTION_TEXT,
        "max_scalar_characters": MAX_PRIVACY_SCAN_CHARS,
        "over_limit_action": "treat-sensitive-and-redact-entire-scalar",
        "detectors": [
            {
                "pattern_id": definition.pattern_id,
                "expression": definition.expression,
                "flags": list(definition.flags),
                "required_markers": list(_REQUIRED_MARKERS.get(definition.pattern_id, ())),
                "engine": (
                    "bounded-forward-scanner"
                    if definition.pattern_id == "url-query-secret"
                    else (
                        "bounded-forward-scanner-with-luhn-filter"
                        if definition.pattern_id == "payment-card-like-number"
                        else "python-re-unicode"
                    )
                ),
            }
            for definition in PRIVACY_DETECTOR_DEFINITIONS
        ],
    }


PRIVACY_PROFILE_DIGEST = hashlib.sha256(rfc8785.dumps(privacy_profile_manifest())).hexdigest()


def contains_sensitive_value(value: str) -> bool:
    if len(value) > MAX_PRIVACY_SCAN_CHARS:
        return True
    for scan_view in privacy_scan_views(value):
        if len(scan_view) > MAX_PRIVACY_SCAN_CHARS:
            return True
        if _scan_view_contains_sensitive(scan_view):
            return True
    return False


def _scan_view_contains_sensitive(value: str) -> bool:
    return (
        bool(payment_card_spans(value))
        or bool(url_query_secret_spans(value))
        or any(pattern.search(value) is not None for pattern in sensitive_patterns_for(value))
    )


def payment_card_spans(value: str) -> tuple[tuple[int, int], ...]:
    """Return bounded card-shaped spans that satisfy the Luhn checksum.

    ASCII-digit lookarounds reject candidates embedded in a longer contiguous
    digit run without relying on Unicode word-boundary semantics. At each
    possible start, all supported lengths are checked longest-first so a valid
    PAN is still found when a following space- or hyphen-separated numeric
    field makes the greedily shaped 19-digit candidate fail Luhn.
    """
    if not value or len(value) > MAX_PRIVACY_SCAN_CHARS:
        return ()
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(value):
        if not _is_ascii_digit(value[index]) or (index > 0 and _is_ascii_digit(value[index - 1])):
            index += 1
            continue

        digit_positions: list[int] = []
        cursor = index
        while cursor < len(value) and len(digit_positions) < MAX_PAYMENT_CARD_DIGITS:
            if not _is_ascii_digit(value[cursor]):
                break
            digit_positions.append(cursor)
            cursor += 1
            if (
                cursor + 1 < len(value)
                and value[cursor] in " -"
                and _is_ascii_digit(value[cursor + 1])
            ):
                cursor += 1

        match_end: int | None = None
        for digit_count in range(
            len(digit_positions),
            MIN_PAYMENT_CARD_DIGITS - 1,
            -1,
        ):
            candidate_end = digit_positions[digit_count - 1] + 1
            if candidate_end < len(value) and _is_ascii_digit(value[candidate_end]):
                continue
            candidate = "".join(value[position] for position in digit_positions[:digit_count])
            if _passes_luhn(candidate):
                match_end = candidate_end
                break

        if match_end is None:
            index += 1
            continue
        spans.append((index, match_end))
        index = match_end
    return tuple(spans)


def _is_ascii_digit(character: str) -> bool:
    return "0" <= character <= "9"


def _passes_luhn(candidate: str) -> bool:
    digits = tuple(ord(character) - ord("0") for character in candidate if "0" <= character <= "9")
    if not MIN_PAYMENT_CARD_DIGITS <= len(digits) <= MAX_PAYMENT_CARD_DIGITS:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def url_query_secret_spans(value: str) -> tuple[tuple[int, int], ...]:
    """Return raw or percent-obfuscated URL-secret spans in original coordinates.

    Each scan view is linear and the fixed percent-decoding depth keeps total
    work bounded by a constant multiple of the scalar limit. Only credential
    syntax characters are decoded, so an encoded fragment or ampersand cannot
    silently change URL structure before a query parser would decode its keys.
    """
    if not value or len(value) > MAX_PRIVACY_SCAN_CHARS:
        return ()
    if "?" not in value:
        return ()
    folded = value.translate(_URL_IGNORECASE_TRANSLATION)
    if "http://" not in folded and "https://" not in folded:
        return ()
    markers = _REQUIRED_MARKERS["url-query-secret"]
    if not any(required_marker in folded for required_marker in markers) and "%" not in value:
        return ()

    spans = list(_url_query_secret_spans_in_view(value))
    if "%" not in value:
        return tuple(spans)

    decoded = value
    source_spans = tuple((index, index + 1) for index in range(len(value)))
    for _ in range(URL_QUERY_SECRET_PERCENT_DECODE_DEPTH):
        decoded, source_spans, changed = _percent_decode_url_credential_view(
            decoded,
            source_spans,
        )
        if not changed:
            break
        for start, end in _url_query_secret_spans_in_view(decoded):
            spans.append((source_spans[start][0], source_spans[end - 1][1]))
    return _merge_overlapping_spans(spans)


def _url_query_secret_spans_in_view(value: str) -> tuple[tuple[int, int], ...]:
    folded = value.translate(_URL_IGNORECASE_TRANSLATION)
    if "?" not in value or ("http://" not in folded and "https://" not in folded):
        return ()
    markers = _REQUIRED_MARKERS["url-query-secret"]
    if not any(required_marker in folded for required_marker in markers):
        return ()
    length = len(value)
    marker_length_at = [0] * length
    for index in range(length):
        for required_marker in markers:
            if not folded.startswith(required_marker, index):
                continue
            value_start = index + len(required_marker)
            if value_start < length and not _is_url_value_boundary(value[value_start]):
                marker_length_at[index] = len(required_marker)
                break

    sentinel = length
    next_question = [sentinel] * (length + 1)
    next_token_boundary = [sentinel] * (length + 1)
    next_value_boundary = [sentinel] * (length + 1)
    next_marker = [sentinel] * (length + 1)
    question = token_boundary = value_boundary = marker_index = sentinel
    for index in range(length - 1, -1, -1):
        character = value[index]
        if character == "?":
            question = index
        if character == "#" or character.isspace():
            token_boundary = index
        if _is_url_value_boundary(character):
            value_boundary = index
        if marker_length_at[index]:
            marker_index = index
        next_question[index] = question
        next_token_boundary[index] = token_boundary
        next_value_boundary[index] = value_boundary
        next_marker[index] = marker_index

    spans: list[tuple[int, int]] = []
    consumed_through = 0
    index = 0
    while index < length:
        if folded.startswith("https://", index):
            scheme_length = 8
        elif folded.startswith("http://", index):
            scheme_length = 7
        else:
            index += 1
            continue
        if index < consumed_through:
            index += scheme_length
            continue
        path_start = index + scheme_length
        question = next_question[path_start]
        if (
            question == sentinel
            or question >= next_token_boundary[path_start]
            or question - path_start > 4096
        ):
            index += scheme_length
            continue
        query_start = question + 1
        url_end = next_token_boundary[query_start]
        marker_index = next_marker[query_start]
        if marker_index == sentinel or marker_index >= url_end or marker_index - query_start > 8192:
            index += scheme_length
            continue

        first_secret = True
        while (
            marker_index != sentinel
            and marker_index < url_end
            and marker_index - query_start <= 8192
        ):
            value_start = marker_index + marker_length_at[marker_index]
            match_end = next_value_boundary[value_start]
            spans.append((index if first_secret else marker_index, match_end))
            first_secret = False
            if match_end >= url_end:
                break
            marker_index = next_marker[match_end + 1]

        consumed_through = url_end
        index = url_end
    return tuple(spans)


def _percent_decode_url_credential_view(
    value: str,
    source_spans: tuple[tuple[int, int], ...],
) -> tuple[str, tuple[tuple[int, int], ...], bool]:
    characters: list[str] = []
    decoded_spans: list[tuple[int, int]] = []
    changed = False
    index = 0
    while index < len(value):
        first_byte = _percent_encoded_byte_at(value, index)
        sequence_length = _utf8_sequence_length(first_byte)
        encoded_end = index + (sequence_length * 3)
        if sequence_length and encoded_end <= len(value):
            encoded_bytes: list[int] = []
            for byte_index in range(sequence_length):
                decoded_byte = _percent_encoded_byte_at(value, index + (byte_index * 3))
                if decoded_byte is None:
                    break
                encoded_bytes.append(decoded_byte)
            if len(encoded_bytes) == sequence_length:
                try:
                    decoded_character = bytes(encoded_bytes).decode("utf-8")
                except UnicodeDecodeError:
                    decoded_character = ""
                canonical = _canonical_url_credential_character(decoded_character)
                if canonical is not None:
                    original_span = (source_spans[index][0], source_spans[encoded_end - 1][1])
                    characters.extend(canonical)
                    decoded_spans.extend(original_span for _ in canonical)
                    index = encoded_end
                    changed = True
                    continue
        characters.append(value[index])
        decoded_spans.append(source_spans[index])
        index += 1
    return "".join(characters), tuple(decoded_spans), changed


def _percent_encoded_byte_at(value: str, index: int) -> int | None:
    if index + 2 >= len(value) or value[index] != "%":
        return None
    try:
        return int(value[index + 1 : index + 3], 16)
    except ValueError:
        return None


def _utf8_sequence_length(first_byte: int | None) -> int:
    if first_byte is None:
        return 0
    if first_byte <= 0x7F:
        return 1
    if 0xC2 <= first_byte <= 0xDF:
        return 2
    if 0xE0 <= first_byte <= 0xEF:
        return 3
    if 0xF0 <= first_byte <= 0xF4:
        return 4
    return 0


def _canonical_url_credential_character(character: str) -> str | None:
    if not character:
        return None
    if character in _PRIVACY_SCAN_SAFE_WHITESPACE_CONTROLS:
        normalized = " "
    elif unicodedata.category(character).startswith("C"):
        normalized = ""
    elif character != "-" and (unicodedata.category(character) == "Pd" or character == "\u2212"):
        normalized = "-"
    else:
        normalized = unicodedata.normalize("NFKC", character)
    folded = normalized.translate(_URL_IGNORECASE_TRANSLATION)
    if all(item in _URL_PERCENT_DECODE_CHARACTERS for item in folded):
        return folded
    return None


def _merge_overlapping_spans(spans: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    if not spans:
        return ()
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _is_url_value_boundary(character: str) -> bool:
    return character in "&#" or character.isspace()


def contains_sensitive_mapping_entry(key: str, value: str) -> bool:
    """Detect secrets split across a structured mapping key and scalar value.

    Every non-empty value under a recognized ASCII sensitive label is treated
    as sensitive, regardless of value length. Non-ASCII mapping keys fail
    closed because partial confusable tables create bypasses. The exact
    canonical redaction sentinel and empty values remain stable on a second
    privacy pass.
    """
    if len(key) > MAX_PRIVACY_SCAN_CHARS:
        return True
    if value in {"", PRIVACY_REDACTION_TEXT}:
        return False
    if not key.isascii():
        return True
    return any(
        _SENSITIVE_MAPPING_KEY_PATTERN.fullmatch(key_view.strip())
        for key_view in privacy_scan_views(key)
    )


def privacy_scan_views(value: str) -> tuple[str, ...]:
    """Return raw and bounded deobfuscated views used by privacy detectors.

    Category-C characters can split a visually contiguous credential or
    identifier without changing what an operator perceives. Unicode dash
    punctuation and the mathematical minus sign can likewise disguise SSNs
    and card-like numbers. Ordinary text whitespace controls become spaces;
    all other category-C code points are removed, dash equivalents become an
    ASCII hyphen, and the result is compatibility-normalized for a second
    scan. The original value is never mutated for persistence.
    """
    if len(value) > MAX_PRIVACY_SCAN_CHARS:
        return (value,)
    normalized_characters: list[str] = []
    changed = False
    for character in value:
        if character in _PRIVACY_SCAN_SAFE_WHITESPACE_CONTROLS:
            normalized_characters.append(" ")
            changed = True
        elif unicodedata.category(character).startswith("C"):
            changed = True
        elif character != "-" and (
            unicodedata.category(character) == "Pd" or character == "\u2212"
        ):
            normalized_characters.append("-")
            changed = True
        else:
            normalized_characters.append(character)
    deobfuscated = unicodedata.normalize("NFKC", "".join(normalized_characters))
    if len(deobfuscated) > MAX_PRIVACY_SCAN_CHARS:
        return (value, deobfuscated)
    if not changed and deobfuscated == value:
        return (value,)
    return (value, deobfuscated)


def sensitive_patterns_for(value: str) -> tuple[re.Pattern[str], ...]:
    """Return detectors whose mandatory literal marker is present in ``value``."""
    # Python's Unicode IGNORECASE accepts a small set of non-ASCII characters
    # as equivalents of ASCII letters (for example dotless-i), while lower()
    # does not necessarily turn those characters into the ASCII spelling used
    # by the marker table. Conservatively run every detector for non-ASCII
    # scalars so the optimization can never change detection semantics.
    if not value.isascii():
        return SENSITIVE_PATTERNS
    lowered = value.lower()
    return tuple(
        pattern
        for definition, pattern in zip(
            _REGEX_DETECTOR_DEFINITIONS,
            SENSITIVE_PATTERNS,
            strict=True,
        )
        if not (markers := _REQUIRED_MARKERS.get(definition.pattern_id))
        or any(marker in lowered for marker in markers)
    )
