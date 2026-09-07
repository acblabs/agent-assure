from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from functools import lru_cache
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from agent_assure.privacy.detectors import (
    MAX_PRIVACY_SCAN_CHARS,
    contains_sensitive_value,
    privacy_scan_views,
)

_MAX_URI_SCAN_CHARS = MAX_PRIVACY_SCAN_CHARS
_MAX_URI_SCAN_WORK_ITEMS = 128
# Durable rendered reports are larger than an individual schema scalar. The
# ceiling covers a report at every declared study bound (including all failure
# summaries and observed identities), while remaining far below the enclosing
# bundle limit. Scan as overlapping, regex-bounded windows so memory use stays
# proportional to the scalar detector bound rather than to this ceiling.
MAX_DURABLE_CREDENTIAL_SCAN_CHARS = 32 * 1024 * 1024
_DURABLE_SCAN_STEP_CHARS = 4_096
_MAX_DURABLE_URI_CANDIDATES = 4_096
_MAX_DURABLE_SCAN_FIELDS = 32_768
_DURABLE_LINE_BREAK = re.compile(r"\r\n|[\n\v\f\r\x1c-\x1e\x85\u2028\u2029]")
_PATH_CONFUSED_USERINFO = re.compile(
    r"^(?:/{2,}|[a-z][a-z0-9+.-]*:/+)[^/?#@:\s]+:[^/?#@\s]*@",
    flags=re.IGNORECASE,
)
_PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", flags=re.IGNORECASE)
_STRUCTURAL_NAME_CASE_EQUIVALENTS = frozenset("İıſK")
_SECRET_LITERAL_PATTERNS = (
    re.compile(r"(?i)^sk-[a-z0-9_-]{16,}$"),
    re.compile(r"(?i)^(?:gh[opusr]|github_pat)_[a-z0-9_]{20,}$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
)
_SECRET_SEARCH_PATTERNS = (
    re.compile(r"(?i)\bsk-(?:proj-)?[a-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\b(?:gh[opusr]|github_pat)_[a-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
PERSISTED_CREDENTIAL_NAMES = frozenset(
    {
        "access-key",
        "access-token",
        "api-key",
        "apikey",
        "auth-token",
        "authorization",
        "bearer-token",
        "client-password",
        "client-secret",
        "credential",
        "credentials",
        "oauth2-bearer",
        "password",
        "passwd",
        "private-key",
        "proxy-authorization",
        "proxy-password",
        "proxy-user",
        "refresh-token",
        "secret",
        "secret-access-key",
        "session-token",
        "sig",
        "signature",
        "subscription-key",
        "token",
        "user",
    }
)
PERSISTED_CREDENTIAL_SUFFIXES = frozenset(
    {
        "access-key",
        "access-token",
        "api-key",
        "auth-token",
        "bearer-token",
        "client-password",
        "client-secret",
        "credential",
        "credentials",
        "password",
        "proxy-password",
        "refresh-token",
        "secret",
        "secret-access-key",
        "session-token",
        "signature",
        "subscription-key",
        "token",
    }
)
SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-api-key",
    }
)


class CredentialScanLimitError(ValueError):
    """Credential scanning could not finish inside its public bounds.

    The exception deliberately carries no candidate text, so callers can fail
    closed without reporting scan exhaustion as detected credential material.
    """


def _looks_like_nested_uri_candidate(value: str) -> bool:
    return bool(
        _PATH_CONFUSED_USERINFO.search(value)
        or _PERCENT_ESCAPE.search(value)
        or any(marker in value for marker in ("://", "//", "?", "#", "=", ";", "@"))
    )


def _durable_scan_windows(value: str) -> Iterator[str]:
    """Yield overlapping detector windows for one bounded durable scalar."""

    if len(value) > MAX_DURABLE_CREDENTIAL_SCAN_CHARS:
        raise CredentialScanLimitError(
            "credential scan exceeds the maximum supported durable-text size"
        )
    if len(value) <= MAX_PRIVACY_SCAN_CHARS:
        yield value
        return
    for offset in range(0, len(value), _DURABLE_SCAN_STEP_CHARS):
        yield value[offset : offset + MAX_PRIVACY_SCAN_CHARS]


def durable_credential_scan_windows(value: str) -> Iterator[str]:
    """Expose the exact bounded windows used for durable-text privacy scans."""

    return _durable_scan_windows(value)


def _durable_scan_fields(value: str) -> Iterator[str]:
    """Yield ``splitlines``-equivalent fields after a bounded preflight.

    Preflighting before yielding preserves the original error precedence while
    avoiding an attacker-sized temporary list. The expression covers every
    boundary recognized by ``str.splitlines()``, with CRLF treated as one.
    """

    field_count = 0
    final_break_end = 0
    for match in _DURABLE_LINE_BREAK.finditer(value):
        field_count += 1
        if field_count > _MAX_DURABLE_SCAN_FIELDS:
            raise CredentialScanLimitError(
                "credential scan exceeds the maximum supported field budget"
            )
        final_break_end = match.end()
    if not value or final_break_end < len(value):
        field_count += 1
        if field_count > _MAX_DURABLE_SCAN_FIELDS:
            raise CredentialScanLimitError(
                "credential scan exceeds the maximum supported field budget"
            )

    cursor = 0
    for match in _DURABLE_LINE_BREAK.finditer(value):
        yield value[cursor : match.start()]
        cursor = match.end()
    if cursor < len(value):
        yield value[cursor:]
    elif not value:
        yield value


def _uri_candidates(value: str) -> tuple[str, ...]:
    """Extract bounded URI-shaped tokens without parsing a whole document."""

    candidates: list[str] = []
    for match in re.finditer(r"[^\s<>`\"']+", value):
        candidate = match.group(0).strip("()[]{},.")
        # A Markdown heading or ordinary fragment marker is not independently
        # URI-shaped. A fragment containing an assignment still enters through
        # ``=`` and is scanned.
        if candidate and (
            _PATH_CONFUSED_USERINFO.search(candidate)
            or _PERCENT_ESCAPE.search(candidate)
            or any(marker in candidate for marker in ("://", "//", "?", "=", ";", "@", "\\"))
        ):
            candidates.append(candidate)
            if len(candidates) > _MAX_DURABLE_URI_CANDIDATES:
                raise CredentialScanLimitError(
                    "credential URI scan exceeds the maximum supported work budget"
                )
    return tuple(candidates)


def matches_credential_name(
    value: str,
    *,
    exact_names: frozenset[str],
    suffixes: frozenset[str],
) -> bool:
    """Match separator-preserving and compact/camelCase credential names."""

    normalized = value.strip().casefold().replace("_", "-")
    compact = _compact_credential_term(normalized)
    if normalized in exact_names:
        return True
    if compact in _compact_credential_terms(exact_names):
        return True
    return any(
        normalized.endswith(separator_suffix) or compact.endswith(compact_suffix)
        for separator_suffix, compact_suffix in _credential_suffix_forms(suffixes)
    )


@lru_cache(maxsize=512)
def _compact_credential_term(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value)


@lru_cache(maxsize=64)
def _compact_credential_terms(values: frozenset[str]) -> frozenset[str]:
    return frozenset(_compact_credential_term(value.casefold()) for value in values)


@lru_cache(maxsize=64)
def _credential_suffix_forms(
    values: frozenset[str],
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted((f"-{value}", _compact_credential_term(value.casefold())) for value in values)
    )


def contains_credential_literal(value: str) -> bool:
    """Detect high-confidence credential literals without general PII heuristics."""

    return any(pattern.search(value) is not None for pattern in _SECRET_SEARCH_PATTERNS)


def _is_exact_credential_name(value: str, exact_names: frozenset[str]) -> bool:
    normalized = value.strip().casefold().replace("_", "-")
    compact = _compact_credential_term(normalized)
    return normalized in exact_names or compact in _compact_credential_terms(exact_names)


def _credential_field_has_value(
    name: str,
    field_value: str,
    *,
    exact_names: frozenset[str],
    is_credential_name: Callable[[str], bool],
) -> bool:
    """Disambiguate prose labels from suffix-derived credential fields."""

    if _is_exact_credential_name(name, exact_names):
        return True
    return len(field_value.strip()) >= 8 and is_credential_name(name)


def _contains_structural_credential_field(
    value: str,
    *,
    exact_names: frozenset[str],
    is_credential_name: Callable[[str], bool],
) -> bool:
    """Scan structural assignments once, including across detector windows.

    Candidate names remain bounded to the original 128 characters, and each
    input character participates in at most a constant amount of work. This
    preserves the regex contract without requiring a credential label and its
    value to fit in the same ``MAX_PRIVACY_SCAN_CHARS`` window.
    """

    def is_name_start(character: str) -> bool:
        # Match Python ``re.IGNORECASE`` semantics for ``[a-z]``: ASCII letters
        # plus the four Unicode case-equivalent code points documented by ``re``.
        return (character.isascii() and character.isalpha()) or (
            character in _STRUCTURAL_NAME_CASE_EQUIVALENTS
        )

    def is_name_character(character: str) -> bool:
        return (
            is_name_start(character)
            or character.isascii()
            and (character.isdigit() or character in "_.-")
        )

    value_length = len(value)
    for start in range(value_length):
        if start > 0 and value[start - 1] not in "\n,{":
            continue
        cursor = start
        while cursor < value_length and value[cursor] in " \t":
            cursor += 1
        if cursor < value_length and value[cursor] in "\"'":
            cursor += 1
        name_start = cursor
        if cursor >= value_length or not is_name_start(value[cursor]):
            continue
        cursor += 1
        while (
            cursor < value_length and cursor - name_start < 128 and is_name_character(value[cursor])
        ):
            cursor += 1
        if cursor < value_length and is_name_character(value[cursor]):
            continue
        name = value[name_start:cursor]
        if cursor < value_length and value[cursor] in "\"'":
            cursor += 1
        while cursor < value_length and value[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= value_length or value[cursor] not in ":=":
            continue
        cursor += 1
        if _is_exact_credential_name(name, exact_names):
            return True
        if not is_credential_name(name):
            continue
        while cursor < value_length and value[cursor] in " \t\r\n":
            cursor += 1
        field_value_length = 0
        while (
            cursor < value_length
            and not value[cursor].isspace()
            and value[cursor] not in ",;"
            and field_value_length < 8
        ):
            cursor += 1
            field_value_length += 1
        if field_value_length >= 8:
            return True
    return False


def contains_credential_uri(
    value: str,
    *,
    is_credential_name: Callable[[str], bool],
) -> bool:
    """Detect credential material in absolute, relative, or nested URI references."""

    if len(value) > _MAX_URI_SCAN_CHARS:
        raise CredentialScanLimitError(
            "credential URI scan exceeds the maximum supported scalar size"
        )
    pending = [value]
    seen: set[str] = set()
    work_items = 0
    while pending:
        if work_items >= _MAX_URI_SCAN_WORK_ITEMS:
            raise CredentialScanLimitError(
                "credential URI scan exceeds the maximum supported work budget"
            )
        candidate = pending.pop()
        if candidate in seen:
            continue
        seen.add(candidate)
        work_items += 1
        if len(candidate) > _MAX_URI_SCAN_CHARS:
            raise CredentialScanLimitError(
                "credential URI scan exceeds the maximum supported scalar size"
            )
        # Security-sensitive URL consumers do not agree on parsing. WHATWG
        # special-scheme parsers treat backslashes as path separators, while
        # Unicode compatibility characters can normalize into URI delimiters.
        # Scan every bounded interpretation without changing persisted text.
        for scan_view in privacy_scan_views(candidate):
            if scan_view != candidate:
                pending.append(scan_view)
            slash_view = scan_view.replace("\\", "/")
            if slash_view != candidate and slash_view != scan_view:
                pending.append(slash_view)
        if _PATH_CONFUSED_USERINFO.search(candidate):
            return True
        decoded = unquote_plus(candidate)
        if decoded != candidate:
            pending.append(decoded)
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            # Malformed URI-like values cannot be safely decomposed for persistence.
            return True
        if parsed.username is not None or parsed.password is not None:
            return True
        for segment in re.split(r"[/;]", parsed.path):
            key, separator, nested_value = segment.partition("=")
            if not separator:
                continue
            if is_credential_name(key):
                return True
            if nested_value and _looks_like_nested_uri_candidate(nested_value):
                pending.append(nested_value)
        for component in (parsed.query, parsed.fragment):
            if not component:
                continue
            try:
                items = parse_qsl(
                    component.replace(";", "&"),
                    keep_blank_values=True,
                    strict_parsing=False,
                )
            except ValueError:
                return True
            for key, nested_value in items:
                if is_credential_name(key):
                    return True
                if nested_value and _looks_like_nested_uri_candidate(nested_value):
                    pending.append(nested_value)
            if _looks_like_nested_uri_candidate(component):
                pending.append(component)
    return False


def _contains_persisted_credential_scalar(
    value: str,
    *,
    exact_names: frozenset[str],
    suffixes: frozenset[str],
    sensitive_header_names: frozenset[str],
    scan_sensitive_values: bool = True,
) -> bool:
    """Apply scalar, structural-URI, header, and literal checks uniformly.

    The caller supplies its credential-name vocabulary so command/config
    surfaces can remain closed without duplicating the security-sensitive
    detection algorithm.
    """

    def is_credential_name(name: str) -> bool:
        return matches_credential_name(
            name,
            exact_names=exact_names,
            suffixes=suffixes,
        )

    stripped = value.strip()
    folded = stripped.casefold()
    header_name, header_separator, header_value = stripped.partition(":")
    normalized_header_name = header_name.strip().casefold().replace("_", "-")
    assignment_name, assignment_separator, assignment_value = stripped.partition("=")
    normalized_assignment_name = assignment_name.casefold().replace("_", "-")
    return bool(
        (scan_sensitive_values and contains_sensitive_value(value))
        or (
            any(
                contains_credential_uri(candidate, is_credential_name=is_credential_name)
                for scan_view in privacy_scan_views(value)
                for candidate in _uri_candidates(scan_view)
            )
        )
        or (
            header_separator
            and (
                normalized_header_name in sensitive_header_names
                or _credential_field_has_value(
                    normalized_header_name,
                    header_value,
                    exact_names=exact_names,
                    is_credential_name=is_credential_name,
                )
            )
        )
        or folded.startswith(("basic ", "bearer "))
        or ("-----begin " in folded and "private key-----" in folded)
        or any(pattern.fullmatch(stripped) for pattern in _SECRET_LITERAL_PATTERNS)
        or (
            assignment_separator
            and assignment_value
            and not assignment_name.startswith("-")
            and _credential_field_has_value(
                normalized_assignment_name,
                assignment_value,
                exact_names=exact_names,
                is_credential_name=is_credential_name,
            )
        )
    )


def contains_persisted_credential(
    value: str,
    *,
    exact_names: frozenset[str],
    suffixes: frozenset[str],
    sensitive_header_names: frozenset[str] = SENSITIVE_HEADER_NAMES,
    scan_sensitive_values: bool = True,
) -> bool:
    """Scan one bounded durable scalar without treating limits as findings."""

    def is_credential_name(name: str) -> bool:
        return matches_credential_name(
            name,
            exact_names=exact_names,
            suffixes=suffixes,
        )

    for window in _durable_scan_windows(value):
        if scan_sensitive_values:
            if any(
                len(scan_view) > MAX_PRIVACY_SCAN_CHARS for scan_view in privacy_scan_views(window)
            ):
                raise CredentialScanLimitError(
                    "credential scan normalization exceeds the supported scalar size"
                )
            if contains_sensitive_value(window):
                return True
    if _contains_structural_credential_field(
        value,
        exact_names=exact_names,
        is_credential_name=is_credential_name,
    ):
        return True

    for field in _durable_scan_fields(value):
        for field_window in _durable_scan_windows(field):
            if _contains_persisted_credential_scalar(
                field_window,
                exact_names=exact_names,
                suffixes=suffixes,
                sensitive_header_names=sensitive_header_names,
                scan_sensitive_values=False,
            ):
                return True
    return False


__all__ = [
    "CredentialScanLimitError",
    "MAX_DURABLE_CREDENTIAL_SCAN_CHARS",
    "PERSISTED_CREDENTIAL_NAMES",
    "PERSISTED_CREDENTIAL_SUFFIXES",
    "SENSITIVE_HEADER_NAMES",
    "contains_credential_literal",
    "contains_credential_uri",
    "contains_persisted_credential",
    "durable_credential_scan_windows",
    "matches_credential_name",
]
