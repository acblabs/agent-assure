"""Shared fail-closed scan for strings crossing durable artifact boundaries."""

from __future__ import annotations

import re
from collections.abc import Mapping

from agent_assure.privacy.credential_uri import (
    PERSISTED_CREDENTIAL_NAMES,
    PERSISTED_CREDENTIAL_SUFFIXES,
    CredentialScanLimitError,
    contains_persisted_credential,
    durable_credential_scan_windows,
    matches_credential_name,
)
from agent_assure.privacy.detectors import MAX_PRIVACY_SCAN_CHARS
from agent_assure.privacy.digest_fields import is_digest_field_name, is_sha256_hex_digest

_SAFE_INPUT_SUMMARY_IDENTIFIER = r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"
_SAFE_INPUT_SUMMARY_PATTERN = re.compile(
    rf"^case={_SAFE_INPUT_SUMMARY_IDENTIFIER}; "
    r"(?P<pseudonym>(?:subject_token|employee_token)=[a-f0-9]{32}); "
    rf"fixture={_SAFE_INPUT_SUMMARY_IDENTIFIER}"
    rf"(?:; query_digest=[a-f0-9]{{64}}; "
    rf"corpus_version={_SAFE_INPUT_SUMMARY_IDENTIFIER})?$"
)
_SAFE_CREDENTIAL_POLICY_KEYS = frozenset(
    {
        "credentials_source",
        "persist_credentials",
        "persist_credential_digests",
        "publish_credentials",
    }
)


class UnsafePersistedTextError(ValueError):
    """Raised without echoing the sensitive candidate."""


def persisted_credential_scan_value(value: str, *, field_name: str | None) -> str:
    """Neutralize only the canonical pseudonym in an approved input summary.

    The full-string grammar remains deliberately narrow. Callers still scan
    every other byte, including any suffix or malformed token assignment.
    """

    if field_name != "input_summary":
        return value
    match = _SAFE_INPUT_SUMMARY_PATTERN.fullmatch(value)
    if match is None:
        return value
    start, end = match.span("pseudonym")
    return value[:start] + "privacy_safe_pseudonym=opaque" + value[end:]


def assert_persisted_text_safe(
    value: object,
    *,
    owner: str,
    field_name: str | None = None,
) -> None:
    """Recursively reject sensitive scalars, credential names, and credential URIs."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            key_name = key if isinstance(key, str) else None
            if key_name is not None and is_unsafe_persisted_mapping_key(key_name):
                raise UnsafePersistedTextError(
                    f"{owner} contains a sensitive or credential-bearing mapping key"
                )
            assert_persisted_text_safe(
                item,
                owner=owner,
                field_name=key_name,
            )
        return
    if isinstance(value, tuple | list):
        for item in value:
            assert_persisted_text_safe(
                item,
                owner=owner,
                field_name=field_name,
            )
        return
    if not isinstance(value, str):
        return
    if field_name is not None and is_digest_field_name(field_name) and is_sha256_hex_digest(value):
        return
    credential_scan_value = persisted_credential_scan_value(value, field_name=field_name)
    try:
        has_credential = contains_persisted_credential(
            credential_scan_value,
            exact_names=PERSISTED_CREDENTIAL_NAMES,
            suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
        )
    except CredentialScanLimitError as exc:
        raise UnsafePersistedTextError(
            f"{owner} could not complete its bounded credential scan"
        ) from exc
    if has_credential:
        raise UnsafePersistedTextError(f"{owner} contains sensitive or credential material")


def assert_persisted_payload_safe(
    value: object,
    *,
    owner: str,
) -> None:
    """Reject any value that the durable-artifact privacy boundary would alter.

    The structural credential scan catches unsafe mapping keys and URI forms
    that are easy to miss when looking at scalar values in isolation. The
    idempotence check then applies the same packet redactor used at publication
    boundaries, including sensitive key/value pairs and ordinary PII.
    """

    assert_persisted_text_safe(value, owner=owner)
    # Import lazily so this low-level structural scanner remains usable by the
    # redaction implementation without creating an import cycle.
    from agent_assure.privacy.redaction import redact_packet_payload

    redaction_input = _bounded_redaction_probe(value)
    if redact_packet_payload(redaction_input) != redaction_input:
        raise UnsafePersistedTextError(f"{owner} contains values outside the privacy boundary")
    _assert_overlong_text_redaction_safe(value, owner=owner)


def _bounded_redaction_probe(value: object) -> object:
    """Replace only overlong scalar values before the structural redaction pass."""

    if isinstance(value, str):
        return "bounded-durable-text" if len(value) > MAX_PRIVACY_SCAN_CHARS else value
    if isinstance(value, Mapping):
        return {key: _bounded_redaction_probe(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_bounded_redaction_probe(item) for item in value)
    if isinstance(value, list):
        return [_bounded_redaction_probe(item) for item in value]
    return value


def _assert_overlong_text_redaction_safe(value: object, *, owner: str) -> None:
    """Apply the ordinary redactor to bounded windows of large documents."""

    if isinstance(value, Mapping):
        for item in value.values():
            _assert_overlong_text_redaction_safe(item, owner=owner)
        return
    if isinstance(value, tuple | list):
        for item in value:
            _assert_overlong_text_redaction_safe(item, owner=owner)
        return
    if not isinstance(value, str) or len(value) <= MAX_PRIVACY_SCAN_CHARS:
        return
    from agent_assure.privacy.redaction import redact_text

    try:
        windows = durable_credential_scan_windows(value)
    except CredentialScanLimitError as exc:
        raise UnsafePersistedTextError(
            f"{owner} could not complete its bounded privacy scan"
        ) from exc
    if any(redact_text(window) != window for window in windows):
        raise UnsafePersistedTextError(f"{owner} contains values outside the privacy boundary")


def is_unsafe_persisted_mapping_key(value: str) -> bool:
    """Return whether a durable mapping key violates the shared boundary."""

    if value in _SAFE_CREDENTIAL_POLICY_KEYS:
        return False
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return True
    return matches_credential_name(
        value,
        exact_names=PERSISTED_CREDENTIAL_NAMES,
        suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
    ) or contains_persisted_credential(
        value,
        exact_names=PERSISTED_CREDENTIAL_NAMES,
        suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
    )


__all__ = [
    "UnsafePersistedTextError",
    "assert_persisted_payload_safe",
    "assert_persisted_text_safe",
    "is_unsafe_persisted_mapping_key",
    "persisted_credential_scan_value",
]
