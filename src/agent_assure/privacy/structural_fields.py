"""Privacy-probe support for already validated public Git identifiers."""

from __future__ import annotations

import re
from typing import Final

from agent_assure.privacy.digest_fields import is_sha256_hex_digest

_GIT_REVISION_PATTERN: Final = re.compile(r"^[a-f0-9]{40}$")
PRIVACY_PROBE_GIT_REVISION: Final = "a" * 40
PRIVACY_PROBE_SHA256_DIGEST: Final = "a" * 64


def is_canonical_git_revision(value: object) -> bool:
    """Return whether *value* is one full lowercase SHA-1-shaped Git object ID."""

    return isinstance(value, str) and _GIT_REVISION_PATTERN.fullmatch(value) is not None


def git_revision_privacy_probe(value: str) -> str:
    """Replace a canonical Git ID only in a caller-authenticated privacy probe.

    This helper deliberately has no field-name based exemption. Callers must
    first validate a typed model or an exact artifact contract, then invoke it
    at an explicit path. Arbitrary packet fields remain fully privacy scanned.
    """

    return PRIVACY_PROBE_GIT_REVISION if is_canonical_git_revision(value) else value


def sha256_digest_privacy_probe(value: str) -> str:
    """Replace a canonical digest only in a caller-authenticated privacy probe."""

    return PRIVACY_PROBE_SHA256_DIGEST if is_sha256_hex_digest(value) else value


__all__ = [
    "PRIVACY_PROBE_GIT_REVISION",
    "PRIVACY_PROBE_SHA256_DIGEST",
    "git_revision_privacy_probe",
    "is_canonical_git_revision",
    "sha256_digest_privacy_probe",
]
