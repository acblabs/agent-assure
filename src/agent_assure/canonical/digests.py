from __future__ import annotations

import hashlib
from typing import Any

from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.canonical.normalize import digest_projection


def sha256_hexdigest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(digest_projection(value))).hexdigest()
