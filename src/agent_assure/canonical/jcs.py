from __future__ import annotations

from typing import Any

import rfc8785


def canonical_bytes(projected: Any) -> bytes:
    result = rfc8785.dumps(projected)
    if isinstance(result, bytes):
        return result
    return result.encode("utf-8")
