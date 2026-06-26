from __future__ import annotations

from dataclasses import dataclass

from agent_assure.privacy.redaction import redact_text


@dataclass(frozen=True)
class SafeError:
    code: str
    message: str


def safe_error(code: str, message: str) -> SafeError:
    return SafeError(code=code, message=redact_text(message))
