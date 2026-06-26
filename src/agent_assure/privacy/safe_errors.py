from __future__ import annotations

import hashlib
import traceback
from dataclasses import dataclass

from agent_assure.privacy.redaction import redact_text


@dataclass(frozen=True)
class SafeError:
    safe_category: str
    exception_class: str
    redacted_message: str
    redacted_stack_digest: str
    local_debug_reference: str

    @property
    def code(self) -> str:
        return self.safe_category

    @property
    def message(self) -> str:
        return self.redacted_message


def safe_error(
    safe_category: str,
    message: str,
    exc: BaseException | None = None,
) -> SafeError:
    exception_class = exc.__class__.__name__ if exc is not None else "Error"
    redacted_message = redact_text(message)
    stack_digest = _redacted_stack_digest(exc, redacted_message)
    return SafeError(
        safe_category=safe_category,
        exception_class=exception_class,
        redacted_message=redacted_message,
        redacted_stack_digest=stack_digest,
        local_debug_reference=f"debug-{stack_digest[:16]}",
    )


def _redacted_stack_digest(exc: BaseException | None, fallback: str) -> str:
    if exc is None:
        stack_text = fallback
    else:
        stack_text = "".join(
            traceback.format_exception(type(exc), exc, exc.__traceback__)
        )
    return hashlib.sha256(redact_text(stack_text).encode("utf-8")).hexdigest()
