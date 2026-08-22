from __future__ import annotations

from agent_assure.privacy.detectors import MAX_PRIVACY_SCAN_CHARS, privacy_scan_views
from agent_assure.privacy.redaction import redact_text


def sanitize_display_text(value: object) -> str:
    """Return bounded, locally redacted single-line display text.

    Persistence uses :func:`redact_text` directly and therefore keeps the
    profile's whole-scalar fail-closed behavior when only the deobfuscated view
    contains a detector match. A renderer has a different final-egress need:
    first materialize the exact profile-bound deobfuscated view that an operator
    could perceive, then perform ordinary ordered substitution on that view.
    This removes terminal/bidi controls, catches secrets reconstructed by their
    removal, and retains unrelated safe context.
    """
    raw = str(value)
    if len(raw) > MAX_PRIVACY_SCAN_CHARS:
        return redact_text(raw)
    display_view = privacy_scan_views(raw)[-1]
    normalized = " ".join(display_view.split())
    return redact_text(normalized)
