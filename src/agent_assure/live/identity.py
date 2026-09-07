"""Stable identities for the executable live-provider boundary."""

from __future__ import annotations

from typing import Final

from agent_assure import __version__

AGENT_ASSURE_EXECUTION_VERSION: Final = __version__
LIVE_ADAPTER_IMPLEMENTATION_ID: Final = "agent-assure/live-provider-adapters/v1"
LIVE_PROVIDER_REQUEST_ENVELOPE_ID: Final = "agent-assure/live-provider-request-envelope/v1"

__all__ = [
    "AGENT_ASSURE_EXECUTION_VERSION",
    "LIVE_ADAPTER_IMPLEMENTATION_ID",
    "LIVE_PROVIDER_REQUEST_ENVELOPE_ID",
]
