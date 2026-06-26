from __future__ import annotations

from agent_assure.policies.catalog import DEFAULT_NOT_EVALUATED_CAPABILITIES, CapabilityStatus


def default_not_evaluated_capabilities() -> tuple[CapabilityStatus, ...]:
    return DEFAULT_NOT_EVALUATED_CAPABILITIES
