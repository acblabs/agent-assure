"""Closed v1 identity values; no writer registration or authority is implied."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import StringConstraints

from agent_assure.schema.base import FrozenStrictModel

SourceIdentityComponent = Annotated[
    str, StringConstraints(strict=True, min_length=1, max_length=512)
]


class SourceEventIdentity(FrozenStrictModel):
    """The exact five-field identity defined by ADR-V1-SCHEMA.

    Components retain their original Unicode, case and whitespace. This value
    has no persisted-artifact envelope, implicit discriminator or self-digest;
    a consumer must bind all components rather than concatenate delimiters.
    """

    identity_contract_id: Literal["source-event-identity/v1"]
    run_id: SourceIdentityComponent
    producer_id: SourceIdentityComponent
    producer_epoch: SourceIdentityComponent
    event_id: SourceIdentityComponent
