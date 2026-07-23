from __future__ import annotations

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.mutation.operators import MutationTarget
from agent_assure.schema.mutation import RFC8785_SAFE_INTEGER_MAX


def select_target(
    targets: tuple[MutationTarget, ...],
    *,
    source_digest: str,
    operator_id: str,
    operator_version: str,
    seed: int,
) -> MutationTarget | None:
    """Select one applicable target with a stable digest-derived ordering."""
    if seed < 0 or seed > RFC8785_SAFE_INTEGER_MAX:
        raise ValueError(f"mutation seed must be between 0 and {RFC8785_SAFE_INTEGER_MAX}")
    if not targets:
        return None
    return min(
        targets,
        key=lambda target: (
            sha256_hexdigest(
                {
                    "source_digest": source_digest,
                    "operator_id": operator_id,
                    "operator_version": operator_version,
                    "seed": seed,
                    "target_identity": target.identity,
                }
            ),
            target.identity,
        ),
    )
