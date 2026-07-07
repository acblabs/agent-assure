"""Experimental framework adapter surface.

The adapter API is intentionally narrow and experimental. Adapters translate
framework event streams into existing agent-assure artifacts; evaluation remains
framework-neutral.
"""

from agent_assure.adapters.base import (
    EXPERIMENTAL_ADAPTER_API,
    FrameworkAdapter,
    FrameworkObservation,
    FrameworkRunProjection,
    build_run_record_from_observations,
    stable_observation_id,
)
from agent_assure.adapters.langgraph import LangGraphAdapter

__all__ = [
    "EXPERIMENTAL_ADAPTER_API",
    "FrameworkAdapter",
    "FrameworkObservation",
    "FrameworkRunProjection",
    "LangGraphAdapter",
    "build_run_record_from_observations",
    "stable_observation_id",
]
