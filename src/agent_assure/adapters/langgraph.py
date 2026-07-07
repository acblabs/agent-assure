from __future__ import annotations

from collections.abc import Iterable, Mapping
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from agent_assure.adapters.base import (
    FrameworkObservation,
    FrameworkRunProjection,
    build_run_record_from_observations,
    stable_observation_id,
    validate_no_raw_payload_keys,
)
from agent_assure.schema.common import DigestHex
from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.usage import UsageSegment

AGENT_ASSURE_METADATA_KEY = "agent_assure"
RESERVED_EVENT_KEYS = frozenset(
    {
        "data",
        "event",
        "metadata",
        "name",
        "parent_ids",
        "run_id",
        "tags",
    }
)


class LangGraphAdapter:
    adapter_id = "experimental-langgraph"
    framework = "langgraph"
    experimental = True

    def __init__(self, *, framework_version: str | None = None) -> None:
        self._framework_version = framework_version or _installed_langgraph_version()

    @property
    def framework_version(self) -> str | None:
        return self._framework_version

    def observations_from_events(
        self,
        events: Iterable[object],
        *,
        run_id: str | None = None,
        case_id: str | None = None,
    ) -> tuple[FrameworkObservation, ...]:
        observations: list[FrameworkObservation] = []
        for raw_event in events:
            event = _normalize_event(raw_event)
            for node_name, agent_metadata in _agent_assure_metadata_items(event):
                if not agent_metadata:
                    raise ValueError("LangGraph agent_assure metadata must not be empty")
                validate_no_raw_payload_keys(
                    agent_metadata,
                    owner="LangGraph agent_assure metadata",
                )
                observed_run_id = _required_string(
                    _metadata_value(agent_metadata, "run_id")
                    or run_id
                    or _string(event.get("run_id"))
                    or "langgraph-run"
                )
                event_type = _required_string(
                    _metadata_value(agent_metadata, "event_type")
                    or _string(event.get("event"))
                    or "node_update"
                )
                sequence_number = _sequence_number(agent_metadata, len(observations) + 1)
                observed_node_name = (
                    _string(_metadata_value(agent_metadata, "node_name"))
                    or _metadata_node_name(event)
                    or node_name
                    or _string(event.get("name"))
                )
                node_id = _string(_metadata_value(agent_metadata, "node_id"))
                observation_id = _string(_metadata_value(agent_metadata, "observation_id"))
                if observation_id is None:
                    observation_id = stable_observation_id(
                        framework=self.framework,
                        run_id=observed_run_id,
                        sequence_number=sequence_number,
                        event_type=event_type,
                        node_name=observed_node_name,
                        node_id=node_id,
                    )
                observations.append(
                    FrameworkObservation(
                        observation_id=observation_id,
                        framework=self.framework,
                        framework_version=_string(
                            _metadata_value(agent_metadata, "framework_version"),
                            self.framework_version,
                        ),
                        run_id=observed_run_id,
                        case_id=_string(_metadata_value(agent_metadata, "case_id"), case_id),
                        sequence_number=sequence_number,
                        timestamp=_string(_metadata_value(agent_metadata, "timestamp")),
                        node_id=node_id,
                        node_name=observed_node_name,
                        event_type=event_type,
                        provider=_string(_metadata_value(agent_metadata, "provider")),
                        model=_string(_metadata_value(agent_metadata, "model")),
                        tool_name=_string(_metadata_value(agent_metadata, "tool_name")),
                        review_route=_string(_metadata_value(agent_metadata, "review_route")),
                        evidence_refs=_string_sequence(
                            _metadata_value(agent_metadata, "evidence_refs")
                        ),
                        redaction_state=_string(
                            _metadata_value(agent_metadata, "redaction_state")
                        ),
                        usage_segment=_usage_segment(agent_metadata),
                        span_context=_span_context(event, agent_metadata),
                        privacy_filtered_attributes=_string_mapping(
                            _metadata_value(agent_metadata, "privacy_filtered_attributes")
                        ),
                    )
                )
        return tuple(observations)

    def observations_from_graph_stream(
        self,
        graph: object,
        input_state: Mapping[str, object],
        *,
        run_id: str,
        case_id: str | None = None,
    ) -> tuple[FrameworkObservation, ...]:
        stream = getattr(graph, "stream", None)
        if not callable(stream):
            raise TypeError("LangGraph compiled graph must expose a callable stream method")
        state = dict(input_state)
        if case_id is not None:
            state.setdefault("case_id", case_id)
        events = stream(state, stream_mode="updates", config={"run_id": run_id})
        return self.observations_from_events(events, run_id=run_id, case_id=case_id)

    def run_record_from_events(
        self,
        events: Iterable[object],
        *,
        projection: FrameworkRunProjection,
        run_id: str,
        case_id: str,
        fixture_manifest_digest: DigestHex,
        configuration_digest: DigestHex | None = None,
    ) -> AgentRunRecord:
        observations = self.observations_from_events(events, run_id=run_id, case_id=case_id)
        return build_run_record_from_observations(
            observations,
            projection=projection,
            run_id=run_id,
            case_id=case_id,
            fixture_manifest_digest=fixture_manifest_digest,
            configuration_digest=configuration_digest,
        )


def _installed_langgraph_version() -> str | None:
    try:
        return version("langgraph")
    except PackageNotFoundError:
        return None


def _normalize_event(raw_event: object) -> Mapping[str, object]:
    if isinstance(raw_event, Mapping):
        return {str(key): value for key, value in raw_event.items()}
    if isinstance(raw_event, tuple | list) and len(raw_event) == 2:
        mode, payload = raw_event
        event: dict[str, object] = {"event": str(mode)}
        if isinstance(payload, Mapping):
            event.update({str(key): value for key, value in payload.items()})
        else:
            event["data"] = payload
        return event
    raise TypeError("LangGraph event must be a mapping or a two-item stream tuple")


def _agent_assure_metadata_items(
    event: Mapping[str, object],
) -> tuple[tuple[str | None, Mapping[str, object]], ...]:
    top_level = event.get(AGENT_ASSURE_METADATA_KEY)
    if isinstance(top_level, Mapping):
        return ((None, _string_key_mapping(top_level)),)
    metadata = event.get("metadata")
    if isinstance(metadata, Mapping):
        nested = metadata.get(AGENT_ASSURE_METADATA_KEY)
        if isinstance(nested, Mapping):
            return ((None, _string_key_mapping(nested)),)
    items: list[tuple[str | None, Mapping[str, object]]] = []
    for key, value in event.items():
        if key in RESERVED_EVENT_KEYS:
            continue
        if not isinstance(value, Mapping):
            continue
        nested = value.get(AGENT_ASSURE_METADATA_KEY)
        if isinstance(nested, Mapping):
            items.append((str(key), _string_key_mapping(nested)))
    if items:
        return tuple(items)
    return ()


def _metadata_node_name(event: Mapping[str, object]) -> str | None:
    metadata = event.get("metadata")
    if not isinstance(metadata, Mapping):
        return None
    for key in ("langgraph_node", "node", "node_name"):
        value = metadata.get(key)
        if isinstance(value, str):
            return value
    return None


def _span_context(
    event: Mapping[str, object],
    agent_metadata: Mapping[str, object],
) -> dict[str, str] | None:
    span_context = _string_mapping(agent_metadata.get("span_context"))
    framework_run_id = _string(event.get("run_id"))
    if framework_run_id is not None:
        span_context.setdefault("framework_run_id", framework_run_id)
    return span_context or None


def _usage_segment(agent_metadata: Mapping[str, object]) -> UsageSegment | None:
    payload = agent_metadata.get("usage_segment")
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise TypeError("LangGraph usage_segment metadata must be a mapping")
    return UsageSegment.model_validate(_string_key_mapping(payload))


def _metadata_value(agent_metadata: Mapping[str, object], key: str) -> object:
    return agent_metadata.get(key)


def _sequence_number(agent_metadata: Mapping[str, object], fallback: int) -> int:
    value = agent_metadata.get("sequence_number")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return fallback


def _string(value: object, default: str | None = None) -> str | None:
    return value if isinstance(value, str) else default


def _required_string(value: object) -> str:
    if isinstance(value, str) and value:
        return value
    raise ValueError("expected non-empty string")


def _string_sequence(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, tuple | list):
        if not all(isinstance(item, str) for item in value):
            raise TypeError("LangGraph string sequence metadata must contain only strings")
        return tuple(value)
    return ()


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    if not all(isinstance(item, str) for item in value.values()):
        raise TypeError("LangGraph string mapping metadata must contain only string values")
    return {
        str(key): item
        for key, item in value.items()
    }


def _string_key_mapping(value: Mapping[Any, Any]) -> dict[str, object]:
    return {str(key): item for key, item in value.items()}
