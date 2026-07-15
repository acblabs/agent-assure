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
CONTAINER_EVENT_KEYS = (
    "custom_metadata",
    "metadata",
    "state_delta",
    "context",
)
ACTION_CONTAINER_KEYS = ("state_delta",)
KNOWN_EVENT_ATTRIBUTES = (
    "agent_assure",
    "custom_metadata",
    "metadata",
    "actions",
    "state_delta",
    "context",
    "usage_metadata",
    "invocation_id",
    "id",
    "author",
    "branch",
    "timestamp",
    "event_type",
    "name",
    "node",
    "node_info",
    "node_name",
)
RESERVED_EVENT_KEYS = frozenset(
    {
        "actions",
        "agent_assure",
        "author",
        "branch",
        "content",
        "context",
        "custom_metadata",
        "event_type",
        "id",
        "invocation_id",
        "metadata",
        "name",
        "node",
        "node_name",
        "partial",
        "state_delta",
        "timestamp",
        "turn_complete",
        "usage_metadata",
    }
)


class GoogleADKAdapter:
    adapter_id = "experimental-google-adk"
    framework = "google-adk"
    experimental = True

    def __init__(self, *, framework_version: str | None = None) -> None:
        self._framework_version = framework_version or _installed_google_adk_version()

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
                    raise ValueError("Google ADK agent_assure metadata must not be empty")
                validate_no_raw_payload_keys(
                    agent_metadata,
                    owner="Google ADK agent_assure metadata",
                )
                observed_run_id = _required_string(
                    _metadata_value(agent_metadata, "run_id")
                    or run_id
                    or _string(event.get("invocation_id"))
                    or "google-adk-run"
                )
                event_type = _required_string(
                    _metadata_value(agent_metadata, "event_type")
                    or _string(event.get("event_type"))
                    or "adk_event"
                )
                sequence_number = _sequence_number(agent_metadata, len(observations) + 1)
                observed_node_name = (
                    _string(_metadata_value(agent_metadata, "node_name"))
                    or _metadata_node_name(event)
                    or node_name
                    or _string(event.get("author"))
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
                        timestamp=_timestamp_string(
                            _first_present(
                                _metadata_value(agent_metadata, "timestamp"),
                                event.get("timestamp"),
                            )
                        ),
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

    def run_record_from_events(
        self,
        events: Iterable[object],
        *,
        projection: FrameworkRunProjection,
        run_id: str,
        case_id: str,
        fixture_manifest_digest: DigestHex,
        configuration_digest: DigestHex | None = None,
        require_observed_human_review: bool = False,
    ) -> AgentRunRecord:
        observations = self.observations_from_events(events, run_id=run_id, case_id=case_id)
        return build_run_record_from_observations(
            observations,
            projection=projection,
            run_id=run_id,
            case_id=case_id,
            fixture_manifest_digest=fixture_manifest_digest,
            configuration_digest=configuration_digest,
            require_observed_human_review=require_observed_human_review,
        )


def _installed_google_adk_version() -> str | None:
    try:
        return version("google-adk")
    except PackageNotFoundError:
        return None


def _normalize_event(raw_event: object) -> Mapping[str, object]:
    if isinstance(raw_event, Mapping):
        return _string_key_mapping(raw_event)
    if isinstance(raw_event, tuple | list) and len(raw_event) == 2:
        mode, payload = raw_event
        event: dict[str, object] = {"event_type": str(mode)}
        if isinstance(payload, Mapping):
            event.update(_string_key_mapping(payload))
        else:
            event["payload"] = payload
        return event
    event = {
        attribute: _attribute_value(raw_event, attribute)
        for attribute in KNOWN_EVENT_ATTRIBUTES
        if hasattr(raw_event, attribute)
    }
    event = {key: value for key, value in event.items() if value is not None}
    if event:
        return event
    raise TypeError("Google ADK event must be a mapping, object, or two-item stream tuple")


def _attribute_value(raw_event: object, attribute: str) -> object:
    value = getattr(raw_event, attribute)
    if attribute in CONTAINER_EVENT_KEYS or attribute == AGENT_ASSURE_METADATA_KEY:
        return _object_mapping(value)
    return value


def _object_mapping(value: object) -> object:
    if isinstance(value, Mapping):
        return _string_key_mapping(value)
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump()
        if isinstance(dumped, Mapping):
            return _string_key_mapping(dumped)
    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        dumped = dict_method()
        if isinstance(dumped, Mapping):
            return _string_key_mapping(dumped)
    return value


def _agent_assure_metadata_items(
    event: Mapping[str, object],
) -> tuple[tuple[str | None, Mapping[str, object]], ...]:
    top_level = event.get(AGENT_ASSURE_METADATA_KEY)
    if isinstance(top_level, Mapping):
        return ((None, _string_key_mapping(top_level)),)
    for key in CONTAINER_EVENT_KEYS:
        container = _mapping(event.get(key))
        if container is None:
            continue
        nested = container.get(AGENT_ASSURE_METADATA_KEY)
        if isinstance(nested, Mapping):
            return ((None, _string_key_mapping(nested)),)
    actions = _mapping(event.get("actions"))
    if actions is not None:
        nested = actions.get(AGENT_ASSURE_METADATA_KEY)
        if isinstance(nested, Mapping):
            return ((None, _string_key_mapping(nested)),)
        for key in ACTION_CONTAINER_KEYS:
            container = _mapping(actions.get(key))
            if container is None:
                continue
            nested = container.get(AGENT_ASSURE_METADATA_KEY)
            if isinstance(nested, Mapping):
                return ((None, _string_key_mapping(nested)),)
    items: list[tuple[str | None, Mapping[str, object]]] = []
    for key, value in event.items():
        if key in RESERVED_EVENT_KEYS:
            continue
        container = _mapping(value)
        if container is None:
            continue
        nested = container.get(AGENT_ASSURE_METADATA_KEY)
        if isinstance(nested, Mapping):
            items.append((str(key), _string_key_mapping(nested)))
    if items:
        return tuple(items)
    return ()


def _mapping(value: object) -> Mapping[str, object] | None:
    mapped = _object_mapping(value)
    if isinstance(mapped, Mapping):
        return _string_key_mapping(mapped)
    return None


def _metadata_node_name(event: Mapping[str, object]) -> str | None:
    for name_key in ("node_name", "node", "author", "name", "branch"):
        value = event.get(name_key)
        if isinstance(value, str):
            return value
    node_info = _mapping(event.get("node_info"))
    if node_info is not None:
        for name_key in ("name", "node_name", "node", "path"):
            value = node_info.get(name_key)
            if isinstance(value, str):
                return value
    for key in CONTAINER_EVENT_KEYS:
        container = _mapping(event.get(key))
        if container is None:
            continue
        for name_key in ("adk_node", "agent_name", "author", "node", "node_name"):
            value = container.get(name_key)
            if isinstance(value, str):
                return value
    return None


def _span_context(
    event: Mapping[str, object],
    agent_metadata: Mapping[str, object],
) -> dict[str, str] | None:
    span_context = _string_mapping(agent_metadata.get("span_context"))
    invocation_id = _string(event.get("invocation_id"))
    event_id = _string(event.get("id"))
    if invocation_id is not None:
        span_context.setdefault("framework_invocation_id", invocation_id)
    if event_id is not None:
        span_context.setdefault("framework_event_id", event_id)
    return span_context or None


def _usage_segment(agent_metadata: Mapping[str, object]) -> UsageSegment | None:
    payload = agent_metadata.get("usage_segment")
    if payload is None:
        return None
    if not isinstance(payload, Mapping):
        raise TypeError("Google ADK usage_segment metadata must be a mapping")
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


def _first_present(*values: object) -> object:
    for value in values:
        if value is not None:
            return value
    return None


def _timestamp_string(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, int | float) and not isinstance(value, bool):
        return f"{float(value):.6f}"
    return None


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
            raise TypeError("Google ADK string sequence metadata must contain only strings")
        return tuple(value)
    return ()


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    if not all(isinstance(item, str) for item in value.values()):
        raise TypeError("Google ADK string mapping metadata must contain only string values")
    return {str(key): item for key, item in value.items()}


def _string_key_mapping(value: Mapping[Any, Any]) -> dict[str, object]:
    return {str(key): item for key, item in value.items()}
