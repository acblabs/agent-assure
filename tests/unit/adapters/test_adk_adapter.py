from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

from agent_assure.adapters import (
    FrameworkAdapter,
    FrameworkRunProjection,
    GoogleADKAdapter,
    build_run_record_from_observations,
)

ROOT = Path(__file__).resolve().parents[3]
RAW_PROMPT = "Member M-4477 raw benefit request with authorization A-99123"
RAW_TOOL_ARGS = '{"member_id":"M-4477","authorization_id":"A-99123"}'


def test_adk_adapter_converts_events_deterministically() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    events = _events()

    first = adapter.observations_from_events(events, run_id="run-adk-001", case_id="case-001")
    second = adapter.observations_from_events(events, run_id="run-adk-001", case_id="case-001")

    assert [item.model_dump(mode="json") for item in first] == [
        item.model_dump(mode="json") for item in second
    ]
    assert [observation.sequence_number for observation in first] == [1, 2, 3]
    assert first[0].framework == "google-adk"
    assert first[0].tool_name == "benefit_policy_lookup"
    assert first[0].evidence_refs == ("ref-benefit-policy-v9",)
    assert first[0].timestamp == "1700000000.000000"
    assert first[1].review_route == "clinical_review"
    assert first[2].provider == "google-vertex-ai"
    assert first[2].timestamp == "1700000000.125000"
    assert first[2].span_context == {
        "framework_event_id": "adk-event-decision",
        "framework_invocation_id": "adk-invocation-001",
    }


def test_adk_adapter_ignores_raw_event_payloads_and_attaches_usage() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    observations = adapter.observations_from_events(
        _events(),
        run_id="run-adk-001",
        case_id="case-001",
    )
    run = build_run_record_from_observations(
        observations,
        projection=_projection(),
        run_id="run-adk-001",
        case_id="case-001",
        fixture_manifest_digest="1" * 64,
        configuration_digest="2" * 64,
    )

    persisted = json.dumps(
        {
            "observations": [observation.model_dump(mode="json") for observation in observations],
            "run": run.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert RAW_PROMPT not in persisted
    assert RAW_TOOL_ARGS not in persisted
    assert run.usage_ledger is not None
    assert run.usage_summary is not None
    assert run.usage_ledger.segments[0].run_id == "run-adk-001"
    assert run.usage_ledger.segments[0].case_id == "case-001"
    assert run.usage_summary.total_tokens == 19


def test_adk_observed_review_flags_override_static_projection() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    observations = adapter.observations_from_events(
        _events(review_required="false", review_performed="false", review_route="auto_approval"),
        run_id="run-adk-001",
        case_id="case-001",
    )

    run = build_run_record_from_observations(
        observations,
        projection=_projection(human_review_required=True, human_review_performed=True),
        run_id="run-adk-001",
        case_id="case-001",
        fixture_manifest_digest="1" * 64,
    )

    assert run.recommendation == "approve"
    assert run.outcome == "approved_with_review"
    assert run.human_review_required is False
    assert run.human_review_performed is False


@pytest.mark.parametrize(
    ("review_required", "review_performed"),
    (
        ("True", "yes"),
        ("", "true"),
    ),
)
def test_adk_observed_review_flags_fail_closed_on_malformed_tokens(
    review_required: str,
    review_performed: str,
) -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    observations = adapter.observations_from_events(
        _events(review_required=review_required, review_performed=review_performed),
        run_id="run-adk-001",
        case_id="case-001",
    )

    with pytest.raises(ValueError, match="must be exactly 'true' or 'false'"):
        build_run_record_from_observations(
            observations,
            projection=_projection(human_review_required=True, human_review_performed=True),
            run_id="run-adk-001",
            case_id="case-001",
            fixture_manifest_digest="1" * 64,
        )


def test_build_run_record_requires_observed_review_flags_when_requested() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    observations = adapter.observations_from_events(
        (
            _event_with_agent_metadata(
                {
                    "case_id": "case-001",
                    "event_type": "decision",
                    "sequence_number": 1,
                    "privacy_filtered_attributes": {
                        "recommendation": "approve",
                        "outcome": "approved_with_review",
                    },
                }
            ),
        ),
        run_id="run-adk-001",
        case_id="case-001",
    )

    with pytest.raises(ValueError, match="observed human_review_required"):
        build_run_record_from_observations(
            observations,
            projection=_projection(human_review_required=True, human_review_performed=True),
            run_id="run-adk-001",
            case_id="case-001",
            fixture_manifest_digest="1" * 64,
            require_observed_human_review=True,
        )


def test_adk_adapter_skips_uninstrumented_events() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = {
        "author": "decision_agent",
        "content": {"parts": [{"text": "raw final completion should be ignored"}]},
    }

    observations = adapter.observations_from_events(
        (event,),
        run_id="run-adk-001",
        case_id="case-001",
    )

    assert observations == ()


def test_adk_adapter_rejects_empty_agent_assure_metadata() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")

    with pytest.raises(ValueError, match="must not be empty"):
        adapter.observations_from_events(
            ({"metadata": {"agent_assure": {}}},),
            run_id="run-adk-001",
            case_id="case-001",
        )


def test_adk_adapter_rejects_raw_metadata_keys() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = {
        "metadata": {
            "agent_assure": {
                "case_id": "case-001",
                "event_type": "bad",
                "raw_prompt": RAW_PROMPT,
            }
        }
    }

    with pytest.raises(ValueError, match="raw payload key"):
        adapter.observations_from_events((event,), run_id="run-adk-001", case_id="case-001")


def test_adk_adapter_rejects_free_text_privacy_filtered_values() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "bad",
            "sequence_number": 1,
            "privacy_filtered_attributes": {"unsafe_value": RAW_PROMPT},
        }
    )

    with pytest.raises(ValueError, match="compact filtered token"):
        adapter.observations_from_events((event,), run_id="run-adk-001", case_id="case-001")


def test_adk_adapter_rejects_free_text_usage_segment_values() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "decision",
            "sequence_number": 1,
            "usage_segment": {
                "segment_id": "usage-case-001",
                "operation": RAW_PROMPT,
                "total_tokens": 19,
            },
        }
    )

    with pytest.raises(ValueError, match=r"usage_segment\.operation"):
        adapter.observations_from_events((event,), run_id="run-adk-001", case_id="case-001")


def test_adk_adapter_rejects_free_text_observation_label_values() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "review_route",
            "sequence_number": 1,
            "review_route": "clinical review route with raw context",
        }
    )

    with pytest.raises(ValueError, match=r"observation\.review_route"):
        adapter.observations_from_events((event,), run_id="run-adk-001", case_id="case-001")


def test_adk_adapter_rejects_non_string_evidence_refs() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "tool_call",
            "sequence_number": 1,
            "evidence_refs": ["ref-benefit-policy-v9", 17],
        }
    )

    with pytest.raises(TypeError, match="string sequence"):
        adapter.observations_from_events((event,), run_id="run-adk-001", case_id="case-001")


def test_adk_adapter_emits_each_parallel_workflow_node() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = {
        "policy_agent": {
            "agent_assure": {
                "case_id": "case-001",
                "event_type": "delegation",
                "sequence_number": 1,
                "tool_name": "benefit_policy_lookup",
                "evidence_refs": ["ref-benefit-policy-v9"],
            }
        },
        "review_agent": {
            "agent_assure": {
                "case_id": "case-001",
                "event_type": "review_route",
                "sequence_number": 2,
                "review_route": "clinical_review",
            }
        },
    }

    observations = adapter.observations_from_events((event,), run_id="run-adk-001")

    assert [observation.node_name for observation in observations] == [
        "policy_agent",
        "review_agent",
    ]
    assert observations[0].evidence_refs == ("ref-benefit-policy-v9",)
    assert observations[1].review_route == "clinical_review"


def test_adk_adapter_reads_stream_tuple_payloads() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = (
        "workflow_update",
        {
            "custom_metadata": {
                "agent_assure": {
                    "case_id": "case-001",
                    "event_type": "decision",
                    "sequence_number": 1,
                    "privacy_filtered_attributes": {
                        "recommendation": "approve",
                        "outcome": "approved_with_review",
                    },
                }
            }
        },
    )

    observations = adapter.observations_from_events(
        (event,),
        run_id="run-adk-001",
        case_id="case-001",
    )

    assert len(observations) == 1
    assert observations[0].event_type == "decision"
    assert observations[0].run_id == "run-adk-001"


def test_adk_adapter_does_not_use_event_id_as_run_id() -> None:
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    event = {
        "id": "adk-event-not-a-run",
        "custom_metadata": {
            "agent_assure": {
                "case_id": "case-001",
                "event_type": "decision",
                "sequence_number": 1,
                "privacy_filtered_attributes": {
                    "recommendation": "approve",
                    "outcome": "approved_with_review",
                },
            }
        },
    }

    observations = adapter.observations_from_events((event,), case_id="case-001")

    assert observations[0].run_id == "google-adk-run"
    assert observations[0].span_context == {"framework_event_id": "adk-event-not-a-run"}


def test_adk_adapter_satisfies_framework_adapter_protocol() -> None:
    assert isinstance(GoogleADKAdapter(framework_version="2.4.0"), FrameworkAdapter)


def test_adk_adapter_reads_real_google_adk_event_when_available() -> None:
    event_module = pytest.importorskip("google.adk.events.event")
    actions_module = pytest.importorskip("google.adk.events.event_actions")
    Event = event_module.Event
    EventActions = actions_module.EventActions
    adapter = GoogleADKAdapter(framework_version="2.4.0")
    custom_metadata_event = Event(
        invocation_id="adk-invocation-001",
        author="policy_agent",
        timestamp=1700000000.25,
        node_path="root/policy_agent@1",
        custom_metadata={
            "agent_assure": {
                "case_id": "case-001",
                "event_type": "tool_call",
                "sequence_number": 1,
                "tool_name": "benefit_policy_lookup",
                "evidence_refs": ["ref-benefit-policy-v9"],
            }
        },
    )
    state_delta_event = Event(
        invocation_id="adk-invocation-001",
        author="review_agent",
        timestamp=1700000001.5,
        actions=EventActions(
            state_delta={
                "agent_assure": {
                    "case_id": "case-001",
                    "event_type": "review_route",
                    "sequence_number": 2,
                    "review_route": "clinical_review",
                    "privacy_filtered_attributes": {
                        "human_review_required": "true",
                        "human_review_performed": "true",
                    },
                }
            }
        ),
    )

    observations = adapter.observations_from_events(
        (custom_metadata_event, state_delta_event),
        case_id="case-001",
    )

    assert len(observations) == 2
    assert observations[0].run_id == "adk-invocation-001"
    assert observations[0].node_name == "policy_agent"
    assert observations[0].timestamp == "1700000000.250000"
    assert observations[0].tool_name == "benefit_policy_lookup"
    assert observations[0].evidence_refs == ("ref-benefit-policy-v9",)
    assert observations[1].timestamp == "1700000001.500000"
    assert observations[1].event_type == "review_route"
    assert observations[1].review_route == "clinical_review"
    assert observations[1].privacy_filtered_attributes == {
        "human_review_performed": "true",
        "human_review_required": "true",
    }


def test_no_adk_specific_evaluator_fork_exists() -> None:
    assert not (ROOT / "src" / "agent_assure" / "evaluation" / "adk.py").exists()
    assert not (ROOT / "src" / "agent_assure" / "evaluation" / "google_adk.py").exists()


def _events(
    *,
    review_required: str = "true",
    review_performed: str = "true",
    review_route: str = "clinical_review",
) -> tuple[object, ...]:
    return (
        {
            "author": "policy_agent",
            "invocation_id": "adk-invocation-001",
            "timestamp": 1700000000,
            "content": {
                "parts": [
                    {
                        "text": RAW_PROMPT,
                    }
                ]
            },
            "actions": {"state_delta": {"tool_args": RAW_TOOL_ARGS}},
            "custom_metadata": {
                "agent_assure": {
                    "case_id": "case-001",
                    "event_type": "delegation",
                    "sequence_number": 1,
                    "node_name": "policy_agent",
                    "tool_name": "benefit_policy_lookup",
                    "evidence_refs": ["ref-benefit-policy-v9"],
                    "redaction_state": "redacted",
                    "privacy_filtered_attributes": {
                        "delegation_route": "root_to_policy_agent",
                        "policy_version": "benefit-policy-v9",
                    },
                },
            },
        },
        {
            "author": "review_agent",
            "invocation_id": "adk-invocation-001",
            "actions": {
                "state_delta": {
                    "agent_assure": {
                        "case_id": "case-001",
                        "event_type": "review_route",
                        "sequence_number": 2,
                        "node_name": "review_agent",
                        "review_route": review_route,
                        "redaction_state": "redacted",
                        "privacy_filtered_attributes": {
                            "human_review_required": review_required,
                            "human_review_performed": review_performed,
                        },
                    },
                },
            },
        },
        _FakeADKEvent(
            author="decision_agent",
            invocation_id="adk-invocation-001",
            id="adk-event-decision",
            timestamp=1700000000.125,
            custom_metadata={
                "agent_assure": {
                    "case_id": "case-001",
                    "event_type": "decision",
                    "sequence_number": 3,
                    "node_name": "decision_agent",
                    "provider": "google-vertex-ai",
                    "model": "gemini-governed-v1",
                    "review_route": review_route,
                    "redaction_state": "redacted",
                    "privacy_filtered_attributes": {
                        "recommendation": "approve",
                        "outcome": "approved_with_review",
                    },
                    "usage_segment": {
                        "segment_id": "usage-case-001",
                        "prompt_tokens": 11,
                        "completion_tokens": 8,
                        "total_tokens": 19,
                    },
                },
            },
        ),
    )


def _event_with_agent_metadata(metadata: dict[str, object]) -> dict[str, object]:
    return {"metadata": {"agent_assure": metadata}}


def _projection(
    *,
    human_review_required: bool = True,
    human_review_performed: bool = True,
) -> FrameworkRunProjection:
    return FrameworkRunProjection(
        pipeline_id="adk-benefit-assurance",
        recommendation="approve",
        outcome="approved_with_review",
        evidence_claim_map={"ref-benefit-policy-v9": ("claim-benefit-evidence",)},
        human_review_required=human_review_required,
        human_review_performed=human_review_performed,
    )


@dataclass(frozen=True)
class _FakeADKEvent:
    author: str
    invocation_id: str
    id: str
    custom_metadata: Mapping[str, object] | None = None
    actions: Mapping[str, object] | None = None
    metadata: Mapping[str, object] | None = None
    timestamp: float | None = None
