from __future__ import annotations

import json

import pytest

from agent_assure.adapters import (
    FrameworkAdapter,
    FrameworkRunProjection,
    LangGraphAdapter,
    build_run_record_from_observations,
)

RAW_PROMPT = "Employee E-7788 raw reimbursement prompt with receipt R-44119"
RAW_TOOL_ARGS = '{"employee_id":"E-7788","receipt_id":"R-44119"}'


def test_langgraph_adapter_converts_events_deterministically() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    events = _events()

    first = adapter.observations_from_events(events, run_id="run-lg-001", case_id="case-001")
    second = adapter.observations_from_events(events, run_id="run-lg-001", case_id="case-001")

    assert [item.model_dump(mode="json") for item in first] == [
        item.model_dump(mode="json") for item in second
    ]
    assert [observation.sequence_number for observation in first] == [1, 2]
    assert first[0].tool_name == "expense_policy_lookup"
    assert first[0].evidence_refs == ("ref-expense-policy-v3",)
    assert first[1].provider == "approved-expense-model"


def test_langgraph_adapter_ignores_raw_event_payloads_and_attaches_usage() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    observations = adapter.observations_from_events(
        _events(),
        run_id="run-lg-001",
        case_id="case-001",
    )
    run = build_run_record_from_observations(
        observations,
        projection=FrameworkRunProjection(
            pipeline_id="langgraph-expense-assurance",
            recommendation="approve",
            outcome="approved_with_review",
            evidence_claim_map={"ref-expense-policy-v3": ("claim-policy-evidence",)},
            evidence_content_digest_map={"ref-expense-policy-v3": "a" * 64},
            human_review_required=True,
            human_review_performed=True,
        ),
        run_id="run-lg-001",
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
    assert run.usage_ledger.segments[0].run_id == "run-lg-001"
    assert run.usage_ledger.segments[0].case_id == "case-001"
    assert run.usage_summary.total_tokens == 20


def test_build_run_record_uses_observed_decision_not_projection() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    observations = adapter.observations_from_events(
        _events(),
        run_id="run-lg-001",
        case_id="case-001",
    )

    run = build_run_record_from_observations(
        observations,
        projection=FrameworkRunProjection(
            pipeline_id="langgraph-expense-assurance",
            recommendation="manual_review",
            outcome="manual_review",
        ),
        run_id="run-lg-001",
        case_id="case-001",
        fixture_manifest_digest="1" * 64,
    )

    assert run.recommendation == "approve"
    assert run.outcome == "approved_with_review"
    assert run.output_summary == "recommendation=approve; outcome=approved_with_review"


def test_build_run_record_requires_observed_final_decision() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    observations = adapter.observations_from_events(
        (
            _event_with_agent_metadata(
                {"case_id": "case-001", "event_type": "decision", "sequence_number": 1}
            ),
        ),
        run_id="run-lg-001",
        case_id="case-001",
    )

    with pytest.raises(ValueError, match="observed recommendation and outcome"):
        build_run_record_from_observations(
            observations,
            projection=_projection(),
            run_id="run-lg-001",
            case_id="case-001",
            fixture_manifest_digest="1" * 64,
        )


def test_langgraph_adapter_skips_uninstrumented_events() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    event = {
        "event": "on_chain_end",
        "name": "decision",
        "data": {"output": "raw final completion should be ignored"},
    }

    observations = adapter.observations_from_events(
        (event,),
        run_id="run-lg-001",
        case_id="case-001",
    )

    assert observations == ()


def test_langgraph_adapter_rejects_empty_agent_assure_metadata() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")

    with pytest.raises(ValueError, match="must not be empty"):
        adapter.observations_from_events(
            ({"metadata": {"agent_assure": {}}},),
            run_id="run-lg-001",
            case_id="case-001",
        )


def test_langgraph_adapter_rejects_raw_metadata_keys() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
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
        adapter.observations_from_events((event,), run_id="run-lg-001", case_id="case-001")


def test_langgraph_adapter_rejects_free_text_privacy_filtered_values() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "bad",
            "sequence_number": 1,
            "privacy_filtered_attributes": {"unsafe_value": RAW_PROMPT},
        }
    )

    with pytest.raises(ValueError, match="compact filtered token"):
        adapter.observations_from_events((event,), run_id="run-lg-001", case_id="case-001")


def test_langgraph_adapter_rejects_free_text_usage_segment_values() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "decision",
            "sequence_number": 1,
            "usage_segment": {
                "segment_id": "usage-case-001",
                "operation": RAW_PROMPT,
                "total_tokens": 20,
            },
        }
    )

    with pytest.raises(ValueError, match=r"usage_segment\.operation"):
        adapter.observations_from_events((event,), run_id="run-lg-001", case_id="case-001")


def test_langgraph_adapter_rejects_free_text_observation_label_values() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "review_route",
            "sequence_number": 1,
            "review_route": "manager review route with raw context",
        }
    )

    with pytest.raises(ValueError, match=r"observation\.review_route"):
        adapter.observations_from_events((event,), run_id="run-lg-001", case_id="case-001")


def test_langgraph_adapter_rejects_non_string_evidence_refs() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    event = _event_with_agent_metadata(
        {
            "case_id": "case-001",
            "event_type": "tool_call",
            "sequence_number": 1,
            "evidence_refs": ["ref-expense-policy-v3", 17],
        }
    )

    with pytest.raises(TypeError, match="string sequence"):
        adapter.observations_from_events((event,), run_id="run-lg-001", case_id="case-001")


def test_langgraph_adapter_emits_each_parallel_update_node() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    event = {
        "policy_lookup": {
            "agent_assure": {
                "case_id": "case-001",
                "event_type": "tool_call",
                "sequence_number": 1,
                "tool_name": "expense_policy_lookup",
                "evidence_refs": ["ref-expense-policy-v3"],
            }
        },
        "review_route": {
            "agent_assure": {
                "case_id": "case-001",
                "event_type": "review_route",
                "sequence_number": 2,
                "review_route": "manager_review",
            }
        },
    }

    observations = adapter.observations_from_events((event,), run_id="run-lg-001")

    assert [observation.node_name for observation in observations] == [
        "policy_lookup",
        "review_route",
    ]
    assert observations[0].evidence_refs == ("ref-expense-policy-v3",)
    assert observations[1].review_route == "manager_review"


def test_build_run_record_rejects_duplicate_observation_ordering() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    observations = adapter.observations_from_events(
        (
            _event_with_agent_metadata(
                {"case_id": "case-001", "event_type": "first", "sequence_number": 1}
            ),
            _event_with_agent_metadata(
                {"case_id": "case-001", "event_type": "second", "sequence_number": 1}
            ),
        ),
        run_id="run-lg-001",
        case_id="case-001",
    )

    with pytest.raises(ValueError, match="duplicate sequence_number"):
        build_run_record_from_observations(
            observations,
            projection=_projection(),
            run_id="run-lg-001",
            case_id="case-001",
            fixture_manifest_digest="1" * 64,
        )


def test_build_run_record_rejects_duplicate_observation_ids() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    observations = adapter.observations_from_events(
        (
            _event_with_agent_metadata(
                {
                    "case_id": "case-001",
                    "event_type": "first",
                    "observation_id": "obs-duplicate",
                    "sequence_number": 1,
                }
            ),
            _event_with_agent_metadata(
                {
                    "case_id": "case-001",
                    "event_type": "second",
                    "observation_id": "obs-duplicate",
                    "sequence_number": 2,
                }
            ),
        ),
        run_id="run-lg-001",
        case_id="case-001",
    )

    with pytest.raises(ValueError, match="duplicate observation_id"):
        build_run_record_from_observations(
            observations,
            projection=_projection(),
            run_id="run-lg-001",
            case_id="case-001",
            fixture_manifest_digest="1" * 64,
        )


@pytest.mark.parametrize(
    ("run_id", "case_id", "match"),
    (
        ("run-other", "case-001", "run_id does not match"),
        ("run-lg-001", "case-other", "case_id does not match"),
    ),
)
def test_build_run_record_rejects_run_or_case_mismatch(
    run_id: str,
    case_id: str,
    match: str,
) -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    observations = adapter.observations_from_events(
        (
            _event_with_agent_metadata(
                {"case_id": "case-001", "event_type": "decision", "sequence_number": 1}
            ),
        ),
        run_id="run-lg-001",
        case_id="case-001",
    )

    with pytest.raises(ValueError, match=match):
        build_run_record_from_observations(
            observations,
            projection=_projection(),
            run_id=run_id,
            case_id=case_id,
            fixture_manifest_digest="1" * 64,
        )


def test_build_run_record_accepts_sequence_zero() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    observations = adapter.observations_from_events(
        (
            _event_with_agent_metadata(
                {
                    "case_id": "case-001",
                    "event_type": "decision",
                    "sequence_number": 0,
                    "privacy_filtered_attributes": {
                        "recommendation": "approve",
                        "outcome": "approved_with_review",
                        "human_review_required": "true",
                        "human_review_performed": "true",
                    },
                }
            ),
        ),
        run_id="run-lg-001",
        case_id="case-001",
    )

    run = build_run_record_from_observations(
        observations,
        projection=_projection(),
        run_id="run-lg-001",
        case_id="case-001",
        fixture_manifest_digest="1" * 64,
    )

    assert run.observation_id.startswith("langgraph-observation-group-")


def test_observations_from_graph_stream_passes_config_and_case_id() -> None:
    adapter = LangGraphAdapter(framework_version="1.2.8")
    graph = _FakeGraph()

    observations = adapter.observations_from_graph_stream(
        graph,
        {"request": "redacted"},
        run_id="run-lg-001",
        case_id="case-001",
    )

    assert graph.seen_stream_mode == "updates"
    assert graph.seen_config == {"run_id": "run-lg-001"}
    assert graph.seen_state["case_id"] == "case-001"
    assert observations[0].case_id == "case-001"
    assert observations[0].node_name == "decision"


def test_langgraph_adapter_satisfies_framework_adapter_protocol() -> None:
    assert isinstance(LangGraphAdapter(framework_version="1.2.8"), FrameworkAdapter)


def _events() -> tuple[dict[str, object], ...]:
    return (
        {
            "event": "on_chain_end",
            "name": "policy_lookup",
            "run_id": "framework-run-001",
            "data": {
                "input": RAW_PROMPT,
                "output": {
                    "tool_args": RAW_TOOL_ARGS,
                    "raw_summary": "do not persist this",
                },
            },
            "metadata": {
                "langgraph_node": "policy_lookup",
                "agent_assure": {
                    "case_id": "case-001",
                    "event_type": "tool_call",
                    "sequence_number": 1,
                    "tool_name": "expense_policy_lookup",
                    "evidence_refs": ["ref-expense-policy-v3"],
                    "redaction_state": "redacted",
                    "privacy_filtered_attributes": {
                        "policy_version": "expense-policy-v3",
                    },
                    "span_context": {
                        "span_id": "span-tool",
                        "parent_span_id": "span-root",
                    },
                },
            },
        },
        {
            "event": "on_chain_end",
            "name": "decision",
            "run_id": "framework-run-001",
            "data": {"output": "raw final completion should be ignored"},
            "metadata": {
                "langgraph_node": "decision",
                "agent_assure": {
                    "case_id": "case-001",
                    "event_type": "decision",
                    "sequence_number": 2,
                    "provider": "approved-expense-model",
                    "model": "expense-risk-v1",
                    "review_route": "manager_review",
                    "redaction_state": "redacted",
                    "privacy_filtered_attributes": {
                        "recommendation": "approve",
                        "outcome": "approved_with_review",
                        "human_review_required": "true",
                        "human_review_performed": "true",
                    },
                    "usage_segment": {
                        "segment_id": "usage-case-001",
                        "prompt_tokens": 12,
                        "completion_tokens": 8,
                        "total_tokens": 20,
                    },
                },
            },
        },
    )


def _event_with_agent_metadata(metadata: dict[str, object]) -> dict[str, object]:
    return {"metadata": {"agent_assure": metadata}}


def _projection() -> FrameworkRunProjection:
    return FrameworkRunProjection(
        pipeline_id="langgraph-expense-assurance",
        recommendation="approve",
        outcome="approved_with_review",
    )


class _FakeGraph:
    seen_state: dict[str, object]
    seen_stream_mode: str
    seen_config: dict[str, str]

    def stream(
        self,
        state: dict[str, object],
        *,
        stream_mode: str,
        config: dict[str, str],
    ) -> tuple[dict[str, object], ...]:
        self.seen_state = state
        self.seen_stream_mode = stream_mode
        self.seen_config = config
        return (
            {
                "decision": {
                    "agent_assure": {
                        "event_type": "decision",
                        "sequence_number": 1,
                        "node_name": "decision",
                    }
                }
            },
        )
