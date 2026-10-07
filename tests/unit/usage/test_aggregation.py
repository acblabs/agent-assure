from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, ValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import (
    EvaluationMetrics,
    EvaluationReport,
    evaluate_runset,
)
from agent_assure.io_limits import MAX_CONFIG_TEXT_BYTES
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.markdown import render_evaluation_markdown
from agent_assure.reporting.usage import usage_summary_lines
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import ComparisonClassification
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.usage import (
    USAGE_SEGMENT_SUM_FIELDS,
    UsageLedger,
    UsagePricingModel,
    UsagePricingSnapshot,
    UsageSegment,
    UsageSummary,
    UsageSummaryDelta,
    summarize_usage_segments,
)
from agent_assure.schema.validation import validate_artifact_payload
from agent_assure.usage.aggregation import (
    aggregate_usage_segments,
    compare_usage_summaries,
    format_usage_delta,
    usage_summary_for_runset,
)
from agent_assure.usage.pricing import (
    DECLARED_PRICING_LIMITATION,
    estimate_segment_cost,
    load_pricing_snapshot,
    pricing_snapshot_digest,
)

ROOT = Path(__file__).resolve().parents[3]


def test_usage_segments_use_integer_micro_usd() -> None:
    segment = UsageSegment(
        segment_id="seg-001",
        total_tokens=42,
        estimated_cost_microusd=123,
        pricing_snapshot_id="local-demo-pricing-v1",
        limitations=(DECLARED_PRICING_LIMITATION,),
    )

    assert segment.estimated_cost_microusd == 123
    assert "estimated_cost_usd" not in UsageSegment.model_fields

    with pytest.raises(ValidationError):
        UsageSegment(segment_id="bad-money", estimated_cost_microusd=1.25)  # type: ignore[arg-type]


def test_declared_pricing_snapshot_estimates_segment_cost() -> None:
    snapshot = _pricing_snapshot()
    segment = UsageSegment(
        segment_id="seg-priced",
        provider="demo",
        model="fixture-model-small",
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
    )

    priced = estimate_segment_cost(segment, snapshot)

    assert priced.estimated_cost_microusd == 25
    assert priced.currency == "USD"
    assert priced.pricing_snapshot_id == "local-demo-pricing-v1"
    assert priced.pricing_snapshot_digest == pricing_snapshot_digest(snapshot)
    assert priced.cost_basis == "declared_pricing_snapshot_v2"
    assert DECLARED_PRICING_LIMITATION in priced.limitations
    assert "Demo fixture pricing only; not live provider pricing." in priced.limitations


def test_declared_pricing_rejects_forged_typed_artifacts_before_derivation() -> None:
    snapshot = _pricing_snapshot().model_copy(update={"artifact_kind": "forged-pricing-snapshot"})
    segment = UsageSegment(
        segment_id="seg-priced",
        provider="demo",
        model="fixture-model-small",
        prompt_tokens=10,
        completion_tokens=5,
        total_tokens=15,
    )

    with pytest.raises(ValidationError, match="artifact_kind"):
        pricing_snapshot_digest(snapshot)
    with pytest.raises(ValidationError, match="artifact_kind"):
        estimate_segment_cost(segment, snapshot)

    forged_segment = segment.model_copy(update={"artifact_kind": "forged-segment"})
    with pytest.raises(ValidationError, match="artifact_kind"):
        estimate_segment_cost(forged_segment, _pricing_snapshot())


def test_precise_pricing_represents_sub_dollar_per_million_rates() -> None:
    snapshot = UsagePricingSnapshot(
        pricing_snapshot_id="sub-dollar-pricing",
        models=(
            UsagePricingModel(
                provider="demo",
                model="low-cost-model",
                input_million_tokens_usd="0.050000",
                output_million_tokens_usd="0.100000",
            ),
        ),
        limitations=("Synthetic precision regression fixture.",),
    )
    segment = UsageSegment(
        segment_id="seg-sub-dollar",
        provider="demo",
        model="low-cost-model",
        prompt_tokens=20,
        completion_tokens=10,
        total_tokens=30,
    )

    priced = estimate_segment_cost(segment, snapshot)

    assert priced.estimated_cost_microusd == 2
    assert priced.cost_basis == "declared_pricing_snapshot_v2"


def test_exact_cost_is_invariant_to_segment_boundaries() -> None:
    snapshot = UsagePricingSnapshot(
        pricing_snapshot_id="segmentation-invariant-pricing",
        models=(
            UsagePricingModel(
                provider="demo",
                model="low-cost-model",
                input_million_tokens_usd="0.050000",
                output_million_tokens_usd="0.000000",
            ),
        ),
        limitations=("Synthetic segmentation-invariance fixture.",),
    )
    split = tuple(
        estimate_segment_cost(
            UsageSegment(
                segment_id=f"split-{index}",
                provider="demo",
                model="low-cost-model",
                prompt_tokens=1,
                completion_tokens=0,
                total_tokens=1,
            ),
            snapshot,
        )
        for index in range(20)
    )
    combined = estimate_segment_cost(
        UsageSegment(
            segment_id="combined",
            provider="demo",
            model="low-cost-model",
            prompt_tokens=20,
            completion_tokens=0,
            total_tokens=20,
        ),
        snapshot,
    )

    split_summary = aggregate_usage_segments(split).usage_summary
    combined_summary = aggregate_usage_segments((combined,)).usage_summary

    assert all(segment.estimated_cost_microusd == 0 for segment in split)
    assert all(segment.estimated_cost_picousd == 50_000 for segment in split)
    assert split_summary.estimated_cost_picousd == 1_000_000
    assert split_summary.estimated_cost_microusd == 1
    assert combined_summary.estimated_cost_picousd == 1_000_000
    assert combined_summary.estimated_cost_microusd == 1


def test_v066_usage_summary_enforces_exact_cost_projection() -> None:
    summary = UsageSummary(
        estimated_cost_microusd=0,
        estimated_cost_picousd=500_000,
    )

    assert summary.estimated_cost_picousd == 500_000
    with pytest.raises(ValidationError, match="half-even projection"):
        UsageSummary(
            estimated_cost_microusd=1,
            estimated_cost_picousd=499_999,
        )
    with pytest.raises(ValidationError, match="requires exact estimated_cost_picousd"):
        UsageSummary(estimated_cost_microusd=1)
    with pytest.raises(ValidationError, match="requires schema_version 0.6.6"):
        UsageSummary(
            schema_version="0.4.3",
            estimated_cost_microusd=1,
            estimated_cost_picousd=1_000_000,
        )


def test_precise_pricing_requires_canonical_fixed_point_strings() -> None:
    with pytest.raises(ValidationError):
        UsagePricingModel(
            provider="demo",
            model="malformed-rate",
            input_million_tokens_usd="0x050000",
            output_million_tokens_usd="0.100000",
        )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "provider": "demo",
            "model": "legacy-null-rate",
            "input_token_microusd": None,
            "output_token_microusd": 1,
        },
        {
            "provider": "demo",
            "model": "precise-null-rate",
            "input_million_tokens_usd": None,
            "output_million_tokens_usd": "1.000000",
        },
    ],
)
def test_pricing_model_schema_rejects_explicit_null_required_rates(
    payload: dict[str, object],
) -> None:
    validator = Draft202012Validator(UsagePricingModel.model_json_schema(mode="validation"))

    with pytest.raises(JsonSchemaValidationError):
        validator.validate(payload)
    with pytest.raises(ValidationError):
        UsagePricingModel.model_validate(payload)


def test_full_pricing_snapshot_validator_rejects_explicit_null_rate() -> None:
    payload = {
        "artifact_kind": "usage-pricing-snapshot",
        "schema_version": "0.6.6",
        "pricing_snapshot_id": "null-rate-snapshot",
        "currency": "USD",
        "models": [
            {
                "provider": "demo",
                "model": "null-rate-model",
                "input_million_tokens_usd": None,
                "output_million_tokens_usd": "1.000000",
            }
        ],
        "limitations": ["Synthetic explicit-null regression fixture."],
    }

    with pytest.raises((JsonSchemaValidationError, ValueError)):
        validate_artifact_payload(payload, "usage-pricing-snapshot")


def test_legacy_pricing_snapshot_remains_readable_but_cannot_masquerade_as_v066() -> None:
    legacy = UsagePricingSnapshot(
        schema_version="0.4.3",
        pricing_snapshot_id="legacy-pricing",
        models=(
            UsagePricingModel(
                provider="demo",
                model="legacy-model",
                input_token_microusd=1,
                output_token_microusd=3,
            ),
        ),
        limitations=("Legacy compatibility fixture.",),
    )

    assert legacy.schema_version == "0.4.3"
    with pytest.raises(ValidationError, match="requires precise per-million rates"):
        UsagePricingSnapshot(
            pricing_snapshot_id="mislabelled-legacy-pricing",
            models=legacy.models,
            limitations=legacy.limitations,
        )


@pytest.mark.parametrize("invalid_identifier", ["vendor\u200bname", "vendor\nname", "x" * 257])
def test_current_usage_join_identifiers_reject_ambiguous_or_oversized_values(
    invalid_identifier: str,
) -> None:
    segment_payload = {
        "artifact_kind": "usage-segment",
        "schema_version": "0.6.6",
        "segment_id": "segment-id-defense",
        "provider": invalid_identifier,
        "model": "model-1",
    }
    with pytest.raises(ValidationError, match="ASCII machine-identifier grammar"):
        UsageSegment.model_validate(segment_payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(UsageSegment.model_json_schema(mode="validation")).validate(
            segment_payload
        )

    snapshot_payload = {
        "artifact_kind": "usage-pricing-snapshot",
        "schema_version": "0.6.6",
        "pricing_snapshot_id": "identifier-defense-pricing",
        "currency": "USD",
        "models": [
            {
                "provider": invalid_identifier,
                "model": "model-1",
                "input_million_tokens_usd": "1.000000",
                "output_million_tokens_usd": "2.000000",
            }
        ],
        "limitations": ["Synthetic identifier-defense fixture."],
    }
    with pytest.raises(ValidationError, match="ASCII machine-identifier grammar"):
        UsagePricingSnapshot.model_validate(snapshot_payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(UsagePricingSnapshot.model_json_schema(mode="validation")).validate(
            snapshot_payload
        )


def test_current_usage_scopes_vertex_version_separator_to_model_identity() -> None:
    vertex_model = "claude-sonnet-4@20250514"
    segment_payload = {
        "artifact_kind": "usage-segment",
        "schema_version": "0.6.6",
        "segment_id": "vertex-model-segment",
        "provider": "anthropic",
        "model": vertex_model,
    }
    snapshot_payload = {
        "artifact_kind": "usage-pricing-snapshot",
        "schema_version": "0.6.6",
        "pricing_snapshot_id": "vertex-model-pricing",
        "currency": "USD",
        "models": [
            {
                "provider": "anthropic",
                "model": vertex_model,
                "input_million_tokens_usd": "1.000000",
                "output_million_tokens_usd": "2.000000",
            }
        ],
        "limitations": ["Synthetic Vertex model identifier fixture."],
    }

    UsageSegment.model_validate(segment_payload)
    UsagePricingSnapshot.model_validate(snapshot_payload)
    Draft202012Validator(UsageSegment.model_json_schema(mode="validation")).validate(
        segment_payload
    )
    Draft202012Validator(UsagePricingSnapshot.model_json_schema(mode="validation")).validate(
        snapshot_payload
    )

    invalid_provider = segment_payload | {"provider": "anthropic@vertex"}
    with pytest.raises(ValidationError):
        UsageSegment.model_validate(invalid_provider)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(UsageSegment.model_json_schema(mode="validation")).validate(
            invalid_provider
        )


def test_historical_usage_join_identifiers_remain_backward_compatible() -> None:
    legacy_identifier = "legacy vendor\u200b"
    segment = UsageSegment(
        schema_version="0.4.3",
        segment_id="legacy-segment",
        provider=legacy_identifier,
        model="legacy model",
    )
    snapshot = UsagePricingSnapshot(
        schema_version="0.4.3",
        pricing_snapshot_id="legacy-identifier-pricing",
        models=(
            UsagePricingModel(
                provider=legacy_identifier,
                model="legacy model",
                input_token_microusd=1,
                output_token_microusd=2,
            ),
        ),
        limitations=("Historical identifier compatibility fixture.",),
    )

    assert segment.provider == snapshot.models[0].provider == legacy_identifier
    Draft202012Validator(UsageSegment.model_json_schema(mode="validation")).validate(
        segment.model_dump(mode="json")
    )
    Draft202012Validator(UsagePricingSnapshot.model_json_schema(mode="validation")).validate(
        snapshot.model_dump(mode="json")
    )


def test_pricing_snapshot_rejects_duplicate_provider_model_pairs_semantically() -> None:
    model = UsagePricingModel(
        provider="demo",
        model="duplicate-model",
        input_million_tokens_usd="1.000000",
        output_million_tokens_usd="2.000000",
    )

    with pytest.raises(ValidationError, match="duplicate provider/model rates"):
        UsagePricingSnapshot(
            pricing_snapshot_id="duplicate-model-pricing",
            models=(model, model),
            limitations=("Synthetic composite-key uniqueness fixture.",),
        )


def test_demo_pricing_snapshot_fixture_is_explicit_and_versioned() -> None:
    snapshot = load_pricing_snapshot(ROOT / "examples" / "usage" / "local-demo-pricing-v1.json")

    assert snapshot.schema_version == "0.6.6"
    assert snapshot.pricing_snapshot_id == "local-demo-pricing-v1"
    assert snapshot.limitations == ("Demo fixture pricing only; not live provider pricing.",)


def test_pricing_snapshot_loader_rejects_oversized_file(tmp_path: Path) -> None:
    snapshot_path = tmp_path / "pricing.json"
    snapshot_path.write_bytes(b"{" + (b" " * MAX_CONFIG_TEXT_BYTES) + b"}")

    with pytest.raises(ValueError, match="pricing snapshot exceeds maximum supported size"):
        load_pricing_snapshot(snapshot_path)


def test_declared_pricing_snapshot_requires_explicit_provider_model_rate() -> None:
    segment = UsageSegment(
        segment_id="seg-unpriced",
        provider="demo",
        model="missing-model",
        prompt_tokens=10,
        completion_tokens=5,
    )

    with pytest.raises(ValueError, match="no rate"):
        estimate_segment_cost(segment, _pricing_snapshot())


def test_declared_pricing_snapshot_refuses_total_token_only_segments() -> None:
    segment = UsageSegment(
        segment_id="seg-total-only",
        provider="demo",
        model="fixture-model-small",
        total_tokens=15,
    )

    with pytest.raises(ValueError, match="prompt_tokens and completion_tokens"):
        estimate_segment_cost(segment, _pricing_snapshot())


def test_declared_pricing_snapshot_requires_explicit_token_class_rates() -> None:
    segment = UsageSegment(
        segment_id="seg-token-classes",
        provider="demo",
        model="fixture-model-small",
        prompt_tokens=10,
        completion_tokens=5,
        cached_tokens=2,
    )

    with pytest.raises(ValueError, match="explicit cached-input rate"):
        estimate_segment_cost(segment, _pricing_snapshot())

    priced = estimate_segment_cost(
        segment.model_copy(update={"reasoning_tokens": 1}),
        _pricing_snapshot(
            cached_input_million_tokens_usd="1.000000",
            reasoning_million_tokens_usd="4.000000",
        ),
    )

    assert priced.estimated_cost_microusd == 26


def test_declared_pricing_snapshot_overwrite_strips_only_known_pricing_limitations() -> None:
    old_snapshot = _pricing_snapshot(
        limitations=("Demo fixture pricing only; not live provider pricing.",)
    )
    new_snapshot = _pricing_snapshot(
        pricing_snapshot_id="local-demo-pricing-v2",
        limitations=("New demo pricing.",),
    )
    segment = UsageSegment(
        segment_id="seg-overwrite",
        provider="demo",
        model="fixture-model-small",
        prompt_tokens=10,
        completion_tokens=5,
        limitations=(
            "Usage segment includes partial measurement caveat.",
            "Reviewer pricing note is non-pricing provenance context.",
        ),
    )

    priced = estimate_segment_cost(segment, old_snapshot)
    repriced = estimate_segment_cost(priced, new_snapshot, overwrite=True)

    assert repriced.pricing_snapshot_id == "local-demo-pricing-v2"
    assert "Demo fixture pricing only; not live provider pricing." not in repriced.limitations
    assert "New demo pricing." in repriced.limitations
    assert "Usage segment includes partial measurement caveat." in repriced.limitations
    assert "Reviewer pricing note is non-pricing provenance context." in repriced.limitations


def test_usage_summary_records_pricing_snapshot_ids_from_segments() -> None:
    snapshot = _pricing_snapshot()
    priced = estimate_segment_cost(
        UsageSegment(
            segment_id="seg-priced",
            provider="demo",
            model="fixture-model-small",
            prompt_tokens=10,
            completion_tokens=5,
            total_tokens=15,
        ),
        snapshot,
    )

    summary = aggregate_usage_segments((priced,)).usage_summary

    assert summary.schema_version == "0.6.6"
    assert summary.estimated_cost_microusd == 25
    assert summary.estimated_cost_picousd == 25_000_000
    assert summary.cost_basis_ids == ("declared_pricing_snapshot_v2",)
    assert summary.pricing_snapshot_ids == ("local-demo-pricing-v1",)
    assert summary.pricing_snapshot_digests == (pricing_snapshot_digest(snapshot),)
    assert summary.cost_observation_count == 1


def test_v043_usage_fields_cannot_be_mislabeled_as_v031() -> None:
    with pytest.raises(ValidationError, match="schema_version 0.4.3"):
        UsageSegment(
            schema_version="0.3.1",
            segment_id="seg-v031-with-digest",
            pricing_snapshot_id="local-demo-pricing-v1",
            pricing_snapshot_digest="a" * 64,
        )
    with pytest.raises(ValidationError, match="schema_version 0.4.3"):
        UsageSummary(
            schema_version="0.3.1",
            total_tokens=1,
            pricing_snapshot_ids=("local-demo-pricing-v1",),
        )
    with pytest.raises(ValidationError, match="basis-point usage deltas require"):
        UsageSummaryDelta(
            schema_version="0.3.1",
            comparison_state="observed",
            baseline_observed=True,
            candidate_observed=True,
            total_tokens_delta=1,
            total_tokens_delta_bps=10_000,
        )


@pytest.mark.parametrize(
    "field_name",
    ("estimated_cost_picousd_delta", "estimated_cost_picousd_delta_bps"),
)
def test_v066_exact_cost_delta_fields_cannot_be_mislabeled_as_legacy(
    field_name: str,
) -> None:
    payload: dict[str, object] = {
        "schema_version": "0.4.3",
        "comparison_state": "observed",
        "baseline_observed": True,
        "candidate_observed": True,
        field_name: -1,
    }

    with pytest.raises(ValidationError, match="exact pico-USD usage deltas require"):
        UsageSummaryDelta.model_validate(payload)


@pytest.mark.parametrize(
    "cost_fields",
    (
        {"estimated_cost_microusd_delta": 1},
        {"estimated_cost_picousd_delta": 1},
    ),
)
def test_v066_cost_delta_requires_exact_and_projected_values(
    cost_fields: dict[str, int],
) -> None:
    payload: dict[str, object] = {
        "comparison_state": "observed",
        "baseline_observed": True,
        "candidate_observed": True,
        **cost_fields,
    }

    with pytest.raises(ValidationError, match="require exact pico-USD and projected micro-USD"):
        UsageSummaryDelta.model_validate(payload)


def test_exact_cost_delta_bps_requires_exact_delta_value() -> None:
    with pytest.raises(
        ValidationError,
        match="estimated_cost_picousd_delta_bps requires estimated_cost_picousd_delta",
    ):
        UsageSummaryDelta(
            comparison_state="observed",
            baseline_observed=True,
            candidate_observed=True,
            estimated_cost_picousd_delta_bps=1,
        )


def test_usage_segment_supports_future_stream_attachment_fields() -> None:
    segment = UsageSegment(
        segment_id="seg-stream-001",
        run_id="run-001",
        span_id="span-child",
        parent_span_id="span-parent",
        event_range_start=7,
        event_range_end=9,
    )

    assert segment.span_id == "span-child"
    assert segment.parent_span_id == "span-parent"
    assert segment.event_range_start == 7
    assert segment.event_range_end == 9


def test_usage_segment_rejects_inverted_event_range() -> None:
    with pytest.raises(ValidationError, match="event_range_end"):
        UsageSegment(segment_id="seg-bad-range", event_range_start=10, event_range_end=9)


def test_usage_segment_requires_limitations_for_declared_estimated_cost() -> None:
    with pytest.raises(ValidationError, match="cost-bearing usage segments require"):
        UsageSegment(segment_id="seg-cost-no-limitation", estimated_cost_microusd=1)


def test_micro_usd_cost_fields_are_usd_only() -> None:
    with pytest.raises(ValidationError, match="currency USD"):
        UsageSegment(
            segment_id="seg-eur-cost",
            estimated_cost_microusd=1,
            currency="EUR",
            limitations=(DECLARED_PRICING_LIMITATION,),
        )
    with pytest.raises(ValidationError, match="currency USD"):
        UsageSummary(estimated_cost_microusd=1, currency="EUR")
    with pytest.raises(ValidationError, match="currency USD"):
        UsageSummaryDelta(
            comparison_state="observed",
            baseline_observed=True,
            candidate_observed=True,
            estimated_cost_microusd_delta=1,
            currency="EUR",
        )
    with pytest.raises(ValidationError, match="currency USD"):
        UsageSummaryDelta(
            comparison_state="observed",
            baseline_observed=True,
            candidate_observed=True,
            estimated_cost_picousd_delta=-1,
            currency="EUR",
        )
    with pytest.raises(ValidationError, match="currency USD"):
        _pricing_snapshot(currency="EUR")


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            UsageSegment,
            {
                "artifact_kind": "usage-segment",
                "schema_version": "0.2.0",
                "segment_id": "seg-legacy-version",
            },
        ),
        (
            UsageLedger,
            {
                "artifact_kind": "usage-ledger",
                "schema_version": "0.2.0",
            },
        ),
        (
            UsageSummary,
            {
                "artifact_kind": "usage-summary",
                "schema_version": "0.2.0",
            },
        ),
        (
            UsageSummaryDelta,
            {
                "artifact_kind": "usage-summary-delta",
                "schema_version": "0.2.0",
                "comparison_state": "observed",
                "baseline_observed": True,
                "candidate_observed": True,
            },
        ),
    ],
)
def test_usage_roots_reject_legacy_schema_version(
    model: type[BaseModel],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_usage_ledger_rejects_missingness_that_conflicts_with_segments() -> None:
    segment = UsageSegment(segment_id="seg-missingness", total_tokens=5)

    with pytest.raises(ValidationError, match="usage ledger missingness must match segments"):
        UsageLedger(segments=(segment,), missingness={})


def test_complete_only_usage_aggregation_requires_v066_ledger_contract() -> None:
    with pytest.raises(ValidationError, match="schema_version 0.6.6"):
        UsageLedger(
            schema_version="0.4.3",
            aggregation_method="sum_complete_fields_v2",
        )
    with pytest.raises(ValidationError, match="0.6.6 requires sum_complete_fields_v2"):
        UsageLedger(
            schema_version="0.6.6",
            aggregation_method="sum_known_fields_v1",
        )

    legacy = UsageLedger(
        schema_version="0.4.3",
        aggregation_method="sum_known_fields_v1",
    )

    assert legacy.schema_version == "0.4.3"
    assert UsageLedger().schema_version == "0.6.6"


def test_legacy_usage_ledger_omission_uses_historical_aggregation_default() -> None:
    ledger = UsageLedger.model_validate(
        {
            "artifact_kind": "usage-ledger",
            "schema_version": "0.4.3",
            "segments": [],
            "missingness": {},
        }
    )

    assert ledger.aggregation_method == "sum_known_fields_v1"


def _usage_ledger_with_legacy_identifier_payload(
    *,
    parent_schema_version: str | None,
    segment_schema_version: str,
    provider: str,
    model: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "usage-ledger",
        "segments": [
            {
                "artifact_kind": "usage-segment",
                "schema_version": segment_schema_version,
                "segment_id": "legacy-child-valid",
                "provider": "provider-1",
                "model": "model-1",
            },
            {
                "artifact_kind": "usage-segment",
                "schema_version": segment_schema_version,
                "segment_id": "legacy-child-under-test",
                "provider": provider,
                "model": model,
            },
        ],
        "missingness": {field_name: 2 for field_name in USAGE_SEGMENT_SUM_FIELDS},
    }
    if parent_schema_version is not None:
        payload["schema_version"] = parent_schema_version
        payload["aggregation_method"] = (
            "sum_complete_fields_v2" if parent_schema_version == "0.6.6" else "sum_known_fields_v1"
        )
    return payload


@pytest.mark.parametrize("segment_schema_version", ("0.3.1", "0.4.3"))
@pytest.mark.parametrize("field_name", ("provider", "model"))
def test_current_usage_ledger_revalidates_every_legacy_child_machine_identifier(
    segment_schema_version: str,
    field_name: str,
) -> None:
    identifiers = {"provider": "provider-1", "model": "model-1"}
    identifiers[field_name] = "legacy\u200bidentifier"
    valid_current_parent_payload = _usage_ledger_with_legacy_identifier_payload(
        parent_schema_version="0.6.6",
        segment_schema_version=segment_schema_version,
        provider="provider-1",
        model="model-1",
    )
    default_parent_payload = _usage_ledger_with_legacy_identifier_payload(
        parent_schema_version=None,
        segment_schema_version=segment_schema_version,
        **identifiers,
    )
    current_parent_payload = _usage_ledger_with_legacy_identifier_payload(
        parent_schema_version="0.6.6",
        segment_schema_version=segment_schema_version,
        **identifiers,
    )

    UsageLedger.model_validate(valid_current_parent_payload)
    for payload in (default_parent_payload, current_parent_payload):
        with pytest.raises(
            ValidationError,
            match=rf"segments\[1\]\.{field_name} must use the ASCII machine-identifier grammar",
        ):
            UsageLedger.model_validate(payload)

    schema = UsageLedger.model_json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(valid_current_parent_payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema).validate(current_parent_payload)


@pytest.mark.parametrize("schema_version", ("0.3.1", "0.4.3"))
def test_legacy_usage_ledger_keeps_legacy_child_identifiers_readable(
    schema_version: str,
) -> None:
    payload = _usage_ledger_with_legacy_identifier_payload(
        parent_schema_version=schema_version,
        segment_schema_version=schema_version,
        provider="legacy vendor\u200b",
        model="legacy model",
    )

    ledger = UsageLedger.model_validate(payload)

    assert ledger.aggregation_method == "sum_known_fields_v1"
    assert ledger.segments[1].provider == "legacy vendor\u200b"
    Draft202012Validator(UsageLedger.model_json_schema(mode="validation")).validate(payload)


def test_legacy_labeled_containers_reject_usage_fields() -> None:
    cases: tuple[tuple[type[BaseModel], dict[str, object]], ...] = (
        (AgentRunRecord, _legacy_agent_run_record_payload(usage_summary=_usage_summary_payload())),
        (RunSet, _legacy_runset_payload(usage_summary=_usage_summary_payload())),
        (RunSet, _legacy_runset_payload(runs=(_agent_run_record_payload(),))),
        (EvaluationSummary, _legacy_evaluation_summary_payload(_usage_summary_payload())),
        (ComparisonSummary, _legacy_comparison_summary_payload(_usage_delta_payload())),
        (EvidencePacket, _legacy_evidence_packet_payload(usage_summary=_usage_summary_payload())),
        (
            EvidencePacket,
            _legacy_evidence_packet_payload(
                evaluation=_evaluation_summary_payload(usage_summary=_usage_summary_payload())
            ),
        ),
        (EvaluationReport, _legacy_evaluation_report_payload(_usage_summary_payload())),
        (
            EvaluationReport,
            _legacy_evaluation_report_payload(
                None,
                candidate_vs_expectations=_evaluation_summary_payload(
                    usage_summary=_usage_summary_payload()
                ),
            ),
        ),
        (ComparisonReport, _legacy_comparison_report_payload(usage_delta=_usage_delta_payload())),
        (
            ComparisonReport,
            _legacy_comparison_report_payload(
                comparison_summary=_comparison_summary_payload(usage_delta=_usage_delta_payload())
            ),
        ),
    )

    for model, payload in cases:
        with pytest.raises(ValidationError, match="usage fields require schema_version 0.3.1"):
            model.model_validate(payload)


def test_aggregate_usage_segments_sums_known_fields_and_tracks_missingness() -> None:
    digest = pricing_snapshot_digest(_pricing_snapshot())
    first = UsageSegment(
        segment_id="seg-001",
        total_tokens=100,
        tool_call_count=2,
        retry_count=1,
        latency_ms=50,
        estimated_cost_microusd=400,
        estimated_cost_picousd=400_000_000,
        cost_basis="declared_pricing_snapshot_v1",
        pricing_snapshot_id="local-demo-pricing-v1",
        pricing_snapshot_digest=digest,
        limitations=(DECLARED_PRICING_LIMITATION,),
    )
    second = UsageSegment(
        segment_id="seg-002",
        total_tokens=50,
        retry_count=0,
        estimated_cost_microusd=100,
        estimated_cost_picousd=100_000_000,
        cost_basis="declared_pricing_snapshot_v1",
        pricing_snapshot_id="local-demo-pricing-v1",
        pricing_snapshot_digest=digest,
        limitations=(DECLARED_PRICING_LIMITATION,),
    )

    aggregation = aggregate_usage_segments((first, second))

    assert aggregation.usage_ledger == UsageLedger(
        segments=(first, second),
        aggregation_method="sum_complete_fields_v2",
        missingness={
            "cached_tokens": 2,
            "completion_tokens": 2,
            "latency_ms": 1,
            "prompt_tokens": 2,
            "reasoning_tokens": 2,
            "tool_call_count": 1,
        },
    )
    assert aggregation.usage_summary == UsageSummary(
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="usage_segment",
        source_count=2,
        coverage_counts={
            "total_tokens": 2,
            "total_tool_calls": 1,
            "total_retries": 2,
            "total_latency_ms": 1,
            "estimated_cost_microusd": 2,
        },
        total_tokens=150,
        total_tool_calls=None,
        total_retries=1,
        total_latency_ms=None,
        estimated_cost_microusd=500,
        estimated_cost_picousd=500_000_000,
        cost_basis_ids=("declared_pricing_snapshot_v1",),
        pricing_snapshot_ids=("local-demo-pricing-v1",),
        pricing_snapshot_digests=(digest,),
        limitations=(
            DECLARED_PRICING_LIMITATION,
            (
                "Declared estimated cost per cost observation was not rendered because "
                "multiple cost-bearing segments did not all declare run_id or case_id."
            ),
            (
                "Usage summary does not aggregate incomplete metric fields; "
                "missing segment fields: cached_tokens=2, completion_tokens=2, "
                "latency_ms=1, prompt_tokens=2, reasoning_tokens=2, tool_call_count=1."
            ),
        ),
    )


def test_usage_aggregation_rejects_forged_typed_segment_before_derivation() -> None:
    segment = UsageSegment(segment_id="forged", total_tokens=1).model_copy(
        update={"artifact_kind": "forged-segment"}
    )

    with pytest.raises(ValidationError, match="artifact_kind"):
        aggregate_usage_segments((segment,))


def test_usage_aggregation_refuses_partial_metric_and_cost_coverage() -> None:
    priced = UsageSegment(
        segment_id="priced",
        total_tokens=10,
        estimated_cost_microusd=5,
        estimated_cost_picousd=5_000_000,
        cost_basis="declared_pricing_snapshot_v2",
        pricing_snapshot_id="pricing-v2",
        pricing_snapshot_digest="a" * 64,
        limitations=(DECLARED_PRICING_LIMITATION,),
    )
    missing = UsageSegment(segment_id="missing")

    summary = aggregate_usage_segments((priced, missing)).usage_summary

    assert summary.total_tokens is None
    assert summary.estimated_cost_microusd is None
    assert any("cost coverage was incomplete" in item for item in summary.limitations)


def test_v066_cost_aggregation_does_not_manufacture_exact_pico_usd() -> None:
    micro_only = UsageSegment(
        segment_id="micro-only",
        estimated_cost_microusd=5,
        cost_basis="declared_pricing_snapshot_v1",
        pricing_snapshot_id="pricing-v1",
        pricing_snapshot_digest="a" * 64,
        limitations=(DECLARED_PRICING_LIMITATION,),
    )

    current = aggregate_usage_segments((micro_only,)).usage_summary
    legacy = summarize_usage_segments(
        (micro_only,),
        aggregation_method="sum_known_fields_v1",
    )

    assert current.estimated_cost_microusd is None
    assert current.estimated_cost_picousd is None
    assert any("exact pico-USD coverage was incomplete" in item for item in current.limitations)
    assert legacy.schema_version == "0.4.3"
    assert legacy.estimated_cost_microusd == 5
    assert legacy.estimated_cost_picousd is None


def test_cost_observation_count_uses_run_or_case_identity() -> None:
    digest = pricing_snapshot_digest(_pricing_snapshot())
    first = UsageSegment(
        segment_id="seg-run-1-a",
        run_id="run-1",
        estimated_cost_microusd=100,
        estimated_cost_picousd=100_000_000,
        cost_basis="declared_pricing_snapshot_v1",
        pricing_snapshot_id="local-demo-pricing-v1",
        pricing_snapshot_digest=digest,
        limitations=(DECLARED_PRICING_LIMITATION,),
    )
    second = first.model_copy(update={"segment_id": "seg-run-1-b"})
    third = first.model_copy(update={"segment_id": "seg-run-2", "run_id": "run-2"})
    case_only = (
        first.model_copy(update={"segment_id": "seg-case-1", "run_id": None, "case_id": "case-1"}),
        first.model_copy(update={"segment_id": "seg-case-2", "run_id": None, "case_id": "case-2"}),
    )

    by_run = aggregate_usage_segments((first, second, third)).usage_summary
    by_case = aggregate_usage_segments(case_only).usage_summary

    assert by_run.cost_observation_count == 2
    assert by_case.cost_observation_count == 2
    assert any("distinct case_id values" in item for item in by_case.limitations)


def test_cost_aggregation_requires_complete_homogeneous_provenance() -> None:
    missing_provenance = aggregate_usage_segments(
        (
            UsageSegment(
                segment_id="seg-cost-unknown",
                estimated_cost_microusd=100,
                limitations=(DECLARED_PRICING_LIMITATION,),
            ),
        )
    ).usage_summary
    digest = pricing_snapshot_digest(_pricing_snapshot())
    mixed_snapshots = aggregate_usage_segments(
        (
            UsageSegment(
                segment_id="seg-cost-v1",
                estimated_cost_microusd=100,
                cost_basis="declared_pricing_snapshot_v1",
                pricing_snapshot_id="local-demo-pricing-v1",
                pricing_snapshot_digest=digest,
                limitations=(DECLARED_PRICING_LIMITATION,),
            ),
            UsageSegment(
                segment_id="seg-cost-v2",
                estimated_cost_microusd=100,
                cost_basis="declared_pricing_snapshot_v1",
                pricing_snapshot_id="local-demo-pricing-v2",
                pricing_snapshot_digest=digest,
                limitations=(DECLARED_PRICING_LIMITATION,),
            ),
        )
    ).usage_summary

    assert missing_provenance.estimated_cost_microusd is None
    assert any("must declare cost_basis" in item for item in missing_provenance.limitations)
    assert mixed_snapshots.estimated_cost_microusd is None
    assert any("pricing snapshot IDs differ" in item for item in mixed_snapshots.limitations)


def test_runset_rejects_usage_summary_that_conflicts_with_ledger() -> None:
    segment = UsageSegment(segment_id="seg-001", total_tokens=100)
    aggregation = aggregate_usage_segments((segment,))

    with pytest.raises(ValidationError, match="usage_summary does not match usage_ledger"):
        RunSet(
            schema_version="0.6.2",
            runset_id="runset-001",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            suite_id="suite-001",
            suite_version="0.1.0",
            suite_digest="0" * 64,
            fixture_manifest_digest="1" * 64,
            usage_ledger=aggregation.usage_ledger,
            usage_summary=aggregation.usage_summary.model_copy(update={"total_tokens": 999}),
            runs=(
                AgentRunRecord(
                    run_id="run-001",
                    case_id="case-001",
                    pipeline_id="pipeline-001",
                    recommendation="approve",
                    outcome="approved",
                    input_summary="input",
                    output_summary="output",
                ),
            ),
        )


def test_runset_usage_suppresses_wholly_missing_run_coverage() -> None:
    observed = aggregate_usage_segments(
        (UsageSegment(segment_id="seg-run-1", run_id="run-1", total_tokens=10),)
    )
    runset = _usage_runset(
        runs=(
            _usage_run_record("run-1"),
            _usage_run_record("run-2"),
        ),
        usage_ledger=observed.usage_ledger,
        usage_summary=observed.usage_summary,
    )

    summary = usage_summary_for_runset(runset)

    assert summary is not None
    assert summary.total_tokens is None
    assert summary.coverage_basis == "run_record"
    assert summary.source_count == 2
    assert summary.coverage_counts is not None
    assert summary.coverage_counts.total_tokens == 1
    assert any("usage ledger did not bind" in item for item in summary.limitations)


def test_runset_usage_rejects_forged_typed_root_before_derivation() -> None:
    runset = _usage_runset(runs=(_usage_run_record("run-1"),)).model_copy(
        update={"artifact_kind": "forged-run-set"}
    )

    with pytest.raises(ValidationError, match="artifact_kind"):
        usage_summary_for_runset(runset)


def test_runset_usage_does_not_trust_unverifiable_top_level_summary() -> None:
    runset = _usage_runset(
        runs=(_usage_run_record("run-1"),),
        usage_summary=UsageSummary(total_tokens=10),
    )

    summary = usage_summary_for_runset(runset)

    assert summary is not None
    assert summary.total_tokens is None
    assert summary.coverage_basis == "run_record"
    assert summary.source_count == 1
    assert summary.coverage_counts is not None
    assert summary.coverage_counts.total_tokens == 0
    assert any("no ledger or run-level coverage evidence" in item for item in summary.limitations)


def test_summary_only_runset_requires_trustworthy_v066_coverage() -> None:
    trusted = UsageSummary(
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="usage_segment",
        source_count=1,
        coverage_counts={"total_tokens": 1},
        total_tokens=10,
    )
    trusted_runset = _usage_runset(
        runs=(
            _usage_run_record("run-1", usage_summary=trusted),
            _usage_run_record(
                "run-2",
                usage_summary=trusted.model_copy(update={"total_tokens": 15}),
            ),
        ),
    )
    untrusted_runset = _usage_runset(
        runs=(
            _usage_run_record(
                "run-1",
                usage_summary=UsageSummary(
                    schema_version="0.4.3",
                    total_tokens=10,
                ),
            ),
        ),
    )
    nested_rollup_runset = _usage_runset(
        runs=(
            _usage_run_record(
                "run-1",
                usage_summary=UsageSummary(
                    aggregation_method="sum_complete_fields_v2",
                    coverage_basis="run_record",
                    source_count=2,
                    coverage_counts={"total_tokens": 2},
                    total_tokens=20,
                ),
            ),
        ),
    )

    trusted_summary = usage_summary_for_runset(trusted_runset)
    with pytest.raises(ValueError, match="run-set artifact failed JSON Schema validation"):
        usage_summary_for_runset(untrusted_runset)
    nested_rollup_summary = usage_summary_for_runset(nested_rollup_runset)

    assert trusted_summary is not None
    assert trusted_summary.coverage_basis == "run_record"
    assert trusted_summary.source_count == 2
    assert trusted_summary.coverage_counts is not None
    assert trusted_summary.coverage_counts.total_tokens == 2
    assert trusted_summary.total_tokens == 25
    assert nested_rollup_summary is not None
    assert nested_rollup_summary.total_tokens is None
    assert nested_rollup_summary.source_count == 1


def test_zero_source_summary_cannot_manufacture_a_zero_usage_observation() -> None:
    with pytest.raises(ValidationError, match="positive usage source_count"):
        UsageSummary(
            aggregation_method="sum_complete_fields_v2",
            coverage_basis="usage_segment",
            source_count=0,
            coverage_counts={"total_tokens": 0},
            total_tokens=0,
        )

    forged = UsageSummary().model_copy(
        update={
            "coverage_basis": "usage_segment",
            "source_count": 0,
            "total_tokens": 0,
        }
    )
    forged_run = _usage_run_record("run-1").model_copy(update={"usage_summary": forged})

    with pytest.raises(ValidationError, match="positive usage source_count"):
        usage_summary_for_runset(_usage_runset(runs=(forged_run,)))


def test_runset_rollup_sums_exact_cost_before_micro_usd_projection() -> None:
    digest = pricing_snapshot_digest(_pricing_snapshot())

    def cost_run(run_id: str) -> AgentRunRecord:
        segment = UsageSegment(
            segment_id=f"segment-{run_id}",
            run_id=run_id,
            estimated_cost_microusd=0,
            estimated_cost_picousd=500_000,
            cost_basis="declared_pricing_snapshot_v2",
            pricing_snapshot_id="local-demo-pricing-v1",
            pricing_snapshot_digest=digest,
            limitations=(DECLARED_PRICING_LIMITATION,),
        )
        usage = aggregate_usage_segments((segment,))
        return _usage_run_record(run_id, usage_ledger=usage.usage_ledger)

    summary = usage_summary_for_runset(_usage_runset(runs=(cost_run("run-1"), cost_run("run-2"))))

    assert summary is not None
    assert summary.coverage_basis == "run_record"
    assert summary.source_count == 2
    assert summary.estimated_cost_picousd == 1_000_000
    assert summary.estimated_cost_microusd == 1


def test_runset_comparison_normalizes_segmented_evidence_to_run_coverage() -> None:
    baseline_usage = aggregate_usage_segments(
        (
            UsageSegment(
                segment_id="baseline",
                run_id="run-1",
                total_tokens=10,
            ),
        )
    )
    candidate_usage = aggregate_usage_segments(
        (
            UsageSegment(
                segment_id="candidate-a",
                run_id="run-1",
                total_tokens=5,
            ),
            UsageSegment(
                segment_id="candidate-b",
                run_id="run-1",
                total_tokens=7,
            ),
        )
    )
    baseline = usage_summary_for_runset(
        _usage_runset(
            runs=(_usage_run_record("run-1"),),
            usage_ledger=baseline_usage.usage_ledger,
            usage_summary=baseline_usage.usage_summary,
        )
    )
    candidate = usage_summary_for_runset(
        _usage_runset(
            runs=(_usage_run_record("run-1"),),
            usage_ledger=candidate_usage.usage_ledger,
            usage_summary=candidate_usage.usage_summary,
        )
    )

    assert baseline is not None
    assert candidate is not None
    assert baseline.coverage_basis == candidate.coverage_basis == "run_record"
    assert baseline.source_count == candidate.source_count == 1
    assert compare_usage_summaries(baseline, candidate).total_tokens_delta == 2


def test_compare_usage_summaries_reports_observed_delta_without_float_money() -> None:
    baseline = _usage_summary_with_cost(
        total_tokens=100,
        total_tool_calls=2,
        total_retries=1,
        total_latency_ms=50,
        estimated_cost_microusd=400,
    )
    candidate = _usage_summary_with_cost(
        total_tokens=140,
        total_tool_calls=3,
        total_retries=1,
        total_latency_ms=75,
        estimated_cost_microusd=425,
    )

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.comparison_state == "observed"
    assert delta.total_tokens_delta == 40
    assert delta.total_tokens_delta_bps == 4000
    assert delta.total_tool_calls_delta == 1
    assert delta.total_tool_calls_delta_bps == 5000
    assert delta.total_retries_delta == 0
    assert delta.total_retries_delta_bps == 0
    assert delta.total_latency_ms_delta == 25
    assert delta.total_latency_ms_delta_bps == 5000
    assert delta.estimated_cost_microusd_delta == 25
    assert delta.estimated_cost_microusd_delta_bps == 625
    assert delta.estimated_cost_picousd_delta == 25_000_000
    assert delta.estimated_cost_picousd_delta_bps == 625
    assert "ROI" not in format_usage_delta(delta)
    assert "bps" in format_usage_delta(delta)
    assert "+25000000 pico-USD" in format_usage_delta(delta)


def test_usage_comparison_and_renderers_reject_forged_typed_roots() -> None:
    baseline = UsageSummary(total_tokens=1).model_copy(update={"artifact_kind": "forged-summary"})

    with pytest.raises(ValidationError, match="artifact_kind"):
        compare_usage_summaries(baseline, UsageSummary(total_tokens=2))
    with pytest.raises(ValidationError, match="artifact_kind"):
        usage_summary_lines(baseline)

    delta = UsageSummaryDelta(
        comparison_state="not_observed",
        baseline_observed=False,
        candidate_observed=False,
    ).model_copy(update={"artifact_kind": "forged-delta"})
    with pytest.raises(ValidationError, match="artifact_kind"):
        format_usage_delta(delta)


def test_compare_usage_summaries_preserves_sub_micro_cost_delta_exactly() -> None:
    baseline = _usage_summary_with_cost(
        estimated_cost_microusd=0,
        estimated_cost_picousd=100_000,
    )
    candidate = _usage_summary_with_cost(
        estimated_cost_microusd=0,
        estimated_cost_picousd=400_000,
    )

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.estimated_cost_microusd_delta == 0
    assert delta.estimated_cost_microusd_delta_bps == 30_000
    assert delta.estimated_cost_picousd_delta == 300_000
    assert delta.estimated_cost_picousd_delta_bps == 30_000
    assert "+300000 pico-USD (+30000 bps)" in format_usage_delta(delta)


def test_format_usage_delta_retains_historical_micro_usd_fallback() -> None:
    delta = UsageSummaryDelta(
        schema_version="0.4.3",
        comparison_state="observed",
        baseline_observed=True,
        candidate_observed=True,
        estimated_cost_microusd_delta=-3,
        estimated_cost_microusd_delta_bps=-750,
    )

    rendered = format_usage_delta(delta)

    assert "-3 micro-USD (-750 bps)" in rendered
    assert "pico-USD" not in rendered


def test_compare_usage_summaries_uses_truncated_integer_basis_points() -> None:
    baseline = UsageSummary(total_tokens=18420)
    candidate = UsageSummary(total_tokens=25980)

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.total_tokens_delta == 7560
    assert delta.total_tokens_delta_bps == 4104


def test_compare_usage_summaries_reports_negative_basis_points() -> None:
    baseline = _usage_summary_with_cost(total_tokens=100, estimated_cost_microusd=1000)
    candidate = _usage_summary_with_cost(total_tokens=75, estimated_cost_microusd=700)

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.total_tokens_delta == -25
    assert delta.total_tokens_delta_bps == -2500
    assert delta.estimated_cost_microusd_delta == -300
    assert delta.estimated_cost_microusd_delta_bps == -3000


def test_usage_delta_requires_compatible_coverage_basis_and_denominator() -> None:
    baseline = UsageSummary(
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="usage_segment",
        source_count=1,
        coverage_counts={"total_tokens": 1},
        total_tokens=10,
    )
    cross_basis = UsageSummary(
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="run_record",
        source_count=1,
        coverage_counts={"total_tokens": 1},
        total_tokens=12,
    )
    different_denominator = UsageSummary(
        aggregation_method="sum_complete_fields_v2",
        coverage_basis="usage_segment",
        source_count=2,
        coverage_counts={"total_tokens": 2},
        total_tokens=12,
    )

    basis_delta = compare_usage_summaries(baseline, cross_basis)
    denominator_delta = compare_usage_summaries(baseline, different_denominator)

    assert basis_delta.total_tokens_delta is None
    assert any("coverage bases differ" in item for item in basis_delta.limitations)
    assert denominator_delta.total_tokens_delta is None
    assert any("coverage source counts differ" in item for item in denominator_delta.limitations)


def test_usage_delta_rejects_legacy_summaries_without_coverage_metadata() -> None:
    baseline = UsageSummary(schema_version="0.4.3", total_tokens=10)
    candidate = UsageSummary(schema_version="0.4.3", total_tokens=12)

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.total_tokens_delta is None
    assert any(
        "require schema_version 0.6.6 complete-coverage metadata" in item
        for item in delta.limitations
    )


def test_declared_cost_delta_requires_comparable_pricing_snapshots() -> None:
    digest = pricing_snapshot_digest(_pricing_snapshot())
    baseline = _usage_summary_with_cost(
        estimated_cost_microusd=1000,
        pricing_snapshot_ids=("local-demo-pricing-v1",),
        pricing_snapshot_digests=(digest,),
    )
    candidate = _usage_summary_with_cost(
        estimated_cost_microusd=700,
        pricing_snapshot_ids=("local-demo-pricing-v2",),
        pricing_snapshot_digests=(digest,),
    )

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.estimated_cost_microusd_delta is None
    assert any("pricing snapshots differ" in limitation for limitation in delta.limitations)


@pytest.mark.parametrize(
    ("baseline_ids", "candidate_ids", "expected_limitation"),
    [
        ((), (), "pricing snapshot IDs were not declared for both sides"),
        (("local-demo-pricing-v1",), (), "pricing snapshot IDs were not declared"),
        ((), ("local-demo-pricing-v1",), "pricing snapshot IDs were not declared"),
    ],
)
def test_declared_cost_delta_requires_snapshot_ids_on_both_sides(
    baseline_ids: tuple[str, ...],
    candidate_ids: tuple[str, ...],
    expected_limitation: str,
) -> None:
    baseline = _usage_summary_with_cost(
        estimated_cost_microusd=1000,
        pricing_snapshot_ids=baseline_ids,
        pricing_snapshot_digests=(),
    )
    candidate = _usage_summary_with_cost(
        estimated_cost_microusd=700,
        pricing_snapshot_ids=candidate_ids,
        pricing_snapshot_digests=(),
    )

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.estimated_cost_microusd_delta is None
    assert any(expected_limitation in limitation for limitation in delta.limitations)


def test_declared_cost_delta_requires_matching_snapshot_digests() -> None:
    baseline = _usage_summary_with_cost(
        estimated_cost_microusd=1000,
        pricing_snapshot_digests=("a" * 64,),
    )
    candidate = _usage_summary_with_cost(
        estimated_cost_microusd=700,
        pricing_snapshot_digests=("b" * 64,),
    )

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.estimated_cost_microusd_delta is None
    assert any("pricing snapshot digests differ" in item for item in delta.limitations)


def test_declared_cost_delta_requires_cost_basis_on_both_sides() -> None:
    digest = pricing_snapshot_digest(_pricing_snapshot())
    baseline = UsageSummary(
        estimated_cost_microusd=1000,
        estimated_cost_picousd=1_000_000_000,
        pricing_snapshot_ids=("local-demo-pricing-v1",),
        pricing_snapshot_digests=(digest,),
    )
    candidate = _usage_summary_with_cost(estimated_cost_microusd=700)

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.estimated_cost_microusd_delta is None
    assert any("cost basis was not declared" in item for item in delta.limitations)


def test_basis_points_note_zero_baseline_limitations_without_side_effects() -> None:
    baseline = UsageSummary(total_tokens=0)
    candidate = UsageSummary(total_tokens=5)

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.total_tokens_delta == 5
    assert delta.total_tokens_delta_bps is None
    assert any("total_tokens_delta_bps" in item for item in delta.limitations)


def test_compare_usage_summaries_treats_missing_usage_as_not_observed() -> None:
    delta = compare_usage_summaries(None, None)

    assert delta.comparison_state == "not_observed"
    assert delta.baseline_observed is False
    assert delta.candidate_observed is False
    assert format_usage_delta(delta) == "Measured usage: not_observed."


def test_usage_delta_carries_partial_missingness_limitations() -> None:
    baseline = aggregate_usage_segments(
        (UsageSegment(segment_id="baseline-seg", total_tokens=100),)
    ).usage_summary
    candidate = aggregate_usage_segments(
        (UsageSegment(segment_id="candidate-seg", total_tokens=125),)
    ).usage_summary

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.total_tokens_delta == 25
    assert any(
        "does not aggregate incomplete metric fields" in limitation
        for limitation in delta.limitations
    )
    assert "does not aggregate incomplete metric fields" in format_usage_delta(delta)


def test_usage_delta_separates_higher_usage_from_governance_state() -> None:
    baseline = UsageSummary(total_tokens=100, total_tool_calls=1, total_retries=0)
    candidate = UsageSummary(total_tokens=125, total_tool_calls=2, total_retries=1)

    delta = compare_usage_summaries(baseline, candidate)

    assert delta.comparison_state == "observed"
    assert delta.total_tokens_delta == 25
    assert delta.total_tool_calls_delta == 1
    assert delta.total_retries_delta == 1
    assert "fail" not in format_usage_delta(delta).lower()


def test_report_markdown_uses_measured_language_for_missing_usage() -> None:
    suite_path = ROOT / "examples" / "prior_auth_synthetic" / "suite.yaml"
    variant_path = ROOT / "examples" / "prior_auth_synthetic" / "variants" / "baseline.yaml"
    compiled = compile_suite(suite_path)
    runset = run_suite(
        compiled,
        load_variant_config(variant_path),
        suite_path.parent,
    )
    report = evaluate_runset(compiled, runset)

    assert report.usage_summary is None

    rendered = render_evaluation_markdown(report)

    assert "## Measured Usage" in rendered
    assert "not_observed" in rendered
    assert "ROI" not in rendered


def _usage_summary_payload() -> dict[str, object]:
    return UsageSummary(total_tokens=1).model_dump(mode="json")


def _usage_delta_payload() -> dict[str, object]:
    return UsageSummaryDelta(
        comparison_state="observed",
        baseline_observed=True,
        candidate_observed=True,
        total_tokens_delta=1,
    ).model_dump(mode="json")


def _agent_run_record_payload() -> dict[str, object]:
    payload = _legacy_agent_run_record_payload()
    payload["schema_version"] = "0.3.1"
    payload["usage_summary"] = _usage_summary_payload()
    return payload


def _legacy_agent_run_record_payload(
    *,
    usage_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "agent-run-record",
        "schema_version": "0.2.0",
        "run_id": "run-001",
        "case_id": "case-001",
        "pipeline_id": "pipeline-001",
        "recommendation": "approve",
        "outcome": "approved",
        "input_summary": "input",
        "output_summary": "output",
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_runset_payload(
    *,
    usage_summary: dict[str, object] | None = None,
    runs: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "run-set",
        "schema_version": "0.2.0",
        "runset_id": "runset-001",
        "suite_id": "suite-001",
        "suite_version": "0.1.0",
        "suite_digest": "0" * 64,
        "fixture_manifest_digest": "1" * 64,
        "runs": list(runs),
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _evaluation_summary_payload(
    *,
    usage_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "evaluation-summary",
        "schema_version": "0.3.1",
        "runset_id": "runset-001",
        "state": "pass",
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_evaluation_summary_payload(
    usage_summary: dict[str, object],
) -> dict[str, object]:
    payload = _evaluation_summary_payload(usage_summary=usage_summary)
    payload["schema_version"] = "0.2.0"
    return payload


def _comparison_summary_payload(
    *,
    usage_delta: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "comparison-summary",
        "schema_version": "0.3.1",
        "baseline_runset_id": "baseline",
        "candidate_runset_id": "candidate",
        "classification": ComparisonClassification.not_evaluated.value,
    }
    if usage_delta is not None:
        payload["usage_delta"] = usage_delta
    return payload


def _legacy_comparison_summary_payload(
    usage_delta: dict[str, object],
) -> dict[str, object]:
    payload = _comparison_summary_payload(usage_delta=usage_delta)
    payload["schema_version"] = "0.2.0"
    return payload


def _legacy_evidence_packet_payload(
    *,
    evaluation: dict[str, object] | None = None,
    usage_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "evidence-packet",
        "schema_version": "0.2.0",
        "packet_id": "packet-001",
        "interpretation": ["read candidate state first"],
        "evaluation": evaluation or _evaluation_summary_payload(),
        "limitations": ["fixture evidence only"],
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_evaluation_report_payload(
    usage_summary: dict[str, object] | None,
    *,
    candidate_vs_expectations: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "evaluation-report",
        "schema_version": "0.2.0",
        "candidate_vs_expectations": candidate_vs_expectations or _evaluation_summary_payload(),
        "runset_id": "runset-001",
        "suite_id": "suite-001",
        "suite_version": "0.1.0",
        "gate_profile": "default",
        "metrics": _metrics_payload(),
    }
    if usage_summary is not None:
        payload["usage_summary"] = usage_summary
    return payload


def _legacy_comparison_report_payload(
    *,
    comparison_summary: dict[str, object] | None = None,
    usage_delta: dict[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "comparison-report",
        "schema_version": "0.2.0",
        "candidate_vs_expectations": _evaluation_summary_payload(),
        "verdict_explanations": [],
        "fixture_equivalence": {"state": "not_evaluated"},
        "baseline_vs_expectations": _evaluation_summary_payload(),
        "control_changes": [],
        "behavioral_changes": [],
        "provenance_changes": [],
        "not_evaluated_capabilities": [],
        "limitations": ["fixture evidence only"],
        "comparison_summary": comparison_summary or _comparison_summary_payload(),
        "baseline_metrics": _metrics_payload(),
        "candidate_metrics": _metrics_payload(),
        "suite_id": "suite-001",
        "suite_version": "0.1.0",
        "gate_profile": "default",
    }
    if usage_delta is not None:
        payload["usage_delta"] = usage_delta
    return payload


def _metrics_payload() -> dict[str, object]:
    return EvaluationMetrics(
        total_cases=1,
        evaluated_cases=1,
        unevaluated_cases=0,
        passed_cases=1,
        failed_cases=0,
        warning_findings=0,
        blocking_findings=0,
        global_blocking_findings=0,
        findings_by_reason={},
        findings_by_control={},
    ).model_dump(mode="json")


def _usage_summary_with_cost(
    *,
    estimated_cost_microusd: int,
    estimated_cost_picousd: int | None = None,
    total_tokens: int | None = None,
    total_tool_calls: int | None = None,
    total_retries: int | None = None,
    total_latency_ms: int | None = None,
    cost_basis_ids: tuple[str, ...] = ("declared_pricing_snapshot_v2",),
    pricing_snapshot_ids: tuple[str, ...] = ("local-demo-pricing-v1",),
    pricing_snapshot_digests: tuple[str, ...] | None = None,
    cost_observation_count: int | None = 1,
) -> UsageSummary:
    digests = pricing_snapshot_digests
    if digests is None:
        digests = (pricing_snapshot_digest(_pricing_snapshot()),)
    return UsageSummary(
        total_tokens=total_tokens,
        total_tool_calls=total_tool_calls,
        total_retries=total_retries,
        total_latency_ms=total_latency_ms,
        estimated_cost_microusd=estimated_cost_microusd,
        estimated_cost_picousd=(
            estimated_cost_microusd * 1_000_000
            if estimated_cost_picousd is None
            else estimated_cost_picousd
        ),
        cost_basis_ids=cost_basis_ids,
        pricing_snapshot_ids=pricing_snapshot_ids,
        pricing_snapshot_digests=digests,
        cost_observation_count=cost_observation_count,
    )


def _pricing_snapshot(
    *,
    pricing_snapshot_id: str = "local-demo-pricing-v1",
    currency: str = "USD",
    limitations: tuple[str, ...] = ("Demo fixture pricing only; not live provider pricing.",),
    cached_input_million_tokens_usd: str | None = None,
    reasoning_million_tokens_usd: str | None = None,
) -> UsagePricingSnapshot:
    return UsagePricingSnapshot(
        pricing_snapshot_id=pricing_snapshot_id,
        currency=currency,
        models=(
            UsagePricingModel(
                provider="demo",
                model="fixture-model-small",
                input_million_tokens_usd="1.000000",
                output_million_tokens_usd="3.000000",
                cached_input_million_tokens_usd=cached_input_million_tokens_usd,
                reasoning_million_tokens_usd=reasoning_million_tokens_usd,
            ),
        ),
        limitations=limitations,
    )


def _usage_run_record(
    run_id: str,
    *,
    usage_ledger: UsageLedger | None = None,
    usage_summary: UsageSummary | None = None,
) -> AgentRunRecord:
    return AgentRunRecord(
        run_id=run_id,
        case_id=f"case-{run_id}",
        pipeline_id="pipeline-001",
        recommendation="approve",
        outcome="approved",
        input_summary="input",
        output_summary="output",
        usage_ledger=usage_ledger,
        usage_summary=usage_summary,
    )


def _usage_runset(
    *,
    runs: tuple[AgentRunRecord, ...],
    usage_ledger: UsageLedger | None = None,
    usage_summary: UsageSummary | None = None,
) -> RunSet:
    return RunSet(
        runset_id="runset-usage-coverage",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id="suite-001",
        suite_version="0.1.0",
        suite_digest="0" * 64,
        fixture_manifest_digest="1" * 64,
        usage_ledger=usage_ledger,
        usage_summary=usage_summary,
        runs=runs,
    )
